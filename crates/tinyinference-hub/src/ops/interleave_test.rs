//! Races staged with the interleaving hook (`Hold`): the schedules the plain
//! in-memory ports cannot produce, written down instead of hoped for.
//!
//! * finding 5.4: an origin move must never let a credential entered for one
//!   origin be used against the other, at **any** point of the edit;
//! * finding 4.6: the three-way same-slug race must not delete the key the
//!   winning add wrote;
//! * findings 4.4 and 4.5: an edit and a key change on one provider are ordered,
//!   and a failing config store at any two consecutive reads never leaves an
//!   orphaned key behind an undone add.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tinyinference_llm::MockModel;
use tinyinference_llm::error::Result as LlmResult;
use tinyinference_llm::model::{ChatModel, ModelRequest, ModelResponse, ModelStream};

use crate::client::{ModelFactory, ModelSpec};
use crate::config::ProviderDraft;
use crate::error::HubError;
use crate::hub::fixtures::{Bed, model, slug};
use crate::hub::{Confirm, ConnectOptions, Hub, ProviderPatch};
use crate::ids::ScopeKey;
use crate::ports::memory::{Call, Hold};
use crate::route::TurnQuery;
use crate::secret::Secret;

const OLD: &str = "https://llm.acme.test/v1";
const NEW: &str = "https://llm.acme-two.test/v1";
const K_OLD: &str = "sk-not-a-real-key-old";
const K_NEW: &str = "sk-not-a-real-key-new";

/// A model that answers and remembers nothing; what matters is what the
/// factory was asked to build it with.
struct Echo;

impl std::fmt::Debug for Echo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Echo")
    }
}

#[async_trait]
impl ChatModel<()> for Echo {
    async fn invoke(&self, _: &(), _: ModelRequest) -> LlmResult<ModelResponse> {
        Ok(MockModel::text_response("ok"))
    }

    async fn stream(&self, state: &(), request: ModelRequest) -> LlmResult<ModelStream> {
        let response = self.invoke(state, request).await?;
        Ok(ModelStream::new(Box::pin(futures::stream::iter(vec![
            tinyinference_llm::model::ModelStreamItem::Completed(response),
        ]))))
    }
}

/// Records `(endpoint, key)` for every model the hub builds: the pair a request
/// would carry.
#[derive(Debug, Default)]
struct Spy {
    built: Mutex<Vec<(String, Option<String>)>>,
}

impl ModelFactory for Spy {
    fn build(&self, spec: &ModelSpec<'_>) -> Result<Arc<dyn ChatModel<()>>, HubError> {
        self.built
            .lock()
            .unwrap()
            .push((spec.turn.base_url.clone(), spec.key.map(str::to_string)));
        Ok(Arc::new(Echo))
    }
}

async fn acme_bed() -> (Bed, Arc<Spy>) {
    let spy = Arc::new(Spy::default());
    let bed = Bed::with(|b| b.model_factory(spy.clone()));
    bed.hub
        .add(
            &bed.scope,
            ProviderDraft::new("custom")
                .with_label("Acme")
                .with_base_url(OLD)
                .with_key(Secret::new(K_OLD))
                .with_model(model("m")),
        )
        .await
        .unwrap();
    (bed, spy)
}

/// Uses the provider the two ways a host does: through a model it kept from
/// before, and through a fresh resolve. Errors are fine (a fail-closed refusal
/// is the point); only what gets *built* matters.
async fn use_it(hub: &Hub, scope: &ScopeKey, kept: &Arc<dyn ChatModel<()>>) {
    let _ = kept.invoke(&(), ModelRequest::default()).await;
    if let Ok(turn) = hub.resolve_for_turn(scope, &TurnQuery::new()).await
        && let Ok(fresh) = hub.chat_model(scope, &turn).await
    {
        let _ = fresh.invoke(&(), ModelRequest::default()).await;
    }
}

fn assert_no_cross_origin_credential(spy: &Spy, at: &str) {
    for (endpoint, key) in spy.built.lock().unwrap().iter() {
        let allowed = match (endpoint.as_str(), key.as_deref()) {
            (OLD, Some(K_OLD)) | (NEW, Some(K_NEW)) => true,
            // No key at all is fail-closed or keyless: never a leak.
            (_, None) => true,
            _ => false,
        };
        assert!(
            allowed,
            "{at}: a request would carry {key:?} to {endpoint}, an origin it was not entered for"
        );
    }
}

/// Runs `edit` (an origin move with a key entered for the new origin) holding
/// it at `hold`, using the provider from another task while it is parked.
async fn move_origin_holding(hold: Option<(bool, Hold)>, label: &str) -> bool {
    let (bed, spy) = acme_bed().await;
    let turn = bed
        .hub
        .resolve_for_turn(&bed.scope, &TurnQuery::new())
        .await
        .unwrap();
    let kept = bed.hub.chat_model(&bed.scope, &turn).await.unwrap();
    kept.invoke(&(), ModelRequest::default()).await.unwrap();
    let mut held = hold.map(|(on_config, hold)| {
        if on_config {
            bed.ports.config.hold(hold)
        } else {
            bed.ports.credentials.hold(hold)
        }
    });
    let reached = std::cell::Cell::new(false);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let edit = async {
        let result = bed
            .hub
            .edit(
                &bed.scope,
                &slug("acme"),
                ProviderPatch::new().base_url(NEW).key(Secret::new(K_NEW)),
            )
            .await;
        let _ = done_tx.send(());
        result
    };
    let probe = async {
        if let Some(held) = held.as_mut() {
            tokio::select! {
                () = held.reached() => {
                    reached.set(true);
                    use_it(&bed.hub, &bed.scope, &kept).await;
                    held.release();
                }
                _ = done_rx => {}
            }
        }
    };
    let (edited, ()) = tokio::join!(edit, probe);
    edited.unwrap();
    // A hold that was never reached must not park the calls made from here on.
    drop(held);
    use_it(&bed.hub, &bed.scope, &kept).await;
    assert_no_cross_origin_credential(&spy, label);
    // And the move worked: the new origin with the new key.
    let turn = bed
        .hub
        .resolve_for_turn(&bed.scope, &TurnQuery::new())
        .await
        .unwrap();
    assert_eq!(turn.base_url, NEW);
    assert_eq!(bed.key_of("acme").await.as_deref(), Some(K_NEW));
    reached.get()
}

#[tokio::test]
async fn ops_race_an_origin_move_never_pairs_a_key_with_an_origin_it_was_not_entered_for() {
    // Every point of the edit at which a host can run: the config's first
    // load/save (before and after taking effect) and the credential store's
    // first and second get/set/delete. `skip` reaches the second call of a kind.
    let slot = slug("acme").key_slot();
    let cfg = |hold: Hold| (true, hold);
    let cred = |hold: Hold| (false, hold);
    let holds: Vec<(&str, (bool, Hold))> = vec![
        ("config save before", cfg(Hold::before(Call::Save))),
        ("config save after", cfg(Hold::after(Call::Save))),
        (
            "config load before #1",
            cfg(Hold::before(Call::Load).skip(1)),
        ),
        (
            "config load before #2",
            cfg(Hold::before(Call::Load).skip(2)),
        ),
        ("config load after #2", cfg(Hold::after(Call::Load).skip(2))),
        ("config load after #3", cfg(Hold::after(Call::Load).skip(3))),
        ("cred set before", cred(Hold::before(Call::Set).slot(&slot))),
        ("cred set after", cred(Hold::after(Call::Set).slot(&slot))),
        (
            "cred delete before",
            cred(Hold::before(Call::Delete).slot(&slot)),
        ),
        (
            "cred delete after",
            cred(Hold::after(Call::Delete).slot(&slot)),
        ),
        ("cred get before", cred(Hold::before(Call::Get).slot(&slot))),
        ("cred get after", cred(Hold::after(Call::Get).slot(&slot))),
        (
            "cred get before #2",
            cred(Hold::before(Call::Get).slot(&slot).skip(1)),
        ),
        (
            "cred get after #2",
            cred(Hold::after(Call::Get).slot(&slot).skip(1)),
        ),
    ];
    let mut missed = Vec::new();
    for (label, hold) in holds {
        if !move_origin_holding(Some(hold), label).await {
            missed.push(label);
        }
    }
    // The schedule must actually have happened: a hold the edit never reached
    // proves nothing about that point.
    assert!(missed.is_empty(), "holds never reached: {missed:?}");
    // And the untouched run is fine too.
    assert!(!move_origin_holding(None, "no hold").await);
}

#[tokio::test]
async fn ops_race_the_three_way_same_slug_add_does_not_delete_the_winning_adds_key() {
    // A1 adds `acme` and is parked right after its record is committed. Meanwhile
    // the provider is removed and added again (A2, with its own key). When A1
    // resumes it must not write its key over A2's, and must not delete it.
    let bed = Bed::new();
    let draft = |key: &str| {
        ProviderDraft::new("custom")
            .with_label("Acme")
            .with_base_url(OLD)
            .with_key(Secret::new(key))
            .with_model(model("m"))
    };
    let mut held = bed.ports.config.hold(Hold::after(Call::Save));
    let a1 = bed.hub.add(&bed.scope, draft("sk-not-a-real-key-a1"));
    let others = async {
        held.reached().await;
        bed.hub
            .remove(&bed.scope, &slug("acme"), Confirm::in_use())
            .await
            .unwrap();
        bed.hub
            .add(&bed.scope, draft("sk-not-a-real-key-a2"))
            .await
            .unwrap();
        held.release();
    };
    let (first, ()) = tokio::join!(a1, others);
    assert!(
        matches!(first, Err(HubError::NotFound(_))),
        "the first add lost its provider: {first:?}"
    );
    assert_eq!(
        bed.key_of("acme").await.as_deref(),
        Some("sk-not-a-real-key-a2"),
        "the winning add's key is untouched"
    );
    assert_eq!(bed.ports.credentials.len(), 1);
}

#[tokio::test]
async fn ops_race_a_key_set_while_an_edit_moves_the_origin_is_ordered_not_interleaved() {
    // set_key on a provider whose edit is parked mid-move waits for the edit
    // (they share the provider's lock), then lands on the provider as it is.
    let (bed, _spy) = acme_bed().await;
    let acme = slug("acme");
    let mut held = bed.ports.config.hold(Hold::before(Call::Save));
    let edit = bed.hub.edit(
        &bed.scope,
        &acme,
        ProviderPatch::new().base_url(NEW).key(Secret::new(K_NEW)),
    );
    let set = async {
        held.reached().await;
        // Started while the edit is parked; it cannot finish before the edit does.
        let mut set = std::pin::pin!(bed.hub.set_key(
            &bed.scope,
            &acme,
            Secret::new("sk-not-a-real-key-late")
        ));
        let polled = futures::poll!(set.as_mut());
        assert!(polled.is_pending(), "set_key waits for the edit's lock");
        held.release();
        set.await.unwrap();
    };
    let (edited, ()) = tokio::join!(edit, set);
    edited.unwrap();
    assert_eq!(
        bed.key_of("acme").await.as_deref(),
        Some("sk-not-a-real-key-late")
    );
    let config = bed.hub.status(&bed.scope).await.unwrap();
    let acme = config
        .providers
        .iter()
        .find(|p| p.view.record.slug == slug("acme"))
        .unwrap();
    assert_eq!(acme.view.record.base_url, NEW);
}

#[tokio::test]
async fn ops_race_a_config_store_failing_at_any_two_reads_never_leaves_a_key_behind_an_undone_add()
{
    // Findings 4.5 / 5.3: `undo_add` read the config twice before deciding what
    // to restore. Rather than guess which read, fail every consecutive pair in
    // turn and check the one thing that must always hold: when the add did not
    // stick, no key belongs to a provider that does not exist.
    for first in 0..14usize {
        let bed = Bed::new();
        bed.openai_rejects_key();
        // The slot held a leftover key from an earlier provider of that slug.
        bed.store_key("openai", "sk-not-a-real-key-earlier").await;
        // Two scripted faults on consecutive loads (identical holds fire on
        // consecutive calls), starting at the `first`-th load of the connect.
        let _a = bed
            .ports
            .config
            .hold(Hold::before(Call::Load).skip(first).fail());
        let _b = bed
            .ports
            .config
            .hold(Hold::before(Call::Load).skip(first).fail());
        let result = bed
            .hub
            .connect(&bed.scope, bed.openai_draft(), ConnectOptions::default())
            .await;
        let stored = bed.ports.config.raw(&bed.scope).unwrap_or_default();
        let record_exists = stored.contains("\"slug\":\"openai\"");
        let key = bed.key_of("openai").await;
        if !record_exists {
            assert_eq!(
                key.as_deref(),
                Some("sk-not-a-real-key-earlier"),
                "pair {first}: the add is gone, so the slot is what it was before it ({result:?})"
            );
        }
    }
}

async fn state_of(bed: &Bed) -> (String, Option<String>) {
    let status = bed.hub.status(&bed.scope).await.unwrap();
    let acme = status
        .providers
        .iter()
        .find(|p| p.view.record.slug == slug("acme"))
        .unwrap();
    (acme.view.record.base_url.clone(), bed.key_of("acme").await)
}

fn move_patch() -> ProviderPatch {
    ProviderPatch::new().base_url(NEW).key(Secret::new(K_NEW))
}

#[tokio::test]
async fn ops_an_origin_move_whose_record_cannot_be_saved_keeps_the_old_origin_and_key() {
    let (bed, _spy) = acme_bed().await;
    let _fault = bed.ports.config.hold(Hold::before(Call::Save).fail());
    bed.hub
        .edit(&bed.scope, &slug("acme"), move_patch())
        .await
        .unwrap_err();
    assert_eq!(state_of(&bed).await, (OLD.to_string(), Some(K_OLD.into())));
}

#[tokio::test]
async fn ops_an_origin_move_whose_key_cannot_be_written_goes_back_to_the_old_origin_and_key() {
    let (bed, _spy) = acme_bed().await;
    let slot = slug("acme").key_slot();
    let _fault = bed
        .ports
        .credentials
        .hold(Hold::before(Call::Set).slot(&slot).fail());
    bed.hub
        .edit(&bed.scope, &slug("acme"), move_patch())
        .await
        .unwrap_err();
    // The record was moved and moved back; the old key is back with it.
    assert_eq!(state_of(&bed).await, (OLD.to_string(), Some(K_OLD.into())));
}

#[tokio::test]
async fn ops_an_origin_move_that_cannot_be_undone_fails_closed_with_no_key_at_all() {
    let (bed, _spy) = acme_bed().await;
    let slot = slug("acme").key_slot();
    let _write = bed
        .ports
        .credentials
        .hold(Hold::before(Call::Set).slot(&slot).fail());
    // The commit is the first save, the move back the second.
    let _back = bed
        .ports
        .config
        .hold(Hold::before(Call::Save).skip(1).fail());
    bed.hub
        .edit(&bed.scope, &slug("acme"), move_patch())
        .await
        .unwrap_err();
    // At the new origin with no key: neither key is usable anywhere.
    assert_eq!(state_of(&bed).await, (NEW.to_string(), None));
}

#[tokio::test]
async fn ops_an_origin_move_validated_against_an_endpoint_that_moved_meanwhile_is_a_conflict() {
    // Finding 4.4: another writer (another hub over this store) moves the
    // endpoint after this edit validated its move and before it saves. Keyless,
    // so that the move itself is allowed.
    let bed = Bed::new();
    bed.hub
        .add(
            &bed.scope,
            ProviderDraft::new("custom")
                .with_label("Acme")
                .with_base_url(OLD)
                .with_model(model("m")),
        )
        .await
        .unwrap();
    let acme = slug("acme");
    // The edit's loads: the first read, the re-read under the lock, then the
    // transaction's own.
    let mut held = bed.ports.config.hold(Hold::before(Call::Load).skip(2));
    let edit = bed
        .hub
        .edit(&bed.scope, &acme, ProviderPatch::new().base_url(NEW));
    let other_writer = async {
        held.reached().await;
        let mut doc: serde_json::Value =
            serde_json::from_str(&bed.ports.config.raw(&bed.scope).unwrap()).unwrap();
        for row in doc["providers"].as_array_mut().unwrap() {
            if row["slug"] == "acme" {
                row["base_url"] = "https://llm.third.test/v1".into();
            }
        }
        bed.ports.config.put_raw(&bed.scope, doc.to_string());
        held.release();
    };
    let (result, ()) = tokio::join!(edit, other_writer);
    assert!(matches!(result, Err(HubError::Conflict)), "{result:?}");
    let (base, _) = state_of(&bed).await;
    assert_eq!(
        base, "https://llm.third.test/v1",
        "the other writer's move stands"
    );
}
