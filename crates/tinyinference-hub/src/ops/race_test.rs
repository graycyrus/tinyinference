//! Tests for writers that interleave: a change lands between another
//! operation's guard check and its save.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;

use crate::config::{HubConfig, ProviderDraft};
use crate::error::HubError;
use crate::hub::fixtures::{KEY, model, scope, slug};
use crate::hub::{Confirm, ConnectOptions};
use crate::ids::ScopeKey;
use crate::ports::memory::MemoryConfig;
use crate::ports::{ConfigStore, CredentialStore, PortError, Version};
use crate::secret::Secret;
use crate::testkit::MemoryPorts;

type Hook = Box<dyn FnOnce(&MemoryConfig) + Send>;

/// A configuration store that lets "another writer" change the document just
/// before this writer's first save, which then loses its compare-and-swap.
struct Racing {
    inner: Arc<MemoryConfig>,
    hook: Mutex<Option<Hook>>,
}

impl std::fmt::Debug for Racing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Racing")
    }
}

#[async_trait]
impl ConfigStore for Racing {
    async fn load(&self, scope: &ScopeKey) -> Result<Option<(HubConfig, Version)>, PortError> {
        self.inner.load(scope).await
    }

    async fn save(
        &self,
        scope: &ScopeKey,
        config: &HubConfig,
        expect: Option<Version>,
    ) -> Result<Version, PortError> {
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook(&self.inner);
        }
        self.inner.save(scope, config, expect).await
    }
}

fn edit_doc(store: &MemoryConfig, scope: &ScopeKey, change: impl FnOnce(&mut serde_json::Value)) {
    let mut doc: serde_json::Value = serde_json::from_str(&store.raw(scope).unwrap()).unwrap();
    change(&mut doc);
    store.put_raw(scope, doc.to_string());
}

async fn rig(hook: Hook) -> (MemoryPorts, crate::hub::Hub, ScopeKey) {
    let ports = MemoryPorts::new();
    let racing = Racing {
        inner: ports.config.clone(),
        hook: Mutex::new(None),
    };
    let racing = Arc::new(racing);
    let hub = ports.builder().config_arc(racing.clone()).build().unwrap();
    let me = scope("company:acme");
    for (kind, key) in [("openai", KEY), ("groq", "gsk-fake")] {
        hub.add(
            &me,
            ProviderDraft::new(kind)
                .with_key(Secret::new(key))
                .with_model(model("m")),
        )
        .await
        .unwrap();
    }
    hub.clear_default(&me).await.unwrap();
    *racing.hook.lock().unwrap() = Some(hook);
    (ports, hub, me)
}

#[tokio::test]
async fn guard_g6_a_pin_added_while_a_removal_runs_is_seen_on_the_retry() {
    let me = scope("company:acme");
    let target = me.clone();
    let (ports, hub, me) = rig(Box::new(move |store| {
        edit_doc(store, &target, |doc| {
            doc["agent_pins"] = json!({"agent:late": {"provider": "groq", "model": "m"}});
        });
    }))
    .await;
    let error = hub
        .remove(&me, &slug("groq"), Confirm::no())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, HubError::InUse(u) if u.agents.len() == 1),
        "the guard was re-run against the version that was actually there: {error:?}"
    );
    // Nothing was removed and the key is back.
    assert_eq!(hub.status(&me).await.unwrap().providers.len(), 2);
    let key = ports
        .credentials
        .get(&me, &slug("groq").key_slot())
        .await
        .unwrap();
    assert_eq!(key.unwrap().expose(), "gsk-fake");
}

#[tokio::test]
async fn ops_a_provider_removed_while_a_removal_runs_leaves_no_orphaned_key() {
    let me = scope("company:acme");
    let target = me.clone();
    let (ports, hub, me) = rig(Box::new(move |store| {
        edit_doc(store, &target, |doc| {
            let rows = doc["providers"].as_array_mut().unwrap();
            rows.retain(|row| row["slug"] != "groq");
        });
    }))
    .await;
    let error = hub
        .remove(&me, &slug("groq"), Confirm::no())
        .await
        .unwrap_err();
    assert!(matches!(error, HubError::NotFound(_)), "{error:?}");
    let key = ports
        .credentials
        .get(&me, &slug("groq").key_slot())
        .await
        .unwrap();
    assert!(
        key.is_none(),
        "the other remover's deletion stands; the key is not resurrected"
    );
}

#[tokio::test]
async fn ops_a_provider_added_twice_at_once_is_created_once_and_the_loser_keeps_its_own_key_out() {
    let me = scope("company:acme");
    let target = me.clone();
    let ports = MemoryPorts::new();
    let racing = Arc::new(Racing {
        inner: ports.config.clone(),
        hook: Mutex::new(None),
    });
    let hub = ports.builder().config_arc(racing.clone()).build().unwrap();
    // Another writer adds `mistral` between this add's load and its save.
    *racing.hook.lock().unwrap() = Some(Box::new(move |store| {
        let mut config = HubConfig::new();
        let record = crate::descriptor::ProviderRecord::new(
            "prv_other",
            slug("mistral"),
            "Mistral",
            "mistral".into(),
            "https://api.mistral.ai/v1",
        );
        config.providers.push(record);
        store.put_raw(&target, serde_json::to_string(&config).unwrap());
    }));
    ports
        .credentials
        .set(&me, &slug("mistral").key_slot(), Secret::new("sk-winner"))
        .await
        .unwrap();
    let error = hub
        .add(
            &me,
            ProviderDraft::new("mistral").with_key(Secret::new("sk-loser")),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, HubError::AlreadyExists { .. }), "{error:?}");
    let key = ports
        .credentials
        .get(&me, &slug("mistral").key_slot())
        .await
        .unwrap();
    assert_eq!(
        key.unwrap().expose(),
        "sk-winner",
        "the loser's key never replaced the winner's"
    );
}

#[tokio::test]
async fn ops_a_health_store_outage_never_turns_a_committed_change_into_a_failure() {
    let ports = MemoryPorts::new();
    let hub = ports.hub();
    let me = scope("company:acme");
    ports.http.route(
        crate::testkit::Match::prefix("https://api.openai.com/v1/models"),
        crate::testkit::Scripted::json(200, &crate::hub::fixtures::models_body(&["m"])),
    );
    ports.health.set_unavailable(true);
    // Every operation that only *observes or forgets* health still succeeds.
    let mutation = hub
        .connect(
            &me,
            ProviderDraft::new("openai").with_key(Secret::new(KEY)),
            ConnectOptions::default(),
        )
        .await
        .expect("the add and the check worked; only the recording failed");
    assert!(mutation.probe.is_some_and(|p| p.ok()));
    hub.set_key(&me, &slug("openai"), Secret::new("sk-rotated"))
        .await
        .unwrap();
    assert!(
        hub.test(
            &me,
            &slug("openai"),
            crate::taxonomy::TestDepth::Catalog,
            None
        )
        .await
        .unwrap()
        .ok()
    );
    // The reads that need health say so, typed.
    assert!(matches!(
        hub.health(&me, &slug("openai")).await,
        Err(HubError::StoreUnreadable {
            port: crate::error::PortName::Health,
            ..
        })
    ));
    hub.clear_default(&me).await.unwrap();
    hub.remove(&me, &slug("openai"), Confirm::no())
        .await
        .unwrap();
    ports.health.set_unavailable(false);
    assert!(hub.status(&me).await.unwrap().providers.is_empty());
    assert!(ports.credentials.is_empty());
}
