//! Tests for the runner itself: that each invariant fires when the thing it
//! guards is broken. The hub cannot be made to break these on demand, so the
//! tests hand the checks a crafted result or a crafted world.

use super::*;
use crate::config::{DefaultChoice, ProviderDraft};
use crate::error::ReasonCode;
use crate::ports::HubEvent;
use crate::ports::{CredentialStore, HealthStore, Http, HubRequest};
use crate::secret::Secret;
use crate::testkit::{Match, Scripted};

fn result(ok: bool, reason: Option<ReasonCode>, text: &str) -> StepResult {
    StepResult {
        ok,
        reason,
        text: text.to_string(),
        resolved: None,
        listed: None,
        infra: false,
        changed: false,
    }
}

fn runner() -> ScenarioRunner {
    ScenarioRunner::new(1)
}

async fn broken(
    runner: &mut ScenarioRunner,
    action: Action,
    result: StepResult,
    before: &[DefaultChoice],
) -> InvariantViolation {
    runner
        .after_step(&action, &result, before)
        .await
        .expect_err("the crafted step breaks an invariant")
}

fn unset() -> Vec<DefaultChoice> {
    vec![DefaultChoice::Unset, DefaultChoice::Unset]
}

#[tokio::test]
async fn sim_invariant_1_a_secret_or_token_in_anything_said_is_caught() {
    let mut r = runner();
    let leaked = format!("sk-sim-{}-3", r.seed());
    let v = broken(
        &mut r,
        Action::Advance { secs: 1 },
        result(true, None, &leaked),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 1);
    let v = broken(
        &mut r,
        Action::Advance { secs: 1 },
        result(true, None, "platform-token-4"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 1);
    assert!(v.to_string().contains("invariant 1"));
    let mut infra = result(false, Some(ReasonCode::Conflict), "conflict");
    infra.infra = true;
    let v = broken(&mut r, Action::Advance { secs: 1 }, infra, &unset()).await;
    assert_eq!(
        v.number, 0,
        "an infrastructure error with no fault injected"
    );
}

#[tokio::test]
async fn sim_invariant_10_the_default_moves_only_where_it_may() {
    let mut r = runner();
    let hub = r.hub().clone();
    let scope = r.scopes[0].clone();
    hub.add(
        &scope,
        ProviderDraft::new("openai").with_model(crate::hub::fixtures::model("m")),
    )
    .await
    .unwrap();
    // The hub's default is now Full{openai}; a step that claims it was Unset before
    // and was not allowed to change it.
    let v = broken(
        &mut r,
        Action::Remove {
            scope: 0,
            prov: 1,
            confirm: true,
        },
        result(false, Some(ReasonCode::NotFound), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 10);
    // An add may set the default only from Unset to Full, or when asked.
    let before = vec![
        DefaultChoice::Full {
            provider: crate::hub::fixtures::slug("groq"),
            model: crate::hub::fixtures::model("m"),
        },
        DefaultChoice::Unset,
    ];
    let v = broken(
        &mut r,
        Action::Add {
            scope: 0,
            prov: 2,
            keyed: false,
        },
        result(true, None, "x"),
        &before,
    )
    .await;
    assert_eq!(v.number, 10);
    // A failed add that changed the default (the bug a rollback once had).
    let hub = r.hub().clone();
    let scope = r.scopes[1].clone();
    hub.add(
        &scope,
        ProviderDraft::new("openai").with_model(crate::hub::fixtures::model("m")),
    )
    .await
    .unwrap();
    let failed_connect = Action::Connect {
        scope: 1,
        prov: 2,
        keyed: true,
        add_anyway: false,
        make_default: true,
        completion: false,
    };
    let v = broken(
        &mut r,
        failed_connect,
        result(false, Some(ReasonCode::Auth), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 10);
    // set_default that succeeded but left another default.
    let v = broken(
        &mut r,
        Action::SetDefault {
            scope: 0,
            prov: 1,
            model: 0,
        },
        result(true, None, "x"),
        &before,
    )
    .await;
    assert_eq!(v.number, 10);
}

#[tokio::test]
async fn sim_invariants_6_and_managed_refusals() {
    let mut r = runner();
    let v = broken(
        &mut r,
        Action::Remove {
            scope: 0,
            prov: 5,
            confirm: true,
        },
        result(true, None, "removed"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 6);
    let v = broken(
        &mut r,
        Action::Connect {
            scope: 0,
            prov: 5,
            keyed: true,
            add_anyway: false,
            make_default: false,
            completion: false,
        },
        result(true, None, "x"),
        &unset(),
    )
    .await;
    assert_eq!(
        v.number, 0,
        "adding the managed provider must be Unsupported"
    );
    let v = broken(
        &mut r,
        Action::Add {
            scope: 0,
            prov: 5,
            keyed: false,
        },
        result(false, Some(ReasonCode::Invalid), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 0);
}

#[tokio::test]
async fn sim_invariant_7_a_resolved_turn_is_an_enabled_provider() {
    let mut r = runner();
    let mut resolved = result(true, None, "turn");
    resolved.resolved = Some(1);
    let v = broken(
        &mut r,
        Action::Resolve {
            scope: 0,
            agent: None,
            workload: None,
        },
        resolved,
        &unset(),
    )
    .await;
    assert_eq!(v.number, 7, "groq was never added");
}

#[tokio::test]
async fn sim_invariant_8_a_failed_add_leaves_neither_a_row_nor_a_key() {
    let mut r = runner();
    let hub = r.hub().clone();
    let scope = r.scopes[0].clone();
    hub.add(&scope, ProviderDraft::new("groq")).await.unwrap();
    let action = Action::Connect {
        scope: 0,
        prov: 1,
        keyed: true,
        add_anyway: false,
        make_default: false,
        completion: false,
    };
    let v = broken(
        &mut r,
        action.clone(),
        result(false, Some(ReasonCode::Auth), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 8, "the row is still there");
    // AlreadyExists is the one failure that legitimately leaves the row.
    assert!(
        r.after_step(
            &action,
            &result(false, Some(ReasonCode::AlreadyExists), "x"),
            &unset()
        )
        .await
        .is_ok()
    );
    // No row, but a key in the slot.
    let mut r = runner();
    r.ports
        .credentials
        .set(
            &r.scopes[0],
            &crate::hub::fixtures::slug("mistral").key_slot(),
            Secret::new("k"),
        )
        .await
        .unwrap();
    let action = Action::Add {
        scope: 0,
        prov: 2,
        keyed: true,
    };
    let v = broken(
        &mut r,
        action,
        result(false, Some(ReasonCode::Auth), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 8);
}

#[tokio::test]
async fn sim_invariant_9_health_does_not_survive_a_key_change() {
    let mut r = runner();
    let hub = r.hub().clone();
    let scope = r.scopes[0].clone();
    hub.add(&scope, ProviderDraft::new("groq")).await.unwrap();
    hub.record_outcome(
        &scope,
        &crate::hub::fixtures::slug("groq"),
        crate::health::Outcome::Ok {
            latency: std::time::Duration::ZERO,
        },
    )
    .await
    .unwrap();
    let mut changed = result(true, None, "x");
    changed.changed = true;
    let v = broken(
        &mut r,
        Action::SetKey { scope: 0, prov: 1 },
        changed,
        &unset(),
    )
    .await;
    assert_eq!(v.number, 9);
    assert!(
        r.ports
            .health
            .get(&scope, &crate::hub::fixtures::slug("groq"))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn sim_invariants_3_and_4_a_list_matches_its_credential_and_a_fetched_rejection_is_an_error()
{
    let mut r = runner();
    let action = Action::List {
        scope: 0,
        prov: 4,
        refresh: true,
    };
    // Ollama lists "llama3": anything else fresh is a leak.
    let mut wrong = result(true, None, "Fresh");
    wrong.listed = Some((
        crate::catalog::Freshness::Fresh,
        vec!["someone-elses-model".into()],
    ));
    let v = broken(&mut r, action.clone(), wrong, &unset()).await;
    assert_eq!(v.number, 3);
    // A fetch that hit a rejecting provider must have failed with auth.
    r.modes[4] = Mode::AuthFail;
    r.requests_before = 0;
    let http = r.ports.http.clone();
    http.route(
        Match::get("http://localhost:11434/x"),
        Scripted::text(200, "x"),
    );
    http.send(
        HubRequest::get("http://localhost:11434/x"),
        &crate::policy::EndpointPolicy::desktop(),
    )
    .await
    .unwrap();
    let v = broken(
        &mut r,
        action.clone(),
        result(true, None, "Fresh"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 4);
    r.modes[4] = Mode::Healthy;
    let v = broken(
        &mut r,
        action,
        result(false, Some(ReasonCode::Unknown), "x"),
        &unset(),
    )
    .await;
    assert_eq!(v.number, 0, "a healthy provider that was asked must answer");
}

#[tokio::test]
async fn sim_invariants_1_2_5_6_the_standing_checks_see_leaks_and_strays() {
    // A request whose URL carries a minted credential.
    let mut r = runner();
    let leaked = format!("sk-sim-{}-0", r.seed());
    r.ports.http.route(
        Match::prefix("https://api.openai.com/"),
        Scripted::text(200, "x"),
    );
    r.ports
        .http
        .send(
            HubRequest::get(format!("https://api.openai.com/v1/models?x={leaked}")),
            &crate::policy::EndpointPolicy::desktop(),
        )
        .await
        .unwrap();
    assert_eq!(r.check_invariants().await.unwrap_err().number, 1);

    // A request to a host outside the world.
    let mut r = runner();
    r.ports.http.route(
        Match::prefix("https://elsewhere.test/"),
        Scripted::text(200, "x"),
    );
    r.ports
        .http
        .send(
            HubRequest::get("https://elsewhere.test/"),
            &crate::policy::EndpointPolicy::desktop(),
        )
        .await
        .unwrap();
    assert_eq!(r.check_invariants().await.unwrap_err().number, 5);

    // A managed request with a token from an earlier minute.
    let mut r = runner();
    r.ports.clock.advance(std::time::Duration::from_secs(300));
    r.ports
        .http
        .route(Match::prefix(MANAGED_BASE), Scripted::text(200, "x"));
    r.ports
        .http
        .send(
            HubRequest::get(format!("{MANAGED_BASE}/models")).with_header(
                "authorization",
                format!("Bearer {}", SimToken::at_minute(1)),
            ),
            &crate::policy::EndpointPolicy::desktop(),
        )
        .await
        .unwrap();
    assert_eq!(r.check_invariants().await.unwrap_err().number, 1);

    // A request the transport refused for one of the world's own URLs.
    let mut r = runner();
    r.ports.http.route(
        Match::prefix("https://api.openai.com/"),
        Scripted::text(200, "x").resolving_to(vec!["10.0.0.1".parse().unwrap()]),
    );
    let _ = r
        .ports
        .http
        .send(
            HubRequest::get("https://api.openai.com/v1/models"),
            &crate::policy::EndpointPolicy::desktop(),
        )
        .await;
    assert_eq!(r.check_invariants().await.unwrap_err().number, 5);

    // An event that says a minted credential, and one that says a token.
    for text in [
        format!("sk-sim-{}-0", runner().seed()),
        "platform-token-7".to_string(),
    ] {
        let mut r = runner();
        if let Ok(slug) = crate::ids::Slug::parse(&text) {
            r.ports.events.emit_test(HubEvent::ProviderAdded {
                scope: r.scopes[0].clone(),
                slug,
            });
            assert_eq!(r.check_invariants().await.unwrap_err().number, 1, "{text}");
        }
    }

    // Stored documents: a leak, a document that does not load, two managed rows.
    for raw in [
        format!(r#"{{"providers":[{{"id":"a","slug":"acme","label":"sk-sim-{}-1","kind":"custom","base_url":"https://a.test"}}]}}"#, runner().seed()),
        r#"{"providers":[{"id":"a","slug":"acme","label":"platform-token-3","kind":"custom","base_url":"https://a.test"}]}"#.to_string(),
        r#"{"providers":"not a list"}"#.to_string(),
        r#"{"providers":[{"id":"a","slug":"tinyhumans","label":"a","kind":"tinyhumans","base_url":""},{"id":"b","slug":"managed-two","label":"b","kind":"tinyhumans","base_url":""}]}"#.to_string(),
    ] {
        let mut r = runner();
        r.ports.config.put_raw(&r.scopes[0], raw.clone());
        let v = r.check_invariants().await.unwrap_err();
        assert!([2, 6].contains(&v.number), "{raw}: {v}");
    }
}

#[tokio::test]
async fn sim_a_failing_step_reports_its_seed_step_and_trace() {
    let mut r = runner();
    let leaked = format!("sk-sim-{}-0", r.seed());
    r.ports.http.route(
        Match::prefix("https://api.openai.com/"),
        Scripted::text(200, "x"),
    );
    r.ports
        .http
        .send(
            HubRequest::get(format!("https://api.openai.com/?k={leaked}")),
            &crate::policy::EndpointPolicy::desktop(),
        )
        .await
        .unwrap();
    let failure = r.step(Action::Advance { secs: 1 }).await.unwrap_err();
    let shown = failure.to_string();
    assert!(
        shown.contains("seed=1 step=0") && shown.contains("Advance"),
        "{shown}"
    );
    assert_eq!(failure.violation.number, 1);
    assert!(std::error::Error::source(&failure).is_none());
}

#[tokio::test]
async fn sim_runner_accessors_and_debug() {
    let r = ScenarioRunner::with(
        9,
        crate::policy::EndpointPolicy::hosted(),
        FaultPlan::flaky(9),
    );
    assert_eq!(r.seed(), 9);
    assert!(r.trace().is_empty());
    assert!(r.hub().policy() == &crate::policy::EndpointPolicy::hosted());
    assert_eq!(r.ports().http.request_count(), 0);
    assert!(format!("{r:?}").contains("seed"));
    let plan = FaultPlan::none(3);
    assert!(plan.p_conflict == 0.0 && plan.p_credential_outage == 0.0);
    assert!(Mode::Healthy.serves() && !Mode::Down.serves());
}

#[tokio::test]
async fn sim_every_action_kind_can_be_taken_by_hand() {
    let mut r = runner();
    let script = [
        Action::Connect {
            scope: 0,
            prov: 0,
            keyed: true,
            add_anyway: false,
            make_default: true,
            completion: false,
        },
        Action::Add {
            scope: 1,
            prov: 4,
            keyed: false,
        },
        Action::Edit {
            scope: 0,
            prov: 0,
            rotate: true,
            model: Some(1),
        },
        Action::SetKey { scope: 0, prov: 0 },
        Action::SetDefault {
            scope: 0,
            prov: 0,
            model: 2,
        },
        Action::Pin {
            scope: 0,
            agent: 0,
            prov: Some(0),
        },
        Action::SetRoute {
            scope: 0,
            workload: 0,
            prov: Some(0),
        },
        Action::Resolve {
            scope: 0,
            agent: Some(0),
            workload: Some(0),
        },
        Action::List {
            scope: 0,
            prov: 0,
            refresh: true,
        },
        Action::Test {
            scope: 0,
            prov: 0,
            completion: true,
        },
        Action::RecordOutcome {
            scope: 0,
            prov: 0,
            ok: false,
            reason: 1,
        },
        Action::Flip {
            prov: 0,
            mode: Mode::AuthFail,
        },
        Action::RetestDown { scope: 0 },
        Action::Advance { secs: 301 },
        Action::ToggleSignedOut,
        Action::ToggleSignedOut,
        Action::SetEnabled {
            scope: 0,
            prov: 0,
            on: false,
            confirm: true,
        },
        Action::ClearKey {
            scope: 0,
            prov: 0,
            confirm: true,
        },
        Action::ClearDefault { scope: 0 },
        Action::Pin {
            scope: 0,
            agent: 0,
            prov: None,
        },
        Action::SetRoute {
            scope: 0,
            workload: 0,
            prov: None,
        },
        Action::Remove {
            scope: 0,
            prov: 0,
            confirm: true,
        },
    ];
    for action in script {
        r.step(action.clone())
            .await
            .unwrap_or_else(|f| panic!("{f}"));
    }
    assert_eq!(r.trace().len(), 22);
    // The random generator covers the same ground under a fixed seed.
    let mut r = ScenarioRunner::new(77);
    r.run_random(120).await.unwrap();
    assert_eq!(r.trace().len(), 120);
    assert!(Rng::new(5).next() != Rng::new(6).next());
    assert!(Rng::new(1).below(0) == 0);
    assert!(Rng::new(1).chance(1.0));
}
