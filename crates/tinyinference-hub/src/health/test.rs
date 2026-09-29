//! Tests for the health fold and the tracker.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::error::{ProviderFailure, ReasonCode, Retry};
use crate::ids::{ScopeKey, Slug};
use crate::ports::memory::{MemoryEvents, MemoryHealth};
use crate::ports::{HubEvent, PortError};
use crate::taxonomy::TestDepth;
use crate::testkit::FakeClock;

fn fail(reason: ReasonCode) -> Option<(ReasonCode, Option<u16>)> {
    Some((reason, None))
}

fn slug() -> Slug {
    Slug::parse("openai").unwrap()
}

fn scope() -> ScopeKey {
    ScopeKey::new("company:acme")
}

// ---- the fold, as a table --------------------------------------------------

#[derive(Clone, Copy)]
enum Step {
    Probe(TestDepth, Option<ReasonCode>),
    Turn(Option<ReasonCode>),
}

fn run(steps: &[Step]) -> ProviderHealth {
    let mut snapshot = HealthSnapshot::default();
    for (n, step) in steps.iter().enumerate() {
        let now = 1_000 + n as u64;
        match *step {
            Step::Probe(depth, reason) => {
                snapshot.record_probe(depth, reason.map(|r| (r, None)), Some(5), now);
            }
            Step::Turn(reason) => {
                snapshot.record_turn(reason.map(|r| (r, None)), now);
            }
        }
    }
    snapshot.health
}

use Step::{Probe, Turn};
use TestDepth::{Catalog, Completion, KeyOnly};

#[test]
fn health_the_fold_table() {
    let ok = ProviderHealth::Ok;
    let cases: Vec<(&str, Vec<Step>, ProviderHealth)> = vec![
        ("nothing recorded", vec![], ProviderHealth::Unknown),
        ("a passing catalog", vec![Probe(Catalog, None)], ok),
        ("a passing turn", vec![Turn(None)], ok),
        (
            "a rejected key is down at once",
            vec![Probe(Catalog, Some(ReasonCode::Auth))],
            ProviderHealth::Down(ReasonCode::Auth),
        ),
        (
            "an exhausted account is down at once",
            vec![Turn(Some(ReasonCode::Quota))],
            ProviderHealth::Down(ReasonCode::Quota),
        ),
        (
            "auth is down even when another lane passes",
            vec![
                Probe(Catalog, None),
                Probe(Completion, Some(ReasonCode::Auth)),
            ],
            ProviderHealth::Down(ReasonCode::Auth),
        ),
        (
            "an unreachable endpoint is down",
            vec![Probe(Catalog, Some(ReasonCode::Endpoint))],
            ProviderHealth::Down(ReasonCode::Endpoint),
        ),
        (
            "one timeout is only degraded",
            vec![Probe(Catalog, Some(ReasonCode::Timeout))],
            ProviderHealth::Degraded(ReasonCode::Timeout),
        ),
        (
            "an unknown model is degraded",
            vec![Turn(Some(ReasonCode::Model))],
            ProviderHealth::Degraded(ReasonCode::Model),
        ),
        (
            "a rate limit is degraded",
            vec![Turn(Some(ReasonCode::RateLimited))],
            ProviderHealth::Degraded(ReasonCode::RateLimited),
        ),
        (
            "the partial outage: catalog fails, completion works",
            vec![
                Probe(Completion, None),
                Probe(Catalog, Some(ReasonCode::Unknown)),
            ],
            ProviderHealth::Degraded(ReasonCode::Unknown),
        ),
        (
            "two lanes failing is down",
            vec![
                Probe(Catalog, Some(ReasonCode::Timeout)),
                Probe(Completion, Some(ReasonCode::Timeout)),
            ],
            ProviderHealth::Down(ReasonCode::Timeout),
        ),
        (
            "three failed turns in a row is down",
            vec![
                Turn(Some(ReasonCode::Timeout)),
                Turn(Some(ReasonCode::Timeout)),
                Turn(Some(ReasonCode::Timeout)),
            ],
            ProviderHealth::Down(ReasonCode::Timeout),
        ),
        (
            "two failed turns are still degraded",
            vec![
                Turn(Some(ReasonCode::Timeout)),
                Turn(Some(ReasonCode::Timeout)),
            ],
            ProviderHealth::Degraded(ReasonCode::Timeout),
        ),
        (
            "a success resets the run of failures",
            vec![
                Turn(Some(ReasonCode::Timeout)),
                Turn(Some(ReasonCode::Timeout)),
                Turn(None),
                Turn(Some(ReasonCode::Timeout)),
            ],
            ProviderHealth::Degraded(ReasonCode::Timeout),
        ),
        (
            "the worst failure names the reason",
            vec![
                Probe(Catalog, Some(ReasonCode::RateLimited)),
                Probe(Completion, Some(ReasonCode::Endpoint)),
            ],
            ProviderHealth::Down(ReasonCode::Endpoint),
        ),
        (
            "a later completion pass does not hide an earlier catalog failure",
            vec![
                Probe(Catalog, Some(ReasonCode::Timeout)),
                Probe(Completion, None),
            ],
            ProviderHealth::Degraded(ReasonCode::Timeout),
        ),
        (
            "a later catalog failure is not superseded by an earlier completion pass",
            vec![
                Probe(Completion, None),
                Probe(Catalog, Some(ReasonCode::Timeout)),
            ],
            ProviderHealth::Degraded(ReasonCode::Timeout),
        ),
        (
            "a real turn that worked supersedes an older completion probe failure",
            vec![Probe(Completion, Some(ReasonCode::Model)), Turn(None)],
            ok,
        ),
        (
            "a real turn that worked does not hide a broken catalog",
            vec![Probe(Catalog, Some(ReasonCode::Endpoint)), Turn(None)],
            ProviderHealth::Degraded(ReasonCode::Endpoint),
        ),
        (
            "a rejected key on the catalog stays down even if a turn worked before it",
            vec![Turn(None), Probe(Catalog, Some(ReasonCode::Auth))],
            ProviderHealth::Down(ReasonCode::Auth),
        ),
        (
            "a failed turn is not superseded by an older completion pass",
            vec![Probe(Completion, None), Turn(Some(ReasonCode::Endpoint))],
            ProviderHealth::Degraded(ReasonCode::Endpoint),
        ),
        (
            "a passing catalog does not clear failing turns",
            vec![Turn(Some(ReasonCode::Endpoint)), Probe(Catalog, None)],
            ProviderHealth::Degraded(ReasonCode::Endpoint),
        ),
        (
            "a passing completion clears failing turns",
            vec![Turn(Some(ReasonCode::Endpoint)), Probe(Completion, None)],
            ok,
        ),
        (
            "key-only pass does not clear a failed completion",
            vec![
                Probe(Completion, Some(ReasonCode::Model)),
                Probe(KeyOnly, None),
            ],
            ProviderHealth::Degraded(ReasonCode::Model),
        ),
        (
            "an unclassified failure is degraded",
            vec![Turn(Some(ReasonCode::Unknown))],
            ProviderHealth::Degraded(ReasonCode::Unknown),
        ),
    ];
    for (name, steps, expected) in cases {
        assert_eq!(run(&steps), expected, "{name}");
    }
}

#[test]
fn health_a_status_change_reports_true_and_a_repeat_reports_false() {
    let mut snapshot = HealthSnapshot::default();
    assert!(
        snapshot.record_probe(Catalog, None, None, 10),
        "Unknown to Ok"
    );
    assert!(!snapshot.record_probe(Catalog, None, None, 20), "Ok to Ok");
    assert_eq!(
        snapshot.changed_at_ms, 10,
        "the change time is when the status changed"
    );
    assert!(snapshot.record_turn(fail(ReasonCode::Auth), 30));
    assert_eq!(snapshot.changed_at_ms, 30);
    assert_eq!(snapshot.last_ok_ms, Some(20));
    let note = snapshot.last_failure.unwrap();
    assert_eq!((note.reason, note.at_ms), (ReasonCode::Auth, 30));
}

#[test]
fn health_signed_out_is_its_own_state_and_survives_until_something_new_is_heard() {
    let mut snapshot = HealthSnapshot::default();
    snapshot.record_probe(Catalog, None, None, 1);
    assert!(snapshot.record_signed_out(2));
    assert_eq!(snapshot.health, ProviderHealth::SignedOut);
    assert!(snapshot.probes.is_empty() && snapshot.turn.is_none());
    assert!(!snapshot.record_signed_out(3), "already signed out");
    snapshot.record_probe(Catalog, None, None, 4);
    assert_eq!(
        snapshot.health,
        ProviderHealth::Ok,
        "signing back in recovers"
    );
}

#[test]
fn health_usable_states() {
    for (health, usable) in [
        (ProviderHealth::Unknown, true),
        (ProviderHealth::Ok, true),
        (ProviderHealth::Degraded(ReasonCode::Timeout), true),
        (ProviderHealth::Down(ReasonCode::Auth), false),
        (ProviderHealth::SignedOut, false),
        (ProviderHealth::Disabled, false),
    ] {
        assert_eq!(health.is_usable(), usable, "{health:?}");
    }
}

#[test]
fn health_wire_forms_are_stable() {
    let json = |h: ProviderHealth| serde_json::to_string(&h).unwrap();
    assert_eq!(json(ProviderHealth::Ok), r#"{"state":"ok"}"#);
    assert_eq!(
        json(ProviderHealth::Down(ReasonCode::Auth)),
        r#"{"state":"down","reason":"auth"}"#
    );
    assert_eq!(json(ProviderHealth::SignedOut), r#"{"state":"signed_out"}"#);
    let mut snapshot = HealthSnapshot::default();
    snapshot.record_probe(Completion, fail(ReasonCode::Model), Some(9), 5);
    snapshot.record_turn(None, 6);
    let back: HealthSnapshot =
        serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
    assert_eq!(back, snapshot);
}

// ---- the tracker -----------------------------------------------------------

struct Bed {
    tracker: HealthTracker,
    store: Arc<MemoryHealth>,
    events: Arc<MemoryEvents>,
    clock: FakeClock,
}

fn bed() -> Bed {
    let store = Arc::new(MemoryHealth::new());
    let events = Arc::new(MemoryEvents::new());
    let clock = FakeClock::new();
    Bed {
        tracker: HealthTracker::new(store.clone(), Arc::new(clock.clone()), events.clone()),
        store,
        events,
        clock,
    }
}

fn failure(reason: ReasonCode) -> Outcome {
    Outcome::Failed(ProviderFailure::new(reason, Retry::Never).with_status(500))
}

#[tokio::test]
async fn health_a_provider_nobody_has_heard_from_is_unknown() {
    let bed = bed();
    assert_eq!(
        bed.tracker.health(&scope(), &slug()).await.unwrap(),
        ProviderHealth::Unknown
    );
    assert_eq!(
        bed.tracker.snapshot(&scope(), &slug()).await.unwrap(),
        HealthSnapshot::default()
    );
}

#[tokio::test]
async fn health_turns_move_the_status_and_each_change_emits_one_event() {
    let bed = bed();
    let (s, p) = (scope(), slug());
    let ok = Outcome::Ok {
        latency: Duration::from_millis(40),
    };
    assert_eq!(
        bed.tracker.record_outcome(&s, &p, &ok).await.unwrap(),
        ProviderHealth::Ok
    );
    assert_eq!(
        bed.tracker.record_outcome(&s, &p, &ok).await.unwrap(),
        ProviderHealth::Ok
    );
    let status = bed
        .tracker
        .record_outcome(&s, &p, &failure(ReasonCode::Auth))
        .await
        .unwrap();
    assert_eq!(status, ProviderHealth::Down(ReasonCode::Auth));
    let events = bed.events.events();
    assert_eq!(
        events.len(),
        2,
        "Unknown to Ok, Ok to Down; the repeat says nothing"
    );
    assert!(matches!(
        &events[1],
        HubEvent::HealthChanged {
            from: ProviderHealth::Ok,
            to: ProviderHealth::Down(ReasonCode::Auth),
            ..
        }
    ));
    let snapshot = bed.tracker.snapshot(&s, &p).await.unwrap();
    assert_eq!(snapshot.last_failure.unwrap().status, Some(500));
}

#[tokio::test]
async fn health_the_wall_clock_stamps_the_signals() {
    let bed = bed();
    let (s, p) = (scope(), slug());
    bed.tracker
        .record_outcome(
            &s,
            &p,
            &Outcome::Ok {
                latency: Duration::ZERO,
            },
        )
        .await
        .unwrap();
    bed.clock.advance(Duration::from_secs(120));
    bed.tracker
        .record_outcome(&s, &p, &failure(ReasonCode::Endpoint))
        .await
        .unwrap();
    let snapshot = bed.tracker.snapshot(&s, &p).await.unwrap();
    assert_eq!(snapshot.last_ok_ms, Some(FakeClock::START_WALL_MS));
    assert_eq!(snapshot.changed_at_ms, FakeClock::START_WALL_MS + 120_000);
}

#[tokio::test]
async fn health_a_signed_out_failure_is_the_signed_out_state_not_a_red_error() {
    let bed = bed();
    let (s, p) = (scope(), slug());
    let status = bed
        .tracker
        .record_outcome(&s, &p, &failure(ReasonCode::SignedOut))
        .await
        .unwrap();
    assert_eq!(status, ProviderHealth::SignedOut);
    assert_eq!(
        bed.tracker.mark_signed_out(&s, &p).await.unwrap(),
        ProviderHealth::SignedOut
    );
    assert_eq!(
        bed.events.events().len(),
        1,
        "no event for staying signed out"
    );
}

#[tokio::test]
async fn health_forgetting_a_provider_returns_it_to_unknown() {
    let bed = bed();
    let (s, p) = (scope(), slug());
    bed.tracker
        .record_outcome(&s, &p, &failure(ReasonCode::Auth))
        .await
        .unwrap();
    bed.tracker.forget(&s, &p).await.unwrap();
    assert_eq!(
        bed.tracker.health(&s, &p).await.unwrap(),
        ProviderHealth::Unknown
    );
}

#[tokio::test]
async fn health_scopes_and_providers_are_independent() {
    let bed = bed();
    bed.tracker
        .record_outcome(&scope(), &slug(), &failure(ReasonCode::Auth))
        .await
        .unwrap();
    assert_eq!(
        bed.tracker
            .health(&ScopeKey::new("other"), &slug())
            .await
            .unwrap(),
        ProviderHealth::Unknown
    );
    assert_eq!(
        bed.tracker
            .health(&scope(), &Slug::parse("groq").unwrap())
            .await
            .unwrap(),
        ProviderHealth::Unknown
    );
}

#[tokio::test]
async fn health_a_failing_store_is_a_typed_error_not_a_silent_unknown() {
    let bed = bed();
    bed.store.set_unavailable(true);
    let error = bed.tracker.health(&scope(), &slug()).await.unwrap_err();
    assert!(matches!(
        error,
        crate::HubError::StoreUnreadable {
            port: crate::error::PortName::Health,
            ..
        }
    ));
    assert!(
        bed.tracker
            .record_outcome(&scope(), &slug(), &failure(ReasonCode::Auth))
            .await
            .is_err()
    );
    assert!(bed.tracker.forget(&scope(), &slug()).await.is_err());
    assert!(
        bed.tracker
            .mark_signed_out(&scope(), &slug())
            .await
            .is_err()
    );
    assert!(
        bed.events.events().is_empty(),
        "nothing is announced that was not stored"
    );
    let _ = PortError::Conflict;
}

#[tokio::test]
async fn health_concurrent_outcomes_do_not_lose_each_other() {
    let bed = Arc::new(bed());
    let calls: Vec<_> = (0..30)
        .map(|_| {
            let bed = bed.clone();
            async move {
                bed.tracker
                    .record_outcome(&scope(), &slug(), &failure(ReasonCode::Timeout))
                    .await
                    .unwrap()
            }
        })
        .collect();
    futures::future::join_all(calls).await;
    let snapshot = bed.tracker.snapshot(&scope(), &slug()).await.unwrap();
    assert_eq!(snapshot.consecutive_failures, 30, "every failure counted");
    assert_eq!(snapshot.health, ProviderHealth::Down(ReasonCode::Timeout));
    assert!(format!("{:?}", bed.tracker).contains("HealthTracker"));
}

#[tokio::test]
async fn health_a_probe_report_feeds_the_tracker_including_its_failure_and_latency() {
    use crate::probe::ProbeReport;
    let bed = bed();
    let (s, p) = (scope(), slug());
    let mut report = ProbeReport {
        depth: TestDepth::Catalog,
        failure: None,
        refusal: None,
        latency: Duration::from_millis(120),
        models: Vec::new(),
        proves_key: true,
        notes: Vec::new(),
    };
    assert_eq!(
        bed.tracker.record_probe(&s, &p, &report).await.unwrap(),
        ProviderHealth::Ok
    );
    let snapshot = bed.tracker.snapshot(&s, &p).await.unwrap();
    assert_eq!(snapshot.probes[&TestDepth::Catalog].latency_ms, Some(120));
    report.failure = Some(ProviderFailure::new(ReasonCode::Auth, Retry::Never).with_status(401));
    assert_eq!(
        bed.tracker.record_probe(&s, &p, &report).await.unwrap(),
        ProviderHealth::Down(ReasonCode::Auth)
    );
    let snapshot = bed.tracker.snapshot(&s, &p).await.unwrap();
    assert_eq!(snapshot.last_failure.unwrap().status, Some(401));
    assert!(!snapshot.probes[&TestDepth::Catalog].ok);
    assert_eq!(bed.events.events().len(), 2);
}

#[test]
fn health_a_stored_failure_with_no_reason_is_degraded_not_ok() {
    // Data written by another build can carry a failed signal with no reason.
    let json = r#"{"health":{"state":"unknown"},"changed_at_ms":0,
        "probes":{"catalog":{"ok":false,"reason":null,"at_ms":1,"latency_ms":null}}}"#;
    let mut snapshot: HealthSnapshot = serde_json::from_str(json).unwrap();
    snapshot.record_probe(TestDepth::KeyOnly, None, None, 2);
    assert_eq!(
        snapshot.health,
        ProviderHealth::Degraded(ReasonCode::Unknown)
    );
}

mod health_props {
    use proptest::prelude::*;

    use super::*;

    fn step() -> impl Strategy<Value = (u8, Option<u8>)> {
        (0u8..4, prop::option::of(0u8..6))
    }

    fn reason(n: u8) -> ReasonCode {
        [
            ReasonCode::Auth,
            ReasonCode::Quota,
            ReasonCode::Endpoint,
            ReasonCode::Timeout,
            ReasonCode::Model,
            ReasonCode::RateLimited,
        ][usize::from(n) % 6]
    }

    fn apply(snapshot: &mut HealthSnapshot, lane: u8, outcome: Option<u8>, now: u64) {
        let failure = outcome.map(|r| (reason(r), None));
        match lane {
            0 => snapshot.record_probe(TestDepth::KeyOnly, failure, None, now),
            1 => snapshot.record_probe(TestDepth::Catalog, failure, None, now),
            2 => snapshot.record_probe(TestDepth::Completion, failure, None, now),
            _ => snapshot.record_turn(failure, now),
        };
    }

    proptest! {
        /// Whatever came before, one success in every lane is `Ok`, and an
        /// account-level failure heard last is `Down`.
        #[test]
        fn health_prop_all_lanes_passing_is_ok_and_a_terminal_failure_heard_last_is_down(
            steps in proptest::collection::vec(step(), 0..40),
            terminal in 0u8..2,
            lane in 0u8..4,
        ) {
            let mut snapshot = HealthSnapshot::default();
            let mut now = 1;
            for (l, outcome) in &steps {
                apply(&mut snapshot, *l, *outcome, now);
                now += 1;
            }
            let mut healed = snapshot.clone();
            for l in 0..4 {
                apply(&mut healed, l, None, now);
                now += 1;
            }
            prop_assert_eq!(healed.health, ProviderHealth::Ok);
            prop_assert_eq!(healed.consecutive_failures, 0);

            apply(&mut snapshot, lane, Some(terminal), now);
            // Auth outranks Quota, so an older unresolved rejection elsewhere wins
            // over a newer quota failure; either way it is Down for an account reason.
            match (terminal, snapshot.health) {
                (0, health) => prop_assert_eq!(health, ProviderHealth::Down(ReasonCode::Auth)),
                (_, ProviderHealth::Down(ReasonCode::Auth | ReasonCode::Quota)) => {}
                (_, other) => prop_assert!(false, "{other:?}"),
            }
            // The snapshot always survives a JSON round trip.
            let back: HealthSnapshot = serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
            prop_assert_eq!(back, snapshot);
        }

        /// `Unknown` only ever describes a provider nobody has heard from.
        #[test]
        fn health_prop_a_heard_provider_is_never_unknown(steps in proptest::collection::vec(step(), 1..30)) {
            let mut snapshot = HealthSnapshot::default();
            for (n, (l, outcome)) in steps.iter().enumerate() {
                apply(&mut snapshot, *l, *outcome, n as u64 + 1);
            }
            prop_assert_ne!(snapshot.health, ProviderHealth::Unknown);
        }
    }
}
