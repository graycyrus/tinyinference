//! The latching rules: how signals become one [`ProviderHealth`].
//!
//! A snapshot keeps the **latest** result of each probe depth and of the real
//! turns. The status is a pure function of those, so it can be recomputed and
//! tested without any I/O:
//!
//! * a rejected credential (`auth`) or an exhausted account (`quota`) is `Down`
//!   at once, whatever else passes: nothing will work until the operator acts;
//! * failures alongside successes are `Degraded` (the partial-outage case: the
//!   catalog read fails while completions work);
//! * a run of [`FAILURES_TO_DOWN`] failed real turns is `Down`, however long ago
//!   a probe last passed, unless the failure is a rate limit or an unknown model
//!   (about the request, so `Degraded`);
//! * with nothing passing, an unreachable endpoint is `Down`; any other failure
//!   is `Degraded` until it repeats ([`FAILURES_TO_DOWN`] failed turns in a
//!   row, or several lanes failing) and then `Down`;
//! * a failing **chat** lane (a completion probe or a real turn) is superseded
//!   by a newer success in the other chat lane: a real turn that worked after a
//!   completion probe failed says chat works, and the reverse. Read-only lanes
//!   (key check, catalog) are never superseded by anything but their own next
//!   result: a working completion says nothing about a broken listing, and that
//!   partial outage is exactly what `Degraded` is for.

use crate::error::ReasonCode;
use crate::taxonomy::TestDepth;

use super::types::{FailureNote, HealthSnapshot, ProbeSignal, ProviderHealth, TurnSignal};

/// Consecutive failed turns after which a transient failure stops being
/// `Degraded` and becomes `Down`.
pub const FAILURES_TO_DOWN: u32 = 3;

/// How much a failure says the provider is unusable; higher wins.
fn severity(reason: ReasonCode) -> u8 {
    match reason {
        ReasonCode::Auth => 7,
        ReasonCode::Quota => 6,
        ReasonCode::Endpoint => 5,
        ReasonCode::Timeout => 4,
        ReasonCode::Model => 3,
        ReasonCode::RateLimited => 2,
        _ => 1,
    }
}

fn is_terminal(reason: ReasonCode) -> bool {
    matches!(reason, ReasonCode::Auth | ReasonCode::Quota)
}

/// Whether a repeating failure means the provider is *down*. A rate limit and an
/// unknown model are about this request, not about the provider: repeating them
/// says "slow down" or "pick another model", so they stay `Degraded` (a `Down`
/// provider is no longer routed to and would never produce the turn that clears
/// it).
fn repeats_mean_down(reason: ReasonCode) -> bool {
    !matches!(reason, ReasonCode::RateLimited | ReasonCode::Model)
}

/// One lane's latest result, for comparison.
#[derive(Clone, Copy)]
struct Lane {
    ok: bool,
    reason: Option<ReasonCode>,
    at_ms: u64,
    /// The probe depth, or `None` for a real turn (which is as deep as a
    /// completion).
    depth: Option<TestDepth>,
}

impl Lane {
    /// Whether this lane exercises chat (a completion probe or a real turn).
    fn is_chat(&self) -> bool {
        matches!(self.depth, None | Some(TestDepth::Completion))
    }

    /// Whether a success in this lane says a failure in `other` is over.
    ///
    /// A rejected credential or an exhausted account is `Down` "whatever else
    /// passes", so a passive success (a real turn) never clears one. Only a
    /// **deliberate** completion probe does: the operator re-testing after
    /// fixing the key or topping up is fresh, current evidence, and without it a
    /// `Down` provider that is no longer routed to would never produce another
    /// turn to clear itself. (Changing the key resets the snapshot outright.)
    fn supersedes(&self, other: &Lane) -> bool {
        let deliberate = self.depth == Some(TestDepth::Completion);
        self.ok
            && self.at_ms >= other.at_ms
            && self.is_chat()
            && other.is_chat()
            && (deliberate || !other.reason.is_some_and(is_terminal))
    }
}

impl HealthSnapshot {
    fn lanes(&self) -> Vec<Lane> {
        let mut lanes: Vec<Lane> = self
            .probes
            .iter()
            .map(|(depth, signal)| Lane {
                ok: signal.ok,
                reason: signal.reason,
                at_ms: signal.at_ms,
                depth: Some(*depth),
            })
            .collect();
        if let Some(turn) = &self.turn {
            lanes.push(Lane {
                ok: turn.ok,
                reason: turn.reason,
                at_ms: turn.at_ms,
                depth: None,
            });
        }
        lanes
    }

    /// Recomputes [`HealthSnapshot::health`] from the signals.
    ///
    /// Returns whether the status changed. Only called after a signal was
    /// recorded, so there is always at least one lane.
    fn refold(&mut self, now_ms: u64) -> bool {
        let lanes = self.lanes();
        let failing: Vec<&Lane> = lanes
            .iter()
            .filter(|lane| !lane.ok)
            .filter(|failed| !lanes.iter().any(|other| other.supersedes(failed)))
            .collect();
        let passing = lanes.iter().filter(|lane| lane.ok).count();
        let turns_failing = failing.iter().any(|lane| lane.depth.is_none());
        let next = match failing
            .iter()
            .filter_map(|lane| lane.reason)
            .max_by_key(|reason| severity(*reason))
        {
            None if failing.is_empty() => ProviderHealth::Ok,
            None => ProviderHealth::Degraded(ReasonCode::Unknown),
            Some(worst) if is_terminal(worst) => ProviderHealth::Down(worst),
            // Turns are what the operator cares about: a run of failed turns is
            // `Down` however long ago some probe last passed.
            Some(worst)
                if turns_failing
                    && self.consecutive_failures >= FAILURES_TO_DOWN
                    && repeats_mean_down(worst) =>
            {
                ProviderHealth::Down(worst)
            }
            Some(worst) if passing > 0 => ProviderHealth::Degraded(worst),
            Some(worst)
                if worst == ReasonCode::Endpoint
                    || (repeats_mean_down(worst)
                        && (self.consecutive_failures >= FAILURES_TO_DOWN
                            || failing.len() >= 2)) =>
            {
                ProviderHealth::Down(worst)
            }
            Some(worst) => ProviderHealth::Degraded(worst),
        };
        let changed = next != self.health;
        if changed {
            self.health = next;
            self.changed_at_ms = now_ms;
        }
        changed
    }

    /// Records the result of a probe at `depth`. Returns whether the status
    /// changed.
    pub fn record_probe(
        &mut self,
        depth: TestDepth,
        failure: Option<(ReasonCode, Option<u16>)>,
        latency_ms: Option<u64>,
        now_ms: u64,
    ) -> bool {
        // A passing completion shows chat works again, so an earlier run of
        // failed turns is over: without this the counter would survive the
        // recovery and one later blip would read as the fourth in a row.
        if depth == TestDepth::Completion && failure.is_none() {
            self.consecutive_failures = 0;
        }
        self.probes.insert(
            depth,
            ProbeSignal {
                ok: failure.is_none(),
                reason: failure.map(|(reason, _)| reason),
                at_ms: now_ms,
                latency_ms,
            },
        );
        self.note(failure, now_ms);
        self.refold(now_ms)
    }

    /// Records the result of a real turn. Returns whether the status changed.
    pub fn record_turn(&mut self, failure: Option<(ReasonCode, Option<u16>)>, now_ms: u64) -> bool {
        self.turn = Some(TurnSignal {
            ok: failure.is_none(),
            reason: failure.map(|(reason, _)| reason),
            at_ms: now_ms,
        });
        self.consecutive_failures = if failure.is_none() {
            0
        } else {
            self.consecutive_failures.saturating_add(1)
        };
        self.note(failure, now_ms);
        self.refold(now_ms)
    }

    /// Marks the provider signed out. Clears every signal: what was learned
    /// while signed in says nothing about now, and the next probe or turn
    /// decides. Returns whether the status changed.
    pub fn record_signed_out(&mut self, now_ms: u64) -> bool {
        self.probes.clear();
        self.turn = None;
        self.consecutive_failures = 0;
        let changed = self.health != ProviderHealth::SignedOut;
        if changed {
            self.health = ProviderHealth::SignedOut;
            self.changed_at_ms = now_ms;
        }
        changed
    }

    fn note(&mut self, failure: Option<(ReasonCode, Option<u16>)>, now_ms: u64) {
        match failure {
            None => self.last_ok_ms = Some(now_ms),
            Some((reason, status)) => {
                self.last_failure = Some(FailureNote {
                    reason,
                    status,
                    at_ms: now_ms,
                });
            }
        }
    }
}
