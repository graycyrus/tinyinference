//! [`HealthTracker`]: health fed by probes and by real turns.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::error::{HubError, PortName, ProviderFailure, ReasonCode};
use crate::ids::{ScopeKey, Slug};
use crate::ports::{Clock, EventSink, HealthStore, HubEvent};
use crate::probe::ProbeReport;

use super::types::{HealthSnapshot, ProviderHealth};

/// One async lock per `(scope, provider)`.
type LockMap = HashMap<(ScopeKey, Slug), Arc<Mutex<()>>>;

/// How a real turn went, reported by the host after every turn so a provider
/// that passes probes but fails turns does not look green.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// The turn succeeded.
    Ok {
        /// How long it took.
        latency: Duration,
    },
    /// The turn failed, already classified.
    Failed(ProviderFailure),
}

/// Reads and updates health snapshots and tells the host when a status changes.
///
/// Updates are serialised in-process **per provider** so two turns finishing
/// together cannot lose one another's signal, while a slow store round trip for
/// one provider never delays another's.
pub struct HealthTracker {
    store: Arc<dyn HealthStore>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn EventSink>,
    locks: std::sync::Mutex<LockMap>,
}

impl HealthTracker {
    /// A tracker over `store`.
    pub fn new(
        store: Arc<dyn HealthStore>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            store,
            clock,
            events,
            locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The lock for one provider, created on first use.
    pub(super) fn lock_for(&self, scope: &ScopeKey, slug: &Slug) -> Arc<Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(locks.entry((scope.clone(), slug.clone())).or_default())
    }

    /// Gives back a lock taken with [`HealthTracker::lock_for`], and drops the
    /// map's entry when nobody else holds or waits on it (the map's copy and
    /// `lock` are the two references when idle). Without this the map would keep
    /// one entry per provider ever seen; dropping it under a waiter would hand
    /// the next caller a fresh lock and let two updates run at once.
    fn release_lock(&self, scope: &ScopeKey, slug: &Slug, lock: Arc<Mutex<()>>) {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (scope.clone(), slug.clone());
        if Arc::strong_count(&lock) <= 2
            && locks.get(&key).is_some_and(|held| Arc::ptr_eq(held, &lock))
        {
            locks.remove(&key);
        }
    }

    /// The snapshot for a provider (an empty one when nothing was recorded).
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store cannot be read.
    pub async fn snapshot(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
    ) -> Result<HealthSnapshot, HubError> {
        Ok(self
            .store
            .get(scope, slug)
            .await
            .map_err(|e| e.into_hub(PortName::Health))?
            .unwrap_or_default())
    }

    /// The folded status for a provider; `Unknown` when nothing was recorded.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store cannot be read.
    pub async fn health(&self, scope: &ScopeKey, slug: &Slug) -> Result<ProviderHealth, HubError> {
        Ok(self.snapshot(scope, slug).await?.health)
    }

    async fn update<F>(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        apply: F,
    ) -> Result<ProviderHealth, HubError>
    where
        F: FnOnce(&mut HealthSnapshot, u64) -> bool,
    {
        let lock = self.lock_for(scope, slug);
        let result = self.update_locked(&lock, scope, slug, apply).await;
        self.release_lock(scope, slug, lock);
        result
    }

    async fn update_locked<F>(
        &self,
        lock: &Mutex<()>,
        scope: &ScopeKey,
        slug: &Slug,
        apply: F,
    ) -> Result<ProviderHealth, HubError>
    where
        F: FnOnce(&mut HealthSnapshot, u64) -> bool,
    {
        let _serial = lock.lock().await;
        let mut snapshot = self.snapshot(scope, slug).await?;
        let from = snapshot.health;
        let changed = apply(&mut snapshot, self.clock.wall_ms());
        let to = snapshot.health;
        self.store
            .put(scope, slug, snapshot)
            .await
            .map_err(|e| e.into_hub(PortName::Health))?;
        if changed {
            self.events.emit(HubEvent::HealthChanged {
                scope: scope.clone(),
                slug: slug.clone(),
                from,
                to,
            });
        }
        Ok(to)
    }

    /// Records a probe's result. Returns the new status.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store fails.
    pub async fn record_probe(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        report: &ProbeReport,
    ) -> Result<ProviderHealth, HubError> {
        let failure = report.failure.as_ref().map(|f| (f.reason, f.status));
        let latency = u64::try_from(report.latency.as_millis()).ok();
        let depth = report.depth;
        self.update(scope, slug, move |snapshot, now| {
            snapshot.record_probe(depth, failure, latency, now)
        })
        .await
    }

    /// Records how a real turn went. A failure whose reason is `signed_out`
    /// marks the provider signed out. Returns the new status.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store fails.
    pub async fn record_outcome(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        outcome: &Outcome,
    ) -> Result<ProviderHealth, HubError> {
        match outcome {
            Outcome::Ok { .. } => {
                self.update(scope, slug, |snapshot, now| snapshot.record_turn(None, now))
                    .await
            }
            Outcome::Failed(failure) if failure.reason == ReasonCode::SignedOut => {
                self.mark_signed_out(scope, slug).await
            }
            Outcome::Failed(failure) => {
                let note = (failure.reason, failure.status);
                self.update(scope, slug, move |snapshot, now| {
                    snapshot.record_turn(Some(note), now)
                })
                .await
            }
        }
    }

    /// Marks a provider signed out (the managed credential chain is empty).
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store fails.
    pub async fn mark_signed_out(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
    ) -> Result<ProviderHealth, HubError> {
        self.update(scope, slug, |snapshot, now| snapshot.record_signed_out(now))
            .await
    }

    /// Forgets a provider's health: it was removed, or its key changed and what
    /// was learned with the old key no longer applies.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the health store fails.
    pub async fn forget(&self, scope: &ScopeKey, slug: &Slug) -> Result<(), HubError> {
        let lock = self.lock_for(scope, slug);
        let _serial = lock.lock().await;
        let forgotten = self
            .store
            .forget(scope, slug)
            .await
            .map_err(|e| e.into_hub(PortName::Health));
        // The provider is gone; its lock need not outlive it, but only if nobody
        // else holds or waits on it: dropping the entry under a waiter would
        // hand the next caller a fresh lock and let two updates run at once.
        // (`lock` and the map's own copy are the two references when idle.)
        drop(_serial);
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (scope.clone(), slug.clone());
        if locks
            .get(&key)
            .is_some_and(|held| Arc::strong_count(held) <= 2)
        {
            locks.remove(&key);
        }
        forgotten
    }
}

impl fmt::Debug for HealthTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthTracker").finish_non_exhaustive()
    }
}
