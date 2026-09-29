//! The model-list cache, ported from OpenCompany's `inference_models.rs` with
//! the semantics it earned in production:
//!
//! * **keyed on the endpoint, never on the credential.** A credential must not
//!   become a map key: hashing one to key a cache puts a derivative of it in
//!   process memory next to the data it guards;
//! * **partitioned by scope whenever a credential was sent.** An endpoint may
//!   publish an entitlement-scoped listing, so a base-URL-only key would hand
//!   one tenant's list to the next. A keyless read is a public property of the
//!   endpoint and stays shared;
//! * **a `401`/`403` is never remembered.** It is a fact about the key
//!   presented, not about the endpoint; memoising it would make a second tenant
//!   read the first's rejection and make a tenant that just rotated a bad key
//!   wait out the memo;
//! * success is fresh for an hour, a failure is remembered for a minute (so an
//!   unreachable provider costs one attempt a minute, not one per request);
//! * **single flight**: callers for one endpoint queue on its lock and re-check
//!   after acquiring it, so a hundred concurrent callers make one request;
//! * **stale on error**: when a refresh fails and an older list exists, the
//!   older list is served with a typed warning instead of an error, unless the
//!   failure was a rejected credential.
//!
//! Time comes from the [`Clock`] port, so an hour of expiry is a
//! `FakeClock::advance`, not a sleep.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;

use crate::endpoint::redact_endpoint;
use crate::error::{HubError, ProviderFailure, ReasonCode};
use crate::ids::ScopeKey;
use crate::ports::Clock;
use crate::taxonomy::CatalogShape;

use super::types::{Freshness, ModelEntry, ModelList};

/// How long a successful listing stays fresh.
pub const CATALOG_TTL: Duration = Duration::from_secs(60 * 60);

/// How long a *failed* read is remembered.
pub const FAILURE_TTL: Duration = Duration::from_secs(60);

/// How long an **empty** listing stays fresh. Short, because an empty listing
/// is usually a local runtime with nothing pulled yet, and the operator is
/// about to fix that.
pub const EMPTY_CATALOG_TTL: Duration = Duration::from_secs(60);

/// How long an expired listing is kept to serve as the stale fallback.
pub const STALE_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// The most endpoint slots kept; beyond this the least recently used go.
pub const MAX_SLOTS: usize = 1024;

/// What one cache slot is keyed on. Never contains a credential.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CatalogKey {
    scope: Option<ScopeKey>,
    endpoint: String,
    shape: CatalogShape,
}

impl CatalogKey {
    /// The key for reading `endpoint` in `shape`.
    ///
    /// `scope` is the caller's scope and is used **only when `credentialed`**:
    /// a read that presented nothing has nothing tenant-specific to leak, and
    /// sharing it keeps one fetch serving every scope on a public endpoint.
    /// Trailing slashes and surrounding space do not make a different endpoint.
    /// The shape is part of the key because one URL can be read two ways and
    /// must not serve a paged envelope to an OpenAI-shaped reader.
    pub fn new(scope: &ScopeKey, credentialed: bool, endpoint: &str, shape: CatalogShape) -> Self {
        Self {
            scope: credentialed.then(|| scope.clone()),
            endpoint: endpoint.trim().trim_end_matches('/').to_string(),
            shape,
        }
    }

    /// The scope this slot is partitioned by, if any.
    pub fn scope(&self) -> Option<&ScopeKey> {
        self.scope.as_ref()
    }
}

impl fmt::Debug for CatalogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogKey")
            .field("scope", &self.scope)
            .field("endpoint", &redact_endpoint(&self.endpoint))
            .field("shape", &self.shape)
            .finish()
    }
}

/// What a fetch closure returns.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct Fetched {
    /// The models, in the provider's order.
    pub models: Vec<ModelEntry>,
    /// The listing had more pages than one read follows.
    pub truncated: bool,
}

impl Fetched {
    /// A complete listing.
    pub fn new(models: Vec<ModelEntry>) -> Self {
        Self {
            models,
            truncated: false,
        }
    }
}

struct Entry {
    at: Instant,
    ttl: Duration,
    models: Vec<ModelEntry>,
    truncated: bool,
}

#[derive(Default)]
struct SlotState {
    entry: Option<Entry>,
    failure: Option<(Instant, ProviderFailure)>,
    last_used: Option<Instant>,
}

struct Slot {
    state: Mutex<SlotState>,
    /// Serialises fetches for this endpoint. Held across the whole fetch.
    fetch: AsyncMutex<()>,
    /// Bumped whenever a fetch completes, success or failure, so a caller that
    /// queued behind one can tell it need not fetch again.
    generation: AtomicU64,
}

impl Slot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::default()),
            fetch: AsyncMutex::new(()),
            generation: AtomicU64::new(0),
        }
    }

    fn state(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fresh(&self, now: Instant) -> Option<ModelList> {
        let state = self.state();
        let entry = state.entry.as_ref()?;
        (now.saturating_duration_since(entry.at) < entry.ttl).then(|| ModelList {
            models: entry.models.clone(),
            freshness: Freshness::Cached,
            truncated: entry.truncated,
        })
    }

    fn fresh_failure(&self, now: Instant) -> Option<ProviderFailure> {
        let state = self.state();
        let (at, failure) = state.failure.as_ref()?;
        (now.saturating_duration_since(*at) < FAILURE_TTL).then(|| failure.clone())
    }

    /// The remembered list (however old) as a stale answer, or the failure.
    ///
    /// An **empty** remembered list is not an answer worth serving: "no models
    /// (as of some time ago)" beside a warning hides the failure that matters.
    fn stale_or(&self, failure: ProviderFailure) -> Result<ModelList, HubError> {
        let state = self.state();
        match state
            .entry
            .as_ref()
            .filter(|entry| !entry.models.is_empty())
        {
            Some(entry) => Ok(ModelList {
                models: entry.models.clone(),
                freshness: Freshness::Stale { failure },
                truncated: entry.truncated,
            }),
            None => Err(HubError::Provider(failure)),
        }
    }

    fn touch(&self, now: Instant) {
        self.state().last_used = Some(now);
    }
}

/// Whether a failure is about the credential presented rather than the
/// endpoint. Such a failure is reported and never remembered.
fn is_credential_failure(failure: &ProviderFailure) -> bool {
    failure.reason == ReasonCode::Auth || matches!(failure.status, Some(401 | 403))
}

/// The catalog cache: one slot per [`CatalogKey`].
pub struct CatalogCache {
    clock: Arc<dyn Clock>,
    slots: Mutex<HashMap<CatalogKey, Arc<Slot>>>,
}

impl CatalogCache {
    /// An empty cache reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<CatalogKey, Arc<Slot>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slot(&self, key: CatalogKey) -> Arc<Slot> {
        let now = self.clock.now();
        let mut slots = self.slots();
        if !slots.contains_key(&key) && slots.len() >= MAX_SLOTS {
            Self::prune(&mut slots, now);
        }
        let slot = slots.entry(key).or_insert_with(|| Arc::new(Slot::new()));
        slot.touch(now);
        Arc::clone(slot)
    }

    /// Makes room: drops slots whose data is past the stale retention, then, if
    /// still full, the least recently used tenth.
    fn prune(slots: &mut HashMap<CatalogKey, Arc<Slot>>, now: Instant) {
        slots.retain(|_, slot| {
            let state = slot.state();
            let newest = state
                .entry
                .as_ref()
                .map(|e| e.at)
                .into_iter()
                .chain(state.failure.as_ref().map(|(at, _)| *at))
                .max();
            newest.is_none_or(|at| now.saturating_duration_since(at) < STALE_RETENTION)
        });
        if slots.len() >= MAX_SLOTS {
            let mut by_use: Vec<(CatalogKey, Option<Instant>)> = slots
                .iter()
                .map(|(key, slot)| (key.clone(), slot.state().last_used))
                .collect();
            by_use.sort_by_key(|(_, used)| *used);
            for (key, _) in by_use.into_iter().take(MAX_SLOTS / 10 + 1) {
                slots.remove(&key);
            }
        }
    }

    /// How many endpoint slots exist.
    pub fn len(&self) -> usize {
        self.slots().len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every slot read on behalf of `scope`, because its credential
    /// changed. A rotation changes what the endpoint will answer without
    /// changing anything in the (non-secret) key, so without this a tenant that
    /// rotated to a key with different entitlements would keep reading the
    /// previous credential's list for the rest of the hour. Keyless slots are
    /// shared and untouched: no credential change can alter them.
    pub fn evict_scope(&self, scope: &ScopeKey) {
        self.slots().retain(|key, _| key.scope() != Some(scope));
    }

    /// Drops every slot for `endpoint`, whatever the scope or shape (the row's
    /// endpoint was edited).
    pub fn evict_endpoint(&self, endpoint: &str) {
        let endpoint = endpoint.trim().trim_end_matches('/');
        self.slots().retain(|key, _| key.endpoint != endpoint);
    }

    /// Drops everything.
    pub fn clear(&self) {
        self.slots().clear();
    }

    /// Returns the list for `key`, calling `fetch` on a miss.
    ///
    /// `refresh` bypasses a fresh entry and a remembered failure (the
    /// operator's Refresh button); callers that queued behind another fetch
    /// still reuse its result rather than each making their own.
    ///
    /// # Errors
    ///
    /// Whatever `fetch` returned, when there is nothing older to serve or the
    /// failure was a rejected credential; the remembered failure when one is
    /// fresh and there is nothing older to serve.
    pub async fn read<F, Fut>(
        &self,
        key: CatalogKey,
        refresh: bool,
        fetch: F,
    ) -> Result<ModelList, HubError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Fetched, HubError>>,
    {
        let slot = self.slot(key);
        let generation_seen = slot.generation.load(Ordering::SeqCst);
        if !refresh {
            let now = self.clock.now();
            if let Some(list) = slot.fresh(now) {
                return Ok(list);
            }
            if let Some(failure) = slot.fresh_failure(now) {
                return slot.stale_or(failure);
            }
        }
        let _flight = slot.fetch.lock().await;
        // A fetch completed while this caller waited for the lock: use its
        // answer instead of asking the provider again.
        if slot.generation.load(Ordering::SeqCst) != generation_seen {
            let now = self.clock.now();
            if let Some(mut list) = slot.fresh(now) {
                list.freshness = Freshness::Cached;
                return Ok(list);
            }
            if let Some(failure) = slot.fresh_failure(now) {
                return slot.stale_or(failure);
            }
        }
        let outcome = fetch().await;
        let now = self.clock.now();
        match outcome {
            Ok(fetched) => {
                let ttl = if fetched.models.is_empty() {
                    EMPTY_CATALOG_TTL
                } else {
                    CATALOG_TTL
                };
                let list = ModelList {
                    models: fetched.models.clone(),
                    freshness: Freshness::Fresh,
                    truncated: fetched.truncated,
                };
                {
                    let mut state = slot.state();
                    state.entry = Some(Entry {
                        at: now,
                        ttl,
                        models: fetched.models,
                        truncated: fetched.truncated,
                    });
                    // The endpoint answers again; a stale "unreachable" would
                    // keep reporting it.
                    state.failure = None;
                }
                slot.generation.fetch_add(1, Ordering::SeqCst);
                Ok(list)
            }
            // About the presented key: reported to this caller, never
            // remembered, and never answered with an older list (a bad key must
            // show).
            Err(HubError::Provider(failure)) if is_credential_failure(&failure) => {
                Err(HubError::Provider(failure))
            }
            Err(HubError::Provider(failure)) => {
                slot.state().failure = Some((now, failure.clone()));
                slot.generation.fetch_add(1, Ordering::SeqCst);
                slot.stale_or(failure)
            }
            // A policy refusal, an unreadable store, a bad input: deterministic
            // or about something other than the endpoint, so not memoised.
            Err(other) => Err(other),
        }
    }
}

impl fmt::Debug for CatalogCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogCache")
            .field("slots", &self.len())
            .finish()
    }
}
