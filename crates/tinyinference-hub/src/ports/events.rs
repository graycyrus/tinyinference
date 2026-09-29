//! [`EventSink`] and [`HubEvent`]: what the hub tells its host about.

use std::fmt::Debug;

use crate::health::ProviderHealth;
use crate::ids::{ScopeKey, Slug};

/// Something the hub observed. Carries identifiers and counts only, never a
/// credential and never raw upstream text.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HubEvent {
    /// A provider's health changed.
    HealthChanged {
        /// The scope.
        scope: ScopeKey,
        /// The provider.
        slug: Slug,
        /// The previous health.
        from: ProviderHealth,
        /// The new health.
        to: ProviderHealth,
    },
    /// A model list was fetched from a provider.
    CatalogFetched {
        /// The scope.
        scope: ScopeKey,
        /// The endpoint, already redacted.
        endpoint: String,
        /// How many models it listed.
        models: usize,
    },
    /// A model list could not be refreshed and an older one was served.
    CatalogServedStale {
        /// The scope.
        scope: ScopeKey,
        /// The endpoint, already redacted.
        endpoint: String,
    },
}

/// Receives [`HubEvent`]s. The default drops them.
pub trait EventSink: Send + Sync + Debug {
    /// Delivers an event. Must not block: the hub calls it inline.
    fn emit(&self, event: HubEvent);
}
