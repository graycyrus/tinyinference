//! Shared plumbing for the operations: drivers, credentials, views, hooks.

use std::sync::{Arc, PoisonError};
use std::sync::atomic::Ordering;

use crate::catalogue;
use crate::config::HubConfig;
use crate::credential::{CredentialChain, CredentialOrigin};
use crate::descriptor::{ProviderDescriptor, ProviderRecord};
use crate::error::{HubError, NotFound, ProviderFailure, ReasonCode, UsedBy};
use crate::health::ProviderHealth;
use crate::ids::{KindId, ScopeKey, Slug};
use crate::kinds::{DriverContext, KindDriver};
use crate::ports::HubEvent;
use crate::secret::Secret;
use crate::taxonomy::{AuthStyle, ProviderGroup};

use super::Hub;
use super::types::{KeyState, ProviderView};

/// A resolved credential and the source that supplied it.
pub(crate) struct Credential {
    pub(crate) key: Option<Secret>,
    pub(crate) origin: Option<CredentialOrigin>,
}

impl Hub {
    pub(crate) fn driver(&self, kind: &KindId) -> Result<Arc<dyn KindDriver>, HubError> {
        self.inner
            .registry
            .get(kind)
            .ok_or_else(|| HubError::NotFound(NotFound::Kind(kind.clone())))
    }

    pub(crate) fn chain_for(&self, kind: &KindId) -> &CredentialChain {
        self.inner
            .chains
            .get(kind)
            .unwrap_or(&self.inner.default_chain)
    }

    /// The header policy for a provider presented with `auth`: the built-in one
    /// plus the header a custom auth style carries the credential in, so a
    /// redirect to another origin strips it too.
    pub(crate) fn headers_for(&self, auth: &AuthStyle) -> crate::policy::HeaderPolicy {
        self.inner.headers.clone().with_auth(auth)
    }

    /// The driver context every request is made with.
    pub(crate) fn cx<'a>(&'a self, headers: &'a crate::policy::HeaderPolicy) -> DriverContext<'a> {
        let cx = DriverContext::new(
            &*self.inner.http,
            &self.inner.policy,
            &*self.inner.clock,
            headers,
        );
        match &self.inner.product {
            Some(product) => cx.with_product(product),
            None => cx,
        }
    }

    /// The auth style a record is presented with.
    pub(crate) fn auth_of(record: &ProviderRecord, descriptor: &ProviderDescriptor) -> AuthStyle {
        record
            .auth_override
            .clone()
            .unwrap_or_else(|| descriptor.auth.clone())
    }

    /// Runs the record's credential chain.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when a source cannot be read. Never treated
    /// as "no key".
    pub(crate) async fn credential(
        &self,
        scope: &ScopeKey,
        record: &ProviderRecord,
    ) -> Result<Credential, HubError> {
        let resolved = self
            .chain_for(&record.kind)
            .resolve(scope, &record.slug)
            .await?;
        Ok(match resolved {
            Some((key, origin)) => Credential {
                key: Some(key),
                origin: Some(origin),
            },
            None => Credential {
                key: None,
                origin: None,
            },
        })
    }

    pub(crate) fn group_of(&self, record: &ProviderRecord) -> ProviderGroup {
        self.inner.registry.get(&record.kind).map_or_else(
            || catalogue::group_of(record.kind.as_str()),
            |d| d.descriptor().group,
        )
    }

    pub(crate) async fn key_state(&self, scope: &ScopeKey, record: &ProviderRecord) -> KeyState {
        match self.credential(scope, record).await {
            Ok(Credential {
                origin: Some(origin),
                ..
            }) => KeyState::Configured(origin),
            Ok(_) => KeyState::Missing,
            Err(_) => KeyState::Unreadable,
        }
    }

    /// A provider as an operator sees it. Never fails: an unreadable credential
    /// store is shown as such.
    pub(crate) async fn view(
        &self,
        scope: &ScopeKey,
        record: &ProviderRecord,
        config: &HubConfig,
    ) -> ProviderView {
        let is_default = match &config.default {
            crate::config::DefaultChoice::Unset => false,
            crate::config::DefaultChoice::ProviderOnly { provider }
            | crate::config::DefaultChoice::Full { provider, .. } => *provider == record.slug,
        };
        ProviderView {
            group: self.group_of(record),
            kind_label: self.inner.registry.get(&record.kind).map_or_else(
                || record.kind.to_string(),
                |d| d.descriptor().label.to_string(),
            ),
            key: self.key_state(scope, record).await,
            is_default,
            record: record.clone(),
        }
    }

    /// What a provider's health reads as to an operator (see
    /// [`ProviderStatus::health`](super::ProviderStatus)).
    pub(crate) async fn effective_health(
        &self,
        scope: &ScopeKey,
        record: &ProviderRecord,
        key: &KeyState,
    ) -> Result<(ProviderHealth, crate::health::HealthSnapshot), HubError> {
        let snapshot = self.inner.health.snapshot(scope, &record.slug).await?;
        let group = self.group_of(record);
        let offline_excluded = !self.inner.policy.allow_public
            && !matches!(group, ProviderGroup::Local | ProviderGroup::Cli);
        let health = if !record.enabled || offline_excluded {
            ProviderHealth::Disabled
        } else if group == ProviderGroup::Managed && matches!(key, KeyState::Missing) {
            ProviderHealth::SignedOut
        } else {
            snapshot.health
        };
        Ok((health, snapshot))
    }

    /// Forgets a provider's health **after** the change that made it stale has
    /// been committed.
    ///
    /// Best effort by design: the operation already succeeded, and health is
    /// derived data. Reporting a failed operation because the health store had an
    /// outage would leave the caller believing a committed change did not happen.
    /// A health store that is down is reported by the reads that need it
    /// (`health`, `status`).
    pub(crate) async fn forget_health(&self, scope: &ScopeKey, slug: &Slug) {
        self.inner
            .retests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(scope.clone(), slug.clone()));
        if let Err(error) = self.inner.health.forget(scope, slug).await {
            tracing::warn!(%slug, reason = %error.reason(), "could not forget a provider's health");
        }
    }

    /// The hooks every credential change runs: the provider's health is
    /// forgotten (what was learned about the old credential says nothing about
    /// the new one) and the scope's cached catalogs are dropped.
    pub(crate) async fn after_key_change(&self, scope: &ScopeKey, slug: &Slug, present: bool) {
        self.inner.cache.evict_scope(scope);
        self.forget_health(scope, slug).await;
        self.inner.events.emit(HubEvent::KeyChanged {
            scope: scope.clone(),
            slug: slug.clone(),
            present,
        });
    }

    /// A rejected credential: tell the source that supplied it so a host that
    /// caches (a rotating token) refreshes instead of replaying it.
    pub(crate) fn note_rejection(
        &self,
        scope: &ScopeKey,
        kind: &KindId,
        origin: Option<&CredentialOrigin>,
        failure: &ProviderFailure,
    ) {
        if let Some(origin) = origin
            && (failure.reason == ReasonCode::Auth || failure.status == Some(401))
        {
            self.chain_for(kind).invalidate_origin(scope, origin);
        }
    }

    /// What references a provider: the default, the hub's own pins and routes,
    /// and whatever the host's [`UsageQuery`](crate::ports::UsageQuery) adds.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] when the host cannot say: a guard that
    /// cannot see must not assume nothing is in use.
    pub(crate) async fn host_used_by(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
    ) -> Result<UsedBy, HubError> {
        match &self.inner.usage {
            Some(usage) => usage
                .used_by(scope, slug)
                .await
                .map_err(|e| e.into_hub(crate::error::PortName::Config)),
            None => Ok(UsedBy::default()),
        }
    }

    /// The references inside the hub's own configuration.
    pub(crate) fn config_used_by(config: &HubConfig, slug: &Slug) -> UsedBy {
        use crate::config::DefaultChoice;
        use crate::route::RouteTarget;
        UsedBy {
            default_choice: match &config.default {
                DefaultChoice::Unset => false,
                DefaultChoice::ProviderOnly { provider } | DefaultChoice::Full { provider, .. } => {
                    provider == slug
                }
            },
            agents: config
                .agent_pins
                .iter()
                .filter(|(_, choice)| &choice.provider == slug)
                .map(|(agent, _)| agent.clone())
                .collect(),
            workloads: config
                .workload_routes
                .iter()
                .filter(|(_, route)| matches!(&route.target, RouteTarget::Provider(s) if s == slug))
                .map(|(workload, _)| workload.clone())
                .collect(),
            other: Vec::new(),
        }
    }

    /// A deterministic opaque record id.
    pub(crate) fn new_record_id(&self, slug: &Slug) -> String {
        use std::hash::{Hash, Hasher};
        let n = self.inner.ids.fetch_add(1, Ordering::SeqCst);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (slug.as_str(), self.inner.clock.wall_ms(), n).hash(&mut hasher);
        let a = hasher.finish();
        (a, n).hash(&mut hasher);
        format!("prv_{a:016x}{:016x}", hasher.finish())
    }
}

impl Hub {
    /// The current value of a provider's key slot: `Ok(None)` is "no key",
    /// `Err` is "could not find out" and stops the caller before it writes.
    pub(crate) async fn read_slot(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
    ) -> Result<Option<Secret>, HubError> {
        self.inner
            .credentials
            .get(scope, &slug.key_slot())
            .await
            .map_err(|e| e.into_hub(crate::error::PortName::Credentials))
    }

    pub(crate) async fn write_slot(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        key: Secret,
    ) -> Result<(), HubError> {
        self.inner
            .credentials
            .set(scope, &slug.key_slot(), key)
            .await
            .map_err(|e| e.into_hub(crate::error::PortName::Credentials))
    }

    pub(crate) async fn delete_slot(&self, scope: &ScopeKey, slug: &Slug) -> Result<(), HubError> {
        self.inner
            .credentials
            .delete(scope, &slug.key_slot())
            .await
            .map_err(|e| e.into_hub(crate::error::PortName::Credentials))
    }

    /// Puts a slot back to what it held before an operation touched it.
    pub(crate) async fn restore_slot(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        previous: Option<Secret>,
    ) -> Result<(), HubError> {
        match previous {
            Some(key) => self.write_slot(scope, slug, key).await,
            None => self.delete_slot(scope, slug).await,
        }
    }
}
