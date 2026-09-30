//! Moving a provider to another origin while entering its key: the one edit
//! whose two stores (the record and the key slot) must change in an order that
//! never pairs a credential with an origin it was not entered for.
//!
//! The order, under the provider's lock:
//!
//! 1. commit the record at the **new** origin and **disabled**, together with
//!    the rest of the patch;
//! 2. write the new key;
//! 3. commit the record's original `enabled` flag back.
//!
//! While the record is disabled nothing can be sent for it (a route to it fails
//! closed, and a model the host kept refuses with `stale_route`), whatever any
//! chain source (the stored slot, an environment variable, a keychain) would
//! answer, so between step 1 and step 3 no credential, old or new, can meet
//! either origin. Clearing the old slot first would not be enough: the other
//! sources of the chain would still answer at the new origin in that window.
//!
//! A failure rolls back in the only order that is safe at every instant: empty
//! the slot (so the new key never meets the old origin, nor the old key the new),
//! move the record back and re-enable it, then restore the old key. If the
//! record cannot be moved back it is left **disabled at the new origin with no
//! key**: unusable, and reported.

use crate::error::{HubError, NotFound};
use crate::hub::Hub;
use crate::ids::{ScopeKey, Slug};
use crate::secret::Secret;

/// Everything an origin move needs, gathered by `Hub::edit` under the lock.
pub(super) struct MovePlan<'a> {
    pub(super) label: Option<&'a str>,
    pub(super) model: Option<&'a crate::ids::ModelId>,
    /// The endpoint being moved to.
    pub(super) target: &'a str,
    /// The endpoint the move was validated against (G3 is re-checked against it
    /// inside the transaction).
    pub(super) validated_base: &'a str,
    pub(super) key: &'a Secret,
    /// The record's `enabled` flag before the move, restored at the end.
    pub(super) was_enabled: bool,
    /// What the slot held before, put back if the move is undone.
    pub(super) previous: Option<Secret>,
}

impl Hub {
    /// Performs the move described by `plan` and returns whether the first
    /// commit changed the document.
    ///
    /// # Errors
    ///
    /// Whatever the first commit returns (nothing was changed), or the failure
    /// that made the move be undone.
    pub(super) async fn move_origin_with_key(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        plan: MovePlan<'_>,
    ) -> Result<bool, HubError> {
        let committed = self
            .transact(scope, |config| {
                let record = config
                    .provider_mut(slug)
                    .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?;
                // G3 against the record as it is now: an edit through another hub
                // over this store may have moved the origin since this move was
                // validated.
                if !crate::policy::same_origin(&record.base_url, plan.validated_base) {
                    return Err(HubError::Conflict);
                }
                if let Some(label) = plan.label {
                    record.label = label.to_string();
                }
                if let Some(model) = plan.model {
                    record.model = Some(model.clone());
                }
                record.base_url = plan.target.to_string();
                record.enabled = false;
                Ok(())
            })
            .await?;

        if let Err(error) = self.write_slot(scope, slug, plan.key.clone()).await {
            self.undo_move(scope, slug, &plan).await;
            return Err(error);
        }
        if plan.was_enabled
            && let Err(error) = self
                .transact(scope, |config| {
                    if let Some(record) = config.provider_mut(slug)
                        && record.base_url == plan.target
                    {
                        record.enabled = true;
                    }
                    Ok(())
                })
                .await
        {
            // The move and the key are in place; only switching it back on
            // failed. Unusable rather than half-usable: say so.
            tracing::warn!(%slug, reason = %error.reason(), "the provider was moved and its key saved but it could not be switched back on");
            return Err(error);
        }
        Ok(committed.changed)
    }

    /// Undoes a move whose key could not be written, in the order that is safe
    /// at every instant (see the module docs). Best effort; each step's failure
    /// is logged and never replaces the reason the move failed.
    async fn undo_move(&self, scope: &ScopeKey, slug: &Slug, plan: &MovePlan<'_>) {
        // The slot may now hold the new key (a write that committed and then
        // timed out) or still the old one; either would meet the wrong origin
        // once the record is switched back on, so it goes first.
        if let Err(error) = self.delete_slot(scope, slug).await {
            tracing::warn!(%slug, reason = %error.reason(), "could not empty the key slot; the provider stays disabled at the new endpoint");
            self.forget_health(scope, slug).await;
            self.inner.cache.evict_scope(scope);
            return;
        }
        let back = self
            .transact(scope, |config| {
                if let Some(record) = config.provider_mut(slug)
                    && record.base_url == plan.target
                {
                    record.base_url = plan.validated_base.to_string();
                    record.enabled = plan.was_enabled;
                }
                Ok(())
            })
            .await;
        if let Err(error) = back {
            tracing::warn!(%slug, reason = %error.reason(), "could not move the endpoint back; the provider stays disabled at the new endpoint with no key");
            self.forget_health(scope, slug).await;
            self.inner.cache.evict_scope(scope);
            return;
        }
        if let Err(error) = self.restore_slot(scope, slug, plan.previous.clone()).await {
            tracing::warn!(%slug, reason = %error.reason(), "could not restore the previous key");
        }
    }
}
