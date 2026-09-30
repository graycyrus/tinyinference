//! Editing a saved provider.
//!
//! Guards: G2 (a cloud preset's endpoint is not typed), G3 (a credential does
//! not follow an endpoint to another origin: changing the origin with a stored
//! key needs the key entered again), G14 (model ids), G21 (entry zero is
//! read-only). A key rotation is never guarded (G5). The kind never changes.

use crate::descriptor::RecordOrigin;
use crate::error::{HubError, InputField, InvalidInput, NotFound, Operation};
use crate::hub::{Hub, Mutation, MutationStatus, ProviderPatch};
use crate::ids::{ScopeKey, Slug, check_provider_name};
use crate::policy::same_origin;
use crate::ports::HubEvent;
use crate::secret::Secret;
use crate::taxonomy::ProviderGroup;

impl Hub {
    /// Changes a saved provider's label, endpoint, model or key.
    ///
    /// The slug never changes (it addresses the key). A typed endpoint is
    /// ignored for a catalogue preset. Changing an endpoint to another origin
    /// while a stored key exists and no new key is supplied is refused, so a key
    /// cannot be sent somewhere its owner never chose. A new key drops the
    /// provider's health and the scope's cached catalogs.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`]; [`HubError::Unsupported`] for the read-only
    /// entry-zero record or a label/endpoint change on the managed provider;
    /// [`HubError::Invalid`] and [`HubError::Policy`] for a patch that fails
    /// validation; [`HubError::Conflict`] when the endpoint's origin was moved
    /// by another writer while a key-less origin change was being applied; and
    /// the stores' errors.
    pub async fn edit(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        patch: ProviderPatch,
    ) -> Result<Mutation, HubError> {
        let config = self.read_config(scope).await?;
        let record = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        if record.origin == RecordOrigin::EntryZero {
            return Err(HubError::Unsupported {
                op: Operation::Edit,
                kind: record.kind.clone(),
            });
        }
        let driver = self.driver(&record.kind)?;
        let descriptor = driver.descriptor();
        if descriptor.group == ProviderGroup::Managed
            && (patch.label.is_some() || patch.base_url.is_some())
        {
            return Err(HubError::Unsupported {
                op: Operation::Edit,
                kind: record.kind.clone(),
            });
        }

        let label = match patch.label.as_deref().map(str::trim) {
            Some(label) => {
                check_provider_name(label).map_err(|e| e.into_hub_error(label))?;
                Some(label.to_string())
            }
            None => None,
        };
        // Guard G2: a cloud preset's endpoint is data, so a typed one is ignored.
        let base_url = match patch.base_url.as_deref() {
            Some(typed) if descriptor.endpoint_editable => {
                Some(self.plan_endpoint(descriptor, Some(typed))?)
            }
            _ => None,
        };
        let model = match &patch.model {
            Some(model) => Some(self.check_model(model)?),
            None => None,
        };
        let key = match &patch.key {
            Some(key) if key.expose().trim().is_empty() => {
                return Err(HubError::Invalid(InvalidInput::Empty(InputField::Key)));
            }
            Some(key) => Some(Secret::new(key.expose().trim())),
            None => None,
        };

        // Everything below that touches the key slot, or moves the endpoint,
        // runs under the provider's lock: another key change or edit of the
        // same provider waits, and what this edit read is what it changes.
        let slot_guard = if key.is_some() || base_url.is_some() {
            Some(self.slot_lock(scope, slug).await)
        } else {
            None
        };
        // The record as it is now that nobody else can be changing this
        // provider's key or endpoint.
        let record = match &slot_guard {
            Some(_) => self
                .read_config(scope)
                .await?
                .provider(slug)
                .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
                .clone(),
            None => record,
        };
        let origin_changes = base_url
            .as_deref()
            .is_some_and(|new| !same_origin(&record.base_url, new));
        // Only an origin move without a new key reads the chain: a label rename or
        // a key rotation must not fail because a source is unreadable.
        if origin_changes && key.is_none() && self.credential(scope, &record).await?.key.is_some() {
            return Err(HubError::Invalid(InvalidInput::Malformed {
                field: InputField::Endpoint,
                reason: "changing the endpoint to another origin needs the key entered again",
            }));
        }

        // A key entered together with an origin move is for the NEW origin, so it
        // must never be usable against the old one, nor the old key against the
        // new one, at any moment a request can be built. The order that
        // guarantees it: clear the old key, move the record, write the new key.
        // Between those steps a keyed request fails closed (no key). The other
        // order (new key first, or record first with the old key still there)
        // has a window in which one origin is paired with the other's key
        // (finding 5.4).
        let move_with_key = origin_changes && key.is_some();
        let previous = match &key {
            Some(_) => Some(self.read_slot(scope, slug).await?),
            None => None,
        };
        if let Some(key) = &key {
            if move_with_key {
                if previous.as_ref().is_some_and(Option::is_some) {
                    self.delete_slot(scope, slug).await?;
                }
            } else {
                self.write_slot(scope, slug, key.clone()).await?;
            }
        }
        let validated_base = record.base_url.clone();
        let committed = self
            .transact(scope, |config| {
                let record = config
                    .provider_mut(slug)
                    .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?;
                if let Some(label) = &label {
                    record.label.clone_from(label);
                }
                if let Some(url) = &base_url {
                    // G3 again, against the record as it is now: an edit through
                    // another hub over this store may have moved the origin since
                    // the check above, and this move was validated against the
                    // old one.
                    if !same_origin(&record.base_url, &validated_base) {
                        return Err(HubError::Conflict);
                    }
                    record.base_url.clone_from(url);
                }
                if let Some(model) = &model {
                    record.model = Some(model.clone());
                }
                Ok(())
            })
            .await;
        let committed = match committed {
            Ok(committed) => committed,
            Err(error) => {
                // A record somebody removed while this ran took its key with it:
                // restoring the old one would resurrect it, and the new one just
                // written belongs to nothing. Anything else puts the old key back.
                if matches!(error, HubError::NotFound(_)) {
                    if key.is_some() && !move_with_key {
                        self.delete_slot(scope, slug).await.ok();
                    }
                } else if let Some(previous) = previous {
                    // The operation's own error is the reason; a failed restore
                    // must not replace it.
                    if let Err(restore) = self.restore_slot(scope, slug, previous).await {
                        tracing::warn!(%slug, ?restore, "could not restore the previous key");
                    }
                }
                return Err(error);
            }
        };
        if move_with_key && let Some(key) = &key {
            // The record is at the new origin with no key: now the key that was
            // entered for it. If it cannot be written, put the record back first
            // and the old key second, so the old key is never usable at the new
            // origin nor the reverse.
            if let Err(error) = self.write_slot(scope, slug, key.clone()).await {
                let back = self
                    .transact(scope, |config| {
                        if let Some(record) = config.provider_mut(slug)
                            && base_url.as_deref() == Some(record.base_url.as_str())
                        {
                            record.base_url.clone_from(&validated_base);
                        }
                        Ok(())
                    })
                    .await;
                match back {
                    Ok(_) => {
                        if let Some(previous) = previous
                            && let Err(restore) = self.restore_slot(scope, slug, previous).await
                        {
                            tracing::warn!(%slug, ?restore, "could not restore the previous key");
                        }
                    }
                    // The record stays at the new origin with no key: fail
                    // closed, and the old key stays cleared.
                    Err(undo) => {
                        tracing::warn!(%slug, ?undo, "could not move the endpoint back after a failed key write");
                    }
                }
                return Err(error);
            }
        }

        if key.is_some() {
            self.after_key_change(scope, slug, true).await;
        }
        if let Some(new) = &base_url
            && *new != record.base_url
        {
            // A different endpoint says nothing about what the old one said.
            self.inner.cache.evict_scope(scope);
            self.forget_health(scope, slug).await;
        }
        let changed = committed.changed || key.is_some();
        if changed {
            self.inner.events.emit(HubEvent::ProviderEdited {
                scope: scope.clone(),
                slug: slug.clone(),
            });
        }
        let config = self.read_config(scope).await?;
        let after = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        let view = self.view(scope, &after, &config).await;
        Ok(Mutation {
            status: if changed {
                MutationStatus::Saved
            } else {
                MutationStatus::Unchanged
            },
            note: if changed {
                format!("{} was updated.", after.label)
            } else {
                "Nothing changed.".to_string()
            },
            probe: None,
            used_by: None,
            record: Some(view),
        })
    }
}
