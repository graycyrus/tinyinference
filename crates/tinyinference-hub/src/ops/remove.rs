//! Removing, disabling and re-keying a provider.
//!
//! Guards: G5 (clearing a key is in-use guarded, a rotation never is), G6
//! (removal is in-use guarded, deletes the key first and puts it back if the
//! record cannot be removed, and **never clears the default**), G7 (disabling is
//! in-use guarded and never scrubs a reference; a route to a disabled provider
//! fails closed), G21 (entry zero is read-only), G13 (a credential write drops
//! the scope's cached catalogs and the provider's health).

use crate::descriptor::RecordOrigin;
use crate::error::{HubError, InputField, InvalidInput, NotFound, Operation, UsedBy};
use crate::hub::{Confirm, Hub, Mutation, MutationStatus};
use crate::ids::{ScopeKey, Slug};
use crate::ports::HubEvent;
use crate::secret::Secret;
use crate::taxonomy::ProviderGroup;

impl Hub {
    /// Everything that references `slug`: the hub's own references, read from
    /// `config`, plus the host's.
    fn merge_used_by(config: &crate::config::HubConfig, slug: &Slug, host: &UsedBy) -> UsedBy {
        let mut used = Self::config_used_by(config, slug);
        for agent in &host.agents {
            if !used.agents.contains(agent) {
                used.agents.push(agent.clone());
            }
        }
        for workload in &host.workloads {
            if !used.workloads.contains(workload) {
                used.workloads.push(workload.clone());
            }
        }
        used.other.extend(host.other.iter().cloned());
        used.default_choice |= host.default_choice;
        used
    }

    /// Removes a provider and its key.
    ///
    /// Refused while anything references it (the default, an agent pin, a
    /// workload route, or something the host reports) unless the caller
    /// confirms; a confirmed removal leaves every reference in place, where it
    /// fails closed on the turn path. **The default is never cleared.** The key
    /// is deleted first and put back if the record cannot be removed.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`]; [`HubError::Unsupported`] for the managed
    /// provider and the read-only entry-zero record; [`HubError::InUse`]; and the
    /// stores' errors.
    pub async fn remove(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        confirm: Confirm,
    ) -> Result<Mutation, HubError> {
        let config = self.read_config(scope).await?;
        let record = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        if self.group_of(&record) == ProviderGroup::Managed
            || record.origin == RecordOrigin::EntryZero
        {
            return Err(HubError::Unsupported {
                op: Operation::Remove,
                kind: record.kind.clone(),
            });
        }
        let host = self.host_used_by(scope, slug).await?;
        let used = Self::merge_used_by(&config, slug, &host);
        if !used.is_empty() && !confirm.in_use {
            return Err(HubError::InUse(used));
        }
        let view = self.view(scope, &record, &config).await;

        // The key delete and the record's removal are one unit against every
        // other key operation on this provider (a concurrent add of the slug
        // must not find the slot half-cleared, nor a key write land in it).
        let _guard = self.slot_lock(scope, slug).await;
        let previous = self.read_slot(scope, slug).await?;
        if previous.is_some() {
            self.delete_slot(scope, slug).await?;
        }
        let committed = self
            .transact(scope, |config| {
                if config.provider(slug).is_none() {
                    return Err(HubError::NotFound(NotFound::Provider(slug.clone())));
                }
                let used = Self::merge_used_by(config, slug, &host);
                if !used.is_empty() && !confirm.in_use {
                    return Err(HubError::InUse(used));
                }
                config.providers.retain(|p| &p.slug != slug);
                Ok(used)
            })
            .await;
        let used = match committed {
            Ok(committed) => committed.value,
            Err(error) => {
                // A record somebody else removed while this ran took its key with
                // it: putting the key back would leave a slot no record owns.
                if !matches!(error, HubError::NotFound(_))
                    && let Some(previous) = previous
                    && let Err(restore) = self.restore_slot(scope, slug, Some(previous)).await
                {
                    tracing::warn!(%slug, ?restore, "could not restore the previous key");
                }
                return Err(error);
            }
        };
        self.inner.cache.evict_scope(scope);
        self.forget_health(scope, slug).await;
        self.inner.events.emit(HubEvent::ProviderRemoved {
            scope: scope.clone(),
            slug: slug.clone(),
        });
        Ok(Mutation {
            status: MutationStatus::Saved,
            note: format!("{} was removed.", record.label),
            probe: None,
            used_by: (!used.is_empty()).then_some(used),
            record: Some(view),
        })
    }

    /// Enables or disables a provider. Disabling is in-use guarded and never
    /// touches a reference: a route to a disabled provider fails closed.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`]; [`HubError::Unsupported`] for the read-only
    /// entry-zero record; [`HubError::InUse`] when disabling a referenced
    /// provider without confirmation; and the stores' errors.
    pub async fn set_enabled(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        on: bool,
        confirm: Confirm,
    ) -> Result<Mutation, HubError> {
        let config = self.read_config(scope).await?;
        let record = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        if record.origin == RecordOrigin::EntryZero {
            return Err(HubError::Unsupported {
                op: Operation::SetEnabled,
                kind: record.kind.clone(),
            });
        }
        if on
            && let Some(descriptor) = crate::catalogue::descriptor(record.kind.as_str())
            && !descriptor.endpoint_editable
            && let Some(preset) = descriptor.default_endpoint
            && !crate::policy::same_origin(&record.base_url, preset)
        {
            // An import that found a cloud row on another origin left it
            // disabled: switching it on would send its key there.
            return Err(HubError::Invalid(InvalidInput::Malformed {
                field: InputField::Endpoint,
                reason: "this cloud provider's stored endpoint is not its preset's; remove it and add it again",
            }));
        }
        let host = if on {
            UsedBy::default()
        } else {
            self.host_used_by(scope, slug).await?
        };
        let committed = self
            .transact(scope, |config| {
                if !on {
                    let used = Self::merge_used_by(config, slug, &host);
                    if !used.is_empty() && !confirm.in_use {
                        return Err(HubError::InUse(used));
                    }
                }
                let record = config
                    .provider_mut(slug)
                    .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?;
                record.enabled = on;
                Ok(())
            })
            .await?;
        if committed.changed {
            self.inner.events.emit(HubEvent::EnabledChanged {
                scope: scope.clone(),
                slug: slug.clone(),
                enabled: on,
            });
        }
        let config = self.read_config(scope).await?;
        let after = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        let view = self.view(scope, &after, &config).await;
        let used = Self::merge_used_by(&config, slug, &host);
        Ok(Mutation {
            status: if committed.changed {
                MutationStatus::Saved
            } else {
                MutationStatus::Unchanged
            },
            note: match (committed.changed, on) {
                (false, _) => "Nothing changed.".to_string(),
                (true, true) => format!("{} was enabled.", after.label),
                (true, false) => format!("{} was disabled.", after.label),
            },
            probe: None,
            used_by: (!on && !used.is_empty()).then_some(used),
            record: Some(view),
        })
    }

    /// Stores a key for a provider, replacing any earlier one. Never guarded:
    /// rotating a key is what an operator does to fix a problem. Nothing is sent
    /// to the provider; call [`Hub::test`] to check it.
    ///
    /// The provider's health and the scope's cached catalogs are dropped.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`]; [`HubError::Invalid`] for an empty key; and
    /// [`HubError::StoreUnreadable`].
    pub async fn set_key(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        key: Secret,
    ) -> Result<Mutation, HubError> {
        let key = Secret::new(key.expose().trim());
        if key.is_empty() {
            return Err(HubError::Invalid(InvalidInput::Empty(InputField::Key)));
        }
        let config = self.read_config(scope).await?;
        let record = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        if self.group_of(&record) == ProviderGroup::Cli {
            return Err(HubError::Unsupported {
                op: Operation::SetKey,
                kind: record.kind.clone(),
            });
        }
        // Under the provider's lock the record cannot be removed (or re-added)
        // between the check and the write: the check is repeated once the lock is
        // held, and the write happens inside it.
        let _guard = self.slot_lock(scope, slug).await;
        if self.read_config(scope).await?.provider(slug).is_none() {
            return Err(HubError::NotFound(NotFound::Provider(slug.clone())));
        }
        self.write_slot(scope, slug, key).await?;
        // Kept for a store shared with another hub, whose removal the lock does
        // not order: the key just written would be owned by nothing.
        let after = self.read_config(scope).await?;
        if after.provider(slug).is_none() {
            self.delete_slot(scope, slug).await.ok();
            return Err(HubError::NotFound(NotFound::Provider(slug.clone())));
        }
        self.after_key_change(scope, slug, true).await;
        let view = self.view(scope, &record, &after).await;
        Ok(Mutation {
            status: MutationStatus::Saved,
            note: format!("The key for {} was saved.", record.label),
            probe: None,
            used_by: None,
            record: Some(view),
        })
    }

    /// Deletes a provider's stored key. In-use guarded (the provider would stop
    /// working for whatever references it); the managed provider's key can be
    /// cleared, after which the rest of its chain answers.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`], [`HubError::InUse`] and the stores' errors.
    pub async fn clear_key(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
        confirm: Confirm,
    ) -> Result<Mutation, HubError> {
        let config = self.read_config(scope).await?;
        let record = config
            .provider(slug)
            .ok_or_else(|| HubError::NotFound(NotFound::Provider(slug.clone())))?
            .clone();
        let host = self.host_used_by(scope, slug).await?;
        let used = Self::merge_used_by(&config, slug, &host);
        if !used.is_empty() && !confirm.in_use {
            return Err(HubError::InUse(used));
        }
        let _guard = self.slot_lock(scope, slug).await;
        let had_key = self.read_slot(scope, slug).await?.is_some();
        if had_key {
            self.delete_slot(scope, slug).await?;
            self.after_key_change(scope, slug, false).await;
        }
        let view = self.view(scope, &record, &config).await;
        Ok(Mutation {
            status: if had_key {
                MutationStatus::Saved
            } else {
                MutationStatus::Unchanged
            },
            note: if had_key {
                format!("The key for {} was removed.", record.label)
            } else {
                "There was no key to remove.".to_string()
            },
            probe: None,
            used_by: (had_key && !used.is_empty()).then_some(used),
            record: Some(view),
        })
    }
}
