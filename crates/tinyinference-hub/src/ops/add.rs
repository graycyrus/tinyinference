//! Adding a provider: `add` (no probe) and `connect` (add, probe, roll back).
//!
//! Guards carried over from OpenCompany: G2 (a cloud preset's endpoint is not
//! typed), G4 (one row per kind when the host asks), G9 (the first provider
//! becomes the default), G11 and G12 (only a rejected credential rolls the add
//! back, and the previous key is restored), G14 and G15 (model and name
//! validation), G16 and G17 (endpoint policy).

use crate::catalogue::is_reserved_slug;
use crate::config::{DefaultChoice, HubConfig, ProviderDraft};
use crate::descriptor::ProviderRecord;
use crate::endpoint::normalize_local_endpoint;
use crate::error::{HubError, InputField, InvalidInput, Operation, PolicyViolation, describe};
use crate::hub::{ConnectOptions, Hub, Mutation, MutationStatus};
use crate::ids::{ModelId, ScopeKey, Slug, check_provider_name, check_slug, slugify};
use crate::policy::check_endpoint;
use crate::ports::HubEvent;
use crate::secret::Secret;
use crate::taxonomy::{ProviderGroup, TestDepth};

/// A validated draft: everything decided before anything is written.
pub(crate) struct AddPlan {
    pub(crate) kind: crate::ids::KindId,
    pub(crate) group: ProviderGroup,
    pub(crate) slug: Slug,
    pub(crate) label: String,
    pub(crate) base_url: String,
    pub(crate) model: Option<ModelId>,
    pub(crate) key: Option<Secret>,
    /// Whether a key is *required* to use the kind: a keyless add is saved
    /// unchecked only when one is.
    pub(crate) key_required: bool,
}

impl Hub {
    /// Validates a draft without touching any store. The guards that need the
    /// current configuration (a taken slug) run later, inside the change.
    pub(crate) fn plan_add(
        &self,
        op: Operation,
        draft: &ProviderDraft,
    ) -> Result<AddPlan, HubError> {
        let driver = self.driver(&draft.kind)?;
        let descriptor = driver.descriptor();
        let group = descriptor.group;
        if matches!(
            group,
            ProviderGroup::Cli | ProviderGroup::Managed | ProviderGroup::OAuthBacked
        ) {
            return Err(HubError::Unsupported {
                op,
                kind: descriptor.kind.clone(),
            });
        }

        let named = draft
            .label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty());
        if group == ProviderGroup::Custom && named.is_none() {
            return Err(HubError::Invalid(InvalidInput::Empty(
                InputField::ProviderName,
            )));
        }
        let label = named.map_or_else(|| descriptor.label.to_string(), str::to_string);
        check_provider_name(&label).map_err(|e| e.into_hub_error(&label))?;

        let kind_slug = descriptor.kind.as_str();
        let is_kind_row = group != ProviderGroup::Custom
            && named.is_none_or(|l| slugify(l) == kind_slug || l == descriptor.label);
        let slug_text = if is_kind_row {
            kind_slug.to_string()
        } else {
            slugify(&label)
        };
        check_slug(std::iter::empty::<&str>(), &slug_text, |s| {
            !(is_kind_row && s == kind_slug) && is_reserved_slug(s)
        })
        .map_err(|e| e.into_hub_error(&slug_text))?;
        let slug = Slug::parse(&slug_text).map_err(HubError::Invalid)?;

        let base_url = self.plan_endpoint(descriptor, draft.base_url.as_deref())?;

        let model = match &draft.model {
            Some(model) => Some(self.check_model(model)?),
            None => None,
        };
        let key = match &draft.key {
            Some(key) if key.expose().trim().is_empty() => {
                return Err(HubError::Invalid(InvalidInput::Empty(InputField::Key)));
            }
            Some(key) => Some(Secret::new(key.expose().trim())),
            None => None,
        };
        Ok(AddPlan {
            kind: descriptor.kind.clone(),
            group,
            slug,
            label,
            base_url,
            model,
            key,
            key_required: descriptor.needs_key && descriptor.auth.needs_credential(),
        })
    }

    /// The endpoint a record is saved with: the preset for a catalogue cloud
    /// kind (a typed URL is ignored, G2), the normalised URL for a local
    /// runtime, the typed URL for everything else; typed ones go through the
    /// endpoint policy.
    pub(crate) fn plan_endpoint(
        &self,
        descriptor: &crate::descriptor::ProviderDescriptor,
        typed: Option<&str>,
    ) -> Result<String, HubError> {
        let typed = typed.map(str::trim).filter(|t| !t.is_empty());
        if !descriptor.endpoint_editable {
            return descriptor
                .default_endpoint
                .map(str::to_string)
                .ok_or(HubError::Invalid(InvalidInput::Empty(InputField::Endpoint)));
        }
        let raw = typed
            .or(descriptor.default_endpoint)
            .ok_or(HubError::Invalid(InvalidInput::Empty(InputField::Endpoint)))?;
        let url = if descriptor.group == ProviderGroup::Local {
            normalize_local_endpoint(raw).ok_or(HubError::Invalid(InvalidInput::Malformed {
                field: InputField::Endpoint,
                reason: "that is not an http or https endpoint with a host",
            }))?
        } else {
            raw.to_string()
        };
        check_endpoint(&url, &self.inner.policy)
            .map_err(|refusal| HubError::Policy(PolicyViolation::from(refusal)))?;
        Ok(url)
    }

    /// Model-id validation (guard G14) with the host's reserved words.
    pub(crate) fn check_model(&self, model: &ModelId) -> Result<ModelId, HubError> {
        let reserved: Vec<&str> = self
            .inner
            .hub_policy
            .reserved_model_words
            .iter()
            .map(String::as_str)
            .collect();
        ModelId::parse_with_reserved(model.as_str(), &reserved).map_err(HubError::Invalid)
    }

    /// Inserts the planned record, enforcing the guards that read the
    /// configuration. Returns the record and whether it became the default.
    fn insert_planned(
        &self,
        config: &mut HubConfig,
        plan: &AddPlan,
        id: &str,
        make_default: bool,
    ) -> Result<(ProviderRecord, bool), HubError> {
        if config.contains(&plan.slug) {
            return Err(HubError::AlreadyExists {
                slug: plan.slug.clone(),
            });
        }
        if self.inner.hub_policy.one_row_per_kind
            && plan.group != ProviderGroup::Custom
            && let Some(existing) = config.providers.iter().find(|p| p.kind == plan.kind)
        {
            return Err(HubError::AlreadyExists {
                slug: existing.slug.clone(),
            });
        }
        let mut record = ProviderRecord::new(
            id,
            plan.slug.clone(),
            plan.label.clone(),
            plan.kind.clone(),
            plan.base_url.clone(),
        );
        record.model.clone_from(&plan.model);
        config.providers.push(record.clone());
        let operator_rows = config
            .providers
            .iter()
            .filter(|p| self.group_of(p) != ProviderGroup::Managed)
            .count();
        let mut became_default = false;
        if make_default {
            let model = plan
                .model
                .clone()
                .ok_or(HubError::Invalid(InvalidInput::Empty(InputField::ModelId)))?;
            config.default = DefaultChoice::Full {
                provider: plan.slug.clone(),
                model,
            };
            became_default = true;
        } else if config.default == DefaultChoice::Unset
            && operator_rows == 1
            && let Some(model) = plan.model.clone()
        {
            // Guard G9: the first provider ever becomes the default. Because
            // this runs inside the change, "still unset and exactly one row" is
            // re-checked against the version that is saved.
            config.default = DefaultChoice::Full {
                provider: plan.slug.clone(),
                model,
            };
            became_default = true;
        }
        Ok((record, became_default))
    }

    /// Adds a provider **without** checking it. Nothing is sent anywhere.
    ///
    /// The key, if any, is written to the credential store first and put back
    /// to what it was if the record cannot be saved.
    ///
    /// # Errors
    ///
    /// [`HubError::NotFound`] for an unknown kind, [`HubError::Unsupported`] for
    /// a CLI, OAuth or managed kind, [`HubError::Invalid`] and
    /// [`HubError::Policy`] for a draft that fails validation,
    /// [`HubError::AlreadyExists`] for a taken slug, and
    /// [`HubError::StoreUnreadable`] or [`HubError::Conflict`] from the stores.
    pub async fn add(&self, scope: &ScopeKey, draft: ProviderDraft) -> Result<Mutation, HubError> {
        let plan = self.plan_add(Operation::Add, &draft)?;
        let (record, _) = self.save_new(scope, &plan, false).await?;
        let config = self.read_config(scope).await.unwrap_or_default();
        let view = self.view(scope, &record, &config).await;
        Ok(Mutation {
            status: MutationStatus::Saved,
            note: format!("{} was added.", plan.label),
            probe: None,
            used_by: None,
            record: Some(view),
        })
    }

    /// Writes the key (remembering the old value) and the record; restores the
    /// key if the record cannot be saved.
    async fn save_new(
        &self,
        scope: &ScopeKey,
        plan: &AddPlan,
        make_default: bool,
    ) -> Result<(ProviderRecord, bool), HubError> {
        let previous = match &plan.key {
            Some(_) => Some(self.read_slot(scope, &plan.slug).await?),
            None => None,
        };
        if let Some(key) = &plan.key {
            self.write_slot(scope, &plan.slug, key.clone()).await?;
        }
        let id = self.new_record_id(&plan.slug);
        let mut inserted = None;
        let committed = self
            .transact(scope, |config| {
                inserted = Some(self.insert_planned(config, plan, &id, make_default)?);
                Ok(())
            })
            .await;
        match committed {
            Ok(_) => {
                let (record, became_default) = inserted.ok_or(HubError::Conflict)?;
                if plan.key.is_some() {
                    self.after_key_change(scope, &plan.slug, true).await;
                }
                self.inner.events.emit(HubEvent::ProviderAdded {
                    scope: scope.clone(),
                    slug: plan.slug.clone(),
                });
                Ok((record, became_default))
            }
            Err(error) => {
                if let Some(previous) = previous {
                    // The record was not saved: put the slot back so a failed
                    // add does not leave a key behind (or overwrite one).
                    self.restore_slot(scope, &plan.slug, previous).await?;
                }
                Err(error)
            }
        }
    }

    /// Adds a provider **and checks it**, rolling the add back when the
    /// provider rejects the credential.
    ///
    /// The check runs at `options.depth` (default: read the catalog) and is
    /// recorded as health. Only a rejected credential undoes the add (a local
    /// runtime also when nothing answers, or it times out), and never with
    /// `options.add_anyway`; an endpoint the policy refuses is undone whatever
    /// `add_anyway` says. When the add is undone the previous key is put back
    /// and the error carries the reason. A row saved without a key for a kind
    /// that needs one is saved unchecked, with a warning.
    ///
    /// # Errors
    ///
    /// Everything [`Hub::add`] returns, plus the provider's failure
    /// ([`HubError::Provider`], or [`HubError::Policy`] for a refused endpoint)
    /// when the add was undone.
    pub async fn connect(
        &self,
        scope: &ScopeKey,
        draft: ProviderDraft,
        options: ConnectOptions,
    ) -> Result<Mutation, HubError> {
        let plan = self.plan_add(Operation::Connect, &draft)?;
        let driver = self.driver(&plan.kind)?;
        if !driver.descriptor().supports_depth(options.depth) {
            return Err(HubError::Unsupported {
                op: Operation::Test(options.depth),
                kind: plan.kind.clone(),
            });
        }
        if options.depth == TestDepth::Completion && plan.model.is_none() {
            return Err(HubError::Invalid(InvalidInput::Empty(InputField::ModelId)));
        }
        if options.make_default && plan.model.is_none() {
            return Err(HubError::Invalid(InvalidInput::Empty(InputField::ModelId)));
        }
        let previous = match &plan.key {
            Some(_) => Some(self.read_slot(scope, &plan.slug).await?),
            None => None,
        };
        let (record, made_default) = self.save_new(scope, &plan, options.make_default).await?;

        // Is there anything to check with? A keyed kind saved without a key is
        // saved unchecked.
        let credential = match self.credential(scope, &record).await {
            Ok(credential) => credential,
            Err(error) => {
                self.undo_add(scope, &record, previous, made_default)
                    .await?;
                return Err(error);
            }
        };
        let probes = !plan.key_required || credential.key.is_some();
        if !probes {
            let config = self.read_config(scope).await.unwrap_or_default();
            let view = self.view(scope, &record, &config).await;
            return Ok(Mutation {
                status: MutationStatus::SavedWithWarning,
                note: format!("{} was added without a key; add one to use it.", plan.label),
                probe: None,
                used_by: None,
                record: Some(view),
            });
        }

        let report = match self
            .probe_record(
                scope,
                &record,
                options.depth,
                plan.model.as_ref(),
                &credential,
            )
            .await
        {
            Ok(report) => report,
            Err(error) => {
                self.undo_add(scope, &record, previous, made_default)
                    .await?;
                return Err(error);
            }
        };
        if let Some(failure) = &report.failure {
            let refused = report.refusal.is_some();
            if refused || (failure.rolls_back(plan.group) && !options.add_anyway) {
                self.undo_add(scope, &record, previous, made_default)
                    .await?;
                let error = report
                    .clone()
                    .into_result()
                    .err()
                    .unwrap_or(HubError::Provider(failure.clone()));
                return Err(error);
            }
        }
        let config = self.read_config(scope).await.unwrap_or_default();
        let view = self.view(scope, &record, &config).await;
        Ok(match &report.failure {
            None => Mutation {
                status: MutationStatus::Saved,
                note: format!("{} is connected.", plan.label),
                probe: Some(report),
                used_by: None,
                record: Some(view),
            },
            Some(failure) => Mutation {
                status: MutationStatus::SavedWithWarning,
                note: describe(failure.reason, &plan.label),
                probe: Some(report),
                used_by: None,
                record: Some(view),
            },
        })
    }

    /// Undoes an add: the record goes (and the default too, when this add made
    /// it), the key slot is put back to what it held, and what was learned
    /// about the new key is forgotten.
    async fn undo_add(
        &self,
        scope: &ScopeKey,
        record: &ProviderRecord,
        previous: Option<Option<Secret>>,
        made_default: bool,
    ) -> Result<(), HubError> {
        let slug = record.slug.clone();
        let removed = self
            .transact(scope, |config| {
                config.providers.retain(|p| p.slug != slug);
                if made_default
                    && matches!(&config.default, DefaultChoice::Full { provider, .. } if *provider == slug)
                {
                    config.default = DefaultChoice::Unset;
                }
                Ok(())
            })
            .await;
        if let Some(previous) = previous {
            self.restore_slot(scope, &slug, previous).await?;
        }
        self.inner.cache.evict_scope(scope);
        self.forget_health(scope, &slug).await;
        removed.map(|_| ())
    }
}
