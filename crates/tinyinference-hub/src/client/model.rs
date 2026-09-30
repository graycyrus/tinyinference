//! [`HubModel`]: the `ChatModel` the hub hands out.

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;
use tinyinference_llm::error::{Error, Result};
use tinyinference_llm::model::{
    ChatModel, ModelProfile, ModelRequest, ModelResponse, ModelStream, ProviderError,
};

use crate::error::{HubError, ProviderFailure, ReasonCode};
use crate::health::Outcome;
use crate::hub::Hub;
use crate::ids::ScopeKey;
use crate::route::ResolvedTurn;
use crate::secret::Secret;

use super::factory::ModelSpec;

/// The legacy billing key OpenCompany and OpenHuman read (D4).
const LEGACY_USAGE_META: &str = "openhuman_usage_meta";
/// The neutral spelling.
const USAGE_META: &str = "usage_meta";

type Built = (Option<Secret>, std::sync::Arc<dyn ChatModel<()>>);

pub(super) struct HubModel {
    hub: Hub,
    scope: ScopeKey,
    turn: ResolvedTurn,
    inner: Mutex<Option<Built>>,
}

impl HubModel {
    pub(super) fn new(hub: Hub, scope: ScopeKey, turn: ResolvedTurn) -> Self {
        Self {
            hub,
            scope,
            turn,
            inner: Mutex::new(None),
        }
    }

    fn provider_error(&self, code: &str, message: &str, retryable: bool) -> Error {
        Error::Provider(Box::new(ProviderError {
            provider: self.turn.kind.to_string(),
            model: self.turn.model.as_ref().map(ToString::to_string),
            status: None,
            code: Some(code.to_string()),
            message: message.to_string(),
            retryable,
            ..ProviderError::default()
        }))
    }

    /// The model for this call: the credential chain is resolved **now**, and
    /// the underlying client is rebuilt only when the credential changed.
    async fn current(&self) -> Result<std::sync::Arc<dyn ChatModel<()>>> {
        let resolved = self
            .hub
            .chain_for(&self.turn.kind)
            .resolve(&self.scope, &self.turn.slug)
            .await;
        // The chain only ever fails as an unreadable source: not "no key", and not
        // a reason to fall through to a call without one.
        let key = match resolved {
            Ok(found) => found.map(|(secret, _)| secret),
            Err(_) => {
                return Err(self.provider_error(
                    "store_unreadable",
                    "the credential store could not be read",
                    true,
                ));
            }
        };
        let managed = self.turn.group == crate::taxonomy::ProviderGroup::Managed;
        if key.is_none() && managed {
            let _ = self
                .hub
                .inner
                .health
                .mark_signed_out(&self.scope, &self.turn.slug)
                .await;
            return Err(self.provider_error("signed_out", "signed out", false));
        }
        {
            let held = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((built_for, model)) = held.as_ref()
                && built_for.as_ref().map(Secret::expose) == key.as_ref().map(Secret::expose)
            {
                return Ok(model.clone());
            }
        }
        let extra = self.hub.request_headers(&self.turn);
        let responses_api = self.hub.serves_responses_api(&self.turn);
        let spec = ModelSpec {
            turn: &self.turn,
            key: key.as_ref().map(Secret::expose),
            extra_headers: &extra,
            responses_api,
        };
        let built = self
            .hub
            .inner
            .models
            .build(&spec)
            .map_err(|e| Error::Unsupported(e.to_string()))?;
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((key, built.clone()));
        Ok(built)
    }

    async fn observe_ok(&self, started: std::time::Instant) {
        let latency = self
            .hub
            .inner
            .clock
            .now()
            .saturating_duration_since(started);
        let _ = self
            .hub
            .record_outcome_lenient(&self.scope, &self.turn, Outcome::Ok { latency })
            .await;
    }

    async fn observe_err(&self, error: &Error) {
        let Some(failure) = failure_of(error) else {
            return;
        };
        if failure.reason == ReasonCode::Auth || failure.status == Some(401) {
            if let Ok(Some((_, origin))) = self
                .hub
                .chain_for(&self.turn.kind)
                .resolve(&self.scope, &self.turn.slug)
                .await
            {
                self.hub
                    .chain_for(&self.turn.kind)
                    .invalidate_origin(&self.scope, &origin);
            }
            // The cached client holds the rejected key: drop it.
            *self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        let _ = self
            .hub
            .record_outcome_lenient(&self.scope, &self.turn, Outcome::Failed(failure))
            .await;
    }
}

/// The provider failure inside an llm error, by reference (llm's `Error` is not
/// `Clone`, but what it carries is).
fn failure_of(error: &Error) -> Option<ProviderFailure> {
    let owned = match error {
        Error::Provider(provider) => Error::Provider(Box::new((**provider).clone())),
        Error::Model(text) => Error::Model(text.clone()),
        Error::Catalog(text) => Error::Catalog(text.clone()),
        Error::Unsupported(_) | Error::Validation(_) | Error::Serialization(_) => return None,
    };
    match HubError::from(owned) {
        HubError::Provider(failure) => Some(failure),
        _ => None,
    }
}

/// Mirrors the billing key both ways so the neutral and the legacy spellings
/// are both present.
fn mirror_usage_meta(response: &mut ModelResponse) {
    let Some(Value::Object(raw)) = response.raw.as_mut() else {
        return;
    };
    match (
        raw.get(USAGE_META).cloned(),
        raw.get(LEGACY_USAGE_META).cloned(),
    ) {
        (None, Some(legacy)) => {
            raw.insert(USAGE_META.to_string(), legacy);
        }
        (Some(neutral), None) => {
            raw.insert(LEGACY_USAGE_META.to_string(), neutral);
        }
        _ => {}
    }
}

#[async_trait]
impl ChatModel<()> for HubModel {
    fn profile(&self) -> Option<&ModelProfile> {
        None
    }

    fn cache_identity(&self) -> Option<String> {
        // Names the route, never a credential.
        Some(format!(
            "hub:{}:{}:{}",
            self.turn.slug,
            self.turn.kind,
            self.turn.model.as_ref().map_or("", |m| m.as_str())
        ))
    }

    async fn invoke(&self, state: &(), request: ModelRequest) -> Result<ModelResponse> {
        let model = self.current().await?;
        let started = self.hub.inner.clock.now();
        match model.invoke(state, request).await {
            Ok(mut response) => {
                mirror_usage_meta(&mut response);
                self.observe_ok(started).await;
                Ok(response)
            }
            Err(error) => {
                self.observe_err(&error).await;
                Err(error)
            }
        }
    }

    async fn stream(&self, state: &(), request: ModelRequest) -> Result<ModelStream> {
        let model = self.current().await?;
        let started = self.hub.inner.clock.now();
        match model.stream(state, request).await {
            Ok(stream) => {
                // Streaming health (time to first token, mid-stream failures) is
                // the router's; a stream that starts is recorded as a turn that
                // worked.
                self.observe_ok(started).await;
                Ok(stream)
            }
            Err(error) => {
                self.observe_err(&error).await;
                Err(error)
            }
        }
    }
}

impl fmt::Debug for HubModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubModel")
            .field("turn", &self.turn)
            .finish_non_exhaustive()
    }
}
