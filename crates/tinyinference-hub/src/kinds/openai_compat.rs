//! [`OpenAiCompatDriver`]: the hosted OpenAI-compatible vendors and custom
//! endpoints.

use async_trait::async_trait;

use crate::catalog::{Fetched, parse_openai};
use crate::catalogue::{catalog_query, custom_descriptor, scoped_catalog_path};
use crate::descriptor::{ProviderDescriptor, Quirk};
use crate::error::{HubError, ProviderFailure, ReasonCode, Retry};
use crate::ports::{HubRequest, HubResponse};

use super::{DriverContext, KindDriver, Target};

/// Serves every kind whose listing is `GET {base}/models` in the OpenAI shape.
///
/// Two vendor rules live here because they are properties of *that host*, not of
/// the protocol: OpenRouter's account-scoped `/models/user` listing (falling
/// back to the public one on a `404`, loudly) and its `GET /key` key check.
#[derive(Clone, Debug)]
pub struct OpenAiCompatDriver {
    descriptor: ProviderDescriptor,
}

impl OpenAiCompatDriver {
    /// A driver for one catalogue row.
    pub fn for_descriptor(descriptor: ProviderDescriptor) -> Self {
        Self { descriptor }
    }

    /// A driver for operator-named OpenAI-compatible endpoints.
    pub fn custom() -> Self {
        Self::for_descriptor(custom_descriptor())
    }
}

/// Reads a successful listing response.
///
/// A body that ran past its cap is refused outright rather than parsed
/// truncated: a parser cannot tell "malformed" from "cut off", and treating the
/// second as the first is how a real, valid, hundreds-of-models catalog once
/// read as a healthy connection with zero models. The failure is `Unknown`, not
/// `Auth`: a catalog too large to read says nothing about the credential.
pub(super) fn read_listing(response: &HubResponse) -> Result<Fetched, HubError> {
    if response.truncated {
        return Err(HubError::Provider(
            ProviderFailure::new(ReasonCode::Unknown, Retry::Never)
                .with_truncated(true)
                .with_raw("the model list is larger than the size cap"),
        ));
    }
    let parsed = parse_openai(&response.body).map_err(HubError::Provider)?;
    Ok(Fetched::new(parsed.entries))
}

#[async_trait]
impl KindDriver for OpenAiCompatDriver {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    async fn key_check(&self, cx: &DriverContext<'_>, target: &Target<'_>) -> Result<(), HubError> {
        if !self.descriptor.has_quirk(Quirk::KeyCheckEndpoint) {
            return Err(HubError::Unsupported {
                op: crate::error::Operation::Test(crate::taxonomy::TestDepth::KeyOnly),
                kind: self.descriptor.kind.clone(),
            });
        }
        let request = HubRequest::get(format!("{}/key", target.base()));
        let request = cx.request(&self.descriptor, target, request);
        cx.call(self, request).await.map(|_| ())
    }

    async fn list_models(
        &self,
        cx: &DriverContext<'_>,
        target: &Target<'_>,
    ) -> Result<Fetched, HubError> {
        let base = target.base();
        let read = |url: String| {
            cx.request(
                &self.descriptor,
                target,
                HubRequest::get(url).with_body_cap(cx.policy.catalog_cap),
            )
        };
        // The account-scoped listing first, where the host has one. A 404 is the
        // look-alike case (a gateway answering on OpenRouter's own host, or
        // OpenRouter withdrawing the path): degrade to the public listing rather
        // than report the account has no models, but loudly, because the picker
        // is then offering models the account may not be able to reach.
        if let Some(path) = scoped_catalog_path(base, target.key().is_some()) {
            match cx.call(self, read(format!("{base}{path}"))).await {
                Ok(response) => return read_listing(&response),
                Err(HubError::Provider(failure)) if failure.status == Some(404) => {
                    tracing::warn!(
                        endpoint = %crate::endpoint::redact_endpoint(base),
                        "the account-scoped model list answered 404; falling back to the \
                         public list, which is not filtered by this key's permissions"
                    );
                }
                Err(other) => return Err(other),
            }
        }
        let response = cx
            .call(self, read(format!("{base}/models{}", catalog_query(base))))
            .await?;
        read_listing(&response)
    }
}
