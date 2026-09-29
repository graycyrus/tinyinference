//! What a driver is handed to do its work: the ports, and the provider being
//! talked to.

use std::fmt;

use crate::catalogue::ANTHROPIC_VERSION;
use crate::descriptor::ProviderDescriptor;
use crate::error::{HubError, ProviderFailure, TransportCondition, classify_transport};
use crate::ids::{KindId, ModelId, Slug};
use crate::policy::{EndpointPolicy, HeaderPolicy};
use crate::ports::{Clock, Http, HubRequest, HubResponse};
use crate::secret::Secret;
use crate::taxonomy::{AuthStyle, ProviderGroup};

use super::KindDriver;

/// The ports and policies one operation runs under. Cheap to build; borrows
/// everything.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct DriverContext<'a> {
    /// The transport.
    pub http: &'a dyn Http,
    /// The endpoint policy every request is held to.
    pub policy: &'a EndpointPolicy,
    /// Time.
    pub clock: &'a dyn Clock,
    /// Which headers may go where.
    pub headers: &'a HeaderPolicy,
    /// The product-identity header (`name`, `value`), sent only to first-party
    /// hosts (guard G26). `None` means the host sends none.
    pub product: Option<&'a (String, String)>,
}

impl<'a> DriverContext<'a> {
    /// A context with no product header.
    pub fn new(
        http: &'a dyn Http,
        policy: &'a EndpointPolicy,
        clock: &'a dyn Clock,
        headers: &'a HeaderPolicy,
    ) -> Self {
        Self {
            http,
            policy,
            clock,
            headers,
            product: None,
        }
    }

    /// This context with a product-identity header.
    #[must_use]
    pub fn with_product(mut self, product: &'a (String, String)) -> Self {
        self.product = Some(product);
        self
    }
}

impl fmt::Debug for DriverContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverContext")
            .field("policy", self.policy)
            .field("product_header", &self.product.map(|(name, _)| name))
            .finish()
    }
}

/// The provider an operation is about: everything a driver needs and nothing it
/// should not have (no record, no store).
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct Target<'a> {
    /// The routing key, named in `SignedOut` and in logs.
    pub slug: &'a Slug,
    /// The catalogue kind.
    pub kind: &'a KindId,
    /// The group.
    pub group: ProviderGroup,
    /// The endpoint, normalised.
    pub base_url: &'a str,
    /// How the credential is presented.
    pub auth: &'a AuthStyle,
    /// The credential, if one resolved.
    pub credential: Option<&'a Secret>,
    /// The model to use for a completion ping.
    pub model: Option<&'a ModelId>,
}

impl fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("slug", self.slug)
            .field("kind", self.kind)
            .field("base_url", &crate::endpoint::redact_endpoint(self.base_url))
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl Target<'_> {
    /// The endpoint without a trailing slash.
    pub fn base(&self) -> &str {
        self.base_url.trim().trim_end_matches('/')
    }

    /// The credential, trimmed, when it is non-empty.
    pub fn key(&self) -> Option<&str> {
        self.credential
            .map(|secret| secret.expose().trim())
            .filter(|key| !key.is_empty())
    }
}

/// Adds the header(s) `auth` uses to present `key`, returning whether a
/// credential was attached.
///
/// A missing or blank key attaches nothing (sending an empty header is worse
/// than sending none), and [`AuthStyle::None`] attaches nothing even when a key
/// is supplied: a keyless local runtime may be *given* a key, but Ollama in
/// particular answers spurious `401`s to one.
pub(crate) fn apply_auth(
    headers: &mut Vec<(String, String)>,
    auth: &AuthStyle,
    key: Option<&str>,
) -> bool {
    let Some(key) = key.map(str::trim).filter(|k| !k.is_empty()) else {
        return false;
    };
    match auth {
        AuthStyle::None => return false,
        AuthStyle::Bearer | AuthStyle::SessionJwt => {
            headers.push(("authorization".to_string(), format!("Bearer {key}")));
        }
        AuthStyle::XApiKey => headers.push(("x-api-key".to_string(), key.to_string())),
        AuthStyle::Anthropic => {
            headers.push(("x-api-key".to_string(), key.to_string()));
            headers.push((
                "anthropic-version".to_string(),
                ANTHROPIC_VERSION.to_string(),
            ));
        }
        AuthStyle::Custom(name) => {
            let name = name.trim();
            if name.is_empty() {
                return false;
            }
            headers.push((name.to_ascii_lowercase(), key.to_string()));
        }
    }
    true
}

impl DriverContext<'_> {
    /// A request to `url` for `target`: credential in the style the provider
    /// expects, the descriptor's extra headers, and the product header only if
    /// `url` is first-party. `credentialed` is set from what was attached, so
    /// the transport applies the cleartext and cross-origin rules.
    pub(crate) fn request(
        &self,
        descriptor: &ProviderDescriptor,
        target: &Target<'_>,
        mut request: HubRequest,
    ) -> HubRequest {
        request.credentialed = apply_auth(&mut request.headers, target.auth, target.key());
        for (name, value) in descriptor.extra_headers {
            request
                .headers
                .push(((*name).to_string(), (*value).to_string()));
        }
        if let Some((name, value)) = self.product {
            let mut product = vec![(name.clone(), value.clone())];
            self.headers
                .strip_product_header_unless_first_party(&mut product, &request.url);
            request.headers.extend(product);
        }
        request.timeout = self.policy.timeout;
        request
    }

    /// Sends `request`, turning a transport failure into a hub error and a
    /// non-2xx answer into a classified [`ProviderFailure`].
    ///
    /// A failure body is cut to the policy's failure cap before it is
    /// classified (an error message is never legitimately large), and a
    /// redirect the transport did not follow is an endpoint failure: the
    /// endpoint did not serve where it said it would.
    pub(crate) async fn call<D: KindDriver + ?Sized>(
        &self,
        driver: &D,
        request: HubRequest,
    ) -> Result<HubResponse, HubError> {
        let response = self
            .http
            .send(request, self.policy)
            .await
            .map_err(crate::ports::HttpError::into_hub)?;
        if response.is_success() {
            return Ok(response);
        }
        if (300..400).contains(&response.status) {
            return Err(HubError::Provider(
                classify_transport(
                    TransportCondition::RedirectRefused,
                    "a redirect was not followed",
                )
                .with_status(response.status),
            ));
        }
        let cap = self.policy.fail_body_cap.min(response.body.len());
        let body = String::from_utf8_lossy(&response.body[..cap]).into_owned();
        let failure: ProviderFailure =
            driver.classify(response.status, &response.header_pairs(), &body);
        Err(HubError::Provider(failure.with_truncated(
            response.truncated || cap < response.body.len(),
        )))
    }
}
