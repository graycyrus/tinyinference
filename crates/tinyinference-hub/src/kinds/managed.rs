//! [`ManagedDriver`]: the first-party TinyHumans provider.

use async_trait::async_trait;

use crate::catalog::{Collector, Fetched, NextPage, page_path, parse_page};
use crate::catalogue::MANAGED_PROXY_PATH;
use crate::descriptor::ProviderDescriptor;
use crate::error::{HubError, ProviderFailure, ReasonCode, Retry};
use crate::ports::HubRequest;
use crate::taxonomy::CatalogShape;

use super::openai_compat::read_listing;
use super::{DriverContext, KindDriver, Target};

/// The managed kind, as an ordinary driver (D1).
///
/// The hub does not hardcode either backend's URL (open question Q3): the host
/// says where the kind lives and in which shape its catalog answers. OpenCompany
/// reaches `{api_url}/agent-integrations/openrouter` with a paged envelope;
/// OpenHuman reaches `{api_url}/openai/v1` with the OpenAI shape and a
/// `?catalog=openrouter` query. Both list prices, which the hub surfaces
/// (D10).
///
/// **Signed out is a typed state, never an empty list** (D3): with no credential
/// every call returns [`HubError::SignedOut`], so a UI says "Sign in" rather
/// than "no models" or a red error.
#[derive(Clone, Debug)]
pub struct ManagedDriver {
    descriptor: ProviderDescriptor,
    shape: CatalogShape,
    query: String,
}

impl ManagedDriver {
    /// The paged envelope (OpenCompany's backend).
    pub fn paged(descriptor: ProviderDescriptor) -> Self {
        Self {
            descriptor,
            shape: CatalogShape::PagedEnvelope,
            query: String::new(),
        }
    }

    /// The OpenAI-shaped listing with an extra query such as
    /// `?catalog=openrouter` (OpenHuman's backend).
    pub fn openai_shaped(descriptor: ProviderDescriptor, query: impl Into<String>) -> Self {
        Self {
            descriptor,
            shape: CatalogShape::OpenAi,
            query: query.into(),
        }
    }

    /// The shape this driver reads.
    pub fn shape(&self) -> CatalogShape {
        self.shape
    }

    /// Whether `base_url` is OpenCompany's proxy path, which answers paged.
    pub fn base_is_paged(base_url: &str) -> bool {
        base_url
            .trim()
            .trim_end_matches('/')
            .ends_with(MANAGED_PROXY_PATH)
    }

    fn signed_out(target: &Target<'_>) -> Result<(), HubError> {
        if target.key().is_none() {
            return Err(HubError::SignedOut {
                provider: target.slug.clone(),
            });
        }
        Ok(())
    }
}

fn unreadable(failure: ProviderFailure) -> HubError {
    HubError::Provider(failure)
}

#[async_trait]
impl KindDriver for ManagedDriver {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    async fn list_models(
        &self,
        cx: &DriverContext<'_>,
        target: &Target<'_>,
    ) -> Result<Fetched, HubError> {
        Self::signed_out(target)?;
        let base = target.base();
        if self.shape != CatalogShape::PagedEnvelope {
            let request = cx.request(
                &self.descriptor,
                target,
                HubRequest::get(format!("{base}/models{}", self.query))
                    .with_body_cap(cx.policy.catalog_cap),
            );
            let response = cx.call(self, request).await?;
            return read_listing(&response);
        }
        let mut collector = Collector::default();
        let mut truncated = false;
        loop {
            let request = cx.request(
                &self.descriptor,
                target,
                HubRequest::get(format!("{base}{}", page_path(collector.offset())))
                    .with_body_cap(cx.policy.page_cap),
            );
            let response = cx.call(self, request).await?;
            if response.truncated {
                return Err(HubError::Provider(
                    ProviderFailure::new(ReasonCode::Unknown, Retry::Never)
                        .with_truncated(true)
                        .with_raw("a model catalog page is larger than the page cap"),
                ));
            }
            let body = String::from_utf8(response.body).map_err(|_| {
                unreadable(
                    ProviderFailure::new(ReasonCode::Unknown, Retry::Never)
                        .with_raw("the model catalog was not UTF-8"),
                )
            })?;
            let page = parse_page(&body).map_err(unreadable)?;
            match collector.push(page) {
                NextPage::At(_) => {}
                NextPage::Done => break,
                NextPage::Truncated { read, total } => {
                    tracing::warn!(
                        read,
                        total,
                        "the model catalog has more pages than one read follows"
                    );
                    truncated = true;
                    break;
                }
            }
        }
        Ok(Fetched {
            models: collector.finish(),
            truncated,
        })
    }

    async fn completion_ping(
        &self,
        cx: &DriverContext<'_>,
        target: &Target<'_>,
        model: &crate::ids::ModelId,
    ) -> Result<(), HubError> {
        Self::signed_out(target)?;
        super::ping::ping_by_protocol(
            cx,
            &self.descriptor,
            &|status, headers, body| self.classify(status, headers, body),
            target,
            model,
        )
        .await
    }
}
