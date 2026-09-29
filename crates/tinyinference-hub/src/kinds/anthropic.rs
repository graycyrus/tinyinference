//! [`AnthropicDriver`]: Anthropic's native `/models` and `/messages` calls.

use async_trait::async_trait;
use serde_json::Value;

use crate::catalog::{Fetched, ModelEntry, parse_openai};
use crate::descriptor::ProviderDescriptor;
use crate::error::{HubError, ProviderFailure, ReasonCode, Retry};
use crate::ports::HubRequest;

use super::{DriverContext, KindDriver, Target};

/// The most models Anthropic returns per page (`limit` is capped at 1000).
const PAGE_SIZE: usize = 1000;

/// The most pages one read follows, so a `has_more` that never clears cannot
/// loop.
const MAX_PAGES: usize = 10;

/// Anthropic's native API.
///
/// Its `GET /models` is paged with a default of **20** per page, so a plain
/// read (OpenCompany's) sees a fraction of the catalog. This driver asks for the
/// maximum page size and follows `has_more`/`last_id`. The native API also
/// rejects a bearer-authenticated request with no `anthropic-version` header as
/// malformed (a `400`, not a `401`), which is why the credential is presented
/// through [`AuthStyle::Anthropic`](crate::AuthStyle) and never as a bearer.
#[derive(Clone, Debug)]
pub struct AnthropicDriver {
    descriptor: ProviderDescriptor,
}

impl AnthropicDriver {
    /// A driver for the Anthropic catalogue row.
    pub fn for_descriptor(descriptor: ProviderDescriptor) -> Self {
        Self { descriptor }
    }
}

fn unreadable(text: &str) -> HubError {
    HubError::Provider(ProviderFailure::new(ReasonCode::Unknown, Retry::Never).with_raw(text))
}

#[async_trait]
impl KindDriver for AnthropicDriver {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    async fn list_models(
        &self,
        cx: &DriverContext<'_>,
        target: &Target<'_>,
    ) -> Result<Fetched, HubError> {
        let base = target.base();
        let mut models: Vec<ModelEntry> = Vec::new();
        let mut after: Option<String> = None;
        for page in 0..MAX_PAGES {
            let mut url = format!("{base}/models?limit={PAGE_SIZE}");
            if let Some(cursor) = &after {
                url.push_str("&after_id=");
                url.push_str(&urlencode(cursor));
            }
            let request = cx.request(
                &self.descriptor,
                target,
                HubRequest::get(url).with_body_cap(cx.policy.catalog_cap),
            );
            let response = cx.call(self, request).await?;
            if response.truncated {
                return Err(HubError::Provider(
                    ProviderFailure::new(ReasonCode::Unknown, Retry::Never)
                        .with_truncated(true)
                        .with_raw("the model list is larger than the size cap"),
                ));
            }
            let parsed = parse_openai(&response.body).map_err(HubError::Provider)?;
            let envelope: Value = serde_json::from_slice(&response.body)
                .map_err(|_| unreadable("the model list was not JSON"))?;
            for entry in parsed.entries {
                if !models.iter().any(|m| m.id == entry.id) {
                    models.push(entry);
                }
            }
            let has_more = envelope.get("has_more").and_then(Value::as_bool) == Some(true);
            let last = envelope
                .get("last_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            match (has_more, last) {
                (true, Some(cursor)) if page + 1 < MAX_PAGES => after = Some(cursor),
                (true, Some(_)) => {
                    return Ok(Fetched {
                        models,
                        truncated: true,
                    });
                }
                // `has_more` with no cursor cannot be followed; stop rather
                // than ask for the first page again.
                _ => break,
            }
        }
        Ok(Fetched::new(models))
    }
}

/// Percent-encodes a cursor for a query value.
fn urlencode(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}
