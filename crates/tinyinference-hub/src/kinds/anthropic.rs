//! [`AnthropicDriver`]: Anthropic's native `/models` and `/messages` calls.

use async_trait::async_trait;
use serde_json::Value;

use crate::catalog::{Fetched, ModelEntry, parse_openai_value, too_large, unreadable};
use crate::descriptor::ProviderDescriptor;
use crate::error::HubError;
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
        let mut models: Vec<ModelEntry> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut after: Option<String> = None;
        for page in 0..MAX_PAGES {
            let mut path = format!("/models?limit={PAGE_SIZE}");
            if let Some(cursor) = &after {
                path.push_str("&after_id=");
                path.push_str(&urlencode(cursor));
            }
            let url = target.join(&path);
            let request = cx.request(
                &self.descriptor,
                target,
                HubRequest::get(url).with_body_cap(cx.policy.catalog_cap),
            );
            let response = cx.call(self, request).await?;
            if response.truncated {
                return Err(HubError::Provider(too_large("the model list")));
            }
            let envelope: Value = serde_json::from_slice(&response.body)
                .map_err(|_| HubError::Provider(unreadable("the model list was not JSON")))?;
            let parsed = parse_openai_value(&envelope).map_err(HubError::Provider)?;
            for entry in parsed.entries {
                if seen.insert(entry.id.clone()) {
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
                        truncated: true,
                        ..Fetched::new(models)
                    });
                }
                // `has_more` with no cursor cannot be followed: stop rather than
                // ask for the first page again, and say the list is a prefix.
                (true, None) => {
                    return Ok(Fetched {
                        truncated: true,
                        ..Fetched::new(models)
                    });
                }
                (false, _) => break,
            }
        }
        Ok(Fetched::new(models))
    }
}

/// Percent-encodes a cursor for a query value.
fn urlencode(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}
