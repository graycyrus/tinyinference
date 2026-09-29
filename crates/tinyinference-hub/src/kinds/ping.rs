//! The one-token completion ping, per wire protocol.

use serde_json::json;

use crate::error::HubError;
use crate::ids::ModelId;
use crate::ports::HubRequest;
use crate::taxonomy::Protocol;

use super::{DriverContext, KindDriver, Target};

/// The most tokens a ping asks for. Small enough to cost almost nothing, large
/// enough that reasoning models that insist on a floor still accept it.
pub(super) const PING_MAX_TOKENS: u32 = 16;

/// The prompt a ping sends.
const PING_PROMPT: &str = "ping";

/// Pings with the protocol the driver's descriptor names.
///
/// OpenAI Chat (and, for the one row that has it, the Responses API, whose
/// chat-completions path also exists) posts to `{base}/chat/completions`; the
/// Anthropic native protocol posts to `{base}/messages`. A `404` on the
/// Responses row is not retried at `/responses`: chat completions is the
/// universal path, and the fallback is a turn concern.
pub(super) async fn ping_by_protocol<D: KindDriver + ?Sized>(
    driver: &D,
    cx: &DriverContext<'_>,
    target: &Target<'_>,
    model: &ModelId,
) -> Result<(), HubError> {
    let descriptor = driver.descriptor();
    let request = match descriptor.protocol {
        Protocol::AnthropicMessages => HubRequest::post_json(
            format!("{}/messages", target.base()),
            &json!({
                "model": model.as_str(),
                "max_tokens": PING_MAX_TOKENS,
                "messages": [{"role": "user", "content": PING_PROMPT}],
            }),
        ),
        _ => HubRequest::post_json(
            format!("{}/chat/completions", target.base()),
            &json!({
                "model": model.as_str(),
                "max_tokens": PING_MAX_TOKENS,
                "messages": [{"role": "user", "content": PING_PROMPT}],
            }),
        ),
    };
    let request = cx.request(descriptor, target, request);
    cx.call(driver, request).await.map(|_| ())
}
