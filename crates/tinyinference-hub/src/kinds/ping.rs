//! The one-token completion ping, per wire protocol.

use serde_json::json;

use crate::error::HubError;
use crate::ids::ModelId;
use crate::ports::HubRequest;
use crate::taxonomy::Protocol;

use crate::descriptor::{ProviderDescriptor, Quirk};
use crate::endpoint::endpoint_host;

use super::context::Classifier;
use super::{DriverContext, Target};

/// The most tokens a ping asks for. Small enough to cost almost nothing, large
/// enough that reasoning models that insist on a floor still accept it.
pub(super) const PING_MAX_TOKENS: u32 = 16;

/// The prompt a ping sends.
const PING_PROMPT: &str = "ping";

/// Whether the endpoint wants `max_completion_tokens`: the catalogue row that
/// says so, or an endpoint that is OpenAI itself or an Azure OpenAI resource
/// however the operator reached it (a `custom` row pointed at api.openai.com
/// gets the same 400 on its reasoning models).
fn wants_max_completion_tokens(descriptor: &ProviderDescriptor, base: &str) -> bool {
    // Only the OpenAI chat wire has the field; Anthropic's native `/messages`
    // requires `max_tokens` wherever it is hosted.
    descriptor.protocol != Protocol::AnthropicMessages
        && (descriptor.has_quirk(Quirk::MaxCompletionTokens)
            || crate::catalogue::is_azure_endpoint(base)
            || endpoint_host(base).is_some_and(|host| host == "api.openai.com"))
}

/// Pings with the protocol the descriptor names.
///
/// OpenAI Chat (and, for the one row that has it, the Responses API, whose
/// chat-completions path also exists) posts to `{base}/chat/completions`; the
/// Anthropic native protocol posts to `{base}/messages`. A `404` on the
/// Responses row is not retried at `/responses`: chat completions is the
/// universal path, and the fallback is a turn concern.
pub(super) async fn ping_by_protocol(
    cx: &DriverContext<'_>,
    descriptor: &ProviderDescriptor,
    classify: &Classifier<'_>,
    target: &Target<'_>,
    model: &ModelId,
) -> Result<(), HubError> {
    let path = match descriptor.protocol {
        Protocol::AnthropicMessages => "/messages",
        _ => "/chat/completions",
    };
    // OpenAI's newer (reasoning) models reject `max_tokens` with a 400 and want
    // `max_completion_tokens`, which OpenAI accepts for every chat model. Other
    // OpenAI-compatible servers know only `max_tokens`, and Anthropic's native
    // API requires it, so the switch is its own descriptor quirk (not a proxy
    // such as the Responses-API flag, which says something else).
    let limit_field = if wants_max_completion_tokens(descriptor, target.base()) {
        "max_completion_tokens"
    } else {
        "max_tokens"
    };
    let request = HubRequest::post_json(
        format!("{}{path}", target.base()),
        &json!({
            "model": model.as_str(),
            limit_field: PING_MAX_TOKENS,
            "messages": [{"role": "user", "content": PING_PROMPT}],
        }),
    );
    let request = cx.request(descriptor, target, request);
    cx.call_with(classify, request).await.map(|_| ())
}
