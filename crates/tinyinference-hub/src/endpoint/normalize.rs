//! Endpoint parsing helpers: the host of a URL and local-endpoint
//! normalisation, ported from OpenCompany's `catalogue.rs`.

use url::{Host, Url};

use super::redact::endpoint_has_credentials;

/// Lowercased authority host of an endpoint URL: scheme, userinfo, port and
/// path dropped. `None` when no host can be parsed.
///
/// An `http` or `https` URL is read with the WHATWG parser, so the answer is the
/// host a client will actually connect to. A hand-rolled split disagrees with
/// that parser on `\`, which a special scheme reads as `/`:
/// `https://evil.test\@tinyhumans.ai/` connects to `evil.test`, and a splitter
/// that only knew `/`, `?` and `#` would report `tinyhumans.ai` and hand
/// first-party headers to the attacker. Anything else (a scheme-less
/// `localhost:1234/v1` an operator typed, or another scheme) falls back to a
/// tolerant split that treats `\` as a delimiter too.
pub fn endpoint_host(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if let Ok(url) = Url::parse(trimmed)
        && matches!(url.scheme(), "http" | "https")
    {
        return url.host().map(|host| match host {
            // Without the brackets `Host`'s `Display` adds for IPv6.
            Host::Ipv6(address) => address.to_string(),
            other => other.to_string().to_ascii_lowercase(),
        });
    }
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = after_scheme
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h).unwrap_or(rest)
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    };
    let host = host.trim().to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// The endpoint an operator typed for a **local runtime**, normalised.
///
/// `None` when it is not usable: empty, or not `http`/`https`. The scheme check
/// is here rather than left to the probe because this is the one category whose
/// endpoint the operator types — a cloud provider's comes from the preset and
/// cannot be wrong, and rejecting before any write is what the connect flow's
/// ordering asks for.
///
/// `/v1` is appended when the path is empty or `/`, because that is where an
/// OpenAI-compatible surface lives and `http://localhost:11434` is what the
/// runtime's own documentation prints. Appending is not guessing: a path the
/// operator supplied is left exactly as typed.
///
/// An endpoint carrying userinfo (`http://user:password@host/v1`) is **not**
/// normalised — see [`endpoint_has_credentials`]. This is the point every
/// stored endpoint passes through, so refusing here is what makes "no
/// credential is ever stored in a `base_url`" a property of the store rather
/// than of whichever handler remembered to check. Callers that have a sentence
/// to give the operator ask [`endpoint_has_credentials`] first; this refusal is
/// the backstop for the ones that do not.
pub fn normalize_local_endpoint(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if endpoint_has_credentials(trimmed) {
        return None;
    }
    let (scheme, rest) = trimmed.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    // No path segment at all (the trailing slash is already gone), so the
    // operator gave a bare origin.
    if !rest.contains('/') {
        return Some(format!("{trimmed}/v1"));
    }
    Some(trimmed.to_string())
}
