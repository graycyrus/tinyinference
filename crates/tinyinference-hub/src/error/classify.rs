//! The provider-failure classifier: a vendor's status, headers and body in, a
//! [`ProviderFailure`] out.
//!
//! Ported branch for branch, **including the order**, from OpenCompany's
//! `probe.rs::classify` (`probe.rs:192`) and extended with OpenHuman's
//! `http_error/*` predicates and the D12 rules. Reordering branches is a
//! behaviour change, not a refactor; the two orderings that matter:
//!
//! * proxy, gateway and 407 rejections are about the *connection*, so they are
//!   checked first, before anything can read "authentication" in them and
//!   delete a valid key;
//! * the auth branch is a *positive* list of phrases in which a vendor says the
//!   credential itself was refused, so a body the classifier does not recognise
//!   keeps the key.
//!
//! The classifier's only inputs are the status and the vendor's body (URLs are
//! stripped from it): never our own request URL, which for a probe always ends
//! in `/models` and would make every failure look like a missing model
//! (guard G19).

use std::time::Duration;

use super::types::{ProviderFailure, ReasonCode, Retry};

/// The longest `Retry-After` the hub will report; anything longer is capped so
/// a hostile header cannot park a caller for days.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// A transport-level failure that never produced an HTTP response.
///
/// Named conditions rather than the transport error's own text, because that
/// text buries the cause (a DNS failure and a timeout read identically) and
/// contains the request URL.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCondition {
    /// The request timed out.
    Timeout,
    /// DNS failure, connection refused, or a TLS handshake that never
    /// completed: nothing usable is at that address.
    ConnectFailed,
    /// The redirect chain was refused or too long.
    RedirectRefused,
    /// Anything else.
    Other,
}

/// Classifies a transport failure. `detail` is the transport's own text and
/// goes to the log-only field, never into the classification.
pub fn classify_transport(condition: TransportCondition, detail: &str) -> ProviderFailure {
    let (reason, retry) = match condition {
        TransportCondition::Timeout => (ReasonCode::Timeout, Retry::Later(None)),
        TransportCondition::ConnectFailed => (ReasonCode::Endpoint, Retry::Later(None)),
        TransportCondition::RedirectRefused => (ReasonCode::Endpoint, Retry::Never),
        TransportCondition::Other => (ReasonCode::Unknown, Retry::Never),
    };
    ProviderFailure::new(reason, retry).with_raw(detail)
}

/// Whether `needle` appears in `haystack` delimited by non-word characters:
/// the `\b...\b` a regex would give. This is what stops `403` matching inside
/// `1403` or `4032`; a model id or request id with those digits in it would
/// otherwise be read as a status code and delete the operator's key.
fn contains_token(haystack: &str, needle: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1] as char);
        let after_ok = end == bytes.len() || !is_word(bytes[end] as char);
        if before_ok && after_ok {
            return true;
        }
        // `start` is the index of an ASCII byte of `needle`, so `start + 1` is
        // always a char boundary.
        from = start + 1;
    }
    false
}

/// Replaces every `http(s)://...` token in `text` with `<url>`.
///
/// Applied to text before it is classified, so a URL that happens to contain
/// `models` or `404` cannot steer the result (guard G19).
pub fn strip_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let lower = rest.to_ascii_lowercase();
        let next = ["https://", "http://"]
            .iter()
            .filter_map(|p| lower.find(p))
            .min();
        let Some(start) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | '<' | ','))
            .unwrap_or(tail.len());
        // Trailing sentence punctuation is not part of the URL.
        let end = tail[..end]
            .trim_end_matches(['.', ';', ':', '!', '?'])
            .len();
        out.push_str("<url>");
        rest = &tail[end..];
    }
}

/// Whether the body says the **credential itself** was refused, as opposed to
/// saying the credential is fine and something else about the request is not.
///
/// A positive list on purpose: a denylist of failure wordings cannot be
/// complete, because it has to anticipate every phrase 29 vendors might use for
/// a cause nobody has thought of yet. Inverting it makes the unanticipated case
/// non-destructive. `authentication` appears only in compound forms, never as
/// the bare word: an endpoint answering *"Bearer authentication is not
/// supported, use x-api-key"* is a 400 about our request shape, with a good key.
fn says_the_credential_was_refused(haystack: &str) -> bool {
    const REFUSALS: &[&str] = &[
        // OpenAI, Groq and everything that copied their wording.
        "invalid api key",
        "invalid_api_key",
        "incorrect api key",
        // Fireworks publishes exactly these two and neither matches the three
        // above, so a genuine bad-key 403 would otherwise read as "unknown".
        "api key you provided is invalid",
        "must provide an api key",
        // Google's compat surface, whose word order matches none of the above.
        "api key not valid",
        // Anthropic's and DeepSeek's typed bodies.
        "authentication_error",
        "authentication failed",
        "authentication fails",
        "invalid authentication",
        "invalid credential",
        "invalid_credential",
        "bad credentials",
        "missing api key",
        "no api key provided",
        // OpenHuman's BYO-provider markers (`http_error/auth_failure.rs`).
        "invalid or missing api key",
        "no api key supplied",
        // Venice's typed code, and the bare word as a body signal.
        "authentication_failed",
        "unauthorized",
    ];
    REFUSALS.iter().any(|phrase| haystack.contains(phrase))
}

/// Phrases that say a spend cap, credit balance or plan quota is exhausted: a
/// hard stop that retrying cannot fix. Union of OpenCompany's generic words,
/// OpenHuman's `quota_and_credits.rs`, and the vendors' published codes.
fn says_spend_is_exhausted(haystack: &str) -> bool {
    const HARD: &[&str] = &[
        "enforced_spend_limit_reached",
        "reached your specified api usage limits",
        "insufficient_quota",
        "exceeded your current quota",
        "credit balance is too low",
        "billing_hard_limit_reached",
        "insufficient credit",
        "insufficient balance",
        "insufficient funds",
        "requires more credits",
        "more credits",
        "can only afford",
        "payment required",
        "usage_limit_reached",
        "usage limit has been reached",
        "monthly_request_count",
        "monthly request",
        "monthly limit",
        "monthly quota",
    ];
    HARD.iter().any(|p| haystack.contains(p))
}

/// Words that mean "this is about pace, not about spend".
fn has_rate_marker(haystack: &str) -> bool {
    const MARKERS: &[&str] = &[
        "per minute",
        "per min",
        "per second",
        "rate limit",
        "rate_limit",
        "requests per",
        "retry after",
        "retry-after",
        "try again in",
        "slow_down",
        "too many requests",
    ];
    MARKERS.iter().any(|m| haystack.contains(m))
        || contains_token(haystack, "tpm")
        || contains_token(haystack, "rpm")
}

/// The generic OpenCompany words for "out of credit" that are only trusted
/// when nothing says the limit is one of pace.
fn says_soft_quota(haystack: &str) -> bool {
    let insufficient_access =
        haystack.contains("insufficient permission") || haystack.contains("insufficient scope");
    haystack.contains("quota")
        || (haystack.contains("insufficient") && !insufficient_access)
        || haystack.contains("billing")
        || haystack.contains("usage limit exceeded")
}

fn says_context_window_exceeded(haystack: &str) -> bool {
    const HINTS: &[&str] = &[
        "exceeds the context window",
        "context window of this model",
        "maximum context length",
        "context length exceeded",
        "context_length_exceeded",
        "context size has been exceeded",
        "prompt is too long",
        "input is too long",
        "greater than the context length",
    ];
    if HINTS.iter().any(|h| haystack.contains(h)) {
        return true;
    }
    if haystack.contains("n_keep") && haystack.contains("n_ctx") {
        return true;
    }
    (haystack.contains("too many tokens") || haystack.contains("token limit exceeded"))
        && !has_rate_marker(haystack)
}

fn says_model_missing(haystack: &str) -> bool {
    haystack.contains("model_not_found")
        || (haystack.contains("not found") && haystack.contains("model"))
        || haystack.contains("does not exist")
        || haystack.contains("is not available")
        || haystack.contains("unknown model")
        || haystack.contains("invalid model")
}

fn says_endpoint_unreachable(haystack: &str) -> bool {
    // "404 / not found / DNS / refused": all four, not the first two. A refused
    // connection and an unresolvable name are the clearest evidence that
    // nothing is at that address.
    haystack.contains("404")
        || haystack.contains("not found")
        || haystack.contains("refused")
        || haystack.contains("unreachable")
        || haystack.contains("dns")
        || haystack.contains("no such host")
        || haystack.contains("could not resolve")
        || haystack.contains("name resolution")
        || haystack.contains("connection reset")
}

/// Classifies a failed provider response.
///
/// `headers` are the response headers as `(name, value)` pairs. The returned
/// failure carries `body` as log-only raw text; nothing here interpolates it
/// into a sentence.
pub fn classify(status: u16, headers: &[(&str, &str)], body: &str) -> ProviderFailure {
    classify_for(None, status, headers, body)
}

/// [`classify`] with the provider kind known, for the two rules that depend on
/// it (OpenRouter's "user not found" is a bad key only there).
pub fn classify_for(
    kind: Option<&str>,
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> ProviderFailure {
    let retry_after = retry_after(headers, body);
    let mut failure = classify_text(kind, Some(status), &strip_urls(body), retry_after.is_some());
    if let Retry::Later(delay) = &mut failure.retry {
        *delay = retry_after;
    }
    failure.status = Some(status);
    failure.request_id = request_id(headers, body);
    if failure.provider_code.is_none() {
        failure.provider_code = provider_code(body);
    }
    failure.raw = crate::secret::LogOnly::new(body.to_string());
    failure
}

/// The classification core, on text that already has its URLs stripped.
///
/// The haystack is `"{status}: {body}"`, lowercased, exactly what OpenCompany's
/// `build_failure_text` builds, so a bare `401` in a body still counts (as a
/// whole token).
pub(crate) fn classify_text(
    kind: Option<&str>,
    status: Option<u16>,
    body: &str,
    has_retry_after: bool,
) -> ProviderFailure {
    let haystack = match status {
        Some(s) => format!("{s}: {body}"),
        None => body.to_string(),
    }
    .trim()
    .to_ascii_lowercase();
    let is_5xx = status.is_some_and(|s| (500..600).contains(&s) || s == 408);
    let later = if is_5xx || has_retry_after {
        Retry::Later(None)
    } else {
        Retry::Never
    };
    let done = |reason: ReasonCode, retry: Retry| ProviderFailure::new(reason, retry);

    // Network, gateway and proxy rejections are about the CONNECTION, not the
    // key. They must not reach the auth branch, or the add flow deletes a valid
    // key over a corporate proxy, a WAF, or a 407 challenge.
    if contains_token(&haystack, "407")
        || haystack.contains("proxy")
        || haystack.contains("cloudflare")
        || haystack.contains("bad gateway")
        || haystack.contains("gateway timeout")
    {
        return done(ReasonCode::Unknown, later);
    }

    // A rejected credential, and only a rejected credential, because this is
    // the one class that deletes the operator's key. `401` is the single status
    // that is, on its own, a statement about the credential; every other
    // status reaches this class through the body, including `403`.
    //
    // There is deliberately no bare 403 rule (open question Q9, default
    // applied): 403 is overwhelmingly about entitlement, geography, residency
    // or moderation, not the key. A 403 whose body says nothing recognisable
    // falls through to `Unknown`, which keeps the key. A kept key that does not
    // work is a second attempt; a deleted key that did work is unrecoverable.
    let openrouter_unknown_user = kind == Some("openrouter")
        && matches!(status, Some(401 | 403))
        && haystack.contains("user not found");
    if contains_token(&haystack, "401")
        || says_the_credential_was_refused(&haystack)
        || openrouter_unknown_user
    {
        return done(ReasonCode::Auth, Retry::Never);
    }

    // Provider-side policy rejections keep the key and are not retryable.
    if status == Some(403)
        && (haystack.contains("access_terminated_error")
            || haystack.contains("currently only available for coding agents"))
    {
        return done(ReasonCode::Unknown, Retry::Never).with_provider_code("access_policy");
    }
    if status == Some(400)
        && (haystack.contains("message rejected")
            || haystack.contains("ombudsman")
            || haystack.contains("\"score\""))
    {
        return done(ReasonCode::Unknown, Retry::Never).with_provider_code("content_moderation");
    }

    // Spend, credit and plan exhaustion is a hard stop: never retried as a
    // cooldown (D12). A soft "quota" word is only trusted when nothing says the
    // limit is one of pace (Google's "quota exceeded ... per minute" is a rate
    // limit).
    if status == Some(402)
        || says_spend_is_exhausted(&haystack)
        || (says_soft_quota(&haystack) && !has_rate_marker(&haystack) && !has_retry_after)
    {
        return done(ReasonCode::Quota, Retry::Never);
    }

    if says_context_window_exceeded(&haystack) {
        return done(ReasonCode::Model, Retry::Never).with_provider_code("context_length_exceeded");
    }
    if status == Some(400) && haystack.contains("no models loaded") {
        return done(ReasonCode::Model, Retry::Never).with_provider_code("no_model_loaded");
    }

    // Before `endpoint`, on purpose: the endpoint branch matches a bare "not
    // found", which would otherwise claim every provider that phrases a missing
    // model as "model not found" and send the operator to check their base URL
    // instead of their model id.
    if says_model_missing(&haystack) {
        return done(ReasonCode::Model, Retry::Never);
    }

    if status == Some(429)
        || contains_token(&haystack, "429")
        || has_rate_marker(&haystack)
        || haystack.contains("rate limit")
    {
        return done(ReasonCode::RateLimited, Retry::Later(None));
    }

    if status == Some(500) && haystack.contains("internal server error (ref:") {
        // Ollama Cloud's hosted-inference 500: provider-internal, no client
        // lever, worth retrying shortly.
        return done(ReasonCode::Unknown, Retry::Later(None))
            .with_provider_code("provider_internal_error");
    }

    if says_endpoint_unreachable(&haystack) {
        return done(ReasonCode::Endpoint, Retry::Later(None));
    }

    if haystack.contains("timeout") || haystack.contains("timed out") {
        return done(ReasonCode::Timeout, Retry::Later(None));
    }

    done(ReasonCode::Unknown, later)
}

/// The provider's own error code from a JSON body: `error.code`, `error.type`,
/// `code` or `type`, first non-empty. Restricted to a short identifier
/// alphabet so it is safe to display.
fn provider_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let pick = |v: &serde_json::Value| -> Option<String> {
        match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };
    let candidates = [
        value.pointer("/error/code"),
        value.pointer("/error/type"),
        value.get("code"),
        value.get("type"),
    ];
    candidates
        .into_iter()
        .flatten()
        .filter_map(pick)
        .find_map(|c| sanitize_identifier(&c))
}

/// The provider's request id: a well-known response header, else a body field.
fn request_id(headers: &[(&str, &str)], body: &str) -> Option<String> {
    for name in [
        "x-request-id",
        "request-id",
        "openai-request-id",
        "x-amzn-requestid",
    ] {
        if let Some((_, v)) = headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(name))
            && let Some(id) = sanitize_identifier(v)
        {
            return Some(id);
        }
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    [value.get("request_id"), value.pointer("/error/request_id")]
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .find_map(sanitize_identifier)
}

/// Accepts a short identifier (`[A-Za-z0-9_.:-]`, at most 128 characters).
fn sanitize_identifier(raw: &str) -> Option<String> {
    let id = raw.trim();
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
    ok.then(|| id.to_string())
}

/// The provider's requested delay: `retry-after-ms`, `retry-after` (seconds, or
/// an HTTP date bounded by core's 30 s backoff cap), else `retry_after: N` text or a Go-style `try again in 1m30s`
/// in the body. Capped at [`MAX_RETRY_AFTER`].
fn retry_after(headers: &[(&str, &str)], body: &str) -> Option<Duration> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    let numeric = |value: Option<&str>, per_unit_ms: f64| {
        value
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|v| (v * per_unit_ms) as u64)
    };
    // Numeric forms are parsed here and capped at [`MAX_RETRY_AFTER`]: core's
    // helper is a *backoff* bound (30 s) and would misreport a provider's
    // six-minute cooldown as thirty seconds. Only the HTTP-date form, which
    // needs the current time, is delegated to it.
    let millis = numeric(header("retry-after-ms"), 1.0)
        .or_else(|| numeric(header("retry-after"), 1_000.0))
        .or_else(|| tinyinference_core::parse_retry_after_ms(header("retry-after")))
        .or_else(|| tinyinference_llm::parse_retry_after_ms(body))
        .or_else(|| parse_try_again_in(body));
    millis.map(|ms| Duration::from_millis(ms).min(MAX_RETRY_AFTER))
}

/// Parses `try again in 1m30s` / `in 250ms` / `in 6.5s` (the Go duration form
/// OpenAI's rate-limit bodies use) into milliseconds.
fn parse_try_again_in(body: &str) -> Option<u64> {
    let lower = body.to_ascii_lowercase();
    let at = lower.find("try again in ")? + "try again in ".len();
    let mut rest = &lower[at..];
    let mut total = 0.0_f64;
    let mut any = false;
    loop {
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        // A sentence-ending "." is not part of a number, and a bare "." is not
        // a number at all.
        if !digits.starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
        let Ok(number) = digits.trim_end_matches('.').parse::<f64>() else {
            break;
        };
        rest = &rest[digits.len()..];
        let (factor, len) = if rest.starts_with("ms") {
            (1.0, 2)
        } else if rest.starts_with('s') {
            (1_000.0, 1)
        } else if rest.starts_with('m') {
            (60_000.0, 1)
        } else if rest.starts_with('h') {
            (3_600_000.0, 1)
        } else {
            break;
        };
        total += number * factor;
        any = true;
        rest = &rest[len..];
    }
    (any && total.is_finite()).then_some(total as u64)
}

#[cfg(test)]
#[path = "classify_test.rs"]
mod tests;
