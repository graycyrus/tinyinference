//! [`follow_redirects`]: the redirect loop every [`Http`](super::Http)
//! implementation needs and none should re-derive.

use std::future::Future;

use crate::error::PolicyViolation;
use crate::policy::{
    EndpointPolicy, HeaderPolicy, check_endpoint_with_credential, check_redirect, resolve_redirect,
};

use super::http::{HttpError, HubRequest, HubResponse, Method};

/// Whether a status is a redirect that carries a target.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Drives `send_one` (a single-hop transport call that does **not** follow
/// redirects) through the redirect chain, enforcing the endpoint policy.
///
/// * the first URL is checked with
///   [`check_endpoint_with_credential`], so a credential over cleartext http
///   off this host is refused before anything is sent;
/// * each redirect target is checked by [`check_redirect`]: at most
///   `policy.max_redirects` hops, the target re-checked like the first URL,
///   and a credentialed request never leaves its origin;
/// * a hop to another origin drops the credential set and the product header
///   (`headers`), so an uncredentialed catalogue read cannot be used to carry
///   one;
/// * `301`, `302` and `303` turn a `POST` into a `GET` without a body; `307`
///   and `308` keep both.
///
/// A redirect without a usable `Location` is returned as the response it is:
/// the caller classifies the 3xx as an endpoint problem.
///
/// # Errors
///
/// [`HttpError::Policy`] when the policy refuses the URL or a hop; otherwise
/// whatever `send_one` returns.
pub async fn follow_redirects<F, Fut>(
    mut request: HubRequest,
    policy: &EndpointPolicy,
    headers: &HeaderPolicy,
    mut send_one: F,
) -> Result<HubResponse, HttpError>
where
    F: FnMut(HubRequest) -> Fut,
    Fut: Future<Output = Result<HubResponse, HttpError>>,
{
    check_endpoint_with_credential(&request.url, policy, request.credentialed)
        .map_err(|refusal| HttpError::Policy(PolicyViolation::from(refusal)))?;
    let mut hop = 0usize;
    loop {
        let mut response = send_one(request.clone()).await?;
        if !is_redirect(response.status) {
            response.url = request.url;
            return Ok(response);
        }
        let Some(target) = response
            .header("location")
            .and_then(|location| resolve_redirect(&request.url, location))
        else {
            response.url = request.url;
            return Ok(response);
        };
        hop += 1;
        check_redirect(policy, &request.url, &target, request.credentialed, hop)
            .map_err(HttpError::Policy)?;
        headers.strip_for_redirect(&mut request.headers, &request.url, &target);
        if matches!(response.status, 301..=303) && request.method == Method::Post {
            request.method = Method::Get;
            request.body = None;
            request
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
        }
        request.url = target;
    }
}
