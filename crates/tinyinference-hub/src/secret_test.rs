use std::marker::PhantomData;

use proptest::prelude::*;
use serde::Serialize;

use super::*;

/// Auto-ref probe: resolves to `true` only when `T: Serialize`.
struct Probe<T>(PhantomData<T>);
trait Fallback {
    fn implements_serialize(&self) -> bool {
        false
    }
}
impl<T> Fallback for Probe<T> {}
impl<T: Serialize> Probe<T> {
    fn implements_serialize(&self) -> bool {
        true
    }
}

#[test]
fn secret_debug_and_display_hide_the_value() {
    let secret = Secret::new("sk-not-a-real-key");
    assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    assert_eq!(format!("{secret}"), "<redacted>");
    assert_eq!(format!("{secret:#?}"), "Secret(<redacted>)");
}

#[test]
fn secret_exposes_only_through_expose() {
    let secret = Secret::from("test-token");
    assert_eq!(secret.expose(), "test-token");
    assert_eq!(secret.len(), 10);
    assert!(!secret.is_empty());
    assert_eq!(Secret::from(String::from("test-token")), secret);
}

#[test]
fn secret_blank_is_empty() {
    assert!(Secret::new("").is_empty());
    assert!(Secret::new("   \n").is_empty());
}

#[test]
fn secret_inside_a_derived_debug_struct_stays_redacted() {
    #[derive(Debug)]
    struct Holder {
        key: Secret,
    }
    let holder = Holder {
        key: Secret::new("sk-not-a-real-key"),
    };
    assert!(!format!("{holder:?}").contains("sk-not"));
    assert_eq!(holder.key.len(), 17);
}

#[test]
fn secret_does_not_implement_serialize() {
    assert!(!Probe::<Secret>(PhantomData).implements_serialize());
    // The probe itself works: a type that is Serialize reports true.
    assert!(Probe::<String>(PhantomData).implements_serialize());
}

#[test]
fn log_only_redacts_in_debug_and_display() {
    let raw = LogOnly::new(String::from("Authorization: Bearer sk-not-a-real-key"));
    assert_eq!(format!("{raw}"), "<redacted>");
    assert_eq!(format!("{raw:?}"), "LogOnly(<redacted>)");
    assert!(raw.expose().contains("Bearer"));
    assert!(raw.into_inner().contains("sk-not"));
}

#[test]
fn log_only_default_is_empty() {
    let raw: LogOnly<String> = LogOnly::default();
    assert!(raw.expose().is_empty());
}

proptest! {
    #[test]
    fn secret_debug_never_contains_the_value(value in "[A-Za-z0-9_-]{8,40}") {
        let secret = Secret::new(value.clone());
        let secret_text = format!("{secret:?}{secret}");
        prop_assert!(!secret_text.contains(&value));
        let raw = LogOnly::new(value.clone());
        let raw_text = format!("{raw:?}{raw}");
        prop_assert!(!raw_text.contains(&value));
    }
}

#[test]
fn credential_names_are_recognised_across_spellings_and_ordinary_names_are_not() {
    for name in [
        "api_key",
        "apiKey",
        "API-KEY",
        "x-api-key",
        "openai_api_key",
        "secret",
        "clientSecret",
        "password",
        "Authorization",
        "bearer_token",
        "key",
        "token",
        "access_token",
        "accessToken",
        "refreshToken",
        "auth",
        "credentials",
        "sig",
        "Signature",
        "private_key",
        "passphrase",
        "db_passwd",
        "APIKEY",
    ] {
        assert!(is_credential_name(name), "{name}");
    }
    for name in [
        "max_tokens",
        "maxTokens",
        "tokenizer",
        "keywords",
        "monkey",
        "tiers",
        "models",
        "display_name",
        "authors",
        "author",
        "signal",
        "design",
        "",
    ] {
        assert!(!is_credential_name(name), "{name}");
    }
}

#[test]
fn credential_names_are_judged_by_their_last_word() {
    // Regression (review round 4): the substring rule flagged `secretary` and
    // missed Azure-style names.
    for name in [
        "subscription-key",
        "Ocp-Apim-Subscription-Key",
        "x-functions-key",
        "app_key",
        "cookie",
        "Set-Cookie",
        "X-Amz-Signature",
        "pwd",
        "client_secret",
        "clientSecret",
        "db_passwd",
    ] {
        assert!(is_credential_name(name), "{name}");
    }
    for name in [
        "secretary",
        "keyword",
        "token_limit",
        "signature_algorithm",
        "cookies_enabled",
        "pwdx",
    ] {
        assert!(!is_credential_name(name), "{name}");
    }
}
