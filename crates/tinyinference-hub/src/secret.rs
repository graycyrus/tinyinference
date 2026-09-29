//! Secret-bearing wrappers: [`Secret`] for credentials and [`LogOnly`] for
//! upstream text that may echo request material.
//!
//! Both wrappers exist so that the *type* carries the redaction rule. A
//! `String` in a struct is one `{:?}` away from a log line; a [`Secret`] is not,
//! because its `Debug` and `Display` never print the value and it has no
//! `Serialize` implementation, so it cannot reach a config file or a wire
//! payload by accident (invariant 1: a credential is never on a record).
//!
//! ```compile_fail,E0277
//! use tinyinference_hub::Secret;
//! let secret = Secret::new("sk-not-a-real-key");
//! // `Secret` deliberately does not implement `serde::Serialize`.
//! let _ = serde_json::to_string(&secret);
//! ```

use std::fmt;

/// The text every redacting `Debug`/`Display` prints in place of a value.
pub(crate) const REDACTED: &str = "<redacted>";

/// A credential. Redacts itself in `Debug` and `Display`; never serialisable.
///
/// The only way to read the value is [`Secret::expose`], which makes each use
/// greppable in review.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a credential value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The credential itself. Call this only where the value is put on the wire.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the wrapped value is empty (an empty key is "no key").
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }

    /// Length of the wrapped value in bytes. Safe to log; the value is not.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A value that may be written to a log channel by the code that owns it but
/// must never appear in a user-facing sentence, `Display`, or `Debug` dump.
///
/// Used for raw upstream error text: it can echo request headers or key
/// fragments, and the sentence built from it is one someone screenshots into a
/// ticket (`probe.rs` design note, OpenCompany).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct LogOnly<T>(T);

impl<T> LogOnly<T> {
    /// Wraps a log-only value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value, for a log or detail channel only.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper. Same rule as [`LogOnly::expose`].
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for LogOnly<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogOnly({REDACTED})")
    }
}

impl<T> fmt::Display for LogOnly<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Whether a field, header or query-parameter name marks its value as a
/// credential.
///
/// camelCase is split (`accessToken` is `access_token`) and `-` and case are
/// ignored. The name is judged by its **last word** so `api_key`,
/// `subscription-key`, `clientSecret` and `db_passwd` are caught while
/// `secretary`, `max_tokens`, `tokenizer` and `keywords` are not: the last word
/// is one of `secret`, `password`, `passwd`, `passphrase`, `credential(s)`,
/// `signature`, `sig`, `cookie`, `pwd`, `authorization`, `bearer` or `apikey`;
/// or `key`/`token` unless a word in the name is plainly benign (`public_key`,
/// `cache_key`, `page_token`); the whole name is `auth`; it contains `api_key`,
/// `access_key`, `private_key`, `authorization` or `bearer`; or it ends in a
/// run-together `apikey`, `secret`, `password`, `passwd`, `passphrase` or
/// `apitoken` (`openaiapikey`, `clientsecret`).
pub(crate) fn is_credential_name(name: &str) -> bool {
    let mut lower = String::with_capacity(name.len() + 4);
    let mut previous: Option<char> = None;
    for c in name.trim().chars() {
        if c.is_ascii_uppercase()
            && previous.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            lower.push('_');
        }
        lower.push(if c == '-' {
            '_'
        } else {
            c.to_ascii_lowercase()
        });
        previous = Some(c);
    }
    // Last words that always mark a credential.
    const ALWAYS: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "signature",
        "sig",
        "cookie",
        "pwd",
        "authorization",
        "bearer",
        "apikey",
    ];
    // `key` and `token` are ambiguous (`public_key`, `page_token`), so a name
    // ending in one is a credential unless a word in it says otherwise.
    const AMBIGUOUS: &[&str] = &["key", "token"];
    const BENIGN_WORDS: &[&str] = &[
        "public",
        "cache",
        "sort",
        "primary",
        "foreign",
        "page",
        "pagination",
        "next",
        "continuation",
        "partition",
        "row",
        "idempotency",
        "shard",
        "order",
        "group",
        "index",
        "lookup",
    ];
    const CONTAINS: &[&str] = &[
        "api_key",
        "access_key",
        "private_key",
        "authorization",
        "bearer",
    ];
    // Run-together spellings (`openaiapikey`, `clientsecret`, `dbpassword`) are
    // caught by suffix, which still leaves `secretary` and `keywords` alone.
    const SUFFIXES: &[&str] = &[
        "apikey",
        "secret",
        "password",
        "passwd",
        "passphrase",
        "apitoken",
    ];
    let last = lower.rsplit('_').next().unwrap_or("");
    let ambiguous =
        AMBIGUOUS.contains(&last) && !lower.split('_').any(|word| BENIGN_WORDS.contains(&word));
    ALWAYS.contains(&last)
        || ambiguous
        || lower == "auth"
        || CONTAINS.iter().any(|c| lower.contains(c))
        || SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
#[path = "secret_test.rs"]
mod tests;
