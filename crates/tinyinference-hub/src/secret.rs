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

#[cfg(test)]
#[path = "secret_test.rs"]
mod tests;
