//! One provider taxonomy, catalogue, typed error taxonomy, and endpoint policy
//! for every TinyInference host.
//!
//! OpenCompany and OpenHuman each implement provider management separately:
//! two catalogues of the same hosted vendors, two error classifiers, and safety
//! invariants (SSRF policy, credential redaction) that only one of them has.
//! This crate is the shared answer, built as a **leaf**: it depends on
//! `tinyinference-llm` (plus small utility crates), nothing depends on it, and no
//! existing public item of any other crate changed.
//!
//! # What is here
//!
//! * [`error`]: [`HubError`], the stable [`ReasonCode`] vocabulary, and
//!   [`classify`] which turns a vendor's status, headers and body into a
//!   [`ProviderFailure`] (spend caps are `quota`/never-retry, distinct from
//!   `rate_limited`).
//! * [`Secret`] and [`LogOnly`]: wrappers that redact themselves everywhere.
//! * [`ids`]: [`Slug`], [`ModelId`], [`KindId`], [`ScopeKey`] and the
//!   validators ported from OpenCompany.
//! * [`taxonomy`]: groups, protocols, auth styles, and [`LocalRuntime`], which
//!   reconciles the four local-runtime enums by conversion.
//! * [`catalogue`] and [`descriptor`]: every built-in kind as data.
//! * [`policy`] and [`endpoint`]: the SSRF policy and endpoint credential
//!   redaction.
//! * [`config`]: the persisted [`HubConfig`](config::HubConfig) and
//!   [`ProviderDraft`](config::ProviderDraft).
//! * [`ports`]: the traits a host implements, and in-memory defaults.
//! * [`credential`]: the ordered credential chain and its sources.
//! * [`catalog`]: listing parsers, the safe model-list cache, metadata merge.
//! * [`probe`] and [`health`]: three-depth probing and folded provider health.
//! * [`kinds`]: the kind drivers and the registry.
//! * `testkit` (feature `testing`): the no-socket simulation kit.
//!
//! # Guarantees
//!
//! A credential is never on a record and never printed: [`Secret`] has no
//! `Serialize`, and its `Debug` and `Display` redact. Raw upstream error text is
//! log-only and never reaches a user-facing sentence.
//!
//! # Example
//!
//! ```
//! use tinyinference_hub::{ReasonCode, Retry, classify};
//!
//! // An Anthropic spend cap arrives as a 429. It is a quota problem, not a
//! // cooldown: never retried.
//! let failure = classify(
//!     429,
//!     &[],
//!     r#"{"type":"error","error":{"type":"rate_limit_error","message":"You have reached your specified API usage limits."}}"#,
//! );
//! assert_eq!(failure.reason, ReasonCode::Quota);
//! assert_eq!(failure.retry, Retry::Never);
//! ```
//!
//! # Features
//!
//! `default = []`. `local-bridge` adds conversions to `tinyinference-local`'s
//! enums. `testing` exposes the simulation kit and `cli` adds the
//! `ProcessSpawner` port. `oauth` and `http-reqwest` are reserved and currently
//! add nothing; `oauth` will only ever define types.

pub mod catalog;
pub mod catalogue;
#[cfg(feature = "cli")]
pub mod cli;
pub mod client;
pub mod config;
pub mod credential;
pub mod descriptor;
pub mod detect;
pub mod endpoint;
pub mod error;
pub mod health;
pub mod hub;
pub mod ids;
pub mod import;
pub mod kinds;
#[cfg(feature = "oauth")]
pub mod oauth;
mod ops;
pub mod policy;
pub mod ports;
pub mod probe;
pub mod route;
mod secret;
pub mod taxonomy;
#[cfg(any(test, feature = "testing"))]
pub mod testkit;

pub use descriptor::{Capabilities, ProviderDescriptor, ProviderRecord, Quirk};
pub use error::{
    CopyContext, HubError, InvalidInput, NotFound, Operation, PolicyViolation, PortName,
    ProviderFailure, ReasonCode, Result, Retry, Unresolved, UsedBy, classify, classify_for,
    classify_transport,
};
pub use ids::{AgentKey, KindId, ModelId, ScopeKey, Slug, WorkloadKey};
pub use policy::{EndpointPolicy, EndpointRefusal, HeaderPolicy};
pub use secret::{LogOnly, Secret};
pub use taxonomy::{
    AuthStyle, CatalogShape, CliKind, LocalRuntime, Protocol, ProviderGroup, TestDepth, Transport,
};

/// Re-exports of the llm types that appear in the hub's own signatures, so a
/// host needs one import. Deliberately not a wholesale re-export.
pub mod llm {
    pub use tinyinference_llm::ProviderKind;
}
