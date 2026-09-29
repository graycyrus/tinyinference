//! One provider taxonomy, catalogue, typed error taxonomy, and endpoint policy
//! for every TinyInference host.
//!
//! This crate is a leaf: it depends on `tinyinference-core` and
//! `tinyinference-llm`, and nothing depends on it. The modules land in the
//! commits that follow; this one adds the error taxonomy, identifiers, and the
//! endpoint policy.

pub mod endpoint;
pub mod error;
pub mod ids;
pub mod policy;
mod secret;
pub mod taxonomy;

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
