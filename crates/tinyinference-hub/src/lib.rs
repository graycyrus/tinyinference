//! One provider taxonomy, catalogue, typed error taxonomy, and endpoint policy
//! for every TinyInference host.
//!
//! This crate is a leaf: it depends on `tinyinference-core` and
//! `tinyinference-llm`, and nothing depends on it. The modules land in the
//! commits that follow; this one adds credential-safe wrappers and endpoint
//! text handling.

pub mod endpoint;
mod secret;

pub use secret::{LogOnly, Secret};
