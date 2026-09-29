//! Provider health: what probes and real turns have said about a provider
//! lately, folded into one status a UI can show.
//!
//! * `types`: [`ProviderHealth`], [`HealthSnapshot`] and the signals inside it.
//!
//! Health is fed by probes **and** by real turns, so a provider that passes a
//! catalog read but fails every completion does not look green. The router
//! crate (a later phase) consumes these signals; this crate only exposes them.

mod types;

pub use types::{FailureNote, HealthSnapshot, ProbeSignal, ProviderHealth, TurnSignal};
