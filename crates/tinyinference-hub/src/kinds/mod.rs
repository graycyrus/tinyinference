//! Kind drivers: how each provider kind is reached.
//!
//! A [`KindDriver`] turns a [`Target`] and a [`DriverContext`] into the three
//! things the hub asks of a provider: validate a key ([`KindDriver::key_check`]),
//! list its models ([`KindDriver::list_models`]), and prove a completion works
//! ([`KindDriver::completion_ping`]). Everything a driver sends goes through the
//! [`Http`](crate::ports::Http) port, so a driver is testable without a socket.
//!
//! `OpenAiCompatDriver` serves the hosted OpenAI-compatible vendors and custom
//! endpoints, including OpenRouter's account-scoped listing and `/key` check.

mod context;
mod openai_compat;
mod ping;
mod traits;

pub use context::{DriverContext, Target};
pub use openai_compat::OpenAiCompatDriver;
pub use traits::KindDriver;

#[cfg(test)]
#[path = "test.rs"]
mod tests;
