//! The no-socket simulation kit (feature `testing`): a fake clock and a
//! scripted HTTP transport.
//!
//! Nothing here binds a port, opens a socket, reads the wall clock, or reads
//! the process environment. Time moves only when a test calls
//! [`FakeClock::advance`] (or a scripted latency does); every HTTP interaction
//! is a [`ScriptedHttp`] rule. [`ScriptedHttp`] applies the *same* endpoint
//! policy an [`Http`](crate::ports::Http) implementation is contractually
//! bound to, so a test that scripts a redirect to `169.254.169.254` sees the
//! refusal a real transport would give.

mod clock;
mod contract;
mod http;
mod script;

pub use clock::FakeClock;
pub use contract::{ContractFixture, ListingBody, run_contract};
pub use http::{RecordedRequest, ScriptedHttp};
pub use script::{Match, Script, Scripted};

#[cfg(test)]
#[path = "test.rs"]
mod tests;
