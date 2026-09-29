//! [`ProcessSpawner`]: running a CLI login's binary (feature `cli`).

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;

use super::PortError;

/// A command to run, as data.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliCommand {
    /// The binary name, resolved by the host.
    pub program: String,
    /// The arguments.
    pub args: Vec<String>,
}

/// What a command printed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliOutput {
    /// The exit status, or `None` when it was killed.
    pub status: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Launches a subprocess. The hub never spawns anything itself.
#[async_trait]
pub trait ProcessSpawner: Send + Sync + Debug {
    /// Runs `command`, giving up after `timeout`.
    ///
    /// # Errors
    ///
    /// [`PortError::Unavailable`] when the binary could not be launched or the
    /// timeout elapsed.
    async fn run(&self, command: &CliCommand, timeout: Duration) -> Result<CliOutput, PortError>;
}
