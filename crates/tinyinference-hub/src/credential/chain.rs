//! [`CredentialSource`] and [`CredentialChain`].

use std::fmt::{self, Debug};

use async_trait::async_trait;

use crate::error::{HubError, PortName};
use crate::ids::{ScopeKey, Slug};
use crate::ports::PortError;
use crate::secret::Secret;

use super::CredentialOrigin;

/// One place a credential may come from.
#[async_trait]
pub trait CredentialSource: Send + Sync + Debug {
    /// What this source is, reported when it answers.
    fn origin(&self) -> CredentialOrigin;

    /// Which host port this source reads, named in a
    /// [`HubError::StoreUnreadable`] when it fails.
    fn port(&self) -> PortName {
        PortName::Credentials
    }

    /// The credential for `slug` in `scope`.
    ///
    /// `Ok(None)` means "not here, try the next source". `Err` stops the chain:
    /// an unreadable source is not an absent one.
    ///
    /// # Errors
    ///
    /// [`PortError`] when the source could not be consulted.
    async fn resolve(&self, scope: &ScopeKey, slug: &Slug) -> Result<Option<Secret>, PortError>;

    /// The credential was rejected. A rotating source drops what it cached so
    /// the next call gets a fresh one. The default does nothing.
    fn invalidate(&self, scope: &ScopeKey) {
        let _ = scope;
    }
}

/// An ordered list of [`CredentialSource`]s.
#[derive(Default)]
pub struct CredentialChain {
    sources: Vec<Box<dyn CredentialSource>>,
}

impl CredentialChain {
    /// An empty chain, which resolves nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// This chain with `source` appended (consulted after the existing ones).
    #[must_use]
    pub fn with(mut self, source: impl CredentialSource + 'static) -> Self {
        self.sources.push(Box::new(source));
        self
    }

    /// Appends an already boxed source.
    #[must_use]
    pub fn with_boxed(mut self, source: Box<dyn CredentialSource>) -> Self {
        self.sources.push(source);
        self
    }

    /// The origins of the sources, in the order they are consulted.
    pub fn origins(&self) -> Vec<CredentialOrigin> {
        self.sources.iter().map(|s| s.origin()).collect()
    }

    /// Whether the chain has no sources.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Runs the chain: the first source that answers with a non-empty value
    /// wins, and its origin comes back with it. Nothing is cached.
    ///
    /// # Errors
    ///
    /// [`HubError::StoreUnreadable`] as soon as a source fails; the sources
    /// after it are not consulted.
    pub async fn resolve(
        &self,
        scope: &ScopeKey,
        slug: &Slug,
    ) -> Result<Option<(Secret, CredentialOrigin)>, HubError> {
        for source in &self.sources {
            match source.resolve(scope, slug).await {
                Ok(Some(secret)) if !secret.is_empty() => {
                    return Ok(Some((secret, source.origin())));
                }
                // A blank value is "not here": an empty key would otherwise
                // shadow a working one further down the chain.
                Ok(Some(_) | None) => {}
                Err(error) => return Err(error.into_hub(source.port())),
            }
        }
        Ok(None)
    }

    /// Tells every source the credential was rejected.
    pub fn invalidate(&self, scope: &ScopeKey) {
        for source in &self.sources {
            source.invalidate(scope);
        }
    }
}

impl Debug for CredentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialChain")
            .field("origins", &self.origins())
            .finish()
    }
}
