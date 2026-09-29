//! [`ProviderRecord`], a configured instance of a kind.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{KindId, ModelId, Slug};
use crate::taxonomy::AuthStyle;

/// Fields a record carries that the hub does not interpret (for example
/// OpenCompany's tier map). Preserved verbatim through a load and a save so an
/// adapter can round-trip its own data (`#[serde(flatten)]`).
pub type LegacyFields = BTreeMap<String, serde_json::Value>;

/// Where a record came from.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOrigin {
    /// Created through the hub's operations.
    #[default]
    Indexed,
    /// OpenCompany's legacy "entry zero": read-only through list operations
    /// (guard G21).
    EntryZero,
    /// Produced by an `import` reader.
    Imported,
}

/// A configured provider instance.
///
/// **There is no credential field, ever** (invariant 1): a key lives in the
/// `CredentialStore` under [`Slug::key_slot`] and is read per request.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// Opaque id (OpenCompany `prv_<32hex>`, OpenHuman `p_<slug>_<rand>`).
    pub id: String,
    /// The routing key.
    pub slug: Slug,
    /// The display name.
    pub label: String,
    /// The catalogue kind.
    pub kind: KindId,
    /// The normalised endpoint; never contains userinfo.
    pub base_url: String,
    /// The provider's chosen model, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    /// Whether the record is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// An auth style overriding the kind's (custom rows only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_override: Option<AuthStyle>,
    /// A record the hub synthesises rather than the operator creating
    /// (`byok-inference`, `ephemeral-route`).
    #[serde(default)]
    pub synthetic: bool,
    /// Where the record came from.
    #[serde(default)]
    pub origin: RecordOrigin,
    /// Fields the hub does not interpret.
    #[serde(default, flatten)]
    pub legacy: LegacyFields,
}

fn default_true() -> bool {
    true
}

impl ProviderRecord {
    /// A new enabled, non-synthetic record.
    pub fn new(
        id: impl Into<String>,
        slug: Slug,
        label: impl Into<String>,
        kind: KindId,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            slug,
            label: label.into(),
            kind,
            base_url: base_url.into(),
            model: None,
            enabled: true,
            auth_override: None,
            synthetic: false,
            origin: RecordOrigin::Indexed,
            legacy: LegacyFields::new(),
        }
    }
}
