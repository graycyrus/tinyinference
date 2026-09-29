//! Descriptor, record and capability tests.

use serde_json::json;

use super::*;
use crate::ids::{KindId, ModelId, Slug};
use crate::taxonomy::AuthStyle;

fn record() -> ProviderRecord {
    ProviderRecord::new(
        "prv_0123456789abcdef0123456789abcdef",
        Slug::parse("acme").unwrap(),
        "Acme",
        KindId::new("custom"),
        "https://api.acme.test/v1",
    )
}

#[test]
fn a_new_record_is_enabled_indexed_and_carries_no_credential() {
    let r = record();
    assert!(r.enabled && !r.synthetic);
    assert_eq!(r.origin, RecordOrigin::Indexed);
    assert!(r.model.is_none() && r.auth_override.is_none() && r.legacy.is_empty());
    let value = serde_json::to_value(&r).unwrap();
    let object = value.as_object().unwrap();
    // Invariant 1: no credential-shaped field, ever.
    for key in object.keys() {
        let lower = key.to_ascii_lowercase();
        for forbidden in ["key", "secret", "token", "credential", "password"] {
            assert!(!lower.contains(forbidden), "record has a `{key}` field");
        }
    }
    assert_eq!(value["slug"], json!("acme"));
    assert_eq!(value["kind"], json!("custom"));
    assert_eq!(value["origin"], json!("indexed"));
}

#[test]
fn a_record_round_trips_including_optional_fields() {
    let mut r = record();
    r.model = Some(ModelId::parse("gpt-5").unwrap());
    r.auth_override = Some(AuthStyle::Custom("api-key".into()));
    r.synthetic = true;
    r.origin = RecordOrigin::Imported;
    r.enabled = false;
    let back: ProviderRecord = serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn a_minimal_stored_record_loads_with_defaults() {
    let r: ProviderRecord = serde_json::from_value(json!({
        "id": "p_1", "slug": "acme", "label": "Acme", "kind": "Custom", "base_url": "https://a.test/v1"
    }))
    .unwrap();
    assert!(r.enabled, "enabled defaults to true");
    assert!(!r.synthetic);
    assert_eq!(r.origin, RecordOrigin::Indexed);
    assert_eq!(r.kind.as_str(), "custom", "kind ids normalise on load");
}

#[test]
fn unknown_fields_are_preserved_verbatim_through_a_round_trip() {
    // OpenCompany's tier map and any future field survive a load and a save.
    let stored = json!({
        "id": "p_1", "slug": "acme", "label": "Acme", "kind": "custom", "base_url": "https://a.test/v1",
        "tiers": {"chat-v1": "gpt-5"}, "future_flag": true
    });
    let r: ProviderRecord = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(r.legacy.len(), 2);
    assert_eq!(r.legacy["future_flag"], json!(true));
    let saved = serde_json::to_value(&r).unwrap();
    assert_eq!(saved["tiers"], stored["tiers"]);
    assert_eq!(saved["future_flag"], json!(true));
}

#[test]
fn a_record_with_a_bad_slug_or_model_id_does_not_load() {
    let bad_slug =
        json!({"id":"1","slug":"Bad Slug","label":"x","kind":"custom","base_url":"https://a.test"});
    assert!(serde_json::from_value::<ProviderRecord>(bad_slug).is_err());
    let bad_model = json!({"id":"1","slug":"ok","label":"x","kind":"custom","base_url":"https://a.test","model":"has space"});
    assert!(serde_json::from_value::<ProviderRecord>(bad_model).is_err());
}

#[test]
fn record_origins_serialise_snake_case() {
    for (origin, wire) in [
        (RecordOrigin::Indexed, "indexed"),
        (RecordOrigin::EntryZero, "entry_zero"),
        (RecordOrigin::Imported, "imported"),
    ] {
        assert_eq!(serde_json::to_value(origin).unwrap(), json!(wire));
    }
    assert_eq!(RecordOrigin::default(), RecordOrigin::Indexed);
}

#[test]
fn capabilities_default_to_unknown_never_yes() {
    let caps = Capabilities::default();
    for tri in [
        caps.tools,
        caps.vision,
        caps.reasoning,
        caps.temperature,
        caps.structured_output,
    ] {
        assert_eq!(tri.value, Tri::Unknown);
        assert_eq!(tri.source, CapSource::Default);
        assert!(!tri.value.is_yes());
    }
    assert_eq!(caps.context_window.value, None);
    assert_eq!(caps.max_output.source, CapSource::Default);
    assert_eq!(Tri::default(), Tri::Unknown);
    assert!(Tri::Yes.is_yes() && !Tri::No.is_yes());
}

#[test]
fn sourced_values_remember_where_they_came_from() {
    let ctx = Sourced::new(Some(128_000u64), CapSource::ProviderApi);
    assert_eq!(ctx.value, Some(128_000));
    assert_eq!(ctx.source, CapSource::ProviderApi);
    let json = serde_json::to_value(ctx).unwrap();
    assert_eq!(json, json!({"value": 128000, "source": "provider_api"}));
    let back: Sourced<Option<u64>> = serde_json::from_value(json).unwrap();
    assert_eq!(back, ctx);
    for (source, wire) in [
        (CapSource::LocalProbe, "local_probe"),
        (CapSource::Registry, "registry"),
        (CapSource::UserOverride, "user_override"),
        (CapSource::Default, "default"),
    ] {
        assert_eq!(serde_json::to_value(source).unwrap(), json!(wire));
    }
    let caps = Capabilities::default();
    let back: Capabilities = serde_json::from_value(serde_json::to_value(caps).unwrap()).unwrap();
    assert_eq!(back, caps);
}

#[test]
fn a_descriptor_serialises_for_a_ui_without_leaking_anything_secret() {
    let d = crate::catalogue::descriptor("anthropic").unwrap();
    let value = serde_json::to_value(d).unwrap();
    assert_eq!(value["kind"], json!("anthropic"));
    assert_eq!(value["auth"], json!("anthropic"));
    assert_eq!(value["protocol"], json!("anthropic_messages"));
    assert_eq!(
        value["default_endpoint"],
        json!("https://api.anthropic.com/v1")
    );
    assert_eq!(value["endpoint_editable"], json!(false));
    assert_eq!(d.slug(), "anthropic");
}

#[test]
fn quirks_serialise_snake_case() {
    assert_eq!(
        serde_json::to_value(Quirk::CatalogUnauthenticated).unwrap(),
        json!("catalog_unauthenticated")
    );
    assert_eq!(
        serde_json::to_value(Quirk::ResponsesApi).unwrap(),
        json!("responses_api")
    );
}
