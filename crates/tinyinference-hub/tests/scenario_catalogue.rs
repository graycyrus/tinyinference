//! A guard for the scenario catalogue (08-test-plan section 4): every named
//! scenario exists as a test, in the file that drives it. Renaming or deleting
//! one fails here instead of silently shrinking the suite.

const HUB_SCENARIOS: &str = include_str!("sim_hub.rs");
const RANDOM_SCENARIOS: &str = include_str!("sim_random.rs");

const CATALOGUE: &[&str] = &[
    "sim_desktop_onboarding",
    "sim_cli_oneshot_env_only",
    "sim_connect_rollback_on_auth",
    "sim_connect_add_anyway",
    "sim_local_rollback_on_timeout",
    "sim_key_rotation_next_call",
    "sim_platform_token_rotation",
    "sim_managed_origin_switch",
    "sim_signed_out",
    "sim_tenant_isolation",
    "sim_refresh_bypass",
    "sim_ssrf_literal_ips",
    "sim_ssrf_redirect_chain",
    "sim_dns_rebinding_scripted",
    "sim_cleartext_credential",
    "sim_offline_local_only",
    "sim_partial_outage",
    "sim_quota_vs_rate",
    "sim_concurrent_writers",
    "sim_delete_vs_pin",
    "sim_disable_fail_closed",
    "sim_store_unreadable",
    "sim_cli_readiness",
    "sim_oauth_disabled",
    "sim_import_oc_then_ops",
    "sim_import_oh_then_resolve",
    "sim_detect_excludes_self",
    "sim_detect_off_when_hosted",
    "sim_slow_stream_completion",
    "sim_malformed_catalogs",
    "sim_paged_catalog",
    "sim_random_regressions",
];

#[test]
fn catalogue_all_thirty_two_scenarios_exist() {
    assert_eq!(CATALOGUE.len(), 32);
    for name in CATALOGUE {
        let declared = format!("async fn {name}(");
        assert!(
            HUB_SCENARIOS.contains(&declared) || RANDOM_SCENARIOS.contains(&declared),
            "the scenario `{name}` is missing"
        );
    }
}

#[test]
fn catalogue_the_guards_have_named_tests() {
    // Every guard of 04-operation-matrix section 2 except G10 (tier routing
    // stays in OpenCompany) has at least one `guard_gNN_` test in the crate.
    let sources = [
        include_str!("../src/ops/test.rs"),
        include_str!("../src/ops/guards_test.rs"),
        include_str!("../src/route/resolve_test.rs"),
        include_str!("../src/import/test.rs"),
        include_str!("guards_foundations.rs"),
        include_str!("guards_engine.rs"),
        include_str!("../src/policy/test.rs"),
        include_str!("../src/ids/test.rs"),
        include_str!("../src/error/test.rs"),
        include_str!("../src/catalog/cache_test.rs"),
        include_str!("../src/catalogue/test.rs"),
        include_str!("../src/health/test.rs"),
    ];
    let all = sources.concat();
    let mut missing = Vec::new();
    for n in (1..=27).filter(|n| *n != 10) {
        let marker = format!("guard_g{n}_");
        let marker_padded = format!("guard_g{n:02}_");
        if !all.contains(&marker) && !all.contains(&marker_padded) {
            missing.push(n);
        }
    }
    assert!(
        missing.is_empty(),
        "guards with no `guard_gNN_` test: {missing:?}"
    );
}
