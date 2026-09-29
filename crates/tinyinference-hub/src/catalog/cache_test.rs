//! Tests for the catalog cache: the invariants OpenCompany learned the hard
//! way, driven by a fake clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::join_all;

use super::*;
use crate::error::{HubError, ProviderFailure, ReasonCode, Retry};
use crate::ids::{ModelId, ScopeKey};
use crate::taxonomy::CatalogShape;
use crate::testkit::FakeClock;

const ENDPOINT: &str = "https://api.acme.test/v1";

fn entry(name: &str) -> ModelEntry {
    ModelEntry::new(ModelId::parse(name).unwrap())
}

fn models(names: &[&str]) -> Vec<ModelEntry> {
    names.iter().map(|n| entry(n)).collect()
}

fn scope(name: &str) -> ScopeKey {
    ScopeKey::new(name)
}

fn cache() -> (CatalogCache, FakeClock) {
    let clock = FakeClock::new();
    (CatalogCache::new(Arc::new(clock.clone())), clock)
}

fn key(scope_name: &str, credentialed: bool) -> CatalogKey {
    CatalogKey::new(
        &scope(scope_name),
        credentialed,
        ENDPOINT,
        CatalogShape::OpenAi,
    )
}

fn failure(reason: ReasonCode, status: Option<u16>) -> HubError {
    let mut f = ProviderFailure::new(reason, Retry::Later(None));
    f.status = status;
    HubError::Provider(f)
}

fn ids(list: &ModelList) -> Vec<&str> {
    list.ids()
}

/// A fetcher that counts calls and answers from a queue.
struct Counter {
    calls: AtomicUsize,
}

impl Counter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    async fn ok(self: Arc<Self>, names: &'static [&'static str]) -> Result<Fetched, HubError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Fetched::new(models(names)))
    }
    async fn err(self: Arc<Self>, error: HubError) -> Result<Fetched, HubError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(error)
    }
}

#[tokio::test]
async fn cache_a_fetch_is_fresh_then_cached_until_the_ttl_then_fetched_again() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    let read = |c: Arc<Counter>| cache.read(key("a", true), false, move || c.ok(&["m1", "m2"]));
    let first = read(counter.clone()).await.unwrap();
    assert_eq!(first.freshness, Freshness::Fresh);
    assert_eq!(ids(&first), ["m1", "m2"]);
    let again = read(counter.clone()).await.unwrap();
    assert_eq!(again.freshness, Freshness::Cached);
    assert_eq!(counter.calls(), 1);
    clock.advance(CATALOG_TTL - Duration::from_secs(1));
    assert_eq!(
        read(counter.clone()).await.unwrap().freshness,
        Freshness::Cached
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        read(counter.clone()).await.unwrap().freshness,
        Freshness::Fresh
    );
    assert_eq!(counter.calls(), 2);
}

#[tokio::test]
async fn cache_the_provider_order_is_preserved() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let list = cache
        .read(key("a", false), false, move || counter.ok(&["z", "a", "m"]))
        .await
        .unwrap();
    assert_eq!(ids(&list), ["z", "a", "m"]);
}

#[tokio::test]
async fn cache_a_failure_is_remembered_for_a_minute_so_an_outage_costs_one_attempt() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    let attempt = |c: Arc<Counter>| {
        cache.read(key("a", false), false, move || {
            c.err(failure(ReasonCode::Endpoint, None))
        })
    };
    let first = attempt(counter.clone()).await.unwrap_err();
    assert_eq!(first.reason(), ReasonCode::Endpoint);
    for _ in 0..5 {
        assert_eq!(
            attempt(counter.clone()).await.unwrap_err().reason(),
            ReasonCode::Endpoint
        );
    }
    assert_eq!(counter.calls(), 1, "the memo answers for the next minute");
    clock.advance(FAILURE_TTL);
    attempt(counter.clone()).await.unwrap_err();
    assert_eq!(
        counter.calls(),
        2,
        "the endpoint is tried again after the memo expires"
    );
}

#[tokio::test]
async fn cache_a_success_after_a_failure_clears_the_memo() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || c.err(failure(ReasonCode::Timeout, None))
        })
        .await
        .unwrap_err();
    clock.advance(FAILURE_TTL);
    let ok = cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || c.ok(&["m"])
        })
        .await
        .unwrap();
    assert_eq!(ok.freshness, Freshness::Fresh);
    let cached = cache
        .read(key("a", false), false, || async {
            panic!("must be cached")
        })
        .await
        .unwrap();
    assert_eq!(cached.freshness, Freshness::Cached);
}

#[tokio::test]
async fn cache_a_401_or_403_is_never_remembered() {
    for (reason, status) in [
        (ReasonCode::Auth, Some(401)),
        (ReasonCode::Auth, None),
        (ReasonCode::Unknown, Some(403)),
        (ReasonCode::Unknown, Some(401)),
    ] {
        let (cache, _) = cache();
        let counter = Counter::new();
        for _ in 0..3 {
            let error = cache
                .read(key("a", true), false, {
                    let c = counter.clone();
                    move || c.err(failure(reason, status))
                })
                .await
                .unwrap_err();
            assert_eq!(error.reason(), reason);
        }
        assert_eq!(
            counter.calls(),
            3,
            "{reason:?}/{status:?}: every caller presents its own key"
        );
    }
}

#[tokio::test]
async fn cache_one_tenants_rejection_is_not_read_back_by_another_or_after_a_rotation() {
    let (cache, _) = cache();
    let counter = Counter::new();
    // Tenant A's key is rejected.
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.err(failure(ReasonCode::Auth, Some(401)))
        })
        .await
        .unwrap_err();
    // Tenant B on the same endpoint with a good key is not affected.
    let b = cache
        .read(key("b", true), false, {
            let c = counter.clone();
            move || c.ok(&["b-model"])
        })
        .await
        .unwrap();
    assert_eq!(ids(&b), ["b-model"]);
    // Tenant A rotates and is tried immediately, with no memo to wait out.
    let a = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["a-model"])
        })
        .await
        .unwrap();
    assert_eq!(ids(&a), ["a-model"]);
}

#[tokio::test]
async fn cache_an_authenticated_list_is_partitioned_by_scope() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let a = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["only-a"])
        })
        .await
        .unwrap();
    let b = cache
        .read(key("b", true), false, {
            let c = counter.clone();
            move || c.ok(&["only-b"])
        })
        .await
        .unwrap();
    assert_eq!((ids(&a), ids(&b)), (vec!["only-a"], vec!["only-b"]));
    assert_eq!(
        counter.calls(),
        2,
        "B never reads A's entitlement-scoped list"
    );
    let a_again = cache
        .read(key("a", true), false, || async { panic!("cached") })
        .await
        .unwrap();
    assert_eq!(ids(&a_again), ["only-a"]);
}

#[tokio::test]
async fn cache_a_keyless_read_is_shared_across_scopes() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || c.ok(&["public"])
        })
        .await
        .unwrap();
    let b = cache
        .read(key("b", false), false, || async { panic!("shared") })
        .await
        .unwrap();
    assert_eq!(ids(&b), ["public"]);
    assert_eq!(counter.calls(), 1);
    assert!(key("a", false).scope().is_none() && key("a", true).scope().is_some());
}

#[tokio::test]
async fn cache_a_keyless_and_a_credentialed_read_do_not_share_a_slot() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || c.ok(&["public"])
        })
        .await
        .unwrap();
    let authed = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["public", "entitled"])
        })
        .await
        .unwrap();
    assert_eq!(ids(&authed), ["public", "entitled"]);
    assert_eq!(counter.calls(), 2);
}

#[tokio::test]
async fn cache_the_shape_is_part_of_the_key() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let openai = CatalogKey::new(&scope("a"), false, ENDPOINT, CatalogShape::OpenAi);
    let paged = CatalogKey::new(&scope("a"), false, ENDPOINT, CatalogShape::PagedEnvelope);
    cache
        .read(openai, false, {
            let c = counter.clone();
            move || c.ok(&["flat"])
        })
        .await
        .unwrap();
    let list = cache
        .read(paged, false, {
            let c = counter.clone();
            move || c.ok(&["paged"])
        })
        .await
        .unwrap();
    assert_eq!(ids(&list), ["paged"]);
}

#[tokio::test]
async fn cache_trailing_slashes_and_spaces_are_the_same_endpoint() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let a = CatalogKey::new(
        &scope("a"),
        false,
        "https://x.test/v1/",
        CatalogShape::OpenAi,
    );
    let b = CatalogKey::new(
        &scope("a"),
        false,
        "  https://x.test/v1 ",
        CatalogShape::OpenAi,
    );
    assert_eq!(a, b);
    cache
        .read(a, false, {
            let c = counter.clone();
            move || c.ok(&["m"])
        })
        .await
        .unwrap();
    cache
        .read(b, false, || async { panic!("same endpoint") })
        .await
        .unwrap();
}

#[tokio::test]
async fn cache_a_hundred_concurrent_callers_make_one_request() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let calls: Vec<_> = (0..100)
        .map(|_| {
            let c = counter.clone();
            cache.read(key("a", true), false, move || async move {
                // Yield so the other callers really do queue behind this one.
                tokio::task::yield_now().await;
                c.ok(&["m"]).await
            })
        })
        .collect();
    let results = join_all(calls).await;
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(counter.calls(), 1, "single flight");
    let fresh = results
        .iter()
        .filter(|r| r.as_ref().unwrap().freshness == Freshness::Fresh)
        .count();
    assert_eq!(fresh, 1, "exactly one caller did the fetching");
}

#[tokio::test]
async fn cache_concurrent_callers_during_an_outage_make_one_request_and_all_see_the_failure() {
    let (cache, _) = cache();
    let counter = Counter::new();
    let calls: Vec<_> = (0..50)
        .map(|_| {
            let c = counter.clone();
            cache.read(key("a", false), false, move || async move {
                tokio::task::yield_now().await;
                c.err(failure(ReasonCode::Timeout, None)).await
            })
        })
        .collect();
    let results = join_all(calls).await;
    assert!(
        results
            .iter()
            .all(|r| r.as_ref().unwrap_err().reason() == ReasonCode::Timeout)
    );
    assert_eq!(counter.calls(), 1, "N callers must not wait N timeouts");
}

#[tokio::test]
async fn cache_refresh_bypasses_a_fresh_entry() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["old"])
        })
        .await
        .unwrap();
    let list = cache
        .read(key("a", true), true, {
            let c = counter.clone();
            move || c.ok(&["new"])
        })
        .await
        .unwrap();
    assert_eq!(
        (list.freshness.clone(), ids(&list)),
        (Freshness::Fresh, vec!["new"])
    );
    let after = cache
        .read(key("a", true), false, || async { panic!("cached") })
        .await
        .unwrap();
    assert_eq!(ids(&after), ["new"]);
}

#[tokio::test]
async fn cache_concurrent_refreshes_share_one_fetch() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["old"])
        })
        .await
        .unwrap();
    let calls: Vec<_> = (0..20)
        .map(|_| {
            let c = counter.clone();
            cache.read(key("a", true), true, move || async move {
                tokio::task::yield_now().await;
                c.ok(&["new"]).await
            })
        })
        .collect();
    let results = join_all(calls).await;
    assert!(results.iter().all(|r| ids(r.as_ref().unwrap()) == ["new"]));
    assert_eq!(counter.calls(), 2, "the first fill plus one shared refresh");
}

#[tokio::test]
async fn cache_a_failed_refresh_serves_the_older_list_with_a_typed_warning() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["old-1", "old-2"])
        })
        .await
        .unwrap();
    clock.advance(CATALOG_TTL + Duration::from_secs(1));
    let list = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.err(failure(ReasonCode::Timeout, None))
        })
        .await
        .unwrap();
    assert_eq!(ids(&list), ["old-1", "old-2"]);
    match &list.freshness {
        Freshness::Stale { failure } => assert_eq!(failure.reason, ReasonCode::Timeout),
        other => panic!("{other:?}"),
    }
    // Within the memo the stale answer keeps coming without another request.
    let again = cache
        .read(key("a", true), false, || async { panic!("memo") })
        .await
        .unwrap();
    assert!(again.is_stale());
    assert_eq!(counter.calls(), 2);
}

#[tokio::test]
async fn cache_a_refresh_button_that_fails_also_falls_back_to_the_older_list() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["old"])
        })
        .await
        .unwrap();
    let list = cache
        .read(key("a", true), true, {
            let c = counter.clone();
            move || c.err(failure(ReasonCode::Endpoint, None))
        })
        .await
        .unwrap();
    assert!(list.is_stale());
    assert_eq!(ids(&list), ["old"]);
}

#[tokio::test]
async fn cache_a_rejected_credential_is_an_error_even_when_an_older_list_exists() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["old"])
        })
        .await
        .unwrap();
    clock.advance(CATALOG_TTL);
    let error = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.err(failure(ReasonCode::Auth, Some(401)))
        })
        .await
        .unwrap_err();
    assert_eq!(error.reason(), ReasonCode::Auth, "a bad key must show");
}

#[tokio::test]
async fn cache_a_failure_with_nothing_older_is_the_error() {
    let (cache, _) = cache();
    let error = cache
        .read(key("a", true), true, || async {
            Err(failure(ReasonCode::RateLimited, Some(429)))
        })
        .await
        .unwrap_err();
    assert_eq!(error.reason(), ReasonCode::RateLimited);
}

#[tokio::test]
async fn cache_stale_data_is_dropped_only_by_pruning_not_by_expiry() {
    let (cache, clock) = cache();
    cache
        .read(key("a", true), false, || async {
            Ok(Fetched::new(models(&["old"])))
        })
        .await
        .unwrap();
    clock.advance(STALE_RETENTION * 3);
    // Still served as stale: retention is enforced when room is needed.
    let list = cache
        .read(key("a", true), false, || async {
            Err(failure(ReasonCode::Endpoint, None))
        })
        .await
        .unwrap();
    assert!(list.is_stale());
}

#[tokio::test]
async fn cache_an_empty_listing_is_fresh_for_a_minute_only() {
    let (cache, clock) = cache();
    let counter = Counter::new();
    let empty = |c: Arc<Counter>| async move {
        c.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Fetched::new(Vec::new()))
    };
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || empty(c)
        })
        .await
        .unwrap();
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || empty(c)
        })
        .await
        .unwrap();
    assert_eq!(counter.calls(), 1);
    clock.advance(EMPTY_CATALOG_TTL);
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || empty(c)
        })
        .await
        .unwrap();
    assert_eq!(
        counter.calls(),
        2,
        "the operator who just pulled a model sees it within a minute"
    );
}

#[tokio::test]
async fn cache_a_truncated_listing_is_flagged_and_stays_flagged_from_the_cache() {
    let (cache, _) = cache();
    let fetched = || async {
        let mut f = Fetched::new(models(&["a"]));
        f.truncated = true;
        Ok(f)
    };
    let first = cache.read(key("a", false), false, fetched).await.unwrap();
    assert!(first.truncated);
    let second = cache
        .read(key("a", false), false, || async { panic!("cached") })
        .await
        .unwrap();
    assert!(second.truncated);
}

#[tokio::test]
async fn cache_a_policy_refusal_or_store_error_is_not_memoised() {
    let (cache, _) = cache();
    let counter = Counter::new();
    for _ in 0..3 {
        let e = cache
            .read(key("a", false), false, {
                let c = counter.clone();
                move || c.err(HubError::Conflict)
            })
            .await
            .unwrap_err();
        assert!(matches!(e, HubError::Conflict));
    }
    assert_eq!(counter.calls(), 3);
}

#[tokio::test]
async fn cache_evicting_a_scope_drops_only_its_authenticated_slots() {
    let (cache, _) = cache();
    let counter = Counter::new();
    cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["a1"])
        })
        .await
        .unwrap();
    cache
        .read(key("b", true), false, {
            let c = counter.clone();
            move || c.ok(&["b1"])
        })
        .await
        .unwrap();
    cache
        .read(key("a", false), false, {
            let c = counter.clone();
            move || c.ok(&["public"])
        })
        .await
        .unwrap();
    assert_eq!(cache.len(), 3);
    cache.evict_scope(&scope("a"));
    assert_eq!(cache.len(), 2);
    // A's rotated key is read on the next call; B and the public entry survive.
    let a = cache
        .read(key("a", true), false, {
            let c = counter.clone();
            move || c.ok(&["a2"])
        })
        .await
        .unwrap();
    assert_eq!(ids(&a), ["a2"]);
    cache
        .read(key("b", true), false, || async { panic!("kept") })
        .await
        .unwrap();
    cache
        .read(key("z", false), false, || async { panic!("kept") })
        .await
        .unwrap();
}

#[tokio::test]
async fn cache_evicting_an_endpoint_drops_every_scope_and_shape() {
    let (cache, _) = cache();
    for (s, cred, shape) in [
        ("a", true, CatalogShape::OpenAi),
        ("b", false, CatalogShape::PagedEnvelope),
    ] {
        cache
            .read(
                CatalogKey::new(&scope(s), cred, ENDPOINT, shape),
                false,
                || async { Ok(Fetched::new(models(&["m"]))) },
            )
            .await
            .unwrap();
    }
    cache
        .read(
            CatalogKey::new(
                &scope("a"),
                false,
                "https://other.test/v1",
                CatalogShape::OpenAi,
            ),
            false,
            || async { Ok(Fetched::new(models(&["o"]))) },
        )
        .await
        .unwrap();
    cache.evict_endpoint(&format!("{ENDPOINT}/"));
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert!(cache.is_empty());
}

#[tokio::test]
async fn cache_it_never_holds_more_than_the_slot_cap_and_keeps_the_hot_ones() {
    let (cache, clock) = cache();
    let hot = CatalogKey::new(
        &scope("hot"),
        false,
        "https://hot.test/v1",
        CatalogShape::OpenAi,
    );
    cache
        .read(hot.clone(), false, || async {
            Ok(Fetched::new(models(&["h"])))
        })
        .await
        .unwrap();
    for n in 0..(MAX_SLOTS + 50) {
        clock.advance(Duration::from_secs(1));
        // Keep the hot slot recently used.
        if n % 50 == 0 {
            cache
                .read(hot.clone(), false, || async {
                    Ok(Fetched::new(models(&["h"])))
                })
                .await
                .unwrap();
        }
        let k = CatalogKey::new(
            &scope("x"),
            false,
            &format!("https://e{n}.test/v1"),
            CatalogShape::OpenAi,
        );
        cache
            .read(k, false, || async { Ok(Fetched::new(models(&["m"]))) })
            .await
            .unwrap();
        assert!(cache.len() <= MAX_SLOTS, "{} slots", cache.len());
    }
    let still_there = cache
        .read(hot, false, || async { panic!("evicted the hot slot") })
        .await
        .unwrap();
    assert_eq!(ids(&still_there), ["h"]);
}

#[tokio::test]
async fn cache_pruning_first_drops_slots_past_the_stale_retention() {
    let (cache, clock) = cache();
    for n in 0..MAX_SLOTS {
        let k = CatalogKey::new(
            &scope("x"),
            false,
            &format!("https://old{n}.test/v1"),
            CatalogShape::OpenAi,
        );
        cache
            .read(k, false, || async { Ok(Fetched::new(models(&["m"]))) })
            .await
            .unwrap();
    }
    assert_eq!(cache.len(), MAX_SLOTS);
    clock.advance(STALE_RETENTION + Duration::from_secs(1));
    let k = CatalogKey::new(
        &scope("x"),
        false,
        "https://new.test/v1",
        CatalogShape::OpenAi,
    );
    cache
        .read(k, false, || async { Ok(Fetched::new(models(&["m"]))) })
        .await
        .unwrap();
    assert_eq!(
        cache.len(),
        1,
        "everything past retention went, nothing else was needed"
    );
}

#[test]
fn cache_debug_never_prints_a_credential_bearing_url() {
    let k = CatalogKey::new(
        &scope("a"),
        true,
        "https://user:hunter2@x.test/v1?key=abc123",
        CatalogShape::OpenAi,
    );
    let debug = format!("{k:?}");
    assert!(
        !debug.contains("hunter2") && !debug.contains("abc123"),
        "{debug}"
    );
    let (cache, _) = cache();
    assert!(format!("{cache:?}").contains("slots"));
}

#[tokio::test]
async fn cache_an_older_empty_list_is_not_served_as_a_stale_answer() {
    // "No models, as of an hour ago" beside a warning hides the failure that
    // matters; the failure is returned instead.
    let (cache, _) = cache();
    cache
        .read(key("a", false), false, || async {
            Ok(Fetched::new(Vec::new()))
        })
        .await
        .unwrap();
    let error = cache
        .read(key("a", false), true, || async {
            Err(failure(ReasonCode::Timeout, None))
        })
        .await
        .unwrap_err();
    assert_eq!(error.reason(), ReasonCode::Timeout);
    // A non-empty older list is still served.
    let other = || {
        CatalogKey::new(
            &scope("a"),
            false,
            "https://other.test/v1",
            CatalogShape::OpenAi,
        )
    };
    cache
        .read(other(), false, || async {
            Ok(Fetched::new(models(&["m"])))
        })
        .await
        .unwrap();
    let list = cache
        .read(other(), true, || async {
            Err(failure(ReasonCode::Timeout, None))
        })
        .await
        .unwrap();
    assert!(list.is_stale());
}

mod cache_props {
    use std::sync::Mutex;

    use proptest::prelude::*;

    use super::*;

    #[derive(Clone, Debug)]
    enum Op {
        Read {
            scope: u8,
            credentialed: bool,
            refresh: bool,
            outcome: u8,
        },
        Advance(u16),
        EvictScope(u8),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..3, any::<bool>(), any::<bool>(), 0u8..4).prop_map(
                |(scope, credentialed, refresh, outcome)| Op::Read {
                    scope,
                    credentialed,
                    refresh,
                    outcome
                }
            ),
            (0u16..4000).prop_map(Op::Advance),
            (0u8..3).prop_map(Op::EvictScope),
        ]
    }

    proptest! {
        /// A tenant never reads another tenant's authenticated list; a fresh
        /// answer means a fetch happened in this very call; a rejected
        /// credential is never remembered (the next read fetches again).
        #[test]
        fn cache_prop_scopes_never_mix_and_rejections_are_never_remembered(ops in proptest::collection::vec(op(), 1..60)) {
            let (cache, clock) = cache();
            let fetches = Arc::new(Mutex::new(0usize));
            for op in ops {
                match op {
                    Op::Advance(secs) => clock.advance(Duration::from_secs(u64::from(secs))),
                    Op::EvictScope(s) => cache.evict_scope(&scope(&format!("s{s}"))),
                    Op::Read { scope: s, credentialed, refresh, outcome } => {
                        let name = format!("s{s}");
                        let before = *fetches.lock().unwrap();
                        let counter = fetches.clone();
                        let label = format!("{name}-{credentialed}");
                        let result = futures::executor::block_on(cache.read(
                            CatalogKey::new(&scope(&name), credentialed, ENDPOINT, CatalogShape::OpenAi),
                            refresh,
                            || async move {
                                *counter.lock().unwrap() += 1;
                                match outcome {
                                    0 | 1 => Ok(Fetched::new(vec![entry(&format!("{label}-model"))])),
                                    2 => Err(failure(ReasonCode::Auth, Some(401))),
                                    _ => Err(failure(ReasonCode::Timeout, None)),
                                }
                            },
                        ));
                        let fetched_now = *fetches.lock().unwrap() > before;
                        if let Ok(list) = &result {
                            for model in &list.models {
                                let id = model.id.as_str();
                                if credentialed {
                                    prop_assert!(id.starts_with(&format!("{name}-true")), "{name} read {id}");
                                } else {
                                    prop_assert!(id.ends_with("-false-model"), "{name} read {id}");
                                }
                            }
                            if list.freshness == Freshness::Fresh {
                                prop_assert!(fetched_now, "Fresh without a fetch");
                            }
                        }
                        if let Err(error) = &result
                            && error.reason() == ReasonCode::Auth
                        {
                            prop_assert!(fetched_now, "an Auth error must come from a fetch, never a memo");
                        }
                    }
                }
            }
        }
    }
}
