# tinyinference-hub

One provider taxonomy, catalogue, typed error taxonomy, and endpoint policy for
every TinyInference host (OpenCompany, OpenHuman, the TUI, CLIs, future
servers).

Two hosts used to implement provider management separately: two catalogues of
the same hosted vendors, two error classifiers, and safety invariants (SSRF
policy, credential redaction) that only one had. This crate is the shared
answer. It is a **leaf**: it depends on `tinyinference-llm` (plus small
utility crates), nothing depends on it, and no existing public item of any
other crate changed.

This build ships the foundations and the engine: ports, credential chain, model
catalogs, probing, health and the kind drivers. Operations, route resolution and
the `ChatModel` factory follow (see "Roadmap").

## What is here

| Module | What it gives you |
|---|---|
| `error` | `HubError`, the stable `ReasonCode` wire vocabulary, `Retry`, and `classify(status, headers, body)`, which turns a vendor response into a `ProviderFailure`. A spend cap is `quota` and never retried; a rate limit is `rate_limited` and carries the provider's own delay. |
| `Secret`, `LogOnly` | Wrappers that redact themselves in `Debug` and `Display`. `Secret` has no `Serialize`; `LogOnly` holds raw upstream text that may echo request material. |
| `ids` | `Slug`, `ModelId`, `KindId`, `ScopeKey`, `AgentKey`, `WorkloadKey`, and the validators ported from OpenCompany (`slugify`, `check_provider_name`, `check_slug`, `check_model_id`). |
| `taxonomy` | Groups, transports, protocols, `AuthStyle`, catalog shapes, `TestDepth`, `CliKind`, and `LocalRuntime`, which reconciles the four local-runtime enums by conversion. |
| `catalogue`, `descriptor` | Every built-in kind as data: the managed kind, 26 cloud providers, 5 local runtimes, 2 CLI logins, with typed quirks. `ProviderRecord` is a configured instance and has no credential field. |
| `config` | `HubConfig` (the persisted document: providers, default, per-agent pins, forward-compatible extra fields; refuses credentials at any depth and documents from a newer schema), `DefaultChoice`, `ModelChoice`, `ProviderDraft`. |
| `policy`, `endpoint` | `EndpointPolicy` presets (`hosted`, `desktop`, `local_only`), `check_endpoint`, `check_address`, redirect checks, `HeaderPolicy`, and endpoint credential refusal, redaction and scrubbing. |
| `ports` | The traits a host implements: `CredentialStore` (get/set/delete; an error is never "no key"), `ConfigStore` (compare-and-swap), `Http`, `Clock`, plus `HealthStore`, `EventSink` and `EnvSource` (in-memory or no-op defaults in `ports::memory`) and the optional `TokenSource` and `Detector` (a host supplies them when it has a rotating token or first-run detection). `ports::memory` has in-memory implementations; `follow_redirects` is the policy-enforcing redirect loop an `Http` implementation shares. |
| `credential` | The ordered `CredentialChain` of `CredentialSource`s (store, environment, static, rotating token, legacy slot). It reports which source answered, re-reads on every call, stops on an unreadable source instead of falling through, and treats a blank value as "not here". |
| `catalog` | Tolerant listing parsers (OpenAI shape including a bare array, Ollama `/api/tags`, LM Studio `/api/v0/models`, the TinyHumans paged envelope), the `CatalogCache` (endpoint-keyed, scope-partitioned when a credential was sent, a rejected key or `403` never remembered, single-flight, stale on error), and `merge_metadata` for registries and operator overrides. |
| `probe`, `health` | `run_probe` at three depths (`KeyOnly`, `Catalog`, `Completion`) with a `ProbeReport`; `HealthTracker` folds probes and real turns (`Outcome`) into `ProviderHealth` (`Ok`, `Degraded`, `Down`, `SignedOut`, ...). |
| `kinds` | `KindDriver` and the built-in drivers (OpenAI-compatible, Anthropic, managed, local, CLI) plus the `DriverRegistry`. A host adds a kind with `register`. |
| `testkit` (feature `testing`) | `FakeClock`, `ScriptedHttp` (applies the same endpoint policy a real `Http` must), and `run_contract`, the suite every driver passes. No sockets, no wall clock. |

## Guarantees

- **A credential is never printed or stored on a record.** `Secret` redacts in
  `Debug` and `Display` and does not implement `Serialize`; `ProviderRecord` has
  no credential field.
- **Raw upstream error text is log-only.** It never reaches `Display`, `Debug`,
  or `HubError::user_message`.
- **Only a rejected credential rolls back an add** (a local runtime also rolls
  back when it is unreachable). The classifier's auth branch is a positive list
  of phrases, so a body it does not recognise keeps the key.
- **SSRF policy on every URL and address.** Link-local and metadata addresses
  are refused under every policy; alternative IPv4 spellings, `localhost` by
  name, and IPv4 embedded in IPv6 (mapped, NAT64, compatible) get the answer for
  the address a client would actually connect to.

## Example

```rust
use tinyinference_hub::{ReasonCode, Retry, classify};

// An Anthropic spend cap arrives as a 429. It is a quota problem, not a
// cooldown: never retried.
let failure = classify(
    429,
    &[],
    r#"{"type":"error","error":{"type":"rate_limit_error","message":"You have reached your specified API usage limits."}}"#,
);
assert_eq!(failure.reason, ReasonCode::Quota);
assert_eq!(failure.retry, Retry::Never);
```

## Features

`default = []`.

| Feature | Effect |
|---|---|
| `local-bridge` | `From`/`TryFrom` between `LocalRuntime` and `tinyinference-local`'s `LocalProviderKind` and `LocalAiProvider`. |
| `testing` | The `testkit` module: `FakeClock`, `ScriptedHttp`, `ContractFixture`, `run_contract`. Always available to this crate's own tests. |
| `cli`, `oauth`, `http-reqwest` | `cli` adds the `ProcessSpawner` port (readiness arrives later). `oauth` and `http-reqwest` are reserved and add nothing yet; `oauth` will only ever define types: no OAuth flow is enabled. |

## Known limits of this slice

- `Http` is a port the host implements; the hub ships the scripted double, not a
  socket implementation (`http-reqwest` is reserved). Turn traffic uses
  `tinyinference-llm`'s own transport, so the hub's per-hop redirect and
  IP-pinning guarantees will cover probes and catalogs, not chat turns.
- The managed kind's endpoint, catalog shape and query are supplied by the host,
  because OpenCompany and OpenHuman reach different backends.

## Roadmap

1. Foundations (done): errors, secrets, identifiers, taxonomy, catalogue,
   endpoint policy.
2. Engine (this crate as it stands): ports, credential chain, model catalog
   cache, probing, health, kind drivers, contract suite.
3. Operations: the `Hub` facade and operation set over the `ConfigStore` (the
   types and the compare-and-swap store already exist), route resolution, import
   readers, the `ChatModel` factory, detection, and the seeded scenario runner.
