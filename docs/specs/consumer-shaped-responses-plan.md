# Implementation Plan: Consumer-Shaped MCP Responses (v1)

> Phase 2 (Plan) of spec-driven development. Companion to
> [`consumer-shaped-responses.md`](./consumer-shaped-responses.md) (the spec).
> Status: **DRAFT — awaiting review.** Do not start Phase 3 (Tasks) until approved.

## Spike findings (rmcp 1.7.0 — load-bearing facts)

> Validated against **rmcp 1.7.0** (`Cargo.toml` now pins `1.7.0`; the lock had already
> resolved the caret `^1.2.0` to 1.7.0, so the build was on 1.7.0 all along). The build, all
> 42 existing tests, and `cargo clippy --all-targets -- -D warnings` pass on 1.7.0 with no code
> changes. All three findings below were re-confirmed in `rmcp-1.7.0/.../tower.rs`.
>
> **New 1.7.0 APIs considered and their bearing on this effort:**
> - `Extension<T>` tool-param extractor (`handler/server/common.rs:142`) — reads
>   `RequestContext.extensions.get::<T>()` directly. *Does not* simplify our case: rmcp inserts
>   only `http::request::Parts` at that level, so our `ResponseConfig` lives one level deeper in
>   `Parts.extensions`; and the extractor hard-errors when absent (breaks STDIO, which has no
>   Parts). The `resolve_config(&ctx)` helper below stays the chosen approach.
> - Dynamic tool routes (`ToolRouter::add_route` / `new_dyn` / `list_all`) — a viable hook for
>   per-session `describe()` schema fragments **if** we later build them; v1 ships `describe()`
>   static, so this is noted-for-later, not used now.

Read `tower.rs` to validate the threading model. Three facts override the design doc's
stated approach:

1. **The service factory takes NO arguments.**
   ```rust
   service_factory: Arc<dyn Fn() -> Result<S, std::io::Error> + Send + Sync>
   ```
   It is invoked once per session on the `initialize` POST (`get_service()` at tower.rs:246).
   It **cannot see the request path or query.** → The design doc's "thread `ResponseConfig`
   into the per-session factory (`src/main.rs:412`)" is **not feasible for per-request data**
   (format segment + query vary per request; the factory fires once per session).

2. **rmcp injects `http::request::Parts` into each request's extensions** (tower.rs:445-456,
   505-506), reachable from a tool handler via `RequestContext`:
   ```rust
   let parts = ctx.extensions.get::<http::request::Parts>();
   ```
   State added via an axum `Extension` layer also lands in `parts.extensions` (documented at
   tower.rs:165-187). → The path+query (and a middleware-pre-parsed `ResponseConfig`) are
   reachable **per-request, inside the handler** — this is the supported seam, not the factory.

3. **`StreamableHttpService` dispatches only on HTTP method** (`handle()` at tower.rs:259) —
   it never inspects the path. `nest_service("/mcp", svc)` matches `/mcp` and `/mcp/*`, so
   `/mcp/json`, `/mcp/toon`, `/mcp/anything` all route to the same service. → **Format-segment
   validation is OUR middleware's job**, not rmcp's. An unknown format must be rejected by the
   middleware (400) or it would silently succeed as default.

### Resulting threading model (replaces the design doc's factory model)

`ResponseConfig` is resolved **per call** by a single helper on `DelugeServer`:

```
STDIO:  config fixed at startup from --response-config. Stored on DelugeServer. No Parts exist;
        helper returns the stored config.
HTTP:   middleware parses (format segment + query) → ResponseConfig once per request, returns
        400 on parse error, inserts Extension<ResponseConfig> on success. Handler's
        RequestContext carries the Parts; helper reads the per-request config from there,
        falling back to the stored default if absent.
```

```rust
// on DelugeServer
fn resolve_config(&self, ctx: &RequestContext<RoleServer>) -> ResponseConfig {
    ctx.extensions
        .get::<http::request::Parts>()
        .and_then(|p| p.extensions.get::<ResponseConfig>().cloned())   // HTTP per-request
        .unwrap_or_else(|| self.default_config.clone())                // STDIO / fallback
}
```

This is one helper, two sources, and it is the only place that knows where config comes from.

## Components & dependency order

```
   ┌─────────────────────────────────────────────────────────────┐
   │ C1  response_config: ResponseConfig + parser + ConfigParseError│  (pure, no deps)
   └───────────────┬───────────────────────────┬───────────────────┘
                   │                            │
        ┌──────────▼──────────┐      ┌──────────▼─────────────┐
        │ C2  shape transform │      │ C3  ids: IdStrategy     │  (pure)
        │ (minified/sparse)   │      │ trait + Full impl       │
        └──────────┬──────────┘      └──────────┬─────────────┘
                   │                            │
        ┌──────────▼────────────────────────────▼─────────────┐
        │ C4  DelugeServer wiring: default_config field,        │
        │     resolve_config(ctx) helper, route all output      │
        │     sites through shape(), all hash sites through ids │
        └──────────┬───────────────────────────────────────────┘
                   │
        ┌──────────▼──────────┐      ┌────────────────────────┐
        │ C5  STDIO: --response│      │ C6  HTTP: /mcp/{format} │
        │ -config flag → cfg   │      │ middleware → Extension  │
        └─────────────────────┘      └────────────────────────┘
```

C1 is the foundation. C2 and C3 are independent pure modules built on C1's types and can be
done in parallel. C4 wires them into `DelugeServer` (depends on C1–C3). C5 and C6 are the two
transport call sites (depend on C4) and can be done in parallel. Tests accompany each.

## Per-component detail

### C1 — `src/response_config/mod.rs` (the DSL)
- `ResponseConfig { format: Format, shape: ShapeOpts, ids: IdSelector }` — `Clone`, in request
  extensions so `Send + Sync + 'static`.
- `ShapeOpts { whitespace: Whitespace /* Pretty|Minified */, sparse: bool }`.
- `Format` enum — `Json` only; parser rejects others. `IdSelector` — `Full` only.
- `parse(format_segment: &str, query: &str) -> Result<ResponseConfig, ConfigParseError>`:
  two-stage — resolve format (empty → `Json`; unknown → error), then dispatch to the json
  param parser (`shape` CSV with `minified`/`pretty` mutual-exclusion check; `ids`).
- STDIO convenience: `parse_flag(s: &str)` splits on first `?` into `(format, query)` and calls
  `parse`. Guarantees HTTP and STDIO share one grammar.
- `ConfigParseError` — `Display` names the offending token + valid values.
- **Default:** `ResponseConfig::default()` == `json` + `pretty` + `full` == today's behavior.

### C2 — `src/response_config/shape.rs` (pure transform)
- `shape_response(value: serde_json::Value, cfg: &ResponseConfig) -> String` (the C1 snippet).
- `sparsify(value)` — operates only on a `{ "torrents": { <hash>: {fields} } }`-shaped object
  (the `list_torrents` / multi-`get_torrent_status` output). Detects structurally; on any other
  shape returns the value unchanged. Emits a sibling `defaults` block and omits per-row fields
  equal to the v1 default set (`download_payload_rate=0, eta=0, label="", progress=100.0,
  state="Seeding", upload_payload_rate=0`). Defaults declared as a `const`/`static` for v1.
- Pretty path must be **byte-identical** to current `to_string_pretty` output (regression guard).

### C3 — `src/ids/mod.rs` (IdStrategy seam)
- `trait IdStrategy { encode(&self,&str)->String; decode(&self,&str)->Result<String,IdError>;
  describe(&self)->SchemaFragment; }` + a batch resolve signature reserved for `resolve_ids`.
- `struct Full;` — `encode` = identity; `decode` = today's `validate_info_hash` then identity
  (permissive: full hash always accepted); `describe` = static fragment documenting the full
  info hash.
- `IdError` — `NotFound | Ambiguous | Expired` variants reserved; `Full` only produces a
  validation error. Error text carries actionable "re-fetch via list_torrents" guidance so the
  `Expired` path is non-breaking to add later.

### C4 — `DelugeServer` wiring (`src/tools/mod.rs` + `handlers.rs`)
- Add `default_config: ResponseConfig` field; `new(...)` gains a `ResponseConfig` arg
  (default-injected by callers). Add `resolve_config(&self, ctx)` helper.
- **Output sites** — replace each `serde_json::to_string_pretty(...)` in `handlers.rs`
  (lines ~55, 91, 225, 247, 522, …) and `mod.rs` (324) with `self.shape(value, &cfg)`. Every
  handler that produces JSON must obtain `cfg` via `resolve_config(&ctx)` → add
  `ctx: RequestContext<RoleServer>` to handlers that lack it (the `#[tool]` macro already
  supports it; several handlers take it today). Mechanical, ~21 sites.
- **Hash sites** — route every `validate_info_hash` / hash-accepting param through
  `cfg.ids.decode(...)` at the top of the handler (Open Q #2: explicit placement). For `Full`
  this is behaviorally identical to today.
- **Scope guard:** resource reads (`mod.rs:488,508`) and `--test-connection` (`main.rs:350`)
  stay `pretty` in v1 — they have no format/query channel. Note in code + spec.

### C5 — STDIO flag (`src/main.rs`)
- New `#[arg(long = "response-config", env = "DELUGE_RESPONSE_CONFIG")] response_config:
  Option<String>`. Parse via `parse_flag` at startup; on error, exit non-zero with the message.
  Pass the resulting `ResponseConfig` (or default) into the stdio `DelugeServer::new`.

### C6 — HTTP middleware (`src/main.rs`)
- A `from_fn` layer on the `/mcp` nest: read the original URI (`OriginalUri` to get the
  pre-nest `/mcp/{format}` path), extract the format segment + query, `parse(...)`. On error →
  `400` with the message. On success → `request.extensions_mut().insert(cfg)`; the rmcp service
  later copies request `Parts` (incl. extensions) into the handler's `RequestContext`.
- Confirm the layer sees the full path (pre-nest) — `OriginalUri` or layering above
  `nest_service`. This is the one detail to verify first in implementation (small spike).
- Applies in both auth modes (OAuth and static-token branches at `main.rs:462,503`).

## Risks & mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Middleware can't see pre-nest `/mcp/{format}` path | **High** (blocks C6) | Verify `OriginalUri` first; fallback = read stripped path from rmcp-injected `Parts.uri` inside the handler instead of middleware. Spike before C6. |
| Adding `RequestContext` to ~21 handlers is churny / risky | Med | Mechanical; covered by the byte-identical pretty regression test on every tool's output. Do C4 in one focused pass, run full test suite. |
| `sparsify` shape-detection misfires on a non-torrent payload | Med | Structural guard: only transform `{torrents:{hash:{...}}}`; round-trip test + pass-through test for other shapes. |
| Pretty output drifts from today (silent contract break) | Med | Golden/regression test captures current output of each read tool before refactor; assert unchanged for default config. |
| `describe()` per-session schema injection has no hook | Low (v1) | Ship `describe()` as a static fragment in v1; defer per-session injection (Open Q #3). Does not block `Full`. |
| Sparse default set wrong for a user's library | Low | Lossless by construction (`{...defaults,...row}`); wrong defaults only cost tokens, never correctness. |

## Verification checkpoints (between phases)

- **After C1:** `cargo test response_config` — grammar table green; HTTP-form == STDIO-form.
- **After C2:** shaper unit tests — pretty byte-identical, minified no-whitespace, sparse
  round-trips, non-torrent pass-through.
- **After C3:** `Full` identity + decode-accepts-full-hash + decode-rejects-garbage.
- **After C4:** full `cargo test` green (regression: every tool's default output unchanged);
  `cargo clippy -- -D warnings`.
- **After C5+C6:** manual matrix — `/mcp/json?shape=minified`, `/mcp/json?shape=sparse`,
  `/mcp/toon` (→400), `/mcp` (→ today's pretty); STDIO `--response-config 'json?shape=minified'`
  and an invalid value (→ non-zero exit). Confirm `cargo run -- --help` documents the flag.

## What stays OUT (re-stated from spec)

`ids=short`/`Prefix`/`Ephemeral`, `resolve_ids` tool, `toon`/`xml`/`text` formats, `fields=`
projection, per-call overrides, resource-read shaping, subprocess/multi-instance. The seams
(`Format` enum, `IdSelector`, `IdError` variants, `describe()`) are built so each is additive.

## Open questions carried into Tasks

Same four as the spec (sparse eligibility detection, decode placement, `describe()` injection,
HTTP routing/config lifetime). Spike finding resolves the spec's Open Q #4 *direction*
(per-request via request extensions, not the factory); the remaining sub-question is only
"`OriginalUri` vs read-from-injected-`Parts`", to be settled in the C6 spike.
