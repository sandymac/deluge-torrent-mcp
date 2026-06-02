# Task Breakdown: Consumer-Shaped MCP Responses (v1)

> Phase 3 (Tasks) of spec-driven development. Companion to
> [`consumer-shaped-responses.md`](./consumer-shaped-responses.md) (spec) and
> [`consumer-shaped-responses-plan.md`](./consumer-shaped-responses-plan.md) (plan).
> Status: **DRAFT — awaiting review.** Do not start Phase 4 (Implement) until approved.

## Conventions for this work

- **Tests are inline `#[cfg(test)]` modules** (project convention — there is no `tests/` dir;
  all 42 existing tests are inline). New pure-module tests live beside their code. A `tests/`
  integration binary is created only if an end-to-end HTTP test is added (T11, optional).
- Every task ends green: `cargo test` + `cargo clippy --all-targets -- -D warnings`.
- Commit per task (small, reviewable); reference the task ID in the message.
- Honor `src/tools/CLAUDE.md` for anything touching tool schemas/descriptions.

## Dependency graph

```
T1 ─┬─→ T2 ──→ T3 ─┐
    └─→ T4 ─────────┼─→ T5 ──→ T6 ──→ T7 ──┬─→ T8 (stdio)
                    │                       └─→ T9 (http) ──→ T10 ──→ T11
   (T2,T4 parallel after T1; T8,T9 parallel after T7)
```

---

## C1 — The DSL

### T1: `ResponseConfig` types + default
- **Description:** Create `src/response_config/mod.rs` with `ResponseConfig`, `Format` (Json),
  `ShapeOpts { whitespace: Whitespace, sparse: bool }`, `Whitespace` (Pretty|Minified),
  `IdSelector` (Full). Derive `Clone, Debug, PartialEq`. `Default` == `json`+`pretty`+`full`.
  Wire the module into `main.rs`/`lib` (`mod response_config;`).
- **Acceptance:** `ResponseConfig::default()` equals json+pretty+full; types are `Clone + Send +
  Sync + 'static` (will live in request extensions).
- **Verify:** `cargo build`; unit test `default_is_json_pretty_full`.
- **Files:** `src/response_config/mod.rs`, `src/main.rs` (module decl).

### T2: The parser + `ConfigParseError`
- **Description:** Add `parse(format_segment: &str, query: &str) -> Result<ResponseConfig,
  ConfigParseError>` and `parse_flag(&str)` (splits on first `?`). Two-stage: resolve format
  (empty → Json; unknown → error), then json param parser — `shape` CSV (`pretty`/`minified`
  mutually exclusive; `sparse` flag) and `ids` (full only). `ConfigParseError: Display` names
  the offending token and lists valid values.
- **Acceptance:** Valid combos parse; `format=`/`/mcp/toon`→err, `shape=bogus`→err,
  `shape=minified,pretty`→err, `ids=short`→err; empty input → default; **HTTP-form and
  STDIO-form of the same config produce the same `ResponseConfig`.**
- **Verify:** unit tests covering the full grammar table incl. the form-equivalence test.
- **Files:** `src/response_config/mod.rs`.
- **Depends:** T1.

---

## C2 — Shape transform (parallel with C3 after T1)

### T3: `shape_response` + `sparsify`
- **Description:** Create `src/response_config/shape.rs`. `shape_response(value, &cfg) ->
  String`: optional `sparsify`, then `to_string`/`to_string_pretty` by whitespace. `sparsify`
  transforms only a `{ "torrents": { <hash>: {fields} }, ... }`-shaped object — emits a sibling
  `defaults` block and omits per-row fields equal to the v1 default set (`download_payload_rate=0,
  eta=0, label="", progress=100.0, state="Seeding", upload_payload_rate=0`, as a `const`); any
  other shape passes through unchanged.
- **Acceptance:** pretty output **byte-identical** to `serde_json::to_string_pretty`; minified
  has no whitespace; sparse emits `defaults` + omits defaulted fields; `{...defaults,...row}`
  round-trips to the full row; non-torrent shapes pass through under sparse.
- **Verify:** unit tests: byte-identical-pretty, no-whitespace-minified, sparse-round-trip,
  non-torrent-passthrough.
- **Files:** `src/response_config/shape.rs`, `src/response_config/mod.rs` (re-export).
- **Depends:** T1.

---

## C3 — IdStrategy seam (parallel with C2 after T1)

### T4: `IdStrategy` trait + `Full`
- **Description:** Create `src/ids/mod.rs`: `trait IdStrategy { encode(&self,&str)->String;
  decode(&self,&str)->Result<String,IdError>; describe(&self)->SchemaFragment; }` + reserved
  batch-resolve signature. `struct Full` — encode=identity, decode=`validate_info_hash` then
  identity (permissive), describe=static fragment. `IdError { NotFound, Ambiguous, Expired,
  Invalid(String) }` with `Display`; error text carries "re-fetch via list_torrents" guidance.
  Reuse existing `validate::validate_info_hash`.
- **Acceptance:** `Full::encode` identity; `decode` accepts valid sha1/sha256 hashes; `decode`
  rejects malformed input with an actionable message; `describe()` returns a non-empty fragment.
- **Verify:** unit tests for encode/decode/describe.
- **Files:** `src/ids/mod.rs`, `src/main.rs` (module decl).
- **Depends:** T1 (for `IdSelector` mapping `Full → Box<dyn IdStrategy>`/enum).

---

## C4 — DelugeServer wiring

### T5: `default_config` field + `resolve_config` helper
- **Description:** Add `default_config: ResponseConfig` to `DelugeServer`; thread it through
  `new(...)` (callers pass `ResponseConfig::default()` for now). Add
  `fn resolve_config(&self, ctx: &RequestContext<RoleServer>) -> ResponseConfig` per the plan
  (read `Parts.extensions::<ResponseConfig>()`, else `default_config`). Add a private
  `fn shape(&self, value, ctx) -> String` convenience wrapping `resolve_config` + `shape_response`.
- **Acceptance:** builds; `resolve_config` returns `default_config` when no Parts present
  (STDIO path); unit test with a synthesized `RequestContext` lacking Parts returns the default.
- **Verify:** `cargo test`; targeted unit test.
- **Files:** `src/tools/mod.rs`.
- **Depends:** T2, T3.

### T6: Capture a "golden" regression baseline
- **Description:** Before changing output sites, add a regression test capturing each read
  tool's current default (pretty) serialized output for a fixed synthetic `Value` input, so
  T7's refactor is provably non-breaking. (Snapshot as inline expected strings or a small
  fixture.) Covers `list_torrents`, `get_torrent_status`, label-action output, resource reads.
- **Acceptance:** tests pass against current code (pre-refactor), pinning today's exact bytes.
- **Verify:** `cargo test` green on unchanged behavior.
- **Files:** `src/tools/values.rs` or new `src/tools/shape_regression_tests.rs` (inline mod).
- **Depends:** T5 (helper available) — but asserts pre-refactor output.

### T7: Route output + hash sites through the seam
- **Description:** Replace each `serde_json::to_string_pretty(...)` output site in
  `handlers.rs` (~lines 55, 91, 225, 247, 522 …) and `mod.rs:324` with `self.shape(value, &ctx)`.
  Add `ctx: RequestContext<RoleServer>` to handlers lacking it (macro supports it; several have
  it). Route every hash-accepting param through `cfg.ids.decode(...)` at handler top (explicit
  placement, Open Q #2). Resource reads (`mod.rs`) and `--test-connection` (`main.rs`) are
  shaped too (post-review revision): resource reads via their `RequestContext`,
  `--test-connection` via the parsed `--response-config`. `sparse` is a structural no-op on
  those shapes; `minified`/`pretty` apply.
- **Acceptance:** T6 golden tests still pass (default config ⇒ identical bytes); all hash
  handling goes through `decode` (grep audit: no direct `validate_info_hash` left in handler
  bodies except via the seam); full suite + clippy green.
- **Verify:** `cargo test`; `cargo clippy --all-targets -- -D warnings`; grep audit.
- **Files:** `src/tools/handlers.rs`, `src/tools/mod.rs` (+ `src/ids/mod.rs` if seam tweaks).
- **Depends:** T4, T5, T6.

---

## C5 / C6 — Transports (parallel after T7)

### T8: STDIO `--response-config` flag
- **Description:** Add `#[arg(long = "response-config", env = "DELUGE_RESPONSE_CONFIG")]
  response_config: Option<String>` to `Cli`. Parse via `parse_flag` at startup; on error, exit
  non-zero with the `ConfigParseError` message. Pass the resulting config (or default) into the
  stdio `DelugeServer::new`.
- **Acceptance:** `--response-config 'json?shape=minified'` ⇒ stdio output has no whitespace;
  invalid value ⇒ non-zero exit with a clear message; absent flag ⇒ today's pretty output;
  `cargo run -- --help` documents the flag.
- **Verify:** unit test on the parse-and-exit path; manual stdio smoke (`--help`, a list call).
- **Files:** `src/main.rs`.
- **Depends:** T2, T5, T7.

### T9: HTTP `/mcp/{format}` middleware
- **Description:** Add a `from_fn` layer on the `/mcp` nest (both auth branches,
  `main.rs:462,503`) that reads the full pre-nest path+query (spike: `OriginalUri` first;
  fallback = read from injected `Parts.uri` in `resolve_config`), `parse(...)`s it, returns
  **400** on error, and inserts `Extension<ResponseConfig>` on success.
- **Acceptance:** `/mcp/json?shape=minified` ⇒ minified; `/mcp/json?shape=sparse` ⇒ sparse;
  `/mcp` and `/mcp/json` ⇒ today's pretty; `/mcp/toon` ⇒ 400 naming valid formats;
  `shape=bogus` ⇒ 400. Works under both static-token and OAuth modes.
- **Verify:** the **C6 routing micro-spike first** (confirm middleware sees pre-nest path);
  then manual curl matrix; unit-test the middleware parse→400/extension logic in isolation.
- **Files:** `src/main.rs`.
- **Depends:** T2, T5, T7.

---

## Hardening & docs

### T10: End-to-end manual matrix + fixups
- **Description:** Run the spec's Success Criteria matrix across both transports; fix any gaps.
  Confirm sparse round-trip on a real multi-torrent response from the live daemon if available.
- **Acceptance:** every spec Success Criterion (1–7) demonstrably holds.
- **Verify:** documented manual run; suite + clippy green.
- **Files:** as needed.
- **Depends:** T8, T9.

### T11 (optional): HTTP integration test
- **Description:** If warranted, add `tests/response_config_http.rs` spinning the axum app and
  asserting 400 on `/mcp/toon` and minified body on `/mcp/json?shape=minified`.
- **Acceptance:** integration test green in CI.
- **Files:** `tests/response_config_http.rs` (creates the `tests/` dir).
- **Depends:** T9.

### T12: Documentation
- **Description:** Update `CLAUDE.md` (clap flag list + a "Consumer-Shaped Responses" section),
  `README` if present, and the `--help`/docs. Note the `format`-segment namespace and that
  shaping is opt-in. Consider an ADR (`docs/adr/0012-*`) recording the per-request config
  resolution decision (factory-can't-see-request) for future maintainers.
- **Acceptance:** docs describe the DSL, defaults, and the OUT-of-scope seams; ADR drafted.
- **Verify:** docs review; links resolve.
- **Files:** `CLAUDE.md`, `docs/adr/0012-...md`, `README*`.
- **Depends:** T10.

---

## Mapping to spec Success Criteria

| Criterion | Task(s) |
|---|---|
| 1 minified parity (stdio/http) | T3, T8, T9 |
| 2 sparse defaults + round-trip | T3 |
| 3 default byte-identical to today | T6, T7 |
| 4 invalid → hard error (400 / non-zero) | T2, T8, T9 |
| 5 all tools route through `decode` | T4, T7 |
| 6 http-form == stdio-form | T2 |
| 7 build/clippy/help | every task + T8, T12 |

## Open questions still to settle (carried)

- **Q1 sparse eligibility:** resolved by T3's structural `{torrents:{...}}` detector — confirm
  that's the only eligible shape in v1 during T3 review.
- **Q2 decode placement:** T7 uses explicit per-handler `decode` (the leaning).
- **Q3 `describe()` injection:** v1 static (T4); dynamic per-session deferred (1.7.0
  `add_route`/`new_dyn` noted in plan).
- **Q4 HTTP path read:** settled by the T9 micro-spike (`OriginalUri` vs injected `Parts.uri`).
