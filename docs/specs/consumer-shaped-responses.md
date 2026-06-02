# Spec: Consumer-Shaped MCP Responses (v1 / MVP)

> Status: **DRAFT — awaiting review.** Phase 1 (Specify) of spec-driven development.
> Companion design doc: [`docs/ideas/consumer-shaped-responses.md`](../ideas/consumer-shaped-responses.md).
> Source motivation: [issue #9](https://github.com/sandymac/deluge-torrent-mcp/issues/9).
> Branch: `feat/consumer-shaped-responses`.

## Objective

Let an MCP client **declare what kind of consumer it is** — a token-sensitive LLM or a
byte/parse-sensitive programmatic tool — and receive a JSON payload shaped for it, configured
**per-endpoint on HTTP** (query string) and **per-flag on STDIO** (`--response-config`),
without forking tool schemas or opening a second Deluge connection.

**Why:** In a representative 1,541-torrent library, `list_torrents` output is ~142k tokens
minified, of which 99.8% of rows are byte-for-byte identical across six "boring" fields, and
the 40-char info-hashes alone cost ~25% of the payload. Pretty-printing buys an LLM nothing.
The current single response shape forces every consumer to pay for whitespace and redundancy
they don't want.

**Who is the user:** the operator configuring the server, on behalf of the MCP client
(Claude Desktop over STDIO, or an agentic framework over HTTP).

**What success looks like:**
- An operator can opt a session into `shape=minified` and/or `shape=sparse` and measurably
  shrink read-path payloads, with **zero change to existing clients that opt into nothing**.
- The shaping is one grammar, one parser, two call sites — adding a future axis value (e.g.
  `ids=short`, `format=toon`) lights up on both transports at once.
- An `IdStrategy` seam exists and all 21 tools route id handling through it, so a future
  abbreviation scheme is additive rather than cross-cutting — even though v1 ships only `Full`.

### Non-goals (explicitly OUT of v1 — see design doc "Not Doing")

`ids=short` / `Prefix` / `Ephemeral` id abbreviation (touches the write contract);
`resolve_ids` tool; `toon` / `xml` / TSV / columnar formats; `fields=` projection; per-call
format overrides; any subprocess or multi-instance; path-as-backend-selector.

## Tech Stack

Rust (edition per `Cargo.toml`), Cargo. No new *runtime* dependencies; `serde_json` for the
`Value` transform, `clap` for the new STDIO flag, the existing `axum` middleware layer for HTTP
parsing. rmcp transport is **not** modified. (As built, one new **dev**-dependency — `tower`,
test-only — was added for the router-level middleware tests; it was already transitive.)

## Commands

```bash
cargo build                 # Build
cargo test                  # Run unit + integration tests
cargo test response_config  # Run just the new parser/shaping tests (by name filter)
cargo clippy -- -D warnings # Lint (matches project CI expectations)
cargo run -- --help         # Verify the new --response-config flag is documented
```

## Project Structure

```
src/main.rs                      → CLI: new --response-config flag; `response_config_layer`
                                   axum middleware that parses /mcp/<format>?<params> and inserts
                                   a ResponseConfig into the request extensions. NOTE (as built):
                                   config is resolved PER REQUEST from the rmcp-injected
                                   http::request::Parts, not threaded through the per-session
                                   factory — see ADR-0012. Also shapes --test-connection.
src/response_config/mod.rs       → NEW. The shared DSL: ResponseConfig struct, the ONE parser
                                   (takes a (format_segment, query) pair from either transport),
                                   format dispatch + json param parser, parse-error type. Pure.
src/response_config/shape.rs     → NEW. The pure JSON Value → Value transform: minified vs
                                   pretty serialization choice, sparse (defaults-block + omit).
src/ids/mod.rs                   → NEW. IdStrategy trait (4 responsibilities) + Full impl.
src/tools/mod.rs                 → DelugeServer gains a default_config field + resolve_config/
                                   shape helpers; tool, resource-read, and bulk-label output
                                   sites route through the shaper; id handling routes through
                                   IdStrategy (validate_info_hash → Full::decode).
(tests)                          → Inline #[cfg(test)] modules (project convention; no tests/
                                   dir): parser grammar in response_config/mod.rs, shaping +
                                   round-trip in shape.rs, and tower-based router tests of the
                                   middleware in main.rs.
docs/specs/consumer-shaped-responses.md  → this spec
docs/ideas/consumer-shaped-responses.md  → the design doc it implements
```

## The Config DSL (decided)

Two-level grammar: **the path segment names the payload format** (the encoding namespace —
`json` in v1, reserving `toon` / `xml` / `text` / … for later). **The query string carries
parameters scoped to that format.** Parameters are format-relative: `shape=sparse` is
meaningful to `json`; a hypothetical `sep=tab` is meaningful to `toon` but nonsense to `json`.
The same `<format>?<params>` string is used on both transports.

```
HTTP:   /mcp/json?shape=minified,sparse              (format = path segment; params = query)
        /mcp/json?shape=minified,sparse&ids=full
        /mcp                                          (no segment → default format, see below)

STDIO:  --response-config 'json?shape=minified,sparse'   (same "<format>?<params>" string)
        --response-config 'json'                          (format only, default params)
```

The single parser takes a `(format_segment, query_string)` pair (HTTP) or splits the STDIO
string on the first `?` into the same pair, then:
1. resolves the **format** segment (v1: only `json` is valid; empty → `json` default),
2. dispatches to that format's **parameter parser** for the query string.

This keeps formats and their parameters cohesive: adding `toon` later means adding a `toon`
format with its own param set (e.g. a separator), without touching the `json` param grammar.

> **vs. design doc:** the doc sketched both `/mcp/json?...` (path) and a query-only `format=`
> axis. We adopt the **path-segment-for-format** form per operator decision — it models
> "format namespace" correctly and makes format-scoped params natural. The STDIO `<format>?<params>`
> string mirrors it exactly (format before the `?` on both transports).

### `json`-format parameters (v1)

| Param | Values (v1) | Default | Meaning |
|---|---|---|---|
| `shape` | `pretty`, `minified`, `sparse` (CSV; `minified`/`pretty` mutually exclusive) | `pretty` | Whitespace + redundancy shaping. |
| `ids` | `full` | `full` | Selects an `IdStrategy`. Only `full` is valid in v1. |

- **`shape=pretty`** — today's behavior, `serde_json::to_string_pretty`. **Default.**
- **`shape=minified`** — `serde_json::to_string` (no whitespace).
- **`shape=sparse`** — the sparse-omission transform (issue #9 approach #2). May combine with
  `minified` (`shape=minified,sparse`) or with `pretty` (sparse = which fields are present;
  whitespace is orthogonal).

### Default format + shape: **json + pretty** (decided — backward compatible)

Plain `/mcp` (no segment), `/mcp/json` with no params, and bare STDIO all behave **exactly as
today** (json, pretty). All token-saving shaping is strictly opt-in. This protects existing
programmatic consumers from a surprise contract change and honors the design doc's "sparse
stays strictly opt-in" assumption.

### Parse errors: **hard error** (decided)

An unknown **format** segment (e.g. `/mcp/toon` in v1), an unknown **parameter** or value
(`shape=bogus`, `ids=short`), or a contradictory combination (`shape=minified,pretty`) is a
**hard failure**:
- **STDIO:** the server refuses to start; `main` exits non-zero with a clear message naming
  the offending format/param and listing valid values.
- **HTTP:** the request is rejected with **400 Bad Request** and a body naming the offending
  format/param. An unknown format segment must 400 (not 404) so the message can name the valid
  formats. A bad config must never silently fall back to the default.

No silent "warn and ignore" — a typo'd token must never masquerade as a working config.

## The Sparse Model (decided — issue #9 approach #2)

Emit a one-time `defaults` block; per torrent, **omit any field whose value equals its
default**. Lossless: the consumer reconstructs a row as `{...defaults, ...torrent}`.

```json
{ "defaults": { "state": "Seeding", "progress": 100.0, "label": "",
                "eta": 0, "download_payload_rate": 0, "upload_payload_rate": 0 },
  "torrents": { "<hash>": { "name": "…", "save_path": "…", "total_size": 2533709373 }, … } }
```

**Default values for v1** (from the issue's measured distribution):
`download_payload_rate=0`, `eta=0`, `label=""`, `progress=100.0`, `state="Seeding"`,
`upload_payload_rate=0`. The defaults set is fixed/declared in code for v1 (not computed from
the response). The exact field list and which tools' outputs are eligible for sparse shaping
are pinned down in the Open Questions below before implementation.

**Sparse applies to the read path only** — list/status outputs that are maps of torrents.
Scalar or single-object outputs (e.g. `get_free_space`) are passed through unchanged.

## IdStrategy Seam (decided — full trait, route all tools through it)

Define the trait with all four responsibilities from the design doc; implement `Full` only.

```rust
trait IdStrategy {
    fn encode(&self, full_hash: &str) -> String;          // identity for Full
    fn decode(&self, token: &str) -> Result<String, IdError>;  // PERMISSIVE: full hash always accepted
    fn describe(&self) -> SchemaFragment;                 // teaches the LLM the id rules
    // resolve_ids tool surface — defined as the contract, Full impl is identity batch
}
```

- `decode` is **permissive**: the full 40/64-hex hash is always accepted regardless of active
  strategy (token shapes are distinguishable), so routing every tool through `decode` now is
  safe and a no-op for `Full`.
- All 21 tools' hash-accepting parameters route through `decode` at the top of the handler
  (leaning toward the explicit `cfg.ids.decode(token)?` placement — greppable, no serde magic;
  see Open Questions). Output rendering of hashes routes through `encode`.
- `describe()` returns the id schema fragment; v1's `Full` fragment documents that the id is
  the full info hash. The per-session dynamic-schema hook (precedent: plugin gating +
  `tools/list_changed`) is the delivery path — confirm it exists before relying on it.

This is the larger-diff option, chosen so a future `Prefix`/`Ephemeral` strategy is purely
additive.

## Code Style

Match surrounding code. Tool/response conventions live in `src/tools/CLAUDE.md` and must be
honored. The shaper is a pure function — no I/O, fully unit-testable:

```rust
/// Shape a tool's JSON output for the declared consumer. Pure transform; never touches I/O.
pub(crate) fn shape_response(value: serde_json::Value, cfg: &ResponseConfig) -> String {
    let value = match cfg.shape.sparse {
        true => sparsify(value),          // defaults-block + omit; no-op on non-torrent-map shapes
        false => value,
    };
    match cfg.shape.whitespace {
        Whitespace::Minified => serde_json::to_string(&value),
        Whitespace::Pretty   => serde_json::to_string_pretty(&value),
    }
    .unwrap_or_default()
}
```

The parser returns `Result<ResponseConfig, ConfigParseError>` and is the single source of
truth for valid axes/values — both call sites depend on it.

## Testing Strategy

`cargo test`; unit tests inline (`#[cfg(test)]`) for the parser and shaper, integration tests
in `tests/response_config.rs`.

- **Parser tests:** every valid combination parses; every invalid token (unknown axis, unknown
  value, `minified,pretty` contradiction, `format=toon`, `ids=short`) returns a
  `ConfigParseError` naming the token. HTTP-query form and STDIO-flag form of the *same* string
  produce the *same* `ResponseConfig` (single-grammar guarantee).
- **Shaper tests:** `pretty` output is byte-identical to today's output (regression guard);
  `minified` has no whitespace; `sparse` emits the `defaults` block and omits default-valued
  fields; **round-trip** — merging `defaults` into each sparse row reproduces the full row
  (losslessness). Non-torrent-map outputs pass through sparse unchanged.
- **IdStrategy tests:** `Full::encode`/`decode` are identity; `decode` accepts a full hash;
  `decode` of malformed input errors.
- **Threading test:** a `ResponseConfig` built from a flag string reaches a tool handler and
  changes its serialized output (in-process, no transport surgery).
- **Default-behavior test:** plain `/mcp` and bare STDIO produce today's pretty output.

Coverage expectation: every parser branch and every shape value exercised. No coverage % gate,
but no untested parser branch.

## Boundaries

- **Always:** run `cargo test` and `cargo clippy -- -D warnings` before any commit; keep
  shaping strictly opt-in; keep the parser the single source of truth for valid axes; honor
  `src/tools/CLAUDE.md` for any tool-schema-facing change; keep `pretty` output byte-identical
  to today (regression test).
- **Ask first:** adding any crate dependency; changing the DSL grammar (format segment / param
  set); modifying the rmcp transport; changing any tool's *input* contract (id decode placement
  that alters arg schemas); persisting any new state.
- **Never:** emit short/abbreviated ids in v1 (write-contract change, OUT of scope); make
  sparse or minified the default; silently ignore an unknown config token; write to stdout
  (corrupts STDIO JSON-RPC framing); open a second Deluge connection or spawn a subprocess.

## Success Criteria

1. `--response-config 'json?shape=minified'` over STDIO and `/mcp/json?shape=minified` over
   HTTP both produce identical whitespace-free `list_torrents` output. *(test + manual)*
2. `shape=sparse` output contains a `defaults` block, omits default-valued fields, and
   `{...defaults, ...row}` reconstructs each full row exactly. *(round-trip test)*
3. Plain `/mcp`, `/mcp/json`, and bare STDIO output are byte-identical to the pre-change
   output. *(regression test)*
4. An unknown format (`/mcp/toon`) or invalid param (`shape=bogus`, `ids=short`,
   `minified,pretty`) yields a hard error: 400 on HTTP, non-zero exit on STDIO. *(test + manual)*
5. All 21 tools route hash handling through `IdStrategy::decode`; `Full` is the only impl and
   is a behavioral no-op. *(test + grep audit)*
6. The HTTP-query and STDIO-flag forms of the same config string parse to the same
   `ResponseConfig`. *(test)*
7. `cargo test` and `cargo clippy -- -D warnings` pass; `cargo run -- --help` documents
   `--response-config`.

## Open Questions (resolve before/within Phase 2 Plan)

1. **Sparse field eligibility.** Issue #9's defaults are for `list_torrents`' specific key set.
   Which tool outputs are eligible for sparse, and how does `sparsify` detect a "torrent map"
   shape generically vs. keying off known tool names? *(Leaning: apply only to outputs that are
   a `{hash: {fields}}` map; detect structurally.)*
2. **Decode placement.** Explicit `cfg.ids.decode(token)?` at the top of each hash-accepting
   tool (greppable, no magic — leaning this way) vs. a `TorrentId` newtype resolved during arg
   deserialization (prettier, but serde can't see per-session runtime state). *(Leaning explicit.)*
3. **Dynamic per-session schema for `describe()`.** Confirm the schema-build hook that the
   plugin-gating / `tools/list_changed` machinery uses can carry an id-schema fragment. If it
   can't cleanly, v1 may ship `describe()` as a static fragment and defer per-session injection.
4. **HTTP routing + config lifetime.** *(Direction resolved by the Phase-2 spike — see the
   plan doc.)* rmcp's service factory takes **no arguments**, so config cannot be threaded
   through the factory as the design doc assumed. rmcp instead injects `http::request::Parts`
   (and axum `Extension`-layer state) into each request's `RequestContext`, so `ResponseConfig`
   is resolved **per request** from request extensions, with the STDIO/startup config as the
   fallback. Remaining sub-question for the C6 spike: read the `/mcp/{format}` path via
   `OriginalUri` in middleware vs. from the rmcp-injected `Parts.uri` inside the handler.

## Phase Gate

This is Phase 1 (Specify). **Do not proceed to Phase 2 (Plan) until this spec is reviewed and
approved.** Plan → Tasks → Implement follow, each gated.
