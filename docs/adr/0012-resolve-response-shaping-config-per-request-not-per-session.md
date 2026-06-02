# 12. Resolve response-shaping config per request, not per session

Date: 2026-06-02

## Status

Accepted

## Context

We wanted MCP clients to declare what kind of consumer they are — a token-sensitive
LLM or a byte/parse-sensitive programmatic tool — and receive a JSON payload shaped
for them (minified, sparse, abbreviated ids). The configuration is a small DSL carried
on the HTTP URL (`/mcp/<format>?<params>`) and the STDIO `--response-config` flag.

The original design sketch assumed the parsed config would be threaded into the
per-session `DelugeServer` factory. A spike against the rmcp `StreamableHttpService`
source disproved that assumption:

- The service factory is `Fn() -> Result<S, io::Error>` — it takes **no arguments** and
  fires once per session (on the `initialize` request). It cannot see the request path
  or query, so per-request data (format segment + query) cannot reach it.
- rmcp instead injects the `http::request::Parts` of each request into that request's
  `RequestContext.extensions`, and axum `Extension`-layer state propagates into
  `Parts.extensions`.
- `StreamableHttpService` dispatches only on HTTP method; it never inspects the path.
  `nest_service("/mcp", …)` routes `/mcp/<anything>` to the same service, so validating
  the format segment is the application's responsibility, not rmcp's.

## Decision

Resolve the `ResponseConfig` **per request**, not per session:

- On HTTP, an axum middleware (`response_config_layer`) on the `/mcp` routes — applied
  outside `nest_service` so it sees the pre-strip `/mcp/<format>` path — parses the
  path+query, returns `400 Bad Request` on a malformed format/param, and inserts a
  `ResponseConfig` into the request extensions. rmcp copies the request `Parts` (with
  that extension) into each tool call's `RequestContext`.
- `DelugeServer::resolve_config(ctx)` reads the config back from the injected `Parts`,
  falling back to a startup default when absent.
- On STDIO there is no request, so the `--response-config` flag is parsed once at
  startup into that same default. The flag also serves as the HTTP fallback default.
- Tool handlers serialize through `DelugeServer::shape(value, &ctx)`. Hash handling is
  routed through an `IdStrategy` seam (`decode`), with `Full` (identity) as the only v1
  strategy, so future id-abbreviation schemes are additive.

## Consequences

- A single grammar and parser serve both transports; the same `<format>?<params>`
  string is byte-identical between the HTTP path+query and the STDIO flag.
- Config is correctly per-request on HTTP: two requests in one session can ask for
  different shapes. This is impossible with a per-session factory.
- Every JSON-producing handler must take a `RequestContext` and call `shape()`; the
  per-request read is a small indirection on each call rather than a one-time setup.
- The default config makes `shape()` call `to_string_pretty` verbatim, so existing
  clients that opt into nothing see byte-identical output (with one deliberate
  consistency fix: a few read paths that previously emitted minified now default to
  pretty like every other tool).
- Shaping applies to all JSON the server emits: tool outputs, MCP resource reads (which
  reach the same per-request config via their `RequestContext`), and the `--test-connection`
  diagnostic (which uses the parsed `--response-config` directly, so it also demonstrates the
  switch is in effect). `sparse` is a structural no-op on the resource/diagnostic shapes since
  they are not the `{"torrents": {...}}` envelope `sparsify` targets; `minified`/`pretty` apply.
