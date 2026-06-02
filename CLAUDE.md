# CLAUDE.md

## Project Overview

An MCP server written in Rust that bridges AI assistants to a running Deluge torrent daemon (`deluged`). Built with the [Model Context Protocol Rust SDK](https://github.com/modelcontextprotocol/rust-sdk), it exposes 21 tools covering torrent management (add, remove, list, pause, resume, status), file operations (move storage, rename folders/files, force recheck), Label-plugin operations (list/create/delete labels, get/set per-label options, assign labels to torrents, pause/resume by label), and server queries (free space, path size).

Supports both **stdio** (Claude Desktop) and **HTTP/SSE** (remote/agentic) transports. Includes tiered safety gates to guard against LLM hallucination, and configurable TLS certificate handling for Deluge's default self-signed certificates. Tools that depend on Deluge plugins (currently the Label plugin) are dynamically shown or hidden based on whether the plugin is enabled on the daemon — toggling the plugin in any Deluge client is reflected in the MCP `tools/list` within seconds via Deluge's `PluginEnabledEvent` / `PluginDisabledEvent` push events.

## Tech Stack
Rust for the code
Cargo for package management and build system

## Dependencies

| Crate | Purpose |
|---|---|
| `rmcp` | Official MCP Rust SDK — stdio and HTTP/SSE transports |
| `tokio` | Async runtime |
| `native-tls` | TLS for Deluge RPC connection — tolerates Deluge's legacy v1 self-signed certificates that rustls rejects |
| `tokio-native-tls` | Async wrapper for native-tls |
| `bytes` | Byte buffer handling for binary protocol framing |
| `flate2` | zlib compression/decompression for Deluge RPC message bodies |
| `serde` | Serialization framework |
| `base64` | Encode .torrent file content for `add_torrent_file` |
| `bendy` | Bencode parser — validates base64 input is a .torrent file in `add_torrent` auto-detection |
| `sha2` | SHA-256 hashing for TLS certificate fingerprint computation |
| `anyhow` | Flexible error handling |
| `thiserror` | Structured error types |
| `axum` | HTTP server for the HTTP/SSE transport |
| `tower-http` | CORS and tracing middleware layers for axum |
| `tracing` | Logging |
| `tracing-subscriber` | Log output formatting — **must be configured to write to stderr or a file, never stdout**. Any output on stdout corrupts the JSON-RPC framing used by the MCP stdio transport. |
| `clap` | CLI args (Deluge host/port/credentials, transport selection, `--enable-tool`, `--disable-tool`, `--list-tools`, `--api-token`, `--http-bind`, `--test-connection`, `--oauth-issuer`, `--oauth-state-file`, `--response-config`) — credentials, OAuth, and response-shaping settings can also be supplied via environment variables (`DELUGE_HOST`, `DELUGE_PORT`, `DELUGE_USERNAME`, `DELUGE_PASSWORD`, `DELUGE_API_TOKEN`, `DELUGE_OAUTH_ISSUER`, `DELUGE_OAUTH_STATE_FILE`, `DELUGE_RESPONSE_CONFIG`) |

rencode serialization is implemented internally as `src/rencode.rs` rather than using a third-party crate.

## Architecture

This is an MCP server that bridges AI models (e.g. Claude) to a running Deluge daemon (`deluged`).

```
MCP Client (Claude Desktop, agentic frameworks, etc.) <--MCP--> deluge-torrent-mcp <--Deluge RPC--> deluged
```

The server supports two MCP transports:
- **stdio** — for local use with Claude Desktop and similar clients
- **HTTP/SSE** — for remote use with network-accessible clients; MCP clients connect to `http://<host>:<port>/mcp`. Protected by optional Bearer token authentication (`--api-token`).

### Deluge RPC API
Deluge exposes a custom binary RPC protocol over TCP (default port 58846). The daemon must be running and accessible. Authentication is required before issuing commands. The API is documented at https://deluge.readthedocs.io/en/deluge-2.0.1/reference/api.html

## MCP Tools

| Tool | Deluge RPC Method | Description |
|---|---|---|
| `add_torrent` | `core.add_torrent_magnet` / `core.add_torrent_url` / `core.add_torrent_file` | Add one or more torrents — source type (magnet, URL, base64 .torrent content) is auto-detected |
| `remove_torrent` | `core.remove_torrent` | Remove one or more torrents, optionally deleting data |
| `list_torrents` | `core.get_torrents_status` | List all torrents with status fields |
| `get_torrent_status` | `core.get_torrent_status` / `core.get_torrents_status` | Get detailed status for one or more torrents |
| `pause_torrent` | `core.pause_torrents` | Pause one or more torrents |
| `resume_torrent` | `core.resume_torrents` | Resume one or more paused torrents |
| `set_torrent_options` | `core.set_torrent_options` | Set options on one or more torrents (e.g. download path, ratio limits) |
| `move_storage` | `core.move_storage` | Move one or more torrents' storage to a new path |
| `rename_folder` | `core.rename_folder` | Rename a folder within a torrent |
| `rename_files` | `core.rename_files` | Rename one or more files within a torrent |
| `force_recheck` | `core.force_recheck` | Force a hash recheck of one or more torrents' files |
| `get_free_space` | `core.get_free_space` | Get free disk space for a given path |
| `get_path_size` | `core.get_path_size` | Get the size of a path on the server |
| `list_labels` | `label.get_labels` | List all labels defined on the daemon (requires Label plugin) |
| `create_label` | `label.add` | Create a new label on the daemon (requires Label plugin) |
| `delete_label` | `label.remove` | Delete a label; assigned torrents become unlabeled (requires Label plugin) |
| `set_torrent_label` | `label.set_torrent` | Assign a label to one or more torrents — empty string or `"No Label"` clears (requires Label plugin) |
| `pause_label` | `core.get_torrents_status` + `core.pause_torrents` | Pause every torrent assigned the given label (requires Label plugin) |
| `resume_label` | `core.get_torrents_status` + `core.resume_torrents` | Resume every torrent assigned the given label (requires Label plugin) |
| `get_label_options` | `label.get_options` | Get a label's default options (speed caps, ratio handling, etc.) (requires Label plugin) |
| `set_label_options` | `label.set_options` | Set a label's default options; applied to every torrent carrying the label (requires Label plugin) |

`list_torrents` accepts filters for `state`, `label` (when the Label plugin is active), `name_contains` (case-insensitive substring, pushed to Deluge's native server-side `name` filter), and `save_path_contains` (case-insensitive substring, applied client-side). It also accepts `sort_by` (one of `name`, `save_path`, `progress`, `total_size`, `download_payload_rate`, `upload_payload_rate`, `eta`, `time_added`, `ratio`) and `sort_order` (`asc` or `desc`). Filters apply before pagination so `total` reflects the filtered count. When the Label plugin is active, each returned torrent also includes its `label`.

Torrents are identified by their **info hash** (40-character SHA-1 or 64-character SHA-256 hex string).

### Safety Gates

Tools have two default states. Eight tools are **disabled by default** to guard against LLM hallucination:

| Tool | Default | Reason |
|---|---|---|
| `add_torrent`, `list_torrents`, `get_torrent_status`, `pause_torrent`, `resume_torrent`, `set_torrent_options`, `get_free_space`, `get_path_size` | enabled | Safe read/write operations |
| `list_labels`, `get_label_options`, `set_torrent_label`, `pause_label`, `resume_label` | enabled (when Label plugin is active) | Read labels or apply/act on existing labels — non-destructive |
| `move_storage`, `rename_folder`, `rename_files`, `force_recheck` | disabled | Modifies filesystem paths or interrupts downloads |
| `create_label`, `delete_label`, `set_label_options` | disabled | Mutates label state — must require explicit operator opt-in |
| `remove_torrent` | disabled | Can permanently delete downloaded data |

Tools are enabled or disabled via `--enable-tool <PATTERN>` / `--disable-tool <PATTERN>`. Patterns are matched as case-sensitive substrings of tool names (minimum 3 characters). Both singular (`--enable-tool`) and plural (`--enable-tools`) forms are accepted. Flags are processed in CLI order — later flags override earlier ones.

`--list-tools` prints all tools with their current visibility, default state, and any plugin gating, and exits without requiring credentials.

When a disabled tool is called, the server returns an error to the LLM. The hint distinguishes between CLI-disabled tools (suggests `--enable-tool=<name>`) and plugin-gated tools (suggests enabling the plugin in Deluge).

### Label Plugin Gating

Eight tools (`list_labels`, `create_label`, `delete_label`, `set_torrent_label`, `pause_label`, `resume_label`, `get_label_options`, `set_label_options`) require Deluge's built-in **Label** plugin to be enabled on the daemon. Visibility rule:

> A label tool is visible to MCP clients **iff** (it is enabled — by default or by `--enable-tool`) **AND** (the Label plugin is currently active on the daemon).

Plugin gating is absolute — `--enable-tool` cannot make a label tool visible if the plugin is inactive. The MCP server detects plugin state via:

1. A one-time probe of `core.get_enabled_plugins` after authentication.
2. Subscription to the daemon's `PluginEnabledEvent` and `PluginDisabledEvent` push events (the same mechanism Deluge's GTK and Web UIs use). Toggling the plugin from any Deluge client — GTK preferences, Web UI, `deluge-console plugin --enable Label` — propagates to the MCP server within seconds.
3. Re-probing on reconnect and on broadcast lag (belt-and-suspenders against missed events).

When the plugin state flips, the MCP server fires `notifications/tools/list_changed` to every connected MCP peer so conforming clients refresh their tool list.

### Wire Format

```
[version: 1 byte][length: 4 bytes big-endian][body: N bytes]
```

- **Body**: rencode-serialized, zlib-compressed
- **Request packet**: `(request_id, method, args, kwargs)`
- **Response types**:
  - `(1, request_id, result)` — RPC_RESPONSE
  - `(2, request_id, exception_type, exception_args, exception_kwargs, traceback)` — RPC_ERROR
  - `(3, event_name, event_args)` — RPC_EVENT (server-initiated)

### Connection & Auth

1. Connect via TLS TCP to `host:port` (default `localhost:58846`)
2. Call `daemon.login(username, password, client_version=...)` — returns auth level (0–10)
3. All subsequent calls are dispatched with the established session

### TLS Certificate Handling

Deluge daemons use self-signed certificates by default. Certificate verification is configurable:

- **Default (skip verification)**: Accepts any certificate. On each connection, logs the certificate's SHA-256 fingerprint at `WARN` level along with the `--cert-fingerprint` flag to use for pinning, making it easy to copy-paste for future use.
- **Pinned fingerprint** (`--cert-fingerprint <SHA256>`): Accepts only a certificate matching the given fingerprint. All others are rejected.

Implemented via `native-tls` with `danger_accept_invalid_certs(true)`. After the TLS handshake, the peer certificate is extracted via `peer_certificate()`, its DER bytes are hashed with SHA-256, and the fingerprint is either verified against the pinned value or logged as a WARN with the copy-pasteable `--cert-fingerprint` flag.

### OAuth State Persistence

By default OAuth state is held in memory only — every registered client, access token, and refresh token is lost on restart, so every MCP client has to re-register and re-consent. Passing `--oauth-state-file <PATH>` (or `DELUGE_OAUTH_STATE_FILE=<PATH>`) activates file-backed persistence for long-lived state.

**What is persisted**: `clients` (dynamic client registrations), `access_tokens`, `refresh_tokens`.
**What is not persisted**: authorization codes (10-min TTL) and pending consent-page sessions (5-min TTL). An in-flight OAuth flow interrupted by a restart simply restarts from the beginning.

**Write strategy**: mutations set a dirty flag; a background task flushes every ~2 s if dirty. A final flush runs on graceful shutdown (Ctrl-C) to capture the last-interval window. Writes are atomic: JSON is written to `<path>.tmp` and then renamed over `<path>`.

**File permissions**: on Unix the file is chmod'd to `0600` before rename because it contains bearer tokens. On Windows the file inherits default ACLs — choose a path inside a user-only directory.

**Missing file on startup**: treated as empty. First-run behavior is unchanged.

**Corrupt / unknown-version file**: logged as a `WARN`, renamed to `<path>.corrupt-<unix_ts>` for recovery, and startup proceeds with empty state rather than crashing. Clients re-register; no data beyond OAuth sessions is affected.

### Consumer-Shaped Responses

An MCP client can declare what kind of consumer it is — a token-sensitive LLM or a byte/parse-sensitive programmatic tool — and receive a JSON payload shaped for it. The configuration is one canonical DSL, parsed by one function (`src/response_config`), and used on both transports:

```
HTTP:   POST /mcp/<format>?<params>     e.g. /mcp/json?shape=minified,sparse
STDIO:  --response-config '<format>?<params>'   e.g. --response-config 'json?shape=minified,sparse'
        (or DELUGE_RESPONSE_CONFIG)
```

The **path segment names the payload format** (the encoding namespace — `json` in v1, reserving `toon`/`xml`/`text` for later). The **query string carries parameters scoped to that format** — a parameter like a future TOON separator means nothing to `json`.

`json`-format parameters (v1):

| Param | Values | Default | Effect |
|---|---|---|---|
| `shape` | `pretty`, `minified`, `sparse` (CSV; `pretty`/`minified` mutually exclusive) | `pretty` | Whitespace + redundancy. `sparse` emits a one-time `defaults` block and omits per-row default-valued fields from `list_torrents`-shaped output (reconstruct a row as `{...defaults, ...row}`). |
| `ids` | `full` | `full` | Selects an `IdStrategy` (`src/ids`). v1 ships `Full` (the id is the 40/64-hex info hash) only. |

**Defaults and back-compat**: plain `/mcp`, `/mcp/json` with no params, and STDIO without the flag all produce today's pretty output. All token-saving shaping is strictly opt-in. An unknown format or invalid parameter is a hard error — `400 Bad Request` on HTTP, non-zero exit at STDIO startup.

**How config reaches a tool**: rmcp's per-session service factory takes no request data, so config is resolved **per request**, not per session. On HTTP, `response_config_layer` (middleware on the `/mcp` routes, outside `nest_service` so it sees the pre-strip path) parses the path+query and inserts a `ResponseConfig` into the request extensions; rmcp copies the `http::request::Parts` into each tool call's `RequestContext`, and `DelugeServer::resolve_config` reads it back, falling back to the startup/STDIO config when absent. Tool handlers serialize via `DelugeServer::shape(value, &ctx)`. See ADR-0012.

**Scope (v1)**: shaping applies to tool outputs. MCP resource reads and `--test-connection` stay pretty (no format/query channel). Not yet built but designed-for: `ids=short` prefix/ephemeral strategies, a `resolve_ids` tool, `toon`/`xml` formats, and `fields=` projection.

## File Structure

| Path | Purpose |
|---|---|
| `Cargo.toml` | The manifest file that defines dependencies, metadata, and crate type. |
| `Cargo.lock` | Contains the exact dependency versions used in the last build. |
| `src/` | Contains all the source code for the project. |
| `src/main.rs` | Entry point — CLI arg parsing, transport selection, server startup, HTTP auth + response-config middleware. |
| `src/rencode.rs` | Internal rencode serializer/deserializer (Deluge wire format). |
| `src/response_config/mod.rs` | The consumer-shaped-response DSL — `ResponseConfig`, the shared parser (HTTP path+query and STDIO flag), parse errors. |
| `src/response_config/shape.rs` | Pure JSON shaping transform — minified/pretty serialization and the sparse (`defaults` block + omit) transform. |
| `src/ids/mod.rs` | The `IdStrategy` seam — `encode`/`decode`/`describe` trait with the v1 `Full` (info-hash-is-id) implementation. |
| `src/deluge/mod.rs` | Deluge RPC client — TLS connection, cert fingerprint logging/pinning, auth, request multiplexing, zlib framing. |
| `src/tools/mod.rs` | MCP tool implementations — all 21 tools, safety gate helpers, plugin watcher, Value→JSON conversion. |
| `src/oauth/persist.rs` | Optional file-backed persistence for OAuth clients + access/refresh tokens — atomic JSON writes, `Instant` ↔ Unix conversion, debounced background flusher. |
| `tests/` | Integration tests. |

## Commands

```bash
# Build the project
cargo build
# Run the project
cargo run
# Run tests
cargo test
# Build documentation
cargo doc --open
```
