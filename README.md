# Deluge Torrent MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Model Context Protocol (MCP) server that bridges AI assistants (like Claude) to a Deluge torrent daemon (`deluged`).

It exposes torrent management — adding, removing, listing, status queries, pause/resume, label organization, and file operations — as MCP tools, communicating with `deluged` over its native TCP RPC protocol.

---

## Overview

An AI-controllable interface to a running Deluge daemon, with guardrails. The server exposes 21 tools covering the full torrent lifecycle:

- **Manage torrents** — add (magnet, URL, or `.torrent` file — auto-detected), remove, list, pause, resume, set options, and read detailed status.
- **File Management** of torrents and files in them on the filesystem (must be enabled) — move storage, rename folders/files, force a recheck, and query free space / path size.
- **Organize with labels** — list/create/delete labels, assign them, pause/resume a whole label at once, and read or write per-label option defaults. Label tools appear automatically when Deluge's **Label** plugin is enabled.

Key properties:

- **Safety gates** — tools that can delete data or rewrite paths are **disabled by default** and must be turned on individually, so a hallucinating model can't wreck your library.
- **Two transports** — **stdio** for a local client like Claude Desktop, and **HTTP/SSE** for a network-accessible, always-on server with optional token or OAuth 2.1 authentication.
- **Configurable response shaping** — per-client JSON formatting (minified and/or defaults-factoring to balance token count vs reasoning abilities) on both transports, with more encodings planned.
- **Flexible TLS** — works out of the box with Deluge's default self-signed certificate, log lines provide an easy copy-paste pinning mechanism for pinning to a cert.
- **Native RPC** — speaks Deluge's binary protocol (rencode/zlib over TLS) directly, deluged thinks it's another client.

**What you'll need:**

- A reachable running **Deluge 2.x** daemon (`deluged`) with the RPC interface reachable, and its RPC credentials (see [Credentials](#credentials)).
- **Rust and Cargo** to build the binary (see [Install](#install)).

---

## Install

This MCP server is distributed as source until matured. Build a release binary with Cargo (you'll need [git](https://git-scm.com/install/) and [Rust and Cargo](https://rustup.rs/)):

```bash
git clone https://github.com/sandymac/deluge-torrent-mcp.git
cd deluge-torrent-mcp
cargo build --release
```

The compiled binary lands at `target/release/deluge-torrent-mcp`.

Sanity-check the build without touching a daemon via `--help` or `--list-tools`:

```bash
./target/release/deluge-torrent-mcp --list-tools
```

---

## Configuration

The server talks to your Deluge daemon the same way regardless of transport — what differs is how your AI client reaches the server:

- **stdio** — the client launches the server as a child process on demand and talks to it over stdin/stdout. Best for a single local client like Claude Desktop. No network exposure, no auth to manage.
- **HTTP/SSE** — you run the server as a long-lived process and clients connect over the network to `http://<host>:<port>/mcp`. Best for remote access, multiple clients, or agentic frameworks. Protect it with a bearer token or OAuth (see [Client Setup](#client-setup)).

**Quick start — stdio:** 

```bash
DELUGE_USERNAME=admin DELUGE_PASSWORD=secret ./deluge-torrent-mcp
```

**Quick start — HTTP, listening on the LAN:**

```bash
DELUGE_USERNAME=admin DELUGE_PASSWORD=secret DELUGE_API_TOKEN=your-secret-token \
  ./deluge-torrent-mcp --transport http --http-bind 0.0.0.0:8080
```

Both connect to a Deluge daemon at `127.0.0.1:58846` by default. Point elsewhere with `--host`/`--port`. The sections below cover everything you can tune; the full flag list is in the [CLI reference](#cli-reference).

### Credentials

The MCP server authenticates to Deluge with an RPC username and password. On the daemon these live in Deluge's `auth` file — typically `~/.config/deluge/auth` (or `/config/auth` in many Docker images) — as `username:password:level` lines.

Supply them by flag (`-u`/`-p`) or, preferably, by environment variable (`DELUGE_USERNAME` / `DELUGE_PASSWORD`):

> **Prefer environment variables for credentials.** Passwords passed as CLI flags show up in process listings (`ps`); environment variables don't.

### Safety gates

By default the server runs in a **safe mode**: the AI can list, add, pause, and resume torrents, but cannot alter the filesystem, remove torrents, or mutate the label set. The following tools are disabled until you explicitly turn them on:

| Tool | Why it's off by default |
|---|---|
| `move_storage` | Moves files on disk |
| `rename_folder` | Modifies filesystem paths |
| `rename_files` | Modifies filesystem paths |
| `force_recheck` | Interrupts active downloads |
| `remove_torrent` | Can permanently delete downloaded data |
| `create_label` | Mutates the label set on the daemon |
| `delete_label` | Removes labels (destructive) |
| `set_label_options` | Rewrites per-label default options (speed caps, move-completed path, etc.) |

See the full inventory and current state with:

```bash
deluge-torrent-mcp --list-tools
```

Turn tools on or off by name or substring pattern (minimum 3 characters). Flags are processed in order, so a later flag overrides an earlier one:

```bash
# Enable a single tool
deluge-torrent-mcp --enable-tool move_storage

# Enable several at once (comma-separated)
deluge-torrent-mcp --enable-tools=move_storage,rename_folder,rename_files

# Enable everything risky, then carve out the most dangerous one
deluge-torrent-mcp --enable-tools=move_storage,rename_folder,rename_files,force_recheck,remove_torrent \
  --disable-tool remove_torrent
```

When the AI calls a disabled tool, the server returns an error naming the exact flag needed to enable it.

### Labels

Deluge ships a built-in **Label** plugin, disabled by default, for grouping and bulk-operating on torrents. When it's enabled on the daemon, the server exposes eight label-aware tools:

| Tool | Default |
|---|---|
| `list_labels` | enabled |
| `get_label_options` | enabled |
| `set_torrent_label` | enabled |
| `pause_label` | enabled |
| `resume_label` | enabled |
| `create_label` | disabled — requires `--enable-tool=create_label` |
| `delete_label` | disabled — requires `--enable-tool=delete_label` |
| `set_label_options` | disabled — requires `--enable-tool=set_label_options` |

`list_torrents` accepts filters for `state`, `label` (when the plugin is active), `name_contains` (case-insensitive substring, pushed to Deluge's native server-side `name` filter), and `save_path_contains` (case-insensitive substring, applied client-side). It also accepts `sort_by` (one of `name`, `save_path`, `progress`, `total_size`, `download_payload_rate`, `upload_payload_rate`, `eta`, `time_added`, `ratio`) and `sort_order` (`asc` or `desc`). Filters apply before pagination so `total` reflects the filtered count. When the plugin is active, each returned torrent also includes its `label`.

> **Watch the substring match.** Because `--enable-tool` matches any substring of a tool name, a single `--enable-tool=label` turns on *every* label tool — including the default-disabled `create_label`, `delete_label`, and `set_label_options`. Use a specific pattern like `--enable-tool=create_label` to enable just one.

**Dynamic visibility.** Label tools show up in the client's tool list only while the Label plugin is enabled on the daemon. The server subscribes to Deluge's `PluginEnabledEvent` / `PluginDisabledEvent` push events (the same mechanism the GTK and Web UIs use), so toggling the plugin from any Deluge client propagates to connected MCP peers within seconds via a `notifications/tools/list_changed` notification — no restart required. `--enable-tool` cannot make a label tool visible if the plugin is inactive on the daemon.

### Response shaping

A client can declare what kind of consumer it is — a token-sensitive LLM, or a byte/parse-sensitive program — and receive JSON shaped to match. The default is **minified** JSON, because the common consumer is a token-sensitive LLM; pass `shape=pretty` when you want human-readable output.

**Quick start** — human-readable output for debugging, on either transport:

```bash
# stdio: fixed for the life of the process
deluge-torrent-mcp --response-config 'json?shape=pretty'

# HTTP: chosen per request via the URL path + query
POST /mcp/json?shape=pretty
```

It's one DSL — `<format>?<params>` — used in both places. Plain `/mcp`, `/mcp/json` with no params, and stdio with no flag all produce minified output.

`json`-format parameters (v1):

| Param | Values | Default | Effect |
|---|---|---|---|
| `shape` | `pretty`, `minified`, `defaults` (comma-separated; `pretty`/`minified` are mutually exclusive) | `minified` | Whitespace and redundancy. `defaults` emits a one-time `defaults` block and omits default-valued fields from `list_torrents`-shaped output — reconstruct a row as `{...defaults, ...row}`. |
| `ids` | `full` | `full` | How torrent ids are rendered. v1 ships `full` only (the id is the 40/64-character info hash). |

Notes:

- `defaults` applies to large, repetitive payloads (such as `list_torrents`) and is a no-op elsewhere; `minified`/`pretty` apply everywhere. Which payloads it covers may expand over time.
- An unknown format or invalid parameter is a hard error: `400 Bad Request` on HTTP, non-zero exit at stdio startup.
- `--test-connection` honors the shaping flag, so you can run it once to *see* the shape before wiring up a client.

> **Rule of thumb:** the default `minified` (add `defaults` for `list_torrents`-heavy use) keeps token use low for LLM clients. Pass `shape=pretty` when you're reading the output yourself.

### TLS certificate handling

Deluge daemons generate a unique self-signed certificate by default.

- **Default behavior** — certificate verification is skipped, so the server connects out of the box. On each connection it logs a `WARN` to stderr containing the certificate's SHA-256 fingerprint **and the ready-to-paste `--cert-fingerprint` flag**. A `--test-connection` run logs the same line, so it's the easiest way to grab the value.
- **Secure pinning** — copy that fingerprint into `--cert-fingerprint`. The server then rejects any certificate that doesn't match:

```bash
deluge-torrent-mcp --cert-fingerprint "A1:B2:C3:..."
```

---

## Client Setup

### Claude Desktop (stdio)

Add the server to your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Use the absolute path to the compiled binary and your Deluge RPC credentials:

```json
{
  "mcpServers": {
    "deluge": {
      "command": "/absolute/path/to/target/release/deluge-torrent-mcp",
      "args": [
        "--host", "127.0.0.1",
        "--port", "58846"
      ],
      "env": {
        "DELUGE_USERNAME": "localclient",
        "DELUGE_PASSWORD": "your_rpc_password"
      }
    }
  }
}
```

> Restart Claude Desktop after editing this file.

### Remote / HTTP clients

Start the server with the HTTP transport, then point clients at `http://<host>:8080/mcp`:

```bash
deluge-torrent-mcp -u admin -p secret --transport http --http-bind 0.0.0.0:8080 --api-token "your-secret-token"
```

> The default `--http-bind` is `127.0.0.1:8080` (loopback only). Pass `0.0.0.0:8080` to listen on all interfaces, as above.

Choose an authentication mode:

**Shared token — simple, recommended.** Set `--api-token` (or `DELUGE_API_TOKEN`). Every request must carry the token:

```
Authorization: Bearer your-secret-token
```

> **Always set a token when binding to a network interface.** Without one, anyone who can reach the port can control Deluge.

**OAuth 2.1 — for internet-facing access.** When remote clients connect back to your MCP server over the internet, set `--oauth-issuer` to the **public HTTPS URL** clients reach (e.g. `https://mcp.dyn.dns`, not a localhost URL) to enable the embedded OAuth 2.1 authorization server (authorization-code flow with PKCE, dynamic client registration, an admin-gated consent screen, and refresh-token rotation):

```bash
deluge-torrent-mcp -u admin -p secret --transport http \
  --oauth-issuer https://mcp.dyn.dns \
  --api-token "your-access-code" \
  --oauth-state-file /home/youruser/.local/share/deluge-mcp/oauth-state.json
```

> **Set `--api-token` alongside `--oauth-issuer`.** The consent screen is gated by the `--api-token` value — it's the "Access Code" an operator must enter to approve a client registration. Without `--api-token`, the consent screen has no password and **anyone who can reach it can click through and obtain a token**. With it set, OAuth gives each client its own revocable credential *and* the token gates who may authorize new clients. The same token also keeps working as a static bearer-token fallback.

- Discovery metadata is published at `<issuer>/.well-known/oauth-authorization-server`; conforming clients register and obtain tokens automatically (subject to the consent gate above).
- By default OAuth state is in-memory, so every client must re-register after a restart. Pass `--oauth-state-file <PATH>` to persist client registrations and tokens across restarts. Writes are atomic; on Unix the file is `chmod`'d to `0600` because it holds bearer tokens — on Windows, place it inside a user-only directory.

**Behind a reverse proxy / TLS.** The server speaks plain HTTP only — terminate TLS at a reverse proxy (nginx, Caddy, Traefik). When the proxy forwards a public hostname, add it with `--allowed-host` (or `DELUGE_ALLOWED_HOST`), otherwise the built-in DNS-rebinding guard rejects the request with `403`. The loopback hosts, the `--http-bind` host, and the `--oauth-issuer` host are accepted automatically.

---

## CLI reference

```bash
deluge-torrent-mcp --host 192.168.1.50 --port 58846 -u admin -p secret [OPTIONS]
```

| Flag | Env variable | Default | Description |
|---|---|---|---|
| `--host <HOST>` | `DELUGE_HOST` | `127.0.0.1` | Deluge daemon hostname or IP (IPv6: bare address, e.g. `::1`) |
| `--port <PORT>` | `DELUGE_PORT` | `58846` | Deluge RPC port |
| `-u, --username <USER>` | `DELUGE_USERNAME` | — | Deluge RPC username |
| `-p, --password <PASS>` | `DELUGE_PASSWORD` | — | Deluge RPC password |
| `--cert-fingerprint <SHA256>` | — | — | Pin the daemon's TLS certificate by fingerprint. A successful `--test-connection` (or any connection) logs the exact value to paste here. |
| `--enable-tool <PATTERN>` | — | — | Enable tools matching pattern (min 3 chars, substring match). Repeatable, comma-separated |
| `--disable-tool <PATTERN>` | — | — | Disable tools matching pattern. Flags are processed in order; last wins |
| `--list-tools` | — | off | Print all tools with their default enabled/disabled state and exit (no daemon connection needed) |
| `--transport <stdio\|http>` | — | `stdio` | MCP transport to use |
| `--http-bind <ADDR>` | — | `127.0.0.1:8080` | Bind address for the HTTP transport. Use `0.0.0.0:8080` for all interfaces (IPv6: bracket notation, e.g. `[::]:8080`) |
| `--allowed-host <HOST>` | `DELUGE_ALLOWED_HOST` | — | Extra Host header value(s) to accept on the HTTP transport, for when behind a reverse proxy. Repeatable, comma-separated |
| `--api-token <TOKEN>` | `DELUGE_API_TOKEN` | — | Bearer token required for HTTP requests (recommended). In OAuth mode it also gates the consent screen as the operator Access Code |
| `--oauth-issuer <URL>` | `DELUGE_OAUTH_ISSUER` | — | Public HTTPS base URL clients reach over the internet; setting it enables OAuth 2.1 mode |
| `--oauth-state-file <PATH>` | `DELUGE_OAUTH_STATE_FILE` | — | Persist OAuth client registrations and tokens across restarts (only meaningful with `--oauth-issuer`) |
| `--response-config <FORMAT?PARAMS>` | `DELUGE_RESPONSE_CONFIG` | `minified` | Shape stdio JSON output, e.g. `json?shape=pretty` for human-readable output |
| `--test-connection` | — | off | Connect to Deluge, verify connection, cert fingerprint, response config, and exit |

---

## Development & Testing

When developing or modifying this server, do not test against your primary Deluge instance — you risk accidental data loss. Spin up a disposable daemon with Docker instead:

```yaml
# docker-compose.yml
services:
  deluge:
    image: lscr.io/linuxserver/deluge:latest
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC
      - DELUGE_DAEMON_LOG_LEVEL=info
    volumes:
      - ./test-config:/config
      - ./test-downloads:/downloads
    ports:
      - 58846:58846 # RPC Port
    restart: unless-stopped
```

Run `docker-compose up -d`, read the generated credentials from `./test-config/auth`, and point the server at `127.0.0.1:58846`.

Contributor notes (architecture, the in-tree Deluge RPC implementation, the stdout/JSON-RPC framing constraint, and more) live in [`CLAUDE.md`](CLAUDE.md) and the ADRs under [`docs/adr/`](docs/adr/).

---

## License

Copyright (c) 2026 Sandy McArthur, Jr.

This project is licensed under the [MIT License](LICENSE). Third-party dependency licenses are listed in [THIRD_PARTY_LICENSES.html](https://htmlpreview.github.io/?https://github.com/sandymac/deluge-torrent-mcp/blob/main/THIRD_PARTY_LICENSES.html).
