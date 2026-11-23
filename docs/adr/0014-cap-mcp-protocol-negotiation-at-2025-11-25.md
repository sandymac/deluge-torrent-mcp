# 14. Cap MCP protocol negotiation at 2025-11-25

Date: 2026-11-23

## Status

Accepted

## Context

rmcp 3.x adds MCP protocol revision `2026-07-28`, and by default a server advertises every
revision the SDK knows. `2026-07-28` removes the `initialize` handshake and sessions
(SEP-2567): clients discover the server via `server/discover` and every request is served
statelessly, even when the HTTP transport runs in legacy session mode.

Several features of this server depend on `initialize` and a long-lived session:

- `DelugeServer::initialize` records each peer in `connected_peers`, which is how the plugin
  watcher delivers `notifications/tools/list_changed` when the Label plugin flips (ADR-0008).
- Resource subscriptions (`resources/subscribe`) keep a `Peer` to push `resources/updated`.
- Each server instance runs a plugin watcher and a resource-event forwarder.

A `2026-07-28` client would get none of the push behaviour, with no error on either side.

Separately, rmcp 3 runs the HTTP session factory for *any* request it routes statelessly —
`server/discover`, and sessionless POSTs carrying inline `_meta` (protocol version + client
capabilities) — even in legacy session mode, and even when the request is then rejected for
its version. The factory used to spawn both background tasks, so each such request leaked
two tasks that lived until process exit.

## Decision

Override `ServerHandler::supported_protocol_versions` to
`ProtocolVersion::known_up_to(&ProtocolVersion::LATEST_WITH_INITIALIZE)` — every revision
through `2025-11-25`. `initialize` negotiates with `negotiate_initialize` against that list,
and `server/discover` advertises only it. The HTTP transport keeps
`legacy_session_mode(true)` explicitly.

Keep the session factory and `DelugeServer::new` side-effect free. The tool gate, the
registry of initialized peers, and the Label-plugin watcher are process-wide
(`SharedState`, one watcher per process), so stateless requests also see live plugin state.
A session registers its peer on `notifications/initialized` (once, pruning closed peers) and
spawns its resource-event forwarder on its first `resources/subscribe`; the forwarder exits
within 30 s of its session's transport closing, even if the daemon is idle.

## Consequences

- An `initialize` requesting `2026-07-28` is answered with `2025-11-25` (standard
  version fallback); the client gets a full session or disconnects. `server/discover` and
  stateless requests naming `2026-07-28` are rejected (`-32022`) with the supported list.
  Current clients negotiate `2025-11-25` or earlier as before.
- Stateless requests at a supported version (inline `_meta`, no `initialize`) are still
  served with live tool gating, but receive no push notifications.
- Raising the ceiling requires moving peer tracking, subscriptions and the plugin watcher
  onto SEP-2575 listen streams.
  A unit test (`protocol_negotiation_is_capped_at_last_initialize_revision`) fails if the
  ceiling moves without that work.
