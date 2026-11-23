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
- Each server instance ran a plugin watcher and a resource-event forwarder (before this
  decision moved the watcher to process scope; see Decision).

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
A session registers its peer on `initialize` (once, after successful negotiation, pruning
closed peers; rmcp 3 lets clients skip `notifications/initialized`, so registering there
would drop `tools/list_changed` for them). `resources/subscribe` is refused outside an
initialized session; the first one spawns the session's resource-event forwarder, which
exits within 30 s of its session's transport closing, even if the daemon is idle. Peers are
pruned by their own closed state, never by list position, because registration and
fan-out run concurrently. The single watcher never awaits clients itself: it updates the
gate and wakes one persistent fan-out task through a `Notify` (one permit, so rapid toggles
coalesce into one follow-up run). Each run notifies all peers concurrently with a 5 s
timeout per peer, so one client that stops reading cannot stall other sessions or later
toggles. rmcp does not cancel a timed-out send — it stays queued for that session — so
coalescing also bounds the pile-up for a wedged peer to one per run. For the same reason the
resource-event forwarder stops on its first timed-out send rather than queueing one per
event; the session's next `resources/subscribe` starts a fresh forwarder.

Known limitation (pre-existing, also in rmcp 1.x): rmcp restarts a session's idle timer on
every message the server sends and discards sends to a dropped SSE stream. A client that
subscribes and then vanishes without `DELETE /mcp` therefore keeps its session alive for as
long as the daemon keeps producing events.

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
