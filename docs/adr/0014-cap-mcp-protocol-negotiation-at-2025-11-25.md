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
- The HTTP session factory spawns one plugin watcher per session; served statelessly it
  would spawn one per request.

A `2026-07-28` client would get none of the push behaviour, with no error on either side.

## Decision

Override `ServerHandler::supported_protocol_versions` to
`ProtocolVersion::known_up_to(&ProtocolVersion::LATEST_WITH_INITIALIZE)` — every revision
through `2025-11-25`. `initialize` negotiates with `negotiate_initialize` against that list,
and `server/discover` advertises only it. The HTTP transport keeps
`legacy_session_mode(true)` explicitly.

Logging (`logging/setLevel`) is deprecated by SEP-2577 in `2026-07-28` but remains part of
every revision we negotiate, so the capability stays, with `#[allow(deprecated)]`.

## Consequences

- Clients that only speak `2026-07-28` are refused at negotiation rather than silently
  losing notifications. Current clients still negotiate `2025-11-25` or earlier.
- Raising the ceiling requires moving peer tracking, subscriptions and the plugin watcher
  onto SEP-2575 listen streams, and making the watcher process-wide instead of per session.
  A unit test (`protocol_negotiation_is_capped_at_last_initialize_revision`) fails if the
  ceiling moves without that work.
