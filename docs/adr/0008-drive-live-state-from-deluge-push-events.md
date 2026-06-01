# 8. Drive live state from Deluge push events

Date: 2026-04-01

## Status

Accepted

## Context

Two features need to reflect daemon state that changes outside the request/
response flow: MCP clients want change notifications for torrents rather than
polling, and the tools that wrap Deluge's optional **Label** plugin are only
valid when that plugin is enabled — which an operator can toggle at any time from
any Deluge client. Polling for both would be wasteful and laggy.

## Decision

Subscribe to the daemon's server-initiated push events (the same mechanism the
GTK and Web UIs use) and let them drive live state:

- Expose torrent state as subscribable **MCP Resources**; a background task
  translates torrent events into resource-update notifications to subscribed
  peers.
- Gate Label-plugin tools on the plugin's live state: a label tool is visible
  only when it is enabled (per [ADR 6](0006-deny-dangerous-tools-by-default-with-per-tool-gating.md))
  **and** the plugin is currently active. Plugin enable/disable events recompute
  visibility and fire a `tools/list_changed` notification.

State is seeded by a one-time probe after authentication and re-seeded on
reconnect and on missed events, so the cache is self-correcting.

## Consequences

- Clients get change-driven updates and an always-accurate tool list within
  seconds of a daemon-side change, without polling or a restart.
- The server carries extra runtime state (subscriptions, connected peers, active
  plugins) and a long-lived event-processing task.
- Plugin gating is absolute: configuration alone cannot surface a label tool when
  the plugin is inactive.
