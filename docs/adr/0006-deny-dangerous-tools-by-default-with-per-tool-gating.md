# 6. Deny dangerous tools by default with per-tool gating

Date: 2026-03-25

## Status

Accepted

## Context

An LLM driving these tools can hallucinate arguments or invoke an operation
unprompted. Some operations are hard or impossible to undo: removing torrents
along with their data, moving or renaming storage, forcing a recheck, and
mutating label definitions. The cost of an erroneous safe call is low; the cost
of an erroneous destructive call is high and asymmetric.

## Decision

Give every tool a default visibility. Safe read/write tools are enabled;
destructive, filesystem-mutating, or state-mutating tools are **disabled by
default**. Operators opt in or out per tool via enable/disable flags matched as
substrings of tool names, evaluated in order so later flags override earlier
ones. A disabled tool, when called, returns an error whose hint explains how to
enable it — distinguishing a tool disabled by configuration from one gated by an
inactive plugin (see [ADR 8](0008-drive-live-state-from-deluge-push-events.md)).

## Consequences

- A fresh install cannot delete data or rewrite storage paths without an explicit
  operator opt-in.
- Gating is granular per tool rather than a coarse "allow risky" switch, at the
  cost of substring patterns that can match more tools than intended — mitigated
  by a minimum pattern length and by logging the effective tool set at startup.
- The set of enabled tools is dynamic state the server must track, not a static
  compile-time list.
