# 9. Design tool parameters defensively for LLM clients

Date: 2026-04-07

## Status

Accepted

## Context

The tools are driven by an LLM through a tool-call serializer the server does not
control, and that path mangles some inputs. A string whose value looks numeric —
notably a hex info hash — has been observed arriving as an integer, with the
serializer having coerced it before the server ever sees it. No server-side
schema constraint can recover the original string once it is corrupted on the
wire. Separately, acting on torrents one call at a time is wasteful when a user
asks to operate on several.

## Decision

Shape tool parameters around how the LLM path actually behaves rather than the
ideal call:

- Take torrent identifiers as arrays so a single call can act on many torrents,
  accumulating per-item results so one bad element does not fail the batch.
- Apply the **wire-shape robustness** rule: any string parameter whose value can
  pattern-match as a number is passed as a length-one array, never a bare scalar,
  so the upstream serializer cannot coerce it to an integer — even for
  single-target operations.

## Consequences

- Batch operations come for free, and identifiers survive the serializer intact.
- Some single-target tools take a one-element array purely to dodge coercion,
  which is slightly unintuitive and must be documented for contributors.
- Sequential batch processing interacts with the per-call timeout from
  [ADR 7](0007-treat-the-daemon-connection-as-untrusted-i-o.md): N stalled items
  can take up to N × the timeout.
