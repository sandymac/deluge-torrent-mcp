# 7. Treat the daemon connection as untrusted I/O

Date: 2026-03-26

## Status

Accepted

## Context

The RPC client reads length-prefixed, zlib-compressed frames from the daemon and
awaits a response for every call. A daemon that is compromised, buggy, or simply
slow can harm the server: an oversized frame or decompression bomb can exhaust
memory, and a stalled daemon-side operation (for example, fetching a `.torrent`
from an unresponsive tracker) can block a call indefinitely and hang the tool
that issued it.

## Decision

Do not assume the daemon is well-behaved. Bound every interaction with it:

- Cap the size of an incoming compressed frame and of its decompressed output,
  rejecting anything larger instead of allocating unbounded memory.
- Bound every RPC call with a timeout; on expiry the pending request is evicted
  and the call returns an error rather than waiting forever.

## Consequences

- Worst-case memory per response is bounded, and a stalled operation surfaces as
  an error the caller can handle (including per-item errors within a batch).
- The size and time limits are fixed; a legitimate response exceeding them would
  be rejected and require raising the limit.
- Because batch items are processed sequentially, several stalled items can take
  up to N × the timeout — making batches concurrent is a possible future change.
