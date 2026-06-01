# 3. Implement the Deluge RPC protocol in-tree

Date: 2026-03-25

## Status

Accepted

## Context

`deluged` speaks a custom binary RPC protocol: each message is `rencode`-encoded,
zlib-compressed, and framed as `[version][length][body]`. `rencode` is a
serialization format specific to the Deluge/libtorrent ecosystem, and there is
no maintained, audited Rust implementation of it. The server cannot talk to the
daemon at all without this codec.

## Decision

Implement the wire protocol inside the crate rather than depend on an external
`rencode` library — a from-scratch serializer/deserializer plus the TLS framing,
request/response multiplexing, and login handshake.

## Consequences

- No dependency on an unmaintained or unaudited third-party codec; the entire
  wire format is auditable and testable in this repository.
- Correctness of the codec is the project's own responsibility — edge cases such
  as fixed-dict tags and deeply nested input must be handled and regression-tested
  here.
- The implementation is coupled to Deluge's protocol quirks and is not intended
  as a general-purpose `rencode` library.
