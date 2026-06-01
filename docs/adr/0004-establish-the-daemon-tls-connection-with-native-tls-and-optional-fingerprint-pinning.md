# 4. Establish the daemon TLS connection with native-tls and optional fingerprint pinning

Date: 2026-03-25

## Status

Accepted

## Context

`deluged` exposes its RPC port over TLS using a self-signed certificate
generated on first run. Two facts shape the connection:

- Deluge's legacy v1 self-signed certificates are rejected *structurally* by
  pure-Rust TLS stacks such as `rustls` — not merely on trust-chain grounds — so
  a connection cannot be established even with verification disabled.
- Standard CA-chain validation always fails against a self-signed certificate,
  so requiring a CA-signed certificate before the server will connect would make
  first-run setup needlessly hard. Silently trusting any certificate forever,
  however, leaves no path to an authenticated connection.

## Decision

Connect using `native-tls` (the platform TLS stack), which tolerates Deluge's
legacy certificates, and establish trust ourselves after the handshake:

- **Default** — accept the certificate, then compute and log its SHA-256
  fingerprint together with the ready-to-paste flag needed to pin it.
- **Pinned** — when a fingerprint is configured, accept only a certificate that
  matches it and reject all others.

## Consequences

- Works against a stock daemon with no certificate provisioning, while the logged
  fingerprint gives operators a one-step upgrade to a pinned, MITM-resistant
  connection.
- In the default mode the connection is encrypted but not authenticated —
  acceptable on a localhost or trusted network, but pinning is required to be safe
  across an untrusted one.
- Trust is the project's responsibility rather than the TLS library's, and the
  connection depends on the platform TLS implementation.
