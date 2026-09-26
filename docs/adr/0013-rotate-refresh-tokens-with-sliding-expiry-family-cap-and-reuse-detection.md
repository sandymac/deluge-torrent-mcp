# 13. Rotate refresh tokens with sliding expiry, a family cap, and reuse detection

Date: 2026-09-26

## Status

Accepted

Extends [ADR 10](0010-authenticate-http-clients-with-oauth-2-1.md).

## Context

OAuth clients such as claude.ai were being bounced to the consent screen far
more often than the design intended. Four causes, all in the refresh-token
path and its persistence:

- Refresh tokens expired 24 h after issue. Because every refresh mints a new
  token with a full TTL, that was a 24 h *inactivity* window, and any client
  idle overnight had to re-consent.
- The 30 s rotation grace period let any holder of a just-rotated token mint a
  brand-new pair. That is a retry-friendly behaviour for a lost response, but
  it also lets a captured token be refreshed alongside the legitimate one, and
  it extends the window on every use.
- The shutdown flush of the state file ran only on Ctrl-C, inside axum's
  graceful-shutdown future. A `systemd` or `docker stop` restart sends SIGTERM,
  so the last flush interval was lost on every ordinary restart, and an open
  SSE stream could make the connection drain outlive the supervisor's kill
  timeout.
- The background flusher and the shutdown flush both wrote `<path>.tmp` and
  renamed it, so they could interleave or land an older snapshot last.

## Decision

- **30 days sliding, 90 days absolute.** A refresh token lives 30 days from
  issue; each rotation mints a successor with a full 30 days, so 30 days is the
  inactivity window. Every token also carries `family_expires_at`, set at the
  authorization-code grant to now + 90 days and inherited unchanged along the
  rotation chain; a successor's expiry is `min(now + 30 d, family_expires_at)`.
  A stolen token therefore cannot be kept alive indefinitely by refreshing.
  `family_expires_at` is persisted; records from files written before it
  existed get a full 90 days from load.
- **Grace period is idempotent, not generative.** Rotation stores the
  replacement `(access, refresh)` pair on the superseded record, under the
  refresh-token lock. Re-presenting the old token within 30 s returns that
  same pair as long as the successor refresh token is itself unused. If the
  successor has already been rotated, the presentation is treated as replay of
  a captured token: every access and refresh token for that `client_id` is
  revoked, a warning is logged, and `invalid_grant` is returned. The real
  client re-consents once; the holder of the copy is out. The replacement pair
  is not persisted, so superseded records are dropped on load.
- **Flush on SIGTERM and after the drain.** The shutdown future resolves on
  Ctrl-C or, on Unix, SIGTERM. It flushes immediately (in case the drain
  outlives the kill timeout) and the server flushes again after `axum::serve`
  returns, capturing any refresh that happened during the drain.
- **Serialised saves.** A `tokio::sync::Mutex<()>` on `OAuthState` is taken
  around snapshot + write by both savers. It is never taken by a request path,
  so it serialises no request work; unique temp names alone would not do,
  since they cannot order the renames.

Access tokens keep their 1 h lifetime. Re-consent does not revoke a client's
existing tokens: a client sharing one registration across two authorizations
would otherwise knock the other out on every consent.

## Consequences

- A client re-consents after 30 days idle or 90 days total, instead of after
  one idle day.
- A retried or racing refresh (lost response, several clients sharing one
  authorization) no longer forces re-consent, and a replayed token now costs
  the attacker the whole session rather than granting one.
- Ordinary restarts under a supervisor preserve the last few seconds of OAuth
  state.
- Grace-period retries do not survive a restart: a client whose refresh
  response was lost during a restart has to re-consent. That window is 30 s.
