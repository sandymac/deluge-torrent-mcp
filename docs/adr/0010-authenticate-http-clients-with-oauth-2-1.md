# 10. Authenticate HTTP clients with OAuth 2.1

Date: 2026-04-11

## Status

Accepted

## Context

The HTTP transport ([ADR 5](0005-support-stdio-and-http-mcp-transports.md)) can
be exposed to a network, so it needs authentication. A single shared Bearer
token is adequate for one trusted client but does not scale to multiple
internet-facing clients, and the MCP authorization specification expects an
OAuth 2.1 flow in which clients register and obtain scoped, rotatable tokens
without a pre-shared secret.

## Decision

Embed an OAuth 2.1 authorization server, enabled when an issuer is configured,
implementing the authorization-code flow with PKCE, dynamic client registration,
protected-resource metadata, and refresh-token rotation. Harden it for internet
exposure: an admin-gated consent screen, HTTPS-only redirect URIs (except
localhost), expiry of unused client registrations, a registration cap, and CSRF
protection on the consent form. The simpler shared-token mode remains available
for single-client setups. Long-lived OAuth state (registrations and tokens) may
optionally be persisted to disk so clients survive a restart without
re-registering; by default it is in-memory only, and persisted files are written
atomically with restrictive permissions because they hold bearer tokens.

## Consequences

- Multiple remote clients can authenticate with standard, revocable credentials,
  while small deployments can still use a shared token.
- This is a substantial, security-sensitive subsystem with its own surface to
  maintain and review.
- Persistence is opt-in, so the default deployment writes no secrets to disk; an
  operator enabling it accepts responsibility for protecting the state file.
