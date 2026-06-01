# 5. Support stdio and HTTP MCP transports

Date: 2026-03-25

## Status

Accepted

## Context

The server must serve two deployment shapes. Local desktop clients spawn it as a
child process and speak MCP over stdin/stdout. Remote and agentic clients need a
network-reachable endpoint. These have different lifecycles, auth needs, and
failure modes.

## Decision

Offer both transports from one binary, selected at runtime:

- **stdio** — the default, for local clients.
- **HTTP** — a streamable-HTTP service mounting the MCP endpoint at `/mcp`, with
  optional Bearer-token auth, CORS, request tracing, and graceful shutdown.

## Consequences

- A single binary covers local and remote use; transport is a deployment choice,
  not a build choice.
- Under stdio, **all logging must go to stderr** — any byte on stdout corrupts
  the JSON-RPC framing. This is a hard, permanent constraint on the codebase.
- The HTTP transport is internet-exposable, which pulls in additional obligations:
  it binds to localhost by default so an unconfigured server is not world-reachable;
  authentication is addressed in [ADR 10](0010-authenticate-http-clients-with-oauth-2-1.md);
  and because the HTTP layer enforces a DNS-rebinding Host allow-list (loopback
  only by default), reverse-proxy deployments must declare the public hostnames
  clients use, or proxied requests are rejected.
