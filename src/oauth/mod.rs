// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Embedded OAuth 2.1 Authorization Server for the MCP HTTP transport.
//!
//! Implements the MCP Authorization spec (2025-03-26) with:
//! - Protected Resource Metadata (RFC 9728)
//! - Authorization Server Metadata (RFC 8414)
//! - Dynamic Client Registration (RFC 7591)
//! - Authorization Code + PKCE (S256) flow with consent screen
//! - Refresh token rotation with grace period
//! - Admin password on consent page (when `--api-token` is set)
//! - Unused client registration expiry (15 minutes)

mod authorize;
mod cleanup;
mod discovery;
mod middleware;
mod persist;
mod registration;
mod state;
mod token;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

// Curated public facade — the only items `main` needs from this subsystem.
// Everything else stays internal to `oauth`; sibling modules reach each other
// through `super::` regardless of these declarations.
pub(crate) use cleanup::spawn_cleanup;
pub(crate) use middleware::oauth_auth_middleware;
pub(crate) use persist::spawn_persistence;
pub(crate) use state::OAuthState;

/// Build a Router containing the OAuth 2.1 endpoints a client calls programmatically:
/// discovery, dynamic registration, and token. A browser-based client must `fetch()`
/// these, so they may sit behind the origin-scoped CORS layer.
///
/// These routes are unauthenticated — they must NOT be behind the MCP auth middleware.
pub(crate) fn oauth_routes(state: Arc<OAuthState>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(discovery::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(discovery::authorization_server_metadata),
        )
        .route("/register", post(registration::handle_register))
        .route("/token", post(token::handle_token))
        .with_state(state)
}

/// Build a Router for the consent endpoint (`/authorize`, GET and POST).
///
/// Must NEVER get CORS: the consent page embeds the nonce that approves the request, so
/// a cross-origin read would let a script approve without the user seeing the page. The
/// authorization endpoint is reached by top-level navigation, which needs no CORS.
pub(crate) fn oauth_authorize_routes(state: Arc<OAuthState>) -> Router {
    Router::new()
        .route(
            "/authorize",
            get(authorize::handle_authorize_get).post(authorize::handle_authorize_post),
        )
        .with_state(state)
}
