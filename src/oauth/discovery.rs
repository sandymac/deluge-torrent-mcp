// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;

use super::state::OAuthState;

// ---------------------------------------------------------------------------
// GET /.well-known/oauth-protected-resource  (RFC 9728)
// ---------------------------------------------------------------------------

pub(crate) async fn protected_resource_metadata(
    State(state): State<Arc<OAuthState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "resource": state.resource,
        "authorization_servers": [&state.issuer],
        "scopes_supported": [],
        "bearer_methods_supported": ["header"],
    }))
}

// ---------------------------------------------------------------------------
// GET /.well-known/oauth-authorization-server  (RFC 8414)
// ---------------------------------------------------------------------------

pub(crate) async fn authorization_server_metadata(
    State(state): State<Arc<OAuthState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "registration_endpoint": format!("{}/register", state.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [],
    }))
}
