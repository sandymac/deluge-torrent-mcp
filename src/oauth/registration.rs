// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::middleware::extract_client_ip;
use super::state::{ClientInfo, MAX_CLIENTS, OAuthState};

// ---------------------------------------------------------------------------
// POST /register  (RFC 7591 Dynamic Client Registration)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub(crate) struct RegisterRequest {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    use axum::response::IntoResponse;
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Check if a redirect URI host is localhost (allowing http://).
fn is_localhost_uri(uri: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(uri) {
        match parsed.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
            Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
            _ => false,
        }
    } else {
        false
    }
}

pub(crate) async fn handle_register(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    use axum::response::IntoResponse;

    let ip = extract_client_ip(&headers);
    trace!(ip = %ip, client_name = ?req.client_name, "POST /register");

    // Validate redirect_uris
    if req.redirect_uris.is_empty() {
        trace!(ip = %ip, "Registration rejected: empty redirect_uris");
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "redirect_uris must not be empty",
        );
    }
    for uri in &req.redirect_uris {
        // OAuth 2.x: redirect_uris must not contain a fragment component
        if uri.contains('#') {
            trace!(ip = %ip, uri = %uri, "Registration rejected: redirect_uri contains fragment");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("redirect_uri must not contain a fragment (#): {uri}"),
            );
        }
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            trace!(ip = %ip, uri = %uri, "Registration rejected: invalid URI scheme");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("redirect_uri must use http or https scheme: {uri}"),
            );
        }
        // Enforce https for non-localhost URIs
        if uri.starts_with("http://") && !is_localhost_uri(uri) {
            trace!(ip = %ip, uri = %uri, "Registration rejected: non-localhost http URI");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("redirect_uri must use https for non-localhost hosts: {uri}"),
            );
        }
    }

    // Only public clients (token_endpoint_auth_method = "none")
    if let Some(ref method) = req.token_endpoint_auth_method {
        if method != "none" {
            trace!(ip = %ip, method = %method, "Registration rejected: unsupported auth method");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "only token_endpoint_auth_method=\"none\" (public clients) is supported",
            );
        }
    }

    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into()]);
    let response_types = req.response_types.unwrap_or_else(|| vec!["code".into()]);

    let client_id = super::state::generate_random_hex(16);

    let info = ClientInfo {
        redirect_uris: req.redirect_uris.clone(),
        client_name: req.client_name.clone(),
        grant_types: grant_types.clone(),
        created_at: Instant::now(),
        authorized: false,
    };

    if state.client_count().await >= MAX_CLIENTS {
        warn!(ip = %ip, limit = MAX_CLIENTS, "Registration rejected: client limit reached");
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "maximum number of registered clients reached",
        );
    }
    state.register_client(client_id.clone(), info).await;

    debug!(ip = %ip, client_id = %client_id, client_name = ?req.client_name, "Registered OAuth client");

    let resp = RegisterResponse {
        client_id,
        client_name: req.client_name,
        redirect_uris: req.redirect_uris,
        grant_types,
        response_types,
        token_endpoint_auth_method: "none".into(),
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}
