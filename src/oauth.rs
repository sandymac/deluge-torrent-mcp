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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::debug;

const CODE_TTL: Duration = Duration::from_secs(10 * 60);
const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const REFRESH_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const REFRESH_GRACE_PERIOD: Duration = Duration::from_secs(30);
const PENDING_AUTH_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CLIENTS: usize = 100;
/// Clients that never complete authorization are removed after this period.
const UNAUTHED_CLIENT_TTL: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct OAuthState {
    pub issuer: String,
    pub resource: String,
    /// Optional admin secret (from `--api-token`) required on the consent page
    /// to authenticate the user before granting authorization. Registration
    /// remains open (capped at `MAX_CLIENTS`) since it grants no access alone.
    admin_secret: Option<String>,
    clients: Mutex<HashMap<String, ClientInfo>>,
    codes: Mutex<HashMap<String, CodeInfo>>,
    access_tokens: Mutex<HashMap<String, TokenInfo>>,
    refresh_tokens: Mutex<HashMap<String, RefreshInfo>>,
    pending_authorizations: Mutex<HashMap<String, PendingAuth>>,
}

struct ClientInfo {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    #[allow(dead_code)]
    grant_types: Vec<String>,
    created_at: Instant,
    /// Set to `true` once a token has been issued for this client.
    /// Unauthorized clients are garbage-collected after `UNAUTHED_CLIENT_TTL`.
    authorized: bool,
}

struct CodeInfo {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    expires_at: Instant,
}

#[allow(dead_code)]
struct TokenInfo {
    client_id: String,
    scope: String,
    expires_at: Instant,
}

struct RefreshInfo {
    client_id: String,
    scope: String,
    access_token: String,
    expires_at: Instant,
    /// Set when this token has been rotated out. The token remains valid for
    /// `REFRESH_GRACE_PERIOD` after this timestamp to handle network failures.
    superseded_at: Option<Instant>,
}

/// Stores the validated parameters from a GET /authorize request while the
/// consent page is displayed to the user. The nonce ties the POST back to
/// this pending authorization.
struct PendingAuth {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    state_param: String,
    expires_at: Instant,
}

impl OAuthState {
    pub fn new(issuer: String, resource: String, admin_secret: Option<String>) -> Self {
        Self {
            issuer,
            resource,
            admin_secret,
            clients: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
            pending_authorizations: Mutex::new(HashMap::new()),
        }
    }

    pub async fn validate_token(&self, token: &str) -> bool {
        let tokens = self.access_tokens.lock().await;
        matches!(tokens.get(token), Some(info) if info.expires_at > Instant::now())
    }

    pub fn spawn_cleanup_task(self: &Arc<Self>) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                let now = Instant::now();
                state.codes.lock().await.retain(|_, v| v.expires_at > now);
                state
                    .access_tokens
                    .lock()
                    .await
                    .retain(|_, v| v.expires_at > now);
                state.refresh_tokens.lock().await.retain(|_, v| {
                    if v.expires_at <= now {
                        return false;
                    }
                    if let Some(superseded) = v.superseded_at {
                        return now.duration_since(superseded) < REFRESH_GRACE_PERIOD;
                    }
                    true
                });
                state
                    .pending_authorizations
                    .lock()
                    .await
                    .retain(|_, v| v.expires_at > now);
                // Sweep clients that never completed authorization
                state.clients.lock().await.retain(|_, v| {
                    v.authorized
                        || now.duration_since(v.created_at) < UNAUTHED_CLIENT_TTL
                });
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_random_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn verify_pkce(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == stored_challenge
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Build a redirect URL by appending query parameters to a base URI using
/// `form_urlencoded::Serializer` for proper encoding.
fn build_redirect_url(base_uri: &str, params: &[(&str, &str)]) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let sep = if base_uri.contains('?') { '&' } else { '?' };
    format!("{base_uri}{sep}{query}")
}

/// Check if a redirect URI host is localhost (allowing http://).
fn is_localhost_uri(uri: &str) -> bool {
    // Strip scheme, check if host starts with localhost or 127.0.0.1
    let after_scheme = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"));
    match after_scheme {
        Some(rest) => {
            let host = rest.split('/').next().unwrap_or("");
            let host_no_port = host.split(':').next().unwrap_or("");
            host_no_port == "localhost" || host_no_port == "127.0.0.1" || host_no_port == "[::1]"
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// GET /.well-known/oauth-protected-resource  (RFC 9728)
// ---------------------------------------------------------------------------

pub async fn protected_resource_metadata(
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

pub async fn oauth_metadata(State(state): State<Arc<OAuthState>>) -> impl IntoResponse {
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

// ---------------------------------------------------------------------------
// POST /register  (RFC 7591 Dynamic Client Registration)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct RegisterRequest {
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
pub struct RegisterResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

pub async fn oauth_register(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Validate redirect_uris
    if req.redirect_uris.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "redirect_uris must not be empty",
        );
    }
    for uri in &req.redirect_uris {
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("redirect_uri must use http or https scheme: {uri}"),
            );
        }
        // Enforce https for non-localhost URIs
        if uri.starts_with("http://") && !is_localhost_uri(uri) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!(
                    "redirect_uri must use https for non-localhost hosts: {uri}"
                ),
            );
        }
    }

    // Only public clients (token_endpoint_auth_method = "none")
    if let Some(ref method) = req.token_endpoint_auth_method {
        if method != "none" {
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

    let client_id = generate_random_hex(16);

    let info = ClientInfo {
        redirect_uris: req.redirect_uris.clone(),
        client_name: req.client_name.clone(),
        grant_types: grant_types.clone(),
        created_at: Instant::now(),
        authorized: false,
    };

    let mut clients = state.clients.lock().await;
    if clients.len() >= MAX_CLIENTS {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "maximum number of registered clients reached",
        );
    }
    clients.insert(client_id.clone(), info);
    drop(clients);

    debug!(client_id = %client_id, "Registered OAuth client");

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

// ---------------------------------------------------------------------------
// GET /authorize — show consent page
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    resource: Option<String>,
}

pub async fn oauth_authorize_get(
    State(state): State<Arc<OAuthState>>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // --- Validate client_id and redirect_uri BEFORE redirecting ---

    let client_id = match params.client_id {
        Some(ref id) if !id.is_empty() => id.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            );
        }
    };

    let redirect_uri = match params.redirect_uri {
        Some(ref uri) if !uri.is_empty() => uri.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            );
        }
    };

    // Look up client
    let clients = state.clients.lock().await;
    let client = match clients.get(&client_id) {
        Some(c) => c,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "unknown client_id",
            );
        }
    };

    // Exact match on redirect_uri (OAuth 2.1 requirement)
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri does not match any registered URI",
        );
    }

    let client_name = client.client_name.clone();
    drop(clients);

    // --- From here, errors redirect back to the client ---

    let state_param = params.state.unwrap_or_default();

    // Validate response_type
    match params.response_type.as_deref() {
        Some("code") => {}
        _ => {
            let url = build_redirect_url(
                &redirect_uri,
                &[
                    ("error", "unsupported_response_type"),
                    ("error_description", "response_type must be \"code\""),
                    ("state", &state_param),
                ],
            );
            return Redirect::to(&url).into_response();
        }
    }

    // PKCE is mandatory (OAuth 2.1)
    let code_challenge = match params.code_challenge {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            let url = build_redirect_url(
                &redirect_uri,
                &[
                    ("error", "invalid_request"),
                    ("error_description", "code_challenge is required"),
                    ("state", &state_param),
                ],
            );
            return Redirect::to(&url).into_response();
        }
    };
    match params.code_challenge_method.as_deref() {
        Some("S256") => {}
        _ => {
            let url = build_redirect_url(
                &redirect_uri,
                &[
                    ("error", "invalid_request"),
                    ("error_description", "code_challenge_method must be \"S256\""),
                    ("state", &state_param),
                ],
            );
            return Redirect::to(&url).into_response();
        }
    }

    let scope = params.scope.unwrap_or_default();

    // Generate a nonce to tie the consent form POST back to this request
    let nonce = generate_random_hex(32);

    let pending = PendingAuth {
        client_id,
        redirect_uri,
        code_challenge,
        scope,
        state_param,
        expires_at: Instant::now() + PENDING_AUTH_TTL,
    };
    state
        .pending_authorizations
        .lock()
        .await
        .insert(nonce.clone(), pending);

    // Render the consent page
    let display_name = client_name.as_deref().unwrap_or("An MCP client");

    let password_field = if state.admin_secret.is_some() {
        r#"<p><label for="password">Access code:</label><br>
<input type="password" id="password" name="password" required autocomplete="off"></p>"#
    } else {
        ""
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize - Deluge Torrent MCP</title>
</head>
<body>
<h2>Deluge Torrent MCP</h2>
<p><strong>{display_name}</strong> is requesting access to your Deluge server.</p>
<form method="POST" action="/authorize">
<input type="hidden" name="nonce" value="{nonce}">
{password_field}
<button type="submit" name="action" value="allow">Allow</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>"#,
        display_name = html_escape(display_name),
        nonce = nonce,
        password_field = password_field,
    );

    Html(html).into_response()
}

// ---------------------------------------------------------------------------
// POST /authorize — process consent
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeConsent {
    nonce: String,
    action: String,
    #[serde(default)]
    password: Option<String>,
}

pub async fn oauth_authorize_post(
    State(state): State<Arc<OAuthState>>,
    Form(consent): Form<AuthorizeConsent>,
) -> Response {
    // Look up and consume the pending authorization
    let pending = match state
        .pending_authorizations
        .lock()
        .await
        .remove(&consent.nonce)
    {
        Some(p) => p,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid or expired authorization session",
            );
        }
    };

    if pending.expires_at <= Instant::now() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization session expired",
        );
    }

    // If the user denied, redirect with error
    if consent.action != "allow" {
        let url = build_redirect_url(
            &pending.redirect_uri,
            &[
                ("error", "access_denied"),
                ("error_description", "user denied the authorization request"),
                ("state", &pending.state_param),
            ],
        );
        return Redirect::to(&url).into_response();
    }

    // Verify admin password if configured
    if let Some(ref expected) = state.admin_secret {
        let provided = consent.password.as_deref().unwrap_or("");
        if provided != expected {
            let url = build_redirect_url(
                &pending.redirect_uri,
                &[
                    ("error", "access_denied"),
                    ("error_description", "incorrect access code"),
                    ("state", &pending.state_param),
                ],
            );
            return Redirect::to(&url).into_response();
        }
    }

    // User approved — generate authorization code
    let code = generate_random_hex(32);

    let code_info = CodeInfo {
        client_id: pending.client_id,
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge,
        scope: pending.scope,
        expires_at: Instant::now() + CODE_TTL,
    };
    state.codes.lock().await.insert(code.clone(), code_info);

    let url = build_redirect_url(
        &pending.redirect_uri,
        &[("code", &code), ("state", &pending.state_param)],
    );
    Redirect::to(&url).into_response()
}

// ---------------------------------------------------------------------------
// POST /token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    // authorization_code fields
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    // refresh_token fields
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    resource: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

pub async fn oauth_token(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<TokenRequest>,
) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, req).await,
        "refresh_token" => handle_refresh_token(&state, req).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("unsupported grant_type: {}", req.grant_type),
        ),
    }
}

async fn handle_authorization_code(state: &OAuthState, req: TokenRequest) -> Response {
    let code_str = match req.code {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code"),
    };
    let client_id = match req.client_id {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing client_id")
        }
    };
    let redirect_uri = match req.redirect_uri {
        Some(ref u) if !u.is_empty() => u.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            )
        }
    };
    let code_verifier = match req.code_verifier {
        Some(ref v) if !v.is_empty() => v.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing code_verifier",
            )
        }
    };

    // Remove code immediately (one-time use)
    let code_info = match state.codes.lock().await.remove(&code_str) {
        Some(info) => info,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or already-used authorization code",
            )
        }
    };

    if code_info.expires_at <= Instant::now() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code expired",
        );
    }

    if code_info.client_id != client_id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
    }

    if code_info.redirect_uri != redirect_uri {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    if !verify_pkce(&code_verifier, &code_info.code_challenge) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    // Verify client still exists and mark as authorized
    {
        let mut clients = state.clients.lock().await;
        match clients.get_mut(&client_id) {
            Some(client) => client.authorized = true,
            None => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client has been revoked",
                );
            }
        }
    }

    // Issue tokens
    let access_token = generate_random_hex(32);
    let refresh_token = generate_random_hex(32);

    state.access_tokens.lock().await.insert(
        access_token.clone(),
        TokenInfo {
            client_id: client_id.clone(),
            scope: code_info.scope.clone(),
            expires_at: Instant::now() + ACCESS_TOKEN_TTL,
        },
    );

    state.refresh_tokens.lock().await.insert(
        refresh_token.clone(),
        RefreshInfo {
            client_id,
            scope: code_info.scope.clone(),
            access_token: access_token.clone(),
            expires_at: Instant::now() + REFRESH_TOKEN_TTL,
            superseded_at: None,
        },
    );

    debug!("Issued access token via authorization_code grant");

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.as_secs(),
        refresh_token: Some(refresh_token),
        scope: code_info.scope,
    })
    .into_response()
}

async fn handle_refresh_token(state: &OAuthState, req: TokenRequest) -> Response {
    let refresh_token_str = match req.refresh_token {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing refresh_token",
            )
        }
    };
    let client_id = match req.client_id {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing client_id")
        }
    };

    let now = Instant::now();

    // Look up the refresh token (don't remove yet — grace period handling)
    let mut refresh_tokens = state.refresh_tokens.lock().await;
    let refresh_info = match refresh_tokens.get(&refresh_token_str) {
        Some(info) => info,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or already-used refresh token",
            )
        }
    };

    if refresh_info.expires_at <= now {
        refresh_tokens.remove(&refresh_token_str);
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token expired",
        );
    }

    // Check if this token has been superseded (rotated out)
    if let Some(superseded) = refresh_info.superseded_at {
        if now.duration_since(superseded) >= REFRESH_GRACE_PERIOD {
            refresh_tokens.remove(&refresh_token_str);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token has been superseded",
            );
        }
        // Within grace period — allow reuse (network retry scenario)
    }

    if refresh_info.client_id != client_id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
    }

    let old_access_token = refresh_info.access_token.clone();
    let scope = req
        .scope
        .clone()
        .unwrap_or_else(|| refresh_info.scope.clone());

    // Mark old refresh token as superseded (don't delete — grace period)
    refresh_tokens
        .get_mut(&refresh_token_str)
        .unwrap()
        .superseded_at
        .get_or_insert(now);
    drop(refresh_tokens);

    // Verify client still exists in registry
    if !state.clients.lock().await.contains_key(&client_id) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client has been revoked",
        );
    }

    // Revoke old access token
    state.access_tokens.lock().await.remove(&old_access_token);

    // Issue new tokens
    let new_access = generate_random_hex(32);
    let new_refresh = generate_random_hex(32);

    state.access_tokens.lock().await.insert(
        new_access.clone(),
        TokenInfo {
            client_id: client_id.clone(),
            scope: scope.clone(),
            expires_at: Instant::now() + ACCESS_TOKEN_TTL,
        },
    );

    state.refresh_tokens.lock().await.insert(
        new_refresh.clone(),
        RefreshInfo {
            client_id,
            scope: scope.clone(),
            access_token: new_access.clone(),
            expires_at: Instant::now() + REFRESH_TOKEN_TTL,
            superseded_at: None,
        },
    );

    debug!("Issued access token via refresh_token grant");

    Json(TokenResponse {
        access_token: new_access,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.as_secs(),
        refresh_token: Some(new_refresh),
        scope,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

/// Minimal HTML entity escaping for safe interpolation into HTML content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
