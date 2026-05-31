// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};

use super::middleware::extract_client_ip;
use super::state::{
    OAuthState, RefreshInfo, TokenInfo,
    ACCESS_TOKEN_TTL, REFRESH_GRACE_PERIOD, REFRESH_TOKEN_TTL,
    generate_random_hex,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    use subtle::ConstantTimeEq;
    let result: bool = computed.as_bytes().ct_eq(code_challenge.as_bytes()).into();
    result
}

/// Build a token response with Cache-Control: no-store per OAuth 2.1 §5.1.
fn token_response(resp: TokenResponse) -> Response {
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        Json(resp),
    )
        .into_response()
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

// ---------------------------------------------------------------------------
// POST /token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct TokenRequest {
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
    #[allow(dead_code)] // accepted per spec but intentionally ignored to prevent scope escalation
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

pub(crate) async fn handle_token(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response {
    let ip = extract_client_ip(&headers);
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, &ip, req).await,
        "refresh_token" => handle_refresh_token(&state, &ip, req).await,
        other => {
            debug!(ip = %ip, grant_type = %other, "Token request with unsupported grant_type");
            oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("unsupported grant_type: {other}"),
            )
        }
    }
}

async fn handle_authorization_code(state: &OAuthState, ip: &str, req: TokenRequest) -> Response {
    let code_str = match req.code {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            trace!(ip = %ip, "Token request (authorization_code) missing code");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code");
        }
    };
    let client_id = match req.client_id {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            trace!(ip = %ip, "Token request (authorization_code) missing client_id");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing client_id");
        }
    };
    let redirect_uri = match req.redirect_uri {
        Some(ref u) if !u.is_empty() => u.clone(),
        _ => {
            trace!(ip = %ip, client_id = %client_id, "Token request (authorization_code) missing redirect_uri");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing redirect_uri");
        }
    };
    let code_verifier = match req.code_verifier {
        Some(ref v) if !v.is_empty() => v.clone(),
        _ => {
            trace!(ip = %ip, client_id = %client_id, "Token request (authorization_code) missing code_verifier");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code_verifier");
        }
    };

    // Remove code immediately (one-time use)
    let code_info = match state.take_auth_code(&code_str).await {
        Some(info) => info,
        None => {
            debug!(ip = %ip, client_id = %client_id, "Token request: invalid or already-used authorization code");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "invalid or already-used authorization code");
        }
    };

    if code_info.expires_at <= Instant::now() {
        debug!(ip = %ip, client_id = %client_id, "Token request: authorization code expired");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "authorization code expired");
    }

    if code_info.client_id != client_id {
        warn!(ip = %ip, expected = %code_info.client_id, got = %client_id, "Token request: client_id mismatch");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client_id mismatch");
    }

    if code_info.redirect_uri != redirect_uri {
        warn!(ip = %ip, client_id = %client_id, "Token request: redirect_uri mismatch");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
    }

    if !verify_pkce(&code_verifier, &code_info.code_challenge) {
        warn!(ip = %ip, client_id = %client_id, "Token request: PKCE verification failed");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }

    // Verify client still exists and mark as authorized
    if !state.mark_client_authorized(&client_id).await {
        warn!(ip = %ip, client_id = %client_id, "Token request: client has been revoked");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client has been revoked");
    }

    // Issue tokens
    let access_token = generate_random_hex(32);
    let refresh_token = generate_random_hex(32);

    state
        .insert_access_token(
            access_token.clone(),
            TokenInfo {
                client_id: client_id.clone(),
                scope: code_info.scope.clone(),
                expires_at: Instant::now() + ACCESS_TOKEN_TTL,
            },
        )
        .await;

    state
        .insert_refresh_token(
            refresh_token.clone(),
            RefreshInfo {
                client_id: client_id.clone(),
                scope: code_info.scope.clone(),
                access_token: access_token.clone(),
                expires_at: Instant::now() + REFRESH_TOKEN_TTL,
                superseded_at: None,
            },
        )
        .await;

    debug!(ip = %ip, client_id = %client_id, "Issued access token via authorization_code grant");

    token_response(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.as_secs(),
        refresh_token: Some(refresh_token),
        scope: code_info.scope,
    })
}

async fn handle_refresh_token(state: &OAuthState, ip: &str, req: TokenRequest) -> Response {
    let refresh_token_str = match req.refresh_token {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            trace!(ip = %ip, "Token request (refresh_token) missing refresh_token");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing refresh_token");
        }
    };
    let client_id = match req.client_id {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            trace!(ip = %ip, "Token request (refresh_token) missing client_id");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing client_id");
        }
    };

    let now = Instant::now();

    // Look up the refresh token
    let refresh_info = match state.get_refresh_info(&refresh_token_str).await {
        Some(info) => info,
        None => {
            debug!(ip = %ip, client_id = %client_id, "Refresh request: invalid or unknown refresh token");
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "invalid or already-used refresh token");
        }
    };

    if refresh_info.expires_at <= now {
        debug!(ip = %ip, client_id = %client_id, "Refresh request: refresh token expired");
        state.remove_refresh_token(&refresh_token_str).await;
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token expired");
    }

    // Check if this token has been superseded (rotated out)
    if let Some(superseded) = refresh_info.superseded_at {
        if now.duration_since(superseded) >= REFRESH_GRACE_PERIOD {
            warn!(ip = %ip, client_id = %client_id, "Refresh request: superseded token past grace period");
            state.remove_refresh_token(&refresh_token_str).await;
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token has been superseded");
        }
        // Within grace period — allow reuse (network retry scenario)
        debug!(ip = %ip, client_id = %client_id, "Refresh request: reusing superseded token within grace period");
    }

    if refresh_info.client_id != client_id {
        warn!(ip = %ip, expected = %refresh_info.client_id, got = %client_id, "Refresh request: client_id mismatch");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client_id mismatch");
    }

    let old_access_token = refresh_info.access_token.clone();
    // Always use the originally granted scope — ignore req.scope to prevent
    // scope escalation (OAuth 2.1: refresh must not exceed original grant).
    let scope = refresh_info.scope.clone();

    // Mark old refresh token as superseded (don't delete — grace period)
    state.mark_refresh_superseded(&refresh_token_str, now).await;

    // Verify client still exists in registry
    if !state.client_exists(&client_id).await {
        warn!(ip = %ip, client_id = %client_id, "Refresh request: client has been revoked");
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client has been revoked");
    }

    // Revoke old access token
    state.revoke_access_token(&old_access_token).await;

    // Issue new tokens
    let new_access = generate_random_hex(32);
    let new_refresh = generate_random_hex(32);

    state
        .insert_access_token(
            new_access.clone(),
            TokenInfo {
                client_id: client_id.clone(),
                scope: scope.clone(),
                expires_at: Instant::now() + ACCESS_TOKEN_TTL,
            },
        )
        .await;

    state
        .insert_refresh_token(
            new_refresh.clone(),
            RefreshInfo {
                client_id: client_id.clone(),
                scope: scope.clone(),
                access_token: new_access.clone(),
                expires_at: Instant::now() + REFRESH_TOKEN_TTL,
                superseded_at: None,
            },
        )
        .await;

    debug!(ip = %ip, client_id = %client_id, "Issued access token via refresh_token grant");

    token_response(TokenResponse {
        access_token: new_access,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.as_secs(),
        refresh_token: Some(new_refresh),
        scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_rfc7636_appendix_b() {
        // Test vector from RFC 7636 Appendix B
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(code_verifier, expected_challenge));
    }

    #[test]
    fn test_pkce_wrong_verifier() {
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce("wrong-verifier", code_challenge));
    }
}
