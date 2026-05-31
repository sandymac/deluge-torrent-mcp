// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::state::OAuthState;

/// Auth middleware that accepts either a valid OAuth access token or the static `--api-token`.
///
/// On 401, returns `WWW-Authenticate: Bearer resource_metadata="<url>"` so MCP clients can
/// discover the OAuth authorization server.
pub(crate) async fn oauth_auth_middleware(
    State(state): State<Arc<OAuthState>>,
    request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(bearer) = token else {
        return unauthorized_response(&state);
    };

    // Check static api_token first (fast path)
    if let Some(expected) = &state.api_token {
        use subtle::ConstantTimeEq;
        let matches: bool = bearer.as_bytes().ct_eq(expected.as_bytes()).into();
        if matches {
            return next.run(request).await;
        }
    }

    // Fall back to OAuth access tokens
    if state.validate_token(bearer).await {
        return next.run(request).await;
    }

    unauthorized_response(&state)
}

fn unauthorized_response(state: &OAuthState) -> Response {
    let resource_metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        state.issuer
    );
    let www_authenticate = format!(
        "Bearer resource_metadata=\"{}\"",
        resource_metadata_url
    );

    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", www_authenticate)],
        "Unauthorized",
    )
        .into_response()
}

/// Extract the best-available client IP from request headers.
///
/// Checks `X-Real-IP` first (set by nginx `proxy_set_header X-Real-IP $remote_addr`),
/// then the first address in `X-Forwarded-For`, then falls back to `"unknown"`.
///
/// Normalizes the result by stripping ports (`1.2.3.4:5678` -> `1.2.3.4`) and IPv6 brackets
/// (`[2001:db8::1]:443` -> `2001:db8::1`).
pub(crate) fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    // X-Real-IP: single IP set by nginx
    let ip = if let Some(ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        ip
    } else if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        // X-Forwarded-For: comma-separated list; use the first (leftmost) entry
        xff.split(',').next().unwrap_or(xff).trim()
    } else {
        return "unknown".to_string();
    };

    // Normalize: strip port and brackets
    // 1.2.3.4:5678 -> 1.2.3.4
    // [2001:db8::1]:443 -> 2001:db8::1
    if let Some(pos) = ip.rfind(':') {
        let potential_ip = &ip[..pos];
        // If it was [ipv6]:port, potential_ip is [ipv6]
        if potential_ip.contains(']') {
            potential_ip.trim_matches(|c| c == '[' || c == ']').to_string()
        } else if potential_ip.contains(':') {
            // It was an IPv6 without a port (contains multiple colons)
            ip.to_string()
        } else {
            // It was an IPv4:port
            potential_ip.to_string()
        }
    } else {
        // No colon at all, already clean
        ip.to_string()
    }
}
