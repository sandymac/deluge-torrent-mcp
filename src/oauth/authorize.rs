// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::{debug, trace, warn};

use super::middleware::extract_client_ip;
use super::state::{
    CodeInfo, OAuthState, PendingAuth, CODE_TTL, MAX_PENDING_AUTHORIZATIONS, PENDING_AUTH_TTL,
    generate_random_hex,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn error_html(status: StatusCode, title: &str, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — Deluge Torrent MCP</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; padding-top: 80px; }}
    .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 32px; max-width: 420px; width: 100%; }}
    h1 {{ margin-top: 0; font-size: 1.3em; color: #991b1b; }}
    p {{ color: #555; line-height: 1.5; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{message}</p>
  </div>
</body>
</html>"#,
        title = html_escape(title),
        message = html_escape(message),
    );
    (status, Html(html)).into_response()
}

fn redirect_error(redirect_uri: &str, error: &str, description: &str, state: Option<&str>) -> Response {
    let mut url = url::Url::parse(redirect_uri).expect("redirect_uri was validated at registration");
    url.query_pairs_mut()
        .append_pair("error", error)
        .append_pair("error_description", description);
    if let Some(s) = state {
        url.query_pairs_mut().append_pair("state", s);
    }
    Redirect::to(url.as_str()).into_response()
}

fn consent_page(client_name: &str, nonce: &str, requires_password: bool, error_message: Option<&str>) -> String {
    let error_banner = match error_message {
        Some(msg) => format!(
            r#"<div style="background:#fef2f2;border:1px solid #fca5a5;color:#991b1b;padding:10px 14px;border-radius:4px;margin-bottom:16px;font-size:0.95em">{}</div>"#,
            html_escape(msg)
        ),
        None => String::new(),
    };

    let password_field = if requires_password {
        r#"<div style="margin-bottom:16px">
            <label for="password" style="display:block;margin-bottom:4px;font-weight:600">Access Code</label>
            <input type="password" id="password" name="password" required autocomplete="off"
                   style="width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box"
                   placeholder="Enter the server access code">
          </div>"#
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize — Deluge Torrent MCP</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; padding-top: 80px; }}
    .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 32px; max-width: 420px; width: 100%; }}
    h1 {{ margin-top: 0; font-size: 1.3em; }}
    .client-name {{ font-weight: 600; color: #333; }}
    .buttons {{ display: flex; gap: 12px; margin-top: 20px; }}
    .buttons button {{ flex: 1; padding: 10px; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; }}
    .allow {{ background: #2563eb; color: white; }}
    .allow:hover {{ background: #1d4ed8; }}
    .deny {{ background: #e5e7eb; color: #333; }}
    .deny:hover {{ background: #d1d5db; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Application</h1>
    {error_banner}
    <p><span class="client-name">{client_name}</span> wants to access your Deluge Torrent MCP server.</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="nonce" value="{nonce}">
      {password_field}
      <div class="buttons">
        <button type="submit" name="action" value="deny" class="deny">Deny</button>
        <button type="submit" name="action" value="allow" class="allow">Allow</button>
      </div>
    </form>
  </div>
</body>
</html>"#,
        client_name = html_escape(client_name),
        nonce = html_escape(nonce),
        error_banner = error_banner,
        password_field = password_field,
    )
}

// ---------------------------------------------------------------------------
// GET /authorize — show consent page
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AuthorizeQuery {
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

pub(crate) async fn handle_authorize_get(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
    let ip = extract_client_ip(&headers);

    // --- Validate client_id and redirect_uri BEFORE redirecting ---

    let client_id = match params.client_id {
        Some(ref id) if !id.is_empty() => id.clone(),
        _ => {
            trace!(ip = %ip, "Authorization request missing client_id");
            return error_html(StatusCode::BAD_REQUEST, "Invalid Request", "The authorization request is missing a client_id parameter.");
        }
    };

    let redirect_uri = match params.redirect_uri {
        Some(ref uri) if !uri.is_empty() => uri.clone(),
        _ => {
            trace!(ip = %ip, client_id = %client_id, "Authorization request missing redirect_uri");
            return error_html(StatusCode::BAD_REQUEST, "Invalid Request", "The authorization request is missing a redirect_uri parameter.");
        }
    };

    // Look up client and validate redirect_uri
    let client_name = match state.client_has_redirect_uri(&client_id, &redirect_uri).await {
        Some(true) => state.get_client_name(&client_id).await.flatten(),
        Some(false) => {
            debug!(
                ip = %ip,
                client_id = %client_id,
                redirect_uri = %redirect_uri,
                "Authorization request redirect_uri not in registered list"
            );
            return error_html(
                StatusCode::BAD_REQUEST,
                "Invalid Request",
                "The redirect URI does not match any registered URI for this client.",
            );
        }
        None => {
            debug!(ip = %ip, client_id = %client_id, "Authorization request for unknown client");
            return error_html(StatusCode::BAD_REQUEST, "Unknown Client", "The client application is not registered with this server.");
        }
    };

    // --- From here, errors redirect back to the client ---

    let state_param = params.state.unwrap_or_default();

    // Validate response_type
    match params.response_type.as_deref() {
        Some("code") => {}
        other => {
            debug!(ip = %ip, client_id = %client_id, response_type = ?other, "Authorization request unsupported response_type");
            return redirect_error(&redirect_uri, "unsupported_response_type", "response_type must be \"code\"", Some(&state_param));
        }
    }

    // PKCE is mandatory (OAuth 2.1)
    let code_challenge = match params.code_challenge {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            debug!(ip = %ip, client_id = %client_id, "Authorization request missing code_challenge");
            return redirect_error(&redirect_uri, "invalid_request", "code_challenge is required", Some(&state_param));
        }
    };
    match params.code_challenge_method.as_deref() {
        Some("S256") => {}
        other => {
            debug!(ip = %ip, client_id = %client_id, method = ?other, "Authorization request unsupported code_challenge_method");
            return redirect_error(&redirect_uri, "invalid_request", "code_challenge_method must be \"S256\"", Some(&state_param));
        }
    }

    let scope = params.scope.unwrap_or_default();

    // Check pending authorization cap before allocating resources
    if state.pending_auth_count().await >= MAX_PENDING_AUTHORIZATIONS {
        warn!(ip = %ip, limit = MAX_PENDING_AUTHORIZATIONS, "Authorization request rejected: pending authorization limit reached");
        return redirect_error(&redirect_uri, "server_error", "too many pending authorization requests", Some(&state_param));
    }

    // Generate a nonce to tie the consent form POST back to this request
    let nonce = generate_random_hex(32);

    let pending = PendingAuth {
        client_id: client_id.clone(),
        redirect_uri,
        code_challenge,
        scope,
        state_param,
        expires_at: Instant::now() + PENDING_AUTH_TTL,
    };
    state.insert_pending_auth(nonce.clone(), pending).await;

    debug!(
        ip = %ip,
        client_id = %client_id,
        client_name = ?client_name,
        "Showing consent page"
    );

    let display_name = client_name.as_deref().unwrap_or("An MCP client");
    Html(consent_page(display_name, &nonce, state.api_token.is_some(), None)).into_response()
}

// ---------------------------------------------------------------------------
// POST /authorize — process consent
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AuthorizeForm {
    nonce: String,
    action: String,
    #[serde(default)]
    password: Option<String>,
}

pub(crate) async fn handle_authorize_post(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Form(consent): Form<AuthorizeForm>,
) -> Response {
    let ip = extract_client_ip(&headers);

    // Peek at the pending authorization without consuming it — wrong password
    // attempts must leave it alive so the user can retry.
    let pending = match state.get_pending_auth(&consent.nonce).await {
        Some(p) => p,
        None => {
            warn!(ip = %ip, "Consent POST with invalid or missing nonce");
            return error_html(
                StatusCode::BAD_REQUEST,
                "Session Not Found",
                "Your authorization session is invalid or has expired. Please start the authorization flow again.",
            );
        }
    };

    if pending.expires_at <= Instant::now() {
        // Clean up the expired entry
        let _ = state.take_pending_auth(&consent.nonce).await;
        warn!(ip = %ip, client_id = %pending.client_id, "Consent session expired");
        return error_html(
            StatusCode::BAD_REQUEST,
            "Session Expired",
            "Your authorization session has expired. Please start the authorization flow again.",
        );
    }

    // If the user denied, consume and redirect with error
    if consent.action != "allow" {
        let _ = state.take_pending_auth(&consent.nonce).await;
        debug!(ip = %ip, client_id = %pending.client_id, "User denied authorization");
        return redirect_error(
            &pending.redirect_uri,
            "access_denied",
            "user denied the authorization request",
            Some(&pending.state_param),
        );
    }

    // Verify admin password if configured
    if let Some(ref expected) = state.api_token {
        let provided = consent.password.as_deref().unwrap_or("");
        use subtle::ConstantTimeEq;
        let matches: bool = provided.as_bytes().ct_eq(expected.as_bytes()).into();
        if !matches {
            warn!(ip = %ip, client_id = %pending.client_id, "Consent rejected: incorrect access code");
            // Re-display the consent page with an error — nonce stays alive for retry
            let client_name = state.get_client_name(&pending.client_id).await.flatten();
            let display_name = client_name.as_deref().unwrap_or("An MCP client");
            return Html(consent_page(
                display_name,
                &consent.nonce,
                true,
                Some("Incorrect access code. Please try again."),
            )).into_response();
        }
    }

    // Success — now consume the pending authorization
    let _ = state.take_pending_auth(&consent.nonce).await;

    // User approved — generate authorization code
    let code = generate_random_hex(32);

    let code_info = CodeInfo {
        client_id: pending.client_id.clone(),
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge,
        scope: pending.scope,
        expires_at: Instant::now() + CODE_TTL,
    };
    state.insert_auth_code(code.clone(), code_info).await;

    debug!(ip = %ip, client_id = %pending.client_id, "Authorization code issued");

    let mut url = url::Url::parse(&pending.redirect_uri).expect("redirect_uri was validated at registration");
    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &pending.state_param);
    Redirect::to(url.as_str()).into_response()
}
