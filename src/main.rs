// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use rmcp::ServiceExt;
use serde_json;
use tracing::{info, warn};

mod deluge;
mod oauth;
mod rencode;
mod tools;

/// All tool names exposed by this server, in a stable order used for logging.
const ALL_TOOLS: &[&str] = &[
    "deluge_add_torrent",
    "deluge_list_torrents",
    "deluge_get_torrent_status",
    "deluge_pause_torrent",
    "deluge_resume_torrent",
    "deluge_set_torrent_options",
    "deluge_get_free_space",
    "deluge_get_path_size",
    "deluge_move_storage",
    "deluge_rename_folder",
    "deluge_rename_files",
    "deluge_force_recheck",
    "deluge_remove_torrent",
];

/// Tools that are disabled unless explicitly enabled via --enable.
const DEFAULT_DISABLED: &[&str] = &[
    "deluge_move_storage",
    "deluge_rename_folder",
    "deluge_rename_files",
    "deluge_force_recheck",
    "deluge_remove_torrent",
];

#[derive(Parser, Debug)]
#[command(name = "deluge-torrent-mcp", about = "MCP server for Deluge torrent daemon", version)]
struct Cli {
    /// Deluge daemon hostname or IP
    #[arg(long, default_value = "127.0.0.1", env = "DELUGE_HOST")]
    host: String,

    /// Deluge RPC port
    #[arg(long, default_value_t = 58846, env = "DELUGE_PORT")]
    port: u16,

    /// Deluge RPC username
    #[arg(short = 'u', long, env = "DELUGE_USERNAME")]
    username: String,

    /// Deluge RPC password
    #[arg(short = 'p', long, env = "DELUGE_PASSWORD")]
    password: String,

    /// TLS certificate SHA-256 fingerprint to pin (colon-separated hex, e.g. AA:BB:CC:...)
    #[arg(long)]
    cert_fingerprint: Option<String>,

    /// Enable tools matching a pattern (min 3 chars, substring of tool name).
    /// Comma-separated or repeated: --enable-tools=move_storage,rename  or  --enable-tool move_storage
    #[arg(long = "enable-tool", alias = "enable-tools", value_name = "PATTERN", value_delimiter = ',', action = clap::ArgAction::Append)]
    enable: Vec<String>,

    /// Disable tools matching a pattern (min 3 chars, substring of tool name).
    /// Disabled by default: move_storage, rename_folder, rename_files, force_recheck, remove_torrent
    /// Can also restrict default-on tools: --disable-tools=add,pause
    #[arg(long = "disable-tool", alias = "disable-tools", value_name = "PATTERN", value_delimiter = ',', action = clap::ArgAction::Append)]
    disable: Vec<String>,

    /// MCP transport to use
    #[arg(long, default_value = "stdio")]
    transport: Transport,

    /// Bind address for HTTP transport (e.g. 127.0.0.1:8080 or 0.0.0.0:8080 for all interfaces)
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_bind: String,

    /// Bearer token required for HTTP transport requests (recommended)
    #[arg(long, env = "DELUGE_API_TOKEN")]
    api_token: Option<String>,

    /// Base URL of this server as the OAuth 2.1 issuer (enables OAuth mode).
    /// Example: http://localhost:8080  or  https://mcp.example.com
    /// When set, OAuth 2.1 endpoints are activated and MCP requests require OAuth tokens.
    /// Can be combined with --api-token to also accept static tokens as a fallback.
    #[arg(long, env = "DELUGE_OAUTH_ISSUER")]
    oauth_issuer: Option<String>,

    /// List all tools with their default enabled/disabled state and exit
    #[arg(long, default_value_t = false)]
    list_tools: bool,

    /// Connect to Deluge, print session status, and exit
    #[arg(long, default_value_t = false)]
    test_connection: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Transport {
    Stdio,
    Http,
}

/// Scan raw CLI args in order and return `(is_enable, pattern)` pairs.
/// Clap cannot preserve relative ordering between two different repeated flags,
/// so we read `std::env::args()` directly for this purpose.
fn parse_tool_flags_in_order() -> anyhow::Result<Vec<(bool, String)>> {
    let args: Vec<String> = std::env::args().collect();
    let mut result = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        let arg = &args[i];
        let (is_enable, patterns_str) =
            if let Some(v) = arg.strip_prefix("--enable-tool=").or_else(|| arg.strip_prefix("--enable-tools=")) {
                (true, v.to_string())
            } else if arg == "--enable-tool" || arg == "--enable-tools" {
                if i + 1 < args.len() {
                    i += 1;
                    (true, args[i].clone())
                } else {
                    bail!("{} requires a value", arg);
                }
            } else if let Some(v) = arg.strip_prefix("--disable-tool=").or_else(|| arg.strip_prefix("--disable-tools=")) {
                (false, v.to_string())
            } else if arg == "--disable-tool" || arg == "--disable-tools" {
                if i + 1 < args.len() {
                    i += 1;
                    (false, args[i].clone())
                } else {
                    bail!("{} requires a value", arg);
                }
            } else {
            i += 1;
            continue;
        };

        for pattern in patterns_str.split(',') {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }
            if pattern.len() < 3 {
                bail!(
                    "Tool pattern '{}' is too short (minimum 3 characters). \
                     Available tools: {}",
                    pattern,
                    ALL_TOOLS.join(", ")
                );
            }
            let matches: Vec<&str> = ALL_TOOLS
                .iter()
                .filter(|&&t| t.contains(pattern))
                .copied()
                .collect();
            if matches.is_empty() {
                bail!(
                    "No tools match pattern '{}'. Available tools: {}",
                    pattern,
                    ALL_TOOLS.join(", ")
                );
            }
            result.push((is_enable, pattern.to_string()));
        }
        i += 1;
    }
    Ok(result)
}

/// Apply ordered enable/disable flags to the default tool state.
/// Last flag wins per tool.
fn resolve_enabled_tools(ordered_flags: Vec<(bool, String)>) -> HashSet<String> {
    let mut state: HashMap<&str, bool> = ALL_TOOLS
        .iter()
        .map(|&t| (t, !DEFAULT_DISABLED.contains(&t)))
        .collect();

    for (is_enable, pattern) in &ordered_flags {
        for &tool in ALL_TOOLS.iter().filter(|&&t| t.contains(pattern.as_str())) {
            state.insert(tool, *is_enable);
        }
    }

    state
        .into_iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(t, _)| t.to_string())
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging must go to stderr — stdout is reserved for MCP JSON-RPC framing
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let ordered_flags = parse_tool_flags_in_order()?;
    let enabled_tools = resolve_enabled_tools(ordered_flags);

    // Handle --list-tools before clap parsing so credentials aren't required.
    if std::env::args().any(|a| a == "--list-tools") {
        eprintln!("{:<22} {:<10} {}", "TOOL", "STATUS", "DEFAULT");
        eprintln!("{}", "-".repeat(46));
        for &tool in ALL_TOOLS {
            let status = if enabled_tools.contains(tool) { "visible" } else { "hidden" };
            let default = if DEFAULT_DISABLED.contains(&tool) { "disabled" } else { "enabled" };
            eprintln!("{:<22} {:<10} {}", tool, status, default);
        }
        eprintln!();
        eprintln!("Visible tools are reported to the MCP client. Hidden tools are not.");
        return Ok(());
    }

    let cli = Cli::parse();

    // Log effective tool permissions at startup
    let enabled_list: Vec<&str> = ALL_TOOLS
        .iter()
        .copied()
        .filter(|&t| enabled_tools.contains(t))
        .collect();
    let disabled_list: Vec<&str> = ALL_TOOLS
        .iter()
        .copied()
        .filter(|&t| !enabled_tools.contains(t))
        .collect();
    info!(enabled = %enabled_list.join(", "), "Enabled tools");
    if !disabled_list.is_empty() {
        warn!(disabled = %disabled_list.join(", "), "Disabled tools");
    }

    info!(
        host = %cli.host,
        port = cli.port,
        "Starting deluge-torrent-mcp"
    );

    let (client, auth_level) = deluge::DelugeClient::connect(
        &cli.host,
        cli.port,
        cli.cert_fingerprint,
        &cli.username,
        &cli.password,
    )
    .await?;
    info!(auth_level, "Authenticated with Deluge daemon");

    if cli.test_connection {
        use crate::rencode::Value;

        // daemon.info — returns a string describing the daemon build
        let info = client.call("daemon.info", vec![], vec![]).await?;
        eprintln!("daemon.info: {}", match &info {
            Value::String(s) => s.as_str(),
            _ => "(unexpected type)",
        });

        // core.get_session_status — terse session health snapshot
        let keys = Value::List(vec![
            Value::String("upload_rate".into()),
            Value::String("download_rate".into()),
            Value::String("total_upload".into()),
            Value::String("total_download".into()),
            Value::String("num_peers".into()),
            Value::String("dht_nodes".into()),
        ]);
        let status = client
            .call("core.get_session_status", vec![keys], vec![])
            .await?;
        let json = serde_json::to_string_pretty(&crate::rencode::value_to_json(status))
            .unwrap_or_default();
        eprintln!("core.get_session_status:\n{json}");

        return Ok(());
    }

    match cli.transport {
        Transport::Stdio => {
            info!("Starting MCP server on stdio");
            let server = tools::DelugeServer::new(client, enabled_tools);
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }

        Transport::Http => {
            use axum::Router;
            use axum::extract::{Request, State};
            use axum::http::StatusCode;
            use axum::middleware::{self, Next};
            use axum::response::Response;
            use axum::routing::{get, post};
            use rmcp::transport::streamable_http_server::{
                StreamableHttpService, StreamableHttpServerConfig,
            };
            use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
            use tower_http::cors::CorsLayer;
            use tower_http::trace::TraceLayer;

            if cli.api_token.is_none() && cli.oauth_issuer.is_none() {
                tracing::warn!(
                    "HTTP transport started without --api-token or --oauth-issuer. \
                     Anyone who can reach this port can control Deluge."
                );
            }

            info!(bind = %cli.http_bind, "Starting MCP server on HTTP");

            // Build the MCP service — factory creates a DelugeServer per session
            let mcp_service = {
                let client = client.clone();
                let enabled_tools = enabled_tools.clone();
                StreamableHttpService::new(
                    move || Ok(tools::DelugeServer::new(client.clone(), enabled_tools.clone())),
                    Arc::new(LocalSessionManager::default()),
                    StreamableHttpServerConfig::default(),
                )
            };

            let app = if let Some(ref oauth_issuer) = cli.oauth_issuer {
                // --- OAuth 2.1 mode ---
                let issuer = oauth_issuer.trim_end_matches('/').to_string();
                let resource = format!("{issuer}/mcp");

                let oauth_state = Arc::new(oauth::OAuthState::new(
                    issuer.clone(),
                    resource,
                    cli.api_token.clone(),
                ));
                oauth_state.spawn_cleanup_task();

                info!(
                    issuer = %issuer,
                    "OAuth 2.1 enabled. Metadata: {issuer}/.well-known/oauth-authorization-server"
                );

                // Unprotected OAuth routes
                let oauth_router = Router::new()
                    .route(
                        "/.well-known/oauth-protected-resource",
                        get(oauth::protected_resource_metadata),
                    )
                    .route(
                        "/.well-known/oauth-authorization-server",
                        get(oauth::oauth_metadata),
                    )
                    .route("/register", post(oauth::oauth_register))
                    .route(
                        "/authorize",
                        get(oauth::oauth_authorize_get).post(oauth::oauth_authorize_post),
                    )
                    .route("/token", post(oauth::oauth_token))
                    .with_state(oauth_state.clone());

                // OAuth-aware auth middleware
                let api_token = cli.api_token.clone();
                let auth_middleware = middleware::from_fn_with_state(
                    (oauth_state.clone(), api_token),
                    |State((oauth_state, api_token)): State<(Arc<oauth::OAuthState>, Option<String>)>,
                     request: Request,
                     next: Next| async move {
                        let bearer = request
                            .headers()
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "));

                        let authorized = match bearer {
                            Some(token) => {
                                // Check static api_token first (fast path)
                                if api_token.as_ref().is_some_and(|t| t == token) {
                                    true
                                } else {
                                    oauth_state.validate_token(token).await
                                }
                            }
                            None => false,
                        };

                        if !authorized {
                            let resource_metadata_url = format!(
                                "{}/.well-known/oauth-protected-resource",
                                oauth_state.issuer,
                            );
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header(
                                    "WWW-Authenticate",
                                    format!("Bearer resource_metadata=\"{resource_metadata_url}\""),
                                )
                                .body(axum::body::Body::from("Unauthorized"))
                                .unwrap();
                        }
                        next.run(request).await
                    },
                );

                // Protected MCP routes — CORS permissive only on /mcp
                let mcp_router = Router::new()
                    .nest_service("/mcp", mcp_service)
                    .layer(auth_middleware)
                    .layer(CorsLayer::permissive());

                // OAuth endpoints get no CORS (browser-to-browser calls are not needed)
                oauth_router
                    .merge(mcp_router)
                    .layer(TraceLayer::new_for_http())
            } else {
                // --- Static Bearer token mode (existing behavior) ---
                let api_token = cli.api_token.clone();
                let auth_middleware = middleware::from_fn_with_state(
                    api_token,
                    |State(token): State<Option<String>>,
                     request: Request,
                     next: Next| async move {
                        if let Some(expected) = token {
                            let authorized = request
                                .headers()
                                .get(axum::http::header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.strip_prefix("Bearer "))
                                .map(|t| t == expected)
                                .unwrap_or(false);

                            if !authorized {
                                return Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .body(axum::body::Body::from("Unauthorized"))
                                    .unwrap();
                            }
                        }
                        next.run(request).await
                    },
                );

                Router::new()
                    .nest_service("/mcp", mcp_service)
                    .layer(auth_middleware)
                    .layer(CorsLayer::permissive())
                    .layer(TraceLayer::new_for_http())
            };

            let listener = tokio::net::TcpListener::bind(&cli.http_bind).await?;
            info!("Listening on http://{}/mcp", cli.http_bind);

            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c()
                        .await
                        .expect("failed to listen for ctrl-c");
                    info!("Shutting down HTTP server");
                })
                .await?;
        }
    }

    Ok(())
}
