// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

#![warn(unreachable_pub)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use rmcp::ServiceExt;

use tracing::{info, warn};

mod deluge;
mod oauth;
mod rencode;
mod tools;

use tools::registry;

/// Comma-separated list of all tool names, for CLI error messages.
fn all_tools_list() -> String {
    registry::all_names().collect::<Vec<_>>().join(", ")
}

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

    /// List all tools with their default enabled/disabled state and exit
    #[arg(long, default_value_t = false)]
    list_tools: bool,

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
    /// Example: <http://localhost:8080>  or  <https://mcp.example.com>
    /// When set, OAuth 2.1 endpoints are activated and MCP requests require OAuth tokens.
    /// Can be combined with --api-token to also accept static tokens as a fallback.
    #[arg(long, env = "DELUGE_OAUTH_ISSUER")]
    oauth_issuer: Option<String>,

    /// Path to a JSON file used to persist OAuth client registrations, access tokens,
    /// and refresh tokens across restarts. Only meaningful with --oauth-issuer.
    /// When unset, OAuth state is in-memory only and is lost on restart.
    /// On Unix the file is chmod'd to 0600 because it contains bearer tokens.
    #[arg(long, env = "DELUGE_OAUTH_STATE_FILE", value_name = "PATH")]
    oauth_state_file: Option<std::path::PathBuf>,

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
                    all_tools_list()
                );
            }
            let any_match = registry::all_names().any(|t| t.contains(pattern));
            if !any_match {
                bail!(
                    "No tools match pattern '{}'. Available tools: {}",
                    pattern,
                    all_tools_list()
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
    let mut state: HashMap<&str, bool> = registry::all_names()
        .map(|t| (t, registry::is_enabled_by_default(t)))
        .collect();

    for (is_enable, pattern) in &ordered_flags {
        for tool in registry::all_names().filter(|t| t.contains(pattern.as_str())) {
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
        #[allow(clippy::print_literal)]
        {
            // the clippy warning on {} is less readable
            eprintln!("{:<28} {:<10} {:<10} {}", "TOOL", "CLI", "DEFAULT", "PLUGIN");
        }
        eprintln!("{}", "-".repeat(64));
        for spec in registry::TOOLS {
            let cli = if enabled_tools.contains(spec.name) { "enabled" } else { "disabled" };
            let default = if spec.default_disabled { "disabled" } else { "enabled" };
            let plugin = if spec.requires_label_plugin { "Label" } else { "-" };
            eprintln!("{:<28} {:<10} {:<10} {}", spec.name, cli, default, plugin);
        }
        eprintln!();
        eprintln!(
            "CLI 'enabled' tools pass the server-side safety gate. 'disabled' tools are \
             rejected and excluded from tools/list."
        );
        eprintln!(
            "Tools in the PLUGIN column additionally require that Deluge plugin to be \
             enabled on the daemon — they are hidden from tools/list whenever the plugin \
             is inactive (regardless of CLI state) and reappear automatically when it is \
             re-enabled."
        );
        return Ok(());
    }

    let cli = Cli::parse();

    // Log effective tool permissions at startup
    let enabled_list: Vec<&str> = registry::all_names()
        .filter(|t| enabled_tools.contains(*t))
        .collect();
    let disabled_list: Vec<&str> = registry::all_names()
        .filter(|t| !enabled_tools.contains(*t))
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

    let api = deluge::DelugeApi::new(client);

    // Probe whether the Label plugin is currently active. The plugin watcher
    // (spawned per DelugeServer below) keeps this value live thereafter.
    let initial_label_plugin_active = api.label_plugin_active().await.unwrap_or(false);
    if initial_label_plugin_active {
        info!("Deluge Label plugin is enabled — label tools are available");
    } else {
        info!(
            "Deluge Label plugin is not enabled — label tools are hidden until the user enables it"
        );
    }
    let plugin_gated_tools: HashSet<String> =
        registry::plugin_gated_names().map(|s| s.to_string()).collect();

    if cli.test_connection {
        use crate::rencode::Value;

        // daemon.info — returns a string describing the daemon build
        let info = api.daemon_info().await?;
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
        let status = api.session_status(keys).await?;
        let json = serde_json::to_string_pretty(&crate::rencode::value_to_json(status))
            .unwrap_or_default();
        eprintln!("core.get_session_status:\n{json}");

        return Ok(());
    }

    match cli.transport {
        Transport::Stdio => {
            info!("Starting MCP server on stdio");
            let server = tools::DelugeServer::new(
                api,
                enabled_tools,
                plugin_gated_tools,
                initial_label_plugin_active,
            );
            server.spawn_plugin_watcher();
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }

        Transport::Http => {
            use axum::Router;
            use axum::extract::{Request, State};
            use axum::http::StatusCode;
            use axum::middleware::{self, Next};
            use axum::response::Response;
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

            // Build the MCP service — factory creates a DelugeServer per session.
            // Each session spawns its own plugin watcher so it gets independent
            // tools/list_changed delivery to its own peer.
            let mcp_service = {
                let api = api.clone();
                let enabled_tools = enabled_tools.clone();
                let plugin_gated_tools = plugin_gated_tools.clone();
                StreamableHttpService::new(
                    move || {
                        let server = tools::DelugeServer::new(
                            api.clone(),
                            enabled_tools.clone(),
                            plugin_gated_tools.clone(),
                            initial_label_plugin_active,
                        );
                        server.spawn_plugin_watcher();
                        Ok(server)
                    },
                    Arc::new(LocalSessionManager::default()),
                    StreamableHttpServerConfig::default(),
                )
            };

            let mut shutdown_oauth_state: Option<Arc<oauth::OAuthState>> = None;

            let app = if let Some(ref oauth_issuer) = cli.oauth_issuer {
                // --- OAuth 2.1 mode ---
                let issuer = oauth_issuer.trim_end_matches('/').to_string();

                let oauth_state = Arc::new(
                    oauth::OAuthState::new_with_persistence(
                        issuer.clone(),
                        cli.api_token.clone(),
                        cli.oauth_state_file.clone(),
                    )
                    .await?,
                );
                oauth::spawn_cleanup(oauth_state.clone());
                oauth::spawn_persistence(oauth_state.clone());

                info!(
                    issuer = %issuer,
                    "OAuth 2.1 enabled. Metadata: {issuer}/.well-known/oauth-authorization-server"
                );
                if let Some(ref path) = cli.oauth_state_file {
                    info!(path = %path.display(), "OAuth state persistence enabled");
                }

                let oauth_router = oauth::oauth_routes(oauth_state.clone());

                let auth_middleware = middleware::from_fn_with_state(
                    oauth_state.clone(),
                    oauth::oauth_auth_middleware,
                );

                shutdown_oauth_state = Some(oauth_state);

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
                        if let Some(ref expected) = token {
                            use subtle::ConstantTimeEq;
                            let authorized = request
                                .headers()
                                .get(axum::http::header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.strip_prefix("Bearer "))
                                .map(|t| {
                                    let matches: bool = t.as_bytes().ct_eq(expected.as_bytes()).into();
                                    matches
                                })
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
                .with_graceful_shutdown(async move {
                    tokio::signal::ctrl_c()
                        .await
                        .expect("failed to listen for ctrl-c");
                    info!("Shutting down HTTP server");
                    if let Some(state) = shutdown_oauth_state {
                        if state.has_persist_path() {
                            if let Err(e) = state.flush().await {
                                warn!(error = %e, "Final OAuth state flush failed");
                            } else {
                                info!("Flushed OAuth state to disk");
                            }
                        }
                    }
                })
                .await?;
        }
    }

    Ok(())
}
