// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

#![warn(unreachable_pub)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use git_version::git_version;
use rmcp::ServiceExt;

use tracing::{info, warn};

mod deluge;
mod ids;
mod oauth;
mod rencode;
mod response_config;
mod tools;

use tools::registry;

/// Comma-separated list of all tool names, for CLI error messages.
fn all_tools_list() -> String {
    registry::all_names().collect::<Vec<_>>().join(", ")
}

/// Short git commit the binary was built from — `-dirty` when the worktree had
/// uncommitted changes, `unknown` when built without git. Captured at compile
/// time by `git-version` (which also tracks git state for rebuilds, so no
/// build script is needed). The `--match` that can't match forces `git describe`
/// to report the bare commit hash rather than a nearby tag.
const GIT_VERSION: &str = git_version!(
    args = ["--always", "--abbrev=7", "--dirty=-dirty", "--match=__never_match__"],
    fallback = "unknown"
);

/// `--version` string: crate version plus the git commit, e.g. `0.7.6 (e7aa054)`.
/// Built once and cached; clap needs a `&'static str`.
fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| format!("{} ({})", env!("CARGO_PKG_VERSION"), GIT_VERSION))
        .as_str()
}

#[derive(Parser, Debug)]
#[command(name = "deluge-torrent-mcp", about = "MCP server for Deluge torrent daemon", version = version())]
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

    /// Additional Host header value(s) to accept on the HTTP transport, for when the
    /// server runs behind a reverse proxy that forwards a public hostname (e.g.
    /// mcp.dyn.dns). The loopback hosts, the --http-bind host, and the --oauth-issuer
    /// host are always accepted; use this for any other public name. Comma-separated or
    /// repeated. Without it, rmcp's DNS-rebinding guard rejects proxied requests with 403.
    #[arg(long = "allowed-host", value_name = "HOST", value_delimiter = ',', action = clap::ArgAction::Append, env = "DELUGE_ALLOWED_HOST")]
    allowed_host: Vec<String>,

    /// Bearer token required for HTTP transport requests (recommended). In OAuth mode this
    /// value also gates the consent screen as the operator "Access Code" — set it, or anyone
    /// who reaches the consent page can approve a client and obtain a token.
    #[arg(long, env = "DELUGE_API_TOKEN")]
    api_token: Option<String>,

    /// Base URL of this server as the OAuth 2.1 issuer (enables OAuth mode). Intended for
    /// internet-facing deployments where remote clients connect back to your MCP server;
    /// use the public HTTPS URL clients reach, e.g. <https://mcp.dyn.dns> (not a
    /// localhost URL). When set, OAuth 2.1 endpoints are activated and MCP requests require
    /// OAuth tokens. Set --api-token alongside it: that value gates the consent screen (the
    /// operator Access Code) and also works as a static bearer-token fallback. Without it the
    /// consent screen is ungated and anyone who can reach it can authorize a client.
    #[arg(long, env = "DELUGE_OAUTH_ISSUER")]
    oauth_issuer: Option<String>,

    /// Path to a JSON file used to persist OAuth client registrations, access tokens,
    /// and refresh tokens across restarts. Only meaningful with --oauth-issuer.
    /// When unset, OAuth state is in-memory only and is lost on restart.
    /// On Unix the file is chmod'd to 0600 because it contains bearer tokens.
    #[arg(long, env = "DELUGE_OAUTH_STATE_FILE", value_name = "PATH")]
    oauth_state_file: Option<std::path::PathBuf>,

    /// Shape STDIO tool responses for a token-sensitive (LLM) or byte-sensitive (programmatic)
    /// consumer. Format `<format>?<params>`, mirroring the HTTP `/mcp/<format>?<params>` URL.
    /// Example: --response-config 'json?shape=pretty'.
    /// v1 values: shape=pretty|minified|sparse (CSV; pretty/minified are exclusive), ids=full.
    /// Omit for the default (minified); pass shape=pretty for human-readable output.
    /// On the HTTP transport this is chosen per-request via the URL instead of this flag.
    #[arg(long, env = "DELUGE_RESPONSE_CONFIG", value_name = "FORMAT?PARAMS")]
    response_config: Option<String>,

    /// Connect to Deluge, verify connection, cert fingerprint, response config, and exit
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

/// Build the HTTP `Host` allow-list for rmcp's DNS-rebinding guard: the loopback
/// defaults plus the `--http-bind` host, the `--oauth-issuer` host, and any
/// explicit `--allowed-host` values. Entries are host-only (no port), which rmcp
/// matches against any port.
fn build_allowed_hosts(
    http_bind: &str,
    oauth_issuer: &Option<String>,
    extra: &[String],
) -> Vec<String> {
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];

    // The host portion of --http-bind (covers non-loopback binds like 0.0.0.0 or a LAN IP).
    if let Some(host) = http_bind.rsplit_once(':').map(|(h, _)| h).filter(|h| !h.is_empty()) {
        hosts.push(host.to_string());
    }

    // The public hostname clients actually use, taken from the OAuth issuer URL.
    if let Some(issuer) = oauth_issuer {
        if let Ok(url) = url::Url::parse(issuer) {
            if let Some(host) = url.host_str() {
                hosts.push(host.to_string());
            }
        }
    }

    hosts.extend(extra.iter().cloned());

    hosts.sort();
    hosts.dedup();
    hosts
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

    // Validate --response-config before connecting to Deluge — a malformed value is an operator
    // error that should fail fast. On STDIO this is the process-wide response shaping; on HTTP
    // it is the fallback default when a request URL carries no per-request config.
    let response_config = match cli.response_config.as_deref() {
        Some(s) => match crate::response_config::parse_flag(s) {
            Ok(cfg) => cfg,
            Err(e) => bail!("Invalid --response-config '{s}': {e}"),
        },
        None => crate::response_config::ResponseConfig::default(),
    };

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
        // Honor --response-config here too: the diagnostic doubles as a demonstration that the
        // shaping switches are in effect.
        let json = crate::response_config::shape_response(
            crate::rencode::value_to_json(status),
            &response_config,
        );
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
                response_config.clone(),
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

            // rmcp's streamable-HTTP transport rejects any Host header not on its
            // allow-list (DNS-rebinding protection), defaulting to loopback only.
            // Behind a reverse proxy the forwarded Host is the public name, so accept:
            // the loopback defaults, the --http-bind host, the --oauth-issuer host, and
            // any operator-supplied --allowed-host. Otherwise proxied requests get 403.
            let allowed_hosts =
                build_allowed_hosts(&cli.http_bind, &cli.oauth_issuer, &cli.allowed_host);
            info!(allowed_hosts = %allowed_hosts.join(", "), "HTTP Host allow-list");
            let http_config =
                StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts);

            // Build the MCP service — factory creates a DelugeServer per session.
            // Each session spawns its own plugin watcher so it gets independent
            // tools/list_changed delivery to its own peer.
            let mcp_service = {
                let api = api.clone();
                let enabled_tools = enabled_tools.clone();
                let plugin_gated_tools = plugin_gated_tools.clone();
                let response_config = response_config.clone();
                StreamableHttpService::new(
                    move || {
                        let server = tools::DelugeServer::new(
                            api.clone(),
                            enabled_tools.clone(),
                            plugin_gated_tools.clone(),
                            initial_label_plugin_active,
                            // HTTP resolves config per-request from the middleware-inserted
                            // extension (T9); this --response-config value is the fallback
                            // default used when a request URL carries no per-request config.
                            response_config.clone(),
                        );
                        server.spawn_plugin_watcher();
                        Ok(server)
                    },
                    Arc::new(LocalSessionManager::default()),
                    http_config,
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
                    // Runs before nest strips /mcp, so it sees the /mcp/<format> tail.
                    .layer(middleware::from_fn(response_config_layer))
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
                    // Runs before nest strips /mcp, so it sees the /mcp/<format> tail.
                    .layer(middleware::from_fn(response_config_layer))
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

/// Axum middleware for the `/mcp` routes: parse the `/mcp/<format>?<params>` path+query into a
/// [`ResponseConfig`](crate::response_config::ResponseConfig) and insert it into the request
/// extensions, where rmcp copies it into each tool call's `RequestContext` (read back by
/// `DelugeServer::resolve_config`). A malformed format/param is rejected with `400 Bad Request`
/// naming the offending token.
///
/// This layer runs before `nest_service("/mcp", …)` strips the `/mcp` prefix, so it sees the
/// full path here — the format segment is the path tail after `/mcp`.
async fn response_config_layer(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match parse_request_config(request.uri().path(), request.uri().query().unwrap_or("")) {
        Ok(cfg) => {
            let mut request = request;
            request.extensions_mut().insert(cfg);
            next.run(request).await
        }
        Err(e) => axum::response::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body(axum::body::Body::from(format!("Bad Request: {e}")))
            .expect("valid response"),
    }
}

/// Pure core of [`response_config_layer`]: derive the format segment from a full request path
/// (the tail after `/mcp`) and parse it with the query string. Split out so the path-extraction
/// rules are unit-testable without axum/tower plumbing.
fn parse_request_config(
    path: &str,
    query: &str,
) -> Result<crate::response_config::ResponseConfig, crate::response_config::ConfigParseError> {
    let format_segment = path.strip_prefix("/mcp").unwrap_or("").trim_matches('/');
    crate::response_config::parse(format_segment, query)
}

#[cfg(test)]
mod tests {
    use super::{build_allowed_hosts, parse_request_config};
    use crate::response_config::{ResponseConfig, Whitespace};

    #[test]
    fn request_config_bare_mcp_path_is_default() {
        assert_eq!(parse_request_config("/mcp", "").unwrap(), ResponseConfig::default());
        assert_eq!(parse_request_config("/mcp/", "").unwrap(), ResponseConfig::default());
    }

    #[test]
    fn request_config_json_segment_with_params() {
        let cfg = parse_request_config("/mcp/json", "shape=minified").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
    }

    #[test]
    fn request_config_sparse_query() {
        let cfg = parse_request_config("/mcp/json", "shape=minified,sparse").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(cfg.shape.sparse);
    }

    #[test]
    fn request_config_unknown_format_segment_errors() {
        assert!(parse_request_config("/mcp/toon", "").is_err());
    }

    #[test]
    fn request_config_invalid_param_errors() {
        assert!(parse_request_config("/mcp/json", "shape=bogus").is_err());
    }

    // --- T11: router-level test of response_config_layer over the production structure. ---
    // Proves the spike: the middleware (layered outside nest_service) sees the full
    // /mcp/<format> path, parses it, and the inserted ResponseConfig survives into the
    // nested service's request.

    /// Nested-service handler: report the path it received (post-nest-strip) and whether the
    /// ResponseConfig extension arrived as `minified`.
    async fn echo_handler(request: axum::extract::Request) -> axum::response::Response {
        let minified = request
            .extensions()
            .get::<ResponseConfig>()
            .map(|c| c.shape.whitespace == Whitespace::Minified)
            .unwrap_or(false);
        let inner_path = request.uri().path().to_string();
        axum::response::Response::new(axum::body::Body::from(format!(
            "inner_path={inner_path};minified={minified}"
        )))
    }

    /// Build a router mirroring production: nest a stub service under `/mcp`, layered with the
    /// real `response_config_layer`.
    fn test_app() -> axum::Router {
        use axum::routing::any;
        let inner = axum::Router::new().fallback(any(echo_handler));
        axum::Router::new()
            .nest_service("/mcp", inner)
            .layer(axum::middleware::from_fn(super::response_config_layer))
    }

    async fn send(uri: &str) -> (axum::http::StatusCode, String) {
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = test_app().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn middleware_extracts_format_and_config_reaches_inner_service() {
        let (status, body) = send("/mcp/json?shape=minified").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        // Middleware saw the full /mcp/json path and inserted a minified config...
        assert!(body.contains("minified=true"), "body: {body}");
        // ...while nest_service stripped /mcp before the inner service.
        assert!(body.contains("inner_path=/json"), "body: {body}");
    }

    #[tokio::test]
    async fn bare_mcp_path_yields_default_minified() {
        let (status, body) = send("/mcp").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("minified=true"), "body: {body}");
    }

    #[tokio::test]
    async fn unknown_format_segment_is_400() {
        let (status, body) = send("/mcp/toon").await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert!(body.contains("toon"), "body: {body}");
    }

    #[tokio::test]
    async fn invalid_param_is_400() {
        let (status, _) = send("/mcp/json?shape=bogus").await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn allowed_hosts_includes_loopback_bind_issuer_and_extra() {
        let hosts = build_allowed_hosts(
            "0.0.0.0:10996",
            &Some("https://mcp.deluge.mcarthur.org".to_string()),
            &["extra.example.com".to_string()],
        );
        for expected in [
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "mcp.deluge.mcarthur.org",
            "extra.example.com",
        ] {
            assert!(hosts.contains(&expected.to_string()), "missing {expected}: {hosts:?}");
        }
    }

    #[test]
    fn allowed_hosts_default_is_loopback_only_and_has_no_empty_entries() {
        let hosts = build_allowed_hosts("127.0.0.1:8080", &None, &[]);
        assert!(hosts.contains(&"localhost".to_string()));
        assert!(hosts.contains(&"127.0.0.1".to_string()));
        // The public hostname is absent when no issuer/extra is given.
        assert!(!hosts.contains(&"mcp.deluge.mcarthur.org".to_string()));
        // A host-only --http-bind (no ':') must not inject an empty entry.
        assert!(!hosts.iter().any(|h| h.is_empty()));
    }
}
