use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;
use tracing::info;

mod deluge;
mod rencode;
mod tools;

#[derive(Parser, Debug)]
#[command(name = "deluge-torrent-mcp", about = "MCP server for Deluge torrent daemon")]
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

    /// Enable risky tools: move_storage, rename_folder, rename_files, force_recheck
    #[arg(long, default_value_t = false)]
    allow_risky: bool,

    /// Enable destructive tools: remove_torrent (implies --allow-risky)
    #[arg(long, default_value_t = false)]
    allow_destructive: bool,

    /// MCP transport to use
    #[arg(long, default_value = "stdio")]
    transport: Transport,

    /// Bind address for HTTP transport (e.g. 0.0.0.0:8080)
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_bind: String,

    /// Bearer token required for HTTP transport requests (recommended)
    #[arg(long, env = "DELUGE_API_TOKEN")]
    api_token: Option<String>,

    /// Connect to Deluge, list torrents, print results to stderr, and exit
    #[arg(long, default_value_t = false)]
    test_connection: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Transport {
    Stdio,
    Http,
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

    let cli = Cli::parse();

    let allow_risky = cli.allow_risky || cli.allow_destructive;
    let allow_destructive = cli.allow_destructive;

    info!(
        host = %cli.host,
        port = cli.port,
        allow_risky,
        allow_destructive,
        "Starting deluge-torrent-mcp"
    );

    let client = deluge::DelugeClient::connect(
        &cli.host,
        cli.port,
        cli.cert_fingerprint,
    )
    .await?;

    let auth_level = client.login(&cli.username, &cli.password).await?;
    info!(auth_level, "Authenticated with Deluge daemon");

    if cli.test_connection {
        use crate::rencode::Value;
        let keys = Value::List(vec![
            Value::String("name".into()),
            Value::String("state".into()),
            Value::String("progress".into()),
            Value::String("total_size".into()),
            Value::String("save_path".into()),
        ]);
        let result = client
            .call("core.get_torrents_status", vec![Value::Dict(vec![]), keys], vec![])
            .await?;
        eprintln!("{result:#?}");
        return Ok(());
    }

    match cli.transport {
        Transport::Stdio => {
            info!("Starting MCP server on stdio");
            let server = tools::DelugeServer::new(client, allow_risky, allow_destructive);
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

            if cli.api_token.is_none() {
                tracing::warn!(
                    "HTTP transport started without --api-token. \
                     Anyone who can reach this port can control Deluge."
                );
            }

            info!(bind = %cli.http_bind, "Starting MCP server on HTTP");

            // Build the MCP service — factory creates a DelugeServer per session
            let mcp_service = {
                let client = client.clone();
                StreamableHttpService::new(
                    move || Ok(tools::DelugeServer::new(client.clone(), allow_risky, allow_destructive)),
                    Arc::new(LocalSessionManager::default()),
                    StreamableHttpServerConfig::default(),
                )
            };

            // Bearer token auth middleware
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

            let app = Router::new()
                .nest_service("/mcp", mcp_service)
                .layer(auth_middleware)
                .layer(CorsLayer::permissive())
                .layer(TraceLayer::new_for_http());

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
