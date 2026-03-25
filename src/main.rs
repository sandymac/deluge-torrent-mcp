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

    let server = tools::DelugeServer::new(client, allow_risky, allow_destructive);

    match cli.transport {
        Transport::Stdio => {
            info!("Starting MCP server on stdio");
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        Transport::Http => {
            // TODO: HTTP/SSE transport
            anyhow::bail!("HTTP transport not yet implemented");
        }
    }

    Ok(())
}
