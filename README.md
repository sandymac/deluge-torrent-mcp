# Deluge Torrent MCP Server

A Model Context Protocol (MCP) server written in Rust that bridges AI assistants (like Claude) to a Deluge torrent daemon (`deluged`).

By integrating this server, your AI assistant can seamlessly manage your torrents — adding, pausing, listing, checking statuses, and managing files — all over Deluge's native TCP RPC protocol.

## Features

- **Native RPC Integration**: Uses Deluge's native binary protocol (rencode/zlib over TLS) rather than relying on the WebUI API.
- **Granular Safety Gates**: Prevents LLM hallucinations from accidentally deleting or moving your files. Risky tools are disabled by default and enabled individually via `--enable-tool`.
- **Flexible TLS Handling**: Seamlessly handles Deluge's default self-signed certificates with a secure, copy-paste pinning mechanism.
- **Dual Transports**: Supports stdio (for local Claude Desktop use) and HTTP/SSE (for remote agentic frameworks).

## Installation

Ensure you have Rust and Cargo installed, then build the release binary:

```bash
git clone https://github.com/sandymac/deluge-torrent-mcp.git
cd deluge-torrent-mcp
cargo build --release
```

The compiled binary will be located at `target/release/deluge-torrent-mcp`.

## Claude Desktop Configuration

To use this with Claude Desktop, add it to your `claude_desktop_config.json` file.

- **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following configuration, using the absolute path to the compiled binary and your Deluge RPC credentials (often found in `~/.config/deluge/auth`):

```json
{
  "mcpServers": {
    "deluge": {
      "command": "/absolute/path/to/target/release/deluge-torrent-mcp",
      "args": [
        "--host", "127.0.0.1",
        "--port", "58846",
        "-u", "localclient",
        "-p", "your_rpc_password"
      ]
    }
  }
}
```

> Restart Claude Desktop after updating this configuration.

## CLI Usage & Options

You can run the server directly to test arguments or use it with other MCP clients.

```bash
deluge-torrent-mcp --host 192.168.1.50 --port 58846 -u admin -p secret [OPTIONS]
```

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--host <HOST>` | `DELUGE_HOST` | `127.0.0.1` | Deluge daemon hostname or IP (IPv6: bare address, e.g. `::1`) |
| `--port <PORT>` | `DELUGE_PORT` | `58846` | Deluge RPC port |
| `-u, --username <USER>` | `DELUGE_USERNAME` | — | Deluge RPC username |
| `-p, --password <PASS>` | `DELUGE_PASSWORD` | — | Deluge RPC password |
| `--enable-tool <PATTERN>` | — | — | Enable tools matching pattern (min 3 chars, substring match). Repeatable, comma-separated |
| `--disable-tool <PATTERN>` | — | — | Disable tools matching pattern. Flags are processed in order; last wins |
| `--list-tools` | — | off | Print all tools with their default enabled/disabled state and exit |
| `--cert-fingerprint <SHA256>` | — | — | Pin the Deluge TLS certificate by fingerprint |
| `--transport <stdio\|http>` | — | `stdio` | MCP transport to use |
| `--http-bind <ADDR>` | — | `0.0.0.0:8080` | Bind address for HTTP transport (IPv6: bracket notation, e.g. `[::]:8080`) |
| `--api-token <TOKEN>` | `DELUGE_API_TOKEN` | — | Bearer token required for HTTP requests |
| `--test-connection` | — | off | Connect, print session status, and exit |

> Prefer environment variables over CLI flags for credentials to avoid passwords appearing in shell history.

## Safety Gates

By default, the server runs in **Safe Mode** — the AI can list, add, pause, and resume torrents, but cannot alter the filesystem or remove torrents. Five tools are disabled by default:

| Tool | Reason |
|---|---|
| `move_storage` | Moves files on disk |
| `rename_folder` | Modifies filesystem paths |
| `rename_files` | Modifies filesystem paths |
| `force_recheck` | Interrupts active downloads |
| `remove_torrent` | Can permanently delete downloaded data |

Use `--list-tools` to see the full list and current defaults:

```bash
deluge-torrent-mcp --list-tools
```

Enable tools by name or substring pattern (minimum 3 characters). Flags are processed in order — later flags override earlier ones:

```bash
# Enable a single tool
deluge-torrent-mcp -u admin -p secret --enable-tool move_storage

# Enable multiple tools
deluge-torrent-mcp -u admin -p secret --enable-tools=move_storage,rename_folder,rename_files

# Enable all five disabled-by-default tools
deluge-torrent-mcp -u admin -p secret --enable-tools=move_storage,rename_folder,rename_files,force_recheck,remove_torrent

# Enable all storage tools, then selectively disable remove
deluge-torrent-mcp -u admin -p secret --enable-tools=move_storage,rename_folder,rename_files,force_recheck,remove_torrent --disable-tool remove_torrent
```

When a disabled tool is called, the server returns an error to the AI describing the exact flag needed to enable it.

## HTTP Transport

To use the HTTP/SSE transport for remote or agentic clients, start with `--transport http`:

```bash
deluge-torrent-mcp -u admin -p secret --transport http --http-bind 0.0.0.0:8080 --api-token "your-secret-token"
```

MCP clients connect to `http://<host>:8080/mcp`. The `--api-token` flag is strongly recommended when binding to a network interface — without it, anyone who can reach the port can access the MCP endpoint and control Deluge.

Clients must include the token in every request when --api-token is set:

```
Authorization: Bearer your-secret-token
```

> For internet-facing deployments, put this behind a reverse proxy (nginx, Caddy, Traefik) that terminates TLS. The server itself does not handle HTTPS.

## TLS Certificate Handling

Deluge daemons generate unique self-signed certificates by default.

- **Default behavior**: Certificate verification is skipped. A `WARN` is logged to stderr with the certificate's SHA-256 fingerprint and the exact CLI flag to pin it.
- **Secure pinning**: Copy the fingerprint from the logs and pass it via `--cert-fingerprint`. The server will subsequently reject any certificate that doesn't match:

```bash
deluge-torrent-mcp -u admin -p secret --cert-fingerprint "A1:B2:C3..."
```

## Development & Testing

When developing or modifying this MCP server, do not test against your primary Deluge instance to avoid accidental data loss.

Instead, spin up a disposable Deluge daemon using Docker:

```yaml
# docker-compose.yml
services:
  deluge:
    image: lscr.io/linuxserver/deluge:latest
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC
      - DELUGE_DAEMON_LOG_LEVEL=info
    volumes:
      - ./test-config:/config
      - ./test-downloads:/downloads
    ports:
      - 58846:58846 # RPC Port
    restart: unless-stopped
```

Run `docker-compose up -d`, check `./test-config/auth` for the generated credentials, and point the MCP server to `127.0.0.1:58846`.

## Note on Logging

All tracing logs are directed to stderr. Do not print to stdout (`println!`), as MCP uses stdout for JSON-RPC framing. Any stray standard output will break the connection with the MCP client.
