# Security Policy

## Reporting a Vulnerability

If you find a security issue, please follow this process:

1. Create a GitHub issue with a deliberately vague title (for example: "Security concern with file handling" or "Potential issue with authentication"). This helps avoid prematurely disclosing details to others.
2. Send the full details privately by email to **Sandy McArthur** at <Sandy@McArthur.org>.

This is a volunteer project. I will try to look at security reports in a reasonable timeframe, but I cannot promise any specific response time or SLA.

## Security Model

`deluge-torrent-mcp` acts as a bridge between an LLM (via the Model Context Protocol) and a Deluge daemon. It can perform many actions on your behalf, including:

- Adding, removing, pausing, resuming, and moving torrents
- Deleting downloaded data (when `remove_torrent` is used with `delete_data=true`)
- Renaming files/folders and forcing rechecks

The MCP server connects to the Deluge daemon over a network connection (default port 58846). It does **not** necessarily run with the same operating system privileges as the `deluged` process.

### LLM / MCP Client Trust

Many potentially destructive tools are disabled by default. Operators must explicitly enable them using `--enable-tool` / `--enable-tools`.

Even with these safety gates enabled, an LLM can still make significant changes to your torrent library.

## Important Risks

| Area | Notes |
|------|-------|
| **Destructive actions** | Tools such as `remove_torrent` (with data deletion), `move_storage`, `rename_folder`, etc. are disabled by default. |
| **HTTP transport exposure** | When using `--transport http`, the server prints a warning if neither `--api-token` nor `--oauth-issuer` is configured. Do not expose this transport publicly without authentication. |
| **Deluge TLS** | By default the server does not verify the Deluge daemon's certificate and only prints a warning. Use `--cert-fingerprint` when connecting to untrusted networks. |

## Recommendations

- Run `deluged` as a dedicated, low-privilege user with the least filesystem access necessary.
- Prefer the default stdio transport when using local clients (such as Claude Desktop).
- When using the HTTP transport, always configure either `--api-token` or OAuth.
- Pin the Deluge daemon's TLS certificate with `--cert-fingerprint` in production or when connecting over untrusted networks.
- Only enable high-risk tools with `--enable-tool` when you actually need them.

## Supported Versions

Only the most recent released version is supported for security issues.
