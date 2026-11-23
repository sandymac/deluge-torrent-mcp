// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Browser-origin policy for the HTTP transport.
//!
//! `--allowed-origin` entries are parsed and normalized once at startup, then used for
//! both enforcement points so they cannot disagree:
//!
//! - rmcp's Origin check on `/mcp` (403 for a non-matching `Origin`), fed the
//!   [`AllowedOrigins::normalized`] strings, which always carry an explicit port or
//!   `:*` so rmcp's deprecated "no port = any port" rule never applies;
//! - the CORS layer ([`AllowedOrigins::cors_layer`]), which grants a browser read
//!   access only for a matching origin and names the headers MCP actually uses
//!   (`Access-Control-Allow-Headers: *` does not cover `Authorization`).

use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// One allowed origin: scheme, lowercase host, and a port (`None` = any port, from `:*`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginRule {
    scheme: String,
    host: String,
    port: Option<u16>,
}

/// A parsed origin as sent by a browser, with its effective port.
#[derive(Debug, PartialEq, Eq)]
struct RequestOrigin {
    scheme: String,
    host: String,
    port: u16,
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

/// Split `scheme://authority` into (scheme, host, port-text). Rejects paths, userinfo,
/// query strings, and non-http(s) schemes. IPv6 hosts keep their brackets.
fn split_origin(s: &str) -> Result<(String, String, Option<&str>), String> {
    let (scheme, authority) = s
        .split_once("://")
        .ok_or_else(|| "missing scheme (expected e.g. http://localhost:6274)".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme `{scheme}` (use http or https)"));
    }
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return Err("must be scheme://host[:port] with no path, query, or userinfo".to_string());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 host".to_string())?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| "bad port".to_string())?),
        };
        (format!("[{}]", h.to_ascii_lowercase()), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err("missing host".to_string());
    }
    Ok((scheme, host, port))
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .ok()
        .filter(|&n| n != 0)
        .ok_or_else(|| format!("invalid port `{p}`"))
}

impl OriginRule {
    fn parse(entry: &str) -> Result<Self, String> {
        let (scheme, host, port) = split_origin(entry)?;
        let port = match port {
            Some("*") => None,
            Some(p) => Some(parse_port(p)?),
            // No port: the scheme's default port only — never "any port".
            None => Some(default_port(&scheme)),
        };
        Ok(Self { scheme, host, port })
    }

    fn normalized(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{p}", self.scheme, self.host),
            None => format!("{}://{}:*", self.scheme, self.host),
        }
    }

    fn matches(&self, origin: &RequestOrigin) -> bool {
        self.scheme == origin.scheme
            && self.host == origin.host
            && self.port.is_none_or(|p| p == origin.port)
    }
}

impl RequestOrigin {
    fn parse(value: &str) -> Option<Self> {
        let (scheme, host, port) = split_origin(value).ok()?;
        let port = match port {
            None => default_port(&scheme),
            Some(p) => parse_port(p).ok()?,
        };
        Some(Self { scheme, host, port })
    }
}

/// The validated `--allowed-origin` list.
#[derive(Debug, Clone, Default)]
pub(crate) struct AllowedOrigins {
    rules: Vec<OriginRule>,
}

impl AllowedOrigins {
    /// Parse and validate every entry. Any malformed or empty entry is a startup error,
    /// so a typo never silently leaves the policy different from what was configured.
    pub(crate) fn parse(entries: &[String]) -> Result<Self, String> {
        let rules = entries
            .iter()
            .map(|raw| {
                let e = raw.trim();
                if e.is_empty() {
                    return Err("empty --allowed-origin entry (check for a stray comma)".to_string());
                }
                OriginRule::parse(e).map_err(|why| format!("invalid --allowed-origin `{e}`: {why}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Entries for rmcp's `allowed_origins`, each with an explicit port or `:*`.
    pub(crate) fn normalized(&self) -> Vec<String> {
        self.rules.iter().map(OriginRule::normalized).collect()
    }

    fn allows(&self, origin: &HeaderValue) -> bool {
        origin
            .to_str()
            .ok()
            .and_then(RequestOrigin::parse)
            .is_some_and(|o| self.rules.iter().any(|r| r.matches(&o)))
    }

    /// CORS for the allowed origins only, or `None` when no origin is allowed (browsers
    /// then get no CORS grant at all). Lists MCP's request and response headers
    /// explicitly: a `*` wildcard would not cover `Authorization`.
    pub(crate) fn cors_layer(&self) -> Option<CorsLayer> {
        if self.is_empty() {
            return None;
        }
        let policy = self.clone();
        let mcp = |name: &'static str| HeaderName::from_static(name);
        Some(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(move |origin, _| policy.allows(origin)))
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    mcp("mcp-session-id"),
                    mcp("mcp-protocol-version"),
                    mcp("last-event-id"),
                ])
                .expose_headers([
                    mcp("mcp-session-id"),
                    mcp("mcp-protocol-version"),
                    header::WWW_AUTHENTICATE,
                ]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(entries: &[&str]) -> AllowedOrigins {
        AllowedOrigins::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn rejects_malformed_and_empty_entries() {
        for bad in ["", "  ", "localhost:6274", "ftp://x", "http://", "http://h/path", "http://h:0", "http://h:99999", "http://u@h"] {
            assert!(AllowedOrigins::parse(&[bad.to_string()]).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn normalizes_to_explicit_ports() {
        let o = allowed(&["http://LocalHost:6274", "https://app.example.com", "http://dev.local:*", "http://[::1]:8080"]);
        assert_eq!(
            o.normalized(),
            ["http://localhost:6274", "https://app.example.com:443", "http://dev.local:*", "http://[::1]:8080"]
        );
    }

    #[test]
    fn matching_honors_scheme_host_and_port() {
        let o = allowed(&["http://localhost:6274", "https://app.example.com", "http://dev.local:*"]);
        assert!(o.allows(&hv("http://localhost:6274")));
        assert!(!o.allows(&hv("http://localhost:6275")));
        assert!(!o.allows(&hv("https://localhost:6274")));
        // No port in the rule = default port only.
        assert!(o.allows(&hv("https://app.example.com")));
        assert!(o.allows(&hv("https://app.example.com:443")));
        assert!(!o.allows(&hv("https://app.example.com:8443")));
        assert!(o.allows(&hv("http://dev.local:1234")));
        assert!(!o.allows(&hv("https://evil.example")));
        assert!(!o.allows(&hv("null")));
    }

    #[test]
    fn no_cors_layer_without_allowed_origins() {
        assert!(AllowedOrigins::default().cors_layer().is_none());
    }

    /// Preflight as a browser sends it before an authenticated MCP POST.
    async fn preflight(origin: &str) -> axum::http::HeaderMap {
        use tower::ServiceExt;
        let cors = allowed(&["http://localhost:6274"]).cors_layer().unwrap();
        let app = axum::Router::new()
            .route("/mcp", axum::routing::post(|| async { "ok" }))
            .layer(cors);
        let req = axum::http::Request::builder()
            .method("OPTIONS")
            .uri("/mcp")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "authorization,content-type,mcp-session-id")
            .body(axum::body::Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().headers().clone()
    }

    #[tokio::test]
    async fn preflight_grants_authorization_to_allowed_origin_only() {
        let ok = preflight("http://localhost:6274").await;
        assert_eq!(ok["access-control-allow-origin"], "http://localhost:6274");
        let allow_headers = ok["access-control-allow-headers"].to_str().unwrap().to_ascii_lowercase();
        assert!(allow_headers.contains("authorization"), "{allow_headers}");
        assert!(allow_headers.contains("mcp-session-id"), "{allow_headers}");

        let denied = preflight("https://evil.example").await;
        assert!(denied.get("access-control-allow-origin").is_none());
    }
}
