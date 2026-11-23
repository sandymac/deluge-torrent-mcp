// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Browser-origin policy for the HTTP transport.
//!
//! `--allowed-origin` entries are parsed with the WHATWG URL parser (`url`), validated,
//! and canonicalized once at startup, then used for both enforcement points so they
//! cannot disagree:
//!
//! - rmcp's Origin check on `/mcp` (403 for a non-matching `Origin`), fed the
//!   [`AllowedOrigins::normalized`] strings — canonical host, and always an explicit
//!   port or `:*`, so rmcp's deprecated "no port = any port" rule never applies;
//! - the CORS layer ([`AllowedOrigins::cors_layer`]), which grants a browser read
//!   access only for a matching origin.
//!
//! Canonicalization matches how browsers serialize `Origin`: lowercase host, IPv6 in
//! compressed bracketed form, IDNs as punycode, default port implied.

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

/// One allowed origin: scheme, canonical host, and a port (`None` = any port, from `:*`).
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

/// Literal syntax check run before URL parsing. The WHATWG parser silently repairs
/// input — backslashes, dot segments, tabs and spaces, an empty port (`h:`), empty
/// userinfo (`@h`) — so without this a malformed entry would pass startup, and a
/// non-canonical request `Origin` could pass CORS while rmcp's stricter check rejects it.
fn check_origin_syntax(s: &str) -> Result<(), String> {
    let lower = s.to_ascii_lowercase();
    let authority = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .ok_or_else(|| "must start with http:// or https://".to_string())?;
    if authority.is_empty() {
        return Err("missing host".to_string());
    }
    if let Some(c) = authority
        .chars()
        .find(|c| matches!(c, '/' | '\\' | '?' | '#' | '@') || c.is_ascii_whitespace() || c.is_control())
    {
        return Err(format!("unexpected character {c:?}; use scheme://host[:port]"));
    }
    if authority.ends_with(':') {
        return Err("empty port".to_string());
    }
    Ok(())
}

/// Parse `scheme://host[:port]` into (scheme, canonical host, effective port).
/// Rejects anything that is not a bare http(s) origin.
fn parse_origin(s: &str) -> Result<(String, String, u16), String> {
    check_origin_syntax(s)?;
    let url = url::Url::parse(s).map_err(|e| format!("not a valid origin ({e})"))?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme `{scheme}` (use http or https)"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain userinfo".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err("must be scheme://host[:port] with no path, query, or fragment".to_string());
    }
    // The parser keeps the authority's trailing slash only as path "/"; reject an explicit
    // one in the input too, so the entry reads as an origin.
    if s.ends_with('/') {
        return Err("must not end with `/`".to_string());
    }
    let host = url.host_str().ok_or_else(|| "missing host".to_string())?;
    if host.contains('*') {
        return Err("wildcard hosts are not supported".to_string());
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "missing port".to_string())?;
    if port == 0 {
        return Err("invalid port 0".to_string());
    }
    Ok((scheme.to_string(), host.to_string(), port))
}

/// Whether an already-validated origin string spells out a port (`…:8080`). Checked
/// textually because the URL parser drops an explicit default port (`:443`).
fn has_explicit_port(origin: &str) -> bool {
    let authority = origin.split_once("://").map_or(origin, |(_, a)| a);
    // An IPv6 host ends in `]`; only a `:` after it can introduce a port.
    let after_host = authority.rsplit_once(']').map_or(authority, |(_, rest)| rest);
    after_host.contains(':')
}

impl OriginRule {
    fn parse(entry: &str) -> Result<Self, String> {
        // `:*` (any port) is our syntax, not URL syntax: strip it before parsing.
        let (base, any_port) = match entry.strip_suffix(":*") {
            Some(base) => (base, true),
            None => (entry, false),
        };
        let (scheme, host, port) = parse_origin(base)?;
        if any_port && has_explicit_port(base) {
            return Err("give either a port or `:*`, not both".to_string());
        }
        Ok(Self { scheme, host, port: (!any_port).then_some(port) })
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
        let (scheme, host, port) = parse_origin(value).ok()?;
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

    /// Entries for rmcp's `allowed_origins`: canonical host, explicit port or `:*`.
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
    /// then get no CORS grant at all).
    ///
    /// Request headers are mirrored from the preflight: the origin is already
    /// allow-listed and credentials mode is never enabled, so an explicit list adds no
    /// protection — and could not enumerate MCP's extensible headers (`Mcp-Method`,
    /// `Mcp-Name`, `Mcp-Param-*`). A literal `*` would not cover `Authorization`.
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
                .allow_headers(AllowHeaders::mirror_request())
                .expose_headers([
                    mcp("mcp-session-id"),
                    mcp("mcp-protocol-version"),
                    header::WWW_AUTHENTICATE,
                ])
                // Every MCP POST is non-simple; let browsers reuse a preflight briefly.
                .max_age(Duration::from_secs(600)),
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
        for bad in [
            "", "  ", "localhost:6274", "ftp://x", "http://", "http://h/path", "http://h/",
            "http://h:0", "http://h:99999", "http://u@h", "http://h?q", "http://::1:8080",
            "http://[oops]:8080", "http://*.example.com", "http://h:8080:*", "null",
            // Forms the URL parser would silently repair:
            "http://localhost:6274/a/..", "http://localhost:6274\\", "http:\\\\localhost:6274",
            "http://@localhost:6274", "http://localhost:", "http://localhost:6274/ ",
            "http://loc\talhost:6274",
        ] {
            assert!(AllowedOrigins::parse(&[bad.to_string()]).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn normalizes_to_canonical_hosts_and_explicit_ports() {
        let o = allowed(&[
            "http://LocalHost:6274",
            "https://app.example.com",
            "http://dev.local:*",
            "http://[0:0:0:0:0:0:0:1]:8080",
            "https://bücher.example",
        ]);
        assert_eq!(
            o.normalized(),
            [
                "http://localhost:6274",
                "https://app.example.com:443",
                "http://dev.local:*",
                "http://[::1]:8080",
                "https://xn--bcher-kva.example:443",
            ]
        );
    }

    #[test]
    fn matching_honors_scheme_host_and_port() {
        let o = allowed(&[
            "http://localhost:6274",
            "https://app.example.com",
            "http://dev.local:*",
            "http://[0:0:0:0:0:0:0:1]:8080",
        ]);
        assert!(o.allows(&hv("http://localhost:6274")));
        assert!(!o.allows(&hv("http://localhost:6275")));
        assert!(!o.allows(&hv("https://localhost:6274")));
        // No port in the rule = default port only.
        assert!(o.allows(&hv("https://app.example.com")));
        assert!(o.allows(&hv("https://app.example.com:443")));
        assert!(!o.allows(&hv("https://app.example.com:8443")));
        assert!(o.allows(&hv("http://dev.local:1234")));
        // Long-form IPv6 rule matches the browser's compressed serialization.
        assert!(o.allows(&hv("http://[::1]:8080")));
        assert!(!o.allows(&hv("https://evil.example")));
        assert!(!o.allows(&hv("null")));
    }

    #[test]
    fn no_cors_layer_without_allowed_origins() {
        assert!(AllowedOrigins::default().cors_layer().is_none());
    }

    /// Preflight as a browser sends it before an authenticated MCP POST.
    async fn preflight(origin: &str, request_headers: &str) -> axum::http::HeaderMap {
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
            .header("access-control-request-headers", request_headers)
            .body(axum::body::Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().headers().clone()
    }

    #[tokio::test]
    async fn preflight_grants_requested_headers_to_allowed_origin_only() {
        let wanted = "authorization,content-type,mcp-session-id,mcp-method,mcp-name";
        let ok = preflight("http://localhost:6274", wanted).await;
        assert_eq!(ok["access-control-allow-origin"], "http://localhost:6274");
        let allow_headers = ok["access-control-allow-headers"].to_str().unwrap().to_ascii_lowercase();
        for h in wanted.split(',') {
            assert!(allow_headers.contains(h), "{h} missing from {allow_headers}");
        }

        let denied = preflight("https://evil.example", wanted).await;
        assert!(denied.get("access-control-allow-origin").is_none());
    }
}
