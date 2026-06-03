// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Consumer-shaped response configuration.
//!
//! An MCP client declares what kind of consumer it is — a token-sensitive LLM or a
//! byte/parse-sensitive programmatic tool — and the server shapes its JSON payload to match.
//! The configuration is expressed as one canonical DSL, parsed by one function ([`parse`]),
//! and used in two places: the HTTP `/mcp/<format>?<params>` path+query, and the STDIO
//! `--response-config '<format>?<params>'` flag (via [`parse_flag`]).
//!
//! The path segment names the *payload format* (the encoding namespace — `json` in v1,
//! reserving `toon`/`xml`/`text` for later); the query string carries parameters scoped to
//! that format. The [`Default`] is `json` + `minified` + `full`: compact output suits the
//! LLM clients that are the common consumer. Human-readable output is opt-in via `shape=pretty`.

mod shape;

pub(crate) use shape::shape_response;

/// A fully-resolved response configuration. Lives in per-request extensions on HTTP and is
/// fixed at startup on STDIO, so it must be cheap to clone and thread-safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResponseConfig {
    /// The payload encoding format (the URL path segment / flag prefix).
    pub(crate) format: Format,
    /// JSON-format shaping parameters.
    pub(crate) shape: ShapeOpts,
    /// Which [`crate::ids::IdStrategy`] renders torrent ids.
    pub(crate) ids: IdSelector,
}

/// The payload encoding format. Only [`Format::Json`] is valid in v1; the enum reserves the
/// namespace so adding `toon`/`xml`/`text` later is not a breaking URL change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Json,
}

/// JSON-format shaping parameters (the `shape=` axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShapeOpts {
    /// Whitespace rendering.
    pub(crate) whitespace: Whitespace,
    /// When true, emit a one-time `defaults` block and omit per-row default-valued fields
    /// (the `defaults` shape token).
    pub(crate) omit_defaults: bool,
}

/// Whitespace rendering for the `json` format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Whitespace {
    /// `serde_json::to_string_pretty` — human-readable; opt in with `shape=pretty`.
    Pretty,
    /// `serde_json::to_string` — no whitespace. The default.
    Minified,
}

/// Selects the [`crate::ids::IdStrategy`] (the `ids=` axis). Only [`IdSelector::Full`] ships in
/// v1; abbreviation strategies are designed-for but not built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdSelector {
    Full,
}

impl Default for ResponseConfig {
    /// `json` + `minified` + `full`. Compact output is the default because LLM clients are the
    /// common consumer; opt into human-readable output with `shape=pretty`.
    fn default() -> Self {
        Self {
            format: Format::Json,
            shape: ShapeOpts {
                whitespace: Whitespace::Minified,
                omit_defaults: false,
            },
            ids: IdSelector::Full,
        }
    }
}

/// A failure to parse a [`ResponseConfig`]. The [`Display`](std::fmt::Display) text names the
/// offending token and lists the valid values, so it can be returned verbatim to an operator
/// (STDIO startup error) or an HTTP client (400 body).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfigParseError {
    /// The path segment / flag prefix is not a known format.
    UnknownFormat(String),
    /// An unrecognized query parameter key.
    UnknownParam(String),
    /// A recognized parameter carried an invalid value.
    InvalidValue { param: String, value: String },
    /// `shape` requested both `pretty` and `minified`.
    ContradictoryWhitespace,
}

impl std::fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFormat(got) => write!(
                f,
                "unknown response format '{got}' (valid formats: json)"
            ),
            Self::UnknownParam(key) => write!(
                f,
                "unknown response parameter '{key}' (valid parameters for json: shape, ids)"
            ),
            Self::InvalidValue { param, value } => match param.as_str() {
                "shape" => write!(
                    f,
                    "invalid shape value '{value}' (valid: pretty, minified, defaults)"
                ),
                "ids" => write!(f, "invalid ids value '{value}' (valid: full)"),
                other => write!(f, "invalid value '{value}' for parameter '{other}'"),
            },
            Self::ContradictoryWhitespace => write!(
                f,
                "shape cannot be both 'pretty' and 'minified'"
            ),
        }
    }
}

impl std::error::Error for ConfigParseError {}

/// Parse a `(format_segment, query)` pair into a [`ResponseConfig`].
///
/// `format_segment` is the URL path segment after `/mcp/` (or the flag prefix before `?`); an
/// empty segment selects the default format. `query` is the raw `&`-joined query string
/// (without a leading `?`); an empty query selects default parameters.
///
/// This is the single grammar shared by both transports — see [`parse_flag`] for the STDIO
/// entry point.
pub(crate) fn parse(format_segment: &str, query: &str) -> Result<ResponseConfig, ConfigParseError> {
    let format = match format_segment {
        "" | "json" => Format::Json,
        other => return Err(ConfigParseError::UnknownFormat(other.to_string())),
    };

    // v1: only the `json` format exists, so there is one parameter parser. A future format
    // would branch here on `format` to its own parameter set.
    let mut cfg = ResponseConfig {
        format,
        ..Default::default()
    };

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "shape" => parse_shape(value, &mut cfg.shape)?,
            "ids" => {
                cfg.ids = match value {
                    "full" => IdSelector::Full,
                    other => {
                        return Err(ConfigParseError::InvalidValue {
                            param: "ids".to_string(),
                            value: other.to_string(),
                        })
                    }
                };
            }
            other => return Err(ConfigParseError::UnknownParam(other.to_string())),
        }
    }

    Ok(cfg)
}

/// Apply a `shape=` CSV value (e.g. `minified,defaults`) onto [`ShapeOpts`].
fn parse_shape(value: &str, shape: &mut ShapeOpts) -> Result<(), ConfigParseError> {
    // An empty value (`?shape=` or a bare `?shape`) is a hard error, not a silent no-op —
    // otherwise a typo that drops the value masquerades as a working config.
    let tokens: Vec<&str> = value.split(',').filter(|s| !s.is_empty()).collect();
    if tokens.is_empty() {
        return Err(ConfigParseError::InvalidValue {
            param: "shape".to_string(),
            value: value.to_string(),
        });
    }

    let mut saw_pretty = false;
    let mut saw_minified = false;
    for token in tokens {
        match token {
            "pretty" => {
                saw_pretty = true;
                shape.whitespace = Whitespace::Pretty;
            }
            "minified" => {
                saw_minified = true;
                shape.whitespace = Whitespace::Minified;
            }
            "defaults" => shape.omit_defaults = true,
            other => {
                return Err(ConfigParseError::InvalidValue {
                    param: "shape".to_string(),
                    value: other.to_string(),
                })
            }
        }
    }
    if saw_pretty && saw_minified {
        return Err(ConfigParseError::ContradictoryWhitespace);
    }
    Ok(())
}

/// Parse a STDIO `--response-config` string of the form `<format>?<params>` (e.g.
/// `json?shape=minified,defaults`). Splits on the first `?` and delegates to [`parse`], so the
/// STDIO flag and the HTTP path+query share one grammar.
pub(crate) fn parse_flag(s: &str) -> Result<ResponseConfig, ConfigParseError> {
    let (format, query) = s.split_once('?').unwrap_or((s, ""));
    parse(format, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_json_minified_full() {
        let cfg = ResponseConfig::default();
        assert_eq!(cfg.format, Format::Json);
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(!cfg.shape.omit_defaults);
        assert_eq!(cfg.ids, IdSelector::Full);
    }

    /// `ResponseConfig` must be cheap to clone and thread-safe — it lives in request extensions.
    #[test]
    fn config_is_clone_send_sync() {
        fn assert_bounds<T: Clone + Send + Sync + 'static>() {}
        assert_bounds::<ResponseConfig>();
    }

    // --- parser: valid inputs ---

    #[test]
    fn empty_input_is_default() {
        assert_eq!(parse("", "").unwrap(), ResponseConfig::default());
        assert_eq!(parse("json", "").unwrap(), ResponseConfig::default());
    }

    #[test]
    fn parses_minified() {
        let cfg = parse("json", "shape=minified").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(!cfg.shape.omit_defaults);
    }

    #[test]
    fn parses_minified_and_defaults_csv() {
        let cfg = parse("json", "shape=minified,defaults").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(cfg.shape.omit_defaults);
    }

    #[test]
    fn parses_defaults_with_implicit_minified() {
        // `defaults` alone leaves whitespace at the default (minified).
        let cfg = parse("json", "shape=defaults").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(cfg.shape.omit_defaults);
    }

    #[test]
    fn parses_ids_full() {
        assert_eq!(parse("json", "ids=full").unwrap().ids, IdSelector::Full);
    }

    #[test]
    fn parses_multiple_params() {
        let cfg = parse("json", "shape=minified,defaults&ids=full").unwrap();
        assert_eq!(cfg.shape.whitespace, Whitespace::Minified);
        assert!(cfg.shape.omit_defaults);
        assert_eq!(cfg.ids, IdSelector::Full);
    }

    // --- parser: hard errors ---

    #[test]
    fn unknown_format_errors() {
        assert_eq!(
            parse("toon", ""),
            Err(ConfigParseError::UnknownFormat("toon".to_string()))
        );
    }

    #[test]
    fn unknown_param_errors() {
        assert_eq!(
            parse("json", "fields=name"),
            Err(ConfigParseError::UnknownParam("fields".to_string()))
        );
    }

    #[test]
    fn invalid_shape_value_errors() {
        assert_eq!(
            parse("json", "shape=bogus"),
            Err(ConfigParseError::InvalidValue {
                param: "shape".to_string(),
                value: "bogus".to_string(),
            })
        );
    }

    #[test]
    fn ids_short_is_rejected_in_v1() {
        assert_eq!(
            parse("json", "ids=short"),
            Err(ConfigParseError::InvalidValue {
                param: "ids".to_string(),
                value: "short".to_string(),
            })
        );
    }

    #[test]
    fn empty_shape_value_errors() {
        // `?shape=` and a bare `?shape` must be hard errors, not silent no-ops.
        assert_eq!(
            parse("json", "shape="),
            Err(ConfigParseError::InvalidValue {
                param: "shape".to_string(),
                value: "".to_string(),
            })
        );
        assert!(parse("json", "shape").is_err());
        // A value that is only separators is likewise empty.
        assert!(parse("json", "shape=,").is_err());
    }

    #[test]
    fn contradictory_whitespace_errors() {
        assert_eq!(
            parse("json", "shape=minified,pretty"),
            Err(ConfigParseError::ContradictoryWhitespace)
        );
    }

    #[test]
    fn error_messages_name_token_and_valid_values() {
        assert!(parse("toon", "").unwrap_err().to_string().contains("json"));
        assert!(parse("json", "shape=x")
            .unwrap_err()
            .to_string()
            .contains("pretty, minified, defaults"));
    }

    // --- parser: HTTP-form and STDIO-form equivalence (single-grammar guarantee) ---

    #[test]
    fn http_form_equals_stdio_form() {
        // HTTP supplies (segment, query) separately; STDIO supplies one "<format>?<params>"
        // string. The same logical config must parse identically.
        let http = parse("json", "shape=minified,defaults&ids=full").unwrap();
        let stdio = parse_flag("json?shape=minified,defaults&ids=full").unwrap();
        assert_eq!(http, stdio);
    }

    #[test]
    fn parse_flag_without_query_is_format_only() {
        assert_eq!(parse_flag("json").unwrap(), ResponseConfig::default());
    }

    #[test]
    fn parse_flag_propagates_errors() {
        assert_eq!(
            parse_flag("json?shape=bogus"),
            Err(ConfigParseError::InvalidValue {
                param: "shape".to_string(),
                value: "bogus".to_string(),
            })
        );
    }
}
