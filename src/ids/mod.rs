// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Torrent-id rendering and resolution — the `ids=` seam.
//!
//! A torrent's id representation is a pluggable [`IdStrategy`] selected by the `ids=` axis of a
//! [`ResponseConfig`](crate::response_config::ResponseConfig). v1 ships [`Full`] only (the
//! 40/64-hex info hash, unchanged), but every hash-accepting tool routes its id handling
//! through this trait so a future abbreviation scheme (`Prefix`, `Ephemeral`) is purely
//! additive rather than cross-cutting across the 21 tools.
//!
//! The trait carries four responsibilities from the design doc: `encode` (output rendering),
//! `decode` (permissive input acceptance — the full hash is ALWAYS accepted whatever the active
//! strategy), `describe` (teach the LLM the id's rules), and a batch resolve that is the future
//! `resolve_ids` tool's contract and the recovery path for expired/abbreviated ids.

// This module lands ahead of its consumer (T7 routes the tools' hash handling through
// `decode`). The reserved `IdError` variants (`NotFound`/`Ambiguous`/`Expired`) and the batch
// resolve are designed-for future strategies and stay unconstructed under `Full`; this allow is
// narrowed to those reserved items in T7 once `encode`/`decode`/`describe` have callers.
#![allow(dead_code)]

use crate::response_config::IdSelector;

/// How a torrent id is rendered on output and resolved on input.
pub(crate) trait IdStrategy: Send + Sync {
    /// Render a full info hash as the id token a consumer sees. Identity for [`Full`].
    fn encode(&self, full_hash: &str) -> String;

    /// Resolve an input token back to a full info hash.
    ///
    /// PERMISSIVE: a full 40/64-hex info hash is always accepted regardless of the active
    /// strategy (token shapes are distinguishable), so routing every tool through `decode` is
    /// safe and a no-op for [`Full`].
    fn decode(&self, token: &str) -> Result<String, IdError>;

    /// A human/LLM-facing fragment describing the id's rules — injected into tool schemas so the
    /// model knows how to read and persist ids.
    fn describe(&self) -> SchemaFragment;

    /// Batch bidirectional translation between tokens and full hashes — the future `resolve_ids`
    /// tool's contract and the recovery path for `Expired`/abbreviated ids. Defaults to mapping
    /// [`decode`](Self::decode) over the batch.
    fn resolve_batch(&self, tokens: &[String]) -> Vec<Result<String, IdError>> {
        tokens.iter().map(|t| self.decode(t)).collect()
    }
}

/// A schema fragment teaching the LLM how to read and persist torrent ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SchemaFragment {
    /// Description text suitable for a tool/field schema `description`.
    pub(crate) description: String,
}

/// A failure to resolve an id token to a full info hash.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdError {
    /// The token is well-formed but no torrent matches (future stateful strategies).
    NotFound,
    /// The token (e.g. a short prefix) matches more than one torrent (future `Prefix`).
    Ambiguous,
    /// The token was a transient id that has since been evicted (future `Ephemeral`).
    Expired,
    /// The token is not a valid id in any accepted form.
    Invalid(String),
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every variant ends with the same actionable recovery guidance so adding the stateful
        // variants later is not a breaking change to the error contract.
        let recover = "[Hint: Do not guess or construct an info_hash. \
                       Use list_torrents to find the correct info_hash.]";
        match self {
            Self::NotFound => write!(f, "no torrent matches that id.\n{recover}"),
            Self::Ambiguous => write!(f, "that id is ambiguous — it matches more than one torrent.\n{recover}"),
            Self::Expired => write!(f, "that id has expired; re-fetch the current ids.\n{recover}"),
            Self::Invalid(msg) => write!(f, "{msg}\n{recover}"),
        }
    }
}

impl std::error::Error for IdError {}

/// The v1 strategy: the id IS the full 40/64-hex info hash. `encode`/`decode` are identity over
/// a validation check.
pub(crate) struct Full;

impl IdStrategy for Full {
    fn encode(&self, full_hash: &str) -> String {
        full_hash.to_string()
    }

    fn decode(&self, token: &str) -> Result<String, IdError> {
        let valid_len = token.len() == 40 || token.len() == 64;
        let valid_hex = token.bytes().all(|b| b.is_ascii_hexdigit());
        if valid_len && valid_hex {
            Ok(token.to_string())
        } else {
            Err(IdError::Invalid(format!(
                "invalid info_hash '{token}': must be 40 or 64 hex characters."
            )))
        }
    }

    fn describe(&self) -> SchemaFragment {
        SchemaFragment {
            description: "A torrent info hash: 40 hex characters (SHA-1) or 64 hex characters \
                          (SHA-256). This is the durable, cross-system key for the torrent."
                .to_string(),
        }
    }
}

/// The single shared instance of the [`Full`] strategy (zero-sized, stateless).
static FULL: Full = Full;

/// Resolve an [`IdSelector`] to its strategy. v1 always returns [`Full`].
pub(crate) fn strategy(selector: IdSelector) -> &'static dyn IdStrategy {
    match selector {
        IdSelector::Full => &FULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_encode_is_identity() {
        let hash = "d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb";
        assert_eq!(Full.encode(hash), hash);
    }

    #[test]
    fn full_decode_accepts_sha1_and_sha256() {
        assert_eq!(
            Full.decode("d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb").unwrap(),
            "d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb"
        );
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(Full.decode(sha256).unwrap(), sha256);
    }

    #[test]
    fn full_decode_rejects_garbage_with_guidance() {
        let err = Full.decode("not-a-hash").unwrap_err();
        assert!(matches!(err, IdError::Invalid(_)));
        assert!(err.to_string().contains("list_torrents"));
    }

    #[test]
    fn full_decode_rejects_bad_length() {
        // 39 chars
        assert!(Full.decode("d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fd").is_err());
        // 50 chars
        assert!(Full.decode(&"a".repeat(50)).is_err());
    }

    #[test]
    fn full_describe_is_non_empty() {
        assert!(!Full.describe().description.is_empty());
    }

    #[test]
    fn strategy_for_full_decodes() {
        let s = strategy(IdSelector::Full);
        assert!(s.decode("d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb").is_ok());
    }

    #[test]
    fn reserved_errors_carry_recovery_guidance() {
        for e in [IdError::NotFound, IdError::Ambiguous, IdError::Expired] {
            assert!(e.to_string().contains("list_torrents"));
        }
    }
}
