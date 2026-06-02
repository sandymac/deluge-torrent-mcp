// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Input validation and source-type detection.
//!
//! These guard against LLM hallucination: rejecting malformed info hashes and
//! label names before they reach Deluge, and detecting whether an `add_torrent`
//! source is valid base64 .torrent content.
//! Kept as `pub(super)` methods on [`DelugeServer`] so callers use `Self::…`.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use super::params::InfoHash;
use super::DelugeServer;
use crate::ids::IdStrategy;

impl DelugeServer {
    /// Validate that info_hashes is non-empty and each hash is well-formed.
    pub(super) fn validate_info_hashes(hashes: &[InfoHash]) -> Result<(), String> {
        if hashes.is_empty() {
            return Err("info_hashes must not be empty.".to_string());
        }
        for h in hashes {
            Self::validate_info_hash(&h.0)?;
        }
        Ok(())
    }

    /// Validate (and, for future strategies, resolve) a torrent info hash by routing it through
    /// the [`IdStrategy`](crate::ids::IdStrategy) seam. v1 has only [`Full`](crate::ids::Full),
    /// whose `decode` accepts a 40-hex (SHA-1) or 64-hex (SHA-256) hash and is otherwise the
    /// identity — so this is a behavioral no-op while establishing the seam. When a second
    /// strategy lands (post-v1), the per-request `IdSelector` is threaded here and the resolved
    /// hash is used downstream.
    pub(super) fn validate_info_hash(hash: &str) -> Result<(), String> {
        crate::ids::Full
            .decode(hash)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Check if a string is base64-encoded bencode (i.e. a .torrent file).
    pub(super) fn is_base64_torrent(s: &str) -> bool {
        let Ok(bytes) = BASE64.decode(s) else {
            return false;
        };
        // Use Decoder directly — Value::from_bencode uses MAX_DEPTH=0 which rejects
        // any nested structures. .torrent files nest up to ~3 levels (dict→info dict→files list).
        let mut decoder = bendy::decoding::Decoder::new(&bytes).with_max_depth(100);
        decoder.next_object().is_ok_and(|obj| obj.is_some())
    }

    /// Validate and normalize a Deluge label name. Lowercases the input and rejects
    /// empty strings or characters outside `[a-z0-9_\-\.]`.
    pub(super) fn validate_label_name(label: &str) -> Result<String, String> {
        let trimmed = label.trim();
        if trimmed.is_empty() {
            return Err("Label name must not be empty.".to_string());
        }
        let lowered = trimmed.to_lowercase();
        let valid = lowered.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.')
        });
        if !valid {
            return Err(format!(
                "Invalid label name '{label}'. Allowed characters: a-z, 0-9, '_', '-', '.'."
            ));
        }
        Ok(lowered)
    }

    /// Normalize a label for `label.set_torrent`. Empty string and the literal
    /// sentinel `"No Label"` are passed through unchanged — both clear the torrent's
    /// label on the daemon. Any other value is validated as a normal label name.
    pub(super) fn normalize_label_for_set(label: &str) -> Result<String, String> {
        if label.is_empty() || label == "No Label" {
            return Ok(label.to_string());
        }
        Self::validate_label_name(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_base64_torrent_detects_valid_torrent() {
        // Minimal valid .torrent: outer dict with announce + info dict containing pieces
        let input = "ZDg6YW5ub3VuY2UzNTp1ZHA6Ly90cmFja2VyLm9wZW5iaXR0b3JyZW50LmNvbTo4MDEzOmNyZWF0aW9uIGRhdGVpMTMyNzA0OTgyN2U0OmluZm9kNjpsZW5ndGhpMjBlNDpuYW1lMTA6c2FtcGxlLnR4dDEyOnBpZWNlIGxlbmd0aGk2NTUzNmU2OnBpZWNlczIwOlzF5lK+DebyeAWzBGT/mwD0ifDJNzpwcml2YXRlaTFlZWU=";
        assert!(DelugeServer::is_base64_torrent(input));
    }

    #[test]
    fn is_base64_torrent_rejects_invalid_inputs() {
        // Commas are not valid base64 characters (LLM hallucination case)
        assert!(!DelugeServer::is_base64_torrent(
            "CqyJwRCvvstNdevprj+KMltWj9C1jzBD,bTC2I2b2RP55"
        ));
        // Plain text (not base64)
        assert!(!DelugeServer::is_base64_torrent("hello world"));
        // Valid base64 but decodes to plain text, not bencode
        assert!(!DelugeServer::is_base64_torrent("aGVsbG8gd29ybGQ="));
        // File path
        assert!(!DelugeServer::is_base64_torrent("/srv/torrents/file.torrent"));
    }

    #[test]
    fn validate_info_hash_accepts_sha1_and_sha256() {
        // 40 hex chars (SHA-1)
        assert!(DelugeServer::validate_info_hash("d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb").is_ok());
        // 64 hex chars (SHA-256, BitTorrent v2)
        assert!(DelugeServer::validate_info_hash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
    }

    #[test]
    fn validate_info_hash_rejects_bad_length_and_nonhex() {
        // 39 chars — wrong length
        assert!(DelugeServer::validate_info_hash("d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fd").is_err());
        // 64 chars but contains a non-hex character ('g')
        assert!(DelugeServer::validate_info_hash(
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_err());
        // 50 chars — between the two valid lengths
        assert!(DelugeServer::validate_info_hash(&"a".repeat(50)).is_err());
    }

    #[test]
    fn validate_label_name_accepts_valid_labels() {
        assert_eq!(DelugeServer::validate_label_name("movies").unwrap(), "movies");
        assert_eq!(DelugeServer::validate_label_name("tv.shows").unwrap(), "tv.shows");
        assert_eq!(
            DelugeServer::validate_label_name("2024_backup").unwrap(),
            "2024_backup"
        );
        assert_eq!(DelugeServer::validate_label_name("a-b-c").unwrap(), "a-b-c");
        // Lowercased
        assert_eq!(DelugeServer::validate_label_name("Movies").unwrap(), "movies");
        // Trimmed
        assert_eq!(DelugeServer::validate_label_name("  movies  ").unwrap(), "movies");
    }

    #[test]
    fn validate_label_name_rejects_invalid_labels() {
        assert!(DelugeServer::validate_label_name("").is_err());
        assert!(DelugeServer::validate_label_name("   ").is_err());
        // Space is not allowed — "No Label" lowercases to "no label" which still has a space
        assert!(DelugeServer::validate_label_name("No Label").is_err());
        assert!(DelugeServer::validate_label_name("has space").is_err());
        assert!(DelugeServer::validate_label_name("emoji\u{1F3AC}").is_err());
        assert!(DelugeServer::validate_label_name("slash/here").is_err());
    }

    #[test]
    fn normalize_label_for_set_passes_clear_sentinels() {
        assert_eq!(DelugeServer::normalize_label_for_set("").unwrap(), "");
        assert_eq!(
            DelugeServer::normalize_label_for_set("No Label").unwrap(),
            "No Label"
        );
        // Anything else goes through normal validation
        assert_eq!(DelugeServer::normalize_label_for_set("Movies").unwrap(), "movies");
        assert!(DelugeServer::normalize_label_for_set("bad name").is_err());
    }
}
