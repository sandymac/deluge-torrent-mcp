// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Input validation and source-type detection.
//!
//! These guard against LLM hallucination: rejecting malformed info hashes and
//! label names before they reach Deluge, and auto-detecting whether an
//! `add_torrent` source is base64 .torrent content or a server file path.
//! Kept as `pub(super)` methods on [`DelugeServer`] so callers use `Self::…`.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use super::params::InfoHash;
use super::DelugeServer;

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

    /// Validate a torrent info hash — 40 hex chars (SHA-1).
    pub(super) fn validate_info_hash(hash: &str) -> Result<(), String> {
        let valid_len = hash.len() == 40;
        let valid_hex = hash.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid_len || !valid_hex {
            return Err(format!(
                "invalid info_hash '{hash}': must be 40 hex characters.\n\
                 [Hint: Do not guess or construct an info_hash. Use list_torrents to find the correct \
                 info_hash for the torrent you want to act on.]"
            ));
        }
        Ok(())
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

    /// Check if a string looks like an absolute file path.
    pub(super) fn looks_like_file_path(s: &str) -> bool {
        // Unix absolute path
        s.starts_with('/')
            // Windows absolute path (e.g. C:\, D:/)
            || (s.len() >= 3
                && s.as_bytes()[0].is_ascii_alphabetic()
                && s.as_bytes()[1] == b':'
                && (s.as_bytes()[2] == b'\\' || s.as_bytes()[2] == b'/'))
            // Windows UNC path (e.g. \\server\share)
            || s.starts_with("\\\\")
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
    fn looks_like_file_path_detects_absolute_paths() {
        // Unix
        assert!(DelugeServer::looks_like_file_path("/srv/torrents/file.torrent"));
        // Windows backslash
        assert!(DelugeServer::looks_like_file_path("C:\\Users\\file.torrent"));
        // Windows forward slash
        assert!(DelugeServer::looks_like_file_path("C:/Users/file.torrent"));
        // Windows UNC
        assert!(DelugeServer::looks_like_file_path("\\\\server\\share\\file.torrent"));
    }

    #[test]
    fn looks_like_file_path_rejects_non_paths() {
        assert!(!DelugeServer::looks_like_file_path("magnet:?xt=urn:btih:abc"));
        assert!(!DelugeServer::looks_like_file_path("aGVsbG8="));
        assert!(!DelugeServer::looks_like_file_path("some random string"));
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
