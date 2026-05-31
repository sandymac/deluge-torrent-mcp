// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Deserializable parameter types for the MCP tools.
//!
//! Each `#[tool]` method takes one of these via `Parameters<…>`. Field doc
//! comments and `#[schemars(...)]` constraints are serialized into the JSON
//! Schema sent to the LLM on every request, so they double as the tool's
//! machine-readable contract — see `tools/CLAUDE.md` for the authoring rules.

use rmcp::schemars;
use serde::Deserialize;

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct AddTorrentParams {
    /// Torrent sources to add. Each entry is auto-detected: magnet: URIs, http/https URLs, base64-encoded .torrent file content, or absolute file paths on the Deluge server.
    #[schemars(length(min = 1))]
    pub(super) torrent_sources: Vec<String>,
}

/// 40-character hex SHA-1 torrent info hash. Use deluge_list_torrents to discover valid values.
#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct InfoHash(
    #[schemars(regex(pattern = r"^[0-9a-fA-F]{40}$"))]
    pub(super) String,
);

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct TorrentIdParams {
    /// Torrent info_hashes to operate on.
    #[schemars(length(min = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct RemoveTorrentParams {
    /// Torrent info_hashes to remove.
    #[schemars(length(min = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// If true, permanently deletes all downloaded files from disk — this is irreversible. If false (default), removes the torrent from Deluge but leaves files on disk. Always confirm with the user before setting to true.
    #[serde(default)]
    pub(super) delete_data: bool,
}

/// Speed values are in KiB/s. Use -1 for unlimited on any numeric field. Omit fields you don't want to change.
#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct SetOptionsParams {
    /// Torrent info_hashes to set options on.
    #[schemars(length(min = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// Max download speed in KiB/s.
    pub(super) max_download_speed: Option<f64>,
    /// Max upload speed in KiB/s.
    pub(super) max_upload_speed: Option<f64>,
    /// Max simultaneous peer connections.
    pub(super) max_connections: Option<i64>,
    /// Seed ratio limit (e.g. 2.0 = 200%).
    pub(super) ratio_limit: Option<f64>,
    /// Remove torrent when ratio_limit is reached.
    pub(super) remove_at_ratio: Option<bool>,
    /// Move files to move_completed_path when download finishes.
    pub(super) move_completed: Option<bool>,
    /// Destination path when move_completed is true. Has no effect unless move_completed is also true.
    pub(super) move_completed_path: Option<String>,
    /// Download first and last pieces first (useful for media previews).
    pub(super) prioritize_first_last_pieces: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct MoveStorageParams {
    /// Torrent info_hashes to move.
    #[schemars(length(min = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// Absolute destination directory path on the Deluge server. Deluge will attempt to create it if it does not exist. The Deluge process must have write access to this path.
    pub(super) dest: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct RenameFolderParams {
    /// Exactly one torrent info_hash whose folder is being renamed.
    // Wrapped in a Vec to sidestep an upstream tool-call serializer bug where scalar string
    // fields whose values pattern-match as hex numbers were silently coerced to integers
    // (decimal digits stripped, alpha chars dropped). The JSON array context locks the
    // element type as string and survives the round trip — same pattern as rename_files.
    #[schemars(length(min = 1, max = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// Folder path prefix to rename, including the torrent root name and trailing slash (e.g. "MyTorrent/" or "MyTorrent/subfolder/").
    pub(super) folder: String,
    /// Replacement folder path prefix. May include path separators. Deluge adds a trailing slash automatically.
    pub(super) new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct FileRename {
    /// Zero-based file index from get_torrent_status 'files' field.
    pub(super) index: u32,
    /// New name/path for the file (may include subdirectory components).
    pub(super) new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct RenameFilesParams {
    /// Exactly one torrent info_hash to rename files in.
    #[schemars(length(min = 1, max = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// File renames to apply (index + new_name pairs).
    pub(super) renames: Vec<FileRename>,
}

#[derive(Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub(super) enum TorrentState {
    Downloading,
    Seeding,
    Paused,
    Queued,
    Checking,
    Error,
    Moving,
    Allocating,
}

#[derive(Deserialize, schemars::JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum SortField {
    Name,
    SavePath,
    Progress,
    TotalSize,
    DownloadPayloadRate,
    UploadPayloadRate,
    Eta,
    TimeAdded,
    Ratio,
}

#[derive(Deserialize, schemars::JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum SortOrder {
    Asc,
    Desc,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct ListTorrentsParams {
    /// Filter by torrent state. Omit to return all torrents.
    pub(super) state: Option<TorrentState>,
    /// Filter by Deluge label. Requires the Label plugin to be enabled on the daemon.
    /// Pass the empty string to filter for unlabeled torrents.
    pub(super) label: Option<String>,
    /// Case-insensitive substring match on torrent name (server-side via Deluge's native filter).
    pub(super) name_contains: Option<String>,
    /// Case-insensitive substring match on save_path.
    pub(super) save_path_contains: Option<String>,
    /// Field to sort by (default: name).
    pub(super) sort_by: Option<SortField>,
    /// Sort direction (default: asc).
    pub(super) sort_order: Option<SortOrder>,
    /// Max torrents per page (default: 100).
    pub(super) limit: Option<usize>,
    /// Torrents to skip (default: 0). Use next_offset from previous response to paginate.
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct PathParams {
    /// Absolute path (file or directory) on the Deluge server to query.
    pub(super) path: String,
}

/// Label names use a restricted character set: lowercase letters, digits, '_', '-', and '.'.
/// Mixed-case input is normalized to lowercase before being sent to Deluge.
#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct LabelNameParams {
    /// Label name. Allowed characters: a-z, 0-9, '_', '-', '.'. Will be lowercased.
    pub(super) label: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct SetTorrentLabelParams {
    /// Torrent info_hashes to apply the label to.
    #[schemars(length(min = 1))]
    pub(super) info_hashes: Vec<InfoHash>,
    /// Label to assign. Pass an empty string or "No Label" to clear the torrent's label.
    /// Otherwise must already exist on the daemon — use deluge_create_label first if it does not.
    pub(super) label: String,
}

/// Per-label default options that Deluge applies to every torrent carrying the label.
/// Speed values are in KiB/s. Use -1 for unlimited on any numeric field. Omit fields you don't want to change.
/// Each `apply_*` flag toggles whether the corresponding group of options takes effect:
/// `apply_max` gates max_download_speed/max_upload_speed/max_connections/max_upload_slots,
/// `apply_queue` gates is_auto_managed/stop_at_ratio/stop_ratio/remove_at_ratio,
/// `apply_move_completed` gates move_completed/move_completed_path.
#[derive(Deserialize, schemars::JsonSchema)]
pub(super) struct SetLabelOptionsParams {
    /// Label to configure. Must already exist on the daemon.
    pub(super) label: String,
    /// Enable the max_* speed and connection limits for torrents carrying this label.
    pub(super) apply_max: Option<bool>,
    /// Max download speed in KiB/s.
    pub(super) max_download_speed: Option<f64>,
    /// Max upload speed in KiB/s.
    pub(super) max_upload_speed: Option<f64>,
    /// Max simultaneous peer connections.
    pub(super) max_connections: Option<i64>,
    /// Max simultaneous upload slots.
    pub(super) max_upload_slots: Option<i64>,
    /// Enable the queue-related options (is_auto_managed, stop/remove-at-ratio).
    pub(super) apply_queue: Option<bool>,
    /// Whether Deluge's queue manager controls the torrent's start/stop state.
    pub(super) is_auto_managed: Option<bool>,
    /// Stop the torrent when its ratio reaches stop_ratio.
    pub(super) stop_at_ratio: Option<bool>,
    /// Seed ratio limit at which the torrent stops (e.g. 2.0 = 200%).
    pub(super) stop_ratio: Option<f64>,
    /// Remove the torrent once stop_ratio is reached.
    pub(super) remove_at_ratio: Option<bool>,
    /// Enable the move-completed options.
    pub(super) apply_move_completed: Option<bool>,
    /// Move files to move_completed_path when download finishes.
    pub(super) move_completed: Option<bool>,
    /// Destination path when move_completed is true.
    pub(super) move_completed_path: Option<String>,
    /// Download first and last pieces first (useful for media previews).
    pub(super) prioritize_first_last: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::{schemars, serde_json};

    // -----------------------------------------------------------------------
    // RenameFolderParams: regression guard for a bug where a scalar string
    // info_hash field was silently coerced to an integer by an upstream
    // tool-call serializer (decimal digits stripped from the hex hash, e.g.
    // `d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb` arrived as `910947815609010`).
    // The corruption happened before the value reached the MCP server, so a
    // schema tweak alone could not fix it. Wrapping the hash in a length-1
    // array — same shape as `RenameFilesParams` — restores the JSON array
    // context that locks the element type as string and survives the round
    // trip. These tests pin that array shape.
    // -----------------------------------------------------------------------

    #[test]
    fn rename_folder_params_deserializes_array_info_hash() {
        let payload = serde_json::json!({
            "info_hashes": ["d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb"],
            "folder": "We Have Always Lived in the Castle by Shirley Jackson/",
            "new_name": "We Have Always Lived in the Castle (Bernadette Dunne)"
        });
        let p: RenameFolderParams = serde_json::from_value(payload).expect("must deserialize");
        assert_eq!(p.info_hashes.len(), 1);
        assert_eq!(p.info_hashes[0].0, "d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb");
        assert_eq!(p.folder, "We Have Always Lived in the Castle by Shirley Jackson/");
        assert_eq!(p.new_name, "We Have Always Lived in the Castle (Bernadette Dunne)");
    }

    #[test]
    fn rename_folder_params_rejects_scalar_string_info_hash() {
        // The pre-fix scalar shape must no longer deserialize. An upstream
        // serializer would coerce hex-shaped scalar strings to integers; the
        // array shape is the only one we accept now.
        let payload = serde_json::json!({
            "info_hash": "d91ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb",
            "folder": "Foo/",
            "new_name": "Bar"
        });
        let result: Result<RenameFolderParams, _> = serde_json::from_value(payload);
        assert!(result.is_err(), "scalar info_hash must be rejected — payload missing required info_hashes");
    }

    #[test]
    fn rename_folder_params_schema_uses_array_for_info_hashes() {
        // The load-bearing assertion: the wire schema is an array of strings,
        // not a scalar string. The array context is what survives the upstream
        // tool-call serializer's hex-shaped-string-to-integer coercion.
        let schema = serde_json::to_value(schemars::schema_for!(RenameFolderParams)).unwrap();
        let info_hashes = schema
            .pointer("/properties/info_hashes")
            .expect("info_hashes property must exist");
        assert_eq!(
            info_hashes.get("type").and_then(|v| v.as_str()),
            Some("array"),
            "info_hashes must be type:array (scalar strings get coerced to integers upstream). Schema was: {info_hashes:#}"
        );
        assert_eq!(
            info_hashes.get("minItems").and_then(|v| v.as_u64()),
            Some(1),
            "info_hashes must have minItems=1. Schema was: {info_hashes:#}"
        );
        assert_eq!(
            info_hashes.get("maxItems").and_then(|v| v.as_u64()),
            Some(1),
            "info_hashes must have maxItems=1 — rename_folder operates on a single torrent. Schema was: {info_hashes:#}"
        );
    }

    #[test]
    fn rename_folder_params_schema_no_scalar_info_hash() {
        // Negative guard: ensure no scalar `info_hash` field sneaks back in.
        // A future maintainer adding it would silently re-introduce the bug
        // because hex-shaped scalar strings get coerced to integers upstream.
        let schema = serde_json::to_value(schemars::schema_for!(RenameFolderParams)).unwrap();
        assert!(
            schema.pointer("/properties/info_hash").is_none(),
            "info_hash (scalar) must not exist — use info_hashes (array) to avoid upstream coercion."
        );
    }

    // -----------------------------------------------------------------------
    // ListTorrentsParams: filter/sort surface (issue #6).
    // -----------------------------------------------------------------------

    #[test]
    fn list_torrents_params_empty_object_uses_defaults() {
        let p: ListTorrentsParams = serde_json::from_value(serde_json::json!({}))
            .expect("empty object must deserialize");
        assert!(p.state.is_none());
        assert!(p.label.is_none());
        assert!(p.name_contains.is_none());
        assert!(p.save_path_contains.is_none());
        assert!(p.sort_by.is_none());
        assert!(p.sort_order.is_none());
        assert!(p.limit.is_none());
        assert!(p.offset.is_none());
    }

    #[test]
    fn list_torrents_params_accepts_all_new_fields() {
        let payload = serde_json::json!({
            "state": "Downloading",
            "label": "movies",
            "name_contains": "ubuntu",
            "save_path_contains": "/media/",
            "sort_by": "total_size",
            "sort_order": "desc",
            "limit": 25,
            "offset": 50,
        });
        let p: ListTorrentsParams = serde_json::from_value(payload).expect("must deserialize");
        assert_eq!(p.name_contains.as_deref(), Some("ubuntu"));
        assert_eq!(p.save_path_contains.as_deref(), Some("/media/"));
        assert!(matches!(p.sort_by, Some(SortField::TotalSize)));
        assert!(matches!(p.sort_order, Some(SortOrder::Desc)));
        assert_eq!(p.limit, Some(25));
        assert_eq!(p.offset, Some(50));
    }

    #[test]
    fn list_torrents_params_rejects_unknown_sort_field() {
        let payload = serde_json::json!({ "sort_by": "bogus" });
        let result: Result<ListTorrentsParams, _> = serde_json::from_value(payload);
        assert!(result.is_err(), "unknown sort_by variant must be rejected");
    }

    #[test]
    fn sort_field_schema_lists_all_variants() {
        let schema = serde_json::to_value(schemars::schema_for!(ListTorrentsParams)).unwrap();
        // Resolve the SortField enum either inline or via $ref to $defs.
        let sort_by = schema
            .pointer("/properties/sort_by")
            .expect("sort_by property must exist");
        let variants = collect_enum_variants(&schema, sort_by);
        let expected: Vec<&str> = vec![
            "name",
            "save_path",
            "progress",
            "total_size",
            "download_payload_rate",
            "upload_payload_rate",
            "eta",
            "time_added",
            "ratio",
        ];
        for v in &expected {
            assert!(
                variants.iter().any(|x| x == v),
                "SortField schema is missing variant {v:?}; got {variants:?}"
            );
        }
        assert_eq!(
            variants.len(),
            expected.len(),
            "SortField schema variant count mismatch — got {variants:?}"
        );
    }

    #[test]
    fn sort_order_schema_lists_asc_desc() {
        let schema = serde_json::to_value(schemars::schema_for!(ListTorrentsParams)).unwrap();
        let sort_order = schema
            .pointer("/properties/sort_order")
            .expect("sort_order property must exist");
        let variants = collect_enum_variants(&schema, sort_order);
        assert_eq!(
            variants,
            vec!["asc".to_string(), "desc".to_string()],
            "SortOrder schema must list exactly [asc, desc]"
        );
    }

    /// Walk an enum-typed schema node, following a single $ref into $defs if needed,
    /// and return the list of string enum variants. Handles schemars' Option<EnumType>
    /// shape where the Option wraps the enum either inline or via $ref.
    fn collect_enum_variants(
        root: &serde_json::Value,
        node: &serde_json::Value,
    ) -> Vec<String> {
        // Direct enum on this node.
        if let Some(arr) = node.get("enum").and_then(|v| v.as_array()) {
            return arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
        // Option<T> shape from schemars: anyOf containing the enum type plus null.
        if let Some(arr) = node.get("anyOf").and_then(|v| v.as_array()) {
            for item in arr {
                let v = collect_enum_variants(root, item);
                if !v.is_empty() {
                    return v;
                }
            }
        }
        // $ref into $defs/<TypeName>.
        if let Some(reference) = node.get("$ref").and_then(|v| v.as_str()) {
            // Strip leading "#/" if present.
            let path = reference.trim_start_matches("#");
            if let Some(target) = root.pointer(path) {
                return collect_enum_variants(root, target);
            }
        }
        Vec::new()
    }
}
