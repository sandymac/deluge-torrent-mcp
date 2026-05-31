// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    Peer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    handler::server::wrapper::Parameters,
    model::{
        CallToolRequestParams, CallToolResult, Icon, Implementation, InitializeRequestParams,
        InitializeResult, ListResourcesResult, ListResourceTemplatesResult, ListToolsResult,
        PaginatedRequestParams, RawResource, RawResourceTemplate, ReadResourceRequestParams,
        ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
        ResourceUpdatedNotificationParam, ServerInfo, SetLevelRequestParams,
        SubscribeRequestParams, Tool, UnsubscribeRequestParams,
    },
    schemars,
    serde_json,
    service::RequestContext,
    tool, tool_router,
    ErrorData, RoleServer,
};
use tokio::sync::{broadcast::error::RecvError, RwLock};
use tracing::{debug, info, warn};

const ICON_SVG: &[u8] = include_bytes!("../../assets/deluge-mcp-icon.svg");
const ICON_48: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-48x48.png");
const ICON_96: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-96x96.png");
use serde::Deserialize;

use crate::deluge::{DelugeClient, DelugeEvent};
use crate::rencode::Value;

pub(crate) mod gate;
pub(crate) mod registry;

use gate::ToolGate;

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct DelugeServer {
    client: Arc<DelugeClient>,
    /// Tool visibility gating — which tools are callable, given operator intent
    /// and the live Label-plugin state. Updated by the plugin watcher.
    gate: Arc<ToolGate>,
    tool_router: ToolRouter<Self>,
    /// Active resource subscriptions: resource URI → connected peer.
    /// One subscriber per URI — last `subscribe` call wins.
    subscribers: Arc<RwLock<HashMap<String, Peer<RoleServer>>>>,
    /// All connected MCP peers, captured on `initialize`.
    /// Used to fan out `notifications/tools/list_changed` when plugin state flips.
    connected_peers: Arc<RwLock<Vec<Peer<RoleServer>>>>,
}

// ---------------------------------------------------------------------------
// Parameter types
// ---------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema)]
struct AddTorrentParams {
    /// Torrent sources to add. Each entry is auto-detected: magnet: URIs, http/https URLs, base64-encoded .torrent file content, or absolute file paths on the Deluge server.
    #[schemars(length(min = 1))]
    torrent_sources: Vec<String>,
}

/// 40-character hex SHA-1 torrent info hash. Use deluge_list_torrents to discover valid values.
#[derive(Deserialize, schemars::JsonSchema)]
struct InfoHash(
    #[schemars(regex(pattern = r"^[0-9a-fA-F]{40}$"))]
    String,
);

#[derive(Deserialize, schemars::JsonSchema)]
struct TorrentIdParams {
    /// Torrent info_hashes to operate on.
    #[schemars(length(min = 1))]
    info_hashes: Vec<InfoHash>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RemoveTorrentParams {
    /// Torrent info_hashes to remove.
    #[schemars(length(min = 1))]
    info_hashes: Vec<InfoHash>,
    /// If true, permanently deletes all downloaded files from disk — this is irreversible. If false (default), removes the torrent from Deluge but leaves files on disk. Always confirm with the user before setting to true.
    #[serde(default)]
    delete_data: bool,
}

/// Speed values are in KiB/s. Use -1 for unlimited on any numeric field. Omit fields you don't want to change.
#[derive(Deserialize, schemars::JsonSchema)]
struct SetOptionsParams {
    /// Torrent info_hashes to set options on.
    #[schemars(length(min = 1))]
    info_hashes: Vec<InfoHash>,
    /// Max download speed in KiB/s.
    max_download_speed: Option<f64>,
    /// Max upload speed in KiB/s.
    max_upload_speed: Option<f64>,
    /// Max simultaneous peer connections.
    max_connections: Option<i64>,
    /// Seed ratio limit (e.g. 2.0 = 200%).
    ratio_limit: Option<f64>,
    /// Remove torrent when ratio_limit is reached.
    remove_at_ratio: Option<bool>,
    /// Move files to move_completed_path when download finishes.
    move_completed: Option<bool>,
    /// Destination path when move_completed is true. Has no effect unless move_completed is also true.
    move_completed_path: Option<String>,
    /// Download first and last pieces first (useful for media previews).
    prioritize_first_last_pieces: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct MoveStorageParams {
    /// Torrent info_hashes to move.
    #[schemars(length(min = 1))]
    info_hashes: Vec<InfoHash>,
    /// Absolute destination directory path on the Deluge server. Deluge will attempt to create it if it does not exist. The Deluge process must have write access to this path.
    dest: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFolderParams {
    /// Exactly one torrent info_hash whose folder is being renamed.
    // Wrapped in a Vec to sidestep an upstream tool-call serializer bug where scalar string
    // fields whose values pattern-match as hex numbers were silently coerced to integers
    // (decimal digits stripped, alpha chars dropped). The JSON array context locks the
    // element type as string and survives the round trip — same pattern as rename_files.
    #[schemars(length(min = 1, max = 1))]
    info_hashes: Vec<InfoHash>,
    /// Folder path prefix to rename, including the torrent root name and trailing slash (e.g. "MyTorrent/" or "MyTorrent/subfolder/").
    folder: String,
    /// Replacement folder path prefix. May include path separators. Deluge adds a trailing slash automatically.
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FileRename {
    /// Zero-based file index from get_torrent_status 'files' field.
    index: u32,
    /// New name/path for the file (may include subdirectory components).
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFilesParams {
    /// Exactly one torrent info_hash to rename files in.
    #[schemars(length(min = 1, max = 1))]
    info_hashes: Vec<InfoHash>,
    /// File renames to apply (index + new_name pairs).
    renames: Vec<FileRename>,
}

#[derive(Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "PascalCase")]
enum TorrentState {
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
enum SortField {
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
enum SortOrder {
    Asc,
    Desc,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ListTorrentsParams {
    /// Filter by torrent state. Omit to return all torrents.
    state: Option<TorrentState>,
    /// Filter by Deluge label. Requires the Label plugin to be enabled on the daemon.
    /// Pass the empty string to filter for unlabeled torrents.
    label: Option<String>,
    /// Case-insensitive substring match on torrent name (server-side via Deluge's native filter).
    name_contains: Option<String>,
    /// Case-insensitive substring match on save_path.
    save_path_contains: Option<String>,
    /// Field to sort by (default: name).
    sort_by: Option<SortField>,
    /// Sort direction (default: asc).
    sort_order: Option<SortOrder>,
    /// Max torrents per page (default: 100).
    limit: Option<usize>,
    /// Torrents to skip (default: 0). Use next_offset from previous response to paginate.
    offset: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PathParams {
    /// Absolute path (file or directory) on the Deluge server to query.
    path: String,
}

/// Label names use a restricted character set: lowercase letters, digits, '_', '-', and '.'.
/// Mixed-case input is normalized to lowercase before being sent to Deluge.
#[derive(Deserialize, schemars::JsonSchema)]
struct LabelNameParams {
    /// Label name. Allowed characters: a-z, 0-9, '_', '-', '.'. Will be lowercased.
    label: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SetTorrentLabelParams {
    /// Torrent info_hashes to apply the label to.
    #[schemars(length(min = 1))]
    info_hashes: Vec<InfoHash>,
    /// Label to assign. Pass an empty string or "No Label" to clear the torrent's label.
    /// Otherwise must already exist on the daemon — use deluge_create_label first if it does not.
    label: String,
}

/// Per-label default options that Deluge applies to every torrent carrying the label.
/// Speed values are in KiB/s. Use -1 for unlimited on any numeric field. Omit fields you don't want to change.
/// Each `apply_*` flag toggles whether the corresponding group of options takes effect:
/// `apply_max` gates max_download_speed/max_upload_speed/max_connections/max_upload_slots,
/// `apply_queue` gates is_auto_managed/stop_at_ratio/stop_ratio/remove_at_ratio,
/// `apply_move_completed` gates move_completed/move_completed_path.
#[derive(Deserialize, schemars::JsonSchema)]
struct SetLabelOptionsParams {
    /// Label to configure. Must already exist on the daemon.
    label: String,
    /// Enable the max_* speed and connection limits for torrents carrying this label.
    apply_max: Option<bool>,
    /// Max download speed in KiB/s.
    max_download_speed: Option<f64>,
    /// Max upload speed in KiB/s.
    max_upload_speed: Option<f64>,
    /// Max simultaneous peer connections.
    max_connections: Option<i64>,
    /// Max simultaneous upload slots.
    max_upload_slots: Option<i64>,
    /// Enable the queue-related options (is_auto_managed, stop/remove-at-ratio).
    apply_queue: Option<bool>,
    /// Whether Deluge's queue manager controls the torrent's start/stop state.
    is_auto_managed: Option<bool>,
    /// Stop the torrent when its ratio reaches stop_ratio.
    stop_at_ratio: Option<bool>,
    /// Seed ratio limit at which the torrent stops (e.g. 2.0 = 200%).
    stop_ratio: Option<f64>,
    /// Remove the torrent once stop_ratio is reached.
    remove_at_ratio: Option<bool>,
    /// Enable the move-completed options.
    apply_move_completed: Option<bool>,
    /// Move files to move_completed_path when download finishes.
    move_completed: Option<bool>,
    /// Destination path when move_completed is true.
    move_completed_path: Option<String>,
    /// Download first and last pieces first (useful for media previews).
    prioritize_first_last: Option<bool>,
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl DelugeServer {
    /// Add one or more torrents to Deluge. Each source is auto-detected: magnet: URI, http/https URL,
    /// base64-encoded .torrent file content, or absolute file path on the Deluge server.
    /// Returns the info_hash of each added torrent. URL sources are fetched asynchronously by Deluge.
    #[tool(name = "deluge_add_torrent", title = "Add Torrent", annotations(destructive_hint = false, open_world_hint = true))]
    async fn add_torrent(
        &self,
        Parameters(p): Parameters<AddTorrentParams>,
    ) -> Result<String, String> {
        if p.torrent_sources.is_empty() {
            return Err("torrent_sources must not be empty.".to_string());
        }
        if p.torrent_sources.len() == 1 {
            return self.add_single_torrent(&p.torrent_sources[0]).await;
        }
        // Batch — return ordered JSON array of results
        let mut results = Vec::new();
        for source in &p.torrent_sources {
            match self.add_single_torrent(source).await {
                Ok(hash) => results.push(serde_json::json!({"info_hash": hash})),
                Err(e) => results.push(serde_json::json!({"error": e})),
            }
        }
        Ok(serde_json::to_string_pretty(&serde_json::Value::Array(results)).unwrap_or_default())
    }

    /// Remove one or more torrents from Deluge.
    #[tool(name = "deluge_remove_torrent", title = "Remove Torrent", annotations(destructive_hint = true, open_world_hint = false))]
    async fn remove_torrent(
        &self,
        Parameters(p): Parameters<RemoveTorrentParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_remove_torrent")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        let hashes = p.info_hashes;
        let status_word = if p.delete_data { "deleted" } else { "ok" };
        let mut results = serde_json::Map::new();
        for hash in &hashes {
            let result = self
                .client
                .call(
                    "core.remove_torrent",
                    vec![Value::String(hash.0.clone()), Value::Bool(p.delete_data)],
                    vec![],
                )
                .await;
            match result {
                Ok(_) => {
                    results.insert(hash.0.clone(), serde_json::json!(status_word));
                }
                Err(e) => {
                    results.insert(
                        hash.0.clone(),
                        serde_json::json!({ "error": Self::enrich_client_error(e) }),
                    );
                }
            }
        }
        if results.len() == 1 {
            // Single torrent — return flat string for backward compat
            let (_, v) = results.into_iter().next().unwrap();
            if let Some(s) = v.as_str() {
                return Ok(s.to_string());
            }
            return Err(v["error"].as_str().unwrap_or("unknown error").to_string());
        }
        Ok(serde_json::to_string_pretty(&serde_json::Value::Object(results)).unwrap_or_default())
    }

    /// List torrents in Deluge with their current status, with filtering, sorting, and pagination.
    /// WORKFLOW: Use this first to discover torrents and obtain info_hash values required by all other tools.
    /// Returns a summary header (total, returned, offset, limit, has_more, next_offset) followed by
    /// a 'torrents' object keyed by info_hash. Each torrent contains: name, state, progress (0–100),
    /// total_size (bytes), download_payload_rate (bytes/sec), upload_payload_rate (bytes/sec),
    /// eta (seconds to completion, -1 if not applicable), save_path.
    /// Filters apply before pagination, so 'total' reflects the filtered count.
    /// If has_more is true, call again with offset=next_offset to retrieve the next page.
    #[tool(name = "deluge_list_torrents", title = "List Torrents", annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_torrents(
        &self,
        Parameters(p): Parameters<ListTorrentsParams>,
    ) -> Result<String, String> {
        let limit = p.limit.unwrap_or(100).max(1);
        let offset = p.offset.unwrap_or(0);
        let sort_by = p.sort_by.unwrap_or(SortField::Name);
        let sort_order = p.sort_order.unwrap_or(SortOrder::Asc);

        let label_plugin_active = self.gate.label_plugin_active();

        if p.label.is_some() && !label_plugin_active {
            return Err(
                "Cannot filter by label: the Label plugin is not enabled on the Deluge daemon.\n\
                 [Hint: Ask the user to enable the Label plugin in Deluge's Preferences \u{2192} Plugins.]"
                    .to_string(),
            );
        }

        // Server-side filters: state, label, name (substring, case-insensitive in Deluge default).
        let mut filter_pairs: Vec<(Value, Value)> = Vec::new();
        if let Some(ref s) = p.state {
            let state_str = serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            filter_pairs.push((Value::String("state".into()), Value::String(state_str)));
        }
        if let Some(ref label) = p.label {
            filter_pairs.push((
                Value::String("label".into()),
                Value::String(label.clone()),
            ));
        }
        if let Some(ref needle) = p.name_contains {
            filter_pairs.push((
                Value::String("name".into()),
                Value::String(needle.clone()),
            ));
        }
        let filter = Value::Dict(filter_pairs);

        // Base keys returned to the caller.
        let base_keys: &[&str] = &[
            "name",
            "state",
            "progress",
            "total_size",
            "download_payload_rate",
            "upload_payload_rate",
            "eta",
            "save_path",
        ];
        let mut keys_set: HashSet<&str> = base_keys.iter().copied().collect();
        if label_plugin_active {
            keys_set.insert("label");
        }
        // Helper keys requested only to support sort. Tracked so we can strip them
        // from the response if they aren't part of the base set.
        let mut helper_keys: Vec<&str> = Vec::new();
        let extra_for_sort: Option<&str> = match sort_by {
            SortField::TimeAdded => Some("time_added"),
            SortField::Ratio => Some("ratio"),
            _ => None,
        };
        if let Some(k) = extra_for_sort {
            if keys_set.insert(k) {
                helper_keys.push(k);
            }
        }
        let keys = Value::List(
            keys_set
                .iter()
                .map(|k| Value::String((*k).into()))
                .collect(),
        );

        let result = self.client
            .call("core.get_torrents_status", vec![filter, keys], vec![])
            .await
            .map_err(Self::enrich_client_error)?;

        let mut pairs = match result {
            Value::Dict(pairs) => pairs,
            other => return Ok(Self::value_to_json_string(other)),
        };

        // Client-side filter: save_path substring (no Deluge native equivalent).
        if let Some(ref needle) = p.save_path_contains {
            Self::filter_by_save_path_substring(&mut pairs, needle);
        }

        let total = pairs.len();

        Self::sort_torrent_pairs(&mut pairs, sort_by, sort_order);

        let page: Vec<_> = pairs.into_iter().skip(offset).take(limit).collect();
        let returned = page.len();
        let has_more = offset + returned < total;

        let mut out = serde_json::Map::new();
        out.insert("total".into(), serde_json::json!(total));
        out.insert("returned".into(), serde_json::json!(returned));
        out.insert("offset".into(), serde_json::json!(offset));
        out.insert("limit".into(), serde_json::json!(limit));
        out.insert("has_more".into(), serde_json::json!(has_more));
        if has_more {
            out.insert("next_offset".into(), serde_json::json!(offset + returned));
        }

        let mut torrents = serde_json::Map::new();
        for (k, mut v) in page {
            Self::strip_helper_keys(&mut v, &helper_keys);
            let key = match k {
                Value::String(s) => s,
                other => format!("{other:?}"),
            };
            torrents.insert(key, crate::rencode::value_to_json(v));
        }
        out.insert("torrents".into(), serde_json::Value::Object(torrents));

        Ok(serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap_or_default())
    }

    /// Get comprehensive status and metadata for one or more torrents.
    /// Use this when you need file details (names, zero-based indices, per-file progress) required
    /// for rename_files, tracker information, piece details, or fields not in list_torrents.
    /// Returns a JSON object keyed by info_hash with all available torrent fields including a 'files' array.
    #[tool(name = "deluge_get_torrent_status", title = "Get Torrent Status", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_torrent_status(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hashes(&p.info_hashes)?;
        if p.info_hashes.len() == 1 {
            let hash = p.info_hashes.into_iter().next().unwrap();
            let result = self
                .client
                .call(
                    "core.get_torrent_status",
                    vec![Value::String(hash.0.clone()), Value::List(vec![])],
                    vec![],
                )
                .await
                .map_err(Self::enrich_client_error)?;
            let mut out = serde_json::Map::new();
            out.insert(hash.0, crate::rencode::value_to_json(result));
            return Ok(serde_json::to_string_pretty(&serde_json::Value::Object(out))
                .unwrap_or_default());
        }
        // Batch — use get_torrents_status with id filter
        let filter = Value::Dict(vec![(
            Value::String("id".into()),
            Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect()),
        )]);
        self.client
            .call("core.get_torrents_status", vec![filter, Value::List(vec![])], vec![])
            .await
            .map(Self::value_to_json_string)
            .map_err(Self::enrich_client_error)
    }

    /// Pause one or more torrents, stopping all upload and download activity.
    #[tool(name = "deluge_pause_torrent", title = "Pause Torrent", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn pause_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hashes(&p.info_hashes)?;
        self.client
            .call(
                "core.pause_torrents",
                vec![Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect())],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Resume one or more paused torrents. If auto-managed, may re-enter the queue rather than downloading immediately.
    #[tool(name = "deluge_resume_torrent", title = "Resume Torrent", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn resume_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hashes(&p.info_hashes)?;
        self.client
            .call(
                "core.resume_torrents",
                vec![Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect())],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Set options on one or more torrents (speed limits, ratio targets, completion behavior). Takes effect immediately.
    #[tool(name = "deluge_set_torrent_options", title = "Set Torrent Options", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn set_torrent_options(
        &self,
        Parameters(p): Parameters<SetOptionsParams>,
    ) -> Result<String, String> {
        Self::validate_info_hashes(&p.info_hashes)?;
        let mut opts: Vec<(Value, Value)> = vec![];
        if let Some(v) = p.max_download_speed {
            opts.push((Value::String("max_download_speed".into()), Value::Float64(v)));
        }
        if let Some(v) = p.max_upload_speed {
            opts.push((Value::String("max_upload_speed".into()), Value::Float64(v)));
        }
        if let Some(v) = p.max_connections {
            opts.push((Value::String("max_connections".into()), Value::Int(v)));
        }
        if let Some(v) = p.ratio_limit {
            opts.push((Value::String("ratio_limit".into()), Value::Float64(v)));
        }
        if let Some(v) = p.remove_at_ratio {
            opts.push((Value::String("remove_at_ratio".into()), Value::Bool(v)));
        }
        if let Some(v) = p.move_completed {
            opts.push((Value::String("move_completed".into()), Value::Bool(v)));
        }
        if let Some(v) = p.move_completed_path {
            opts.push((Value::String("move_completed_path".into()), Value::String(v)));
        }
        if let Some(v) = p.prioritize_first_last_pieces {
            opts.push((
                Value::String("prioritize_first_last_pieces".into()),
                Value::Bool(v),
            ));
        }
        if opts.is_empty() {
            return Err("No options provided. Set at least one option field (e.g. max_download_speed, ratio_limit).".to_string());
        }
        self.client
            .call(
                "core.set_torrent_options",
                vec![
                    Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect()),
                    Value::Dict(opts),
                ],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Move one or more torrents' data files to a new directory on the Deluge server.
    /// ASYNC: Returns immediately but the file move continues in the background.
    /// Torrents enter Moving state during the operation and return to their previous state when complete.
    /// Use list_torrents or get_torrent_status to confirm the move has finished (state leaves Moving).
    #[tool(name = "deluge_move_storage", title = "Move Storage", annotations(destructive_hint = false, open_world_hint = false))]
    async fn move_storage(
        &self,
        Parameters(p): Parameters<MoveStorageParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_move_storage")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        self.client
            .call(
                "core.move_storage",
                vec![
                    Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect()),
                    Value::String(p.dest.clone()),
                ],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Rename a folder within a torrent's file structure.
    /// ASYNC: The rename occurs asynchronously in Deluge.
    /// Best performed on paused torrents. The old folder may remain on disk as an orphan — Deluge
    /// renames the tracked path but does not always remove the original directory.
    /// If renaming causes file path mismatches, follow up with force_recheck to reconcile.
    #[tool(name = "deluge_rename_folder", title = "Rename Folder", annotations(destructive_hint = false, open_world_hint = false))]
    async fn rename_folder(
        &self,
        Parameters(p): Parameters<RenameFolderParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_rename_folder")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        if p.info_hashes.len() != 1 {
            return Err("rename_folder operates on a single torrent. Provide exactly one info_hash.".to_string());
        }
        let hash = p.info_hashes.into_iter().next().unwrap();
        if p.folder.is_empty() {
            return Err(
                "folder must not be empty.\n\
                 [Hint: Include the torrent root name and trailing slash, \
                 e.g. \"MyTorrent/\" or \"MyTorrent/subfolder/\".]"
                    .to_string(),
            );
        }
        // Ensure trailing slash — without it, "Foo" would match "FooBar/file.txt"
        let folder = if p.folder.ends_with('/') {
            p.folder
        } else {
            format!("{}/", p.folder)
        };
        self.client
            .call(
                "core.rename_folder",
                vec![
                    Value::String(hash.0),
                    Value::String(folder),
                    Value::String(p.new_name),
                ],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Rename one or more files within a torrent.
    /// ASYNC: The rename occurs asynchronously in Deluge.
    /// PREREQUISITE: Call get_torrent_status first to retrieve file indices from the 'files' field.
    /// File indices are zero-based and stable for the lifetime of the torrent in Deluge.
    #[tool(name = "deluge_rename_files", title = "Rename Files", annotations(destructive_hint = false, open_world_hint = false))]
    async fn rename_files(
        &self,
        Parameters(p): Parameters<RenameFilesParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_rename_files")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        if p.info_hashes.len() != 1 {
            return Err("rename_files operates on a single torrent. Provide exactly one info_hash.".to_string());
        }
        let hash = p.info_hashes.into_iter().next().unwrap();
        let renames = Value::List(
            p.renames
                .iter()
                .map(|r| {
                    Value::List(vec![
                        Value::Int(r.index as i64),
                        Value::String(r.new_name.clone()),
                    ])
                })
                .collect(),
        );
        self.client
            .call(
                "core.rename_files",
                vec![Value::String(hash.0), renames],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Force a full hash recheck of one or more torrents' files. Use after external moves, corruption suspicion, or renames.
    /// ASYNC: Enters Checking state immediately; returns to previous state (including Paused) when done.
    #[tool(name = "deluge_force_recheck", title = "Force Recheck", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn force_recheck(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_force_recheck")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        self.client
            .call(
                "core.force_recheck",
                vec![Value::List(p.info_hashes.into_iter().map(|h| Value::String(h.0)).collect())],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Get free disk space at a path on the Deluge server. Returns bytes, or error if path is invalid.
    #[tool(name = "deluge_get_free_space", title = "Get Free Space", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_free_space(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.client
            .call("core.get_free_space", vec![Value::String(p.path)], vec![])
            .await
            .map(|v| match v {
                Value::Int(bytes) => bytes.to_string(),
                other => Self::value_to_string(other),
            })
            .map_err(Self::enrich_client_error)
    }

    /// Get the total size of a file or directory on the Deluge server. Returns bytes, or -1 if inaccessible.
    #[tool(name = "deluge_get_path_size", title = "Get Path Size", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_path_size(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.client
            .call("core.get_path_size", vec![Value::String(p.path)], vec![])
            .await
            .map(|v| match v {
                Value::Int(bytes) => bytes.to_string(),
                other => Self::value_to_string(other),
            })
            .map_err(Self::enrich_client_error)
    }

    /// Create a new label on the Deluge daemon. Labels are used to group and bulk-operate on torrents.
    #[tool(name = "deluge_create_label", title = "Create Label", annotations(destructive_hint = false, open_world_hint = false))]
    async fn create_label(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_create_label")?;
        let label = Self::validate_label_name(&p.label)?;
        self.client
            .call("label.add", vec![Value::String(label)], vec![])
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_label_error)
    }

    /// Delete a label from the Deluge daemon. Torrents previously assigned this label become unlabeled.
    /// The torrents themselves and their data are not affected.
    #[tool(name = "deluge_delete_label", title = "Delete Label", annotations(destructive_hint = true, idempotent_hint = false, open_world_hint = false))]
    async fn delete_label(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_delete_label")?;
        let label = Self::validate_label_name(&p.label)?;
        self.client
            .call("label.remove", vec![Value::String(label)], vec![])
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_label_error)
    }

    /// Assign a label to one or more torrents. A torrent can only have one label at a time.
    /// PREREQUISITE: The label must already exist — use deluge_create_label first if needed.
    #[tool(name = "deluge_set_torrent_label", title = "Set Torrent Label", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn set_torrent_label(
        &self,
        Parameters(p): Parameters<SetTorrentLabelParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_set_torrent_label")?;
        Self::validate_info_hashes(&p.info_hashes)?;
        let label = Self::normalize_label_for_set(&p.label)?;

        let create_label_hint = self.create_label_hint();
        let mut results = serde_json::Map::new();
        for hash in &p.info_hashes {
            let result = self
                .client
                .call(
                    "label.set_torrent",
                    vec![Value::String(hash.0.clone()), Value::String(label.clone())],
                    vec![],
                )
                .await;
            match result {
                Ok(_) => {
                    results.insert(hash.0.clone(), serde_json::json!("ok"));
                }
                Err(e) => {
                    let msg = Self::enrich_label_set_error(e, &label, create_label_hint.as_deref());
                    results.insert(hash.0.clone(), serde_json::json!({ "error": msg }));
                }
            }
        }
        if results.len() == 1 {
            let (_, v) = results.into_iter().next().unwrap();
            if let Some(s) = v.as_str() {
                return Ok(s.to_string());
            }
            return Err(v["error"].as_str().unwrap_or("unknown error").to_string());
        }
        Ok(serde_json::to_string_pretty(&serde_json::Value::Object(results)).unwrap_or_default())
    }

    /// Pause every torrent assigned the given label. Errors if no torrents currently have this label.
    #[tool(name = "deluge_pause_label", title = "Pause Label", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn pause_label(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_pause_label")?;
        let label = Self::validate_label_name(&p.label)?;
        self.bulk_act_on_label(&label, "core.pause_torrents", "paused").await
    }

    /// Resume every paused torrent assigned the given label. Errors if no torrents currently have this label.
    #[tool(name = "deluge_resume_label", title = "Resume Label", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn resume_label(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_resume_label")?;
        let label = Self::validate_label_name(&p.label)?;
        self.bulk_act_on_label(&label, "core.resume_torrents", "resumed").await
    }

    /// List all labels defined on the Deluge daemon. Returns a JSON array of label names.
    #[tool(name = "deluge_list_labels", title = "List Labels", annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_labels(&self) -> Result<String, String> {
        self.gate.check("deluge_list_labels")?;
        let result = self
            .client
            .call("label.get_labels", vec![], vec![])
            .await
            .map_err(Self::enrich_label_error)?;
        Ok(Self::value_to_json_string(result))
    }

    /// Get a label's default options (speed caps, ratio handling, move-completed path, etc.).
    /// These defaults are applied to every torrent assigned this label.
    #[tool(name = "deluge_get_label_options", title = "Get Label Options", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_label_options(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_get_label_options")?;
        let label = Self::validate_label_name(&p.label)?;
        let result = self
            .client
            .call("label.get_options", vec![Value::String(label)], vec![])
            .await
            .map_err(Self::enrich_label_error)?;
        Ok(Self::value_to_json_string(result))
    }

    /// Set default options on a label. Options are applied to every torrent currently carrying
    /// the label and to any new torrents assigned the label going forward.
    #[tool(name = "deluge_set_label_options", title = "Set Label Options", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn set_label_options(
        &self,
        Parameters(p): Parameters<SetLabelOptionsParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_set_label_options")?;
        let label = Self::validate_label_name(&p.label)?;

        let mut opts: Vec<(Value, Value)> = Vec::new();
        if let Some(v) = p.apply_max {
            opts.push((Value::String("apply_max".into()), Value::Bool(v)));
        }
        if let Some(v) = p.max_download_speed {
            opts.push((Value::String("max_download_speed".into()), Value::Float64(v)));
        }
        if let Some(v) = p.max_upload_speed {
            opts.push((Value::String("max_upload_speed".into()), Value::Float64(v)));
        }
        if let Some(v) = p.max_connections {
            opts.push((Value::String("max_connections".into()), Value::Int(v)));
        }
        if let Some(v) = p.max_upload_slots {
            opts.push((Value::String("max_upload_slots".into()), Value::Int(v)));
        }
        if let Some(v) = p.apply_queue {
            opts.push((Value::String("apply_queue".into()), Value::Bool(v)));
        }
        if let Some(v) = p.is_auto_managed {
            opts.push((Value::String("is_auto_managed".into()), Value::Bool(v)));
        }
        if let Some(v) = p.stop_at_ratio {
            opts.push((Value::String("stop_at_ratio".into()), Value::Bool(v)));
        }
        if let Some(v) = p.stop_ratio {
            opts.push((Value::String("stop_ratio".into()), Value::Float64(v)));
        }
        if let Some(v) = p.remove_at_ratio {
            opts.push((Value::String("remove_at_ratio".into()), Value::Bool(v)));
        }
        if let Some(v) = p.apply_move_completed {
            opts.push((
                Value::String("apply_move_completed".into()),
                Value::Bool(v),
            ));
        }
        if let Some(v) = p.move_completed {
            opts.push((Value::String("move_completed".into()), Value::Bool(v)));
        }
        if let Some(v) = p.move_completed_path {
            opts.push((
                Value::String("move_completed_path".into()),
                Value::String(v),
            ));
        }
        if let Some(v) = p.prioritize_first_last {
            opts.push((
                Value::String("prioritize_first_last".into()),
                Value::Bool(v),
            ));
        }
        if opts.is_empty() {
            return Err(
                "No options provided. Set at least one option field (e.g. stop_at_ratio, max_download_speed, move_completed_path).".to_string(),
            );
        }

        self.client
            .call(
                "label.set_options",
                vec![Value::String(label), Value::Dict(opts)],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_label_error)
    }
}

// ---------------------------------------------------------------------------
// Constructor and helpers
// ---------------------------------------------------------------------------

impl DelugeServer {
    pub(crate) fn new(
        client: Arc<DelugeClient>,
        user_intent_tools: HashSet<String>,
        plugin_gated_tools: HashSet<String>,
        initial_label_plugin_active: bool,
    ) -> Self {
        let gate = Arc::new(ToolGate::new(
            user_intent_tools,
            plugin_gated_tools,
            initial_label_plugin_active,
        ));

        let subscribers: Arc<RwLock<HashMap<String, Peer<RoleServer>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Background task: forward Deluge push events to subscribed MCP peers.
        let mut event_rx = client.subscribe_events();
        let subs_for_task = subscribers.clone();
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        let uris = event_to_resource_uris(&event);
                        if uris.is_empty() {
                            continue;
                        }
                        let mut failed_uris = Vec::new();
                        {
                            let subs = subs_for_task.read().await;
                            for uri in &uris {
                                if let Some(peer) = subs.get(uri) {
                                    let param =
                                        ResourceUpdatedNotificationParam::new(uri.clone());
                                    if let Err(e) =
                                        peer.notify_resource_updated(param).await
                                    {
                                        debug!(
                                            "resource_updated notification failed for {uri}: {e}"
                                        );
                                        failed_uris.push(uri.clone());
                                    }
                                }
                            }
                        }
                        if !failed_uris.is_empty() {
                            let mut subs = subs_for_task.write().await;
                            for uri in &failed_uris {
                                subs.remove(uri);
                            }
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(
                            "Resource event subscriber lagged by {n} events — \
                             some resource_updated notifications may have been missed"
                        );
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        Self {
            client,
            gate,
            tool_router: Self::tool_router(),
            subscribers,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Spawn the plugin watcher. Listens for Deluge `PluginEnabled`/`PluginDisabled`
    /// events for the Label plugin and updates the [`ToolGate`] accordingly.
    /// On reconnect or broadcast lag it re-probes via `core.get_enabled_plugins`
    /// to recover the authoritative state.
    pub(crate) fn spawn_plugin_watcher(&self) {
        let client = self.client.clone();
        let gate = self.gate.clone();
        let connected_peers = self.connected_peers.clone();
        let mut event_rx = client.subscribe_events();

        tokio::spawn(async move {
            // Seed from an authoritative probe. The constructor's
            // `initial_label_plugin_active` may be stale (e.g. captured at
            // process start but the plugin toggled before this HTTP session
            // opened), and the broadcast receiver was created above — any
            // events that arrive between here and the loop will be buffered.
            if let Some(active) = probe_label_plugin(&client).await {
                apply_label_state(active, &gate, &connected_peers).await;
            }

            loop {
                match event_rx.recv().await {
                    Ok(DelugeEvent::PluginEnabled { name }) if name == "Label" => {
                        apply_label_state(true, &gate, &connected_peers).await;
                    }
                    Ok(DelugeEvent::PluginDisabled { name }) if name == "Label" => {
                        apply_label_state(false, &gate, &connected_peers).await;
                    }
                    Ok(DelugeEvent::Reconnected) => {
                        // Re-seed from the daemon — the previous state may be stale
                        // and `set_event_interest` was just re-issued, so we may have
                        // missed transitions while disconnected.
                        if let Some(active) = probe_label_plugin(&client).await {
                            apply_label_state(active, &gate, &connected_peers).await;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(
                            "Plugin watcher lagged by {n} events — re-probing plugin state"
                        );
                        if let Some(active) = probe_label_plugin(&client).await {
                            apply_label_state(active, &gate, &connected_peers).await;
                        }
                    }
                    Err(RecvError::Closed) => break,
                    _ => {}
                }
            }
        });
    }

    /// Validate that info_hashes is non-empty and each hash is well-formed.
    fn validate_info_hashes(hashes: &[InfoHash]) -> Result<(), String> {
        if hashes.is_empty() {
            return Err("info_hashes must not be empty.".to_string());
        }
        for h in hashes {
            Self::validate_info_hash(&h.0)?;
        }
        Ok(())
    }

    /// Validate a torrent info hash — 40 hex chars (SHA-1).
    fn validate_info_hash(hash: &str) -> Result<(), String> {
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

    /// Auto-detect the source type and add a single torrent to Deluge.
    /// Detection order: magnet: → http/https URL → base64 .torrent → server file path.
    async fn add_single_torrent(&self, source: &str) -> Result<String, String> {
        let opts = Value::Dict(vec![]);

        let result = if source.starts_with("magnet:") {
            self.client
                .call(
                    "core.add_torrent_magnet",
                    vec![Value::String(source.to_string()), opts],
                    vec![],
                )
                .await
        } else if source.starts_with("http://") || source.starts_with("https://") {
            self.client
                .call(
                    "core.add_torrent_url",
                    vec![Value::String(source.to_string()), opts],
                    vec![],
                )
                .await
        } else if {
            // Size guard BEFORE base64 decode to prevent oversized allocation
            const MAX_BASE64_BYTES: usize = 32 * 1024 * 1024; // 32 MB
            if source.len() > MAX_BASE64_BYTES {
                return Err(format!(
                    "base64 content is {} bytes, exceeding the 32 MB limit. \
                     .torrent files are typically under 1 MB — this input is likely incorrect.",
                    source.len()
                ));
            }
            Self::is_base64_torrent(source)
        } {
            self.client
                .call(
                    "core.add_torrent_file",
                    vec![
                        Value::String("upload.torrent".to_string()),
                        Value::String(source.to_string()),
                        opts,
                    ],
                    vec![],
                )
                .await
        } else if Self::looks_like_file_path(source) {
            // Absolute file path on the Deluge server
            if std::path::Path::new(source)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err("file path must not contain '..' components".to_string());
            }
            let bytes = tokio::fs::read(source).await.map_err(|e| {
                format!(
                    "Failed to read file: {e}\n\
                     [Hint: file paths must be absolute paths to .torrent files on the \
                     Deluge server's filesystem, not on the client machine.]"
                )
            })?;
            let encoded = BASE64.encode(&bytes);
            let filename = std::path::Path::new(source)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file.torrent")
                .to_string();
            self.client
                .call(
                    "core.add_torrent_file",
                    vec![Value::String(filename), Value::String(encoded), opts],
                    vec![],
                )
                .await
        } else {
            return Err(
                "Unrecognized torrent source format. Each source must be one of: \
                 a magnet: URI, an http/https URL, base64-encoded .torrent file content, \
                 or an absolute file path on the Deluge server.\n\
                 [Hint: Do not fabricate .torrent file content. Use a magnet link or URL instead.]"
                    .to_string(),
            );
        };

        result
            .map(|v| match v {
                Value::String(s) => s,
                other => Self::value_to_string(other),
            })
            .map_err(Self::enrich_client_error)
    }

    /// Check if a string is base64-encoded bencode (i.e. a .torrent file).
    fn is_base64_torrent(s: &str) -> bool {
        let Ok(bytes) = BASE64.decode(s) else {
            return false;
        };
        // Use Decoder directly — Value::from_bencode uses MAX_DEPTH=0 which rejects
        // any nested structures. .torrent files nest up to ~3 levels (dict→info dict→files list).
        let mut decoder = bendy::decoding::Decoder::new(&bytes).with_max_depth(100);
        decoder.next_object().is_ok_and(|obj| obj.is_some())
    }

    /// Check if a string looks like an absolute file path.
    fn looks_like_file_path(s: &str) -> bool {
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

    /// Enrich transport-level errors (connection loss, send failure, reconnect timeout) with
    /// guidance telling the LLM whether to retry and what to check.
    fn enrich_client_error(e: anyhow::Error) -> String {
        let msg = e.to_string();
        if msg.starts_with("send failed")
            || msg.starts_with("Failed to reconnect")
            || msg.contains("connection lost")
            || msg.starts_with("response channel dropped")
        {
            format!(
                "{msg}\n[Hint: The connection to Deluge was interrupted. \
                 Retry the operation once — the server reconnects automatically. \
                 If it keeps failing, check that the Deluge daemon is running and reachable.]"
            )
        } else {
            msg
        }
    }

    /// Extract a named field from a torrent status Value (a `Value::Dict`).
    /// Returns None for non-Dict values or missing keys.
    fn extract_field<'a>(v: &'a Value, field: &str) -> Option<&'a Value> {
        if let Value::Dict(fields) = v {
            for (k, val) in fields {
                if matches!(k, Value::String(s) if s == field) {
                    return Some(val);
                }
            }
        }
        None
    }

    /// Extract a string field. Non-string or missing fields return None.
    fn extract_str<'a>(v: &'a Value, field: &str) -> Option<&'a str> {
        match Self::extract_field(v, field) {
            Some(Value::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extract a numeric field as f64. Coerces Int, Float32, and Float64.
    /// Non-numeric or missing fields return None.
    fn extract_num(v: &Value, field: &str) -> Option<f64> {
        match Self::extract_field(v, field) {
            Some(Value::Int(i)) => Some(*i as f64),
            Some(Value::Float32(f)) => Some(*f as f64),
            Some(Value::Float64(f)) => Some(*f),
            _ => None,
        }
    }

    /// Extract the torrent name. Used as a stable tie-breaker during sort.
    fn torrent_name(v: &Value) -> &str {
        Self::extract_str(v, "name").unwrap_or("")
    }

    /// Compare two torrent dicts by a numeric field. Missing or non-numeric values
    /// sort as Equal. Uses partial_cmp; NaN compares as Equal.
    fn cmp_num(a: &Value, b: &Value, field: &str) -> std::cmp::Ordering {
        let av = Self::extract_num(a, field);
        let bv = Self::extract_num(b, field);
        match (av, bv) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            _ => std::cmp::Ordering::Equal,
        }
    }

    /// Retain only torrent pairs whose `save_path` contains `needle` (case-insensitive).
    /// Pairs missing a string `save_path` are dropped.
    fn filter_by_save_path_substring(pairs: &mut Vec<(Value, Value)>, needle: &str) {
        let needle = needle.to_lowercase();
        pairs.retain(|(_, v)| {
            Self::extract_str(v, "save_path")
                .map(|s| s.to_lowercase().contains(&needle))
                .unwrap_or(false)
        });
    }

    /// Sort torrent pairs by `sort_by` in `sort_order`, with name-asc as a stable
    /// tiebreaker. The tiebreak is preserved under desc — only the primary
    /// comparator is inverted, so torrents tied on the primary key still come back
    /// in name-asc order, giving deterministic pagination in both directions.
    fn sort_torrent_pairs(
        pairs: &mut [(Value, Value)],
        sort_by: SortField,
        sort_order: SortOrder,
    ) {
        pairs.sort_by(|(_, a), (_, b)| {
            use std::cmp::Ordering;
            let primary = match sort_by {
                SortField::Name => Self::torrent_name(a).cmp(Self::torrent_name(b)),
                SortField::SavePath => Self::extract_str(a, "save_path")
                    .unwrap_or("")
                    .cmp(Self::extract_str(b, "save_path").unwrap_or("")),
                SortField::Progress => Self::cmp_num(a, b, "progress"),
                SortField::TotalSize => Self::cmp_num(a, b, "total_size"),
                SortField::DownloadPayloadRate => Self::cmp_num(a, b, "download_payload_rate"),
                SortField::UploadPayloadRate => Self::cmp_num(a, b, "upload_payload_rate"),
                SortField::Eta => Self::cmp_num(a, b, "eta"),
                SortField::TimeAdded => Self::cmp_num(a, b, "time_added"),
                SortField::Ratio => Self::cmp_num(a, b, "ratio"),
            };
            let primary = if matches!(sort_order, SortOrder::Desc) {
                primary.reverse()
            } else {
                primary
            };
            match primary {
                Ordering::Equal => Self::torrent_name(a).cmp(Self::torrent_name(b)),
                other => other,
            }
        });
    }

    /// Strip helper keys from a torrent status `Value::Dict` in place. No-op for
    /// non-Dict values or when `helper_keys` is empty.
    fn strip_helper_keys(v: &mut Value, helper_keys: &[&str]) {
        if helper_keys.is_empty() {
            return;
        }
        if let Value::Dict(ref mut fields) = v {
            fields.retain(|(fk, _)| match fk {
                Value::String(s) => !helper_keys.iter().any(|h| h == s),
                _ => true,
            });
        }
    }

    fn value_to_string(v: Value) -> String {
        serde_json::to_string(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }

    fn value_to_json_string(v: Value) -> String {
        serde_json::to_string(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }

    /// Validate and normalize a Deluge label name. Lowercases the input and rejects
    /// empty strings or characters outside `[a-z0-9_\-\.]`.
    fn validate_label_name(label: &str) -> Result<String, String> {
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
    fn normalize_label_for_set(label: &str) -> Result<String, String> {
        if label.is_empty() || label == "No Label" {
            return Ok(label.to_string());
        }
        Self::validate_label_name(label)
    }

    /// Build a hint that points the LLM to deluge_create_label, but only if that
    /// tool is currently enabled. Returns `None` otherwise.
    fn create_label_hint(&self) -> Option<String> {
        if self.gate.is_enabled("deluge_create_label") {
            Some(
                "If the label does not exist, create it first with deluge_create_label."
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// Common implementation of pause_label / resume_label. Looks up the torrents
    /// carrying the label via a server-side filter, errors if none, then forwards
    /// the hash list to the supplied core action.
    async fn bulk_act_on_label(
        &self,
        label: &str,
        action_method: &str,
        action_past_tense: &str,
    ) -> Result<String, String> {
        let filter = Value::Dict(vec![(
            Value::String("label".into()),
            Value::String(label.to_string()),
        )]);
        let keys = Value::List(vec![Value::String("label".into())]);
        let status = self
            .client
            .call("core.get_torrents_status", vec![filter, keys], vec![])
            .await
            .map_err(Self::enrich_client_error)?;

        let hashes: Vec<String> = match status {
            Value::Dict(pairs) => pairs
                .into_iter()
                .filter_map(|(k, _)| match k {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
            other => {
                return Err(format!(
                    "Unexpected response from core.get_torrents_status: {other:?}"
                ));
            }
        };

        if hashes.is_empty() {
            return Err(format!(
                "No torrents have label '{label}'.\n\
                 [Hint: Use deluge_list_torrents to see which labels are in use, \
                 or pick a different label.]"
            ));
        }

        let count = hashes.len();
        let hash_values: Vec<Value> =
            hashes.iter().cloned().map(Value::String).collect();

        self.client
            .call(action_method, vec![Value::List(hash_values)], vec![])
            .await
            .map_err(Self::enrich_client_error)?;

        let out = serde_json::json!({
            "label": label,
            "action": action_past_tense,
            "count": count,
            "info_hashes": hashes,
        });
        Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
    }

    /// Map common label.* RPC errors to actionable messages. Keeps the raw exception
    /// text so the LLM has full context, then appends a [Hint: ...] for known cases.
    fn enrich_label_error(e: anyhow::Error) -> String {
        let msg = e.to_string();
        let hint = if msg.contains("Unknown Label") {
            Some(
                "The label does not exist on the Deluge daemon. \
                 Use deluge_list_torrents to discover labels in use, or create the label first.",
            )
        } else if msg.contains("Label already exists") {
            Some(
                "A label with this name already exists. \
                 No action needed if you intended to use the existing label.",
            )
        } else if msg.contains("Empty Label") || msg.contains("Invalid label") {
            Some(
                "Deluge rejected the label name. \
                 Allowed characters: a-z, 0-9, '_', '-', '.'.",
            )
        } else if msg.contains("KeyError")
            && (msg.contains("label.") || msg.contains("'label.'"))
        {
            Some(
                "The Label plugin appears to be disabled on the Deluge daemon — \
                 the label.* RPC methods are unregistered. \
                 The MCP server will hide label tools shortly.",
            )
        } else {
            None
        };
        match hint {
            Some(h) => format!("{msg}\n[Hint: {h}]"),
            None => msg,
        }
    }

    /// Specialized error handling for `label.set_torrent`. If the label is missing
    /// and `deluge_create_label` is currently enabled, suggest using it.
    fn enrich_label_set_error(
        e: anyhow::Error,
        label: &str,
        create_hint: Option<&str>,
    ) -> String {
        let msg = e.to_string();
        if msg.contains("Unknown Label") {
            let mut out = format!(
                "Label '{label}' does not exist on the Deluge daemon. ({msg})"
            );
            if let Some(hint) = create_hint {
                out.push_str(&format!("\n[Hint: {hint}]"));
            } else {
                out.push_str(
                    "\n[Hint: Ask the user to create the label in Deluge first, \
                     or to enable the create_label MCP tool.]",
                );
            }
            out
        } else {
            Self::enrich_label_error(e)
        }
    }
}

/// Map a Deluge push event to the resource URIs that should be notified.
fn event_to_resource_uris(event: &DelugeEvent) -> Vec<String> {
    let torrent_uri = |hash: &str| format!("deluge://torrent/{hash}");
    let with_list = |hash: &str| {
        vec!["deluge://torrents".to_string(), torrent_uri(hash)]
    };
    match event {
        DelugeEvent::TorrentAdded { info_hash, .. } => with_list(info_hash),
        DelugeEvent::TorrentRemoved { info_hash } => with_list(info_hash),
        DelugeEvent::TorrentStateChanged { info_hash, .. } => with_list(info_hash),
        DelugeEvent::TorrentFinished { info_hash } => with_list(info_hash),
        DelugeEvent::TorrentResumed { info_hash } => with_list(info_hash),
        DelugeEvent::TorrentStorageMoved { info_hash, .. } => with_list(info_hash),
        DelugeEvent::TorrentFileRenamed { info_hash, .. } => vec![torrent_uri(info_hash)],
        DelugeEvent::TorrentFolderRenamed { info_hash, .. } => vec![torrent_uri(info_hash)],
        DelugeEvent::PluginEnabled { .. }
        | DelugeEvent::PluginDisabled { .. }
        | DelugeEvent::Reconnected
        | DelugeEvent::Unknown { .. } => vec![],
    }
}

// ---------------------------------------------------------------------------
// Plugin watcher helpers
// ---------------------------------------------------------------------------

/// Probe the Deluge daemon for whether the Label plugin is currently enabled.
/// Returns `None` on RPC failure (caller should keep the previous state).
pub(crate) async fn probe_label_plugin(client: &Arc<DelugeClient>) -> Option<bool> {
    match client.call("core.get_enabled_plugins", vec![], vec![]).await {
        Ok(Value::List(items)) => Some(items.iter().any(
            |v| matches!(v, Value::String(s) if s == "Label"),
        )),
        Ok(other) => {
            warn!("core.get_enabled_plugins returned unexpected shape: {other:?}");
            None
        }
        Err(e) => {
            warn!("core.get_enabled_plugins failed: {e}");
            None
        }
    }
}

/// Apply a new Label-plugin state to the [`ToolGate`]. If it actually changes
/// the visible tool set, fans out `tools/list_changed` to every connected peer.
/// Stale peers (those whose send fails) are pruned.
async fn apply_label_state(
    active: bool,
    gate: &Arc<ToolGate>,
    connected_peers: &Arc<RwLock<Vec<Peer<RoleServer>>>>,
) {
    if !gate.set_label_plugin_active(active) {
        return;
    }

    info!(
        "Label plugin is now {} on the Deluge daemon — tool list updated",
        if active { "enabled" } else { "disabled" }
    );

    // Fan out tools/list_changed. Prune peers whose notify fails (closed
    // sessions) while preserving any peers added concurrently via initialize()
    // between the snapshot and the prune. `connected_peers` is append-only
    // outside this function, so positions 0..snapshot_len correspond to the
    // snapshot and positions >= snapshot_len are new arrivals we must keep.
    let peers_snapshot: Vec<Peer<RoleServer>> = connected_peers.read().await.clone();
    let snapshot_len = peers_snapshot.len();
    let mut success = vec![false; snapshot_len];
    for (i, peer) in peers_snapshot.iter().enumerate() {
        match peer.notify_tool_list_changed().await {
            Ok(()) => success[i] = true,
            Err(e) => debug!("notify_tool_list_changed failed for a peer: {e}"),
        }
    }

    let mut peers = connected_peers.write().await;
    let current = std::mem::take(&mut *peers);
    for (i, peer) in current.into_iter().enumerate() {
        if i >= snapshot_len || success[i] {
            peers.push(peer);
        }
    }
}

// ---------------------------------------------------------------------------
// ServerHandler
// ---------------------------------------------------------------------------

impl ServerHandler for DelugeServer {
    fn get_info(&self) -> ServerInfo {
        let icons = vec![
            Icon::new(format!("data:image/svg+xml;base64,{}", BASE64.encode(ICON_SVG)))
                .with_mime_type("image/svg+xml")
                .with_sizes(vec!["any".to_string()]),
            Icon::new(format!("data:image/png;base64,{}", BASE64.encode(ICON_48)))
                .with_mime_type("image/png")
                .with_sizes(vec!["48x48".to_string()]),
            Icon::new(format!("data:image/png;base64,{}", BASE64.encode(ICON_96)))
                .with_mime_type("image/png")
                .with_sizes(vec!["96x96".to_string()]),
        ];
        ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_logging()
                .build(),
        )
            .with_server_info(
                Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
                    .with_icons(icons),
            )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        // Track this peer so the plugin watcher can deliver tools/list_changed.
        self.connected_peers.write().await.push(context.peer.clone());
        Ok(self.get_info())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let enabled = self.gate.visible();
        let tools: Vec<Tool> = self
            .tool_router
            .list_all()
            .into_iter()
            .filter(|t| enabled.contains(t.name.as_ref()))
            .collect();
        Ok(ListToolsResult { tools, meta: None, next_cursor: None })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.tool_router.call(ToolCallContext::new(self, request, context)).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }

    async fn set_level(
        &self,
        _request: SetLevelRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        Ok(())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: vec![Resource {
                raw: RawResource {
                    uri: "deluge://torrents".to_string(),
                    name: "All Torrents".to_string(),
                    title: Some("All Torrents".to_string()),
                    description: Some(
                        "Snapshot of all torrents with current status. \
                         Subscribe for live updates when torrents are added, removed, \
                         or change state."
                            .to_string(),
                    ),
                    mime_type: Some("application/json".to_string()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                annotations: None,
            }],
            meta: None,
            next_cursor: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![ResourceTemplate {
                raw: RawResourceTemplate {
                    uri_template: "deluge://torrent/{info_hash}".to_string(),
                    name: "Torrent Status".to_string(),
                    title: Some("Torrent Status".to_string()),
                    description: Some(
                        "Complete status and metadata for a single torrent. \
                         Subscribe for live updates on state changes, file renames, \
                         and storage moves."
                            .to_string(),
                    ),
                    mime_type: Some("application/json".to_string()),
                    icons: None,
                },
                annotations: None,
            }],
            meta: None,
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = &request.uri;

        if uri == "deluge://torrents" {
            let result = self
                .client
                .call(
                    "core.get_torrents_status",
                    vec![
                        Value::Dict(vec![]),
                        Value::List(vec![
                            Value::String("name".into()),
                            Value::String("state".into()),
                            Value::String("progress".into()),
                            Value::String("total_size".into()),
                            Value::String("download_payload_rate".into()),
                            Value::String("upload_payload_rate".into()),
                            Value::String("eta".into()),
                            Value::String("save_path".into()),
                        ]),
                    ],
                    vec![],
                )
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

            let text = serde_json::to_string_pretty(&crate::rencode::value_to_json(result))
                .unwrap_or_default();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: uri.clone(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ]))
        } else if let Some(hash) = uri.strip_prefix("deluge://torrent/") {
            if let Err(e) = Self::validate_info_hash(hash) {
                return Err(ErrorData::invalid_params(e, None));
            }
            let result = self
                .client
                .call(
                    "core.get_torrent_status",
                    vec![Value::String(hash.to_string()), Value::List(vec![])],
                    vec![],
                )
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

            let text = serde_json::to_string_pretty(&crate::rencode::value_to_json(result))
                .unwrap_or_default();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: uri.clone(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ]))
        } else {
            Err(ErrorData::resource_not_found(
                format!("Unknown resource URI: {uri}"),
                None,
            ))
        }
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let uri = &request.uri;
        let valid = uri == "deluge://torrents"
            || uri
                .strip_prefix("deluge://torrent/")
                .map(|hash| {
                    (hash.len() == 40 || hash.len() == 64)
                        && hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
                .unwrap_or(false);
        if !valid {
            return Err(ErrorData::resource_not_found(
                format!("Unknown resource URI: {uri}"),
                None,
            ));
        }
        self.subscribers
            .write()
            .await
            .insert(uri.clone(), context.peer.clone());
        debug!("Subscribed to resource {uri}");
        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if self.subscribers.write().await.remove(&request.uri).is_some() {
            debug!("Unsubscribed from resource {}", request.uri);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_registered_tools() {
        // The registry (super::registry::TOOLS) is the single source of truth
        // for tool policy; the #[tool_router] macro is the source of truth for
        // what is actually callable. If they drift — a tool added to one but
        // not the other — gating silently breaks. Pin them together.
        use std::collections::HashSet;
        let registered: HashSet<String> = DelugeServer::tool_router()
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        let registry: HashSet<String> =
            registry::all_names().map(|s| s.to_string()).collect();
        assert_eq!(
            registry, registered,
            "registry::TOOLS and the #[tool_router] tool set must match exactly"
        );
    }

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

    // -----------------------------------------------------------------------
    // ListTorrentsParams: runtime behavior — filtering, sorting (incl. the
    // desc-tiebreak invariant), and helper-key stripping. The schema/deserialize
    // tests above are not enough on their own: a regression in the live
    // `list_torrents` output (e.g. flipping the tiebreak under desc) would still
    // pass them. These tests pin the actual filter/sort/strip behavior.
    // -----------------------------------------------------------------------

    /// Build a torrent dict with the given fields. Numeric values default to
    /// `Value::Float64` so they round-trip through `cmp_num` like Deluge's wire
    /// values.
    fn td(name: &str, save_path: &str, num_fields: &[(&str, f64)]) -> Value {
        let mut fields: Vec<(Value, Value)> = vec![
            (Value::String("name".into()), Value::String(name.into())),
            (
                Value::String("save_path".into()),
                Value::String(save_path.into()),
            ),
        ];
        for (k, v) in num_fields {
            fields.push((Value::String((*k).into()), Value::Float64(*v)));
        }
        Value::Dict(fields)
    }

    fn pair(hash: &str, dict: Value) -> (Value, Value) {
        (Value::String(hash.into()), dict)
    }

    fn names(pairs: &[(Value, Value)]) -> Vec<&str> {
        pairs
            .iter()
            .map(|(_, v)| DelugeServer::torrent_name(v))
            .collect()
    }

    #[test]
    fn filter_by_save_path_substring_is_case_insensitive() {
        let mut pairs = vec![
            pair("a", td("AlphaBook", "/srv/Media/audiobooks", &[])),
            pair("b", td("BetaBook", "/srv/media/ebooks", &[])),
            pair("c", td("GammaBook", "/srv/data/other", &[])),
            // Missing save_path: dropped.
            pair(
                "d",
                Value::Dict(vec![(
                    Value::String("name".into()),
                    Value::String("DeltaBook".into()),
                )]),
            ),
        ];
        DelugeServer::filter_by_save_path_substring(&mut pairs, "MEDIA");
        assert_eq!(names(&pairs), vec!["AlphaBook", "BetaBook"]);
    }

    #[test]
    fn filter_by_save_path_substring_empty_needle_keeps_all_with_save_path() {
        let mut pairs = vec![
            pair("a", td("Alpha", "/x", &[])),
            pair("b", td("Beta", "/y", &[])),
        ];
        let before = pairs.len();
        DelugeServer::filter_by_save_path_substring(&mut pairs, "");
        assert_eq!(pairs.len(), before);
    }

    #[test]
    fn sort_torrent_pairs_asc_by_total_size_tiebreaks_by_name() {
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[("total_size", 100.0)])),
            pair("b", td("Alpha", "/x", &[("total_size", 100.0)])),
            pair("c", td("Bravo", "/x", &[("total_size", 50.0)])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::TotalSize, SortOrder::Asc);
        // 50 first, then the 100s in name-asc order.
        assert_eq!(names(&pairs), vec!["Bravo", "Alpha", "Charlie"]);
    }

    #[test]
    fn sort_torrent_pairs_desc_inverts_primary_only() {
        // Regression test: under desc the primary comparator must be inverted,
        // but the name-asc tiebreak must be preserved. A naive `pairs.reverse()`
        // after an asc sort would invert both, making tied groups come back in
        // name-desc order.
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[("total_size", 100.0)])),
            pair("b", td("Alpha", "/x", &[("total_size", 100.0)])),
            pair("c", td("Bravo", "/x", &[("total_size", 50.0)])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::TotalSize, SortOrder::Desc);
        // 100s first (desc on primary), but tied group is still Alpha < Charlie.
        assert_eq!(names(&pairs), vec!["Alpha", "Charlie", "Bravo"]);
    }

    #[test]
    fn sort_torrent_pairs_desc_by_name_is_pure_name_desc() {
        // When the primary key IS name, desc gives a straight name-desc ordering.
        let mut pairs = vec![
            pair("a", td("Alpha", "/x", &[])),
            pair("b", td("Charlie", "/x", &[])),
            pair("c", td("Bravo", "/x", &[])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::Name, SortOrder::Desc);
        assert_eq!(names(&pairs), vec!["Charlie", "Bravo", "Alpha"]);
    }

    #[test]
    fn sort_torrent_pairs_missing_numeric_fields_sort_as_equal() {
        // When neither side has the numeric field, primary is Equal and the
        // tiebreak (name-asc) decides regardless of asc/desc on the primary.
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[])),
            pair("b", td("Alpha", "/x", &[])),
            pair("c", td("Bravo", "/x", &[])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::Ratio, SortOrder::Desc);
        assert_eq!(names(&pairs), vec!["Alpha", "Bravo", "Charlie"]);
    }

    #[test]
    fn strip_helper_keys_removes_listed_keys_only() {
        let mut v = td(
            "Alpha",
            "/x",
            &[("total_size", 100.0), ("time_added", 12345.0), ("ratio", 1.5)],
        );
        DelugeServer::strip_helper_keys(&mut v, &["time_added", "ratio"]);
        let Value::Dict(fields) = &v else {
            panic!("expected Dict");
        };
        let keys: Vec<&str> = fields
            .iter()
            .filter_map(|(k, _)| match k {
                Value::String(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"name"));
        assert!(keys.contains(&"save_path"));
        assert!(keys.contains(&"total_size"));
        assert!(!keys.contains(&"time_added"));
        assert!(!keys.contains(&"ratio"));
    }

    #[test]
    fn strip_helper_keys_empty_list_is_noop() {
        let mut v = td("Alpha", "/x", &[("time_added", 12345.0)]);
        let before = v.clone();
        DelugeServer::strip_helper_keys(&mut v, &[]);
        // Field set is identical.
        let Value::Dict(after_fields) = &v else {
            panic!("expected Dict");
        };
        let Value::Dict(before_fields) = &before else {
            panic!("expected Dict");
        };
        assert_eq!(before_fields.len(), after_fields.len());
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
