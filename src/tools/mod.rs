// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    Peer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    handler::server::wrapper::Parameters,
    model::{
        CallToolRequestParams, CallToolResult, Icon, Implementation, ListResourcesResult,
        ListResourceTemplatesResult, ListToolsResult, PaginatedRequestParams, RawResource,
        RawResourceTemplate, ReadResourceRequestParams, ReadResourceResult, Resource,
        ResourceContents, ResourceTemplate, ResourceUpdatedNotificationParam, ServerInfo,
        SetLevelRequestParams, SubscribeRequestParams, Tool, UnsubscribeRequestParams,
    },
    schemars,
    serde_json,
    service::RequestContext,
    tool, tool_router,
    ErrorData, RoleServer,
};
use tokio::sync::{broadcast::error::RecvError, RwLock};
use tracing::{debug, warn};

const ICON_SVG: &[u8] = include_bytes!("../../assets/deluge-mcp-icon.svg");
const ICON_48: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-48x48.png");
const ICON_96: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-96x96.png");
use serde::Deserialize;

use crate::deluge::{DelugeClient, DelugeEvent};
use crate::rencode::Value;

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DelugeServer {
    client: Arc<DelugeClient>,
    enabled_tools: std::collections::HashSet<String>,
    tool_router: ToolRouter<Self>,
    /// Active resource subscriptions: resource URI → connected peer.
    /// One subscriber per URI — last `subscribe` call wins.
    subscribers: Arc<RwLock<HashMap<String, Peer<RoleServer>>>>,
}

// ---------------------------------------------------------------------------
// Parameter types
// ---------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema)]
struct AddTorrentParams {
    /// Magnet URI (must start with 'magnet:').
    magnet_link: Option<String>,
    /// HTTP/HTTPS URL to a .torrent file. Fetched asynchronously — returns before download completes.
    url: Option<String>,
    /// Absolute path to a .torrent file on the Deluge server's filesystem.
    file_path: Option<String>,
    /// Base64-encoded .torrent file contents.
    file_content: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TorrentIdParams {
    /// Target torrent info_hash.
    info_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RemoveTorrentParams {
    /// Target torrent info_hash.
    info_hash: String,
    /// If true, permanently deletes all downloaded files from disk — this is irreversible. If false (default), removes the torrent from Deluge but leaves files on disk. Always confirm with the user before setting to true.
    #[serde(default)]
    delete_data: bool,
}

/// Speed values are in KiB/s; use -1 for unlimited. Omit fields you don't want to change.
#[derive(Deserialize, schemars::JsonSchema)]
struct SetOptionsParams {
    /// Target torrent info_hash.
    info_hash: String,
    /// Max download speed in KiB/s (-1 = unlimited).
    max_download_speed: Option<f64>,
    /// Max upload speed in KiB/s (-1 = unlimited).
    max_upload_speed: Option<f64>,
    /// Max simultaneous peer connections (-1 = unlimited).
    max_connections: Option<i64>,
    /// Seed ratio limit (e.g. 2.0 = 200%; -1 = unlimited).
    ratio_limit: Option<f64>,
    /// Remove torrent when ratio_limit is reached.
    remove_at_ratio: Option<bool>,
    /// Move files to move_completed_path when download finishes.
    move_completed: Option<bool>,
    /// Destination path when move_completed is true.
    move_completed_path: Option<String>,
    /// Download first and last pieces first (useful for media previews).
    prioritize_first_last_pieces: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct MoveStorageParams {
    /// Target torrent info_hash.
    info_hash: String,
    /// Absolute destination directory path on the Deluge server. Deluge will attempt to create it if it does not exist. The Deluge process must have write access to this path.
    dest: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFolderParams {
    /// Target torrent info_hash.
    info_hash: String,
    /// Current folder name within the torrent's file structure (as shown in the torrent file list, not a filesystem path).
    folder: String,
    /// New folder name. Should not contain path separators.
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FileRename {
    /// Zero-based file index from get_torrent_status 'files' field.
    index: i64,
    /// New name/path for the file (may include subdirectory components).
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFilesParams {
    /// Target torrent info_hash.
    info_hash: String,
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

#[derive(Deserialize, schemars::JsonSchema)]
struct ListTorrentsParams {
    /// Filter by torrent state. Omit to return all torrents.
    state: Option<TorrentState>,
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

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl DelugeServer {
    /// Add a new torrent to Deluge by magnet link, .torrent URL, server file path, or base64 file content.
    /// Provide EXACTLY ONE of: magnet_link, url, file_path, or file_content — not multiple.
    /// Returns the info_hash of the newly added torrent on success.
    /// When using url, Deluge fetches the .torrent file asynchronously; the call returns once the
    /// fetch begins, not when it completes, and will return an error if the URL is unreachable.
    #[tool(title = "Add Torrent", annotations(destructive_hint = false, open_world_hint = true))]
    async fn add_torrent(
        &self,
        Parameters(p): Parameters<AddTorrentParams>,
    ) -> Result<String, String> {
        let opts = Value::Dict(vec![]);

        let result = if let Some(uri) = p.magnet_link {
            if !uri.starts_with("magnet:") {
                return Err("magnet_link must start with 'magnet:'".to_string());
            }
            self.client
                .call("core.add_torrent_magnet", vec![Value::String(uri), opts], vec![])
                .await
        } else if let Some(url) = p.url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("url must start with 'http://' or 'https://'".to_string());
            }
            self.client
                .call("core.add_torrent_url", vec![Value::String(url), opts], vec![])
                .await
        } else if let Some(path) = p.file_path {
            if std::path::Path::new(&path)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err("file_path must not contain '..' components".to_string());
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|e| format!(
                    "Failed to read file: {e}\n\
                     [Hint: file_path must be an absolute path to a .torrent file on the \
                     Deluge server's filesystem, not on the client machine.]"
                ))?;
            let encoded = BASE64.encode(&bytes);
            let filename = std::path::Path::new(&path)
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
        } else if let Some(content) = p.file_content {
            const MAX_FILE_CONTENT_BYTES: usize = 32 * 1024 * 1024; // 32 MB
            if content.len() > MAX_FILE_CONTENT_BYTES {
                return Err(format!(
                    "file_content is {} bytes, exceeding the 32 MB limit. \
                     .torrent files are typically under 1 MB — this input is likely incorrect.",
                    content.len()
                ));
            }
            self.client
                .call(
                    "core.add_torrent_file",
                    vec![
                        Value::String("upload.torrent".to_string()),
                        Value::String(content),
                        opts,
                    ],
                    vec![],
                )
                .await
        } else {
            return Err(
                "Provide one of: magnet_link, url, file_path, or file_content".to_string(),
            );
        };

        result
            .map(|v| match v {
                Value::String(s) => s,
                other => Self::value_to_string(other),
            })
            .map_err(Self::enrich_client_error)
    }

    /// Remove a torrent from Deluge.
    /// If delete_data is true, all downloaded files are permanently deleted from disk — irreversible.
    /// If delete_data is false (default), files remain on disk and only the torrent entry is removed.
    #[tool(title = "Remove Torrent", annotations(destructive_hint = true, open_world_hint = false))]
    async fn remove_torrent(
        &self,
        Parameters(p): Parameters<RemoveTorrentParams>,
    ) -> Result<String, String> {
        self.tool_gate("remove_torrent")?;
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call(
                "core.remove_torrent",
                vec![
                    Value::String(p.info_hash.clone()),
                    Value::Bool(p.delete_data),
                ],
                vec![],
            )
            .await
            .map(|_| if p.delete_data { "deleted".to_string() } else { "ok".to_string() })
            .map_err(Self::enrich_client_error)
    }

    /// List torrents in Deluge with their current status, with optional state filtering and pagination.
    /// WORKFLOW: Use this first to discover torrents and obtain info_hash values required by all other tools.
    /// Returns a summary header (total, returned, offset, limit, has_more, next_offset) followed by
    /// a 'torrents' object keyed by info_hash. Each torrent contains: name, state, progress (0–100),
    /// total_size (bytes), download_payload_rate (bytes/sec), upload_payload_rate (bytes/sec),
    /// eta (seconds to completion, -1 if not applicable), save_path.
    /// Possible state values: Allocating, Checking, Downloading, Seeding, Paused, Queued, Error, Moving.
    /// If has_more is true, call again with offset=next_offset to retrieve the next page.
    #[tool(title = "List Torrents", annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_torrents(
        &self,
        Parameters(p): Parameters<ListTorrentsParams>,
    ) -> Result<String, String> {
        let limit = p.limit.unwrap_or(100).max(1);
        let offset = p.offset.unwrap_or(0);

        let filter = match p.state {
            Some(ref s) => {
                let state_str = serde_json::to_value(s)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default();
                Value::Dict(vec![(
                    Value::String("state".into()),
                    Value::String(state_str),
                )])
            }
            None => Value::Dict(vec![]),
        };

        let keys = Value::List(vec![
            Value::String("name".into()),
            Value::String("state".into()),
            Value::String("progress".into()),
            Value::String("total_size".into()),
            Value::String("download_payload_rate".into()),
            Value::String("upload_payload_rate".into()),
            Value::String("eta".into()),
            Value::String("save_path".into()),
        ]);

        let result = self.client
            .call("core.get_torrents_status", vec![filter, keys], vec![])
            .await
            .map_err(Self::enrich_client_error)?;

        let mut pairs = match result {
            Value::Dict(pairs) => pairs,
            other => return Ok(Self::value_to_json_string(other)),
        };

        let total = pairs.len();

        // Sort by name for deterministic pagination
        pairs.sort_by(|(_, a), (_, b)| {
            Self::torrent_name(a).cmp(Self::torrent_name(b))
        });

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
        for (k, v) in page {
            let key = match k {
                Value::String(s) => s,
                other => format!("{other:?}"),
            };
            torrents.insert(key, crate::rencode::value_to_json(v));
        }
        out.insert("torrents".into(), serde_json::Value::Object(torrents));

        Ok(serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap_or_default())
    }

    /// Get comprehensive status and metadata for a single torrent.
    /// Use this when you need file details (names, zero-based indices, per-file progress) required
    /// for rename_files, tracker information, piece details, or fields not in list_torrents.
    /// Returns a JSON object with all available torrent fields including a 'files' array.
    #[tool(title = "Get Torrent Status", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_torrent_status(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call(
                "core.get_torrent_status",
                vec![Value::String(p.info_hash), Value::List(vec![])],
                vec![],
            )
            .await
            .map(Self::value_to_json_string)
            .map_err(Self::enrich_client_error)
    }

    /// Pause a torrent, stopping all upload and download activity.
    #[tool(title = "Pause Torrent", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn pause_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call("core.pause_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Resume a paused torrent. If auto-managed, may re-enter the queue rather than downloading immediately.
    #[tool(title = "Resume Torrent", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn resume_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call("core.resume_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Set per-torrent options (speed limits, ratio targets, completion behavior). Takes effect immediately.
    #[tool(title = "Set Torrent Options", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn set_torrent_options(
        &self,
        Parameters(p): Parameters<SetOptionsParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
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
            return Err("No options provided.".to_string());
        }
        self.client
            .call(
                "core.set_torrent_options",
                vec![
                    Value::List(vec![Value::String(p.info_hash.clone())]),
                    Value::Dict(opts),
                ],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Move a torrent's data files to a new directory on the Deluge server.
    /// ASYNC: Returns immediately but the file move continues in the background.
    /// The torrent enters Moving state during the operation and returns to its previous state when complete.
    /// Use list_torrents or get_torrent_status to confirm the move has finished (state leaves Moving).
    #[tool(title = "Move Storage", annotations(destructive_hint = false, open_world_hint = false))]
    async fn move_storage(
        &self,
        Parameters(p): Parameters<MoveStorageParams>,
    ) -> Result<String, String> {
        self.tool_gate("move_storage")?;
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call(
                "core.move_storage",
                vec![
                    Value::List(vec![Value::String(p.info_hash.clone())]),
                    Value::String(p.dest.clone()),
                ],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Rename a top-level folder within a torrent's file structure.
    /// ASYNC: The rename occurs asynchronously in Deluge.
    /// Best performed on paused torrents. The old folder may remain on disk as an orphan — Deluge
    /// renames the tracked path but does not always remove the original directory.
    /// If renaming causes file path mismatches, follow up with force_recheck to reconcile.
    #[tool(title = "Rename Folder", annotations(destructive_hint = false, open_world_hint = false))]
    async fn rename_folder(
        &self,
        Parameters(p): Parameters<RenameFolderParams>,
    ) -> Result<String, String> {
        self.tool_gate("rename_folder")?;
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call(
                "core.rename_folder",
                vec![
                    Value::String(p.info_hash.clone()),
                    Value::String(p.folder.clone()),
                    Value::String(p.new_name.clone()),
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
    #[tool(title = "Rename Files", annotations(destructive_hint = false, open_world_hint = false))]
    async fn rename_files(
        &self,
        Parameters(p): Parameters<RenameFilesParams>,
    ) -> Result<String, String> {
        self.tool_gate("rename_files")?;
        Self::validate_info_hash(&p.info_hash)?;
        let renames = Value::List(
            p.renames
                .iter()
                .map(|r| {
                    Value::List(vec![
                        Value::Int(r.index),
                        Value::String(r.new_name.clone()),
                    ])
                })
                .collect(),
        );
        self.client
            .call(
                "core.rename_files",
                vec![Value::String(p.info_hash.clone()), renames],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Force a full hash recheck of a torrent's files. Use after external moves, corruption suspicion, or renames.
    /// ASYNC: Enters Checking state immediately; returns to previous state (including Paused) when done.
    #[tool(title = "Force Recheck", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn force_recheck(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        self.tool_gate("force_recheck")?;
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call(
                "core.force_recheck",
                vec![Value::List(vec![Value::String(p.info_hash.clone())])],
                vec![],
            )
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Get free disk space at a path on the Deluge server. Returns bytes, or error if path is invalid.
    #[tool(title = "Get Free Space", annotations(read_only_hint = true, open_world_hint = false))]
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
    #[tool(title = "Get Path Size", annotations(read_only_hint = true, open_world_hint = false))]
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
}

// ---------------------------------------------------------------------------
// Constructor and helpers
// ---------------------------------------------------------------------------

impl DelugeServer {
    pub fn new(
        client: Arc<DelugeClient>,
        enabled_tools: std::collections::HashSet<String>,
    ) -> Self {
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
            enabled_tools,
            tool_router: Self::tool_router(),
            subscribers,
        }
    }

    fn tool_gate(&self, tool_name: &str) -> Result<(), String> {
        if self.enabled_tools.contains(tool_name) {
            Ok(())
        } else {
            Err(format!(
                "Tool '{tool_name}' is disabled. Use --enable-tool={tool_name} to enable it.\n\
                 [Hint: This tool has been administratively disabled on this server. \
                 Do not attempt this operation by other means — inform the user that the \
                 server must be restarted with --enable-tool={tool_name} to allow this action.]"
            ))
        }
    }

    /// Validate a torrent info hash — 40 hex chars (v1/SHA-1) or 64 hex chars (v2/SHA-256).
    fn validate_info_hash(hash: &str) -> Result<(), String> {
        let valid_len = hash.len() == 40 || hash.len() == 64;
        let valid_hex = hash.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid_len || !valid_hex {
            return Err(format!(
                "invalid info_hash '{hash}': must be 40 hex characters (v1) or 64 hex characters (v2).\n\
                 [Hint: Do not guess or construct an info_hash. Use list_torrents to find the correct \
                 info_hash for the torrent you want to act on.]"
            ));
        }
        Ok(())
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

    /// Extract the torrent name from a torrent status Value for sorting purposes.
    fn torrent_name(v: &Value) -> &str {
        if let Value::Dict(fields) = v {
            for (k, val) in fields {
                if matches!(k, Value::String(s) if s == "name") {
                    if let Value::String(s) = val {
                        return s.as_str();
                    }
                }
            }
        }
        ""
    }

    fn value_to_string(v: Value) -> String {
        serde_json::to_string(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }

    fn value_to_json_string(v: Value) -> String {
        serde_json::to_string(&crate::rencode::value_to_json(v)).unwrap_or_default()
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
        DelugeEvent::Unknown { .. } => vec![],
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

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools: Vec<Tool> = self
            .tool_router
            .list_all()
            .into_iter()
            .filter(|t| self.enabled_tools.contains(t.name.as_ref()))
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
