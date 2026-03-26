use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{Implementation, ServerInfo},
    schemars,
    serde_json,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::deluge::DelugeClient;
use crate::rencode::Value;

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DelugeServer {
    client: Arc<DelugeClient>,
    enabled_tools: std::collections::HashSet<String>,
    tool_router: ToolRouter<Self>,
}

// ---------------------------------------------------------------------------
// Parameter types
// ---------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema)]
struct AddTorrentParams {
    /// A magnet URI (must start with 'magnet:'). Provide EXACTLY ONE of magnet_link, url, file_path, or file_content — not multiple.
    magnet_link: Option<String>,
    /// HTTP or HTTPS URL pointing to a remote .torrent file. Deluge fetches this asynchronously — the call may succeed before the download completes. Provide EXACTLY ONE of magnet_link, url, file_path, or file_content.
    url: Option<String>,
    /// Absolute path to a .torrent file on the Deluge server's filesystem. Provide EXACTLY ONE of magnet_link, url, file_path, or file_content.
    file_path: Option<String>,
    /// Base64-encoded contents of a .torrent file. Provide EXACTLY ONE of magnet_link, url, file_path, or file_content.
    file_content: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TorrentIdParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RemoveTorrentParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
    /// If true, permanently deletes all downloaded files from disk — this is irreversible. If false (default), removes the torrent from Deluge but leaves files on disk. Always confirm with the user before setting to true.
    #[serde(default)]
    delete_data: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SetOptionsParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
    /// Maximum download speed in KiB/s. Use -1 for unlimited (global default). Example: 10240 = 10 MiB/s. Only set fields you want to change.
    max_download_speed: Option<f64>,
    /// Maximum upload speed in KiB/s. Use -1 for unlimited. Example: 1024 = 1 MiB/s.
    max_upload_speed: Option<f64>,
    /// Maximum number of simultaneous peer connections. Use -1 for unlimited.
    max_connections: Option<i64>,
    /// Target upload/download ratio for seeding (e.g. 2.0 = upload twice what was downloaded). Use -1.0 for unlimited.
    ratio_limit: Option<f64>,
    /// If true, automatically removes the torrent when ratio_limit is reached. Only meaningful when ratio_limit is set.
    remove_at_ratio: Option<bool>,
    /// If true, moves downloaded files to move_completed_path when the download finishes.
    move_completed: Option<bool>,
    /// Absolute directory path on the Deluge server to move completed files to. Only used when move_completed is true.
    move_completed_path: Option<String>,
    /// If true, prioritizes downloading the first and last pieces first — useful for media files that need headers/footers to begin playback before fully downloaded.
    prioritize_first_last_pieces: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct MoveStorageParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
    /// Absolute destination directory path on the Deluge server. Deluge will attempt to create it if it does not exist. The Deluge process must have write access to this path.
    dest: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFolderParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
    /// Current folder name within the torrent's file structure (as shown in the torrent file list, not a filesystem path).
    folder: String,
    /// New folder name. Should not contain path separators.
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FileRename {
    /// Zero-based index of the file within the torrent. Obtain indices by calling get_torrent_status and reading the 'files' field, which lists all files with their indices in order.
    index: i64,
    /// New filename for this file. May include subdirectory path components (e.g. "subfolder/newname.mkv") to move the file within the torrent's folder structure.
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFilesParams {
    /// Info hash identifying the torrent: 40 hex characters (v1/SHA-1) or 64 hex characters (v2/SHA-256). Obtain from list_torrents or get_torrent_status.
    info_hash: String,
    /// List of file renames to apply. Each entry needs an index (from get_torrent_status 'files' field) and the new_name to assign.
    renames: Vec<FileRename>,
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
    #[tool]
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
                .map_err(|e| format!("Failed to read file: {e}"))?;
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
            .map(|v| format!("Torrent added. Hash: {}", Self::value_to_string(v)))
            .map_err(|e| e.to_string())
    }

    /// Remove a torrent from Deluge. Disabled by default; enable with --enable-tool=remove_torrent.
    /// If delete_data is true, all downloaded files are permanently deleted from disk — irreversible.
    /// If delete_data is false (default), files remain on disk and only the torrent entry is removed.
    /// Returns true on success. Returns an error if the info_hash is not found in Deluge.
    #[tool]
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
            .map(|_| {
                format!(
                    "Torrent {} removed{}.",
                    p.info_hash,
                    if p.delete_data { " (data deleted)" } else { "" }
                )
            })
            .map_err(|e| e.to_string())
    }

    /// List all torrents in Deluge with their current status.
    /// WORKFLOW: Use this first to discover torrents and obtain info_hash values required by all other tools.
    /// Returns a JSON object keyed by info_hash. Each value contains: name, state, progress (0–100),
    /// total_size (bytes), download_payload_rate (bytes/sec), upload_payload_rate (bytes/sec),
    /// eta (seconds to completion, -1 if not applicable), save_path.
    /// Possible state values: Allocating, Checking, Downloading, Seeding, Paused, Queued, Error, Moving.
    #[tool]
    async fn list_torrents(&self) -> Result<String, String> {
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
        self.client
            .call(
                "core.get_torrents_status",
                vec![Value::Dict(vec![]), keys],
                vec![],
            )
            .await
            .map(Self::value_to_json_string)
            .map_err(|e| e.to_string())
    }

    /// Get comprehensive status and metadata for a single torrent.
    /// Use this when you need file details (names, zero-based indices, per-file progress) required
    /// for rename_files, tracker information, piece details, or fields not in list_torrents.
    /// Returns a JSON object with all available torrent fields including a 'files' array.
    #[tool]
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
            .map_err(|e| e.to_string())
    }

    /// Pause a torrent, stopping all upload and download activity.
    /// The torrent remains in Deluge and can be resumed with resume_torrent.
    /// Safe to call on an already-paused torrent (idempotent). Returns nothing on success.
    #[tool]
    async fn pause_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call("core.pause_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| format!("Torrent {} paused.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Resume a previously paused torrent.
    /// If auto-management is enabled, the torrent may re-enter the queue rather than downloading immediately.
    /// Safe to call on a torrent that is not paused (no-op). Returns nothing on success.
    #[tool]
    async fn resume_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        Self::validate_info_hash(&p.info_hash)?;
        self.client
            .call("core.resume_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| format!("Torrent {} resumed.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Set per-torrent options such as speed limits, ratio targets, and completion behavior.
    /// Only include options you want to change — omitted fields are left unchanged.
    /// Speed values are in KiB/s (1024 KiB/s = 1 MiB/s); use -1 for unlimited (global default).
    /// Changes take effect immediately on the running torrent. Returns nothing on success.
    #[tool]
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
            .map(|_| format!("Options updated for torrent {}.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Move a torrent's data files to a new directory on the Deluge server. Disabled by default; enable with --enable-tool=move_storage.
    /// ASYNC: Returns immediately but the file move continues in the background.
    /// The torrent enters Moving state during the operation and returns to its previous state when complete.
    /// Use list_torrents or get_torrent_status to confirm the move has finished (state leaves Moving).
    #[tool]
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
            .map(|_| format!("Moving torrent {} to '{}'.", p.info_hash, p.dest))
            .map_err(|e| e.to_string())
    }

    /// Rename a top-level folder within a torrent's file structure. Disabled by default; enable with --enable-tool=rename_folder.
    /// ASYNC: The rename occurs asynchronously in Deluge.
    /// Best performed on paused torrents. The old folder may remain on disk as an orphan — Deluge
    /// renames the tracked path but does not always remove the original directory.
    /// If renaming causes file path mismatches, follow up with force_recheck to reconcile.
    #[tool]
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
            .map(|_| {
                format!(
                    "Renamed folder '{}' to '{}' in torrent {}.",
                    p.folder, p.new_name, p.info_hash
                )
            })
            .map_err(|e| e.to_string())
    }

    /// Rename one or more files within a torrent. Disabled by default; enable with --enable-tool=rename_files.
    /// ASYNC: The rename occurs asynchronously in Deluge.
    /// PREREQUISITE: Call get_torrent_status first to retrieve file indices from the 'files' field.
    /// File indices are zero-based and stable for the lifetime of the torrent in Deluge.
    #[tool]
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
            .map(|_| format!("Renamed {} file(s) in torrent {}.", p.renames.len(), p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Force a full hash recheck of a torrent's downloaded files against the torrent metadata. Disabled by default; enable with --enable-tool=force_recheck.
    /// Use after moving files outside Deluge, suspecting data corruption, or after a rename operation to reconcile file paths.
    /// ASYNC: The torrent enters Checking state immediately and returns to its previous state when done.
    /// If the torrent was Paused before the recheck, it automatically returns to Paused after checking completes.
    /// This operation is CPU and disk I/O intensive.
    #[tool]
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
            .map(|_| format!("Recheck started for torrent {}.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Get the available free disk space at a path on the Deluge server.
    /// Returns free space in bytes as an integer (divide by 1073741824 for GiB).
    /// Returns an error if the path is invalid or does not exist.
    /// Use before add_torrent or move_storage to verify sufficient space is available.
    #[tool]
    async fn get_free_space(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.client
            .call("core.get_free_space", vec![Value::String(p.path)], vec![])
            .await
            .map(|v| match v {
                Value::Int(bytes) => format!("{} bytes ({:.2} GiB) free", bytes, bytes as f64 / 1_073_741_824.0),
                other => Self::value_to_string(other),
            })
            .map_err(|e| e.to_string())
    }

    /// Get the total size of a file or directory on the Deluge server.
    /// Returns size in bytes as an integer, or -1 if the path is inaccessible (never raises an error).
    /// For directories, returns the recursive total size of all contents.
    /// Useful for verifying downloaded content size or checking the size of a directory before moving it.
    #[tool]
    async fn get_path_size(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.client
            .call("core.get_path_size", vec![Value::String(p.path)], vec![])
            .await
            .map(|v| match v {
                Value::Int(bytes) => format!("{} bytes ({:.2} GiB)", bytes, bytes as f64 / 1_073_741_824.0),
                other => Self::value_to_string(other),
            })
            .map_err(|e| e.to_string())
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
        Self {
            client,
            enabled_tools,
            tool_router: Self::tool_router(),
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
                "invalid info_hash '{hash}': must be 40 hex characters (v1) or 64 hex characters (v2)"
            ));
        }
        Ok(())
    }

    fn value_to_string(v: Value) -> String {
        serde_json::to_string_pretty(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }

    fn value_to_json_string(v: Value) -> String {
        serde_json::to_string_pretty(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// ServerHandler
// ---------------------------------------------------------------------------

#[tool_handler]
impl ServerHandler for DelugeServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default().with_server_info(Implementation::new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
        ))
    }
}
