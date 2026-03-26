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
    /// Magnet link (magnet:?xt=...)
    magnet_link: Option<String>,
    /// URL to a remote .torrent file
    url: Option<String>,
    /// Absolute path to a .torrent file on the server
    file_path: Option<String>,
    /// Base64-encoded .torrent file content
    file_content: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TorrentIdParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RemoveTorrentParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
    /// Also delete downloaded data from disk
    #[serde(default)]
    delete_data: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SetOptionsParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
    /// Maximum download speed in KiB/s (-1 for unlimited)
    max_download_speed: Option<f64>,
    /// Maximum upload speed in KiB/s (-1 for unlimited)
    max_upload_speed: Option<f64>,
    /// Maximum number of connections (-1 for unlimited)
    max_connections: Option<i64>,
    /// Seed ratio limit (-1 for unlimited)
    ratio_limit: Option<f64>,
    /// Remove torrent when ratio limit is reached
    remove_at_ratio: Option<bool>,
    /// Move completed downloads to a different path
    move_completed: Option<bool>,
    /// Path to move completed downloads to
    move_completed_path: Option<String>,
    /// Prioritize first and last pieces
    prioritize_first_last_pieces: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct MoveStorageParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
    /// Destination path for the torrent data
    dest: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFolderParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
    /// Current folder name within the torrent
    folder: String,
    /// New folder name
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FileRename {
    /// File index within the torrent
    index: i64,
    /// New filename
    new_name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RenameFilesParams {
    /// Info hash of the torrent (40-character hex string)
    info_hash: String,
    /// List of file renames
    renames: Vec<FileRename>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PathParams {
    /// Filesystem path to query
    path: String,
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl DelugeServer {
    /// Add a torrent by magnet link, URL, or .torrent file.
    /// Provide exactly one of: magnet_link, url, file_path, or file_content.
    #[tool]
    async fn add_torrent(
        &self,
        Parameters(p): Parameters<AddTorrentParams>,
    ) -> Result<String, String> {
        let opts = Value::Dict(vec![]);

        let result = if let Some(uri) = p.magnet_link {
            self.client
                .call("core.add_torrent_magnet", vec![Value::String(uri), opts], vec![])
                .await
        } else if let Some(url) = p.url {
            self.client
                .call("core.add_torrent_url", vec![Value::String(url), opts], vec![])
                .await
        } else if let Some(path) = p.file_path {
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|e| format!("Failed to read file '{path}': {e}"))?;
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

    /// Remove a torrent. Disabled by default; enable with --enable=remove_torrent.
    #[tool]
    async fn remove_torrent(
        &self,
        Parameters(p): Parameters<RemoveTorrentParams>,
    ) -> Result<String, String> {
        self.tool_gate("remove_torrent")?;
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

    /// List all torrents with their current status.
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

    /// Get detailed status for a single torrent.
    #[tool]
    async fn get_torrent_status(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
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

    /// Pause a torrent.
    #[tool]
    async fn pause_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        self.client
            .call("core.pause_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| format!("Torrent {} paused.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Resume a paused torrent.
    #[tool]
    async fn resume_torrent(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        self.client
            .call("core.resume_torrent", vec![Value::String(p.info_hash.clone())], vec![])
            .await
            .map(|_| format!("Torrent {} resumed.", p.info_hash))
            .map_err(|e| e.to_string())
    }

    /// Set per-torrent options such as speed limits and ratio settings.
    #[tool]
    async fn set_torrent_options(
        &self,
        Parameters(p): Parameters<SetOptionsParams>,
    ) -> Result<String, String> {
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

    /// Move a torrent's storage to a new path. Disabled by default; enable with --enable=move_storage.
    #[tool]
    async fn move_storage(
        &self,
        Parameters(p): Parameters<MoveStorageParams>,
    ) -> Result<String, String> {
        self.tool_gate("move_storage")?;
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

    /// Rename a folder within a torrent. Disabled by default; enable with --enable=rename_folder.
    #[tool]
    async fn rename_folder(
        &self,
        Parameters(p): Parameters<RenameFolderParams>,
    ) -> Result<String, String> {
        self.tool_gate("rename_folder")?;
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

    /// Rename one or more files within a torrent. Disabled by default; enable with --enable=rename_files.
    #[tool]
    async fn rename_files(
        &self,
        Parameters(p): Parameters<RenameFilesParams>,
    ) -> Result<String, String> {
        self.tool_gate("rename_files")?;
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

    /// Force a hash recheck of a torrent's files. Disabled by default; enable with --enable=force_recheck.
    #[tool]
    async fn force_recheck(
        &self,
        Parameters(p): Parameters<TorrentIdParams>,
    ) -> Result<String, String> {
        self.tool_gate("force_recheck")?;
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

    /// Get free disk space for a given path on the Deluge server.
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

    /// Get the size of a path on the Deluge server.
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
                "Tool '{tool_name}' is disabled. Use --enable={tool_name} to enable it."
            ))
        }
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
