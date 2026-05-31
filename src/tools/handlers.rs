// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! The 21 MCP tool implementations.
//!
//! Each `#[tool]` method validates its [`params`](super::params), passes the
//! request to the [`DelugeApi`](crate::deluge::DelugeApi) via `self.api`, and
//! shapes the response. Cross-cutting concerns live elsewhere: visibility
//! gating in [`gate`](super::gate), wire calls in the API layer, and the
//! stateless validation/extraction/error helpers on [`DelugeServer`](super).

use std::collections::HashSet;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{serde_json, tool, tool_router};

use super::params::*;
use super::{hash_strings, DelugeServer, LabelAction};
use crate::rencode::Value;

impl DelugeServer {
    /// Build the tool router. Wraps the private `tool_router()` the
    /// `#[tool_router]` macro generates in this module so the constructor in
    /// [`super`] can reach it.
    pub(super) fn build_tool_router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        Self::tool_router()
    }
}

#[tool_router]
impl DelugeServer {
    /// Add one or more torrents to Deluge. Each source is auto-detected: magnet: URI, http/https URL,
    /// or base64-encoded .torrent file content. To add a .torrent that exists as a file, read its
    /// bytes and pass them base64-encoded.
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
            let result = self.api.remove_torrent(&hash.0, p.delete_data).await;
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

        let result = self
            .api
            .get_torrents_status(filter, keys)
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
                .api
                .get_torrent_status(&hash.0, Value::List(vec![]))
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
        self.api
            .get_torrents_status(filter, Value::List(vec![]))
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
        self.api
            .pause(hash_strings(p.info_hashes))
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
        self.api
            .resume(hash_strings(p.info_hashes))
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
        self.api
            .set_torrent_options(hash_strings(p.info_hashes), opts)
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
        self.api
            .move_storage(hash_strings(p.info_hashes), &p.dest)
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
        self.api
            .rename_folder(&hash.0, &folder, &p.new_name)
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
        let renames = p
            .renames
            .into_iter()
            .map(|r| (r.index as i64, r.new_name))
            .collect();
        self.api
            .rename_files(&hash.0, renames)
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
        self.api
            .force_recheck(hash_strings(p.info_hashes))
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_client_error)
    }

    /// Get free disk space at a path on the Deluge server. Returns bytes, or error if path is invalid.
    #[tool(name = "deluge_get_free_space", title = "Get Free Space", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_free_space(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.api
            .get_free_space(&p.path)
            .await
            .map(|v| match v {
                Value::Int(bytes) => bytes.to_string(),
                other => Self::value_to_json_string(other),
            })
            .map_err(Self::enrich_client_error)
    }

    /// Get the total size of a file or directory on the Deluge server. Returns bytes, or -1 if inaccessible.
    #[tool(name = "deluge_get_path_size", title = "Get Path Size", annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_path_size(&self, Parameters(p): Parameters<PathParams>) -> Result<String, String> {
        self.api
            .get_path_size(&p.path)
            .await
            .map(|v| match v {
                Value::Int(bytes) => bytes.to_string(),
                other => Self::value_to_json_string(other),
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
        self.api
            .label_add(&label)
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
        self.api
            .label_remove(&label)
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
            let result = self.api.label_set_torrent(&hash.0, &label).await;
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
        self.bulk_act_on_label(&label, LabelAction::Pause).await
    }

    /// Resume every paused torrent assigned the given label. Errors if no torrents currently have this label.
    #[tool(name = "deluge_resume_label", title = "Resume Label", annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn resume_label(
        &self,
        Parameters(p): Parameters<LabelNameParams>,
    ) -> Result<String, String> {
        self.gate.check("deluge_resume_label")?;
        let label = Self::validate_label_name(&p.label)?;
        self.bulk_act_on_label(&label, LabelAction::Resume).await
    }

    /// List all labels defined on the Deluge daemon. Returns a JSON array of label names.
    #[tool(name = "deluge_list_labels", title = "List Labels", annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_labels(&self) -> Result<String, String> {
        self.gate.check("deluge_list_labels")?;
        let result = self
            .api
            .label_get_labels()
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
            .api
            .label_get_options(&label)
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

        self.api
            .label_set_options(&label, opts)
            .await
            .map(|_| "ok".to_string())
            .map_err(Self::enrich_label_error)
    }
}
