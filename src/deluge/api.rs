// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Typed domain wrapper over the raw [`DelugeClient`] RPC channel.
//!
//! Every Deluge RPC method name and positional-argument layout lives here, in
//! one method per call. The MCP tool layer talks to Deluge exclusively through
//! these methods, so it never builds a raw `(method, args)` pair itself — that
//! keeps the wire shapes in a single auditable place and stops a typo in a
//! method name or a misordered argument from reaching the daemon.
//!
//! Methods return the raw [`Value`] from the daemon; response shaping and
//! LLM-facing error enrichment remain the tool layer's responsibility.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::broadcast;
use tracing::warn;

use super::{DelugeClient, DelugeEvent};
use crate::rencode::Value;

/// Cheap-to-clone handle exposing Deluge's RPC surface as typed methods.
#[derive(Clone)]
pub(crate) struct DelugeApi {
    client: Arc<DelugeClient>,
}

/// Build the positional `Value::List` of info-hash strings that Deluge's bulk
/// torrent methods expect.
fn hash_list(hashes: Vec<String>) -> Value {
    Value::List(hashes.into_iter().map(Value::String).collect())
}

/// Empty options dict accepted by the `add_torrent_*` methods.
fn empty_opts() -> Value {
    Value::Dict(vec![])
}

impl DelugeApi {
    pub(crate) fn new(client: Arc<DelugeClient>) -> Self {
        Self { client }
    }

    /// Subscribe to Deluge push events (torrent lifecycle, plugin toggles,
    /// reconnects). See [`DelugeClient::subscribe_events`].
    pub(crate) fn subscribe_events(&self) -> broadcast::Receiver<DelugeEvent> {
        self.client.subscribe_events()
    }

    // -- Adding torrents --

    pub(crate) async fn add_magnet(&self, uri: &str) -> Result<Value> {
        self.client
            .call(
                "core.add_torrent_magnet",
                vec![Value::String(uri.to_string()), empty_opts()],
                vec![],
            )
            .await
    }

    pub(crate) async fn add_url(&self, url: &str) -> Result<Value> {
        self.client
            .call(
                "core.add_torrent_url",
                vec![Value::String(url.to_string()), empty_opts()],
                vec![],
            )
            .await
    }

    pub(crate) async fn add_file(&self, filename: &str, content_base64: &str) -> Result<Value> {
        self.client
            .call(
                "core.add_torrent_file",
                vec![
                    Value::String(filename.to_string()),
                    Value::String(content_base64.to_string()),
                    empty_opts(),
                ],
                vec![],
            )
            .await
    }

    // -- Torrent lifecycle --

    pub(crate) async fn remove_torrent(&self, hash: &str, delete_data: bool) -> Result<Value> {
        self.client
            .call(
                "core.remove_torrent",
                vec![Value::String(hash.to_string()), Value::Bool(delete_data)],
                vec![],
            )
            .await
    }

    pub(crate) async fn pause(&self, hashes: Vec<String>) -> Result<Value> {
        self.client
            .call("core.pause_torrents", vec![hash_list(hashes)], vec![])
            .await
    }

    pub(crate) async fn resume(&self, hashes: Vec<String>) -> Result<Value> {
        self.client
            .call("core.resume_torrents", vec![hash_list(hashes)], vec![])
            .await
    }

    pub(crate) async fn force_recheck(&self, hashes: Vec<String>) -> Result<Value> {
        self.client
            .call("core.force_recheck", vec![hash_list(hashes)], vec![])
            .await
    }

    pub(crate) async fn set_torrent_options(
        &self,
        hashes: Vec<String>,
        options: Vec<(Value, Value)>,
    ) -> Result<Value> {
        self.client
            .call(
                "core.set_torrent_options",
                vec![hash_list(hashes), Value::Dict(options)],
                vec![],
            )
            .await
    }

    // -- Storage and renaming --

    pub(crate) async fn move_storage(&self, hashes: Vec<String>, dest: &str) -> Result<Value> {
        self.client
            .call(
                "core.move_storage",
                vec![hash_list(hashes), Value::String(dest.to_string())],
                vec![],
            )
            .await
    }

    pub(crate) async fn rename_folder(
        &self,
        hash: &str,
        folder: &str,
        new_name: &str,
    ) -> Result<Value> {
        self.client
            .call(
                "core.rename_folder",
                vec![
                    Value::String(hash.to_string()),
                    Value::String(folder.to_string()),
                    Value::String(new_name.to_string()),
                ],
                vec![],
            )
            .await
    }

    pub(crate) async fn rename_files(
        &self,
        hash: &str,
        renames: Vec<(i64, String)>,
    ) -> Result<Value> {
        let renames = Value::List(
            renames
                .into_iter()
                .map(|(index, name)| Value::List(vec![Value::Int(index), Value::String(name)]))
                .collect(),
        );
        self.client
            .call(
                "core.rename_files",
                vec![Value::String(hash.to_string()), renames],
                vec![],
            )
            .await
    }

    // -- Status queries --

    /// Fetch status for the torrents matching `filter`, returning only `keys`.
    pub(crate) async fn get_torrents_status(&self, filter: Value, keys: Value) -> Result<Value> {
        self.client
            .call("core.get_torrents_status", vec![filter, keys], vec![])
            .await
    }

    /// Fetch status for a single torrent, returning only `keys` (empty list = all).
    pub(crate) async fn get_torrent_status(&self, hash: &str, keys: Value) -> Result<Value> {
        self.client
            .call(
                "core.get_torrent_status",
                vec![Value::String(hash.to_string()), keys],
                vec![],
            )
            .await
    }

    // -- Server queries --

    pub(crate) async fn get_free_space(&self, path: &str) -> Result<Value> {
        self.client
            .call("core.get_free_space", vec![Value::String(path.to_string())], vec![])
            .await
    }

    pub(crate) async fn get_path_size(&self, path: &str) -> Result<Value> {
        self.client
            .call("core.get_path_size", vec![Value::String(path.to_string())], vec![])
            .await
    }

    pub(crate) async fn daemon_info(&self) -> Result<Value> {
        self.client.call("daemon.info", vec![], vec![]).await
    }

    pub(crate) async fn session_status(&self, keys: Value) -> Result<Value> {
        self.client
            .call("core.get_session_status", vec![keys], vec![])
            .await
    }

    /// Whether the Label plugin is currently enabled on the daemon.
    /// Returns `None` on RPC failure (caller should keep the previous state).
    pub(crate) async fn label_plugin_active(&self) -> Option<bool> {
        match self.client.call("core.get_enabled_plugins", vec![], vec![]).await {
            Ok(Value::List(items)) => {
                Some(items.iter().any(|v| matches!(v, Value::String(s) if s == "Label")))
            }
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

    // -- Label plugin --

    pub(crate) async fn label_add(&self, label: &str) -> Result<Value> {
        self.client
            .call("label.add", vec![Value::String(label.to_string())], vec![])
            .await
    }

    pub(crate) async fn label_remove(&self, label: &str) -> Result<Value> {
        self.client
            .call("label.remove", vec![Value::String(label.to_string())], vec![])
            .await
    }

    pub(crate) async fn label_set_torrent(&self, hash: &str, label: &str) -> Result<Value> {
        self.client
            .call(
                "label.set_torrent",
                vec![Value::String(hash.to_string()), Value::String(label.to_string())],
                vec![],
            )
            .await
    }

    pub(crate) async fn label_get_labels(&self) -> Result<Value> {
        self.client.call("label.get_labels", vec![], vec![]).await
    }

    pub(crate) async fn label_get_options(&self, label: &str) -> Result<Value> {
        self.client
            .call("label.get_options", vec![Value::String(label.to_string())], vec![])
            .await
    }

    pub(crate) async fn label_set_options(
        &self,
        label: &str,
        options: Vec<(Value, Value)>,
    ) -> Result<Value> {
        self.client
            .call(
                "label.set_options",
                vec![Value::String(label.to_string()), Value::Dict(options)],
                vec![],
            )
            .await
    }
}
