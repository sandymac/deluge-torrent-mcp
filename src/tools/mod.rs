// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    Peer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    model::{
        CallToolRequestParams, CallToolResult, Icon, Implementation, InitializeRequestParams,
        InitializeResult, ListResourcesResult, ListResourceTemplatesResult, ListToolsResult,
        PaginatedRequestParams, RawResource, RawResourceTemplate, ReadResourceRequestParams,
        ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
        ResourceUpdatedNotificationParam, ServerInfo, SetLevelRequestParams,
        SubscribeRequestParams, Tool, UnsubscribeRequestParams,
    },
    serde_json,
    service::RequestContext,
    ErrorData, RoleServer,
};
use tokio::sync::{broadcast::error::RecvError, RwLock};
use tracing::{debug, warn};

const ICON_SVG: &[u8] = include_bytes!("../../assets/deluge-mcp-icon.svg");
const ICON_48: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-48x48.png");
const ICON_96: &[u8] = include_bytes!("../../assets/deluge-mcp-icon-96x96.png");

use crate::deluge::{DelugeApi, DelugeEvent};
use crate::rencode::Value;

mod errors;
pub(crate) mod gate;
mod handlers;
mod params;
mod plugin_watcher;
pub(crate) mod registry;
mod validate;
mod values;

use gate::ToolGate;
use params::*;
use plugin_watcher::{apply_label_state, event_to_resource_uris};

/// Flatten validated info hashes into the `Vec<String>` the [`DelugeApi`] bulk
/// methods accept.
fn hash_strings(hashes: Vec<InfoHash>) -> Vec<String> {
    hashes.into_iter().map(|h| h.0).collect()
}

/// Which bulk action `bulk_act_on_label` applies to a label's torrents.
#[derive(Clone, Copy)]
enum LabelAction {
    Pause,
    Resume,
}

impl LabelAction {
    fn past_tense(self) -> &'static str {
        match self {
            LabelAction::Pause => "paused",
            LabelAction::Resume => "resumed",
        }
    }
}

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct DelugeServer {
    api: DelugeApi,
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
// Constructor, plugin watcher, and self-methods
// ---------------------------------------------------------------------------

impl DelugeServer {
    pub(crate) fn new(
        api: DelugeApi,
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
        let mut event_rx = api.subscribe_events();
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
            api,
            gate,
            tool_router: Self::build_tool_router(),
            subscribers,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Spawn the plugin watcher. Listens for Deluge `PluginEnabled`/`PluginDisabled`
    /// events for the Label plugin and updates the [`ToolGate`] accordingly.
    /// On reconnect or broadcast lag it re-probes via `core.get_enabled_plugins`
    /// to recover the authoritative state.
    pub(crate) fn spawn_plugin_watcher(&self) {
        let api = self.api.clone();
        let gate = self.gate.clone();
        let connected_peers = self.connected_peers.clone();
        let mut event_rx = api.subscribe_events();

        tokio::spawn(async move {
            // Seed from an authoritative probe. The constructor's
            // `initial_label_plugin_active` may be stale (e.g. captured at
            // process start but the plugin toggled before this HTTP session
            // opened), and the broadcast receiver was created above — any
            // events that arrive between here and the loop will be buffered.
            if let Some(active) = api.label_plugin_active().await {
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
                        if let Some(active) = api.label_plugin_active().await {
                            apply_label_state(active, &gate, &connected_peers).await;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(
                            "Plugin watcher lagged by {n} events — re-probing plugin state"
                        );
                        if let Some(active) = api.label_plugin_active().await {
                            apply_label_state(active, &gate, &connected_peers).await;
                        }
                    }
                    Err(RecvError::Closed) => break,
                    _ => {}
                }
            }
        });
    }

    /// Auto-detect the source type and add a single torrent to Deluge.
    /// Detection order: magnet: → http/https URL → base64 .torrent → server file path.
    async fn add_single_torrent(&self, source: &str) -> Result<String, String> {
        let result = if source.starts_with("magnet:") {
            self.api.add_magnet(source).await
        } else if source.starts_with("http://") || source.starts_with("https://") {
            self.api.add_url(source).await
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
            self.api.add_file("upload.torrent", source).await
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
                .unwrap_or("file.torrent");
            self.api.add_file(filename, &encoded).await
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
    /// carrying the label via a server-side filter, errors if none, then applies
    /// the action to the whole set.
    async fn bulk_act_on_label(
        &self,
        label: &str,
        action: LabelAction,
    ) -> Result<String, String> {
        let filter = Value::Dict(vec![(
            Value::String("label".into()),
            Value::String(label.to_string()),
        )]);
        let keys = Value::List(vec![Value::String("label".into())]);
        let status = self
            .api
            .get_torrents_status(filter, keys)
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
        let result = match action {
            LabelAction::Pause => self.api.pause(hashes.clone()).await,
            LabelAction::Resume => self.api.resume(hashes.clone()).await,
        };
        result.map_err(Self::enrich_client_error)?;

        let out = serde_json::json!({
            "label": label,
            "action": action.past_tense(),
            "count": count,
            "info_hashes": hashes,
        });
        Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
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
            let result = self
                .api
                .get_torrents_status(Value::Dict(vec![]), keys)
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
                .api
                .get_torrent_status(hash, Value::List(vec![]))
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
        let registered: HashSet<String> = DelugeServer::build_tool_router()
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
}
