// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    Peer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::tool::ToolCallContext,
    model::{
        CallToolRequestParams, CallToolResponse, Icon, Implementation, InitializeRequestParams,
        InitializeResult, ListResourcesResult, ListResourceTemplatesResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
        ResourceUpdatedNotificationParam, ServerConfig, SubscribeRequestParams, Tool,
        UnsubscribeRequestParams,
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
use crate::response_config::{shape_response, ResponseConfig};

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

/// Largest total of `torrent_sources` `add_torrent` accepts in one call (32 MiB) — a
/// single base64 `.torrent` or several summed. Enforced per call, not per source, so
/// that everything the tool accepts also fits in one transport message.
pub(crate) const MAX_BASE64_TORRENT_BYTES: usize = 32 * 1024 * 1024;

/// Largest single MCP message either transport accepts: a maximal `add_torrent` call
/// plus 1 MiB headroom for the JSON-RPC envelope and JSON string escaping. Applied as
/// rmcp's HTTP `max_request_body_bytes` (default 4 MiB) and stdio `max_line_length`
/// (default 16 MiB) so neither transport rejects an input `add_torrent` would accept,
/// while still bounding memory per message. Oversized messages get HTTP 413; on stdio
/// rmcp drops the line and logs to stderr without a JSON-RPC error.
pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = MAX_BASE64_TORRENT_BYTES + 1024 * 1024;
const _: () = assert!(MAX_MCP_MESSAGE_BYTES > MAX_BASE64_TORRENT_BYTES);

/// Protocol versions this server negotiates — everything up to and including the last
/// revision with an `initialize` handshake. See `ServerHandler::supported_protocol_versions`
/// on [`DelugeServer`] and ADR-0014.
fn supported_protocol_versions() -> &'static [ProtocolVersion] {
    ProtocolVersion::known_up_to(&ProtocolVersion::LATEST_WITH_INITIALIZE)
}

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
    /// Response shaping config used when a request carries none. On STDIO this is the
    /// process-wide config from `--response-config`; on HTTP it is the fallback when a request's
    /// per-request config is absent. See [`Self::resolve_config`].
    default_config: ResponseConfig,
    /// Set once this server's session background tasks (resource-event forwarder and
    /// plugin watcher) have been spawned. They start from `initialize`, not construction:
    /// rmcp 3 also runs the HTTP session factory for stateless requests (inline `_meta`,
    /// `server/discover`) that never initialize, and spawning there leaked two tasks per
    /// request. See [`Self::start_session_tasks`].
    session_tasks_started: Arc<AtomicBool>,
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
        default_config: ResponseConfig,
    ) -> Self {
        let gate = Arc::new(ToolGate::new(
            user_intent_tools,
            plugin_gated_tools,
            initial_label_plugin_active,
        ));

        let subscribers: Arc<RwLock<HashMap<String, Peer<RoleServer>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        Self {
            api,
            gate,
            tool_router: Self::build_tool_router(),
            subscribers,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            default_config,
            session_tasks_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawn this session's background tasks — at most once per server instance.
    ///
    /// Called from `initialize`, so only real sessions (stdio, or an HTTP session that
    /// completed the handshake) get them. Each task exits after the next Deluge event
    /// once `peer`'s transport has closed, so ended sessions stop accumulating tasks.
    fn start_session_tasks(&self, peer: &Peer<RoleServer>) {
        if self.session_tasks_started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.spawn_event_forwarder(peer.clone());
        self.spawn_plugin_watcher(peer.clone());
    }

    /// Forward Deluge push events to this session's resource subscribers as
    /// `notifications/resources/updated`.
    fn spawn_event_forwarder(&self, session_peer: Peer<RoleServer>) {
        let mut event_rx = self.api.subscribe_events();
        let subs_for_task = self.subscribers.clone();
        tokio::spawn(async move {
            loop {
                let received = event_rx.recv().await;
                if session_peer.is_transport_closed() {
                    debug!("Session closed — stopping resource event forwarder");
                    break;
                }
                match received {
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
    }

    /// Resolve the [`ResponseConfig`] for the current call.
    ///
    /// On HTTP the per-request config is parsed by middleware and travels in the rmcp-injected
    /// [`http::request::Parts`](axum::http::request::Parts) extensions; read it from there. On
    /// STDIO (no `Parts`) and as the HTTP fallback, use the server's [`Self::default_config`].
    pub(crate) fn resolve_config(&self, ctx: &RequestContext<RoleServer>) -> ResponseConfig {
        config_from_extensions(&ctx.extensions, &self.default_config)
    }

    /// Shape a tool's JSON output for the current call's consumer. Convenience wrapper over
    /// [`Self::resolve_config`] + [`shape_response`].
    pub(crate) fn shape(
        &self,
        value: serde_json::Value,
        ctx: &RequestContext<RoleServer>,
    ) -> String {
        shape_response(value, &self.resolve_config(ctx))
    }

    /// Spawn the plugin watcher. Listens for Deluge `PluginEnabled`/`PluginDisabled`
    /// events for the Label plugin and updates the [`ToolGate`] accordingly.
    /// On reconnect or broadcast lag it re-probes via `core.get_enabled_plugins`
    /// to recover the authoritative state.
    fn spawn_plugin_watcher(&self, session_peer: Peer<RoleServer>) {
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
                let received = event_rx.recv().await;
                if session_peer.is_transport_closed() {
                    debug!("Session closed — stopping plugin watcher");
                    break;
                }
                match received {
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
    /// Detection order: magnet: → http/https URL → base64 .torrent content.
    async fn add_single_torrent(&self, source: &str) -> Result<String, String> {
        let result = if source.starts_with("magnet:") {
            self.api.add_magnet(source).await
        } else if source.starts_with("http://") || source.starts_with("https://") {
            self.api.add_url(source).await
        } else {
            // Otherwise the source must be base64-encoded .torrent file content,
            // which Deluge decodes via add_torrent_file. Deluge has no RPC that
            // reads a server-side path, so a path is not an accepted source.
            // Size guard BEFORE base64 decode to prevent oversized allocation.
            if source.len() > MAX_BASE64_TORRENT_BYTES {
                return Err(format!(
                    "base64 content is {} bytes, exceeding the 32 MB limit. \
                     .torrent files are typically under 1 MB — this input is likely incorrect.",
                    source.len()
                ));
            }
            if Self::is_base64_torrent(source) {
                self.api.add_file("upload.torrent", source).await
            } else {
                return Err(
                    "Unrecognized torrent source format. Each source must be one of: \
                     a magnet: URI, an http/https URL, or base64-encoded .torrent file content.\n\
                     [Hint: Do not fabricate .torrent file content. Use a magnet link or URL. \
                     To add a .torrent file, read its bytes and pass them base64-encoded.]"
                        .to_string(),
                );
            }
        };

        result
            .map(|v| match v {
                Value::String(s) => s,
                other => Self::value_to_json_string(other),
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
        ctx: &RequestContext<RoleServer>,
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
        Ok(self.shape(out, ctx))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler
// ---------------------------------------------------------------------------

impl ServerHandler for DelugeServer {
    fn get_info(&self) -> ServerConfig {
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
        // `enable_logging` is deprecated by SEP-2577 (2026-07-28), but this server caps
        // negotiation at 2025-11-25 (see `supported_protocol_versions`), where clients may
        // still send `logging/setLevel`.
        #[allow(deprecated)]
        let capabilities = rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_logging()
                .build();
        ServerConfig::new(capabilities)
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
            context.peer.set_peer_info(request.clone());
        }
        // Negotiate first: a refused version gets no peer tracking or background tasks.
        let result = self.negotiate_initialize(&request)?;
        // Track this peer so the plugin watcher can deliver tools/list_changed.
        self.connected_peers.write().await.push(context.peer.clone());
        self.start_session_tasks(&context.peer);
        Ok(result)
    }

    /// Cap negotiation at 2025-11-25, the last revision with an `initialize` handshake.
    ///
    /// 2026-07-28 clients are served statelessly via `server/discover` and never call
    /// `initialize`, so peer tracking (`connected_peers` → `tools/list_changed`), resource
    /// subscriptions, and the per-session plugin watcher would silently stop working for
    /// them. Raise this ceiling only after those move onto SEP-2575 listen streams.
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(supported_protocol_versions())
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
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.tool_router.call(ToolCallContext::new(self, request, context)).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }

    // Logging is deprecated by SEP-2577, but still part of the protocol versions we negotiate.
    #[allow(deprecated)]
    async fn set_level(
        &self,
        _request: rmcp::model::SetLevelRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        Ok(())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new("deluge://torrents", "All Torrents")
                .with_title("All Torrents")
                .with_description(
                    "Snapshot of all torrents with current status, as \
                     {\"torrents\": {<info_hash>: {fields}}}. \
                     Subscribe for live updates when torrents are added, removed, \
                     or change state.",
                )
                .with_mime_type("application/json"),
        ]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("deluge://torrent/{info_hash}", "Torrent Status")
                .with_title("Torrent Status")
                .with_description(
                    "Complete status and metadata for a single torrent. \
                     Subscribe for live updates on state changes, file renames, \
                     and storage moves.",
                )
                .with_mime_type("application/json"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
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

            // Wrap in the {"torrents": {<hash>: {...}}} envelope so this resource shapes
            // identically to list_torrents — in particular so `defaults` (which targets that
            // envelope) elides default-valued fields here too, the biggest payload in the
            // system. Resource reads honor the same per-request (HTTP) / --response-config
            // (STDIO) shaping as tool outputs.
            let wrapped = serde_json::json!({ "torrents": crate::rencode::value_to_json(result) });
            let text = self.shape(wrapped, &context);
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: uri.clone(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ])
            .into())
        } else if let Some(hash) = uri.strip_prefix("deluge://torrent/") {
            if let Err(e) = Self::validate_info_hash(hash) {
                return Err(ErrorData::invalid_params(e, None));
            }
            let result = self
                .api
                .get_torrent_status(hash, Value::List(vec![]))
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

            let text = self.shape(crate::rencode::value_to_json(result), &context);
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: uri.clone(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ])
            .into())
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

/// Pure core of [`DelugeServer::resolve_config`]: read a per-request [`ResponseConfig`] from the
/// rmcp-injected [`Parts`](axum::http::request::Parts) extensions (HTTP), falling back to
/// `default` (STDIO, or HTTP with no per-request config). Free function so it is unit-testable
/// without constructing a [`DelugeServer`].
fn config_from_extensions(
    ext: &rmcp::model::Extensions,
    default: &ResponseConfig,
) -> ResponseConfig {
    ext.get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ResponseConfig>().cloned())
        .unwrap_or_else(|| default.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STDIO / no-Parts: `resolve_config` returns the server default unchanged.
    #[test]
    fn config_from_empty_extensions_is_default() {
        let ext = rmcp::model::Extensions::default();
        let default = ResponseConfig::default();
        assert_eq!(config_from_extensions(&ext, &default), default);
    }

    /// HTTP: a per-request config in the injected `Parts` extensions wins over the default.
    #[test]
    fn config_from_parts_extension_wins() {
        use crate::response_config::{Format, IdSelector, ShapeOpts, Whitespace};
        let per_request = ResponseConfig {
            format: Format::Json,
            shape: ShapeOpts {
                whitespace: Whitespace::Minified,
                omit_defaults: true,
            },
            ids: IdSelector::Full,
        };
        // Synthesize the rmcp-injected http::request::Parts carrying the per-request config.
        let mut parts = axum::http::Request::builder()
            .uri("/mcp/json?shape=minified,defaults")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.extensions.insert(per_request.clone());

        let mut ext = rmcp::model::Extensions::default();
        ext.insert(parts);

        let default = ResponseConfig::default();
        assert_eq!(config_from_extensions(&ext, &default), per_request);
        assert_ne!(per_request, default);
    }

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

    #[test]
    fn protocol_negotiation_is_capped_at_last_initialize_revision() {
        let versions = super::supported_protocol_versions();
        assert!(versions.contains(&ProtocolVersion::V_2025_11_25));
        assert!(versions.contains(&ProtocolVersion::V_2024_11_05));
        // 2026-07-28 drops `initialize` and sessions, which peer tracking, resource
        // subscriptions and the plugin watcher depend on. See ADR-0014.
        assert!(!versions.contains(&ProtocolVersion::V_2026_07_28));
    }
}
