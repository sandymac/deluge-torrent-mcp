// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Helpers backing the live plugin/resource notification machinery.
//!
//! [`event_to_resource_uris`] maps a Deluge push event to the MCP resource URIs
//! that should be re-fetched; [`apply_label_state`] records a Label-plugin
//! toggle in the [`ToolGate`] and, when the visible tool set changes, fans out
//! `tools/list_changed` to every connected peer. The watcher task that drives
//! these lives in [`SharedState::spawn_plugin_watcher`](super::SharedState).

use std::sync::Arc;

use rmcp::{Peer, RoleServer};
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::gate::ToolGate;
use crate::deluge::DelugeEvent;

/// Map a Deluge push event to the resource URIs that should be notified.
pub(super) fn event_to_resource_uris(event: &DelugeEvent) -> Vec<String> {
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

/// Apply a new Label-plugin state to the [`ToolGate`]. If it actually changes
/// the visible tool set, fans out `tools/list_changed` to every connected peer.
/// Peers whose session has closed are pruned.
pub(super) async fn apply_label_state(
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

    // Fan out tools/list_changed from a snapshot, so no lock is held across awaits.
    let peers_snapshot: Vec<Peer<RoleServer>> = connected_peers.read().await.clone();
    for peer in &peers_snapshot {
        if let Err(e) = peer.notify_tool_list_changed().await {
            debug!("notify_tool_list_changed failed for a peer: {e}");
        }
    }

    // Prune by the peer's own state, never by position: sessions register and
    // prune concurrently, so indices from the snapshot cannot be trusted here.
    // A failed notify means the session's transport is closed.
    prune_closed_peers(&mut *connected_peers.write().await);
}

/// Drop peers whose session transport has closed.
pub(super) fn prune_closed_peers(peers: &mut Vec<Peer<RoleServer>>) {
    peers.retain(|p| !p.is_transport_closed());
}
