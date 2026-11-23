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
use tracing::{debug, info, warn};

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

    // Fan out tools/list_changed from a snapshot (no lock held across awaits), off the
    // watcher loop and concurrently, each send bounded by NOTIFY_TIMEOUT. rmcp's send
    // waits for room in the session's outbound channel, so one client that stops
    // reading its SSE stream would otherwise stall every other peer and the watcher
    // itself — which is process-wide, so later toggles would never reach the gate.
    let peers_snapshot: Vec<Peer<RoleServer>> = connected_peers.read().await.clone();
    let connected_peers = connected_peers.clone();
    tokio::spawn(async move {
        let mut sends = tokio::task::JoinSet::new();
        for peer in peers_snapshot {
            sends.spawn(async move {
                match tokio::time::timeout(NOTIFY_TIMEOUT, peer.notify_tool_list_changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => debug!("notify_tool_list_changed failed for a peer: {e}"),
                    Err(_) => warn!("notify_tool_list_changed timed out for a peer; skipping it"),
                }
            });
        }
        while sends.join_next().await.is_some() {}

        // Prune by the peer's own state, never by position: sessions register and
        // prune concurrently, so indices from the snapshot cannot be trusted here.
        prune_closed_peers(&mut *connected_peers.write().await);
    });
}

/// Upper bound on one server→client notification send. A peer that cannot accept
/// a notification within this window is skipped for that notification.
pub(super) const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Drop peers whose session transport has closed.
pub(super) fn prune_closed_peers(peers: &mut Vec<Peer<RoleServer>>) {
    peers.retain(|p| !p.is_transport_closed());
}
