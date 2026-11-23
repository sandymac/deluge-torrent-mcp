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
use tokio::sync::{Notify, RwLock};
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
/// the visible tool set, wakes the `tools/list_changed` fan-out (see
/// [`spawn_tool_list_fanout`]). Never awaits a client.
pub(super) fn apply_label_state(active: bool, gate: &Arc<ToolGate>, fanout: &Notify) {
    if !gate.set_label_plugin_active(active) {
        return;
    }

    info!(
        "Label plugin is now {} on the Deluge daemon — tool list updated",
        if active { "enabled" } else { "disabled" }
    );
    fanout.notify_one();
}

/// Spawn the process-wide `tools/list_changed` fan-out task and return its waker.
///
/// One persistent task, not one per toggle: [`Notify`] holds at most one permit, so
/// toggles that arrive while a fan-out is running coalesce into a single follow-up run
/// (the notification carries no payload; clients re-fetch `tools/list`, which already
/// reflects the gate). Each run notifies a snapshot of peers concurrently, each send
/// bounded by [`NOTIFY_TIMEOUT`], so a client that stops reading its SSE stream cannot
/// stall the others. A timed-out send stays queued inside rmcp and is not cancelled, so
/// coalescing also bounds how many can pile up for a wedged peer: one per run.
pub(super) fn spawn_tool_list_fanout(
    connected_peers: Arc<RwLock<Vec<Peer<RoleServer>>>>,
) -> Arc<Notify> {
    let wake = Arc::new(Notify::new());
    let wake_task = wake.clone();
    tokio::spawn(async move {
        loop {
            wake_task.notified().await;
            // Snapshot so no lock is held across awaits.
            let peers_snapshot: Vec<Peer<RoleServer>> = connected_peers.read().await.clone();
            let mut sends = tokio::task::JoinSet::new();
            for peer in peers_snapshot {
                sends.spawn(async move {
                    match tokio::time::timeout(NOTIFY_TIMEOUT, peer.notify_tool_list_changed())
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => debug!("notify_tool_list_changed failed for a peer: {e}"),
                        Err(_) => warn!("notify_tool_list_changed timed out for a peer"),
                    }
                });
            }
            while sends.join_next().await.is_some() {}

            // Prune by the peer's own state, never by position: sessions register and
            // prune concurrently, so indices from the snapshot cannot be trusted here.
            prune_closed_peers(&mut *connected_peers.write().await);
        }
    });
    wake
}

/// Upper bound on one server→client notification send. A peer that cannot accept
/// a notification within this window is skipped for that notification.
pub(super) const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Drop peers whose session transport has closed.
pub(super) fn prune_closed_peers(peers: &mut Vec<Peer<RoleServer>>) {
    peers.retain(|p| !p.is_transport_closed());
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::apply_label_state;
    use crate::tools::gate::ToolGate;

    fn gate() -> Arc<ToolGate> {
        let tool = "deluge_list_labels".to_string();
        Arc::new(ToolGate::new(
            HashSet::from([tool.clone()]),
            HashSet::from([tool]),
            false,
        ))
    }

    async fn woken(fanout: &Notify) -> bool {
        tokio::time::timeout(Duration::from_millis(50), fanout.notified()).await.is_ok()
    }

    #[tokio::test]
    async fn wakes_fanout_only_when_visibility_changes() {
        let (gate, fanout) = (gate(), Notify::new());
        apply_label_state(false, &gate, &fanout); // unchanged
        assert!(!woken(&fanout).await);
        apply_label_state(true, &gate, &fanout); // changed
        assert!(woken(&fanout).await);
    }

    #[tokio::test]
    async fn rapid_toggles_coalesce_into_one_wake() {
        let (gate, fanout) = (gate(), Notify::new());
        for active in [true, false, true, false, true] {
            apply_label_state(active, &gate, &fanout);
        }
        assert!(woken(&fanout).await);
        assert!(!woken(&fanout).await, "Notify should hold at most one permit");
    }
}
