// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Deluge push-event model and wire decoder.
//!
//! The daemon delivers RPC_EVENT frames as `(event_name, positional_args)`.
//! [`parse_event`] turns those into the typed [`DelugeEvent`] the rest of the
//! crate matches on.

use crate::rencode::Value;

/// A push event received from the Deluge daemon via the RPC_EVENT wire message,
/// plus synthetic local events the client emits for connection lifecycle.
///
/// Several variants carry payload fields (`state`, `path`, `index`, …) that no
/// control-flow path reads today — they are decoded for fidelity and surfaced
/// through the `Debug` impl in the client's event log. `#[allow(dead_code)]`
/// keeps that faithful wire model without per-field noise.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum DelugeEvent {
    TorrentAdded { info_hash: String, from_state: bool },
    TorrentRemoved { info_hash: String },
    TorrentStateChanged { info_hash: String, state: String },
    TorrentFinished { info_hash: String },
    TorrentResumed { info_hash: String },
    TorrentStorageMoved { info_hash: String, path: String },
    TorrentFileRenamed { info_hash: String, index: i64, name: String },
    TorrentFolderRenamed { info_hash: String, old_name: String, new_name: String },
    PluginEnabled { name: String },
    PluginDisabled { name: String },
    /// Synthetic event fired locally after a (re)connect + event-interest registration.
    /// Listeners that track server-side state (e.g. plugin enablement) should re-seed.
    Reconnected,
    Unknown { name: String },
}

/// Decode a Deluge push event by name and positional args list into a typed [`DelugeEvent`].
pub(super) fn parse_event(name: &str, args: &[Value]) -> DelugeEvent {
    let str_arg = |i: usize| -> String {
        match args.get(i) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    };
    let bool_arg = |i: usize| -> bool {
        match args.get(i) {
            Some(Value::Int(n)) => *n != 0,
            Some(Value::Bool(b)) => *b,
            _ => false,
        }
    };
    let int_arg = |i: usize| -> i64 {
        match args.get(i) {
            Some(Value::Int(n)) => *n,
            _ => 0,
        }
    };

    match name {
        "TorrentAddedEvent" => DelugeEvent::TorrentAdded {
            info_hash: str_arg(0),
            from_state: bool_arg(1),
        },
        "TorrentRemovedEvent" => DelugeEvent::TorrentRemoved { info_hash: str_arg(0) },
        "TorrentStateChangedEvent" => DelugeEvent::TorrentStateChanged {
            info_hash: str_arg(0),
            state: str_arg(1),
        },
        "TorrentFinishedEvent" => DelugeEvent::TorrentFinished { info_hash: str_arg(0) },
        "TorrentResumedEvent" => DelugeEvent::TorrentResumed { info_hash: str_arg(0) },
        "TorrentStorageMovedEvent" => DelugeEvent::TorrentStorageMoved {
            info_hash: str_arg(0),
            path: str_arg(1),
        },
        "TorrentFileRenamedEvent" => DelugeEvent::TorrentFileRenamed {
            info_hash: str_arg(0),
            index: int_arg(1),
            name: str_arg(2),
        },
        "TorrentFolderRenamedEvent" => DelugeEvent::TorrentFolderRenamed {
            info_hash: str_arg(0),
            old_name: str_arg(1),
            new_name: str_arg(2),
        },
        "PluginEnabledEvent" => DelugeEvent::PluginEnabled { name: str_arg(0) },
        "PluginDisabledEvent" => DelugeEvent::PluginDisabled { name: str_arg(0) },
        _ => DelugeEvent::Unknown { name: name.to_string() },
    }
}
