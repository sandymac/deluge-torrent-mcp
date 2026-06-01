// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Single source of truth for the MCP tools this server exposes and their
//! gating policy.
//!
//! Tool *behaviour* lives with each `#[tool]` method in [`super`]; this table
//! records only the two policy bits that cannot be expressed on the macro:
//! whether a tool is disabled until an operator opts in, and whether it depends
//! on a Deluge plugin. `main` derives its CLI handling, startup logging, and
//! `--list-tools` output from here, and a test pins this list against the names
//! actually registered on the [`ToolRouter`](rmcp::handler::server::router::tool::ToolRouter)
//! so the two can never silently drift.

/// Policy description for one MCP tool.
pub(crate) struct ToolSpec {
    /// Tool name, exactly as registered via `#[tool(name = "...")]`.
    pub(crate) name: &'static str,
    /// Disabled unless an operator opts in with `--enable-tool`. These tools
    /// modify the filesystem or delete data, so they must not be on by default.
    pub(crate) default_disabled: bool,
    /// Requires the Deluge Label plugin to be active on the daemon. Hidden from
    /// `tools/list` whenever the plugin is inactive, regardless of CLI flags.
    pub(crate) requires_label_plugin: bool,
}

impl ToolSpec {
    const fn enabled(name: &'static str) -> Self {
        ToolSpec { name, default_disabled: false, requires_label_plugin: false }
    }
    const fn disabled(name: &'static str) -> Self {
        ToolSpec { name, default_disabled: true, requires_label_plugin: false }
    }
    const fn label_enabled(name: &'static str) -> Self {
        ToolSpec { name, default_disabled: false, requires_label_plugin: true }
    }
    const fn label_disabled(name: &'static str) -> Self {
        ToolSpec { name, default_disabled: true, requires_label_plugin: true }
    }
}

/// Every tool the server can expose, in a stable order used for logging and
/// the `--list-tools` table.
pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::enabled("deluge_add_torrent"),
    ToolSpec::enabled("deluge_list_torrents"),
    ToolSpec::enabled("deluge_get_torrent_status"),
    ToolSpec::enabled("deluge_pause_torrent"),
    ToolSpec::enabled("deluge_resume_torrent"),
    ToolSpec::enabled("deluge_set_torrent_options"),
    ToolSpec::enabled("deluge_get_free_space"),
    ToolSpec::enabled("deluge_get_path_size"),
    ToolSpec::disabled("deluge_move_storage"),
    ToolSpec::disabled("deluge_rename_folder"),
    ToolSpec::disabled("deluge_rename_files"),
    ToolSpec::disabled("deluge_force_recheck"),
    ToolSpec::disabled("deluge_remove_torrent"),
    ToolSpec::label_enabled("deluge_list_labels"),
    ToolSpec::label_disabled("deluge_create_label"),
    ToolSpec::label_disabled("deluge_delete_label"),
    ToolSpec::label_enabled("deluge_set_torrent_label"),
    ToolSpec::label_enabled("deluge_pause_label"),
    ToolSpec::label_enabled("deluge_resume_label"),
    ToolSpec::label_enabled("deluge_get_label_options"),
    ToolSpec::label_disabled("deluge_set_label_options"),
];

/// Every tool name, in registry order.
pub(crate) fn all_names() -> impl Iterator<Item = &'static str> {
    TOOLS.iter().map(|t| t.name)
}

/// Names of tools gated behind the Label plugin.
pub(crate) fn plugin_gated_names() -> impl Iterator<Item = &'static str> {
    TOOLS.iter().filter(|t| t.requires_label_plugin).map(|t| t.name)
}

/// Look up a tool's spec by name.
pub(crate) fn get(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == name)
}

/// Whether a tool is enabled by default (i.e. not in the opt-in set).
pub(crate) fn is_enabled_by_default(name: &str) -> bool {
    get(name).map(|t| !t.default_disabled).unwrap_or(false)
}
