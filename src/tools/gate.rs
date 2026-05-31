// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Tool visibility gating.
//!
//! [`ToolGate`] owns the answer to "which tools are callable right now" and the
//! two policy inputs that determine it: the operator's intent (defaults plus
//! `--enable-tool`) and the live Label-plugin state on the daemon. It is the
//! single place that combines them, so the rest of the server only asks yes/no
//! questions ([`ToolGate::check`], [`ToolGate::is_enabled`]) instead of
//! recomputing the policy.

use std::collections::HashSet;
use std::sync::RwLock;

/// Owns the currently-visible tool set and the inputs that produce it.
///
/// Visibility rule: a tool is callable iff the operator enabled it **and**, if
/// it is plugin-gated, the required plugin is active on the daemon.
pub(crate) struct ToolGate {
    /// Tools the operator authorised (via defaults or `--enable-tool`). Static
    /// for the life of the process; plugin gating is layered on top.
    user_intent: HashSet<String>,
    /// Tools that require the Deluge Label plugin to be active. Static.
    plugin_gated: HashSet<String>,
    /// Currently callable tools = `user_intent` minus any plugin-gated tool
    /// whose plugin is inactive. Updated live by the plugin watcher.
    enabled: RwLock<HashSet<String>>,
    /// Whether the Label plugin is currently active on the daemon.
    label_plugin_active: RwLock<bool>,
}

impl ToolGate {
    pub(crate) fn new(
        user_intent: HashSet<String>,
        plugin_gated: HashSet<String>,
        label_plugin_active: bool,
    ) -> Self {
        let enabled = compute_enabled(&user_intent, &plugin_gated, label_plugin_active);
        Self {
            user_intent,
            plugin_gated,
            enabled: RwLock::new(enabled),
            label_plugin_active: RwLock::new(label_plugin_active),
        }
    }

    /// Whether the Label plugin is currently active on the daemon.
    pub(crate) fn label_plugin_active(&self) -> bool {
        *self.label_plugin_active.read().unwrap()
    }

    /// Whether `name` is currently callable.
    pub(crate) fn is_enabled(&self, name: &str) -> bool {
        self.enabled.read().unwrap().contains(name)
    }

    /// Snapshot of the currently-visible tool names (for `tools/list`).
    pub(crate) fn visible(&self) -> HashSet<String> {
        self.enabled.read().unwrap().clone()
    }

    /// Record a new Label-plugin state and recompute the visible set.
    /// Returns `true` if the visible set (or the plugin flag) actually changed —
    /// the caller uses this to decide whether to fan out `tools/list_changed`.
    pub(crate) fn set_label_plugin_active(&self, active: bool) -> bool {
        let new_set = compute_enabled(&self.user_intent, &self.plugin_gated, active);
        let mut current_active = self.label_plugin_active.write().unwrap();
        let mut current_set = self.enabled.write().unwrap();
        let changed = *current_active != active || *current_set != new_set;
        *current_active = active;
        *current_set = new_set;
        changed
    }

    /// Defense-in-depth check before dispatching a tool call. Returns an
    /// actionable error if the tool is not currently callable, distinguishing
    /// administratively-disabled tools from plugin-gated ones.
    pub(crate) fn check(&self, tool_name: &str) -> Result<(), String> {
        if self.enabled.read().unwrap().contains(tool_name) {
            return Ok(());
        }
        // Disabled — pick the right hint. CLI intent wins: if the operator did
        // not opt into this tool, the plugin hint is misleading (enabling the
        // plugin alone won't make the tool visible).
        if !self.user_intent.contains(tool_name) {
            return Err(disabled_message(tool_name));
        }
        // User intended this tool; it must be gated by an inactive plugin.
        let plugin_gated = self.plugin_gated.contains(tool_name);
        if plugin_gated && !*self.label_plugin_active.read().unwrap() {
            Err(plugin_inactive_message(tool_name))
        } else {
            Err(disabled_message(tool_name))
        }
    }
}

/// Compute the visible tool set: operator intent minus plugin-gated tools whose
/// plugin is inactive.
fn compute_enabled(
    user_intent: &HashSet<String>,
    plugin_gated: &HashSet<String>,
    label_plugin_active: bool,
) -> HashSet<String> {
    let mut out = user_intent.clone();
    if !label_plugin_active {
        for t in plugin_gated {
            out.remove(t);
        }
    }
    out
}

fn disabled_message(tool_name: &str) -> String {
    format!(
        "Tool '{tool_name}' is disabled. Use --enable-tool={tool_name} to enable it.\n\
         [Hint: This tool has been administratively disabled on this server. \
         Do not attempt this operation by other means — inform the user that the \
         server must be restarted with --enable-tool={tool_name} to allow this action.]"
    )
}

fn plugin_inactive_message(tool_name: &str) -> String {
    format!(
        "Tool '{tool_name}' is currently unavailable because the Label plugin is not \
         enabled on the Deluge daemon.\n\
         [Hint: Ask the user to enable the Label plugin in Deluge's \
         Preferences \u{2192} Plugins, or via `deluge-console plugin --enable Label`. \
         Once enabled the tool becomes available without restarting the MCP server.]"
    )
}
