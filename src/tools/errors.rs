// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! LLM-facing error enrichment.
//!
//! Deluge and the transport layer return terse error strings. These helpers
//! preserve the raw text (so the model keeps full context) and append a
//! `[Hint: …]` for known, recoverable cases — telling the model whether to
//! retry and what to check. Kept as `pub(super)` methods on [`DelugeServer`]
//! so the tool handlers reach them as `Self::…`.

use super::DelugeServer;

impl DelugeServer {
    /// Enrich transport-level errors (connection loss, send failure, reconnect timeout) with
    /// guidance telling the LLM whether to retry and what to check.
    pub(super) fn enrich_client_error(e: anyhow::Error) -> String {
        let msg = e.to_string();
        if msg.starts_with("send failed")
            || msg.starts_with("Failed to reconnect")
            || msg.contains("connection lost")
            || msg.starts_with("response channel dropped")
        {
            format!(
                "{msg}\n[Hint: The connection to Deluge was interrupted. \
                 Retry the operation once — the server reconnects automatically. \
                 If it keeps failing, check that the Deluge daemon is running and reachable.]"
            )
        } else {
            msg
        }
    }

    /// Map common label.* RPC errors to actionable messages. Keeps the raw exception
    /// text so the LLM has full context, then appends a [Hint: ...] for known cases.
    pub(super) fn enrich_label_error(e: anyhow::Error) -> String {
        let msg = e.to_string();
        let hint = if msg.contains("Unknown Label") {
            Some(
                "The label does not exist on the Deluge daemon. \
                 Use deluge_list_torrents to discover labels in use, or create the label first.",
            )
        } else if msg.contains("Label already exists") {
            Some(
                "A label with this name already exists. \
                 No action needed if you intended to use the existing label.",
            )
        } else if msg.contains("Empty Label") || msg.contains("Invalid label") {
            Some(
                "Deluge rejected the label name. \
                 Allowed characters: a-z, 0-9, '_', '-', '.'.",
            )
        } else if msg.contains("KeyError")
            && (msg.contains("label.") || msg.contains("'label.'"))
        {
            Some(
                "The Label plugin appears to be disabled on the Deluge daemon — \
                 the label.* RPC methods are unregistered. \
                 The MCP server will hide label tools shortly.",
            )
        } else {
            None
        };
        match hint {
            Some(h) => format!("{msg}\n[Hint: {h}]"),
            None => msg,
        }
    }

    /// Specialized error handling for `label.set_torrent`. If the label is missing
    /// and `deluge_create_label` is currently enabled, suggest using it.
    pub(super) fn enrich_label_set_error(
        e: anyhow::Error,
        label: &str,
        create_hint: Option<&str>,
    ) -> String {
        let msg = e.to_string();
        if msg.contains("Unknown Label") {
            let mut out = format!(
                "Label '{label}' does not exist on the Deluge daemon. ({msg})"
            );
            if let Some(hint) = create_hint {
                out.push_str(&format!("\n[Hint: {hint}]"));
            } else {
                out.push_str(
                    "\n[Hint: Ask the user to create the label in Deluge first, \
                     or to enable the create_label MCP tool.]",
                );
            }
            out
        } else {
            Self::enrich_label_error(e)
        }
    }
}
