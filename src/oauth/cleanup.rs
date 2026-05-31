// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;

use tracing::debug;

use super::state::OAuthState;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Spawn a background task that periodically sweeps expired tokens, codes,
/// pending authorizations, and stale client registrations.
pub(crate) fn spawn_cleanup(state: Arc<OAuthState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let result = state.sweep_expired().await;

            if result.codes > 0 {
                debug!(count = result.codes, "Swept expired authorization codes");
            }
            if result.access_tokens > 0 {
                debug!(count = result.access_tokens, "Swept expired access tokens");
            }
            if result.refresh_tokens > 0 {
                debug!(count = result.refresh_tokens, "Swept expired/superseded refresh tokens");
            }
            if result.pending_auths > 0 {
                debug!(count = result.pending_auths, "Swept expired pending authorizations");
            }
            if result.clients > 0 {
                debug!(count = result.clients, "Swept unauthorized expired client registrations");
            }
        }
    });
}
