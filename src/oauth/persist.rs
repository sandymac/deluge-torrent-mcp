// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! File-based persistence for long-lived OAuth state (clients, access tokens,
//! refresh tokens). Short-lived state (auth codes, pending consent sessions)
//! is not persisted — those flows simply restart after a server restart.
//!
//! Writes are debounced: mutations set a dirty flag on `OAuthState`, and a
//! background task flushes every `FLUSH_INTERVAL` if dirty. File writes are
//! atomic via `tmp` + `rename`. On Unix, the file is chmod'd to 0600 before
//! rename because it contains bearer tokens.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::state::{ClientInfo, OAuthState, REFRESH_GRACE_PERIOD, RefreshInfo, TokenInfo, UNAUTHED_CLIENT_TTL};

/// Schema version for the on-disk format. Bump when the JSON shape changes.
pub const SCHEMA_VERSION: u32 = 1;

/// How often the background task wakes to flush dirty state.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// On-disk schema
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub version: u32,
    #[serde(default)]
    pub clients: HashMap<String, PersistedClient>,
    #[serde(default)]
    pub access_tokens: HashMap<String, PersistedToken>,
    #[serde(default)]
    pub refresh_tokens: HashMap<String, PersistedRefresh>,
}

#[derive(Serialize, Deserialize)]
pub struct PersistedClient {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    pub created_at_unix: u64,
    pub authorized: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PersistedToken {
    pub client_id: String,
    pub scope: String,
    pub expires_at_unix: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PersistedRefresh {
    pub client_id: String,
    pub scope: String,
    pub access_token: String,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub superseded_at_unix: Option<u64>,
}

impl PersistedState {
    fn empty() -> Self {
        Self {
            version: SCHEMA_VERSION,
            clients: HashMap::new(),
            access_tokens: HashMap::new(),
            refresh_tokens: HashMap::new(),
        }
    }

    /// Build a `PersistedState` from current runtime maps.
    pub fn from_runtime(
        clients: &HashMap<String, ClientInfo>,
        access_tokens: &HashMap<String, TokenInfo>,
        refresh_tokens: &HashMap<String, RefreshInfo>,
    ) -> Self {
        let now_i = Instant::now();
        let now_s = SystemTime::now();

        let clients = clients
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PersistedClient {
                        redirect_uris: v.redirect_uris.clone(),
                        client_name: v.client_name.clone(),
                        grant_types: v.grant_types.clone(),
                        created_at_unix: instant_to_unix(v.created_at, now_i, now_s),
                        authorized: v.authorized,
                    },
                )
            })
            .collect();

        let access_tokens = access_tokens
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PersistedToken {
                        client_id: v.client_id.clone(),
                        scope: v.scope.clone(),
                        expires_at_unix: instant_to_unix(v.expires_at, now_i, now_s),
                    },
                )
            })
            .collect();

        let refresh_tokens = refresh_tokens
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PersistedRefresh {
                        client_id: v.client_id.clone(),
                        scope: v.scope.clone(),
                        access_token: v.access_token.clone(),
                        expires_at_unix: instant_to_unix(v.expires_at, now_i, now_s),
                        superseded_at_unix: v
                            .superseded_at
                            .map(|i| instant_to_unix(i, now_i, now_s)),
                    },
                )
            })
            .collect();

        Self {
            version: SCHEMA_VERSION,
            clients,
            access_tokens,
            refresh_tokens,
        }
    }

    /// Hydrate runtime maps from a `PersistedState`. Entries that have already
    /// expired at load time are dropped — they'd be swept seconds later anyway.
    pub fn into_runtime(
        self,
    ) -> (
        HashMap<String, ClientInfo>,
        HashMap<String, TokenInfo>,
        HashMap<String, RefreshInfo>,
    ) {
        let now_i = Instant::now();
        let now_s = SystemTime::now();

        let mut clients = HashMap::new();
        for (id, pc) in self.clients {
            // Authorized clients never get swept by age, so created_at is irrelevant.
            // For unauthorized clients, drop any that have already exceeded the TTL.
            let created_at = if pc.authorized {
                now_i
            } else {
                let saved = UNIX_EPOCH + Duration::from_secs(pc.created_at_unix);
                let age = now_s.duration_since(saved).unwrap_or(Duration::ZERO);
                if age >= UNAUTHED_CLIENT_TTL {
                    continue;
                }
                now_i.checked_sub(age).unwrap_or(now_i)
            };
            clients.insert(
                id,
                ClientInfo {
                    redirect_uris: pc.redirect_uris,
                    client_name: pc.client_name,
                    grant_types: pc.grant_types,
                    created_at,
                    authorized: pc.authorized,
                },
            );
        }

        let mut access_tokens = HashMap::new();
        for (tok, pt) in self.access_tokens {
            if let Some(expires_at) = unix_to_instant(pt.expires_at_unix, now_i, now_s) {
                if expires_at > now_i {
                    access_tokens.insert(
                        tok,
                        TokenInfo {
                            client_id: pt.client_id,
                            scope: pt.scope,
                            expires_at,
                        },
                    );
                }
            }
        }

        let mut refresh_tokens = HashMap::new();
        for (tok, pr) in self.refresh_tokens {
            let Some(expires_at) = unix_to_instant(pr.expires_at_unix, now_i, now_s) else {
                continue;
            };
            if expires_at <= now_i {
                continue;
            }

            // For superseded refresh tokens, the grace window is only 30 s —
            // if restart took longer than that, drop the token outright.
            let superseded_at = match pr.superseded_at_unix {
                None => None,
                Some(ts) => {
                    let saved = UNIX_EPOCH + Duration::from_secs(ts);
                    let since = now_s.duration_since(saved).unwrap_or(Duration::ZERO);
                    if since >= REFRESH_GRACE_PERIOD {
                        continue;
                    }
                    Some(now_i.checked_sub(since).unwrap_or(now_i))
                }
            };

            refresh_tokens.insert(
                tok,
                RefreshInfo {
                    client_id: pr.client_id,
                    scope: pr.scope,
                    access_token: pr.access_token,
                    expires_at,
                    superseded_at,
                },
            );
        }

        (clients, access_tokens, refresh_tokens)
    }
}

// ---------------------------------------------------------------------------
// Instant ↔ Unix helpers
// ---------------------------------------------------------------------------

fn instant_to_unix(i: Instant, now_i: Instant, now_s: SystemTime) -> u64 {
    let sys = if i >= now_i {
        now_s + (i - now_i)
    } else {
        now_s.checked_sub(now_i - i).unwrap_or(UNIX_EPOCH)
    };
    sys.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_to_instant(ts: u64, now_i: Instant, now_s: SystemTime) -> Option<Instant> {
    let target = UNIX_EPOCH + Duration::from_secs(ts);
    if target >= now_s {
        Some(now_i + target.duration_since(now_s).ok()?)
    } else {
        let delta = now_s.duration_since(target).ok()?;
        now_i.checked_sub(delta)
    }
}

// ---------------------------------------------------------------------------
// Disk I/O
// ---------------------------------------------------------------------------

pub async fn load(path: &Path) -> anyhow::Result<PersistedState> {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PersistedState::empty()),
        Err(e) => return Err(e.into()),
    };

    match serde_json::from_slice::<PersistedState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Ok(state),
        Ok(state) => {
            warn!(
                path = %path.display(),
                version = state.version,
                expected = SCHEMA_VERSION,
                "Unknown OAuth state schema version; starting with empty state",
            );
            rename_corrupt(path).await;
            Ok(PersistedState::empty())
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to parse OAuth state file; starting with empty state",
            );
            rename_corrupt(path).await;
            Ok(PersistedState::empty())
        }
    }
}

pub async fn save(path: &Path, state: &PersistedState) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(state)?;
    let tmp_path = tmp_sibling(path, ".tmp");

    tokio::fs::write(&tmp_path, &json).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).await?;
    }

    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

async fn rename_corrupt(path: &Path) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let corrupt = tmp_sibling(path, &format!(".corrupt-{ts}"));
    match tokio::fs::rename(path, &corrupt).await {
        Ok(()) => warn!(from = %path.display(), to = %corrupt.display(), "Renamed corrupt OAuth state file"),
        Err(e) => warn!(from = %path.display(), to = %corrupt.display(), error = %e, "Failed to rename corrupt OAuth state file"),
    }
}

fn tmp_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Background flusher
// ---------------------------------------------------------------------------

pub fn spawn_persistence(state: Arc<OAuthState>) {
    if !state.has_persist_path() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(FLUSH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(e) = state.flush_if_dirty().await {
                warn!(error = %e, "OAuth state flush failed");
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::OAuthState;
    use crate::oauth::state::{ClientInfo, RefreshInfo};

    fn temp_state_path(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("deluge-mcp-oauth-{tag}-{ts}.json"))
    }

    #[test]
    fn instant_roundtrip_future() {
        let now_i = Instant::now();
        let now_s = SystemTime::now();
        let future = now_i + Duration::from_secs(300);
        let ts = instant_to_unix(future, now_i, now_s);
        let back = unix_to_instant(ts, now_i, now_s).unwrap();
        let diff = back.duration_since(future);
        assert!(diff < Duration::from_secs(1), "diff too large: {diff:?}");
    }

    #[test]
    fn instant_roundtrip_past_within_uptime() {
        // Can only test past Instants that are within the process's uptime.
        // On CI the process has been running for at least a moment.
        let now_i = Instant::now();
        let now_s = SystemTime::now();
        if let Some(past) = now_i.checked_sub(Duration::from_millis(100)) {
            let ts = instant_to_unix(past, now_i, now_s);
            let back = unix_to_instant(ts, now_i, now_s).unwrap();
            let diff = now_i.duration_since(back);
            assert!(diff < Duration::from_secs(1), "diff too large: {diff:?}");
        }
    }

    #[test]
    fn empty_persisted_state_roundtrips() {
        let empty = PersistedState::empty();
        let bytes = serde_json::to_vec(&empty).unwrap();
        let back: PersistedState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.version, SCHEMA_VERSION);
        assert!(back.clients.is_empty());
    }

    #[tokio::test]
    async fn oauth_state_save_load_roundtrip() {
        let path = temp_state_path("roundtrip");
        let _ = tokio::fs::remove_file(&path).await;

        // Seed first instance.
        {
            let state = OAuthState::new_with_persistence(
                "http://localhost:8080".into(),
                None,
                Some(path.clone()),
            )
            .await
            .unwrap();

            state
                .register_client(
                    "client-abc".into(),
                    ClientInfo {
                        redirect_uris: vec!["http://localhost:9000/cb".into()],
                        client_name: Some("test client".into()),
                        grant_types: vec!["authorization_code".into()],
                        created_at: Instant::now(),
                        authorized: true,
                    },
                )
                .await;

            state
                .insert_refresh_token(
                    "refresh-xyz".into(),
                    RefreshInfo {
                        client_id: "client-abc".into(),
                        scope: "mcp".into(),
                        access_token: "access-123".into(),
                        expires_at: Instant::now() + Duration::from_secs(3600),
                        superseded_at: None,
                    },
                )
                .await;

            state.flush().await.unwrap();
        }

        // Load a fresh instance from the same file.
        let reloaded = OAuthState::new_with_persistence(
            "http://localhost:8080".into(),
            None,
            Some(path.clone()),
        )
        .await
        .unwrap();

        assert!(reloaded.client_exists("client-abc").await);
        assert_eq!(
            reloaded.get_client_name("client-abc").await,
            Some(Some("test client".into()))
        );
        let refresh = reloaded.get_refresh_info("refresh-xyz").await;
        assert!(refresh.is_some(), "refresh token should survive reload");
        let refresh = refresh.unwrap();
        assert_eq!(refresh.client_id, "client-abc");
        assert_eq!(refresh.access_token, "access-123");
        assert!(refresh.superseded_at.is_none());

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn missing_file_loads_as_empty() {
        let path = temp_state_path("missing");
        let _ = tokio::fs::remove_file(&path).await;

        let state = OAuthState::new_with_persistence(
            "http://localhost:8080".into(),
            None,
            Some(path.clone()),
        )
        .await
        .unwrap();

        assert!(!state.client_exists("anything").await);
    }

    #[tokio::test]
    async fn corrupt_file_is_renamed_and_recovered() {
        let path = temp_state_path("corrupt");
        tokio::fs::write(&path, b"{not valid json").await.unwrap();

        let state = OAuthState::new_with_persistence(
            "http://localhost:8080".into(),
            None,
            Some(path.clone()),
        )
        .await
        .unwrap();

        // Starts with empty state (no crash).
        assert!(!state.client_exists("anything").await);

        // Original corrupt file has been moved aside.
        assert!(!path.exists(), "corrupt file should be renamed away");

        // Clean up any .corrupt-* siblings.
        if let Some(parent) = path.parent() {
            if let Some(stem) = path.file_name() {
                let prefix = format!("{}.corrupt-", stem.to_string_lossy());
                if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let name = entry.file_name();
                        if name.to_string_lossy().starts_with(&prefix) {
                            let _ = tokio::fs::remove_file(entry.path()).await;
                        }
                    }
                }
            }
        }
    }
}
