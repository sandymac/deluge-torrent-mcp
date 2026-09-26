// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::Mutex;
use tracing::{info, trace};

use super::persist;

pub(crate) const CODE_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
/// Sliding: every refresh mints a new token with a full TTL, so this is the
/// inactivity window before a client must re-authorize.
pub(crate) const REFRESH_TOKEN_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Absolute lifetime of a refresh-token chain from the consent that started
/// it, so a stolen token cannot be kept alive indefinitely by refreshing.
pub(crate) const REFRESH_ABSOLUTE_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
pub(crate) const REFRESH_GRACE_PERIOD: Duration = Duration::from_secs(30);
pub(crate) const PENDING_AUTH_TTL: Duration = Duration::from_secs(5 * 60);
pub(crate) const MAX_CLIENTS: usize = 100;
pub(crate) const MAX_PENDING_AUTHORIZATIONS: usize = 1000;
/// Clients that never complete authorization are removed after this period.
pub(crate) const UNAUTHED_CLIENT_TTL: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

pub(crate) struct ClientInfo {
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) client_name: Option<String>,
    #[allow(dead_code)]
    pub(crate) grant_types: Vec<String>,
    pub(crate) created_at: Instant,
    /// Set to `true` once a token has been issued for this client.
    /// Unauthorized clients are garbage-collected after `UNAUTHED_CLIENT_TTL`.
    pub(crate) authorized: bool,
}

pub(crate) struct CodeInfo {
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) code_challenge: String,
    pub(crate) scope: String,
    pub(crate) expires_at: Instant,
}

#[allow(dead_code)]
pub(crate) struct TokenInfo {
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) expires_at: Instant,
}

pub(crate) struct RefreshInfo {
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) access_token: String,
    pub(crate) expires_at: Instant,
    /// Hard ceiling inherited along the rotation chain from the original
    /// authorization-code grant; sliding renewals never extend past it.
    pub(crate) family_expires_at: Instant,
    /// Set when this token is consumed by rotation: when, and the
    /// (access, refresh) pair that replaced it. Presenting it again within
    /// `REFRESH_GRACE_PERIOD` returns that same pair, so a retry after a lost
    /// response or two clients racing to refresh don't get bounced to re-auth.
    pub(crate) superseded: Option<(Instant, String, String)>,
}

/// Outcome of presenting a refresh token to the token endpoint.
pub(crate) enum RefreshOutcome {
    /// A fresh rotation, or a retry within the grace window handed the pair
    /// that rotation already minted.
    Issued {
        access_token: String,
        refresh_token: String,
        scope: String,
    },
    /// Unknown, expired, or superseded past the grace window. Any record is gone.
    Invalid(&'static str),
    /// Presented with a `client_id` other than the one it was issued to.
    ClientMismatch { expected: String },
    /// A superseded token whose replacement was itself already rotated:
    /// replay of a captured token. Every token for the client is revoked.
    Replay,
}

/// Stores the validated parameters from a GET /authorize request while the
/// consent page is displayed to the user. The nonce ties the POST back to
/// this pending authorization.
#[derive(Clone)]
pub(crate) struct PendingAuth {
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) code_challenge: String,
    pub(crate) scope: String,
    pub(crate) state_param: String,
    pub(crate) expires_at: Instant,
}

// ---------------------------------------------------------------------------
// OAuthState
// ---------------------------------------------------------------------------

pub(crate) struct OAuthState {
    pub(crate) issuer: String,
    pub(crate) resource: String,
    pub(crate) api_token: Option<String>,
    clients: Mutex<HashMap<String, ClientInfo>>,
    codes: Mutex<HashMap<String, CodeInfo>>,
    access_tokens: Mutex<HashMap<String, TokenInfo>>,
    refresh_tokens: Mutex<HashMap<String, RefreshInfo>>,
    pending_authorizations: Mutex<HashMap<String, PendingAuth>>,
    persist_path: Option<PathBuf>,
    dirty: AtomicBool,
    /// Serialises snapshot+write so the two savers (background flusher,
    /// shutdown flush) can't interleave on the shared `.tmp` file or land an
    /// older snapshot after a newer one. Never taken by a request path.
    save_lock: Mutex<()>,
}

impl OAuthState {
    /// Construct with an optional persistence file. If `persist_path` is set
    /// and the file exists, its contents seed the clients/access/refresh maps.
    /// A missing file is treated as empty — no error.
    pub(crate) async fn new_with_persistence(
        issuer: String,
        api_token: Option<String>,
        persist_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let (clients, access_tokens, refresh_tokens) = match persist_path.as_deref() {
            Some(path) => {
                let loaded = persist::load(path).await?;
                let (c, a, r) = loaded.into_runtime();
                info!(
                    path = %path.display(),
                    clients = c.len(),
                    access_tokens = a.len(),
                    refresh_tokens = r.len(),
                    "Loaded persisted OAuth state",
                );
                (c, a, r)
            }
            None => (HashMap::new(), HashMap::new(), HashMap::new()),
        };
        Ok(Self::from_parts(
            issuer,
            api_token,
            persist_path,
            clients,
            access_tokens,
            refresh_tokens,
        ))
    }

    fn from_parts(
        issuer: String,
        api_token: Option<String>,
        persist_path: Option<PathBuf>,
        clients: HashMap<String, ClientInfo>,
        access_tokens: HashMap<String, TokenInfo>,
        refresh_tokens: HashMap<String, RefreshInfo>,
    ) -> Self {
        let resource = format!("{issuer}/mcp");
        Self {
            issuer,
            resource,
            api_token,
            clients: Mutex::new(clients),
            codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(access_tokens),
            refresh_tokens: Mutex::new(refresh_tokens),
            pending_authorizations: Mutex::new(HashMap::new()),
            persist_path,
            dirty: AtomicBool::new(false),
            save_lock: Mutex::new(()),
        }
    }

    pub(crate) fn has_persist_path(&self) -> bool {
        self.persist_path.is_some()
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Force an immediate flush of persisted maps to disk, regardless of the dirty flag.
    /// Used on graceful shutdown to capture any mutations from the last flush interval.
    pub(crate) async fn flush(&self) -> anyhow::Result<()> {
        if self.persist_path.is_none() {
            return Ok(());
        }
        let _serialised = self.save_lock.lock().await;
        self.dirty.store(false, Ordering::Relaxed);
        self.flush_inner().await
    }

    /// Flush only if the dirty flag is set. Clears the flag *before* writing so
    /// concurrent mutations during the write re-mark it for the next tick.
    pub(crate) async fn flush_if_dirty(&self) -> anyhow::Result<()> {
        if self.persist_path.is_none() {
            return Ok(());
        }
        let _serialised = self.save_lock.lock().await;
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        // Re-set dirty on failure so the next tick retries.
        if let Err(e) = self.flush_inner().await {
            self.dirty.store(true, Ordering::Relaxed);
            return Err(e);
        }
        Ok(())
    }

    /// Snapshot + write. Callers hold `save_lock`.
    async fn flush_inner(&self) -> anyhow::Result<()> {
        let path = self.persist_path.as_deref().expect("flush_inner called without persist_path");
        let snapshot = {
            let clients = self.clients.lock().await;
            let access = self.access_tokens.lock().await;
            let refresh = self.refresh_tokens.lock().await;
            persist::PersistedState::from_runtime(&clients, &access, &refresh)
        };
        persist::save(path, &snapshot).await
    }

    // -- Client operations --

    pub(crate) async fn client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub(crate) async fn register_client(&self, client_id: String, info: ClientInfo) {
        self.clients.lock().await.insert(client_id, info);
        self.mark_dirty();
    }

    pub(crate) async fn get_client_name(&self, client_id: &str) -> Option<Option<String>> {
        self.clients.lock().await.get(client_id).map(|c| c.client_name.clone())
    }

    pub(crate) async fn client_has_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Option<bool> {
        self.clients.lock().await.get(client_id).map(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
    }

    pub(crate) async fn client_exists(&self, client_id: &str) -> bool {
        self.clients.lock().await.contains_key(client_id)
    }

    pub(crate) async fn mark_client_authorized(&self, client_id: &str) -> bool {
        let mut clients = self.clients.lock().await;
        match clients.get_mut(client_id) {
            Some(client) => {
                client.authorized = true;
                drop(clients);
                self.mark_dirty();
                true
            }
            None => false,
        }
    }

    // -- Pending authorization operations --

    pub(crate) async fn pending_auth_count(&self) -> usize {
        self.pending_authorizations.lock().await.len()
    }

    pub(crate) async fn insert_pending_auth(&self, nonce: String, pending: PendingAuth) {
        self.pending_authorizations.lock().await.insert(nonce, pending);
    }

    pub(crate) async fn get_pending_auth(&self, nonce: &str) -> Option<PendingAuth> {
        self.pending_authorizations.lock().await.get(nonce).cloned()
    }

    pub(crate) async fn take_pending_auth(&self, nonce: &str) -> Option<PendingAuth> {
        self.pending_authorizations.lock().await.remove(nonce)
    }

    // -- Authorization code operations --

    pub(crate) async fn insert_auth_code(&self, code: String, info: CodeInfo) {
        self.codes.lock().await.insert(code, info);
    }

    pub(crate) async fn take_auth_code(&self, code: &str) -> Option<CodeInfo> {
        self.codes.lock().await.remove(code)
    }

    // -- Access token operations --

    pub(crate) async fn validate_token(&self, token: &str) -> bool {
        let tokens = self.access_tokens.lock().await;
        let valid = matches!(tokens.get(token), Some(info) if info.expires_at > Instant::now());
        trace!(valid, "Bearer token validation");
        valid
    }

    pub(crate) async fn insert_access_token(&self, token: String, info: TokenInfo) {
        self.access_tokens.lock().await.insert(token, info);
        self.mark_dirty();
    }

    // -- Refresh token operations --

    pub(crate) async fn insert_refresh_token(&self, token: String, info: RefreshInfo) {
        self.refresh_tokens.lock().await.insert(token, info);
        self.mark_dirty();
    }

    /// Look up a refresh token and return a snapshot of its data.
    #[cfg(test)]
    pub(crate) async fn get_refresh_info(&self, token: &str) -> Option<RefreshSnapshot> {
        self.refresh_tokens.lock().await.get(token).map(|info| RefreshSnapshot {
            client_id: info.client_id.clone(),
            access_token: info.access_token.clone(),
            family_expires_at: info.family_expires_at,
        })
    }

    /// Consume a refresh token (rotation): mint a new (access, refresh) pair
    /// carrying the original scope, revoke the old access token, and keep the
    /// old refresh record for `REFRESH_GRACE_PERIOD` holding the pair it was
    /// replaced by. Re-presenting it within that window returns the same pair
    /// while the successor is unused (idempotent retry); once the successor
    /// has itself been rotated the presentation is replay of a captured token
    /// and every token for the client is revoked. The successor is minted and
    /// stored under the refresh-token lock so a concurrent retry sees it.
    pub(crate) async fn rotate_refresh_token(&self, old_token: &str, client_id: &str) -> RefreshOutcome {
        let now = Instant::now();
        let mut tokens = self.refresh_tokens.lock().await;
        let Some(info) = tokens.get(old_token) else {
            return RefreshOutcome::Invalid("invalid or already-used refresh token");
        };
        if info.client_id != client_id {
            return RefreshOutcome::ClientMismatch { expected: info.client_id.clone() };
        }

        let past_grace =
            matches!(&info.superseded, Some((at, _, _)) if now.duration_since(*at) >= REFRESH_GRACE_PERIOD);
        if info.expires_at <= now || past_grace {
            tokens.remove(old_token);
            drop(tokens);
            self.mark_dirty();
            return RefreshOutcome::Invalid(if past_grace {
                "refresh token has been superseded"
            } else {
                "refresh token expired"
            });
        }

        if let Some((_, access_token, refresh_token)) = info.superseded.clone() {
            // Lost-response retry: the successor is still unused, so hand
            // back the same answer.
            if tokens.get(&refresh_token).is_some_and(|s| s.superseded.is_none()) {
                let scope = info.scope.clone();
                return RefreshOutcome::Issued { access_token, refresh_token, scope };
            }
            // The successor was already rotated by someone else, so this is a
            // replay of a captured token. Revoke everything the client holds:
            // the real client re-consents once, the holder of the copy is out.
            tokens.retain(|_, t| t.client_id != client_id);
            drop(tokens);
            self.access_tokens.lock().await.retain(|_, t| t.client_id != client_id);
            self.mark_dirty();
            return RefreshOutcome::Replay;
        }

        // Fresh rotation. Always carry the originally granted scope — the
        // request's `scope` is ignored to prevent escalation (OAuth 2.1).
        let new_access = generate_random_hex(32);
        let new_refresh = generate_random_hex(32);
        let info = tokens.get_mut(old_token).expect("present: looked up above");
        let scope = info.scope.clone();
        let old_access = info.access_token.clone();
        let family_expires_at = info.family_expires_at;
        info.superseded = Some((now, new_access.clone(), new_refresh.clone()));
        tokens.insert(
            new_refresh.clone(),
            RefreshInfo {
                client_id: client_id.to_string(),
                scope: scope.clone(),
                access_token: new_access.clone(),
                expires_at: (now + REFRESH_TOKEN_TTL).min(family_expires_at),
                family_expires_at,
                superseded: None,
            },
        );
        drop(tokens);

        let mut access = self.access_tokens.lock().await;
        access.remove(&old_access);
        access.insert(
            new_access.clone(),
            TokenInfo {
                client_id: client_id.to_string(),
                scope: scope.clone(),
                expires_at: now + ACCESS_TOKEN_TTL,
            },
        );
        drop(access);
        self.mark_dirty();

        RefreshOutcome::Issued { access_token: new_access, refresh_token: new_refresh, scope }
    }

    // -- Cleanup --

    pub(crate) async fn sweep_expired(&self) -> SweepResult {
        let now = Instant::now();
        let mut result = SweepResult::default();

        self.codes.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.codes += 1; false }
        });

        self.access_tokens.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.access_tokens += 1; false }
        });

        self.refresh_tokens.lock().await.retain(|_, v| {
            let past_grace =
                matches!(&v.superseded, Some((at, _, _)) if now.duration_since(*at) >= REFRESH_GRACE_PERIOD);
            if v.expires_at <= now || past_grace {
                result.refresh_tokens += 1;
                return false;
            }
            true
        });

        self.pending_authorizations.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.pending_auths += 1; false }
        });

        self.clients.lock().await.retain(|_, v| {
            if v.authorized || now.duration_since(v.created_at) < UNAUTHED_CLIENT_TTL {
                true
            } else {
                result.clients += 1;
                false
            }
        });

        if result.clients > 0 || result.access_tokens > 0 || result.refresh_tokens > 0 {
            self.mark_dirty();
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_random_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Snapshot of refresh token data returned by `get_refresh_info`.
#[cfg(test)]
pub(crate) struct RefreshSnapshot {
    pub(crate) client_id: String,
    pub(crate) access_token: String,
    pub(crate) family_expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct SweepResult {
    pub(crate) codes: usize,
    pub(crate) access_tokens: usize,
    pub(crate) refresh_tokens: usize,
    pub(crate) pending_auths: usize,
    pub(crate) clients: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_state() -> OAuthState {
        OAuthState::new_with_persistence("http://localhost:8080".into(), None, None)
            .await
            .unwrap()
    }

    fn refresh(client_id: &str, access_token: &str) -> RefreshInfo {
        let now = Instant::now();
        RefreshInfo {
            client_id: client_id.into(),
            scope: "mcp".into(),
            access_token: access_token.into(),
            expires_at: now + REFRESH_TOKEN_TTL,
            family_expires_at: now + REFRESH_ABSOLUTE_TTL,
            superseded: None,
        }
    }

    async fn rotate(state: &OAuthState, token: &str, client_id: &str) -> Option<(String, String)> {
        match state.rotate_refresh_token(token, client_id).await {
            RefreshOutcome::Issued { access_token, refresh_token, .. } => Some((access_token, refresh_token)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn refresh_retry_within_grace_returns_same_pair() {
        let state = fresh_state().await;
        state.insert_refresh_token("r1".into(), refresh("c", "a1")).await;

        let first = rotate(&state, "r1", "c").await.expect("first rotation");
        let retry = rotate(&state, "r1", "c").await.expect("retry within grace");
        assert_eq!(first, retry);

        // Both tokens from the pair are live, the old access token is not,
        // and the wrong client is still rejected.
        assert!(state.validate_token(&first.0).await);
        assert!(!state.validate_token("a1").await);
        assert!(rotate(&state, &first.1, "c").await.is_some());
        assert!(matches!(
            state.rotate_refresh_token("r1", "someone-else").await,
            RefreshOutcome::ClientMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn refresh_replay_after_successor_rotated_revokes_client() {
        let state = fresh_state().await;
        state.insert_refresh_token("r1".into(), refresh("c", "a1")).await;
        let (a2, r2) = rotate(&state, "r1", "c").await.unwrap();
        let (a3, r3) = rotate(&state, &r2, "c").await.unwrap();

        // r1 is two generations old: a replay, not a retry. Everything dies.
        assert!(matches!(state.rotate_refresh_token("r1", "c").await, RefreshOutcome::Replay));
        assert!(!state.validate_token(&a2).await);
        assert!(!state.validate_token(&a3).await);
        assert!(rotate(&state, &r3, "c").await.is_none());
    }

    #[tokio::test]
    async fn refresh_rotation_never_extends_past_family_cap() {
        let state = fresh_state().await;
        let cap = Instant::now() + Duration::from_secs(60);
        state
            .refresh_tokens
            .lock()
            .await
            .insert("r1".into(), RefreshInfo { expires_at: cap, family_expires_at: cap, ..refresh("c", "a1") });

        let (_, r2) = rotate(&state, "r1", "c").await.unwrap();
        let tokens = state.refresh_tokens.lock().await;
        assert_eq!(tokens[&r2].expires_at, cap);
        assert_eq!(tokens[&r2].family_expires_at, cap);
    }
}
