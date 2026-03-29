// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

// Deluge RPC client — connection, authentication, and method wrappers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BytesMut};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_native_tls::TlsStream;
use tracing::{debug, info, warn};

use crate::rencode::{self, Value};

const PROTOCOL_VERSION: u8 = 1;
const RPC_RESPONSE: i64 = 1;
const RPC_ERROR: i64 = 2;
// RPC_EVENT = 3 — server-initiated, ignored for now

const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024; // 32 MB compressed
const MAX_DECOMPRESSED_BYTES: usize = MAX_FRAME_BYTES * 4; // 128 MB decompressed

type PendingMap = Mutex<HashMap<i64, oneshot::Sender<Result<Value>>>>;

/// Active TLS connection state — writer half, pending response map, and generation counter.
/// The generation is used by the read loop cleanup task to avoid nulling out a newer connection
/// that was established after this one died.
struct LiveConn {
    generation: u64,
    writer: WriteHalf<TlsStream<TcpStream>>,
    pending: Arc<PendingMap>,
}

pub struct DelugeClient {
    // Stored for reconnect
    host: String,
    port: u16,
    cert_fingerprint: Option<String>,
    username: String,
    password: String,

    // None when disconnected; reconnected lazily on next call()
    conn: Arc<AsyncMutex<Option<LiveConn>>>,
    next_id: AtomicI64,
    next_generation: AtomicU64,
}

impl DelugeClient {
    /// Connect to a Deluge daemon via TLS TCP and authenticate.
    ///
    /// Returns the client and the granted auth level (0–10).
    /// All parameters are stored for automatic reconnection if the connection drops.
    pub async fn connect(
        host: &str,
        port: u16,
        cert_fingerprint: Option<String>,
        username: &str,
        password: &str,
    ) -> Result<(Arc<Self>, i64)> {
        let client = Arc::new(Self {
            host: host.to_string(),
            port,
            cert_fingerprint,
            username: username.to_string(),
            password: password.to_string(),
            conn: Arc::new(AsyncMutex::new(None)),
            next_id: AtomicI64::new(1),
            next_generation: AtomicU64::new(1),
        });

        let (live_conn, auth_level) = client.try_connect_and_login().await?;
        *client.conn.lock().await = Some(live_conn);

        Ok((client, auth_level))
    }

    /// Send an RPC call and wait for the response.
    ///
    /// If the connection is dead (e.g. after a laptop sleep), transparently
    /// reconnects with exponential backoff before sending.
    pub async fn call(
        &self,
        method: &str,
        args: Vec<Value>,
        kwargs: Vec<(Value, Value)>,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        // Hold the conn lock only during send, not during the response wait.
        {
            let mut conn_guard = self.conn.lock().await;

            if conn_guard.is_none() {
                info!("Connection to Deluge lost — reconnecting...");
                let (new_conn, auth_level) = self.try_connect_and_login_with_retry().await?;
                debug!(auth_level, "Re-authenticated with Deluge daemon");
                *conn_guard = Some(new_conn);
            }

            let conn = conn_guard.as_mut().unwrap();
            conn.pending.lock().unwrap().insert(id, tx);

            let request = Value::List(vec![Value::List(vec![
                Value::Int(id),
                Value::String(method.to_string()),
                Value::List(args),
                Value::Dict(kwargs),
            ])]);
            let encoded = rencode::encode(&request);
            let compressed = zlib_compress(&encoded)?;

            if let Err(e) = send_frame(&mut conn.writer, &compressed).await {
                conn.pending.lock().unwrap().remove(&id);
                *conn_guard = None;
                return Err(anyhow!("send failed: {e}"));
            }
        } // conn lock released here — other calls can proceed while we wait

        rx.await
            .map_err(|_| anyhow!("response channel dropped for request {id}"))?
    }

    /// Establish a new TLS connection and authenticate. Used for both initial
    /// connect and reconnect. Does not touch `self.conn`.
    async fn try_connect_and_login(&self) -> Result<(LiveConn, i64)> {
        let cx = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        let cx = tokio_native_tls::TlsConnector::from(cx);

        let tcp = TcpStream::connect((&self.host as &str, self.port)).await?;
        let tls = cx.connect(&self.host, tcp).await?;

        // Fingerprint logging / pinning
        if let Some(cert) = tls.get_ref().peer_certificate()? {
            let der = cert.to_der()?;
            let fp = cert_fingerprint_from_der(&der);
            match &self.cert_fingerprint {
                Some(pinned) => {
                    if !fp.eq_ignore_ascii_case(pinned) {
                        bail!(
                            "TLS certificate fingerprint mismatch: expected {pinned}, got {fp}"
                        );
                    }
                    debug!("TLS certificate fingerprint verified: {fp}");
                }
                None => {
                    warn!(
                        "TLS certificate not verified. \
                         To pin this certificate, add: --cert-fingerprint \"{fp}\""
                    );
                }
            }
        }

        let (reader, mut writer) = tokio::io::split(tls);
        let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));

        // Stamp this connection with a unique generation so the cleanup task
        // can avoid nulling out a newer connection established after this one died.
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);

        // Spawn read loop. On termination, drain pending requests with an error
        // and mark the connection as dead so the next call() triggers reconnect.
        let conn_ref = self.conn.clone();
        let pending_for_loop = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = read_loop(reader, pending_for_loop.clone()).await {
                warn!("Deluge read loop terminated: {e}. Will reconnect on next request.");
            }
            for (_, tx) in pending_for_loop.lock().unwrap().drain() {
                let _ = tx.send(Err(anyhow!("connection lost")));
            }
            // Only null out conn if it still holds this generation — a newer
            // connection may have already been established.
            let mut guard = conn_ref.lock().await;
            if guard.as_ref().map(|c| c.generation) == Some(generation) {
                *guard = None;
            }
        });

        // Login directly — can't use self.call() here because the conn lock
        // may already be held by the caller (during reconnect).
        let login_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let result = send_call_direct(
            &mut writer,
            &pending,
            login_id,
            "daemon.login",
            vec![
                Value::String(self.username.clone()),
                Value::String(self.password.clone()),
            ],
            vec![(
                Value::String("client_version".into()),
                Value::String("2.0.0".into()),
            )],
        )
        .await?;

        let auth_level = match result {
            Value::Int(level) => level,
            other => bail!("unexpected login result: {other:?}"),
        };

        Ok((LiveConn { generation, writer, pending }, auth_level))
    }

    /// Retry `try_connect_and_login` with exponential backoff.
    /// Attempts: 5 max, delays: 2s, 4s, 8s, 16s, 30s (~60s total).
    /// This covers the typical WiFi reconnect window after a laptop wakes from sleep.
    async fn try_connect_and_login_with_retry(&self) -> Result<(LiveConn, i64)> {
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.try_connect_and_login().await {
                Ok(result) => {
                    info!("Reconnected to Deluge daemon");
                    return Ok(result);
                }
                Err(e) if attempt >= MAX_ATTEMPTS => {
                    return Err(anyhow!(
                        "Failed to reconnect after {MAX_ATTEMPTS} attempts: {e}"
                    ));
                }
                Err(e) => {
                    let delay_secs = 2u64.pow(attempt.min(5)).min(30);
                    warn!(
                        attempt,
                        MAX_ATTEMPTS,
                        "Reconnect failed: {e}. Retrying in {delay_secs}s"
                    );
                    tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                }
            }
        }
    }
}

fn cert_fingerprint_from_der(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Send a single RPC call and await the response, operating directly on a
/// writer and pending map. Used for login during connect/reconnect to avoid
/// re-entering the conn lock held by call().
async fn send_call_direct(
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    pending: &Arc<PendingMap>,
    id: i64,
    method: &str,
    args: Vec<Value>,
    kwargs: Vec<(Value, Value)>,
) -> Result<Value> {
    let (tx, rx) = oneshot::channel();
    pending.lock().unwrap().insert(id, tx);

    let request = Value::List(vec![Value::List(vec![
        Value::Int(id),
        Value::String(method.to_string()),
        Value::List(args),
        Value::Dict(kwargs),
    ])]);
    let encoded = rencode::encode(&request);
    let compressed = zlib_compress(&encoded)?;
    send_frame(writer, &compressed).await?;

    rx.await.map_err(|_| anyhow!("login response channel dropped"))?
}

async fn send_frame(
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    body: &[u8],
) -> Result<()> {
    let mut header = [0u8; 5];
    header[0] = PROTOCOL_VERSION;
    header[1..5].copy_from_slice(&(body.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(body).await?;
    Ok(())
}

async fn read_loop(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    pending: Arc<PendingMap>,
) -> Result<()> {
    let mut buf = BytesMut::new();

    loop {
        let mut tmp = [0u8; 4096];
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            bail!("connection closed by Deluge daemon");
        }
        buf.extend_from_slice(&tmp[..n]);

        // Drain all complete frames from the buffer.
        loop {
            if buf.len() < 5 {
                break;
            }
            let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if length > MAX_FRAME_BYTES {
                bail!(
                    "incoming frame is {length} bytes, exceeding the {} MB limit; \
                     this may indicate a misconfigured or malicious server",
                    MAX_FRAME_BYTES / (1024 * 1024)
                );
            }
            if buf.len() < 5 + length {
                break;
            }
            buf.advance(5);
            let body = buf.split_to(length);

            if let Err(e) = dispatch_frame(&body, &pending) {
                warn!("error dispatching frame: {e}");
            }
        }
    }
}

fn dispatch_frame(body: &[u8], pending: &Arc<PendingMap>) -> Result<()> {
    let decompressed = zlib_decompress(body)?;
    let value = rencode::decode(&decompressed)?;

    let items = match value {
        Value::List(items) => items,
        other => bail!("expected list at top level, got {other:?}"),
    };

    let msg_type = match items.first() {
        Some(Value::Int(n)) => *n,
        other => bail!("expected int message type, got {other:?}"),
    };

    match msg_type {
        RPC_RESPONSE => {
            // [1, request_id, result]
            let id = match items.get(1) {
                Some(Value::Int(n)) => *n,
                _ => bail!("missing request_id in RPC_RESPONSE"),
            };
            let result = items.into_iter().nth(2).unwrap_or(Value::None);
            if let Some(tx) = pending.lock().unwrap().remove(&id) {
                let _ = tx.send(Ok(result));
            }
        }

        RPC_ERROR => {
            // [2, request_id, exception_type, exception_args, exception_kwargs, traceback]
            let id = match items.get(1) {
                Some(Value::Int(n)) => *n,
                _ => bail!("missing request_id in RPC_ERROR"),
            };
            let exc_type = match items.get(2) {
                Some(Value::String(s)) => s.clone(),
                _ => "UnknownError".to_string(),
            };
            let exc_msg = match items.get(3) {
                Some(Value::List(args)) => args
                    .iter()
                    .find_map(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default(),
                _ => String::new(),
            };
            if let Some(tx) = pending.lock().unwrap().remove(&id) {
                let _ = tx.send(Err(anyhow!("{}", enrich_deluge_error(&exc_type, &exc_msg))));
            }
        }

        other => {
            // RPC_EVENT (3) or unknown — log and ignore
            debug!("ignoring message type {other}");
        }
    }

    Ok(())
}

/// Enrich a Deluge RPC exception with an actionable hint for the LLM.
/// Preserves the raw exception text so the LLM retains full context,
/// then appends a [Hint: ...] for known recoverable error types.
fn enrich_deluge_error(exc_type: &str, exc_msg: &str) -> String {
    let hint = match exc_type {
        "InvalidTorrentError" if exc_msg.to_lowercase().contains("already") => Some(
            "This torrent is already in Deluge. Use list_torrents to find its info_hash — do not retry adding it.",
        ),
        "InvalidTorrentError" => Some(
            "The torrent data is invalid or unrecognized. Do not retry with the same input.",
        ),
        "AddTorrentError" => Some(
            "The torrent could not be added. The file may be corrupt or the URL unreachable. Do not retry with the same input.",
        ),
        "InvalidPathError" => Some(
            "The path does not exist on the Deluge server. Verify the path with get_free_space or get_path_size before retrying.",
        ),
        "WrappedException"
            if exc_msg.contains("Errno 2") || exc_msg.contains("No such file") =>
        {
            Some("File or directory not found on the Deluge server. Verify the path exists before retrying.")
        }
        "WrappedException"
            if exc_msg.contains("Errno 13") || exc_msg.contains("Permission denied") =>
        {
            Some("Permission denied on the Deluge server. The Deluge process lacks access to this path. Do not retry.")
        }
        "NotAuthorizedError" => Some(
            "The Deluge connection lacks sufficient permissions for this operation. Do not retry — inform the user.",
        ),
        "BadLoginError" => Some(
            "Deluge authentication failed. Do not retry — inform the user to check their credentials.",
        ),
        _ => None,
    };

    match hint {
        Some(h) => format!("{exc_type}: {exc_msg}\n[Hint: {h}]"),
        None => format!("{exc_type}: {exc_msg}"),
    }
}

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_BYTES as u64 + 1)
        .read_to_end(&mut out)?;
    if out.len() > MAX_DECOMPRESSED_BYTES {
        bail!(
            "decompressed frame exceeds the {} MB limit; \
             this may indicate a misconfigured or malicious server",
            MAX_DECOMPRESSED_BYTES / (1024 * 1024)
        );
    }
    Ok(out)
}
