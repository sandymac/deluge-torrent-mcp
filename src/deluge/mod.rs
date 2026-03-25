// Deluge RPC client — connection, authentication, and method wrappers.

mod tls;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BytesMut};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_rustls::client::TlsStream;
use tracing::{debug, warn};

use crate::rencode::{self, Value};

const PROTOCOL_VERSION: u8 = 1;
const RPC_RESPONSE: i64 = 1;
const RPC_ERROR: i64 = 2;
// RPC_EVENT = 3 — server-initiated, ignored for now

type PendingMap = Mutex<HashMap<i64, oneshot::Sender<Result<Value>>>>;

pub struct DelugeClient {
    writer: AsyncMutex<WriteHalf<TlsStream<TcpStream>>>,
    pending: Arc<PendingMap>,
    next_id: AtomicI64,
}

impl DelugeClient {
    /// Connect to a Deluge daemon via TLS TCP.
    ///
    /// If `cert_fingerprint` is None the server certificate is accepted without
    /// verification and its SHA-256 fingerprint is logged at WARN level so the
    /// user can copy-paste it for future pinning.
    pub async fn connect(
        host: &str,
        port: u16,
        cert_fingerprint: Option<String>,
    ) -> Result<Arc<Self>> {
        // Install the default crypto provider if not already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let verifier = Arc::new(tls::CertVerifier::new(cert_fingerprint));
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect((host, port)).await?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("invalid server name '{host}': {e}"))?;
        let tls = connector.connect(server_name, tcp).await?;

        let (reader, writer) = tokio::io::split(tls);
        let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));

        let client = Arc::new(Self {
            writer: AsyncMutex::new(writer),
            pending: pending.clone(),
            next_id: AtomicI64::new(1),
        });

        // Background task: reads frames and dispatches responses to waiters.
        tokio::spawn(async move {
            if let Err(e) = read_loop(reader, pending).await {
                warn!("Deluge read loop terminated: {e}");
            }
        });

        Ok(client)
    }

    /// Authenticate with the Deluge daemon. Returns the granted auth level (0–10).
    pub async fn login(&self, username: &str, password: &str) -> Result<i64> {
        let result = self
            .call(
                "daemon.login",
                vec![
                    Value::String(username.to_string()),
                    Value::String(password.to_string()),
                ],
                vec![(
                    Value::String("client_version".to_string()),
                    Value::String("2.0.0".to_string()),
                )],
            )
            .await?;
        match result {
            Value::Int(level) => Ok(level),
            other => bail!("unexpected login result: {other:?}"),
        }
    }

    /// Send an RPC call and wait for the response.
    pub async fn call(
        &self,
        method: &str,
        args: Vec<Value>,
        kwargs: Vec<(Value, Value)>,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        // Wire format: a list containing one request tuple
        let request = Value::List(vec![Value::List(vec![
            Value::Int(id),
            Value::String(method.to_string()),
            Value::List(args),
            Value::Dict(kwargs),
        ])]);

        let encoded = rencode::encode(&request);
        let compressed = zlib_compress(&encoded)?;

        send_frame(&mut *self.writer.lock().await, &compressed).await?;

        rx.await
            .map_err(|_| anyhow!("response channel dropped for request {id}"))?
    }
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
                let _ = tx.send(Err(anyhow!("{exc_type}: {exc_msg}")));
            }
        }

        other => {
            // RPC_EVENT (3) or unknown — log and ignore
            debug!("ignoring message type {other}");
        }
    }

    Ok(())
}

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}
