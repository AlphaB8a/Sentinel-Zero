use crate::engine::EngineEvent;
use crate::ipc::{listen::ListenSpec, protocol::IpcMessage};
use crate::model::ActionCard;
use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use sentinel_protocol::Ack;
use serde_json::Value;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

/// Minimal NDJSON plugin host. Production hardening will:
/// - bind under /run/user/$UID with 0700 dir, 0600 socket
/// - enforce max line length and rate limits
pub async fn run_ipc(listen_spec: &str, tx: mpsc::Sender<EngineEvent>) -> anyhow::Result<()> {
    let listen = ListenSpec::parse(listen_spec).context("parse listen spec")?;

    match listen {
        ListenSpec::Unix(path) => {
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)
                .with_context(|| format!("bind unix socket {}", path.display()))?;

            loop {
                let (stream, _) = listener.accept().await?;
                let tx = tx.clone();
                tokio::spawn(async move {
                    handle_stream(stream, tx).await;
                });
            }
        }
        ListenSpec::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind tcp {}", addr))?;

            loop {
                let (stream, _) = listener.accept().await?;
                let tx = tx.clone();
                tokio::spawn(async move {
                    handle_stream(stream, tx).await;
                });
            }
        }
        ListenSpec::TcpTls(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind tcp+tls {}", addr))?;
            let acceptor = tls_acceptor_from_env()?;

            loop {
                let (stream, _) = listener.accept().await?;
                let tx = tx.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        handle_stream(tls_stream, tx).await;
                    }
                });
            }
        }
    }
}

async fn handle_stream<S>(stream: S, tx: mpsc::Sender<EngineEvent>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let mut value = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(_) => {
                write_ack(
                    &mut writer,
                    Ack {
                        status: "bad_request".into(),
                        error: Some("bad_request".into()),
                        ..Default::default()
                    },
                )
                .await;
                continue;
            }
        };

        let mut id = None;
        if let Value::Object(obj) = &mut value {
            if let Some(Value::String(id_value)) = obj.get("id") {
                id = Some(id_value.clone());
            }
            obj.remove("id");
            obj.remove("v");
        }

        if let Ok(msg) = serde_json::from_value::<IpcMessage>(value) {
            let now_ms = now_ms();
            match msg {
                IpcMessage::Hello {
                    plugin_id,
                    protocol_version,
                    sdk_version,
                    capabilities,
                    schema_hash,
                } => {
                    let host_caps = ["metrics", "alerts", "actions", "heartbeat"];
                    let negotiated_caps: Vec<String> = capabilities
                        .iter()
                        .filter(|cap| host_caps.contains(&cap.as_str()))
                        .cloned()
                        .collect();

                    let _ = tx
                        .send(EngineEvent::PluginHello {
                            plugin_id: plugin_id.clone(),
                            protocol_version,
                            sdk_version,
                            capabilities: capabilities.clone(),
                            schema_hash,
                            ts_ms: now_ms,
                        })
                        .await;
                    let _ = tx
                        .send(EngineEvent::PluginLog(format!(
                            "Plugin hello: {}",
                            plugin_id
                        )))
                        .await;

                    let ack = Ack {
                        status: "ok".into(),
                        server_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                        required_protocol: Some(1),
                        negotiated_caps: Some(negotiated_caps),
                        id,
                        ..Default::default()
                    };
                    write_ack(&mut writer, ack).await;
                    continue;
                }
                IpcMessage::Heartbeat {
                    plugin_id,
                    ts_ms: _,
                } => {
                    let _ = tx
                        .send(EngineEvent::PluginHeartbeat {
                            plugin_id: plugin_id.clone(),
                            ts_ms: now_ms,
                        })
                        .await;
                    let _ = tx
                        .send(EngineEvent::PluginLog(format!("Heartbeat: {}", plugin_id)))
                        .await;

                    let ack = Ack {
                        status: "ok".into(),
                        id,
                        ..Default::default()
                    };
                    write_ack(&mut writer, ack).await;
                    continue;
                }
                IpcMessage::Register { plugin_id } => {
                    let _ = tx
                        .send(EngineEvent::PluginLog(format!(
                            "Plugin attached: {}",
                            plugin_id
                        )))
                        .await;
                }
                IpcMessage::PushMetrics { metrics } => {
                    let _ = tx.send(EngineEvent::PluginMetric(metrics)).await;
                }
                IpcMessage::PushAlerts { alerts } => {
                    let _ = tx.send(EngineEvent::PluginAlerts(alerts)).await;
                }
                IpcMessage::ProposeAction {
                    title,
                    cmd,
                    dangerous,
                } => {
                    let _ = tx
                        .send(EngineEvent::PluginAction(ActionCard {
                            title,
                            cmd,
                            dangerous,
                        }))
                        .await;
                }
            }
            let ack = Ack {
                status: "ok".into(),
                id,
                ..Default::default()
            };
            write_ack(&mut writer, ack).await;
        } else {
            let ack = Ack {
                status: "bad_request".into(),
                error: Some("bad_request".into()),
                id,
                ..Default::default()
            };
            write_ack(&mut writer, ack).await;
        }
    }
}

async fn write_ack<W: AsyncWrite + Unpin>(writer: &mut W, ack: Ack) {
    let mut line = serde_json::to_vec(&ack)
        .unwrap_or_else(|_| b"{\"status\":\"bad_request\",\"error\":\"encode_failed\"}".to_vec());
    line.push(b'\n');
    let _ = writer.write_all(&line).await;
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn tls_acceptor_from_env() -> anyhow::Result<TlsAcceptor> {
    let cert_file = std::env::var("SENTINEL_TLS_CERT_FILE")
        .context("SENTINEL_TLS_CERT_FILE required for tcp+tls")?;
    let key_file = std::env::var("SENTINEL_TLS_KEY_FILE")
        .context("SENTINEL_TLS_KEY_FILE required for tcp+tls")?;
    let ca_file = std::env::var("SENTINEL_TLS_CA_FILE")
        .context("SENTINEL_TLS_CA_FILE required for tcp+tls")?;

    let certs = load_certs(&cert_file).with_context(|| format!("read cert file {}", cert_file))?;
    let key = load_key(&key_file).with_context(|| format!("read key file {}", key_file))?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&ca_file).with_context(|| format!("read CA file {}", ca_file))? {
        roots
            .add(cert)
            .with_context(|| format!("add CA cert from {}", ca_file))?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build mTLS client verifier")?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("build tls server config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path)?;
    let mut reader = StdBufReader::new(pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs")?;
    if certs.is_empty() {
        anyhow::bail!("no certs found in {}", path);
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let pem = fs::read(path)?;
    let mut reader = StdBufReader::new(pem.as_slice());
    let key = rustls_pemfile::private_key(&mut reader)
        .context("parse private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path))?;
    Ok(key)
}
