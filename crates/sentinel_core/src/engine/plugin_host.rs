use crate::engine::EngineEvent;
use crate::ipc::{listen::ListenSpec, protocol::IpcMessage};
use crate::model::ActionCard;
use anyhow::Context;
use sentinel_protocol::Ack;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::mpsc;

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
