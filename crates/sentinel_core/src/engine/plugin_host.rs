use crate::engine::EngineEvent;
use crate::ipc::{listen::ListenSpec, protocol::IpcMessage};
use crate::model::ActionCard;
use anyhow::Context;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use sentinel_protocol::Ack;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

const DEFAULT_IPC_MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_IPC_MAX_LINE_BYTES: usize = 1024 * 1024;
const DEFAULT_IPC_READ_TIMEOUT_MS: u64 = 30_000;
const MAX_IPC_READ_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_IPC_MAX_MESSAGES_PER_CONN: u64 = 10_000;
const MAX_IPC_MAX_MESSAGES_PER_CONN: u64 = 1_000_000;
const SENTINEL_ALLOW_NON_LOOPBACK_BIND: &str = "SENTINEL_ALLOW_NON_LOOPBACK_BIND";
const SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS: &str = "SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS";

/// Minimal NDJSON plugin host. Production hardening will:
/// - bind under /run/user/$UID with 0700 dir, 0600 socket
/// - enforce max line length and rate limits
pub async fn run_ipc(listen_spec: &str, tx: mpsc::Sender<EngineEvent>) -> anyhow::Result<()> {
    let listen = ListenSpec::parse(listen_spec).context("parse listen spec")?;
    enforce_bind_policy(&listen)?;
    let max_line_bytes = ipc_max_line_bytes()?;
    let read_timeout = ipc_read_timeout()?;
    let max_messages_per_conn = ipc_max_messages_per_conn()?;

    match listen {
        ListenSpec::Unix(path) => {
            prepare_unix_socket_path(&path)?;
            let listener = UnixListener::bind(&path)
                .with_context(|| format!("bind unix socket {}", path.display()))?;
            secure_unix_socket_permissions(&path)?;

            loop {
                let (stream, _) = listener.accept().await?;
                let tx = tx.clone();
                tokio::spawn(async move {
                    handle_stream(
                        stream,
                        tx,
                        max_line_bytes,
                        read_timeout,
                        max_messages_per_conn,
                    )
                    .await;
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
                    handle_stream(
                        stream,
                        tx,
                        max_line_bytes,
                        read_timeout,
                        max_messages_per_conn,
                    )
                    .await;
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
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_stream(
                                tls_stream,
                                tx,
                                max_line_bytes,
                                read_timeout,
                                max_messages_per_conn,
                            )
                            .await;
                        }
                        Err(err) => {
                            let _ = tx
                                .send(EngineEvent::PluginLog(format!(
                                    "TLS handshake rejected: {}",
                                    err
                                )))
                                .await;
                        }
                    }
                });
            }
        }
    }
}

async fn handle_stream<S>(
    stream: S,
    tx: mpsc::Sender<EngineEvent>,
    max_line_bytes: usize,
    read_timeout: Duration,
    max_messages_per_conn: u64,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line_buf = Vec::with_capacity(max_line_bytes.min(4096));
    let mut message_count = 0u64;

    loop {
        if message_count >= max_messages_per_conn {
            write_ack(
                &mut writer,
                Ack {
                    status: "bad_request".into(),
                    error: Some("message_limit_exceeded".into()),
                    ..Default::default()
                },
            )
            .await;
            return;
        }
        line_buf.clear();
        loop {
            let mut byte = [0u8; 1];
            let n = match timeout(read_timeout, reader.read(&mut byte)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => return,
                Err(_) => {
                    let _ = tx
                        .send(EngineEvent::PluginLog(
                            "plugin stream read timeout; disconnecting".to_string(),
                        ))
                        .await;
                    return;
                }
            };
            if n == 0 {
                break;
            }
            if line_buf.len() < max_line_bytes + 1 {
                line_buf.push(byte[0]);
            }
            if byte[0] == b'\n' || line_buf.len() > max_line_bytes {
                break;
            }
        }
        if line_buf.is_empty() {
            return;
        }
        message_count = message_count.saturating_add(1);
        if line_buf.len() > max_line_bytes {
            write_ack(
                &mut writer,
                Ack {
                    status: "bad_request".into(),
                    error: Some("line_too_long".into()),
                    ..Default::default()
                },
            )
            .await;
            return;
        }

        let line = match std::str::from_utf8(&line_buf) {
            Ok(line) => line.trim_end(),
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
        let mut value = match serde_json::from_str::<Value>(line) {
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
    validate_tls_key_permissions(&key_file)?;
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
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs")?;
    if certs.is_empty() {
        anyhow::bail!("no certs found in {}", path);
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let pem = fs::read(path)?;
    let key = PrivateKeyDer::from_pem_slice(&pem).context("parse private key")?;
    Ok(key)
}

fn validate_tls_key_permissions(path: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var("SENTINEL_TLS_ALLOW_INSECURE_KEY_PERMS")
            .ok()
            .as_deref()
            == Some("1")
        {
            return Ok(());
        }
        let link_meta =
            fs::symlink_metadata(path).with_context(|| format!("tls key metadata {}", path))?;
        if link_meta.file_type().is_symlink() {
            anyhow::bail!("tls key file must not be a symlink: {}", path);
        }
        let meta = fs::metadata(path).with_context(|| format!("tls key metadata {}", path))?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "tls key file must not be group/world accessible: {} mode={:o}",
                path,
                mode & 0o777
            );
        }
    }
    Ok(())
}

fn enforce_bind_policy(listen: &ListenSpec) -> anyhow::Result<()> {
    match listen {
        ListenSpec::Unix(path) => ensure_unix_socket_parent_secure(path),
        ListenSpec::Tcp(addr) | ListenSpec::TcpTls(addr) => {
            let allow_non_loopback = env_flag(SENTINEL_ALLOW_NON_LOOPBACK_BIND);
            validate_bind_address(*addr, allow_non_loopback)
        }
    }
}

fn validate_bind_address(
    addr: std::net::SocketAddr,
    allow_non_loopback: bool,
) -> anyhow::Result<()> {
    if addr.ip().is_loopback() || allow_non_loopback {
        return Ok(());
    }
    anyhow::bail!(
        "non-loopback bind denied for {}; set {}=1 to override",
        addr,
        SENTINEL_ALLOW_NON_LOOPBACK_BIND
    );
}

fn prepare_unix_socket_path(path: &Path) -> anyhow::Result<()> {
    ensure_unix_socket_parent_secure(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    anyhow::bail!(
                        "refusing to remove non-socket path before bind: {}",
                        path.display()
                    );
                }
            }
            fs::remove_file(path)
                .with_context(|| format!("remove stale socket path {}", path.display()))?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("inspect existing socket path {}", path.display()))
        }
    }
}

fn ensure_unix_socket_parent_secure(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unix socket path has no parent: {}", path.display()))?;
    if !parent.exists() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket parent directory {}", parent.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if env_flag(SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS) {
            return Ok(());
        }
        let meta = fs::metadata(parent)
            .with_context(|| format!("stat socket parent directory {}", parent.display()))?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "socket parent must not be group/world accessible: {} mode={:o}; set {}=1 to override",
                parent.display(),
                mode & 0o777,
                SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS
            );
        }
    }
    Ok(())
}

fn secure_unix_socket_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("stat unix socket {}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .with_context(|| format!("set unix socket perms {}", path.display()))?;
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn ipc_max_line_bytes() -> anyhow::Result<usize> {
    match std::env::var("SENTINEL_IPC_MAX_LINE_BYTES") {
        Ok(raw) => parse_ipc_max_line_bytes(&raw),
        Err(_) => Ok(DEFAULT_IPC_MAX_LINE_BYTES),
    }
}

fn ipc_read_timeout() -> anyhow::Result<Duration> {
    match std::env::var("SENTINEL_IPC_READ_TIMEOUT_MS") {
        Ok(raw) => parse_ipc_read_timeout_ms(&raw).map(Duration::from_millis),
        Err(_) => Ok(Duration::from_millis(DEFAULT_IPC_READ_TIMEOUT_MS)),
    }
}

fn ipc_max_messages_per_conn() -> anyhow::Result<u64> {
    match std::env::var("SENTINEL_IPC_MAX_MESSAGES_PER_CONN") {
        Ok(raw) => parse_ipc_max_messages_per_conn(&raw),
        Err(_) => Ok(DEFAULT_IPC_MAX_MESSAGES_PER_CONN),
    }
}

fn parse_ipc_max_line_bytes(raw: &str) -> anyhow::Result<usize> {
    let parsed = raw
        .parse::<usize>()
        .with_context(|| "SENTINEL_IPC_MAX_LINE_BYTES must be an integer")?;
    if !(1024..=MAX_IPC_MAX_LINE_BYTES).contains(&parsed) {
        anyhow::bail!(
            "SENTINEL_IPC_MAX_LINE_BYTES must be in [1024, {}]",
            MAX_IPC_MAX_LINE_BYTES
        );
    }
    Ok(parsed)
}

fn parse_ipc_read_timeout_ms(raw: &str) -> anyhow::Result<u64> {
    let parsed = raw
        .parse::<u64>()
        .with_context(|| "SENTINEL_IPC_READ_TIMEOUT_MS must be an integer")?;
    if !(1000..=MAX_IPC_READ_TIMEOUT_MS).contains(&parsed) {
        anyhow::bail!(
            "SENTINEL_IPC_READ_TIMEOUT_MS must be in [1000, {}]",
            MAX_IPC_READ_TIMEOUT_MS
        );
    }
    Ok(parsed)
}

fn parse_ipc_max_messages_per_conn(raw: &str) -> anyhow::Result<u64> {
    let parsed = raw
        .parse::<u64>()
        .with_context(|| "SENTINEL_IPC_MAX_MESSAGES_PER_CONN must be an integer")?;
    if !(1..=MAX_IPC_MAX_MESSAGES_PER_CONN).contains(&parsed) {
        anyhow::bail!(
            "SENTINEL_IPC_MAX_MESSAGES_PER_CONN must be in [1, {}]",
            MAX_IPC_MAX_MESSAGES_PER_CONN
        );
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    #[test]
    fn parse_ipc_max_line_bytes_bounds() {
        assert_eq!(parse_ipc_max_line_bytes("1024").expect("lower bound"), 1024);
        assert!(parse_ipc_max_line_bytes("999").is_err());
        assert!(parse_ipc_max_line_bytes("not-a-number").is_err());
    }

    #[test]
    fn parse_ipc_read_timeout_bounds() {
        assert_eq!(
            parse_ipc_read_timeout_ms("1000").expect("lower bound"),
            1000
        );
        assert!(parse_ipc_read_timeout_ms("999").is_err());
        assert!(parse_ipc_read_timeout_ms("nan").is_err());
    }

    #[test]
    fn parse_ipc_max_messages_per_conn_bounds() {
        assert_eq!(
            parse_ipc_max_messages_per_conn("1").expect("lower bound"),
            1
        );
        assert!(parse_ipc_max_messages_per_conn("0").is_err());
        assert!(parse_ipc_max_messages_per_conn("x").is_err());
    }

    #[test]
    fn bind_policy_rejects_non_loopback_without_override() {
        let addr: SocketAddr = "0.0.0.0:7777".parse().expect("addr");
        assert!(validate_bind_address(addr, false).is_err());
    }

    #[test]
    fn bind_policy_allows_non_loopback_with_override() {
        let addr: SocketAddr = "0.0.0.0:7777".parse().expect("addr");
        assert!(validate_bind_address(addr, true).is_ok());
    }

    #[test]
    fn bind_policy_allows_loopback_by_default() {
        let addr: SocketAddr = "127.0.0.1:7777".parse().expect("addr");
        assert!(validate_bind_address(addr, false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_unix_socket_path_rejects_regular_file() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("prepare_unix_socket_path_rejects_regular_file");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let sock_path = dir.join("sentinel.sock");
        fs::write(&sock_path, "not-a-socket").expect("write");
        let err = prepare_unix_socket_path(&sock_path).expect_err("must reject regular file");
        assert!(err.to_string().contains("non-socket"));
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_unix_socket_parent_secure_rejects_world_writable() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("ensure_unix_socket_parent_secure_rejects_world_writable");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod");
        let sock_path = dir.join("sentinel.sock");
        let err = ensure_unix_socket_parent_secure(&sock_path).expect_err("must reject perms");
        assert!(err
            .to_string()
            .contains("must not be group/world accessible"));
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn unique_test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sentinel_core_{}_{}_{}",
            label,
            std::process::id(),
            now_ms()
        ));
        path
    }
}
