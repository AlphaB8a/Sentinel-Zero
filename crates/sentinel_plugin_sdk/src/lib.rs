use anyhow::Context;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sentinel_protocol::ListenSpec;
use std::{fs, sync::Arc};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub use sentinel_protocol::{Ack, AlertCard, IpcMessage, MetricPoint, Severity};

pub enum IpcStream {
    Unix(UnixStream),
    Tcp(TcpStream),
    TcpTls(Box<TlsStream<TcpStream>>),
}

impl IpcStream {
    pub async fn send_ndjson(&mut self, msg: &IpcMessage) -> anyhow::Result<()> {
        match self {
            IpcStream::Unix(stream) => send_ndjson(stream, msg).await,
            IpcStream::Tcp(stream) => send_ndjson(stream, msg).await,
            IpcStream::TcpTls(stream) => send_ndjson(stream, msg).await,
        }
    }
}

pub async fn connect_spec(spec: &str) -> anyhow::Result<IpcStream> {
    match ListenSpec::parse(spec)? {
        ListenSpec::Unix(path) => {
            let stream = UnixStream::connect(&path)
                .await
                .context("connect unix socket")?;
            Ok(IpcStream::Unix(stream))
        }
        ListenSpec::Tcp(addr) => {
            let stream = TcpStream::connect(addr)
                .await
                .context("connect tcp socket")?;
            Ok(IpcStream::Tcp(stream))
        }
        ListenSpec::TcpTls(addr) => {
            let stream = TcpStream::connect(addr)
                .await
                .context("connect tcp+tls socket")?;
            let connector = tls_connector_from_env()?;
            let server_name_str = std::env::var("SENTINEL_TLS_SERVER_NAME")
                .unwrap_or_else(|_| "localhost".to_string());
            let server_name = ServerName::try_from(server_name_str.clone())
                .context("invalid SENTINEL_TLS_SERVER_NAME")?;
            let stream = connector
                .connect(server_name, stream)
                .await
                .with_context(|| format!("tls handshake failed for {}", server_name_str))?;
            Ok(IpcStream::TcpTls(Box::new(stream)))
        }
    }
}

pub async fn connect(path: &str) -> anyhow::Result<UnixStream> {
    UnixStream::connect(path)
        .await
        .context("connect unix socket")
}

pub async fn send_ndjson<S>(stream: &mut S, msg: &IpcMessage) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    stream.write_all(&line).await.context("write ndjson")
}

fn tls_connector_from_env() -> anyhow::Result<TlsConnector> {
    let cert_file = std::env::var("SENTINEL_TLS_CERT_FILE")
        .context("SENTINEL_TLS_CERT_FILE required for tcp+tls")?;
    let key_file = std::env::var("SENTINEL_TLS_KEY_FILE")
        .context("SENTINEL_TLS_KEY_FILE required for tcp+tls")?;
    let ca_file = std::env::var("SENTINEL_TLS_CA_FILE")
        .context("SENTINEL_TLS_CA_FILE required for tcp+tls")?;

    let mut roots = RootCertStore::empty();
    for cert in load_certs(&ca_file).with_context(|| format!("read CA file {}", ca_file))? {
        roots
            .add(cert)
            .with_context(|| format!("add CA cert from {}", ca_file))?;
    }

    let certs = load_certs(&cert_file).with_context(|| format!("read cert file {}", cert_file))?;
    validate_tls_key_permissions(&key_file)?;
    let key = load_key(&key_file).with_context(|| format!("read key file {}", key_file))?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build tls client config")?;
    Ok(TlsConnector::from(Arc::new(config)))
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
