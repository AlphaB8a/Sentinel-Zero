use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sentinel_protocol::ListenSpec;
use std::{fs, io::BufReader, sync::Arc};
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
    let key = load_key(&key_file).with_context(|| format!("read key file {}", key_file))?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build tls client config")?;
    Ok(TlsConnector::from(Arc::new(config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path)?;
    let mut reader = BufReader::new(pem.as_slice());
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
    let mut reader = BufReader::new(pem.as_slice());
    let key = rustls_pemfile::private_key(&mut reader)
        .context("parse private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path))?;
    Ok(key)
}
