use anyhow::Context;
use sentinel_protocol::ListenSpec;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

pub use sentinel_protocol::{Ack, AlertCard, IpcMessage, MetricPoint, Severity};

pub enum IpcStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl IpcStream {
    pub async fn send_ndjson(&mut self, msg: &IpcMessage) -> anyhow::Result<()> {
        match self {
            IpcStream::Unix(stream) => send_ndjson(stream, msg).await,
            IpcStream::Tcp(stream) => send_ndjson(stream, msg).await,
        }
    }
}

pub async fn connect_spec(spec: &str) -> anyhow::Result<IpcStream> {
    match ListenSpec::parse(spec)? {
        ListenSpec::Unix(path) => {
            let stream = UnixStream::connect(&path).await.context("connect unix socket")?;
            Ok(IpcStream::Unix(stream))
        }
        ListenSpec::Tcp(addr) => {
            let stream = TcpStream::connect(addr).await.context("connect tcp socket")?;
            Ok(IpcStream::Tcp(stream))
        }
    }
}

pub async fn connect(path: &str) -> anyhow::Result<UnixStream> {
    UnixStream::connect(path).await.context("connect unix socket")
}

pub async fn send_ndjson<S>(stream: &mut S, msg: &IpcMessage) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    stream.write_all(&line).await.context("write ndjson")
}
