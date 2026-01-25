use anyhow::{anyhow, Result};
use sentinel_plugin_sdk::{connect_spec, send_ndjson, IpcMessage, IpcStream, MetricPoint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

async fn read_ack<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(anyhow!("host closed connection before ack"));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("ack line too long"));
        }
    }

    Ok(String::from_utf8_lossy(&buf).trim_end().to_string())
}

async fn send_and_ack<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &IpcMessage,
) -> Result<()> {
    send_ndjson(stream, msg).await?;
    let ack = read_ack(stream).await?;
    println!("ack: {}", ack);
    Ok(())
}

async fn run_stream<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, plugin_id: &str) -> Result<()> {
    send_and_ack(
        &mut stream,
        &IpcMessage::Register {
            plugin_id: plugin_id.to_string(),
        },
    )
    .await?;

    let metrics = vec![MetricPoint {
        source: plugin_id.to_string(),
        label: "Fan Speed".into(),
        value: "100%".into(),
    }];

    send_and_ack(&mut stream, &IpcMessage::PushMetrics { metrics }).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let spec = std::env::var("SENTINEL_IPC")
        .unwrap_or_else(|_| "unix:/tmp/sentinel.sock".to_string());
    let plugin_id = "example.rust";

    eprintln!("[plugin-example] connecting via SENTINEL_IPC={}", spec);

    let stream = connect_spec(&spec).await?;
    match stream {
        IpcStream::Unix(s) => run_stream(s, plugin_id).await?,
        IpcStream::Tcp(s) => run_stream(s, plugin_id).await?,
    }

    Ok(())
}
