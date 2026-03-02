use anyhow::{anyhow, Result};
use sentinel_plugin_sdk::{connect_spec, send_ndjson, IpcMessage, IpcStream, MetricPoint};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::{sleep, Duration};

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn run_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    plugin_id: &str,
) -> Result<()> {
    send_and_ack(
        &mut stream,
        &IpcMessage::Hello {
            plugin_id: plugin_id.to_string(),
            protocol_version: 1,
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec!["metrics".into()],
            schema_hash: None,
        },
    )
    .await?;

    send_and_ack(
        &mut stream,
        &IpcMessage::Register {
            plugin_id: plugin_id.to_string(),
        },
    )
    .await?;

    let metrics = vec![
        MetricPoint {
            source: plugin_id.to_string(),
            label: "CPU Temp (C)".into(),
            value: "90.0".into(),
        },
        MetricPoint {
            source: plugin_id.to_string(),
            label: "GPU0 Temp (C)".into(),
            value: "90.0".into(),
        },
        MetricPoint {
            source: plugin_id.to_string(),
            label: "GPU1 Temp (C)".into(),
            value: "90.0".into(),
        },
        MetricPoint {
            source: plugin_id.to_string(),
            label: "Disk Free (%)".into(),
            value: "5.0".into(),
        },
        MetricPoint {
            source: plugin_id.to_string(),
            label: "Net Up (Mbps)".into(),
            value: "120.0".into(),
        },
        MetricPoint {
            source: plugin_id.to_string(),
            label: "Net Down (Mbps)".into(),
            value: "45.0".into(),
        },
    ];

    send_and_ack(&mut stream, &IpcMessage::PushMetrics { metrics }).await?;

    for _ in 0..2 {
        send_and_ack(
            &mut stream,
            &IpcMessage::Heartbeat {
                plugin_id: plugin_id.to_string(),
                ts_ms: now_ms(),
            },
        )
        .await?;
        sleep(Duration::from_millis(750)).await;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let spec =
        std::env::var("SENTINEL_IPC").unwrap_or_else(|_| "unix:/tmp/sentinel.sock".to_string());
    let plugin_id = "demo.bridge";

    eprintln!("[plugin-demo] connecting via SENTINEL_IPC={}", spec);

    let stream = connect_spec(&spec).await?;
    match stream {
        IpcStream::Unix(s) => run_stream(s, plugin_id).await?,
        IpcStream::Tcp(s) => run_stream(s, plugin_id).await?,
        IpcStream::TcpTls(s) => run_stream(s, plugin_id).await?,
    }

    Ok(())
}
