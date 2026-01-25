mod listen;

use serde::{Deserialize, Serialize};

pub use listen::ListenSpec;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricPoint {
    pub source: String,
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
    Crit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertCard {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    pub ts_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ack {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_protocol: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_caps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "payload")]
pub enum IpcMessage {
    Hello {
        plugin_id: String,
        protocol_version: u32,
        sdk_version: String,
        capabilities: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_hash: Option<String>,
    },
    Heartbeat {
        plugin_id: String,
        ts_ms: u64,
    },
    Register {
        plugin_id: String,
    },
    PushMetrics {
        metrics: Vec<MetricPoint>,
    },
    PushAlerts {
        alerts: Vec<AlertCard>,
    },
    ProposeAction {
        title: String,
        cmd: String,
        dangerous: bool,
    },
}
