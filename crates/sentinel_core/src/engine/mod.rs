pub mod physics;
pub mod plugin_host;

use crate::model::{ActionCard, AlertCard, MetricPoint, Snapshot};
use crate::perfkit::PerfActionCard;

#[derive(Debug)]
pub enum EngineEvent {
    Physics(Snapshot),
    PluginLog(String),
    PluginMetric(Vec<MetricPoint>),
    PluginAction(ActionCard),
    PluginHello {
        plugin_id: String,
        protocol_version: u32,
        sdk_version: String,
        capabilities: Vec<String>,
        schema_hash: Option<String>,
        ts_ms: u64,
    },
    PluginHeartbeat { plugin_id: String, ts_ms: u64 },
    PluginAlerts(Vec<AlertCard>),
    ActionCards(Vec<PerfActionCard>),
}
