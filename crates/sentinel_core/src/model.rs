use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
pub use sentinel_protocol::{AlertCard, MetricPoint, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneId {
    Sidebar,
    Dashboard,
    Processes,
    AiConsole,
    Inspector,
}

#[derive(Debug, Clone, Copy)]
pub struct LayoutConfig {
    pub main_split: u16,  // 70
    pub left_split: u16,  // 45
    pub right_split: u16, // 60
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self { main_split: 70, left_split: 45, right_split: 60 }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub cpu: f32,
    pub mem_gb: f32,
    pub disk_free_pct: Option<f32>,
    pub procs: Vec<ProcRow>,
    pub plugins: Vec<MetricPoint>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcRow {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub mem: f32,
}

#[derive(Clone, Debug)]
pub struct ActionCard {
    pub title: String,
    pub cmd: String,
    pub dangerous: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PluginInfo {
    pub plugin_id: String,
    pub caps: Vec<String>,
    pub last_seen_ts_ms: u64,
    pub connected_since_ts_ms: u64,
    pub protocol_version: u32,
    pub sdk_version: String,
    pub schema_hash: Option<String>,
}

#[derive(Default)]
pub struct PluginRegistry {
    pub plugins: HashMap<String, PluginInfo>,
}

#[derive(Default)]
pub struct MetricRegistry {
    pub metrics: BTreeMap<(String, String), MetricPoint>, // (source,label)
}

#[derive(Default)]
pub struct AlertState {
    pub alerts: Vec<AlertCard>,
    pub updated_ts_ms: u64,
}
