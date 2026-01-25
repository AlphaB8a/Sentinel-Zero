use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub api_version: String,
    pub plan_id: String,
    pub profile: Profile,
    pub created_ts: u64,
    pub author: String,
    pub description: String,

    pub targets: Targets,
    pub policy: Policy,
    pub changes: Changes,
    pub verification: Verification,
    pub rollback: Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub os_family: OsFamily,
    pub kernel_series: Option<String>,
    pub hardware_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub apply_mode: ApplyMode,
    pub risk_level: RiskLevel,
    pub require_tty_confirm: bool,
    pub forbid_remote_apply: bool,
    pub allowlist_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Changes {
    pub kernel_cmdline: KernelCmdline,
    pub sysctl: Sysctl,
    pub systemd: Systemd,
    pub udev: Udev,
    pub zram: Zram,
    pub nvidia: Nvidia,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelCmdline {
    pub enabled: bool,
    pub fragment_path: String,
    pub require_reboot: bool,
    pub params: CmdlineParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmdlineParams {
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sysctl {
    pub enabled: bool,
    pub file_path: String,
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Systemd {
    pub enabled: bool,
    pub dropins: Vec<SystemdDropin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdDropin {
    pub unit: String,
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Udev {
    pub enabled: bool,
    pub rules_path: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zram {
    pub enabled: bool,
    pub mode: ZramMode,
    pub config_path: String,
    pub settings: BTreeMap<String, ZramDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZramDevice {
    pub zram_size: String,
    pub compression: String,
    pub swap_priority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nvidia {
    pub enabled: bool,
    pub settings: NvidiaSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvidiaSettings {
    pub persistence_mode: Option<bool>,
    pub power_limit_watts: Option<u32>,
    pub compute_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub preflight_checks: Vec<String>,
    pub postflight_checks: Vec<String>,
    pub sentinel_emit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    pub strategy: RollbackStrategy,
    pub snapshot_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    SiliconConstrainedNomad,
    SovereignIntelligenceArchitect,
    ImmutableOperator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Ubuntu,
    Debian,
    Fedora,
    Arch,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyMode {
    ProposeOnly,
    ApplyWithConfirm,
    ApplyUnattended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZramMode {
    SystemdZramGenerator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStrategy {
    RestorePrevious,
    ExplicitInverse,
}
