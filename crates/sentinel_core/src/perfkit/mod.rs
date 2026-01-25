use crate::model::AlertCard;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Risk {
    Info,
    Warn,
    Crit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfActionCard {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub risk: Risk,
    pub expected_effect: String,
    pub apply: String,
    pub rollback: String,
    pub proof: String,
}

/// v0.1: deterministic proposals based only on current alerts.
/// No execution. No side effects.
pub fn compute_actions(alerts: &[AlertCard]) -> Vec<PerfActionCard> {
    let mut out = Vec::new();

    // Disk low → cleanup suggestion + (optional) prune suggestion
    if alerts.iter().any(|a| a.id == "disk.low") {
        out.push(PerfActionCard {
            id: "action.disk.cleanup.cache".into(),
            title: "Free disk space (safe cleanup)".into(),
            summary: "Suggest clearing cache directories to regain space.".into(),
            risk: Risk::Info,
            expected_effect: "More free disk space; reduced risk of failed writes.".into(),
            apply: "echo \"Suggested: clear cache dirs (example): rm -rf ~/.cache/*\"".into(),
            rollback: "echo \"Rollback: none (cache cleanup is not reversible)\"".into(),
            proof: "Disk Free (%) increases; disk.low alert clears.".into(),
        });

        out.push(PerfActionCard {
            id: "action.disk.prune.models".into(),
            title: "Prune old models/artifacts (dangerous)".into(),
            summary: "Remove large unused artifacts to reclaim significant space.".into(),
            risk: Risk::Crit,
            expected_effect: "Significant disk recovery; may delete valuable assets.".into(),
            apply: "echo \"Suggested: identify large dirs then delete (manual review required)\""
                .into(),
            rollback: "echo \"Rollback: restore from backup/snapshot\"".into(),
            proof: "Disk Free (%) increases; disk.low alert clears.".into(),
        });
    }

    // Thermal GPU0/GPU1 → power limit suggestion (dangerous)
    if alerts.iter().any(|a| a.id.starts_with("thermal.gpu")) {
        out.push(PerfActionCard {
            id: "action.gpu.powerlimit".into(),
            title: "Reduce GPU power limit (dangerous)".into(),
            summary: "Lower GPU power to reduce heat and throttling.".into(),
            risk: Risk::Warn,
            expected_effect: "Lower temps; may reduce performance.".into(),
            apply: "echo \"Suggested: nvidia-smi -pl <watts> (manual confirm)\"".into(),
            rollback: "echo \"Rollback: restore previous power limit\"".into(),
            proof: "GPU temp decreases; thermal alert clears.".into(),
        });
    }

    // Collector offline → restart suggestion (safe if you have a service; informational otherwise)
    if alerts
        .iter()
        .any(|a| a.id.starts_with("collector.offline."))
    {
        out.push(PerfActionCard {
            id: "action.collector.restart".into(),
            title: "Restart collector".into(),
            summary: "Collector appears offline; restart or relaunch it.".into(),
            risk: Risk::Info,
            expected_effect: "Collector returns; metrics resume; offline alert clears.".into(),
            apply: "echo \"Suggested: restart the collector process/service (manual)\"".into(),
            rollback: "echo \"Rollback: none\"".into(),
            proof: "ALERT_CLEAR collector.offline.* appears; metrics resume.".into(),
        });
    }

    // Deterministic ordering: stable sort by id
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
