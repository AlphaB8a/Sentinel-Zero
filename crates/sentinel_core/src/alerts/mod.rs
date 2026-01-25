use sentinel_protocol::{AlertCard, MetricPoint, Severity};
use std::{collections::HashSet, env};
use tracing::info;

pub struct Thresholds {
    pub cpu_temp_c_warn: f32,
    pub gpu_temp_c_warn: f32,
    pub disk_free_pct_warn: f32,
    pub collector_stale_ms: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        let collector_stale_ms = env::var("SENTINEL_OFFLINE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15_000);

        Self {
            cpu_temp_c_warn: 85.0,
            gpu_temp_c_warn: 85.0,
            disk_free_pct_warn: 10.0,
            collector_stale_ms,
        }
    }
}

#[derive(Default)]
pub struct AlertDiffTracker {
    prev_ids: HashSet<String>,
}

impl AlertDiffTracker {
    pub fn log_transitions(&mut self, alerts: &[AlertCard]) {
        let new_ids: HashSet<String> = alerts.iter().map(|a| a.id.clone()).collect();
        for id in new_ids.difference(&self.prev_ids) {
            info!("ALERT_SET {}", id);
        }
        for id in self.prev_ids.difference(&new_ids) {
            info!("ALERT_CLEAR {}", id);
        }
        self.prev_ids = new_ids;
    }
}

pub fn compute_alerts(
    now_ms: u64,
    thresholds: &Thresholds,
    metrics: &[MetricPoint],
    disk_free_pct: Option<f32>,
    plugin_last_seen: &[(String, u64)],
) -> Vec<AlertCard> {
    let mut out = Vec::new();

    let cpu_temp = metric_with_source(metrics, "CPU Temp (C)");
    let gpu0_temp = metric_with_source(metrics, "GPU0 Temp (C)");
    let gpu1_temp = metric_with_source(metrics, "GPU1 Temp (C)");

    if let Some((t, source)) = cpu_temp {
        if t >= thresholds.cpu_temp_c_warn {
            let body = if source != "host" {
                format!("CPU temp {:.1}C ({})", t, source)
            } else {
                format!("CPU temp {:.1}C", t)
            };
            out.push(AlertCard {
                id: "thermal.cpu".into(),
                severity: Severity::Warn,
                title: "CPU hot".into(),
                body,
                ts_ms: now_ms,
                source: Some(source),
            });
        }
    }
    if let Some((t, source)) = gpu0_temp {
        if t >= thresholds.gpu_temp_c_warn {
            let body = if source != "host" {
                format!("GPU0 temp {:.1}C ({})", t, source)
            } else {
                format!("GPU0 temp {:.1}C", t)
            };
            out.push(AlertCard {
                id: "thermal.gpu0".into(),
                severity: Severity::Warn,
                title: "GPU0 hot".into(),
                body,
                ts_ms: now_ms,
                source: Some(source),
            });
        }
    }
    if let Some((t, source)) = gpu1_temp {
        if t >= thresholds.gpu_temp_c_warn {
            let body = if source != "host" {
                format!("GPU1 temp {:.1}C ({})", t, source)
            } else {
                format!("GPU1 temp {:.1}C", t)
            };
            out.push(AlertCard {
                id: "thermal.gpu1".into(),
                severity: Severity::Warn,
                title: "GPU1 hot".into(),
                body,
                ts_ms: now_ms,
                source: Some(source),
            });
        }
    }

    if let Some(pct) = disk_free_pct {
        if pct <= thresholds.disk_free_pct_warn {
            out.push(AlertCard {
                id: "disk.low".into(),
                severity: Severity::Warn,
                title: "Low disk space".into(),
                body: format!("Free {:.1}%", pct),
                ts_ms: now_ms,
                source: Some("host".into()),
            });
        }
    }

    for (plugin_id, last_seen_ms) in plugin_last_seen {
        if now_ms.saturating_sub(*last_seen_ms) > thresholds.collector_stale_ms {
            out.push(AlertCard {
                id: format!("collector.offline.{}", plugin_id),
                severity: Severity::Warn,
                title: "Collector offline".into(),
                body: format!("{} last seen {}ms ago", plugin_id, now_ms - *last_seen_ms),
                ts_ms: now_ms,
                source: Some("host".into()),
            });
        }
    }

    out
}

fn metric_with_source(metrics: &[MetricPoint], label: &str) -> Option<(f32, String)> {
    let sources = ["host", "demo.bridge", "demo"];
    for source in sources {
        if let Some(m) = metrics.iter().find(|m| m.source == source && m.label == label) {
            if let Ok(value) = m.value.trim().parse::<f32>() {
                return Some((value, m.source.clone()));
            }
        }
    }
    None
}
