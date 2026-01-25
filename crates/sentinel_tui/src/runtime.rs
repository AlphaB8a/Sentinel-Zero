use crate::{ingest_host_metrics, ingest_metrics, now_ms, touch_plugin, AppState};
use sentinel_core::{
    alerts::{compute_alerts, AlertDiffTracker, Thresholds},
    engine,
    model::{AlertState, LayoutConfig, MetricRegistry, PluginInfo, PluginRegistry, Snapshot},
    perfkit::compute_actions,
};
use std::{collections::HashMap, time::{Duration, Instant}};
use tokio::sync::mpsc;

pub fn init_app_state<'a>() -> AppState<'a> {
    let mut app = AppState {
        should_quit: false,
        active_pane: sentinel_core::model::PaneId::AiConsole,
        ui_mode: crate::UiMode::Normal,
        layout: LayoutConfig::default(),
        snapshot: Snapshot::default(),
        ai_input: tui_textarea::TextArea::default(),
        ai_log: vec![("System".into(), "Sentinel Kernel Online.".into())],
        action_queue: vec![],
        actions: Vec::new(),
        metric_registry: MetricRegistry::default(),
        metrics_latest: HashMap::new(),
        plugin_registry: PluginRegistry::default(),
        alert_state: AlertState::default(),
        plugin_alerts: Vec::new(),
    };
    app.ai_input.set_block(ratatui::widgets::Block::default().borders(ratatui::widgets::Borders::ALL));
    app
}

pub fn handle_engine_event(app: &mut AppState, evt: engine::EngineEvent) {
    match evt {
        engine::EngineEvent::Physics(mut snap) => {
            // merge plugin metrics (flatten current registry)
            if !app.metric_registry.metrics.is_empty() {
                snap.plugins = app.metric_registry.metrics.values().cloned().collect();
            }
            ingest_host_metrics(app, &snap);
            app.snapshot = snap;
        }
        engine::EngineEvent::PluginLog(msg) => app.ai_log.push(("Plugin".into(), msg)),
        engine::EngineEvent::PluginMetric(metrics) => {
            ingest_metrics(app, metrics.clone());
            for m in metrics {
                let ts_ms = now_ms();
                touch_plugin(&mut app.plugin_registry, &m.source, ts_ms);
                app.metric_registry.metrics.insert((m.source.clone(), m.label.clone()), m);
            }
        }
        engine::EngineEvent::PluginAction(a) => app.action_queue.push(a),
        engine::EngineEvent::PluginHello {
            plugin_id,
            protocol_version,
            sdk_version,
            capabilities,
            schema_hash,
            ts_ms,
        } => {
            let entry = app
                .plugin_registry
                .plugins
                .entry(plugin_id.clone())
                .or_insert_with(|| PluginInfo {
                    plugin_id: plugin_id.clone(),
                    connected_since_ts_ms: ts_ms,
                    ..Default::default()
                });
            entry.protocol_version = protocol_version;
            entry.sdk_version = sdk_version;
            entry.caps = capabilities;
            entry.schema_hash = schema_hash;
            entry.last_seen_ts_ms = ts_ms;
        }
        engine::EngineEvent::PluginHeartbeat { plugin_id, ts_ms } => {
            touch_plugin(&mut app.plugin_registry, &plugin_id, ts_ms);
        }
        engine::EngineEvent::PluginAlerts(alerts) => {
            app.plugin_alerts = alerts;
        }
        engine::EngineEvent::ActionCards(cards) => {
            app.actions = cards;
        }
    }
}

pub struct AlertEvaluator {
    thresholds: Thresholds,
    alert_diff: AlertDiffTracker,
    last_eval: Instant,
    tx: mpsc::Sender<engine::EngineEvent>,
}

impl AlertEvaluator {
    pub fn new(tx: mpsc::Sender<engine::EngineEvent>) -> Self {
        Self {
            thresholds: Thresholds::default(),
            alert_diff: AlertDiffTracker::default(),
            last_eval: Instant::now(),
            tx,
        }
    }

    pub fn maybe_eval(&mut self, app: &mut AppState) {
        if self.last_eval.elapsed() < Duration::from_secs(1) {
            return;
        }

        let metrics: Vec<_> = app.metric_registry.metrics.values().cloned().collect();
        let plugin_last_seen: Vec<(String, u64)> = app
            .plugin_registry
            .plugins
            .iter()
            .map(|(id, info)| (id.clone(), info.last_seen_ts_ms))
            .collect();
        let now = now_ms();
        let mut alerts = compute_alerts(
            now,
            &self.thresholds,
            &metrics,
            app.snapshot.disk_free_pct,
            &plugin_last_seen,
        );
        alerts.extend(app.plugin_alerts.clone());
        self.alert_diff.log_transitions(&alerts);
        app.alert_state.alerts = alerts;
        app.alert_state.updated_ts_ms = now;
        let actions = compute_actions(&app.alert_state.alerts);
        let _ = self.tx.try_send(engine::EngineEvent::ActionCards(actions));
        self.last_eval = Instant::now();
    }
}
