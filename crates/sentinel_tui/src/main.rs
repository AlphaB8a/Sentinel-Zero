mod runtime;
mod ui;

use anyhow::Result;
use ratatui::crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use sentinel_core::{
    engine,
    model::{
        AlertCard, AlertState, LayoutConfig, MetricRegistry, PaneId, PluginInfo, PluginRegistry,
        Snapshot,
    },
};
use std::{
    collections::HashMap,
    io::{self, IsTerminal},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiMode {
    Normal,
    Bridge,
}

pub struct AppState<'a> {
    pub should_quit: bool,
    pub active_pane: PaneId,
    pub ui_mode: UiMode,
    pub layout: LayoutConfig,
    pub snapshot: Snapshot,

    pub ai_input: tui_textarea::TextArea<'a>,
    pub ai_log: Vec<(String, String)>,
    pub action_queue: Vec<sentinel_core::model::ActionCard>,
    pub actions: Vec<sentinel_core::perfkit::PerfActionCard>,

    pub metric_registry: MetricRegistry,
    pub metrics_latest: HashMap<(String, String), String>,
    pub plugin_registry: PluginRegistry,
    pub alert_state: AlertState,
    pub plugin_alerts: Vec<AlertCard>,
}

fn has_tty() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn parse_options() -> (bool, String) {
    let mut headless = std::env::var("SENTINEL_HEADLESS").ok().as_deref() == Some("1");
    let mut listen_spec =
        std::env::var("SENTINEL_IPC").unwrap_or_else(|_| "unix:/tmp/sentinel.sock".to_string());

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--headless" => headless = true,
            "--ipc" => {
                if let Some(value) = args.next() {
                    listen_spec = value;
                } else {
                    eprintln!("sentinel_tui: --ipc requires a value");
                    std::process::exit(2);
                }
            }
            _ => {}
        }
    }

    (headless, listen_spec)
}

fn touch_plugin(registry: &mut PluginRegistry, plugin_id: &str, ts_ms: u64) {
    if let Some(info) = registry.plugins.get_mut(plugin_id) {
        info.last_seen_ts_ms = ts_ms;
        return;
    }

    registry.plugins.insert(
        plugin_id.to_string(),
        PluginInfo {
            plugin_id: plugin_id.to_string(),
            last_seen_ts_ms: ts_ms,
            connected_since_ts_ms: ts_ms,
            ..Default::default()
        },
    );
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

fn ingest_metrics(app: &mut AppState, metrics: Vec<sentinel_core::model::MetricPoint>) {
    for m in metrics {
        app.metrics_latest.insert((m.source, m.label), m.value);
    }
}

fn ingest_host_metrics(app: &mut AppState, snap: &Snapshot) {
    app.metrics_latest.insert(
        ("host".to_string(), ui::CPU_LOAD.to_string()),
        format!("{:.1}", snap.cpu),
    );
    app.metrics_latest.insert(
        ("host".to_string(), ui::RAM_USED.to_string()),
        format!("{:.2}", snap.mem_gb),
    );
    if let Some(pct) = snap.disk_free_pct {
        app.metrics_latest.insert(
            ("host".to_string(), ui::DISK_FREE.to_string()),
            format!("{:.1}", pct),
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    better_panic::install();
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    let (headless, listen_spec) = parse_options();

    if !has_tty() && !headless {
        eprintln!("sentinel_tui: no TTY detected. Re-run with --headless to start backend only.");
        std::process::exit(2);
    }

    let (tx, mut rx) = mpsc::channel::<engine::EngineEvent>(200);

    // Spawn workers
    let tx_phy = tx.clone();
    tokio::spawn(async move {
        engine::physics::run_physics(tx_phy).await;
    });
    let tx_ipc = tx.clone();
    tokio::spawn(async move {
        if let Err(err) = engine::plugin_host::run_ipc(&listen_spec, tx_ipc).await {
            eprintln!("sentinel_tui: ipc host error: {:#}", err);
        }
    });

    let mut app = runtime::init_app_state();
    let mut alert_eval = runtime::AlertEvaluator::new(tx.clone());

    if headless {
        eprintln!("sentinel_tui running in headless mode; backend active.");
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                Some(evt) = rx.recv() => {
                    runtime::handle_engine_event(&mut app, evt);
                }
                _ = ticker.tick() => {}
            }
            alert_eval.maybe_eval(&mut app);
        }
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        tokio::select! {
            Some(evt) = rx.recv() => {
                runtime::handle_engine_event(&mut app, evt);
            }
            _ = tokio::time::sleep(timeout) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                            KeyCode::Char('b') => {
                                app.ui_mode = match app.ui_mode {
                                    UiMode::Normal => UiMode::Bridge,
                                    UiMode::Bridge => UiMode::Normal,
                                };
                            }
                            KeyCode::Tab => {
                                app.active_pane = match app.active_pane {
                                    PaneId::Sidebar => PaneId::Dashboard,
                                    PaneId::Dashboard => PaneId::Processes,
                                    PaneId::Processes => PaneId::AiConsole,
                                    PaneId::AiConsole => PaneId::Inspector,
                                    PaneId::Inspector => PaneId::Sidebar,
                                };
                            }
                            KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                if app.layout.main_split > 20 { app.layout.main_split -= 5; }
                            }
                            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                if app.layout.main_split < 80 { app.layout.main_split += 5; }
                            }
                            _ => {
                                if app.active_pane == PaneId::AiConsole {
                                    if key.code == KeyCode::Enter {
                                        let text = app.ai_input.lines().join("\n");
                                        if !text.trim().is_empty() {
                                            app.ai_log.push(("User".into(), text));
                                        }
                                        app.ai_input = tui_textarea::TextArea::default();
                                        app.ai_input.set_block(ratatui::widgets::Block::default().borders(ratatui::widgets::Borders::ALL));
                                    } else {
                                        app.ai_input.input(key);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }

        alert_eval.maybe_eval(&mut app);
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
