use crate::{AppState, UiMode};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Row, Table},
};
use sentinel_core::{
    model::{AlertCard, PaneId, Severity},
    perfkit::Risk,
};

pub const CPU_LOAD: &str = "CPU Load (%)";
pub const CPU_TEMP: &str = "CPU Temp (C)";
pub const GPU0_TEMP: &str = "GPU0 Temp (C)";
pub const GPU1_TEMP: &str = "GPU1 Temp (C)";
pub const RAM_USED: &str = "RAM Used (GB)";
pub const DISK_FREE: &str = "Disk Free (%)";
pub const NET_UP: &str = "Net Up (Mbps)";
pub const NET_DOWN: &str = "Net Down (Mbps)";

const SOURCE_PRIORITY: [&str; 3] = ["host", "demo.bridge", "demo"];

pub fn draw(f: &mut Frame, app: &mut AppState) {
    let area = f.area();

    // Top / workspace / bottom
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    f.render_widget(
        Paragraph::new(" SENTINEL ZERO [TUI] ")
            .style(Style::default().bg(Color::Red).fg(Color::White)),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(" CTRL+Q: Quit | TAB: Cycle | CTRL+H/L: Resize | B: Bridge ")
            .style(Style::default().bg(Color::DarkGray)),
        chunks[2],
    );

    match app.ui_mode {
        UiMode::Normal => draw_normal(f, app, chunks[1]),
        UiMode::Bridge => draw_bridge(f, app, chunks[1]),
    }
}

fn draw_normal(f: &mut Frame, app: &mut AppState, area: Rect) {
    let workspace = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(24), Constraint::Min(0)])
        .split(area);

    draw_sidebar(f, app, workspace[0]);

    let main_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(app.layout.main_split),
            Constraint::Percentage(100 - app.layout.main_split),
        ])
        .split(workspace[1]);

    let left_col = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.layout.left_split),
            Constraint::Percentage(100 - app.layout.left_split),
        ])
        .split(main_split[0]);

    let right_col = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.layout.right_split),
            Constraint::Percentage(100 - app.layout.right_split),
        ])
        .split(main_split[1]);

    draw_dashboard(f, app, left_col[0]);
    draw_processes(f, app, left_col[1]);
    draw_ai(f, app, right_col[0]);
    draw_inspector(f, app, right_col[1]);
}

fn style(current: PaneId, target: PaneId) -> Style {
    if current == target {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    }
}

fn draw_sidebar(f: &mut Frame, app: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .title("NAV")
        .border_style(style(app.active_pane, PaneId::Sidebar));

    let items = vec![
        "[1] Dashboard",
        "[2] Processes",
        "[3] AI Console",
        "[4] Inspector",
        "",
        "PLUGINS:",
        "• (connect via --ipc unix:/tmp/sentinel.sock)",
    ];

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn draw_dashboard(f: &mut Frame, app: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("(A) Dashboard")
        .border_style(style(app.active_pane, PaneId::Dashboard));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(inner);

    let cpu = Gauge::default()
        .block(Block::default().title("CPU"))
        .percent(app.snapshot.cpu.clamp(0.0, 100.0) as u16)
        .gauge_style(Style::default().fg(Color::Green));
    f.render_widget(cpu, chunks[0]);

    let items: Vec<ListItem> = app
        .snapshot
        .plugins
        .iter()
        .map(|m| ListItem::new(format!("{}: {}", m.label, m.value)))
        .collect();
    f.render_widget(List::new(items), chunks[1]);
}

fn draw_processes(f: &mut Frame, app: &AppState, area: Rect) {
    let rows: Vec<Row> = app
        .snapshot
        .procs
        .iter()
        .map(|p| {
            Row::new(vec![
                p.pid.to_string(),
                p.name.clone(),
                format!("{:.1}", p.cpu),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Min(10),
            Constraint::Length(6),
        ],
    )
    .header(Row::new(vec!["PID", "Name", "CPU"]).style(Style::default().fg(Color::Yellow)))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("(C) Processes")
            .border_style(style(app.active_pane, PaneId::Processes)),
    );

    f.render_widget(table, area);
}

fn draw_ai(f: &mut Frame, app: &mut AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("(B) AI Agent")
        .border_style(style(app.active_pane, PaneId::AiConsole));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(inner);

    let logs: Vec<ListItem> = app
        .ai_log
        .iter()
        .rev()
        .take(200)
        .rev()
        .map(|(r, m)| ListItem::new(format!("{}: {}", r, m)))
        .collect();
    f.render_widget(List::new(logs), chunks[0]);

    f.render_widget(&app.ai_input, chunks[1]);
}

fn draw_inspector(f: &mut Frame, app: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("(D) Inspector")
        .border_style(style(app.active_pane, PaneId::Inspector));
    f.render_widget(Paragraph::new("Select entity...").block(block), area);
}

fn draw_bridge(f: &mut Frame, app: &AppState, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(rows[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[2]);

    render_panel(
        f,
        top[0],
        "CPU",
        vec![
            kv_line("Load", metric_value(app, CPU_LOAD)),
            kv_line("Temp", metric_value(app, CPU_TEMP)),
        ],
    );
    render_panel(
        f,
        top[1],
        "RAM",
        vec![kv_line("Used", metric_value(app, RAM_USED))],
    );

    render_panel(
        f,
        mid[0],
        "GPU0",
        vec![kv_line("Temp", metric_value(app, GPU0_TEMP))],
    );
    render_panel(
        f,
        mid[1],
        "GPU1",
        vec![kv_line("Temp", metric_value(app, GPU1_TEMP))],
    );
    render_panel(
        f,
        mid[2],
        "Network",
        vec![
            kv_line("Up", metric_value(app, NET_UP)),
            kv_line("Down", metric_value(app, NET_DOWN)),
        ],
    );

    render_panel(
        f,
        bottom[0],
        "Disk",
        vec![kv_line("Free", metric_value(app, DISK_FREE))],
    );
    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(bottom[1]);
    render_alerts_panel(f, right_split[0], &app.alert_state.alerts);
    render_actions_panel(f, right_split[1], app);
}

fn kv_line(name: &str, value: Option<String>) -> String {
    match value {
        Some(value) => format!("{}: {}", name, value),
        None => format!("{}: No data (collector offline?)", name),
    }
}

fn metric_value(app: &AppState, label: &str) -> Option<String> {
    for source in SOURCE_PRIORITY {
        let key = (source.to_string(), label.to_string());
        if let Some(value) = app.metrics_latest.get(&key) {
            return Some(value.clone());
        }
    }
    None
}

fn render_panel(f: &mut Frame, area: Rect, title: &str, mut lines: Vec<String>) {
    if lines.is_empty() {
        lines.push("No data (collector offline?)".into());
    }
    let block = Block::default().borders(Borders::ALL).title(title);
    let text = lines.join("\n");
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn render_alerts_panel(f: &mut Frame, area: Rect, alerts: &[AlertCard]) {
    let block = Block::default().borders(Borders::ALL).title("Alerts");
    if alerts.is_empty() {
        f.render_widget(Paragraph::new("No alerts").block(block), area);
        return;
    }

    let mut ordered: Vec<&AlertCard> = alerts.iter().collect();
    ordered.sort_by(|a, b| {
        let ra = severity_rank(&a.severity);
        let rb = severity_rank(&b.severity);
        rb.cmp(&ra).then_with(|| b.ts_ms.cmp(&a.ts_ms))
    });

    let items: Vec<ListItem> = ordered
        .into_iter()
        .take(6)
        .map(|alert| {
            let color = match alert.severity {
                Severity::Info => Color::Cyan,
                Severity::Warn => Color::Yellow,
                Severity::Error => Color::Red,
                Severity::Crit => Color::Magenta,
            };
            let line = format!("[{:?}] {} - {}", alert.severity, alert.title, alert.body);
            ListItem::new(line).style(Style::default().fg(color))
        })
        .collect();

    f.render_widget(List::new(items).block(block), area);
}

fn risk_tag(risk: &Risk) -> &'static str {
    match risk {
        Risk::Info => "INFO",
        Risk::Warn => "WARN",
        Risk::Crit => "CRIT",
    }
}

fn render_actions_panel(f: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default().borders(Borders::ALL).title("Actions");
    if app.actions.is_empty() {
        f.render_widget(Paragraph::new("No actions").block(block), area);
        return;
    }

    let items: Vec<ListItem> = app
        .actions
        .iter()
        .take(8)
        .map(|action| {
            let line = format!(
                "[{}] {} — {}",
                risk_tag(&action.risk),
                action.title,
                action.summary
            );
            ListItem::new(line)
        })
        .collect();

    f.render_widget(List::new(items).block(block), area);
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Crit => 3,
        Severity::Error => 2,
        Severity::Warn => 1,
        Severity::Info => 0,
    }
}
