use crate::model::ProcessInfo;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};
use std::collections::HashSet;

pub fn render_process_table(
    frame: &mut Frame,
    area: Rect,
    processes: &[ProcessInfo],
    state: &mut TableState,
    theme: &Theme,
    filter: &str,
    tagged_pids: &HashSet<u32>,
) {
    let filtered_processes: Vec<&ProcessInfo> = processes
        .iter()
        .filter(|p| {
            let pid_str = p.pid.to_string();
            let kind_str = p.attribution.kind.to_string();
            let exe_str = p.exe.as_ref().and_then(|e| e.to_str()).unwrap_or("");
            let cmd_str = p.cmdline.join(" ");
            let cwd_str = p.cwd_status.as_ref().and_then(|c| c.to_str()).unwrap_or("");
            let user_str = p.user.as_deref().unwrap_or("");
            let fields = [
                p.name.as_str(),
                &pid_str,
                &kind_str,
                &p.attribution.reason,
                exe_str,
                &cmd_str,
                cwd_str,
                user_str,
            ];
            crate::ui::matches_filter_tokens(&fields, filter)
        })
        .collect();

    let header_cells = [
        "TAG",
        "PID",
        "PROCESS NAME",
        "AI ATTRIBUTION",
        "CONFIDENCE",
        "SAFE TO STOP",
        "CPU%",
        "RAM",
        "PORTS",
        "TIME",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = filtered_processes.iter().map(|p| {
        let is_tagged = tagged_pids.contains(&p.pid);
        let tag_cell = if is_tagged {
            Cell::from("[x]").style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Cell::from("[ ]").style(Style::default().fg(Color::DarkGray))
        };

        let ports_str = if p.listening_ports.is_empty() {
            "-".to_string()
        } else {
            p.listening_ports
                .iter()
                .map(|pt| pt.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let conf_style = theme.confidence_style(p.attribution.confidence);

        let safe_cell = if p.attribution.safe_to_terminate {
            Cell::from("YES").style(Style::default().fg(theme.success))
        } else {
            Cell::from("NO (PROTECTED)").style(Style::default().fg(theme.muted))
        };

        let cells = vec![
            tag_cell,
            Cell::from(p.pid.to_string()),
            Cell::from(p.name.clone()),
            Cell::from(p.attribution.kind.to_string()),
            Cell::from(p.attribution.confidence.to_string()).style(conf_style),
            safe_cell,
            Cell::from(p.formatted_cpu()),
            Cell::from(p.formatted_memory()),
            Cell::from(ports_str),
            Cell::from(p.formatted_runtime()),
        ];
        Row::new(cells).height(1)
    });

    let tag_suffix = if tagged_pids.is_empty() {
        String::new()
    } else {
        format!(" [{} Tagged]", tagged_pids.len())
    };

    let title = if filter.is_empty() {
        format!(
            " Active Processes ({}){} ",
            filtered_processes.len(),
            tag_suffix
        )
    } else {
        format!(
            " Active Processes ({}) [Filter: '{}']{} ",
            filtered_processes.len(),
            filter,
            tag_suffix
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Percentage(20),
            Constraint::Percentage(16),
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Percentage(15),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(theme.primary)),
    )
    .row_highlight_style(theme.row_selected_style())
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, state);
}
