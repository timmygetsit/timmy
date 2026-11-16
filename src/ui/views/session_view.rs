use crate::model::agent::Confidence;
use crate::model::session::{SessionInfo, SessionStatus, TrackedResource};
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

#[allow(clippy::too_many_arguments)]
pub fn render_session_view(
    frame: &mut Frame,
    area: Rect,
    sessions: &[SessionInfo],
    selected_resources: &[TrackedResource],
    selected_tree: Option<&str>,
    show_tree: bool,
    state: &mut TableState,
    theme: &Theme,
    filter: &str,
) {
    let filtered_sessions: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| {
            let kind_str = s.agent_kind.to_string();
            let status_str = s.status.to_string();
            let pid_str = s.root_pid.map(|p| p.to_string()).unwrap_or_default();
            let proc_name = s.root_process_name.as_deref().unwrap_or("");
            let fields = [s.id.as_str(), &kind_str, &status_str, &pid_str, proc_name];
            crate::ui::matches_filter_tokens(&fields, filter)
        })
        .collect();

    if filtered_sessions.is_empty() {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                " No AI Agent Coding Sessions Recorded ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(" Start tracking an AI coding session using the CLI: "),
            Line::from(Span::styled(
                "   timmy session start --agent claude ",
                Style::default().fg(Color::Cyan),
            )),
            Line::from(""),
            Line::from(" Or auto-detect any currently running coding agent: "),
            Line::from(Span::styled(
                "   timmy session start ",
                Style::default().fg(Color::Cyan),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" AI Agent Sessions ")
                .title_style(theme.title_style()),
        );
        frame.render_widget(msg, area);
        return;
    }

    // Split area into top (Sessions table) and bottom (Selected Session Resources drilldown)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // 1. Sessions Table (Top)
    let header_cells = [
        "SESSION ID",
        "AI AGENT",
        "STATUS",
        "STARTED AT",
        "DURATION",
        "RESOURCES",
        "MEMORY",
        "PORTS",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = filtered_sessions.iter().map(|s| {
        let status_style = match s.status {
            SessionStatus::Active => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            SessionStatus::Stopped => Style::default().fg(Color::Yellow),
            SessionStatus::Completed => Style::default().fg(Color::DarkGray),
        };

        let started_str = s.start_time.format("%Y-%m-%d %H:%M").to_string();

        let cells = vec![
            Cell::from(s.id.clone()),
            Cell::from(s.agent_kind.to_string()).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from(s.status.to_string()).style(status_style),
            Cell::from(started_str),
            Cell::from(s.duration_str()),
            Cell::from(s.resource_count.to_string()),
            Cell::from(s.formatted_memory()).style(Style::default().fg(Color::Green)),
            Cell::from(s.ports_str()),
        ];
        Row::new(cells)
    });

    let sessions_table = Table::new(
        rows,
        [
            Constraint::Length(25), // ID
            Constraint::Length(16), // Agent
            Constraint::Length(11), // Status
            Constraint::Length(18), // Started
            Constraint::Length(12), // Duration
            Constraint::Length(10), // Resources
            Constraint::Length(12), // Memory
            Constraint::Min(12),    // Ports
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " AI Agent Sessions ({}) - [↑/↓] Select | [Enter] Inspect Cleanup Plan ",
                filtered_sessions.len()
            ))
            .title_style(theme.title_style()),
    )
    .row_highlight_style(theme.row_selected_style());

    frame.render_stateful_widget(sessions_table, chunks[0], state);

    // 2. Tracked Resources Table (Bottom)
    let res_header_cells = [
        "PID",
        "RESOURCE / PROCESS",
        "ATTRIBUTION",
        "DETACHED",
        "SAFE TO STOP",
        "RAM",
        "PORTS",
        "EVIDENCE",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme.header_style()));
    let res_header = Row::new(res_header_cells).height(1);

    let res_rows = selected_resources.iter().map(|r| {
        let conf_style = match r.confidence {
            Confidence::Confirmed => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            Confidence::HighConfidence => Style::default().fg(Color::Cyan),
            Confidence::Inferred => Style::default().fg(Color::Yellow),
            Confidence::Unknown => Style::default().fg(Color::DarkGray),
        };

        let safe_style = if r.safe_to_terminate {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };

        let detached_style = if r.is_detached {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let evidence_summary = r
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| "-".to_string());

        let cells = vec![
            Cell::from(
                r.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(r.name.clone()),
            Cell::from(r.confidence.to_string()).style(conf_style),
            Cell::from(if r.is_detached { "YES (PID 1)" } else { "no" }).style(detached_style),
            Cell::from(if r.safe_to_terminate {
                "YES"
            } else {
                "NO (SHIELD)"
            })
            .style(safe_style),
            Cell::from(r.formatted_memory()),
            Cell::from(r.ports_str()),
            Cell::from(evidence_summary),
        ];
        Row::new(cells)
    });

    let selected_session_id = state
        .selected()
        .and_then(|idx| filtered_sessions.get(idx))
        .map(|s| s.id.as_str())
        .unwrap_or("None");

    if show_tree {
        let tree_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Process Lineage Tree for Session [ {} ] - [t] Switch to Table | [Enter] Inspect ",
                selected_session_id
            ))
            .title_style(theme.title_style());

        let tree_content = selected_tree.unwrap_or("No lineage edges recorded for this session.");
        let tree_lines: Vec<Line> = tree_content
            .lines()
            .map(|l| {
                if l.contains("[ACTIVE]") {
                    Line::styled(l, Style::default().fg(Color::Green))
                } else if l.contains("[EXITED]") {
                    Line::styled(l, Style::default().fg(Color::DarkGray))
                } else if l.contains("[ROOT]") {
                    Line::styled(
                        l,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                } else if l.contains("Ports:") {
                    Line::styled(l, Style::default().fg(Color::Magenta))
                } else if l.contains("Evidence:") {
                    Line::styled(l, Style::default().fg(Color::Yellow))
                } else {
                    Line::from(l)
                }
            })
            .collect();
        let tree_widget = Paragraph::new(tree_lines).block(tree_block);
        frame.render_widget(tree_widget, chunks[1]);
    } else {
        let resources_table = Table::new(
            res_rows,
            [
                Constraint::Length(8),  // PID
                Constraint::Length(20), // Name
                Constraint::Length(12), // Confidence
                Constraint::Length(14), // Detached
                Constraint::Length(14), // Safe to stop
                Constraint::Length(10), // RAM
                Constraint::Length(14), // Ports
                Constraint::Min(25),    // Evidence
            ],
        )
        .header(res_header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Tracked Resources for Selected Session [ {} ] ({}) - [t] Switch to Tree | [Enter] Inspect ",
                    selected_session_id,
                    selected_resources.len()
                ))
                .title_style(theme.title_style()),
        );

        frame.render_widget(resources_table, chunks[1]);
    }
}
