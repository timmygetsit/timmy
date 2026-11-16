use crate::model::agent::Confidence;
use crate::model::docker::ContainerState;
use crate::model::{ContainerDetail, ContainerInfo};
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

/// Renders the main Docker containers table in the TUI.
pub fn render_docker_table(
    frame: &mut Frame,
    area: Rect,
    containers: &[ContainerInfo],
    state: &mut TableState,
    theme: &Theme,
    filter: &str,
) {
    let filtered: Vec<&ContainerInfo> = containers
        .iter()
        .filter(|c| {
            let sess_str = c.session_id.as_deref().unwrap_or("");
            let fields = [
                c.name.as_str(),
                c.image.as_str(),
                c.id.as_str(),
                c.short_id.as_str(),
                sess_str,
                c.status.as_str(),
            ];
            crate::ui::matches_filter_tokens(&fields, filter)
        })
        .collect();

    let header_cells = [
        "CONTAINER ID",
        "NAME",
        "IMAGE",
        "STATE",
        "CPU %",
        "MEMORY",
        "PORTS",
        "SESSION",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = filtered.iter().map(|c| {
        let state_style = match c.state {
            ContainerState::Running => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            ContainerState::Paused | ContainerState::Restarting => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            ContainerState::Exited | ContainerState::Created => {
                Style::default().fg(Color::DarkGray)
            }
            ContainerState::Dead => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ContainerState::Unknown(_) => Style::default().fg(theme.muted),
        };

        let session_style = match c.confidence {
            Confidence::Confirmed => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            Confidence::HighConfidence => Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            Confidence::Inferred => Style::default().fg(Color::Yellow),
            Confidence::Unknown => Style::default().fg(theme.muted),
        };

        let cells = vec![
            Cell::from(c.short_id.clone()),
            Cell::from(c.name.clone()),
            Cell::from(c.image.clone()),
            Cell::from(c.state.to_string()).style(state_style),
            Cell::from(c.formatted_cpu()),
            Cell::from(c.formatted_memory()),
            Cell::from(c.formatted_ports()),
            Cell::from(c.formatted_session()).style(session_style),
        ];
        Row::new(cells).height(1)
    });

    let title = if containers.is_empty() {
        " Docker Containers (No active containers found) ".to_string()
    } else if filter.is_empty() {
        format!(" Docker Containers ({}) ", filtered.len())
    } else {
        format!(
            " Docker Containers ({}) [Filter: '{}'] ",
            filtered.len(),
            filter
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(16),
            Constraint::Percentage(20),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Percentage(16),
            Constraint::Percentage(14),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(if containers.is_empty() {
                theme.muted
            } else {
                theme.primary
            })),
    )
    .row_highlight_style(theme.row_selected_style())
    .highlight_symbol("▶ ");

    if containers.is_empty() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(4)])
            .split(area);

        frame.render_stateful_widget(table, chunks[0], state);

        let placeholder_lines = vec![
            Line::from(vec![
                Span::styled("ℹ  Docker Engine Status: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("No containers active or Docker daemon is unreachable."),
            ]),
            Line::from(vec![
                Span::raw("   Socket searched: "),
                Span::styled("~/.docker/run/docker.sock", Style::default().fg(Color::Yellow)),
                Span::raw(" and "),
                Span::styled("/var/run/docker.sock", Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("   Note: ", Style::default().fg(Color::Green)),
                Span::raw("TIMMY runs in strictly read-only mode. It never stops, kills, or restarts containers."),
            ]),
        ];
        let placeholder = Paragraph::new(placeholder_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Docker Diagnostics "),
        );
        frame.render_widget(placeholder, chunks[1]);
    } else {
        frame.render_stateful_widget(table, area, state);
    }
}

/// Renders deep container inspection details inside a modal overlay.
pub fn render_docker_detail_modal(
    frame: &mut Frame,
    area: Rect,
    detail: &ContainerDetail,
    theme: &Theme,
) {
    let modal_width = (area.width * 88 / 100).max(60).min(area.width);
    let modal_height = (area.height * 92 / 100).max(24).min(area.height);

    let modal_area = Rect {
        x: area.x + (area.width - modal_width) / 2,
        y: area.y + (area.height - modal_height) / 2,
        width: modal_width,
        height: modal_height,
    };

    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            " Docker Inspection: {} ({}) ",
            detail.info.name, detail.info.short_id
        ))
        .border_style(Style::default().fg(theme.primary));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Overview & State
            Constraint::Length(4), // Session Attribution
            Constraint::Length(5), // Execution & Networking
            Constraint::Min(5),    // Mounts & Masked Environment
            Constraint::Length(1), // Footer instruction
        ])
        .split(inner);

    // 1. Overview & State
    let state_color = match detail.info.state {
        ContainerState::Running => Color::Green,
        ContainerState::Paused | ContainerState::Restarting => Color::Yellow,
        ContainerState::Exited | ContainerState::Created => Color::DarkGray,
        ContainerState::Dead => Color::Red,
        ContainerState::Unknown(_) => theme.muted,
    };

    let overview_lines = vec![
        Line::from(vec![
            Span::styled(
                "Container ID: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&detail.info.id),
            Span::raw("  "),
            Span::styled(
                "Image: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&detail.info.image),
        ]),
        Line::from(vec![
            Span::styled(
                "State:        ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                detail.info.state.to_string(),
                Style::default()
                    .fg(state_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" (Exit Code: "),
            Span::raw(
                detail
                    .info
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
            ),
            Span::raw(", Restarts: "),
            Span::raw(
                detail
                    .info
                    .restart_count
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "0".to_string()),
            ),
            Span::raw(", Health: "),
            Span::raw(detail.info.health_status.as_deref().unwrap_or("none")),
            Span::raw(")"),
        ]),
        Line::from(vec![
            Span::styled(
                "Created:      ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(detail.info.created_at.as_deref().unwrap_or("N/A")),
            Span::raw("  "),
            Span::styled(
                "Started: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(detail.info.started_at.as_deref().unwrap_or("N/A")),
        ]),
        Line::from(vec![
            Span::styled(
                "Resources:    ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("CPU: {}", detail.info.formatted_cpu()),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("Memory: {}", detail.info.formatted_memory()),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" | "),
            Span::raw(format!(
                "Runtime: {}",
                detail.info.runtime.as_deref().unwrap_or("runc")
            )),
        ]),
    ];
    let overview_p = Paragraph::new(overview_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" Container Summary "),
    );
    frame.render_widget(overview_p, chunks[0]);

    // 2. Session Attribution
    let session_color = match detail.info.confidence {
        Confidence::Confirmed => Color::Green,
        Confidence::HighConfidence => Color::Cyan,
        Confidence::Inferred => Color::Yellow,
        Confidence::Unknown => theme.muted,
    };

    let evidence_str = if detail.info.evidence.is_empty() {
        "None (No correlating session markers discovered)".to_string()
    } else {
        detail.info.evidence.join("; ")
    };

    let session_lines = vec![
        Line::from(vec![
            Span::styled(
                "Session ID:    ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(detail.info.session_id.as_deref().unwrap_or("None")),
            Span::raw("  "),
            Span::styled(
                "Confidence: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                detail.info.confidence.to_string(),
                Style::default()
                    .fg(session_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Evidence:      ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(evidence_str),
        ]),
    ];
    let session_p = Paragraph::new(session_lines)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .title(" AI Agent Session Attribution "),
        );
    frame.render_widget(session_p, chunks[1]);

    // 3. Execution & Networking
    let exec_lines = vec![
        Line::from(vec![
            Span::styled(
                "Command:       ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(detail.info.command.as_deref().unwrap_or("-")),
        ]),
        Line::from(vec![
            Span::styled(
                "Entrypoint:    ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(detail.info.entrypoint.as_deref().unwrap_or("-")),
        ]),
        Line::from(vec![
            Span::styled(
                "Ports / Net:   ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "Ports: [{}] | Mode: {} | IP: {}",
                detail.info.formatted_ports(),
                detail.info.network_mode.as_deref().unwrap_or("bridge"),
                if detail.info.ip_addresses.is_empty() {
                    "-"
                } else {
                    &detail.info.ip_addresses[0]
                }
            )),
        ]),
    ];
    let exec_p = Paragraph::new(exec_lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" Execution & Network (Secrets Masked) "),
    );
    frame.render_widget(exec_p, chunks[2]);

    // 4. Mounts & Masked Environment
    let mut mounts_lines = Vec::new();
    if detail.mounts.is_empty() {
        mounts_lines.push(Line::from("Mounts: (None attached)"));
    } else {
        mounts_lines.push(Line::from(Span::styled(
            "Storage Mounts:",
            Style::default()
                .fg(theme.primary)
                .add_modifier(Modifier::BOLD),
        )));
        for m in &detail.mounts {
            mounts_lines.push(Line::from(format!(
                "  • {} -> {} [{}, {}]",
                m.source,
                m.destination,
                m.mount_type,
                if m.read_only { "ro" } else { "rw" }
            )));
        }
    }

    mounts_lines.push(Line::from(""));
    if detail.env_keys.is_empty() {
        mounts_lines.push(Line::from(
            "Environment: (No environment variables recorded)",
        ));
    } else {
        mounts_lines.push(Line::from(Span::styled(
            "Environment Variables (Names Only, Values Suppressed):",
            Style::default()
                .fg(theme.primary)
                .add_modifier(Modifier::BOLD),
        )));
        for k in detail.env_keys.iter().take(12) {
            mounts_lines.push(Line::from(format!("  • {}", k)));
        }
        if detail.env_keys.len() > 12 {
            mounts_lines.push(Line::from(format!(
                "  ... ({} more variables omitted)",
                detail.env_keys.len() - 12
            )));
        }
    }

    let mounts_p = Paragraph::new(mounts_lines)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .title(" Storage & Environment "),
        );
    frame.render_widget(mounts_p, chunks[3]);

    // 5. Footer instruction
    let footer_text = Line::from(vec![
        Span::styled(
            "Press [Esc], [Enter], or [q] to close",
            Style::default().fg(theme.muted),
        ),
        Span::raw(" | "),
        Span::styled(
            "Read-only: TIMMY never terminates containers",
            Style::default().fg(Color::Green),
        ),
    ]);
    frame.render_widget(Paragraph::new(footer_text), chunks[4]);
}
