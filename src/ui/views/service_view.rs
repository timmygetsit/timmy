use crate::model::agent::Confidence;
use crate::model::service::{LaunchdDomain, ServiceInfo, ServiceState};
use crate::platform::SnapshotStatus;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

/// Renders the main macOS background services and LaunchDaemons table.
#[allow(clippy::too_many_arguments)]
pub fn render_service_table(
    frame: &mut Frame,
    area: Rect,
    services: &[ServiceInfo],
    state: &mut TableState,
    theme: &Theme,
    filter: &str,
    status: &SnapshotStatus,
    last_refresh: Option<std::time::Instant>,
) {
    let filtered: Vec<&ServiceInfo> = services
        .iter()
        .filter(|s| {
            let pid_str = s.pid.map(|pid| pid.to_string()).unwrap_or_default();
            let domain_str = s.formatted_domain();
            let exe_str = s.executable_or_program().unwrap_or("");
            let session_str = s.session_id.as_deref().unwrap_or("");
            let status_str = s.status.to_string();
            let fields = [
                s.name.as_str(),
                s.label.as_str(),
                &pid_str,
                &domain_str,
                exe_str,
                session_str,
                &status_str,
            ];
            crate::ui::matches_filter_tokens(&fields, filter)
        })
        .collect();

    let header_cells = [
        "SERVICE NAME",
        "DOMAIN",
        "STATE",
        "PID",
        "PROGRAM / EXECUTABLE",
        "SESSION",
        "CONFIDENCE",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = filtered.iter().map(|s| {
        let state_style = match &s.state {
            ServiceState::Running => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            ServiceState::Loaded => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            ServiceState::DiscoveredOnDisk => Style::default().fg(Color::Cyan),
            ServiceState::NotRunning => Style::default().fg(Color::DarkGray),
            ServiceState::Error(_) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ServiceState::Unknown => Style::default().fg(theme.muted),
        };

        let domain_style = match s.domain {
            Some(LaunchdDomain::User) => Style::default().fg(Color::Cyan),
            Some(LaunchdDomain::SystemThirdParty) => Style::default().fg(Color::Magenta),
            Some(LaunchdDomain::SystemApple) => Style::default().fg(Color::DarkGray),
            _ => Style::default().fg(theme.muted),
        };

        let session_style = match s.confidence {
            Confidence::Confirmed => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            Confidence::HighConfidence => Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            Confidence::Inferred => Style::default().fg(Color::Yellow),
            Confidence::Unknown => Style::default().fg(theme.muted),
        };

        let exe_str = s.executable_or_program().unwrap_or("-");

        let cells = vec![
            Cell::from(s.name.clone()),
            Cell::from(s.formatted_domain()).style(domain_style),
            Cell::from(s.formatted_state()).style(state_style),
            Cell::from(
                s.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(exe_str.to_string()),
            Cell::from(s.formatted_session()).style(session_style),
            Cell::from(s.confidence.to_string()).style(session_style),
        ];
        Row::new(cells).height(1)
    });

    let (status_badge, border_color) = match status {
        SnapshotStatus::Initial => (" [INITIALIZING - NO SNAPSHOT]".to_string(), theme.muted),
        SnapshotStatus::Complete => {
            let is_partial = services.iter().any(|s| s.is_partial);
            if is_partial {
                (
                    " [PARTIAL SNAPSHOT - INCOMPLETE]".to_string(),
                    Color::Yellow,
                )
            } else {
                ("".to_string(), theme.primary)
            }
        }
        SnapshotStatus::Partial { reason } => (
            format!(" [PARTIAL SNAPSHOT - INCOMPLETE: {}]", reason),
            Color::Yellow,
        ),
        SnapshotStatus::Stale { error } => {
            let age_str = match last_refresh {
                Some(t) => {
                    let secs = t.elapsed().as_secs();
                    if secs < 60 {
                        format!("{}s ago", secs)
                    } else if secs < 3600 {
                        format!("{}m ago", secs / 60)
                    } else {
                        format!("{}h ago", secs / 3600)
                    }
                }
                None => "unknown".to_string(),
            };
            (
                format!(
                    " [STALE SNAPSHOT - LAST GOOD {}] [ERROR: {}]",
                    age_str, error
                ),
                Color::LightRed,
            )
        }
        SnapshotStatus::Failed { error } => {
            (format!(" [INSPECTION FAILED: {}]", error), Color::Red)
        }
    };

    let title = if services.is_empty() {
        format!(
            " Background Services (0 services discovered){} ",
            status_badge
        )
    } else if filter.is_empty() {
        format!(" Background Services ({}){} ", filtered.len(), status_badge)
    } else {
        format!(
            " Background Services ({}){} [Filter: '{}'] ",
            filtered.len(),
            status_badge,
            filter
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Percentage(25),
            Constraint::Length(14),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(theme.row_selected_style())
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, state);
}

/// Renders deep LaunchAgent and LaunchDaemon inspection details inside a modal overlay.
pub fn render_service_detail_modal(
    frame: &mut Frame,
    area: Rect,
    service: &ServiceInfo,
    theme: &Theme,
) {
    let modal_width = (area.width * 88 / 100).max(65).min(area.width);
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
        .title(format!(" Launchd Inspection: {} ", service.name))
        .border_style(Style::default().fg(theme.primary));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Overview & Launchd Runtime State
            Constraint::Length(6), // Execution & Program Arguments
            Constraint::Length(5), // Scheduling, KeepAlive & Sockets
            Constraint::Length(4), // Environment & Permissions
            Constraint::Min(4),    // AI Session Attribution & Provenance
            Constraint::Length(1), // Footer instruction
        ])
        .split(inner);

    // 1. Overview & Launchd Runtime State
    let state_color = match &service.state {
        ServiceState::Running => Color::Green,
        ServiceState::Loaded => Color::Yellow,
        ServiceState::DiscoveredOnDisk => Color::Cyan,
        ServiceState::NotRunning => Color::DarkGray,
        ServiceState::Error(_) => Color::Red,
        ServiceState::Unknown => theme.muted,
    };

    let plist_path_str = service
        .plist
        .as_ref()
        .map(|p| p.source_path.to_string_lossy().to_string())
        .or_else(|| service.path.clone())
        .unwrap_or_else(|| "Not discovered on disk (loaded in runtime only)".to_string());

    let exit_status_str = match service.last_exit_status {
        Some(code) => format!("{}", code),
        None => "N/A".to_string(),
    };

    let overview_lines = vec![
        Line::from(vec![
            Span::styled(
                "Canonical Label: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&service.label),
            Span::raw("  "),
            Span::styled(
                "Domain: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                service.formatted_domain(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Lifecycle State: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                service.formatted_state(),
                Style::default()
                    .fg(state_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Last Exit Code: ", Style::default().fg(theme.primary)),
            Span::raw(exit_status_str),
            Span::raw("  "),
            Span::styled("PID: ", Style::default().fg(theme.primary)),
            Span::raw(
                service
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Plist Path:      ", Style::default().fg(theme.primary)),
            Span::raw(plist_path_str),
        ]),
        Line::from(vec![
            Span::styled("Plist Status:    ", Style::default().fg(theme.primary)),
            Span::styled(
                match &service.plist_status {
                    crate::model::service::PlistStatus::Valid { .. } => {
                        "Valid (Parsed successfully)".to_string()
                    }
                    crate::model::service::PlistStatus::Malformed { error, .. } => {
                        format!("Malformed ({})", error)
                    }
                    crate::model::service::PlistStatus::Unreadable { error, .. } => {
                        format!("Unreadable ({})", error)
                    }
                    crate::model::service::PlistStatus::NotDiscovered => {
                        "Not discovered on disk (Runtime-only)".to_string()
                    }
                },
                if service.plist_status.is_error() {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                },
            ),
        ]),
    ];
    let p_overview = Paragraph::new(overview_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" 1. Service Identification & Runtime State ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(p_overview, chunks[0]);

    // 2. Execution & Program Arguments
    let program_str = service
        .plist
        .as_ref()
        .and_then(|p| p.program.as_deref())
        .or_else(|| service.executable_or_program())
        .unwrap_or("-");

    let args_str = if let Some(ref p) = service.plist {
        if p.program_arguments.is_empty() {
            "-".to_string()
        } else {
            p.program_arguments.join(" ")
        }
    } else {
        "-".to_string()
    };

    let working_dir_str = service
        .plist
        .as_ref()
        .and_then(|p| p.working_directory.as_deref())
        .unwrap_or("-");

    let exec_lines = vec![
        Line::from(vec![
            Span::styled(
                "Program Binary: ",
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(program_str),
        ]),
        Line::from(vec![
            Span::styled("Arguments (Masked): ", Style::default().fg(theme.primary)),
            Span::raw(args_str),
        ]),
        Line::from(vec![
            Span::styled("Working Directory:  ", Style::default().fg(theme.primary)),
            Span::raw(working_dir_str),
        ]),
    ];
    let p_exec = Paragraph::new(exec_lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" 2. Program Execution & Working Directory ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(p_exec, chunks[1]);

    // 3. Scheduling, KeepAlive & Sockets
    let run_at_load_str = match service.plist.as_ref().and_then(|p| p.run_at_load) {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "Not configured",
    };

    let keep_alive_str = match service.plist.as_ref().and_then(|p| p.keep_alive.as_ref()) {
        Some(k) => k.to_string(),
        None => "Not configured".to_string(),
    };

    let interval_str = match service.plist.as_ref().and_then(|p| p.start_interval) {
        Some(secs) => format!("Every {} seconds", secs),
        None => service
            .plist
            .as_ref()
            .and_then(|p| p.start_calendar_interval.as_deref())
            .unwrap_or("On-Demand")
            .to_string(),
    };

    let sockets_str = service
        .plist
        .as_ref()
        .map(|p| {
            if p.sockets.is_empty() {
                "-".to_string()
            } else {
                p.sockets.join(", ")
            }
        })
        .unwrap_or_else(|| "-".to_string());

    let mach_str = service
        .plist
        .as_ref()
        .map(|p| {
            if p.mach_services.is_empty() {
                "-".to_string()
            } else {
                p.mach_services.join(", ")
            }
        })
        .unwrap_or_else(|| "-".to_string());

    let sched_lines = vec![
        Line::from(vec![
            Span::styled("RunAtLoad:  ", Style::default().fg(theme.primary)),
            Span::raw(run_at_load_str),
            Span::raw("    "),
            Span::styled("KeepAlive:  ", Style::default().fg(theme.primary)),
            Span::raw(keep_alive_str),
            Span::raw("    "),
            Span::styled("Schedule:   ", Style::default().fg(theme.primary)),
            Span::raw(interval_str),
        ]),
        Line::from(vec![
            Span::styled("Sockets:    ", Style::default().fg(theme.primary)),
            Span::raw(sockets_str),
            Span::raw("    "),
            Span::styled("MachServices: ", Style::default().fg(theme.primary)),
            Span::raw(mach_str),
        ]),
    ];
    let p_sched = Paragraph::new(sched_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" 3. Scheduling, Activation & Inter-Process Communication ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(p_sched, chunks[2]);

    // 4. Environment & Permissions
    let env_names_str = if let Some(ref p) = service.plist {
        if p.environment_variable_names.is_empty() {
            "None defined".to_string()
        } else {
            p.environment_variable_names.join(", ")
        }
    } else {
        "N/A".to_string()
    };

    let user_str = service
        .plist
        .as_ref()
        .and_then(|p| p.user_name.as_deref())
        .unwrap_or("-");

    let group_str = service
        .plist
        .as_ref()
        .and_then(|p| p.group_name.as_deref())
        .unwrap_or("-");

    let env_lines = vec![
        Line::from(vec![
            Span::styled(
                "Environment Variable Names (Values Redacted): ",
                Style::default().fg(theme.primary),
            ),
            Span::raw(env_names_str),
        ]),
        Line::from(vec![
            Span::styled("User:  ", Style::default().fg(theme.primary)),
            Span::raw(user_str),
            Span::raw("    "),
            Span::styled("Group: ", Style::default().fg(theme.primary)),
            Span::raw(group_str),
        ]),
    ];
    let p_env = Paragraph::new(env_lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" 4. Environment Configuration & Permissions ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(p_env, chunks[3]);

    // 5. AI Session Attribution & Provenance
    let conf_color = match service.confidence {
        Confidence::Confirmed => Color::Green,
        Confidence::HighConfidence => Color::Cyan,
        Confidence::Inferred => Color::Yellow,
        Confidence::Unknown => theme.muted,
    };

    let mut attr_lines = vec![Line::from(vec![
        Span::styled(
            "Attributed AI Session: ",
            Style::default()
                .fg(theme.primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            service.formatted_session(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled(
            "Confidence Grade: ",
            Style::default()
                .fg(theme.primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            service.confidence.to_string(),
            Style::default().fg(conf_color).add_modifier(Modifier::BOLD),
        ),
    ])];

    if service.evidence.is_empty() {
        attr_lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(Color::DarkGray)),
            Span::raw("No active correlation evidence linked this service to an AI agent session."),
        ]));
    } else {
        for ev in &service.evidence {
            attr_lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(theme.primary)),
                Span::raw(ev.clone()),
            ]));
        }
    }

    let p_attr = Paragraph::new(attr_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" 5. AI Agent Correlation & Provenance Evidence ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(p_attr, chunks[4]);

    // 6. Footer instruction
    let footer_text = vec![Line::from(vec![
        Span::styled(" [Esc / Enter / q] ", Style::default().fg(Color::Yellow)),
        Span::raw("Close Details  |  "),
        Span::styled("Note: ", Style::default().fg(Color::Green)),
        Span::raw("TIMMY LaunchAgent inspection is strictly read-only. No service modification or lifecycle operations are performed."),
    ])];
    let p_footer = Paragraph::new(footer_text);
    frame.render_widget(p_footer, chunks[5]);
}
