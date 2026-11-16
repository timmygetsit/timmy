use crate::model::ProcessDetail;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render_detail_modal(frame: &mut Frame, area: Rect, detail: &ProcessDetail, theme: &Theme) {
    // Center modal with safe dimension bounds
    let modal_width = (area.width * 85 / 100).max(60).min(area.width);
    let modal_height = (area.height * 90 / 100).max(22).min(area.height);

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
            " Process Inspection: {} (PID: {}) ",
            detail.info.name, detail.info.pid
        ))
        .border_style(Style::default().fg(theme.primary));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Attribution & Resource summary
            Constraint::Length(3), // Command line (sanitized)
            Constraint::Length(3), // Lineage / Ancestors
            Constraint::Min(4),    // Sanitized Env & Ports
            Constraint::Length(1), // Footer instruction
        ])
        .split(inner);

    // 1. Attribution summary & evidence
    let conf_style = theme.confidence_style(detail.info.attribution.confidence);
    let parent_str = match (
        detail.info.attribution.parent_pid,
        &detail.info.attribution.parent_name,
    ) {
        (Some(pid), Some(name)) => format!("{} (PID {})", name, pid),
        (Some(pid), None) => format!("PID {}", pid),
        _ => "N/A".to_string(),
    };

    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                "AI Attribution: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "{} [{}]",
                    detail.info.attribution.kind, detail.info.attribution.confidence
                ),
                conf_style,
            ),
            Span::raw(" | "),
            Span::styled(
                "Confirmed Ownership: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if detail.info.attribution.is_confirmed {
                    "YES"
                } else {
                    "INFERRED / DESCENDANT"
                },
                if detail.info.attribution.is_confirmed {
                    Style::default().fg(theme.success)
                } else {
                    Style::default().fg(theme.highlight)
                },
            ),
            Span::raw(" | "),
            Span::styled(
                "Safe to Stop: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if detail.info.attribution.safe_to_terminate {
                    "YES"
                } else {
                    "NO (PROTECTED)"
                },
                if detail.info.attribution.safe_to_terminate {
                    Style::default().fg(theme.success)
                } else {
                    Style::default().fg(theme.danger)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Attribution Evidence: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(&detail.info.attribution.evidence),
            Span::raw(" | "),
            Span::styled("Parent: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(parent_str),
        ]),
        Line::from(vec![
            Span::styled("CPU: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(detail.info.formatted_cpu()),
            Span::raw(" | "),
            Span::styled("Memory: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(detail.info.formatted_memory()),
            Span::raw(" | "),
            Span::styled("Runtime: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(detail.info.formatted_runtime()),
            Span::raw(" | "),
            Span::styled("CWD: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(
                detail
                    .cwd
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
            ),
        ]),
    ];
    let summary_para = Paragraph::new(summary_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(summary_para, chunks[0]);

    // 2. Command line (sanitized)
    let cmdline_str = if detail.cmdline.is_empty() {
        "N/A".to_string()
    } else {
        detail.cmdline.join(" ")
    };
    let cmd_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Full Command Line (Sanitized):",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            cmdline_str,
            Style::default().fg(Color::Yellow),
        )),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(cmd_para, chunks[1]);

    // 3. Process Lineage
    let mut lineage_spans = vec![
        Span::styled(
            "Lineage Tree: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("PID {}", detail.info.pid),
            Style::default().fg(Color::Cyan),
        ),
    ];
    for anc in &detail.parent_chain {
        lineage_spans.push(Span::raw(" ➔ "));
        lineage_spans.push(Span::styled(
            format!("{} (PID {})", anc.name, anc.pid),
            Style::default().fg(Color::White),
        ));
    }
    let lineage_para = Paragraph::new(Line::from(lineage_spans));
    frame.render_widget(lineage_para, chunks[2]);

    // 4. Sanitized Environment
    let mut env_lines = vec![Line::from(Span::styled(
        format!(
            "Sanitized Environment Variables ({}) [Sensitive credentials/tokens masked]:",
            detail.environment.len()
        ),
        Style::default().add_modifier(Modifier::BOLD),
    ))];

    for (k, v) in detail.environment.iter().take(20) {
        env_lines.push(Line::from(vec![
            Span::styled(format!("{}: ", k), Style::default().fg(Color::Blue)),
            Span::raw(v),
        ]));
    }
    if detail.environment.len() > 20 {
        env_lines.push(Line::from(Span::styled(
            format!("... and {} more variables", detail.environment.len() - 20),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let env_para = Paragraph::new(env_lines)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(env_para, chunks[3]);

    // 5. Footer
    let footer = Paragraph::new("Press [Esc] or [Enter] to return").style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::ITALIC),
    );
    frame.render_widget(footer, chunks[4]);
}
