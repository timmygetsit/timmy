use crate::model::agent::Confidence;
use crate::model::session::{CleanupRecommendation, SessionInfo, TrackedResource};
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Tabs},
    Frame,
};

#[allow(clippy::too_many_arguments)]
pub fn render_session_modal(
    frame: &mut Frame,
    area: Rect,
    session: &SessionInfo,
    resources: &[TrackedResource],
    recommendations: &[CleanupRecommendation],
    tree_text: &str,
    active_tab: usize,
    scroll: usize,
    theme: &Theme,
) {
    let modal_width = (area.width * 92 / 100).max(65).min(area.width);
    let modal_height = (area.height * 92 / 100).max(22).min(area.height);

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
            " AI Coding Session Deep Inspection: {} ",
            session.id
        ))
        .border_style(Style::default().fg(theme.primary));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Session summary
            Constraint::Length(3), // Navigation Tabs
            Constraint::Min(8),    // Active Tab Content (Tree / Cleanup Plan / Resources)
            Constraint::Length(2), // Safety Disclaimer & Footer
        ])
        .split(inner);

    // 1. Session summary
    let root_str = session
        .root_pid
        .map(|p| {
            format!(
                "{} (PID {})",
                session.root_process_name.as_deref().unwrap_or("agent"),
                p
            )
        })
        .unwrap_or_else(|| "None identified".to_string());

    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                "Agent Identity: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                session.agent_kind.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  Status: "),
            Span::styled(
                session.status.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  Confidence: "),
            Span::styled(
                session.confidence.to_string(),
                theme.confidence_style(session.confidence),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Start Time:     ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                session
                    .start_time
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ),
            Span::raw("  |  Duration: "),
            Span::styled(session.duration_str(), Style::default().fg(Color::Yellow)),
            Span::raw("  |  Root Agent: "),
            Span::styled(root_str, Style::default().fg(Color::LightBlue)),
        ]),
        Line::from(vec![
            Span::styled(
                "Total Memory:   ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                session.formatted_memory(),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  |  CPU%: "),
            Span::styled(session.formatted_cpu(), Style::default().fg(Color::Yellow)),
            Span::raw("  |  Listening Ports: "),
            Span::styled(session.ports_str(), Style::default().fg(Color::Magenta)),
        ]),
    ];
    let summary_widget = Paragraph::new(summary_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .title(" Session Overview ")
            .title_style(theme.title_style()),
    );
    frame.render_widget(summary_widget, chunks[0]);

    // 2. Navigation Tabs
    let tab_titles = vec![
        Line::from("[1] Process Lineage Tree"),
        Line::from(format!("[2] Cleanup Plan ({})", recommendations.len())),
        Line::from(format!("[3] Tracked Resources ({})", resources.len())),
    ];
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .title(" View Selection [1-3 / Tab] ")
                .title_style(theme.title_style()),
        )
        .select(active_tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        );
    frame.render_widget(tabs, chunks[1]);

    // 3. Tab Content
    match active_tab {
        0 => {
            // Tab 0: Process Lineage Tree
            let lines: Vec<&str> = tree_text.lines().collect();
            let total_lines = lines.len();
            let visible_height = chunks[2].height.saturating_sub(2) as usize;

            let max_scroll = total_lines.saturating_sub(visible_height);
            let effective_scroll = scroll.min(max_scroll);

            let visible_lines: Vec<Line> = lines
                .iter()
                .skip(effective_scroll)
                .take(visible_height)
                .map(|line| {
                    if line.contains("[ACTIVE]") {
                        Line::styled(*line, Style::default().fg(Color::Green))
                    } else if line.contains("[EXITED]") {
                        Line::styled(*line, Style::default().fg(Color::DarkGray))
                    } else if line.contains("[ROOT]") {
                        Line::styled(
                            *line,
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )
                    } else if line.contains("Ports:") {
                        Line::styled(*line, Style::default().fg(Color::Magenta))
                    } else if line.contains("Evidence:") {
                        Line::styled(*line, Style::default().fg(Color::Yellow))
                    } else {
                        Line::from(*line)
                    }
                })
                .collect();

            let scroll_indicator = if total_lines > visible_height {
                format!(
                    " [Line {}/{} - Scroll ↑/↓] ",
                    effective_scroll + 1,
                    total_lines
                )
            } else {
                String::new()
            };

            let tree_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" Process Lineage Tree{} ", scroll_indicator))
                .title_style(theme.title_style());

            let tree_widget = Paragraph::new(visible_lines).block(tree_block);
            frame.render_widget(tree_widget, chunks[2]);
        }
        1 => {
            // Tab 1: Cleanup Plan (Recommendations)
            let rec_header_cells = [
                "RESOURCE",
                "PID",
                "MEMORY",
                "PORTS",
                "OWNERSHIP",
                "DETACHED",
                "ELIGIBLE",
                "USER AUTH",
                "ELIGIBILITY DETAILS",
            ]
            .iter()
            .map(|h| Cell::from(*h).style(theme.header_style()));
            let rec_header = Row::new(rec_header_cells).height(1);

            let rec_rows = recommendations.iter().map(|rec| {
                let conf_style = match rec.ownership_confidence {
                    Confidence::Confirmed => Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                    Confidence::HighConfidence => Style::default().fg(Color::Cyan),
                    Confidence::Inferred => Style::default().fg(Color::Yellow),
                    Confidence::Unknown => Style::default().fg(Color::DarkGray),
                };

                let eligible_style = if rec.termination_eligible {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                };

                let detached_style = if rec.is_detached {
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let ports_str = if rec.associated_ports.is_empty() {
                    "-".to_string()
                } else {
                    rec.associated_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                };

                let cells = vec![
                    Cell::from(rec.resource_name.clone()),
                    Cell::from(rec.pid_or_id.clone()),
                    Cell::from(rec.memory_formatted.clone()),
                    Cell::from(ports_str),
                    Cell::from(rec.ownership_confidence.to_string()).style(conf_style),
                    Cell::from(if rec.is_detached { "YES" } else { "no" }).style(detached_style),
                    Cell::from(if rec.termination_eligible {
                        "ELIGIBLE"
                    } else {
                        "BLOCKED"
                    })
                    .style(eligible_style),
                    Cell::from(if rec.user_authorized {
                        "GRANTED"
                    } else {
                        "NO (PENDING)"
                    })
                    .style(Style::default().fg(Color::Yellow)),
                    Cell::from(rec.eligibility_reason.clone()),
                ];
                Row::new(cells)
            });

            let rec_table = Table::new(
                rec_rows,
                [
                    Constraint::Length(16), // Resource
                    Constraint::Length(8),  // PID
                    Constraint::Length(10), // RAM
                    Constraint::Length(10), // Ports
                    Constraint::Length(12), // Ownership
                    Constraint::Length(10), // Detached
                    Constraint::Length(12), // Eligible
                    Constraint::Length(14), // User Auth
                    Constraint::Min(25),    // Details
                ],
            )
            .header(rec_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(
                        " Session Cleanup Recommendations ({}) ",
                        recommendations.len()
                    ))
                    .title_style(theme.title_style()),
            );

            frame.render_widget(rec_table, chunks[2]);
        }
        _ => {
            // Tab 2: Tracked Resources Table
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

            let res_rows = resources.iter().map(|r| {
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
                    Cell::from(if r.is_detached { "YES (PID 1)" } else { "no" })
                        .style(detached_style),
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

            let resources_table = Table::new(
                res_rows,
                [
                    Constraint::Length(8),  // PID
                    Constraint::Length(20), // Name
                    Constraint::Length(14), // Attribution
                    Constraint::Length(14), // Detached
                    Constraint::Length(14), // Safe to stop
                    Constraint::Length(12), // RAM
                    Constraint::Length(14), // Ports
                    Constraint::Min(20),    // Evidence
                ],
            )
            .header(res_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" All Tracked Resources ({}) ", resources.len()))
                    .title_style(theme.title_style()),
            );

            frame.render_widget(resources_table, chunks[2]);
        }
    }

    // 4. Disclaimer and Footer
    let footer_text = vec![
        Line::from(vec![
            Span::styled(
                "SAFETY NOTICE: ",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                "Cleanup plan is advisory only. Processes are NOT terminated automatically without explicit user authorization.",
            ),
        ]),
        Line::from(vec![
            Span::styled(
                " [1] Lineage Tree | [2] Cleanup Plan | [3] Resources | [Tab] Switch | [↑/↓] Scroll | [Esc/Enter] Close ",
                Style::default().fg(Color::White).bg(Color::DarkGray),
            ),
        ]),
    ];
    let footer_widget = Paragraph::new(footer_text);
    frame.render_widget(footer_widget, chunks[3]);
}
