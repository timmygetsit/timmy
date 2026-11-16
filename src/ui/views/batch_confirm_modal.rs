use crate::model::ProcessInfo;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame,
};

pub fn render_batch_confirm_modal(
    frame: &mut Frame,
    area: Rect,
    eligible: &[ProcessInfo],
    blocked: &[(ProcessInfo, String)],
    force: bool,
    theme: &Theme,
) {
    let total_count = eligible.len() + blocked.len();
    let modal_width = (area.width * 85 / 100).max(65).min(area.width);
    let modal_height = (area.height * 85 / 100).max(18).min(area.height);

    let modal_area = Rect {
        x: area.x + (area.width - modal_width) / 2,
        y: area.y + (area.height - modal_height) / 2,
        width: modal_width,
        height: modal_height,
    };

    frame.render_widget(Clear, modal_area);

    let sig_name = if force { "SIGKILL" } else { "SIGTERM" };
    let border_color = if force { theme.danger } else { theme.warning };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            " Confirm Batch Termination: {} Processes ({}) ",
            total_count, sig_name
        ))
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Warning summary
            Constraint::Min(6),    // Eligible processes table
            if !blocked.is_empty() {
                Constraint::Length((blocked.len() as u16 + 2).min(8))
            } else {
                Constraint::Length(0)
            }, // Blocked processes
            Constraint::Length(2), // Prompt footer
        ])
        .split(inner);

    // 1. Warning summary
    let summary_lines = vec![
        Line::from(vec![
            Span::styled("ACTION: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(
                    "Terminate {} eligible processes using {}",
                    eligible.len(),
                    sig_name
                ),
                Style::default()
                    .fg(if force { Color::Red } else { Color::Yellow })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            format!(
                "ELIGIBLE: {}  |  BLOCKED BY SYSTEM SAFETY SHIELD: {}",
                eligible.len(),
                blocked.len()
            ),
            Style::default().fg(Color::White),
        )]),
    ];
    let summary = Paragraph::new(summary_lines);
    frame.render_widget(summary, chunks[0]);

    // 2. Eligible processes table
    let header_cells = ["PID", "PROCESS NAME", "AI ATTRIBUTION", "RAM", "PORTS"]
        .iter()
        .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = eligible.iter().map(|p| {
        let ports_str = if p.listening_ports.is_empty() {
            "-".to_string()
        } else {
            p.listening_ports
                .iter()
                .map(|pt| pt.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let cells = vec![
            Cell::from(p.pid.to_string()),
            Cell::from(p.name.clone()),
            Cell::from(p.attribution.kind.to_string()),
            Cell::from(p.formatted_memory()),
            Cell::from(ports_str),
        ];
        Row::new(cells)
    });

    let eligible_table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Min(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Eligible for Termination ({}) ", eligible.len()))
            .title_style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(eligible_table, chunks[1]);

    // 3. Blocked processes section
    if !blocked.is_empty() {
        let blocked_rows = blocked.iter().map(|(p, reason)| {
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.name.clone()),
                Cell::from("BLOCKED")
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Cell::from(reason.clone()).style(Style::default().fg(Color::Yellow)),
            ])
        });
        let blocked_table = Table::new(
            blocked_rows,
            [
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Length(12),
                Constraint::Min(25),
            ],
        )
        .header(Row::new(vec![
            Cell::from("PID").style(theme.header_style()),
            Cell::from("PROCESS").style(theme.header_style()),
            Cell::from("STATUS").style(theme.header_style()),
            Cell::from("SAFETY REASON").style(theme.header_style()),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Shielded by Safety Guardrails ({}) - Will NOT Be Terminated ",
                    blocked.len()
                ))
                .title_style(Style::default().fg(Color::Red)),
        );
        frame.render_widget(blocked_table, chunks[2]);
    }

    // 4. Prompt footer
    let prompt_text = vec![Line::from(vec![
        Span::styled(
            "Execute batch termination? ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "[y] YES, TERMINATE ELIGIBLE",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("[n/Esc] Cancel", Style::default().fg(Color::White)),
    ])];
    let prompt = Paragraph::new(prompt_text);
    frame.render_widget(prompt, chunks[3]);
}
