use crate::model::ProcessInfo;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render_confirm_modal(
    frame: &mut Frame,
    area: Rect,
    process: &ProcessInfo,
    force: bool,
    theme: &Theme,
) {
    let modal_width = 64.min(area.width);
    let modal_height = 14.min(area.height);

    let modal_area = Rect {
        x: area.x + (area.width - modal_width) / 2,
        y: area.y + (area.height - modal_height) / 2,
        width: modal_width,
        height: modal_height,
    };

    frame.render_widget(Clear, modal_area);

    let border_color = if force { theme.danger } else { theme.warning };
    let action_title = if force {
        " FORCE KILL PROCESS (SIGKILL) "
    } else {
        " TERMINATE PROCESS (SIGTERM) "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            action_title,
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);

    let warning_lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                &process.name,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" (PID: {})", process.pid)),
        ]),
        Line::from(vec![
            Span::styled(
                "Attribution: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{} [{}]",
                process.attribution.kind, process.attribution.confidence
            )),
        ]),
        Line::from(vec![
            Span::styled("Action: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                if force {
                    "Send SIGKILL immediately (potential unsaved state loss)"
                } else {
                    "Send SIGTERM gracefully (allows process to cleanly exit)"
                },
                Style::default().fg(if force { Color::Red } else { Color::Cyan }),
            ),
        ]),
    ];
    let warning_para = Paragraph::new(warning_lines);
    frame.render_widget(warning_para, chunks[0]);

    let prompt_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Are you sure you want to proceed?",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw(
            "TIMMY will never kill processes without explicit authorization.",
        )),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(prompt_para, chunks[1]);

    let action_keys = Paragraph::new(Line::from(vec![
        Span::styled(
            " [y] Confirm ",
            Style::default()
                .bg(border_color)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled(
            " [n / Esc] Cancel ",
            Style::default().bg(Color::DarkGray).fg(Color::White),
        ),
    ]));
    frame.render_widget(action_keys, chunks[2]);
}
