use crate::model::ListeningPort;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Constraint, Rect},
    style::Style,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

pub fn render_port_table(
    frame: &mut Frame,
    area: Rect,
    ports: &[ListeningPort],
    state: &mut TableState,
    theme: &Theme,
    filter: &str,
) {
    let filtered_ports: Vec<&ListeningPort> = ports
        .iter()
        .filter(|p| {
            let port_str = p.port.to_string();
            let pid_str = p.pid.map(|pid| pid.to_string()).unwrap_or_default();
            let proc_str = p.process_name.as_deref().unwrap_or("");
            let proto_str = p.protocol.to_string();
            let fields = [&port_str, &pid_str, proc_str, &proto_str, &p.ip];
            crate::ui::matches_filter_tokens(&fields, filter)
        })
        .collect();

    let header_cells = ["PORT", "PROTO", "IP ADDRESS", "PID", "PROCESS", "STATE"]
        .iter()
        .map(|h| Cell::from(*h).style(theme.header_style()));
    let header = Row::new(header_cells).height(1);

    let rows = filtered_ports.iter().map(|p| {
        let cells = vec![
            Cell::from(p.port.to_string()),
            Cell::from(p.protocol.to_string()),
            Cell::from(p.ip.clone()),
            Cell::from(
                p.pid
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(
                p.process_name
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
            ),
            Cell::from(p.state.to_string()),
        ];
        Row::new(cells).height(1)
    });

    let title = if filter.is_empty() {
        format!(" Listening Ports ({}) ", filtered_ports.len())
    } else {
        format!(
            " Listening Ports ({}) [Filter: '{}'] ",
            filtered_ports.len(),
            filter
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Percentage(25),
            Constraint::Length(10),
            Constraint::Percentage(35),
            Constraint::Length(12),
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
