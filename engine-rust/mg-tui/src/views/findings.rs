/*******************************************************************
 * Filename:        findings.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Findings browser with severity filter
 * Notes:           'f' cycles filter: all → critical → high → medium → low → info
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

// Map severity string to a display color
fn severity_color(s: &str) -> Color {
    match s.to_lowercase().as_str() {
        "critical" => Color::Red,
        "high" => Color::LightRed,
        "medium" => Color::Yellow,
        "low" => Color::Blue,
        _ => Color::Gray,
    }
}

// Render findings table with optional severity filter
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let filter = &app.findings_filter;
    let filtered: Vec<_> = app
        .data
        .findings
        .iter()
        .filter(|f| filter.is_empty() || f.severity.eq_ignore_ascii_case(filter))
        .collect();

    let filter_label = if filter.is_empty() { "all".to_string() } else { filter.clone() };
    let title = format!(" Findings — filter: {filter_label}  (f to cycle) ");

    let header = Row::new(vec![
        Cell::from("Severity").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Host").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Title").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("ID").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = filtered
        .iter()
        .map(|f| {
            Row::new(vec![
                Cell::from(f.severity.clone())
                    .style(Style::default().fg(severity_color(&f.severity))),
                Cell::from(f.host.clone()),
                Cell::from(f.title.clone()),
                Cell::from(f.id.clone()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(12),
        Constraint::Percentage(28),
        Constraint::Percentage(45),
        Constraint::Percentage(15),
    ];

    let mut state = TableState::default();
    if !filtered.is_empty() {
        state.select(Some(app.finding_cursor.min(filtered.len() - 1)));
    }

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan));

    f.render_stateful_widget(table, area, &mut state);
}
