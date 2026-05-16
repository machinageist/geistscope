/*******************************************************************
 * Filename:        requests.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Request corpus table view
 * Notes:           Shows normalized traffic/corpus.jsonl rows for pivots
 *                  into browser, replay, fuzz, and findings workflows.
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

// Render normalized request corpus rows
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let requests = &app.data.requests;
    let header = Row::new(vec![
        Cell::from("ID").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Method").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Host").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Path").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Auth").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Source").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Seen").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = requests
        .iter()
        .map(|request| {
            let status = request
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".into());
            let status_style = request
                .status
                .map_or(Style::default().fg(Color::Gray), |status| {
                    if status < 300 {
                        Style::default().fg(Color::Green)
                    } else if status < 400 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::Red)
                    }
                });
            Row::new(vec![
                Cell::from(short_id(&request.id)),
                Cell::from(request.method.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(status).style(status_style),
                Cell::from(request.host.clone()),
                Cell::from(path_label(&request.path, &request.mime)),
                Cell::from(request.auth_state.clone()),
                Cell::from(request.source.clone()),
                Cell::from(seen_label(&request.captured_at)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(10),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(22),
        Constraint::Percentage(31),
        Constraint::Percentage(9),
        Constraint::Percentage(6),
        Constraint::Percentage(6),
    ];

    let mut state = TableState::default();
    if !requests.is_empty() {
        state.select(Some(app.request_cursor.min(requests.len() - 1)));
    }

    let title = format!(" Requests - {} corpus rows  Enter browse ", requests.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan));

    f.render_stateful_widget(table, area, &mut state);
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

fn seen_label(captured_at: &str) -> String {
    captured_at.chars().take(10).collect()
}

fn path_label(path: &str, mime: &str) -> String {
    if mime.is_empty() {
        path.to_string()
    } else {
        format!("{path}  {mime}")
    }
}
