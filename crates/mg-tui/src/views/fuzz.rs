/*******************************************************************
 * Filename:        fuzz.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Fuzz job results viewer — only shows interesting hits
 * Notes:           Pulls from all fuzz-*.json files in recon/
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

// Render table of interesting fuzz results
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let results = &app.data.fuzz_results;

    let header = Row::new(vec![
        Cell::from("Label").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Δ Len").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("ms").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = results
        .iter()
        .map(|r| {
            let status_color = if r.status < 300 {
                Color::Green
            } else if r.status < 400 {
                Color::Yellow
            } else {
                Color::Red
            };
            let timing_color = if r.elapsed_ms > 4000 { Color::Magenta } else { Color::Reset };
            Row::new(vec![
                Cell::from(r.label.clone()),
                Cell::from(r.status.to_string())
                    .style(Style::default().fg(status_color)),
                Cell::from(format!("{:+}", r.len_delta)),
                Cell::from(r.elapsed_ms.to_string())
                    .style(Style::default().fg(timing_color)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(55),
        Constraint::Percentage(12),
        Constraint::Percentage(18),
        Constraint::Percentage(15),
    ];

    let mut state = TableState::default();
    if !results.is_empty() {
        state.select(Some(app.fuzz_cursor.min(results.len() - 1)));
    }

    let title = format!(" Fuzz — {} interesting results ", results.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan));

    f.render_stateful_widget(table, area, &mut state);
}
