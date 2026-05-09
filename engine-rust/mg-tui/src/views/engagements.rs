/*******************************************************************
 * Filename:        engagements.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Engagement list table view
 * Notes:           Enter selects; recon_done shown as checkmark
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

// Render engagement list as a scrollable table
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Target").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Platform").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Recon").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Findings").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = app
        .engagements
        .iter()
        .map(|e| {
            let recon_cell = if e.recon_done { "✓" } else { "·" };
            Row::new(vec![
                Cell::from(e.name.clone()),
                Cell::from(e.target.clone()),
                Cell::from(e.platform.clone()),
                Cell::from(recon_cell),
                Cell::from(e.findings_count.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(35),
        Constraint::Percentage(15),
        Constraint::Percentage(10),
        Constraint::Percentage(15),
    ];

    let mut state = TableState::default();
    state.select(Some(app.engagement_cursor));

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Engagements — ↑↓ move  Enter select  Tab next ")
                .borders(Borders::ALL),
        )
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan));

    f.render_stateful_widget(table, area, &mut state);
}
