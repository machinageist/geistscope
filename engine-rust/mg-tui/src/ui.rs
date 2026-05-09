/*******************************************************************
 * Filename:        ui.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Top-level render: tab bar + status bar + active view
 * Notes:           Status bar shows selected engagement and key hints
 *******************************************************************/

use crate::app::{App, Tab};
use crate::views::{browser, engagements, findings, fuzz, hosts, logs};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Tabs},
};

// Render all UI layers: tab bar, active view, status bar
pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    render_tab_bar(f, app, chunks[0]);

    match app.tab {
        Tab::Engagements => engagements::render(f, app, chunks[1]),
        Tab::Hosts => hosts::render(f, app, chunks[1]),
        Tab::Findings => findings::render(f, app, chunks[1]),
        Tab::Fuzz => fuzz::render(f, app, chunks[1]),
        Tab::Logs => logs::render(f, app, chunks[1]),
        Tab::Browser => browser::render(f, app, chunks[1]),
    }

    render_status_bar(f, app, chunks[2]);
}

// Render tab bar highlighting the active tab
fn render_tab_bar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(format!(" {} ", t.title())))
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .block(Block::default().borders(Borders::ALL).title(" GeistScope "))
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
        .divider("|");

    f.render_widget(tabs, area);
}

// Render one-line status bar with engagement name and key hints
fn render_status_bar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let engagement_label = app
        .selected_engagement
        .as_deref()
        .unwrap_or("(none selected)");

    let text = Line::from(vec![
        Span::styled(" Engagement: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(engagement_label, Style::default().fg(Color::Cyan)),
        Span::raw("   "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" next tab  "),
        Span::styled("BackTab", Style::default().fg(Color::Yellow)),
        Span::raw(" prev  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("f", Style::default().fg(Color::Yellow)),
        Span::raw(" filter  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh "),
    ]);

    let p = ratatui::widgets::Paragraph::new(text)
        .style(Style::default().bg(Color::DarkGray));
    f.render_widget(p, area);
}
