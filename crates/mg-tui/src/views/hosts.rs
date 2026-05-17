/*******************************************************************
 * Filename:        hosts.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Host list + detail panel view
 * Notes:           Left pane = host list; right pane = fingerprint/ports detail
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

// Render split pane: host list on left, host detail on right
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    render_host_list(f, app, chunks[0]);
    render_host_detail(f, app, chunks[1]);
}

// Render scrollable host list
fn render_host_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .data
        .hosts
        .iter()
        .map(|h| {
            let port_count = h.open_ports.len();
            let label = format!("{}  ({} ports)", h.hostname, port_count);
            ListItem::new(label)
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.host_cursor));

    let list = List::new(items)
        .block(Block::default().title(" Hosts  Enter browse ").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut state);
}

// Render detail panel for the selected host
fn render_host_detail(f: &mut Frame, app: &App, area: Rect) {
    let host = match app.data.hosts.get(app.host_cursor) {
        Some(h) => h,
        None => {
            let p = Paragraph::new("No host selected")
                .block(Block::default().title(" Detail ").borders(Borders::ALL));
            f.render_widget(p, area);
            return;
        }
    };

    let mut lines: Vec<Line> = Vec::new();

    // Hostname heading
    lines.push(Line::from(vec![
        Span::styled("Host:  ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(host.hostname.clone()),
    ]));

    // HTTP status
    if let Some(code) = host.status_code {
        let color = if code < 300 { Color::Green } else if code < 400 { Color::Yellow } else { Color::Red };
        lines.push(Line::from(vec![
            Span::styled("HTTP:  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(code.to_string(), Style::default().fg(color)),
        ]));
    }

    // Server header value
    if let Some(server) = &host.server {
        lines.push(Line::from(vec![
            Span::styled("Server:", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {server}")),
        ]));
    }

    lines.push(Line::raw(""));

    // Open ports
    lines.push(Line::from(Span::styled("Open ports:", Style::default().add_modifier(Modifier::BOLD))));
    if host.open_ports.is_empty() {
        lines.push(Line::raw("  (none found)"));
    } else {
        let port_str = host.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        lines.push(Line::raw(format!("  {port_str}")));
    }

    lines.push(Line::raw(""));

    // Tech stack
    lines.push(Line::from(Span::styled("Tech stack:", Style::default().add_modifier(Modifier::BOLD))));
    if host.tech_stack.is_empty() {
        lines.push(Line::raw("  (none detected)"));
    } else {
        for tech in &host.tech_stack {
            lines.push(Line::raw(format!("  • {tech}")));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default().title(" Host Detail ").borders(Borders::ALL));
    f.render_widget(p, area);
}
