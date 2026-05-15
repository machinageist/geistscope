/*******************************************************************
 * Filename:        harness.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Harness status tab: endpoint registry and audit events
 * Notes:           Uses audit.log-derived state until mg-harness becomes a
 *                  long-running process with explicit queue state.
 *******************************************************************/

use crate::app::App;
use crate::loader::HarnessEvent;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

// Render harness summary and event tail
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Min(0),
        ])
        .split(area);

    render_summary(f, app, chunks[0]);
    render_registry(f, chunks[1]);
    render_events(f, app, chunks[2]);
}

// Render current harness status
fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.selected_engagement.as_deref().unwrap_or("(none)");
    let harness = &app.data.harness;
    let endpoint_specs = mg_harness::registry();
    let implemented = endpoint_specs
        .iter()
        .filter(|spec| spec.implemented)
        .count();
    let total = endpoint_specs.len();

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "Engagement: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(selected.to_string(), Style::default().fg(Color::Cyan)),
            Span::raw("   "),
            Span::styled("Endpoints: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{implemented}/{total} implemented"),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Current endpoint: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                harness.current_endpoint.clone(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Last result: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                harness.last_result.clone(),
                status_style(&harness.last_result),
            ),
            Span::raw("   "),
            Span::styled(
                "Queue depth: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                harness.queue_depth.to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from("Queue depth is inferred as 0 until the harness daemon lands."),
    ];

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Harness Status ")
            .borders(Borders::ALL),
    );
    f.render_widget(paragraph, area);
}

// Render endpoint registry summary
fn render_registry(f: &mut Frame, area: Rect) {
    let rows: Vec<Row> = mg_harness::registry()
        .into_iter()
        .map(|spec| {
            let implemented = if spec.implemented { "yes" } else { "planned" };
            Row::new(vec![
                Cell::from(spec.name),
                Cell::from(format!("{:?}", spec.risk)),
                Cell::from(implemented),
                Cell::from(spec.description),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["Endpoint", "Risk", "Status", "Description"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" Endpoint Registry ")
            .borders(Borders::ALL),
    );

    f.render_widget(table, area);
}

// Render harness-only audit event tail
fn render_events(f: &mut Frame, app: &App, area: Rect) {
    let events = &app.data.harness.events;
    let inner_height = area.height.saturating_sub(2) as usize;
    let start = app
        .harness_offset
        .min(events.len().saturating_sub(inner_height));
    let lines: Vec<Line> = events[start..]
        .iter()
        .take(inner_height)
        .map(render_event_line)
        .collect();

    let title = format!(
        " Harness Audit Tail - {} events  (up/down scroll) ",
        events.len()
    );
    let paragraph =
        Paragraph::new(lines).block(Block::default().title(title).borders(Borders::ALL));
    f.render_widget(paragraph, area);
}

// Render one parsed harness event
fn render_event_line(event: &HarnessEvent) -> Line<'static> {
    let status = if event.status.is_empty() {
        "recorded".to_string()
    } else {
        event.status.clone()
    };
    let risk = if event.risk.is_empty() {
        "-".to_string()
    } else {
        event.risk.clone()
    };
    Line::from(vec![
        Span::styled(
            format!("{} ", event.timestamp),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{:<18}", event.endpoint),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!(" risk={:<12}", risk),
            Style::default().fg(Color::Magenta),
        ),
        Span::styled(format!(" status={:<16}", status), status_style(&status)),
        Span::styled(
            format!(" target={} ", event.target),
            Style::default().fg(Color::Gray),
        ),
        Span::raw(event.raw.clone()),
    ])
}

// Return color for status-like strings
fn status_style(status: &str) -> Style {
    if status.contains("ok") || status.contains("true") || status.contains("recorded") {
        Style::default().fg(Color::Green)
    } else if status.contains("blocked") || status.contains("false") || status.contains("error") {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Yellow)
    }
}
