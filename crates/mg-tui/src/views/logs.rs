/*******************************************************************
 * Filename:        logs.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Live audit.log tail view
 * Notes:           Scrolls with ↑↓; auto-scrolls to bottom on refresh
 *******************************************************************/

use crate::app::App;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

// Render log lines, scrolled to log_offset from top
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let lines = &app.data.log_lines;
    let start = app.log_offset.min(lines.len().saturating_sub(inner_height));
    let visible: Vec<Line> = lines[start..]
        .iter()
        .take(inner_height)
        .map(|l| colorize_log_line(l))
        .collect();

    let title = format!(" Logs — {} lines  (↑↓ scroll) ", lines.len());
    let p = Paragraph::new(visible)
        .block(Block::default().title(title).borders(Borders::ALL));
    f.render_widget(p, area);
}

// Colorize log lines by keyword prefix
fn colorize_log_line(line: &str) -> Line<'static> {
    let color = if line.contains("ERROR") || line.contains("FAIL") {
        Color::Red
    } else if line.contains("WARN") {
        Color::Yellow
    } else if line.contains("OK") || line.contains("done") || line.contains("complete") {
        Color::Green
    } else {
        Color::Gray
    };
    Line::from(Span::styled(line.to_string(), Style::default().fg(color)))
}
