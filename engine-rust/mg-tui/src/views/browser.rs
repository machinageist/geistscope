/*******************************************************************
 * Filename:        browser.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     In-TUI browser view: URL bar, rendered page, link navigator
 * Notes:           render_page renders line-by-line so image placeholder lines
 *                  can be swapped out for cached halfblock pixel spans.
 *                  Keys: u=URL  ↑↓/jk=scroll  [/]=links  Enter=follow
 *                        b=back  R=reload  mouse wheel=scroll  click=link/tab
 *******************************************************************/

use crate::app::App;
use crate::html_render::{FieldType, FormElement, parse_field_marker, parse_img_marker};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

// Render URL bar, status line, page content, and link/help bar
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // URL bar
            Constraint::Length(1), // HTTP status line
            Constraint::Min(0),    // page content
            Constraint::Length(1), // link / help bar
        ])
        .split(area);

    render_url_bar(f, app, chunks[0]);
    render_status_line(f, app, chunks[1]);
    render_page(f, app, chunks[2]);
    render_link_bar(f, app, chunks[3]);
}

// Render editable URL input bar
fn render_url_bar(f: &mut Frame, app: &App, area: Rect) {
    let b = &app.browser;
    let display = if b.url_editing { &b.url_buf } else { &b.url };
    let cursor = if b.url_editing { "\u{2502}" } else { "" };
    let label = if b.url_editing {
        Span::styled(" URL \u{25B8} ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" URL   ", Style::default().fg(Color::DarkGray))
    };
    let border_style = if b.url_editing {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let p = Paragraph::new(Line::from(vec![
        label,
        Span::styled(display.clone(), Style::default().fg(Color::White)),
        Span::styled(cursor, Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(border_style));
    f.render_widget(p, area);
}

// Render one-line HTTP status bar
fn render_status_line(f: &mut Frame, app: &App, area: Rect) {
    let b = &app.browser;
    let spans = if b.loading {
        vec![Span::styled(" \u{27F3} Loading\u{2026}", Style::default().fg(Color::Yellow))]
    } else if let Some(err) = &b.error {
        vec![
            Span::styled(" \u{2717} ", Style::default().fg(Color::Red)),
            Span::raw(err.clone()),
        ]
    } else if b.status > 0 {
        let status_color = match b.status {
            200..=299 => Color::Green,
            300..=399 => Color::Yellow,
            400..=499 => Color::LightRed,
            _ => Color::Red,
        };
        let title = b.page.as_ref().and_then(|p| {
            if p.title.is_empty() { None } else { Some(p.title.clone()) }
        });
        let img_count = b.page.as_ref().map_or(0, |p| p.images.len());
        let cached = b.image_cache.len();
        let mut s = vec![
            Span::styled(format!(" {} ", b.status), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
            Span::styled("\u{00B7} ", Style::default().fg(Color::DarkGray)),
            Span::styled(b.content_type.clone(), Style::default().fg(Color::Gray)),
        ];
        if img_count > 0 {
            s.push(Span::styled(
                format!("  \u{00B7}  \u{1F5BC} {cached}/{img_count}"),
                Style::default().fg(Color::DarkGray),
            ));
        }
        if let Some(t) = title {
            s.push(Span::styled("  \u{00B7}  ", Style::default().fg(Color::DarkGray)));
            s.push(Span::styled(t, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
        }
        s
    } else {
        vec![Span::styled(
            "  u URL  Enter navigate  b back  [ ] links  R reload  scroll or wheel",
            Style::default().fg(Color::DarkGray),
        )]
    };
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// Render page content line-by-line, substituting image placeholders from cache
fn render_page(f: &mut Frame, app: &App, area: Rect) {
    let b = &app.browser;
    let page = match &b.page {
        None => {
            let msg = if b.loading { "Fetching\u{2026}" } else { "No page loaded.  Press  u  to enter a URL." };
            f.render_widget(
                Paragraph::new(msg).style(Style::default().fg(Color::DarkGray)),
                area,
            );
            return;
        }
        Some(p) => p,
    };

    let selected_n = b.selected_link + 1;

    for (screen_row, line) in page.lines.iter().skip(b.scroll).enumerate() {
        let screen_row = screen_row as u16;
        if screen_row >= area.height {
            break;
        }
        let row_rect = Rect::new(area.x, area.y + screen_row, area.width, 1);

        if let Some((img_idx, img_row)) = parse_img_marker(line) {
            // Substitute cached halfblock line if available
            if let Some(cached) = b.image_cache.get(&img_idx) {
                let render_line = cached.get(img_row).cloned().unwrap_or_else(Line::default);
                f.render_widget(Paragraph::new(render_line), row_rect);
            } else if img_row == 0 {
                // Loading placeholder on the first row of each unreceived image
                let alt = page
                    .images
                    .iter()
                    .find(|i| i.index == img_idx)
                    .map(|i| i.alt.as_str())
                    .unwrap_or("image");
                f.render_widget(
                    Paragraph::new(Span::styled(
                        format!(" \u{27F3} [{alt}]"),
                        Style::default().fg(Color::DarkGray),
                    )),
                    row_rect,
                );
            }
        } else if let Some(field_idx) = parse_field_marker(line) {
            // Render interactive form field at this line
            if let Some(field) = page.form_elements.iter().find(|f| f.index == field_idx) {
                let value = b.field_values.get(&field_idx)
                    .map(String::as_str)
                    .unwrap_or(&field.value);
                let is_focused = b.focused_field == Some(field_idx);
                let rendered = render_field_line(field, value, is_focused, area.width);
                f.render_widget(Paragraph::new(rendered), row_rect);
            }
        } else {
            f.render_widget(
                Paragraph::new(highlight_selected_link(line.clone(), selected_n)),
                row_rect,
            );
        }
    }
}

// Render one interactive form field line based on its type and focus state
fn render_field_line(field: &FormElement, value: &str, is_focused: bool, width: u16) -> Line<'static> {
    let w = width.saturating_sub(4) as usize;
    match &field.field_type {
        FieldType::Hidden => Line::default(),

        FieldType::Submit | FieldType::Button => {
            let label = if !field.placeholder.is_empty() { field.placeholder.as_str() }
                else if !field.value.is_empty() { field.value.as_str() }
                else { "Submit" };
            let style = if is_focused {
                Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            };
            Line::from(Span::styled(format!("  [ {label} ]"), style))
        }

        FieldType::Checkbox { checked } => {
            let on = value == "1" || value == "true" || (value.is_empty() && *checked);
            let box_str = if on { "[x]" } else { "[ ]" };
            let style = if is_focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(vec![
                Span::styled(box_str.to_string(), style),
                Span::raw(format!(" {}", field.name)),
            ])
        }

        FieldType::Radio { checked } => {
            let on = value == "1" || value == "true" || (value.is_empty() && *checked);
            let box_str = if on { "(\u{2022})" } else { "( )" };
            let style = if is_focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(vec![
                Span::styled(box_str.to_string(), style),
                Span::raw(format!(" {}", field.name)),
            ])
        }

        FieldType::Select(options) => {
            let label = options.iter()
                .find(|(v, _)| v == value)
                .map(|(_, l)| l.as_str())
                .or_else(|| options.first().map(|(_, l)| l.as_str()))
                .unwrap_or(value);
            let style = if is_focused {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Cyan)
            };
            Line::from(Span::styled(format!("  \u{25BE} {label} "), style))
        }

        FieldType::File => {
            let display = if value.is_empty() { "(no file chosen)".to_string() } else { value.to_string() };
            let style = if is_focused {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::UNDERLINED)
            };
            Line::from(vec![
                Span::styled(format!("  \u{1F4C4} {display}"), style),
            ])
        }

        FieldType::Password => {
            let hidden = "\u{2022}".repeat(value.chars().count().min(w));
            let display = if value.is_empty() {
                format!("  {:<w$}", field.placeholder)
            } else {
                format!("  {hidden}")
            };
            render_text_input_line(&display, is_focused)
        }

        // Text, Email, Search, TextArea all render as editable text lines
        _ => {
            let display = if value.is_empty() {
                format!("  {:<w$}", field.placeholder)
            } else {
                format!("  {value}")
            };
            render_text_input_line(&display, is_focused)
        }
    }
}

// Render a single-line text input widget
fn render_text_input_line(display: &str, is_focused: bool) -> Line<'static> {
    if is_focused {
        Line::from(vec![
            Span::styled(display.to_string(), Style::default().fg(Color::Black).bg(Color::White)),
            Span::styled("\u{2502}", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)),
        ])
    } else {
        Line::from(Span::styled(
            display.to_string(),
            Style::default().fg(Color::White).add_modifier(Modifier::UNDERLINED),
        ))
    }
}

// Brighten the [N] span that corresponds to the selected link
fn highlight_selected_link(line: Line<'static>, n: usize) -> Line<'static> {
    let marker = format!("[{n}]");
    Line::from(
        line.spans
            .into_iter()
            .map(|s| {
                if s.content.as_ref() == marker.as_str() {
                    Span::styled(s.content, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
                } else {
                    s
                }
            })
            .collect::<Vec<_>>(),
    )
}

// Render link navigator + key hints
fn render_link_bar(f: &mut Frame, app: &App, area: Rect) {
    let b = &app.browser;
    let spans = if b.focused_field.is_some() {
        vec![Span::styled(
            "  Tab next field  Shift-Tab prev  Enter submit  Esc unfocus  type to edit",
            Style::default().fg(Color::Yellow),
        )]
    } else if b.link_count() > 0 {
        let url = b.selected_link_url().unwrap_or("");
        vec![
            Span::styled(
                format!(" [{}/{}] ", b.selected_link + 1, b.link_count()),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(url.to_string(), Style::default().fg(Color::White)),
            Span::styled(
                "   [ prev  ] next  Enter follow  Tab field  b back  u URL  R reload",
                Style::default().fg(Color::DarkGray),
            ),
        ]
    } else {
        vec![Span::styled(
            "  u URL  b back  \u{2191}\u{2193} scroll  Tab field  R reload  mouse wheel to scroll",
            Style::default().fg(Color::DarkGray),
        )]
    };
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

