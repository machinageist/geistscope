/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     mg-tui entry point: terminal setup, event + mouse loop, cleanup
 * Notes:           Single mpsc channel carries AppMsg (page fetches + image fetches).
 *                  Mouse: wheel=scroll, left-click tab bar=switch, click content=link.
 *                  Image threads spawn after each page load, one per <img> slot.
 *******************************************************************/

mod app;
mod browser_fetch;
mod halfblock;
mod html_render;
mod loader;
mod ui;
mod views;

use anyhow::Result;
use app::{App, Tab};
use browser_fetch::{AppMsg, FetchResult, fetch_page, fetch_post};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use html_render::{FieldType, parse_field_marker};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    env, io,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_millis(250);
const SEVERITY_CYCLE: &[&str] = &["", "critical", "high", "medium", "low", "info"];
// Rows scrolled per mouse-wheel click
const MOUSE_SCROLL_STEP: usize = 3;

fn main() -> Result<()> {
    let engagements_dir = engagements_dir();
    let mut app = App::new(engagements_dir);
    let (tx, rx) = mpsc::channel::<AppMsg>();
    run(&mut app, tx, rx)
}

// Resolve engagements directory from env or default
fn engagements_dir() -> PathBuf {
    env::var("MG_ENGAGEMENTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("engagements"))
}

// Setup terminal (raw mode + alternate screen + mouse), run loop, restore on exit
fn run(app: &mut App, tx: Sender<AppMsg>, rx: Receiver<AppMsg>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, app, tx, rx);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    result
}

// Main event loop: draw, handle input, refresh engagement data, apply messages
fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tx: Sender<AppMsg>,
    rx: Receiver<AppMsg>,
) -> Result<()> {
    let mut last_refresh = Instant::now();

    loop {
        terminal.draw(|f| ui::render(f, app))?;

        // Refresh engagement file data on timer
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            app.refresh();
            last_refresh = Instant::now();
        }

        // Drain all pending background messages (page + image fetches)
        while let Ok(msg) = rx.try_recv() {
            match msg {
                AppMsg::Page(Ok(r)) => apply_page(app, *r, &tx),
                AppMsg::Page(Err(e)) => {
                    app.browser.loading = false;
                    app.browser.error = Some(e);
                }
                AppMsg::Image(r) => {
                    app.browser.image_cache.insert(r.index, r.lines);
                }
            }
        }

        if event::poll(POLL_TIMEOUT)?
            && let event = event::read()?
        {
            match event {
                Event::Key(key) => handle_key(app, key.code, key.modifiers, &tx),
                Event::Mouse(me) => handle_mouse(app, me.kind, me.column, me.row, terminal, &tx),
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

// Apply a successful page load: store page, spawn image fetch threads
fn apply_page(app: &mut App, r: FetchResult, tx: &Sender<AppMsg>) {
    // Collect image slots before the page is moved into app state
    let image_srcs: Vec<(usize, String)> = r
        .page
        .images
        .iter()
        .map(|i| (i.index, i.src.clone()))
        .collect();
    let base_url = r.url.clone();

    app.browser.url = r.url;
    app.browser.url_buf = app.browser.url.clone();
    app.browser.request_method = r.request_method;
    app.browser.status = r.status;
    app.browser.content_type = r.content_type;
    app.browser.response_headers = r.response_headers;
    app.browser.response_cookies = r.response_cookies;
    app.browser.image_cache.clear();
    app.browser.page = Some(r.page);
    app.browser.loading = false;
    app.browser.error = None;
    app.browser.scroll = 0;
    app.browser.selected_link = 0;
    app.browser.recompute_find_matches();

    // Spawn one background thread per image slot
    for (index, raw_src) in image_srcs {
        let resolved = resolve_url(&raw_src, &base_url);
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Some(result) = browser_fetch::fetch_image(&resolved, index) {
                let _ = tx.send(AppMsg::Image(result));
            }
        });
    }
}

// Kick off a page fetch in a background thread
fn navigate(url: String, tx: &Sender<AppMsg>) {
    let tx = tx.clone();
    std::thread::spawn(move || {
        let _ = tx.send(AppMsg::Page(
            fetch_page(&url).map(Box::new).map_err(|e| e.to_string()),
        ));
    });
}

// Dispatch keyboard events
fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers, tx: &Sender<AppMsg>) {
    // Browser search input intercepts text until Enter or Esc
    if app.tab == Tab::Browser && app.browser.find_editing {
        handle_find_key(app, code);
        return;
    }

    // URL bar editing intercepts most keys
    if app.tab == Tab::Browser && app.browser.url_editing {
        handle_url_bar_key(app, code, tx);
        return;
    }

    // Field focus intercepts most keys while a form field is active
    if app.tab == Tab::Browser && app.browser.focused_field.is_some() {
        handle_field_key(app, code, modifiers, tx);
        return;
    }

    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => app.should_quit = true,

        // On Browser tab, Tab/BackTab cycle form fields instead of switching tabs
        KeyCode::Tab if app.tab == Tab::Browser => app.browser.focus_next_field(),
        KeyCode::BackTab if app.tab == Tab::Browser => app.browser.focus_prev_field(),
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),

        KeyCode::Up | KeyCode::Char('k') => app.cursor_up(),
        KeyCode::Down | KeyCode::Char('j') => app.cursor_down(),

        KeyCode::PageUp if app.tab == Tab::Browser => {
            for _ in 0..20 {
                app.cursor_up();
            }
        }
        KeyCode::PageDown if app.tab == Tab::Browser => {
            for _ in 0..20 {
                app.cursor_down();
            }
        }

        KeyCode::Enter if app.tab == Tab::Engagements => {
            app.select_engagement();
        }

        KeyCode::Enter if app.tab == Tab::Browser => {
            if let Some(url) = app.browser.selected_link_url().map(str::to_string) {
                let resolved = resolve_url(&url, &app.browser.url);
                app.browser.begin_navigate(&resolved);
                navigate(resolved, tx);
            }
        }

        KeyCode::Char('u') if app.tab == Tab::Browser => {
            app.browser.url_editing = true;
            app.browser.url_buf = app.browser.url.clone();
        }
        KeyCode::Char('b') if app.tab == Tab::Browser => {
            if let Some(prev) = app.browser.go_back() {
                navigate(prev, tx);
            }
        }
        KeyCode::Char('R') if app.tab == Tab::Browser => {
            let url = app.browser.url.clone();
            if !url.is_empty() {
                app.browser.loading = true;
                app.browser.error = None;
                navigate(url, tx);
            }
        }
        KeyCode::Char('/') if app.tab == Tab::Browser => app.browser.begin_find(),
        KeyCode::Char('n') if app.tab == Tab::Browser => app.browser.next_find_match(),
        KeyCode::Char('N') if app.tab == Tab::Browser => app.browser.prev_find_match(),
        KeyCode::Char('i') if app.tab == Tab::Browser => app.browser.toggle_inspector(),
        KeyCode::Char(']') if app.tab == Tab::Browser => app.browser.next_link(),
        KeyCode::Char('[') if app.tab == Tab::Browser => app.browser.prev_link(),

        KeyCode::Char('r') => app.refresh(),
        KeyCode::Char('f') => cycle_findings_filter(app),

        _ => {}
    }
}

// Handle browser search input
fn handle_find_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => app.browser.apply_find(),
        KeyCode::Esc => app.browser.cancel_find(),
        KeyCode::Backspace => {
            app.browser.find_buf.pop();
        }
        KeyCode::Char(c) => app.browser.find_buf.push(c),
        _ => {}
    }
}

// Handle key input while a form field is focused
fn handle_field_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers, tx: &Sender<AppMsg>) {
    let idx = match app.browser.focused_field {
        Some(i) => i,
        None => return,
    };

    match code {
        KeyCode::Esc => app.browser.focused_field = None,

        KeyCode::Tab => app.browser.focus_next_field(),
        KeyCode::BackTab => app.browser.focus_prev_field(),

        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => app.should_quit = true,

        KeyCode::Enter => {
            // Find the form this field belongs to; submit or advance
            let form_idx = app
                .browser
                .page
                .as_ref()
                .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                .and_then(|f| f.form_index);
            if let Some(fi) = form_idx {
                submit_form(app, fi, tx);
            } else {
                app.browser.focus_next_field();
            }
        }

        KeyCode::Backspace => {
            if let Some(v) = app.browser.field_values.get_mut(&idx) {
                v.pop();
            } else {
                let def = app
                    .browser
                    .page
                    .as_ref()
                    .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                    .map(|f| f.value.clone())
                    .unwrap_or_default();
                let mut s = def;
                s.pop();
                app.browser.field_values.insert(idx, s);
            }
        }

        KeyCode::Char(' ') => {
            // Space toggles checkbox/radio; submits submit buttons; otherwise appends
            let field_type = app
                .browser
                .page
                .as_ref()
                .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                .map(|f| f.field_type.clone());
            match field_type {
                Some(FieldType::Checkbox { .. }) => {
                    let cur = app
                        .browser
                        .field_values
                        .get(&idx)
                        .map(String::as_str)
                        .unwrap_or("0");
                    let toggled = if cur == "1" { "0" } else { "1" };
                    app.browser.field_values.insert(idx, toggled.to_string());
                }
                Some(FieldType::Submit) | Some(FieldType::Button) => {
                    let form_idx = app
                        .browser
                        .page
                        .as_ref()
                        .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                        .and_then(|f| f.form_index);
                    if let Some(fi) = form_idx {
                        submit_form(app, fi, tx);
                    }
                }
                _ => {
                    let entry = app.browser.field_values.entry(idx).or_insert_with(|| {
                        app.browser
                            .page
                            .as_ref()
                            .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                            .map(|f| f.value.clone())
                            .unwrap_or_default()
                    });
                    entry.push(' ');
                }
            }
        }

        KeyCode::Char(c) => {
            let entry = app.browser.field_values.entry(idx).or_insert_with(|| {
                app.browser
                    .page
                    .as_ref()
                    .and_then(|p| p.form_elements.iter().find(|f| f.index == idx))
                    .map(|f| f.value.clone())
                    .unwrap_or_default()
            });
            entry.push(c);
        }

        _ => {}
    }
}

// Submit a form by index: GET appends query string, POST uses fetch_post
fn submit_form(app: &mut App, form_idx: usize, tx: &Sender<AppMsg>) {
    let page = match &app.browser.page {
        Some(p) => p,
        None => return,
    };
    let form = match page.forms.get(form_idx) {
        Some(f) => f,
        None => return,
    };
    let action = if form.action.is_empty() {
        app.browser.url.clone()
    } else {
        resolve_url(&form.action, &app.browser.url)
    };
    let method = form.method.clone();

    // Build params from non-hidden, named fields belonging to this form
    let params: Vec<(String, String)> = page
        .form_elements
        .iter()
        .filter(|f| f.form_index == Some(form_idx) && !f.name.is_empty())
        .filter(|f| {
            !matches!(
                f.field_type,
                FieldType::Hidden | FieldType::Submit | FieldType::Button | FieldType::File
            )
        })
        .map(|f| {
            let val = app
                .browser
                .field_values
                .get(&f.index)
                .cloned()
                .unwrap_or_else(|| f.value.clone());
            (f.name.clone(), val)
        })
        .collect();

    if method == "post" {
        let url = action.clone();
        app.browser.begin_navigate(&url);
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            let _ = tx2.send(AppMsg::Page(
                fetch_post(&url, &params)
                    .map(Box::new)
                    .map_err(|e| e.to_string()),
            ));
        });
    } else {
        let url = build_get_url(&action, &params);
        app.browser.begin_navigate(&url);
        navigate(url, tx);
    }
}

// Build a GET URL by appending form params as a query string
fn build_get_url(action: &str, params: &[(String, String)]) -> String {
    if params.is_empty() {
        return action.to_string();
    }
    let qs: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    if action.contains('?') {
        format!("{action}&{qs}")
    } else {
        format!("{action}?{qs}")
    }
}

// Percent-encode a value for a URL query string (RFC 3986 unreserved chars pass through)
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => '+'.to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// Handle URL bar typing, Enter to navigate, Esc to cancel
fn handle_url_bar_key(app: &mut App, code: KeyCode, tx: &Sender<AppMsg>) {
    match code {
        KeyCode::Enter => {
            let raw = app.browser.url_buf.trim().to_string();
            if !raw.is_empty() {
                let url = ensure_scheme(raw);
                app.browser.begin_navigate(&url);
                navigate(url, tx);
            } else {
                app.browser.url_editing = false;
            }
        }
        KeyCode::Esc => {
            app.browser.url_editing = false;
            app.browser.url_buf = app.browser.url.clone();
        }
        KeyCode::Backspace => {
            app.browser.url_buf.pop();
        }
        KeyCode::Char(c) => app.browser.url_buf.push(c),
        _ => {}
    }
}

// Dispatch mouse events
fn handle_mouse(
    app: &mut App,
    kind: MouseEventKind,
    col: u16,
    row: u16,
    terminal: &Terminal<CrosstermBackend<io::Stdout>>,
    tx: &Sender<AppMsg>,
) {
    let size = terminal.size().unwrap_or_default();

    match kind {
        // Wheel scrolling works in any tab
        MouseEventKind::ScrollDown => {
            for _ in 0..MOUSE_SCROLL_STEP {
                app.cursor_down();
            }
        }
        MouseEventKind::ScrollUp => {
            for _ in 0..MOUSE_SCROLL_STEP {
                app.cursor_up();
            }
        }

        MouseEventKind::Down(MouseButton::Left) => {
            // Tab bar occupies rows 0-2 (Block border + content + border)
            if row <= 2 {
                if let Some(tab) = tab_at_column(col) {
                    app.tab = tab;
                }
                return;
            }

            // Browser content area: rows 7..h-1 (3 tab + 3 url + 1 status = 7 offset)
            if app.tab == Tab::Browser && !app.browser.url_editing {
                let content_top: u16 = 7; // tab(3) + url(3) + status(1)
                let content_bot = size.height.saturating_sub(1); // minus link bar
                if row >= content_top && row < content_bot {
                    let content_row = (row - content_top) as usize + app.browser.scroll;
                    follow_link_at_row(app, content_row, col, tx);
                }
                // Clicks in the URL bar region (rows 3-5) focus it
                if (3..=5).contains(&row) {
                    app.browser.url_editing = true;
                    app.browser.url_buf = app.browser.url.clone();
                }
            }
        }
        _ => {}
    }
}

// Attempt to follow a link or focus a field at a given source line and click column
fn follow_link_at_row(app: &mut App, line_idx: usize, click_col: u16, tx: &Sender<AppMsg>) {
    let page = match &app.browser.page {
        Some(p) => p,
        None => return,
    };
    let line = match page.lines.get(line_idx) {
        Some(l) => l,
        None => return,
    };

    // If the line is a field placeholder, focus that field on click
    if let Some(field_idx) = parse_field_marker(line) {
        app.browser.focused_field = Some(field_idx);
        return;
    }

    // Find the [N] marker closest to the clicked column
    let mut best: Option<(u16, usize)> = None; // (distance, 0-based link index)
    let mut col = 0u16;
    for span in &line.spans {
        let len = span.content.chars().count() as u16;
        if let Some(n) = parse_link_marker(span.content.as_ref()) {
            let center = col + len / 2;
            let dist = center.abs_diff(click_col);
            if best.is_none() || dist < best.unwrap().0 {
                best = Some((dist, n - 1));
            }
        }
        col += len;
    }

    if let Some((_, link_idx)) = best {
        app.browser.selected_link = link_idx;
        if let Some(url) = app.browser.selected_link_url().map(str::to_string) {
            let resolved = resolve_url(&url, &app.browser.url);
            app.browser.begin_navigate(&resolved);
            navigate(resolved, tx);
        }
    }
}

// Return the [N] number encoded in a span like "[3]", or None
fn parse_link_marker(s: &str) -> Option<usize> {
    s.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

// Find which tab a column-click lands on given the tab bar layout
fn tab_at_column(col: u16) -> Option<Tab> {
    let mut x: u16 = 1; // skip left border
    for &tab in Tab::ALL {
        let width = tab.title().len() as u16 + 2; // " Title "
        if col >= x && col < x + width {
            return Some(tab);
        }
        x += width + 1; // +1 for "|" divider
    }
    None
}

// Cycle the findings severity filter through the severity levels
fn cycle_findings_filter(app: &mut App) {
    let pos = SEVERITY_CYCLE
        .iter()
        .position(|&s| s == app.findings_filter.as_str())
        .unwrap_or(0);
    app.findings_filter = SEVERITY_CYCLE[(pos + 1) % SEVERITY_CYCLE.len()].to_string();
    app.finding_cursor = 0;
}

// Prepend https:// if URL has no scheme
fn ensure_scheme(url: String) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        format!("https://{url}")
    }
}

// Resolve a potentially relative href against the current page URL
fn resolve_url(href: &str, base: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    if let Ok(base_url) = url::Url::parse(base)
        && let Ok(resolved) = base_url.join(href)
    {
        return resolved.to_string();
    }
    href.to_string()
}
