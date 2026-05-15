/*******************************************************************
 * Filename:        app.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     App state machine: selected tab, cursor, data cache, browser
 * Notes:           Tabs map 1:1 to views; data refreshed on 2s timer tick
 *******************************************************************/

use crate::html_render::{FieldType, RenderedPage};
use crate::loader::{EngagementData, EngagementEntry, list_engagements, load_engagement_data};
use ratatui::text::Line;
use std::collections::HashMap;
use std::path::PathBuf;

// Named tabs in display order
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Engagements,
    Hosts,
    Findings,
    Fuzz,
    Logs,
    Harness,
    Browser,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[
        Tab::Engagements,
        Tab::Hosts,
        Tab::Findings,
        Tab::Fuzz,
        Tab::Logs,
        Tab::Harness,
        Tab::Browser,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Engagements => "Engagements",
            Tab::Hosts => "Hosts",
            Tab::Findings => "Findings",
            Tab::Fuzz => "Fuzz",
            Tab::Logs => "Logs",
            Tab::Harness => "Harness",
            Tab::Browser => "Browser",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_index(i: usize) -> Tab {
        Tab::ALL.get(i).copied().unwrap_or(Tab::Engagements)
    }
}

// All state for the in-TUI browser
#[derive(Default)]
pub struct BrowserState {
    pub url: String,
    pub url_buf: String,
    pub url_editing: bool,
    pub status: u16,
    pub content_type: String,
    pub page: Option<RenderedPage>,
    pub error: Option<String>,
    pub loading: bool,
    pub scroll: usize,
    pub selected_link: usize,
    pub history: Vec<String>,
    // index → pre-rendered halfblock lines, populated as images download
    pub image_cache: HashMap<usize, Vec<Line<'static>>>,
    // form interaction: which field is focused, and live values keyed by element index
    pub focused_field: Option<usize>,
    pub field_values: HashMap<usize, String>,
}

impl BrowserState {
    // Total link count in current page
    pub fn link_count(&self) -> usize {
        self.page.as_ref().map_or(0, |p| p.links.len())
    }

    // URL of currently selected link (1-indexed display, 0-indexed internal)
    pub fn selected_link_url(&self) -> Option<&str> {
        self.page
            .as_ref()?
            .links
            .get(self.selected_link)
            .map(String::as_str)
    }

    // Advance to next link
    pub fn next_link(&mut self) {
        let count = self.link_count();
        if count > 0 {
            self.selected_link = (self.selected_link + 1) % count;
        }
    }

    // Go to previous link
    pub fn prev_link(&mut self) {
        let count = self.link_count();
        if count > 0 {
            self.selected_link = if self.selected_link == 0 {
                count - 1
            } else {
                self.selected_link - 1
            };
        }
    }

    // Push current URL to history and reset page state for a new navigation
    pub fn begin_navigate(&mut self, new_url: &str) {
        if !self.url.is_empty() {
            self.history.push(self.url.clone());
        }
        self.url = new_url.to_string();
        self.url_buf = new_url.to_string();
        self.url_editing = false;
        self.loading = true;
        self.error = None;
        self.scroll = 0;
        self.selected_link = 0;
        self.focused_field = None;
        self.field_values.clear();
    }

    // Collect non-hidden field indices from the current page in document order
    fn visible_field_indices(&self) -> Vec<usize> {
        self.page.as_ref().map_or(Vec::new(), |p| {
            p.form_elements
                .iter()
                .filter(|f| !matches!(f.field_type, FieldType::Hidden))
                .map(|f| f.index)
                .collect()
        })
    }

    // Move focus to the next visible form field (wraps)
    pub fn focus_next_field(&mut self) {
        let indices = self.visible_field_indices();
        if indices.is_empty() {
            return;
        }
        let next = match self.focused_field {
            None => indices[0],
            Some(cur) => {
                let pos = indices.iter().position(|&i| i == cur).unwrap_or(0);
                indices[(pos + 1) % indices.len()]
            }
        };
        self.focused_field = Some(next);
    }

    // Move focus to the previous visible form field (wraps)
    pub fn focus_prev_field(&mut self) {
        let indices = self.visible_field_indices();
        if indices.is_empty() {
            return;
        }
        let prev = match self.focused_field {
            None => *indices.last().unwrap(),
            Some(cur) => {
                let pos = indices.iter().position(|&i| i == cur).unwrap_or(0);
                if pos == 0 {
                    *indices.last().unwrap()
                } else {
                    indices[pos - 1]
                }
            }
        };
        self.focused_field = Some(prev);
    }

    // Restore previous history entry
    pub fn go_back(&mut self) -> Option<String> {
        let prev = self.history.pop()?;
        self.url = prev.clone();
        self.url_buf = prev.clone();
        self.scroll = 0;
        self.selected_link = 0;
        self.loading = true;
        self.error = None;
        Some(prev)
    }
}

// Top-level application state
pub struct App {
    pub tab: Tab,
    pub engagements: Vec<EngagementEntry>,
    pub engagement_cursor: usize,
    pub selected_engagement: Option<String>,
    pub data: EngagementData,
    pub host_cursor: usize,
    pub finding_cursor: usize,
    pub fuzz_cursor: usize,
    pub log_offset: usize,
    pub harness_offset: usize,
    pub findings_filter: String,
    pub engagements_dir: PathBuf,
    pub should_quit: bool,
    pub browser: BrowserState,
}

impl App {
    // Initialize app state and load initial engagement list
    pub fn new(engagements_dir: PathBuf) -> Self {
        let engagements = list_engagements(&engagements_dir).unwrap_or_default();
        App {
            tab: Tab::Engagements,
            engagements,
            engagement_cursor: 0,
            selected_engagement: None,
            data: EngagementData::default(),
            host_cursor: 0,
            finding_cursor: 0,
            fuzz_cursor: 0,
            log_offset: 0,
            harness_offset: 0,
            findings_filter: String::new(),
            engagements_dir,
            should_quit: false,
            browser: BrowserState::default(),
        }
    }

    // Reload engagement list and currently selected engagement data
    pub fn refresh(&mut self) {
        self.engagements = list_engagements(&self.engagements_dir).unwrap_or_default();
        if let Some(name) = &self.selected_engagement.clone() {
            self.data = load_engagement_data(&self.engagements_dir, name);
        }
    }

    // Select engagement under cursor and load its data
    pub fn select_engagement(&mut self) {
        if let Some(entry) = self.engagements.get(self.engagement_cursor) {
            let name = entry.name.clone();
            self.data = load_engagement_data(&self.engagements_dir, &name);
            self.selected_engagement = Some(name);
            self.host_cursor = 0;
            self.finding_cursor = 0;
            self.fuzz_cursor = 0;
            self.log_offset = 0;
            self.harness_offset = 0;
        }
    }

    // Move cursor up in the active list
    pub fn cursor_up(&mut self) {
        match self.tab {
            Tab::Engagements => {
                if self.engagement_cursor > 0 {
                    self.engagement_cursor -= 1;
                }
            }
            Tab::Hosts => {
                if self.host_cursor > 0 {
                    self.host_cursor -= 1;
                }
            }
            Tab::Findings => {
                if self.finding_cursor > 0 {
                    self.finding_cursor -= 1;
                }
            }
            Tab::Fuzz => {
                if self.fuzz_cursor > 0 {
                    self.fuzz_cursor -= 1;
                }
            }
            Tab::Logs => {
                if self.log_offset > 0 {
                    self.log_offset -= 1;
                }
            }
            Tab::Harness => {
                if self.harness_offset > 0 {
                    self.harness_offset -= 1;
                }
            }
            Tab::Browser => {
                if self.browser.scroll > 0 {
                    self.browser.scroll -= 1;
                }
            }
        }
    }

    // Move cursor down in the active list
    pub fn cursor_down(&mut self) {
        match self.tab {
            Tab::Engagements => {
                if self.engagement_cursor + 1 < self.engagements.len() {
                    self.engagement_cursor += 1;
                }
            }
            Tab::Hosts => {
                if self.host_cursor + 1 < self.data.hosts.len() {
                    self.host_cursor += 1;
                }
            }
            Tab::Findings => {
                let filtered = self.filtered_findings_len();
                if self.finding_cursor + 1 < filtered {
                    self.finding_cursor += 1;
                }
            }
            Tab::Fuzz => {
                if self.fuzz_cursor + 1 < self.data.fuzz_results.len() {
                    self.fuzz_cursor += 1;
                }
            }
            Tab::Logs => {
                if self.log_offset + 1 < self.data.log_lines.len() {
                    self.log_offset += 1;
                }
            }
            Tab::Harness => {
                if self.harness_offset + 1 < self.data.harness.events.len() {
                    self.harness_offset += 1;
                }
            }
            Tab::Browser => {
                let max = self.browser.page.as_ref().map_or(0, |p| p.lines.len());
                if self.browser.scroll + 1 < max {
                    self.browser.scroll += 1;
                }
            }
        }
    }

    // Count findings matching the current severity filter
    fn filtered_findings_len(&self) -> usize {
        if self.findings_filter.is_empty() {
            return self.data.findings.len();
        }
        self.data
            .findings
            .iter()
            .filter(|f| f.severity.eq_ignore_ascii_case(&self.findings_filter))
            .count()
    }

    // Navigate to next tab
    pub fn next_tab(&mut self) {
        let i = (self.tab.index() + 1) % Tab::ALL.len();
        self.tab = Tab::from_index(i);
    }

    // Navigate to previous tab
    pub fn prev_tab(&mut self) {
        let i = if self.tab.index() == 0 {
            Tab::ALL.len() - 1
        } else {
            self.tab.index() - 1
        };
        self.tab = Tab::from_index(i);
    }
}
