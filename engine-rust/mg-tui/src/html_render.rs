/*******************************************************************
 * Filename:        html_render.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     HTML → terminal-rendered lines with styled spans
 * Notes:           Recursive DOM walker. Images get IMAGE_BLOCK_HEIGHT
 *                  placeholder lines with \x01IMG:idx:row\x01 markers;
 *                  the browser view substitutes halfblock pixels at draw time.
 *                  Video gets an inline styled box. Links get [N] indices.
 *******************************************************************/

use ego_tree::NodeRef;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use scraper::{Html, Selector, node::Node};

// Height (in terminal rows) reserved per inline image
pub const IMAGE_BLOCK_HEIGHT: usize = 16;

// SOH prefix used to mark image placeholder lines (cannot appear in HTML text)
const IMG_PFX: char = '\x01';

// STX prefix used to mark form field placeholder lines (cannot appear in HTML text)
const FIELD_PFX: char = '\x02';

// Metadata for one image embedded in the page
#[derive(Clone)]
pub struct ImageSlot {
    pub index: usize,
    pub src: String,
    pub alt: String,
    #[allow(dead_code)]
    pub start_line: usize,
}

// Input field type from HTML
#[derive(Clone, Debug)]
pub enum FieldType {
    Text,
    Password,
    Email,
    Search,
    TextArea,
    Checkbox { checked: bool },
    Radio { checked: bool },
    Submit,
    Button,
    Hidden,
    File,
    Select(Vec<(String, String)>), // (value, display_label)
}

// One interactive form element
#[derive(Clone)]
pub struct FormElement {
    pub index: usize,
    pub form_index: Option<usize>,
    pub name: String,
    pub value: String,
    pub placeholder: String,
    pub field_type: FieldType,
}

// Metadata for a <form> element
#[derive(Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String, // "get" or "post"
}

// Full output of the renderer
pub struct RenderedPage {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    pub links: Vec<String>,
    pub images: Vec<ImageSlot>,
    pub forms: Vec<FormInfo>,
    pub form_elements: Vec<FormElement>,
}

// Rendering accumulator
struct Ctx {
    lines: Vec<Line<'static>>,
    links: Vec<String>,
    images: Vec<ImageSlot>,
    forms: Vec<FormInfo>,
    form_elements: Vec<FormElement>,
    current_form: Option<usize>,
    current: Vec<Span<'static>>,
    style_stack: Vec<Style>,
    skip: u32,
    in_pre: bool,
    had_blank: bool,
    image_count: usize,
    field_count: usize,
}

impl Default for Ctx {
    fn default() -> Self {
        Ctx {
            lines: Vec::new(),
            links: Vec::new(),
            images: Vec::new(),
            forms: Vec::new(),
            form_elements: Vec::new(),
            current_form: None,
            current: Vec::new(),
            style_stack: vec![Style::default()],
            skip: 0,
            in_pre: false,
            had_blank: true,
            image_count: 0,
            field_count: 0,
        }
    }
}

impl Ctx {
    // Return top of style stack
    fn style(&self) -> Style {
        self.style_stack.last().copied().unwrap_or_default()
    }

    // Push inherited style merged with patch
    fn push_style(&mut self, patch: Style) {
        let merged = self.style().patch(patch);
        self.style_stack.push(merged);
    }

    // Restore previous style
    fn pop_style(&mut self) {
        if self.style_stack.len() > 1 {
            self.style_stack.pop();
        }
    }

    // Append text to current line, collapsing whitespace unless in <pre>
    fn push_text(&mut self, text: &str) {
        if self.skip > 0 {
            return;
        }
        if self.in_pre {
            let style = self.style();
            for (i, part) in text.split('\n').enumerate() {
                if i > 0 {
                    self.flush_current();
                }
                if !part.is_empty() {
                    self.current.push(Span::styled(part.to_string(), style));
                    self.had_blank = false;
                }
            }
            return;
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.is_empty() {
            return;
        }
        let mut s = words.join(" ");
        if !self.current.is_empty() && text.starts_with(|c: char| c.is_ascii_whitespace()) {
            s = format!(" {s}");
        }
        if text.ends_with(|c: char| c.is_ascii_whitespace()) {
            s.push(' ');
        }
        let style = self.style();
        self.current.push(Span::styled(s, style));
        self.had_blank = false;
    }

    // Add a span directly
    fn push_span(&mut self, s: Span<'static>) {
        self.current.push(s);
        self.had_blank = false;
    }

    // Move in-progress spans to a completed line
    fn flush_current(&mut self) {
        let spans = std::mem::take(&mut self.current);
        if !spans.is_empty() || !self.had_blank {
            self.lines.push(Line::from(spans));
        }
    }

    // Flush current line if non-empty
    fn newline(&mut self) {
        if !self.current.is_empty() {
            self.flush_current();
        }
    }

    // Ensure at least one blank separator line
    fn ensure_blank(&mut self) {
        self.newline();
        if !self.had_blank {
            self.lines.push(Line::raw(""));
            self.had_blank = true;
        }
    }

    // Push a full decorative line
    fn push_raw_line(&mut self, s: String) {
        self.newline();
        self.lines.push(Line::raw(s));
        self.had_blank = false;
    }

    // Register a hyperlink and return its 1-based display number
    fn add_link(&mut self, href: String) -> usize {
        self.links.push(href);
        self.links.len()
    }

    // Emit IMAGE_BLOCK_HEIGHT placeholder lines for an inline image
    fn emit_image(&mut self, src: &str, alt: &str) {
        self.ensure_blank();
        let idx = self.image_count;
        self.image_count += 1;
        let start_line = self.lines.len();
        self.images.push(ImageSlot {
            index: idx,
            src: src.to_string(),
            alt: alt.to_string(),
            start_line,
        });
        for row in 0..IMAGE_BLOCK_HEIGHT {
            // Each placeholder line: \x01IMG:idx:row\x01
            self.lines.push(Line::from(Span::raw(
                format!("{IMG_PFX}IMG:{idx}:{row}{IMG_PFX}"),
            )));
        }
        self.had_blank = false;
        self.ensure_blank();
    }

    // Register a form element; emit a placeholder line unless hidden
    fn emit_field(&mut self, field: FormElement) {
        let idx = field.index;
        let is_hidden = matches!(field.field_type, FieldType::Hidden);
        self.form_elements.push(field);
        if is_hidden {
            return;
        }
        self.newline();
        self.lines.push(Line::from(Span::raw(
            format!("{FIELD_PFX}FIELD:{idx}{FIELD_PFX}"),
        )));
        self.had_blank = false;
    }

    // Emit a styled 4-line video/audio box
    fn emit_media_box(&mut self, tag: &str, src: &str, media_type: &str) {
        self.ensure_blank();
        let bar = "─".repeat(68);
        let icon = if tag == "video" { "▶ VIDEO" } else { "♪ AUDIO" };
        let color = if tag == "video" { Color::Magenta } else { Color::Blue };
        let style = Style::default().fg(color).add_modifier(Modifier::BOLD);
        self.lines.push(Line::from(Span::styled(format!("{icon} {bar}"), style)));
        if !src.is_empty() {
            self.lines.push(Line::from(vec![
                Span::styled("  src:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(src.to_string(), Style::default().fg(Color::White)),
            ]));
        }
        if !media_type.is_empty() {
            self.lines.push(Line::from(vec![
                Span::styled("  type: ", Style::default().fg(Color::DarkGray)),
                Span::styled(media_type.to_string(), Style::default().fg(Color::Gray)),
            ]));
        }
        self.lines.push(Line::from(Span::styled(bar, style)));
        self.had_blank = false;
        self.ensure_blank();
    }
}

// Walk one DOM node and update ctx
fn walk_node(node: NodeRef<'_, Node>, ctx: &mut Ctx) {
    match node.value() {
        Node::Text(t) => {
            ctx.push_text(t.text.as_ref());
        }
        Node::Element(elem) => {
            let tag = elem.name();

            // Completely skip invisible subtrees
            if matches!(tag, "script" | "style" | "noscript" | "svg" | "canvas" | "head") {
                return;
            }

            if ctx.skip > 0 {
                ctx.skip -= 1;
                for child in node.children() {
                    walk_node(child, ctx);
                }
                ctx.skip += 1;
                return;
            }

            match tag {
                // --- void / line-break ---
                "br" => ctx.newline(),
                "hr" => {
                    ctx.ensure_blank();
                    ctx.push_raw_line("─".repeat(72));
                    ctx.had_blank = false;
                    ctx.ensure_blank();
                }

                // --- headings ---
                "h1" => {
                    ctx.ensure_blank();
                    ctx.push_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.newline();
                    ctx.push_raw_line("═".repeat(72));
                    ctx.ensure_blank();
                }
                "h2" => {
                    ctx.ensure_blank();
                    ctx.push_style(Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.newline();
                    ctx.push_raw_line("─".repeat(52));
                    ctx.ensure_blank();
                }
                "h3" | "h4" | "h5" | "h6" => {
                    ctx.ensure_blank();
                    ctx.push_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.newline();
                    ctx.ensure_blank();
                }

                // --- form container: register and track current form index ---
                "form" => {
                    let action = elem.attr("action").unwrap_or("").to_string();
                    let method = elem.attr("method").unwrap_or("get").to_lowercase();
                    let fi = ctx.forms.len();
                    ctx.forms.push(FormInfo { action, method });
                    let prev = ctx.current_form;
                    ctx.current_form = Some(fi);
                    ctx.ensure_blank();
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.current_form = prev;
                    ctx.newline();
                }

                // --- block containers ---
                "p" | "div" | "section" | "article" | "main" | "aside"
                | "header" | "footer" | "nav" | "fieldset" | "figure"
                | "address" | "details" | "summary" => {
                    ctx.ensure_blank();
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.newline();
                }

                // --- lists ---
                "ul" | "ol" | "dl" => {
                    ctx.ensure_blank();
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.ensure_blank();
                }
                "li" => {
                    ctx.newline();
                    ctx.push_span(Span::raw("  • "));
                    for c in node.children() { walk_node(c, ctx); }
                }
                "dt" => {
                    ctx.newline();
                    ctx.push_style(Style::default().add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "dd" => {
                    ctx.newline();
                    ctx.push_span(Span::raw("    "));
                    for c in node.children() { walk_node(c, ctx); }
                }

                // --- preformatted ---
                "pre" => {
                    ctx.ensure_blank();
                    ctx.in_pre = true;
                    ctx.push_style(Style::default().fg(Color::Yellow));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.in_pre = false;
                    ctx.newline();
                    ctx.ensure_blank();
                }

                // --- inline formatting ---
                "strong" | "b" => {
                    ctx.push_style(Style::default().add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "em" | "i" | "cite" | "var" => {
                    ctx.push_style(Style::default().add_modifier(Modifier::ITALIC));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "u" | "ins" => {
                    ctx.push_style(Style::default().add_modifier(Modifier::UNDERLINED));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "s" | "del" | "strike" => {
                    ctx.push_style(Style::default().add_modifier(Modifier::CROSSED_OUT));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "code" | "kbd" | "samp" | "tt" => {
                    ctx.push_style(Style::default().fg(Color::Yellow));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "mark" => {
                    ctx.push_style(Style::default().fg(Color::Black).bg(Color::Yellow));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "small" | "sub" | "sup" => {
                    ctx.push_style(Style::default().fg(Color::Gray));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                }
                "abbr" | "acronym" => {
                    for c in node.children() { walk_node(c, ctx); }
                    if let Some(title) = elem.attr("title") {
                        ctx.push_span(Span::styled(
                            format!(" ({title})"),
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                }
                "q" => {
                    ctx.push_span(Span::raw("\u{201C}"));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.push_span(Span::raw("\u{201D}"));
                }
                "blockquote" => {
                    ctx.ensure_blank();
                    ctx.push_style(Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC));
                    ctx.push_span(Span::raw("  \u{258C} "));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.newline();
                    ctx.ensure_blank();
                }

                // --- links ---
                "a" => {
                    let href = elem.attr("href").unwrap_or("").to_string();
                    let is_real = !href.is_empty()
                        && !href.starts_with('#')
                        && !href.starts_with("javascript:");
                    if is_real {
                        let n = ctx.add_link(href);
                        ctx.push_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::UNDERLINED));
                        for c in node.children() { walk_node(c, ctx); }
                        ctx.pop_style();
                        ctx.push_span(Span::styled(
                            format!("[{n}]"),
                            Style::default().fg(Color::DarkGray),
                        ));
                    } else {
                        for c in node.children() { walk_node(c, ctx); }
                    }
                }

                // --- images (inline, with async halfblock rendering) ---
                "img" => {
                    let src = elem.attr("src").unwrap_or("");
                    let alt = elem.attr("alt").unwrap_or("image");
                    if src.is_empty() {
                        ctx.push_span(Span::styled(
                            format!("[img: {alt}]"),
                            Style::default().fg(Color::DarkGray),
                        ));
                    } else {
                        ctx.emit_image(src, alt);
                    }
                }

                // <picture>: walk children; the nested <img> handles rendering
                "picture" => {
                    for c in node.children() { walk_node(c, ctx); }
                }

                // <source> standalone (outside <video>/<picture>): ignore
                "source" => {}

                // --- video / audio with nested <source> extraction ---
                "video" | "audio" => {
                    let mut src = elem.attr("src").unwrap_or("").to_string();
                    let mut media_type = elem.attr("type").unwrap_or("").to_string();
                    // Check children for <source src="...">
                    for child in node.children() {
                        if let Node::Element(ce) = child.value()
                            && ce.name() == "source" && src.is_empty() {
                            src = ce.attr("src").unwrap_or("").to_string();
                            media_type = ce.attr("type").unwrap_or("").to_string();
                        }
                    }
                    ctx.emit_media_box(tag, &src, &media_type);
                }

                // --- form elements ---
                "input" => {
                    let t = elem.attr("type").unwrap_or("text").to_lowercase();
                    let name = elem.attr("name").unwrap_or("").to_string();
                    let value = elem.attr("value").unwrap_or("").to_string();
                    let placeholder = elem.attr("placeholder").unwrap_or("").to_string();
                    let field_type = match t.as_str() {
                        "password" => FieldType::Password,
                        "email" => FieldType::Email,
                        "search" => FieldType::Search,
                        "checkbox" => FieldType::Checkbox { checked: elem.attr("checked").is_some() },
                        "radio" => FieldType::Radio { checked: elem.attr("checked").is_some() },
                        "submit" => FieldType::Submit,
                        "button" => FieldType::Button,
                        "hidden" => FieldType::Hidden,
                        "file" => FieldType::File,
                        _ => FieldType::Text,
                    };
                    let idx = ctx.field_count;
                    ctx.field_count += 1;
                    ctx.emit_field(FormElement { index: idx, form_index: ctx.current_form, name, value, placeholder, field_type });
                }
                "textarea" => {
                    let name = elem.attr("name").unwrap_or("").to_string();
                    let placeholder = elem.attr("placeholder").unwrap_or("").to_string();
                    let value: String = node.children()
                        .filter_map(|c| if let Node::Text(t) = c.value() { Some(t.text.as_ref().to_string()) } else { None })
                        .collect::<Vec<_>>().join("");
                    let idx = ctx.field_count;
                    ctx.field_count += 1;
                    ctx.emit_field(FormElement { index: idx, form_index: ctx.current_form, name, value, placeholder, field_type: FieldType::TextArea });
                }
                "button" => {
                    let btn_type = elem.attr("type").unwrap_or("submit").to_lowercase();
                    let name = elem.attr("name").unwrap_or("").to_string();
                    let value = elem.attr("value").unwrap_or("").to_string();
                    let placeholder: String = node.children()
                        .filter_map(|c| if let Node::Text(t) = c.value() { Some(t.text.as_ref().to_string()) } else { None })
                        .collect::<Vec<_>>().join("").trim().to_string();
                    let field_type = if btn_type == "submit" { FieldType::Submit } else { FieldType::Button };
                    let idx = ctx.field_count;
                    ctx.field_count += 1;
                    ctx.emit_field(FormElement { index: idx, form_index: ctx.current_form, name, value, placeholder, field_type });
                }
                "select" => {
                    let name = elem.attr("name").unwrap_or("").to_string();
                    let mut options: Vec<(String, String)> = Vec::new();
                    let mut default_value = String::new();
                    for child in node.children() {
                        if let Node::Element(ce) = child.value()
                            && ce.name() == "option" {
                            let val = ce.attr("value").unwrap_or("").to_string();
                            let label: String = child.children()
                                .filter_map(|c| if let Node::Text(t) = c.value() { Some(t.text.as_ref().to_string()) } else { None })
                                .collect::<Vec<_>>().join("").trim().to_string();
                            if ce.attr("selected").is_some() { default_value = val.clone(); }
                            options.push((val, label));
                        }
                    }
                    if default_value.is_empty() {
                        default_value = options.first().map(|(v, _)| v.clone()).unwrap_or_default();
                    }
                    let idx = ctx.field_count;
                    ctx.field_count += 1;
                    ctx.emit_field(FormElement { index: idx, form_index: ctx.current_form, name, value: default_value, placeholder: String::new(), field_type: FieldType::Select(options) });
                }
                "label" => {
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.push_span(Span::raw(": "));
                }

                // --- tables ---
                "table" => {
                    ctx.ensure_blank();
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.ensure_blank();
                }
                "thead" | "tbody" | "tfoot" | "colgroup" | "col" => {
                    for c in node.children() { walk_node(c, ctx); }
                }
                "tr" => {
                    ctx.newline();
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.newline();
                    ctx.push_raw_line("\u{00B7}".repeat(72));
                }
                "th" => {
                    ctx.push_span(Span::raw("\u{2502} "));
                    ctx.push_style(Style::default().add_modifier(Modifier::BOLD));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.pop_style();
                    ctx.push_span(Span::raw(" "));
                }
                "td" => {
                    ctx.push_span(Span::raw("\u{2502} "));
                    for c in node.children() { walk_node(c, ctx); }
                    ctx.push_span(Span::raw(" "));
                }

                // Structural pass-through
                _ => {
                    for c in node.children() { walk_node(c, ctx); }
                }
            }
        }
        _ => {}
    }
}

// Parse HTML and produce terminal lines, links, and image slots
pub fn render_html(src: &str, _base_url: &str) -> RenderedPage {
    let doc = Html::parse_document(src);
    let mut ctx = Ctx::default();

    // Extract <title>
    let title_sel = Selector::parse("title").unwrap();
    let title = doc
        .select(&title_sel)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    // Walk <body> if present, else walk <html>
    let body_sel = Selector::parse("body").unwrap();
    if let Some(body) = doc.select(&body_sel).next() {
        for child in body.children() {
            walk_node(child, &mut ctx);
        }
    } else {
        for child in doc.root_element().children() {
            walk_node(child, &mut ctx);
        }
    }

    ctx.newline();

    RenderedPage {
        title,
        lines: ctx.lines,
        links: ctx.links,
        images: ctx.images,
        forms: ctx.forms,
        form_elements: ctx.form_elements,
    }
}

// Wrap a plain-text body into rendered lines
pub fn render_plain(text: &str) -> RenderedPage {
    let lines = text.lines().map(|l| Line::raw(l.to_string())).collect();
    RenderedPage { title: "(plain text)".into(), lines, links: vec![], images: vec![], forms: vec![], form_elements: vec![] }
}

// Return the field element index for a FIELD placeholder line, or None
pub fn parse_field_marker(line: &Line<'_>) -> Option<usize> {
    let s = line.spans.first()?.content.as_ref();
    if !s.starts_with(FIELD_PFX) || !s.ends_with(FIELD_PFX) {
        return None;
    }
    let inner = &s[FIELD_PFX.len_utf8()..s.len() - FIELD_PFX.len_utf8()];
    inner.strip_prefix("FIELD:")?.parse().ok()
}

// Return (image_index, row_within_image) for a placeholder line, or None
pub fn parse_img_marker(line: &Line<'_>) -> Option<(usize, usize)> {
    let s = line.spans.first()?.content.as_ref();
    if !s.starts_with(IMG_PFX) || !s.ends_with(IMG_PFX) {
        return None;
    }
    let inner = &s[IMG_PFX.len_utf8()..s.len() - IMG_PFX.len_utf8()];
    let rest = inner.strip_prefix("IMG:")?;
    let mut parts = rest.splitn(2, ':');
    let idx: usize = parts.next()?.parse().ok()?;
    let row: usize = parts.next()?.parse().ok()?;
    Some((idx, row))
}
