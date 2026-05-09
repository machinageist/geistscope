/*******************************************************************
 * Filename:        extract.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Extract links and JS asset URLs from parsed HTML
 * Notes:           Uses the `scraper` crate for HTML parsing.
 *                  Returns raw strings — normalization to absolute URLs
 *                  happens in crawl.rs using the page's base URL.
 *******************************************************************/

use scraper::{Html, Selector};
use std::sync::OnceLock;

// Compiled CSS selectors — initialized once for the process lifetime
struct Selectors {
    anchor: Selector,
    script_src: Selector,
    form_action: Selector,
    #[allow(dead_code)]  // reserved for stylesheet/canonical link extraction in v2
    link_href: Selector,
}

static SELECTORS: OnceLock<Selectors> = OnceLock::new();

// Initialize selectors exactly once; panics on invalid CSS (caught at startup)
fn selectors() -> &'static Selectors {
    SELECTORS.get_or_init(|| Selectors {
        anchor:      Selector::parse("a[href]").unwrap(),
        script_src:  Selector::parse("script[src]").unwrap(),
        form_action: Selector::parse("form[action]").unwrap(),
        link_href:   Selector::parse("link[href]").unwrap(),
    })
}

// Pull all href values from anchor tags — these are crawl candidates
pub fn extract_links(html: &str) -> Vec<String> {
    let doc = Html::parse_document(html);
    let sel = selectors();
    doc.select(&sel.anchor)
        .filter_map(|el| el.value().attr("href"))
        .map(|s| s.to_string())
        .collect()
}

// Pull all external script src values — these are JS assets to analyze
pub fn extract_script_srcs(html: &str) -> Vec<String> {
    let doc = Html::parse_document(html);
    let sel = selectors();
    doc.select(&sel.script_src)
        .filter_map(|el| el.value().attr("src"))
        .map(|s| s.to_string())
        .collect()
}

// Extract inline <script> block text — run through the secret/endpoint analyzer
pub fn extract_inline_scripts(html: &str) -> Vec<String> {
    let doc = Html::parse_document(html);
    // scraper doesn't expose text nodes via selector; use all script elements
    let script_sel = Selector::parse("script:not([src])").unwrap();
    doc.select(&script_sel)
        .map(|el| el.text().collect::<Vec<_>>().join(""))
        .filter(|s| !s.trim().is_empty())
        .collect()
}

// Extract form action URLs — useful for endpoint discovery
pub fn extract_form_actions(html: &str) -> Vec<String> {
    let doc = Html::parse_document(html);
    let sel = selectors();
    doc.select(&sel.form_action)
        .filter_map(|el| el.value().attr("action"))
        .map(|s| s.to_string())
        .collect()
}

// Resolve a raw href/src string to an absolute URL using the page's base URL
// Returns None for javascript: / mailto: / data: / # fragments
pub fn resolve_url(raw: &str, base: &url::Url) -> Option<url::Url> {
    let trimmed = raw.trim();
    // skip non-http schemes and fragment-only refs
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("data:")
        || trimmed.starts_with("tel:")
    {
        return None;
    }
    base.join(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // r##"..."## required because the HTML contains the sequence "#section" which
    // would terminate a single-hash raw string early
    const PAGE: &str = r##"
        <html><body>
            <a href="/about">About</a>
            <a href="https://cdn.example.com/page">CDN</a>
            <a href="javascript:void(0)">Skip</a>
            <a href="#section">Frag</a>
            <script src="/js/app.js"></script>
            <script>const X = fetch("/api/v1/users");</script>
            <form action="/submit">...</form>
        </body></html>
    "##;

    #[test]
    fn extracts_links() {
        let links = extract_links(PAGE);
        assert!(links.contains(&"/about".to_string()));
        assert!(links.contains(&"https://cdn.example.com/page".to_string()));
        // javascript: and # are extracted raw; resolution filters them
        assert_eq!(links.len(), 4);
    }

    #[test]
    fn extracts_script_srcs() {
        let srcs = extract_script_srcs(PAGE);
        assert_eq!(srcs, vec!["/js/app.js"]);
    }

    #[test]
    fn extracts_inline_scripts() {
        let scripts = extract_inline_scripts(PAGE);
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("fetch"));
    }

    #[test]
    fn extracts_form_actions() {
        let actions = extract_form_actions(PAGE);
        assert_eq!(actions, vec!["/submit"]);
    }

    #[test]
    fn resolve_url_handles_schemes() {
        let base = url::Url::parse("https://example.com/page").unwrap();
        assert!(resolve_url("javascript:void(0)", &base).is_none());
        assert!(resolve_url("#section", &base).is_none());
        assert!(resolve_url("mailto:x@y.com", &base).is_none());
        assert_eq!(
            resolve_url("/about", &base).unwrap().as_str(),
            "https://example.com/about"
        );
        assert_eq!(
            resolve_url("https://other.com/", &base).unwrap().as_str(),
            "https://other.com/"
        );
    }
}
