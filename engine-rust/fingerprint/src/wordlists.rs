// Author: Jeff
// Date: 2026-05-01
// Description: Map fingerprint tech stack to likely subdomain/path candidates

use crate::Fingerprint;

// Return tech-specific wordlist additions based on detected stack
pub fn tech_wordlist(fp: &Fingerprint) -> Vec<&'static str> {
    let mut words: Vec<&'static str> = Vec::new();

    match fp.cms.as_deref() {
        Some("wordpress") => words.extend(&[
            "wp-admin", "wp-content", "wp-login", "xmlrpc", "wp-json", "wp-cron",
        ]),
        Some("drupal") => words.extend(&[
            "admin", "user", "node", "sites", "modules", "themes",
        ]),
        Some("joomla") => words.extend(&[
            "administrator", "components", "modules", "plugins", "templates",
        ]),
        Some("shopify") => words.extend(&[
            "admin", "apps", "checkout", "account", "collections", "products",
        ]),
        _ => {}
    }

    match fp.framework.as_deref() {
        Some("nextjs") | Some("react") => words.extend(&[
            "api", "_next", "static", "app", "dashboard", "auth",
        ]),
        Some("nuxt") | Some("vue") => words.extend(&[
            "api", "_nuxt", "app", "admin", "dashboard",
        ]),
        Some("angular") => words.extend(&[
            "api", "app", "assets", "admin", "dashboard",
        ]),
        Some("laravel") => words.extend(&[
            "api", "telescope", "horizon", "nova", "sanctum", "storage",
        ]),
        Some("rails") => words.extend(&[
            "admin", "api", "sidekiq", "rails", "health",
        ]),
        Some("django") => words.extend(&[
            "admin", "api", "static", "media", "accounts",
        ]),
        Some("express") | Some("aspnet") => words.extend(&[
            "api", "admin", "health", "metrics",
        ]),
        _ => {}
    }

    match fp.cdn.as_deref() {
        Some("vercel") => words.extend(&["api", "preview"]),
        Some("netlify") => words.extend(&["api", "functions"]),
        _ => {}
    }

    match fp.cloud.as_deref() {
        Some("aws") => words.extend(&["api", "s3", "cdn", "assets", "media", "files"]),
        Some("gcp") => words.extend(&["api", "storage", "cdn", "app"]),
        Some("azure") => words.extend(&["api", "blob", "cdn", "app"]),
        _ => {}
    }

    words.dedup();
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordpress_wordlist_includes_admin() {
        let fp = Fingerprint { cms: Some("wordpress".into()), ..Default::default() };
        assert!(tech_wordlist(&fp).contains(&"wp-admin"));
    }

    #[test]
    fn laravel_wordlist_includes_telescope() {
        let fp = Fingerprint { framework: Some("laravel".into()), ..Default::default() };
        assert!(tech_wordlist(&fp).contains(&"telescope"));
    }

    #[test]
    fn empty_fingerprint_returns_empty() {
        let fp = Fingerprint::default();
        assert!(tech_wordlist(&fp).is_empty());
    }
}
