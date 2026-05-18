/*******************************************************************
 * Filename:        fingerprints.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     Static table of known-vulnerable service fingerprints for
 *                  subdomain takeover detection.
 * Notes:           CNAME suffix matching is case-insensitive; body signature
 *                  is a substring search, also case-insensitive.
 *******************************************************************/

// One entry in the known-vulnerable service table
pub struct ServiceFingerprint {
    pub service: &'static str,
    /// Suffix the dangling CNAME target must end with (e.g. ".github.io")
    pub cname_suffix: &'static str,
    /// Substring present in the HTTP response body when the service slot is unclaimed
    pub body_signature: &'static str,
}

// Known-vulnerable services — CNAME suffix + HTTP body signature
pub static FINGERPRINTS: &[ServiceFingerprint] = &[
    ServiceFingerprint {
        service: "GitHub Pages",
        cname_suffix: ".github.io",
        body_signature: "There isn't a GitHub Pages site here",
    },
    ServiceFingerprint {
        service: "Heroku",
        cname_suffix: ".herokuapp.com",
        body_signature: "No such app",
    },
    ServiceFingerprint {
        service: "Fastly",
        cname_suffix: ".fastly.net",
        body_signature: "Fastly error: unknown domain",
    },
    ServiceFingerprint {
        service: "Fastly LB",
        cname_suffix: ".fastlylb.net",
        body_signature: "Fastly error: unknown domain",
    },
    ServiceFingerprint {
        service: "Shopify",
        cname_suffix: ".myshopify.com",
        body_signature: "Sorry, this shop is currently unavailable",
    },
    ServiceFingerprint {
        service: "AWS S3",
        cname_suffix: ".s3.amazonaws.com",
        body_signature: "NoSuchBucket",
    },
    ServiceFingerprint {
        service: "AWS S3 (website)",
        cname_suffix: ".s3-website",
        body_signature: "NoSuchBucket",
    },
    ServiceFingerprint {
        service: "Azure",
        cname_suffix: ".azurewebsites.net",
        body_signature: "404 Web Site not found",
    },
    ServiceFingerprint {
        service: "Pantheon",
        cname_suffix: ".pantheonsite.io",
        body_signature: "404 error unknown site",
    },
    ServiceFingerprint {
        service: "Ghost",
        cname_suffix: ".ghost.io",
        body_signature: "The thing you were looking for is no longer here",
    },
    ServiceFingerprint {
        service: "Surge.sh",
        cname_suffix: ".surge.sh",
        body_signature: "project not found",
    },
    ServiceFingerprint {
        service: "Netlify",
        cname_suffix: ".netlify.app",
        body_signature: "Not Found - Request ID",
    },
    ServiceFingerprint {
        service: "ReadTheDocs",
        cname_suffix: ".readthedocs.io",
        body_signature: "is not a valid ReadTheDocs project",
    },
];

// Return the first fingerprint whose CNAME suffix matches the given target (case-insensitive)
pub fn match_cname(cname_target: &str) -> Option<&'static ServiceFingerprint> {
    let lower = cname_target.to_lowercase();
    FINGERPRINTS
        .iter()
        .find(|fp| lower.contains(fp.cname_suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_pages_suffix_matches() {
        let fp = match_cname("foo.github.io").unwrap();
        assert_eq!(fp.service, "GitHub Pages");
    }

    #[test]
    fn no_match_returns_none() {
        assert!(match_cname("totally.different.tld").is_none());
    }

    #[test]
    fn matching_is_case_insensitive() {
        let fp = match_cname("FOO.NETLIFY.APP").unwrap();
        assert_eq!(fp.service, "Netlify");
    }

    #[test]
    fn fingerprint_table_is_nonempty() {
        assert!(!FINGERPRINTS.is_empty());
    }
}
