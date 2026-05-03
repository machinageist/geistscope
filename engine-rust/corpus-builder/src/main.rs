/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     corpus-builder CLI — mine and query subdomain/path corpus
 *******************************************************************/
mod cli;

use std::fs;
use corpus_builder::{ct, wayback, Corpus};

// Validate ASCII domain syntax — alnum + . + -, no leading/trailing dot or dash,
// no double-dot, must contain at least one dot
fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && !s.contains("..")
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// Read domains file, skip blank/comment lines, warn on (and skip) malformed entries
fn read_domains(path: &str) -> Vec<String> {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| { eprintln!("cannot read {path}: {e}"); std::process::exit(1); });
    let mut valid = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_lowercase();
        if is_valid_domain(&lower) {
            valid.push(lower);
        } else {
            eprintln!("skipping invalid domain at line {}: {line}", i + 1);
        }
    }
    valid
}

fn open_corpus(db: &str) -> Corpus {
    Corpus::open(db).unwrap_or_else(|e| { eprintln!("cannot open {db}: {e}"); std::process::exit(1); })
}

#[tokio::main]
async fn main() {
    let args = cli::get_args();

    match args.command {
        cli::Command::MineCt { domains, db, rate_limit_ms } => {
            let domains = read_domains(&domains);
            let mut corpus = open_corpus(&db);
            eprintln!("Mining CT logs for {} domains → {db}", domains.len());
            ct::mine_ct_logs(&domains, &mut corpus, rate_limit_ms).await;
            let (_, subs, _) = corpus.stats().unwrap_or_default();
            eprintln!("Done. Total subdomains in corpus: {subs}");
        }

        cli::Command::MineWayback { domains, db, rate_limit_ms } => {
            let domains = read_domains(&domains);
            let mut corpus = open_corpus(&db);
            eprintln!("Mining Wayback CDX for {} domains → {db}", domains.len());
            wayback::mine_wayback(&domains, &mut corpus, rate_limit_ms).await;
            let (_, _, paths) = corpus.stats().unwrap_or_default();
            eprintln!("Done. Total paths in corpus: {paths}");
        }

        cli::Command::Query { domain, db } => {
            let corpus = open_corpus(&db);
            let subs = corpus.subdomains(&domain).unwrap_or_default();
            if subs.is_empty() {
                eprintln!("No subdomains found for {domain}");
            } else {
                println!("Subdomains for {domain} ({} total):", subs.len());
                for s in &subs { println!("  {s}"); }
            }
        }

        cli::Command::Stats { db } => {
            let corpus = open_corpus(&db);
            match corpus.stats() {
                Ok((domains, subs, paths)) => {
                    println!("Corpus: {domains} domains, {subs} subdomains, {paths} paths");
                }
                Err(e) => eprintln!("stats error: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_domain;

    #[test]
    fn valid_domains_accepted() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("api.staging.example.com"));
        assert!(is_valid_domain("a.b"));
        assert!(is_valid_domain("foo-bar.example.com"));
    }

    #[test]
    fn malformed_domains_rejected() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("no-dot"));
        assert!(!is_valid_domain(".leading-dot.com"));
        assert!(!is_valid_domain("trailing-dot."));
        assert!(!is_valid_domain("double..dot.com"));
        assert!(!is_valid_domain("-leading-dash.com"));
        assert!(!is_valid_domain("under_score.com"));
        assert!(!is_valid_domain("space in.com"));
        assert!(!is_valid_domain("ampersand&injection.com"));
    }
}
