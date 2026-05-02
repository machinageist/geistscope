/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     corpus-builder CLI — mine and query subdomain/path corpus
 *******************************************************************/
mod cli;

use std::fs;
use corpus_builder::{ct, wayback, Corpus};

fn read_domains(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| { eprintln!("cannot read {path}: {e}"); std::process::exit(1); })
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
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
            let corpus = open_corpus(&db);
            eprintln!("Mining CT logs for {} domains → {db}", domains.len());
            ct::mine_ct_logs(&domains, &corpus, rate_limit_ms).await;
            let (_, subs, _) = corpus.stats().unwrap_or_default();
            eprintln!("Done. Total subdomains in corpus: {subs}");
        }

        cli::Command::MineWayback { domains, db, rate_limit_ms } => {
            let domains = read_domains(&domains);
            let corpus = open_corpus(&db);
            eprintln!("Mining Wayback CDX for {} domains → {db}", domains.len());
            wayback::mine_wayback(&domains, &corpus, rate_limit_ms).await;
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
