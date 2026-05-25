/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-25
 * Description:     mg-webscan — merged active web-vulnerability scanner
 *                  suite covering injection, request-tampering, and
 *                  client-trust classes against the crawl corpus.
 * Notes:           Subcommand-routed; each module owns its CLI args and
 *                  output subdir under the engagement workspace.
 *                  Replaces mg-xss, mg-sqli, mg-ssrf, mg-ssti, mg-xxe,
 *                  mg-traversal, mg-redirect, mg-csrf, mg-cmdinject,
 *                  mg-cors-exploit, mg-cache-poison, mg-proto-pollute,
 *                  mg-deser, and mg-smuggle.
 *******************************************************************/

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cache_poison;
mod cmdinject;
mod cors;
mod csrf;
mod deser;
mod proto_pollute;
mod redirect;
mod smuggle;
mod sqli;
mod ssrf;
mod ssti;
mod traversal;
mod xss;
mod xxe;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-webscan",
    about = "Merged active web-vuln scanner — XSS, SQLi, SSRF, SSTI, XXE, traversal, redirect, CSRF, command injection, CORS, cache poisoning, prototype pollution, deserialization, request smuggling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Reflected and DOM-based XSS injection
    Xss(xss::Args),
    /// SQL injection detection
    Sqli(sqli::Args),
    /// Server-side request forgery detection
    Ssrf(ssrf::Args),
    /// Server-side template injection detection
    Ssti(ssti::Args),
    /// XML external entity injection detection
    Xxe(xxe::Args),
    /// Path/directory traversal detection
    Traversal(traversal::Args),
    /// Open-redirect detection
    Redirect(redirect::Args),
    /// CSRF protection analysis
    Csrf(csrf::Args),
    /// OS command injection detection
    Cmdinject(cmdinject::Args),
    /// CORS misconfiguration exploitation
    Cors(cors::Args),
    /// Web cache poisoning detection
    CachePoison(cache_poison::Args),
    /// Prototype pollution detection
    ProtoPollute(proto_pollute::Args),
    /// Insecure deserialization detection
    Deser(deser::Args),
    /// HTTP request smuggling detection
    Smuggle(smuggle::Args),
}

// ── Entry point ──────────────────────────────────────────────────────────────

// Parse the CLI and route to the selected scanner module
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Xss(args) => xss::run(args).await,
        Command::Sqli(args) => sqli::run(args).await,
        Command::Ssrf(args) => ssrf::run(args).await,
        Command::Ssti(args) => ssti::run(args).await,
        Command::Xxe(args) => xxe::run(args).await,
        Command::Traversal(args) => traversal::run(args).await,
        Command::Redirect(args) => redirect::run(args).await,
        Command::Csrf(args) => csrf::run(args).await,
        Command::Cmdinject(args) => cmdinject::run(args).await,
        Command::Cors(args) => cors::run(args).await,
        Command::CachePoison(args) => cache_poison::run(args).await,
        Command::ProtoPollute(args) => proto_pollute::run(args).await,
        Command::Deser(args) => deser::run(args).await,
        Command::Smuggle(args) => smuggle::run(args).await,
    }
}
