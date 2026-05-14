/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-02
 * Description:     mg-engagement CLI — initialize, scope, audit, findings
 *******************************************************************/
mod cli;

use anyhow::{Context, Result, anyhow};
use engagement::{Engagement, EngagementMeta, Finding, Severity, Status};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(anyhow!("unknown severity: {other}")),
    }
}

// Generate a finding ID like "2026-05-02-001" by counting existing files for today
fn next_finding_id(findings_dir: &Path) -> Result<String> {
    let today = OffsetDateTime::now_utc()
        .date()
        .format(&time::format_description::parse("[year]-[month]-[day]").unwrap())?;
    let mut max_seq = 0u32;
    if findings_dir.exists() {
        for entry in std::fs::read_dir(findings_dir)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            // Match prefix like "2026-05-02-NNN-"
            if let Some(rest) = name.strip_prefix(&format!("{today}-"))
                && let Some(seq_part) = rest.split('-').next()
                && let Ok(n) = seq_part.parse::<u32>()
            {
                max_seq = max_seq.max(n);
            }
        }
    }
    Ok(format!("{today}-{:03}", max_seq + 1))
}

fn cmd_init(
    root: &Path,
    name: String,
    target: String,
    platform: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
) -> Result<()> {
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let meta = EngagementMeta {
        name: name.clone(),
        target,
        created_at: String::new(),
        platform,
        url,
        tags,
    };
    let e = Engagement::init(root, meta)?;
    println!("initialized engagement {} at {}", name, e.root.display());
    Ok(())
}

fn cmd_list(root: &Path) -> Result<()> {
    let all = Engagement::list(root)?;
    if all.is_empty() {
        println!("no engagements under {}", root.display());
        return Ok(());
    }
    println!("{:<24} {:<28} {:<14} CREATED", "NAME", "TARGET", "PLATFORM");
    for e in &all {
        let plat = e.meta.platform.as_deref().unwrap_or("-");
        println!(
            "{:<24} {:<28} {:<14} {}",
            e.meta.name, e.meta.target, plat, e.meta.created_at
        );
    }
    Ok(())
}

fn cmd_show(root: &Path, name: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    println!("name:       {}", e.meta.name);
    println!("target:     {}", e.meta.target);
    println!("created_at: {}", e.meta.created_at);
    if let Some(p) = &e.meta.platform {
        println!("platform:   {p}");
    }
    if let Some(u) = &e.meta.url {
        println!("url:        {u}");
    }
    if !e.meta.tags.is_empty() {
        println!("tags:       {}", e.meta.tags.join(", "));
    }
    let s = e.scope()?;
    println!("\nin scope:");
    for p in &s.in_scope {
        println!("  + {p}");
    }
    if !s.out_of_scope.is_empty() {
        println!("out of scope:");
        for p in &s.out_of_scope {
            println!("  - {p}");
        }
    }
    println!("\nroot: {}", e.root.display());
    Ok(())
}

fn cmd_check(root: &Path, name: &str, target: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let s = e.scope()?;
    if s.is_in_scope(target) {
        println!("IN SCOPE   {target}");
        Ok(())
    } else {
        println!("OUT OF SCOPE   {target}");
        std::process::exit(2);
    }
}

fn cmd_scope_modify(
    root: &Path,
    name: &str,
    pattern: &str,
    remove: bool,
    deny: bool,
) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let mut s = e.scope()?;
    let list: &mut Vec<String> = if deny {
        &mut s.out_of_scope
    } else {
        &mut s.in_scope
    };
    if remove {
        let before = list.len();
        list.retain(|p| p != pattern);
        if list.len() == before {
            return Err(anyhow!("pattern not found: {pattern}"));
        }
        println!(
            "removed {pattern} from {}",
            if deny { "out_of_scope" } else { "in_scope" }
        );
    } else {
        if list.iter().any(|p| p == pattern) {
            return Err(anyhow!("pattern already present: {pattern}"));
        }
        list.push(pattern.to_string());
        println!(
            "added {pattern} to {}",
            if deny { "out_of_scope" } else { "in_scope" }
        );
    }
    e.save_scope(&s)?;
    Ok(())
}

fn cmd_note(root: &Path, name: &str, text: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    e.append_note(text)?;
    println!("appended note to {}/notes.md", e.root.display());
    Ok(())
}

fn cmd_finding(
    root: &Path,
    name: &str,
    title: String,
    target: String,
    severity: &str,
) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let scope = e.scope()?;
    if !scope.is_in_scope(&target) {
        return Err(anyhow!(
            "target {target} is OUT OF SCOPE for engagement {name}; refusing to create finding"
        ));
    }

    let sev = parse_severity(severity)?;
    let id = next_finding_id(&e.findings_dir())?;
    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let f = Finding {
        id,
        title,
        severity: sev,
        status: Status::Draft,
        target,
        created: now,
        body: Finding::skeleton_body(),
    };
    let path = f.write_to(&e.findings_dir())?;
    println!("created {}", path.display());
    Ok(())
}

fn main() -> Result<()> {
    let args = cli::get_args();
    let root = Path::new(&args.root);

    match args.command {
        cli::Command::Init {
            name,
            target,
            platform,
            url,
            tags,
        } => cmd_init(root, name, target, platform, url, tags),
        cli::Command::List => cmd_list(root),
        cli::Command::Show { name } => cmd_show(root, &name),
        cli::Command::Check { name, target } => cmd_check(root, &name, &target),
        cli::Command::ScopeAdd {
            name,
            pattern,
            remove,
        } => cmd_scope_modify(root, &name, &pattern, remove, false),
        cli::Command::ScopeDeny {
            name,
            pattern,
            remove,
        } => cmd_scope_modify(root, &name, &pattern, remove, true),
        cli::Command::Note { name, text } => cmd_note(root, &name, &text),
        cli::Command::Finding {
            name,
            title,
            target,
            severity,
        } => cmd_finding(root, &name, title, target, &severity),
    }
}
