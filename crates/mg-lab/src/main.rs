// Author: Jeff
// Date: 2026-05-28
// Description: CLI for controlled lab identity, tenant, role, and resource records
// Notes: Stores lab metadata under the engagement root without secrets

use anyhow::{Context, Result};
use browser_lab::{BrowserEngine, BrowserProfile, ProxySettings, RedactedBrowserProfile};
use clap::{Parser, Subcommand};
use lab_model::{Identity, LabModel, Resource, Role, Tenant};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const LAB_DIR: &str = "lab";
const IDENTITIES_DIR: &str = "identities";
const TENANTS_DIR: &str = "tenants";
const ROLES_DIR: &str = "roles";
const RESOURCES_DIR: &str = "resources";
const BROWSER_PROFILES_DIR: &str = "browser-profiles";
const DEFAULT_BROWSER_IMAGE: &str = "mcr.microsoft.com/playwright:latest";
const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
const DEFAULT_PROXY_PORT: u16 = 8080;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "mg-lab",
    about = "Manage controlled lab records for an engagement"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List all controlled lab records for an engagement
    List {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Create or query controlled identities
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Create or query controlled tenants
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Create or query controlled roles
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },
    /// Create or query controlled resources
    Resource {
        #[command(subcommand)]
        command: ResourceCommand,
    },
    /// Create or query isolated browser profiles
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Create a controlled identity metadata record
    Create {
        /// Engagement root directory
        engagement: PathBuf,
        /// Safe identity id
        id: String,
        /// Human-readable label
        #[arg(long)]
        label: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Create a controlled tenant metadata record
    Create {
        /// Engagement root directory
        engagement: PathBuf,
        /// Safe tenant id
        id: String,
        /// Human-readable label
        #[arg(long)]
        label: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RoleCommand {
    /// Create a controlled role metadata record
    Create {
        /// Engagement root directory
        engagement: PathBuf,
        /// Safe role id
        id: String,
        /// Human-readable label
        #[arg(long)]
        label: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ResourceCommand {
    /// Create a controlled resource metadata record
    Create {
        /// Engagement root directory
        engagement: PathBuf,
        /// Safe resource id
        id: String,
        /// Tenant that owns this resource
        #[arg(long)]
        tenant: String,
        /// Resource kind such as invoice or project
        #[arg(long = "type")]
        resource_type: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BrowserCommand {
    /// Create an isolated browser profile metadata record
    Create {
        /// Engagement root directory
        engagement: PathBuf,
        /// Safe browser profile id
        id: String,
        /// Controlled identity id
        #[arg(long)]
        identity: String,
        /// Controlled tenant id
        #[arg(long)]
        tenant: String,
        /// Controlled role id
        #[arg(long)]
        role: String,
        /// Container/browser engine: podman|docker|playwright-local
        #[arg(long)]
        engine: String,
        /// Named session id for this browser profile
        #[arg(long)]
        session: Option<String>,
        /// Browser image to launch later
        #[arg(long, default_value = DEFAULT_BROWSER_IMAGE)]
        image: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Build container run arguments for an isolated browser profile
    Start {
        /// Engagement root directory
        engagement: PathBuf,
        /// Browser profile id
        id: String,
        /// Print launch args without starting a container
        #[arg(long)]
        dry_run: bool,
        /// Allow proxy hosts outside loopback
        #[arg(long)]
        allow_non_loopback_proxy: bool,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// List browser profiles as redacted metadata
    List {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Validate profile account labels against lab records
    Validate {
        /// Engagement root directory
        engagement: PathBuf,
        /// Browser profile id
        id: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct WriteOutput<T: Serialize> {
    kind: &'static str,
    path: String,
    record: T,
}

#[derive(Debug, Serialize)]
struct BrowserStartOutput {
    dry_run: bool,
    launched: bool,
    engine: BrowserEngine,
    profile_id: String,
    args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BrowserValidateOutput {
    valid: bool,
    profile_id: String,
    identity: Identity,
    tenant: Tenant,
    role: Role,
}

#[derive(Debug, Serialize)]
struct BrowserListOutput {
    kind: &'static str,
    records: Vec<RedactedBrowserProfile>,
}

// ── Entrypoint ───────────────────────────────────────────────────────────────

// Run the CLI and print errors through anyhow
fn main() -> Result<()> {
    let output = run_with_args(std::env::args())?;
    print!("{output}");
    Ok(())
}

// Run the CLI with explicit args for tests
fn run_with_args<I, T>(args: I) -> Result<String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = Args::try_parse_from(args)?;
    match args.command {
        Command::List { engagement, json } => list_lab(&engagement, json),
        Command::Identity { command } => match command {
            IdentityCommand::Create {
                engagement,
                id,
                label,
                json,
            } => create_identity(&engagement, &id, &label, json),
        },
        Command::Tenant { command } => match command {
            TenantCommand::Create {
                engagement,
                id,
                label,
                json,
            } => create_tenant(&engagement, &id, &label, json),
        },
        Command::Role { command } => match command {
            RoleCommand::Create {
                engagement,
                id,
                label,
                json,
            } => create_role(&engagement, &id, &label, json),
        },
        Command::Resource { command } => match command {
            ResourceCommand::Create {
                engagement,
                id,
                tenant,
                resource_type,
                json,
            } => create_resource(&engagement, &id, &tenant, &resource_type, json),
        },
        Command::Browser { command } => match command {
            BrowserCommand::Create {
                engagement,
                id,
                identity,
                tenant,
                role,
                engine,
                session,
                image,
                json,
            } => create_browser_profile(
                &engagement,
                &id,
                &identity,
                &tenant,
                &role,
                &engine,
                session.as_deref(),
                image,
                json,
            ),
            BrowserCommand::Start {
                engagement,
                id,
                dry_run,
                allow_non_loopback_proxy,
                json,
            } => start_browser_profile(&engagement, &id, dry_run, allow_non_loopback_proxy, json),
            BrowserCommand::List { engagement, json } => list_browser_profiles(&engagement, json),
            BrowserCommand::Validate {
                engagement,
                id,
                json,
            } => validate_browser_profile(&engagement, &id, json),
        },
    }
}

// ── Record readers ───────────────────────────────────────────────────────────

// List all lab records as a stable lab model JSON document
fn list_lab(engagement: &Path, json: bool) -> Result<String> {
    let engagement_name = engagement
        .file_name()
        .and_then(|name| name.to_str())
        .context("engagement path should end with a UTF-8 directory name")?;
    let model = LabModel {
        engagement: engagement_name.into(),
        identities: read_collection(engagement, IDENTITIES_DIR)?,
        tenants: read_collection(engagement, TENANTS_DIR)?,
        roles: read_collection(engagement, ROLES_DIR)?,
        resources: read_collection(engagement, RESOURCES_DIR)?,
        boundaries: Vec::new(),
    };

    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&model)?))
    } else {
        Ok(format!(
            "identities={} tenants={} roles={} resources={}\n",
            model.identities.len(),
            model.tenants.len(),
            model.roles.len(),
            model.resources.len()
        ))
    }
}

// Read one lab collection sorted by path for stable output
fn read_collection<T>(engagement: &Path, collection: &str) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let collection_path = engagement.join(LAB_DIR).join(collection);
    if !collection_path.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&collection_path)
        .with_context(|| format!("read lab collection {}", collection_path.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    let mut records = Vec::new();
    for path in files {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read lab record {}", path.display()))?;
        records.push(serde_json::from_str(&raw)?);
    }
    Ok(records)
}

// ── Record writers ───────────────────────────────────────────────────────────

// Create an identity record under lab/identities
fn create_identity(engagement: &Path, id: &str, label: &str, json: bool) -> Result<String> {
    let identity = Identity::new(id, label)?;
    let record_id = identity.id.clone();
    write_record(
        engagement,
        "identity",
        IDENTITIES_DIR,
        &record_id,
        identity,
        json,
    )
}

// Create a tenant record under lab/tenants
fn create_tenant(engagement: &Path, id: &str, label: &str, json: bool) -> Result<String> {
    let tenant = Tenant::new(id, label)?;
    let record_id = tenant.id.clone();
    write_record(engagement, "tenant", TENANTS_DIR, &record_id, tenant, json)
}

// Create a role record under lab/roles
fn create_role(engagement: &Path, id: &str, label: &str, json: bool) -> Result<String> {
    let role = Role::new(id, label)?;
    let record_id = role.id.clone();
    write_record(engagement, "role", ROLES_DIR, &record_id, role, json)
}

// Create a resource record under lab/resources
fn create_resource(
    engagement: &Path,
    id: &str,
    tenant_id: &str,
    resource_type: &str,
    json: bool,
) -> Result<String> {
    let resource = Resource::new(id, tenant_id, resource_type)?;
    let record_id = resource.id.clone();
    write_record(
        engagement,
        "resource",
        RESOURCES_DIR,
        &record_id,
        resource,
        json,
    )
}

// Create a browser profile record under lab/browser-profiles
#[allow(clippy::too_many_arguments)]
fn create_browser_profile(
    engagement: &Path,
    id: &str,
    identity_id: &str,
    tenant_id: &str,
    role_id: &str,
    engine: &str,
    session_id: Option<&str>,
    image: String,
    json: bool,
) -> Result<String> {
    let engine = parse_browser_engine(engine)?;
    let session_id = session_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("session-{identity_id}"));
    let profile = BrowserProfile::new(
        id,
        engine,
        image,
        session_id,
        identity_id.into(),
        tenant_id.into(),
        role_id.into(),
        ProxySettings::loopback(DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT),
    )?;
    let record_id = profile.id.clone();
    write_record(
        engagement,
        "browser_profile",
        BROWSER_PROFILES_DIR,
        &record_id,
        profile,
        json,
    )
}

// List browser profiles using redacted model-visible metadata
fn list_browser_profiles(engagement: &Path, json: bool) -> Result<String> {
    let profiles: Vec<BrowserProfile> = read_collection(engagement, BROWSER_PROFILES_DIR)?;
    let records = profiles
        .into_iter()
        .map(|profile| profile.redacted_metadata())
        .collect::<Vec<_>>();
    let output = BrowserListOutput {
        kind: "browser_profiles",
        records,
    };

    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&output)?))
    } else {
        Ok(format!("browser_profiles={}\n", output.records.len()))
    }
}

// Validate that a browser profile points at existing lab account records
fn validate_browser_profile(engagement: &Path, id: &str, json: bool) -> Result<String> {
    let profile: BrowserProfile = read_record(engagement, BROWSER_PROFILES_DIR, id)?;
    let identity: Identity = read_record(engagement, IDENTITIES_DIR, &profile.identity_id)?;
    let tenant: Tenant = read_record(engagement, TENANTS_DIR, &profile.tenant_id)?;
    let role: Role = read_record(engagement, ROLES_DIR, &profile.role_id)?;
    let output = BrowserValidateOutput {
        valid: true,
        profile_id: profile.id,
        identity,
        tenant,
        role,
    };

    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&output)?))
    } else {
        Ok(format!("browser profile {} valid\n", output.profile_id))
    }
}

// Build launch arguments for a browser profile without exposing secrets
fn start_browser_profile(
    engagement: &Path,
    id: &str,
    dry_run: bool,
    allow_non_loopback_proxy: bool,
    json: bool,
) -> Result<String> {
    let profile: BrowserProfile = read_record(engagement, BROWSER_PROFILES_DIR, id)?;
    if !allow_non_loopback_proxy && !is_loopback_host(&profile.proxy.host) {
        anyhow::bail!("non-loopback proxy exposure requires --allow-non-loopback-proxy");
    }
    if !dry_run {
        anyhow::bail!("browser start currently requires --dry-run");
    }

    let args = browser_run_args(engagement, &profile);
    let output = BrowserStartOutput {
        dry_run,
        launched: false,
        engine: profile.engine.clone(),
        profile_id: profile.id,
        args,
    };

    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&output)?))
    } else {
        Ok(format!(
            "{} {}\n",
            format_engine(&output.engine),
            output.args.join(" ")
        ))
    }
}

// Read one typed lab record by id
fn read_record<T>(engagement: &Path, collection: &str, id: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = engagement
        .join(LAB_DIR)
        .join(collection)
        .join(format!("{id}.json"));
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read lab record {}", path.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

// Build deterministic container args for a browser dry run
fn browser_run_args(engagement: &Path, profile: &BrowserProfile) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--network=host".into(),
        "--name".into(),
        format!("mg-browser-{}", profile.id),
        "-e".into(),
        format!(
            "HTTPS_PROXY={}://{}:{}",
            profile.proxy.scheme, profile.proxy.host, profile.proxy.port
        ),
        "-v".into(),
        format!(
            "{}:/home/pwuser/.cache/ms-playwright:rw",
            engagement
                .join(LAB_DIR)
                .join(&profile.cache_volume)
                .display()
        ),
        "-v".into(),
        format!(
            "{}:/home/pwuser/profile:rw",
            engagement
                .join(LAB_DIR)
                .join(&profile.storage_volume)
                .display()
        ),
        profile.image.clone(),
    ]
}

// Check whether a proxy host is loopback scoped
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

// Format an engine for text output
fn format_engine(engine: &BrowserEngine) -> &'static str {
    match engine {
        BrowserEngine::Podman => "podman",
        BrowserEngine::Docker => "docker",
        BrowserEngine::PlaywrightLocal => "playwright-local",
    }
}

// Parse browser engine names from CLI input
fn parse_browser_engine(engine: &str) -> Result<BrowserEngine> {
    match engine {
        "podman" => Ok(BrowserEngine::Podman),
        "docker" => Ok(BrowserEngine::Docker),
        "playwright-local" => Ok(BrowserEngine::PlaywrightLocal),
        other => anyhow::bail!("unsupported browser engine: {other}"),
    }
}

// Write one lab record to its stable relative path
fn write_record<T>(
    engagement: &Path,
    kind: &'static str,
    collection: &str,
    id: &str,
    record: T,
    json: bool,
) -> Result<String>
where
    T: Serialize,
{
    let relative_path = PathBuf::from(LAB_DIR)
        .join(collection)
        .join(format!("{id}.json"));
    let output_path = engagement.join(&relative_path);
    let parent = output_path
        .parent()
        .context("lab output path should have a parent")?;

    std::fs::create_dir_all(parent)
        .with_context(|| format!("create lab record directory {}", parent.display()))?;
    let record_json = serde_json::to_string_pretty(&record)?;
    std::fs::write(&output_path, record_json)
        .with_context(|| format!("write lab record {}", output_path.display()))?;

    let output = WriteOutput {
        kind,
        path: relative_path.to_string_lossy().into_owned(),
        record,
    };

    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&output)?))
    } else {
        Ok(format!(
            "created {kind} {id} at {}\n",
            output_path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::run_with_args;
    use serde_json::Value;

    #[test]
    fn identity_create_json_writes_under_engagement_lab() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();

        let output = run_with_args([
            "mg-lab",
            "identity",
            "create",
            engagement.to_str().unwrap(),
            "alice",
            "--label",
            "Alice Admin",
            "--json",
        ])
        .unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["kind"], "identity");
        assert_eq!(parsed["record"]["id"], "alice");
        assert_eq!(parsed["path"], "lab/identities/alice.json");
        assert!(engagement.join("lab/identities/alice.json").exists());
    }

    #[test]
    fn tenant_role_and_resource_create_emit_stable_json() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();

        let tenant = run_with_args([
            "mg-lab",
            "tenant",
            "create",
            engagement.to_str().unwrap(),
            "tenant-a",
            "--label",
            "Tenant A",
            "--json",
        ])
        .unwrap();
        let role = run_with_args([
            "mg-lab",
            "role",
            "create",
            engagement.to_str().unwrap(),
            "admin",
            "--label",
            "Admin",
            "--json",
        ])
        .unwrap();
        let resource = run_with_args([
            "mg-lab",
            "resource",
            "create",
            engagement.to_str().unwrap(),
            "invoice-1",
            "--tenant",
            "tenant-a",
            "--type",
            "invoice",
            "--json",
        ])
        .unwrap();

        let tenant_json: Value = serde_json::from_str(&tenant).unwrap();
        let role_json: Value = serde_json::from_str(&role).unwrap();
        let resource_json: Value = serde_json::from_str(&resource).unwrap();
        assert_eq!(tenant_json["kind"], "tenant");
        assert_eq!(tenant_json["path"], "lab/tenants/tenant-a.json");
        assert_eq!(role_json["kind"], "role");
        assert_eq!(role_json["path"], "lab/roles/admin.json");
        assert_eq!(resource_json["kind"], "resource");
        assert_eq!(resource_json["record"]["tenant_id"], "tenant-a");
        assert_eq!(resource_json["record"]["resource_type"], "invoice");
        assert_eq!(resource_json["path"], "lab/resources/invoice-1.json");
    }

    #[test]
    fn list_json_emits_stable_lab_model() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();
        run_with_args([
            "mg-lab",
            "identity",
            "create",
            engagement.to_str().unwrap(),
            "alice",
            "--label",
            "Alice Admin",
            "--json",
        ])
        .unwrap();
        run_with_args([
            "mg-lab",
            "tenant",
            "create",
            engagement.to_str().unwrap(),
            "tenant-a",
            "--label",
            "Tenant A",
            "--json",
        ])
        .unwrap();

        let output =
            run_with_args(["mg-lab", "list", engagement.to_str().unwrap(), "--json"]).unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["engagement"], "example-program");
        assert_eq!(parsed["identities"][0]["id"], "alice");
        assert_eq!(parsed["tenants"][0]["id"], "tenant-a");
        assert_eq!(parsed["roles"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["resources"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn browser_create_json_writes_profile_under_lab_browser_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();

        let output = run_with_args([
            "mg-lab",
            "browser",
            "create",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--identity",
            "alice",
            "--tenant",
            "tenant-a",
            "--role",
            "admin",
            "--engine",
            "podman",
            "--json",
        ])
        .unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["kind"], "browser_profile");
        assert_eq!(parsed["path"], "lab/browser-profiles/alice-admin.json");
        assert_eq!(parsed["record"]["identity_id"], "alice");
        assert_eq!(parsed["record"]["tenant_id"], "tenant-a");
        assert_eq!(parsed["record"]["role_id"], "admin");
        assert_eq!(parsed["record"]["engine"], "podman");
        assert!(
            engagement
                .join("lab/browser-profiles/alice-admin.json")
                .exists()
        );
    }

    #[test]
    fn browser_start_dry_run_json_emits_container_args_without_launching() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();
        run_with_args([
            "mg-lab",
            "browser",
            "create",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--identity",
            "alice",
            "--tenant",
            "tenant-a",
            "--role",
            "admin",
            "--engine",
            "podman",
            "--json",
        ])
        .unwrap();

        let output = run_with_args([
            "mg-lab",
            "browser",
            "start",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--dry-run",
            "--json",
        ])
        .unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["dry_run"], true);
        assert_eq!(parsed["engine"], "podman");
        assert_eq!(parsed["args"][0], "run");
        assert!(
            parsed["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "--network=host")
        );
        assert_eq!(parsed["launched"], false);
    }

    #[test]
    fn browser_start_refuses_non_loopback_proxy_without_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(engagement.join("lab/browser-profiles")).unwrap();
        std::fs::write(
            engagement.join("lab/browser-profiles/alice-admin.json"),
            r#"{
  "id": "alice-admin",
  "engine": "podman",
  "image": "mcr.microsoft.com/playwright:latest",
  "session_id": "session-alice",
  "identity_id": "alice",
  "tenant_id": "tenant-a",
  "role_id": "admin",
  "proxy": { "host": "0.0.0.0", "port": 8080, "scheme": "http" },
  "storage_volume": "browser-profiles/alice-admin/storage",
  "cache_volume": "browser-profiles/alice-admin/cache"
}"#,
        )
        .unwrap();

        let err = run_with_args([
            "mg-lab",
            "browser",
            "start",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--dry-run",
            "--json",
        ])
        .unwrap_err();

        assert!(err.to_string().contains("non-loopback proxy exposure"));
    }

    #[test]
    fn browser_validate_confirms_profile_account_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();
        run_with_args([
            "mg-lab",
            "identity",
            "create",
            engagement.to_str().unwrap(),
            "alice",
            "--label",
            "Alice Admin",
            "--json",
        ])
        .unwrap();
        run_with_args([
            "mg-lab",
            "tenant",
            "create",
            engagement.to_str().unwrap(),
            "tenant-a",
            "--label",
            "Tenant A",
            "--json",
        ])
        .unwrap();
        run_with_args([
            "mg-lab",
            "role",
            "create",
            engagement.to_str().unwrap(),
            "admin",
            "--label",
            "Admin",
            "--json",
        ])
        .unwrap();
        run_with_args([
            "mg-lab",
            "browser",
            "create",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--identity",
            "alice",
            "--tenant",
            "tenant-a",
            "--role",
            "admin",
            "--engine",
            "podman",
            "--json",
        ])
        .unwrap();

        let output = run_with_args([
            "mg-lab",
            "browser",
            "validate",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--json",
        ])
        .unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["valid"], true);
        assert_eq!(parsed["profile_id"], "alice-admin");
        assert_eq!(parsed["identity"]["id"], "alice");
        assert_eq!(parsed["tenant"]["id"], "tenant-a");
        assert_eq!(parsed["role"]["id"], "admin");
    }

    #[test]
    fn browser_list_json_emits_redacted_profile_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let engagement = tmp.path().join("example-program");
        std::fs::create_dir_all(&engagement).unwrap();
        run_with_args([
            "mg-lab",
            "browser",
            "create",
            engagement.to_str().unwrap(),
            "alice-admin",
            "--identity",
            "alice",
            "--tenant",
            "tenant-a",
            "--role",
            "admin",
            "--engine",
            "podman",
            "--json",
        ])
        .unwrap();

        let output = run_with_args([
            "mg-lab",
            "browser",
            "list",
            engagement.to_str().unwrap(),
            "--json",
        ])
        .unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["kind"], "browser_profiles");
        assert_eq!(parsed["records"][0]["id"], "alice-admin");
        assert_eq!(parsed["records"][0]["identity_id"], "alice");
        assert!(parsed["records"][0].get("image").is_none());
        assert!(parsed["records"][0].get("storage_volume").is_none());
    }
}
