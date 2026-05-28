// Author: Jeff
// Date: 2026-05-28
// Description: CLI for controlled lab identity, tenant, role, and resource records
// Notes: Stores lab metadata under the engagement root without secrets

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lab_model::{Identity, LabModel, Resource, Role, Tenant};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

const LAB_DIR: &str = "lab";
const IDENTITIES_DIR: &str = "identities";
const TENANTS_DIR: &str = "tenants";
const ROLES_DIR: &str = "roles";
const RESOURCES_DIR: &str = "resources";

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

#[derive(Debug, Serialize)]
struct WriteOutput<T: Serialize> {
    kind: &'static str,
    path: String,
    record: T,
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
}
