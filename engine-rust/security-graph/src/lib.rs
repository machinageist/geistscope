/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Local-first security graph model and JSONL store
 * Notes:           The file-backed adapter keeps current engagement files as
 *                  the source of truth while exposing a future Postgres-ready
 *                  graph boundary for harness and UI callers.
 *******************************************************************/

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use engagement::Engagement;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const MAX_NEIGHBOR_LIMIT: usize = 100;

// Graph node classes understood by the first security graph slice
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Host,
    Url,
    Parameter,
    Identity,
    Jwt,
    Session,
    Cookie,
    Api,
    Finding,
    Technology,
    ReplayChain,
}

impl NodeKind {
    // Return the stable wire name for this node kind
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Url => "url",
            Self::Parameter => "parameter",
            Self::Identity => "identity",
            Self::Jwt => "jwt",
            Self::Session => "session",
            Self::Cookie => "cookie",
            Self::Api => "api",
            Self::Finding => "finding",
            Self::Technology => "technology",
            Self::ReplayChain => "replay_chain",
        }
    }
}

impl std::str::FromStr for NodeKind {
    type Err = SecurityGraphError;

    // Parse a node kind from endpoint arguments
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "host" => Ok(Self::Host),
            "url" => Ok(Self::Url),
            "parameter" => Ok(Self::Parameter),
            "identity" => Ok(Self::Identity),
            "jwt" => Ok(Self::Jwt),
            "session" => Ok(Self::Session),
            "cookie" => Ok(Self::Cookie),
            "api" => Ok(Self::Api),
            "finding" => Ok(Self::Finding),
            "technology" => Ok(Self::Technology),
            "replay_chain" => Ok(Self::ReplayChain),
            other => Err(SecurityGraphError::Invalid(format!(
                "unknown node kind `{other}`"
            ))),
        }
    }
}

// Graph edge classes understood by the first security graph slice
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Calls,
    AuthenticatesTo,
    References,
    DiscoveredBy,
    VulnerableTo,
    RelatedTo,
    ReplayedFrom,
}

impl EdgeKind {
    // Return the stable wire name for this edge kind
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calls => "calls",
            Self::AuthenticatesTo => "authenticates_to",
            Self::References => "references",
            Self::DiscoveredBy => "discovered_by",
            Self::VulnerableTo => "vulnerable_to",
            Self::RelatedTo => "related_to",
            Self::ReplayedFrom => "replayed_from",
        }
    }
}

// Evidence pointer attached to nodes and edges
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
}

impl EvidenceRef {
    // Build an evidence reference with an optional source path
    pub fn new(uri: impl Into<String>, source_path: Option<&Path>) -> Self {
        Self {
            uri: uri.into(),
            source_path: source_path.map(|path| path.display().to_string()),
        }
    }
}

// One persisted graph node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityNode {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    #[serde(default)]
    pub properties: BTreeMap<String, Value>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    pub first_seen: String,
    pub last_seen: String,
}

impl SecurityNode {
    // Build a new graph node with a deterministic ID
    pub fn new(
        kind: NodeKind,
        key: impl AsRef<str>,
        label: impl Into<String>,
        timestamp: &str,
    ) -> Self {
        Self {
            id: node_id(kind, key.as_ref()),
            kind,
            label: label.into(),
            properties: BTreeMap::new(),
            evidence_refs: Vec::new(),
            first_seen: timestamp.to_string(),
            last_seen: timestamp.to_string(),
        }
    }

    // Add one JSON property
    pub fn property(mut self, key: impl Into<String>, value: Value) -> Self {
        self.properties.insert(key.into(), value);
        self
    }

    // Add one evidence reference
    pub fn evidence(mut self, evidence_ref: EvidenceRef) -> Self {
        self.evidence_refs.push(evidence_ref);
        self
    }
}

// One persisted graph edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, Value>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    pub first_seen: String,
    pub last_seen: String,
}

impl SecurityEdge {
    // Build a new graph edge with a deterministic ID
    pub fn new(
        kind: EdgeKind,
        from: impl AsRef<str>,
        to: impl AsRef<str>,
        discriminator: impl AsRef<str>,
        timestamp: &str,
    ) -> Self {
        let from = from.as_ref().to_string();
        let to = to.as_ref().to_string();
        Self {
            id: edge_id(kind, &from, &to, discriminator.as_ref()),
            from,
            to,
            kind,
            label: None,
            properties: BTreeMap::new(),
            evidence_refs: Vec::new(),
            first_seen: timestamp.to_string(),
            last_seen: timestamp.to_string(),
        }
    }

    // Add one JSON property
    pub fn property(mut self, key: impl Into<String>, value: Value) -> Self {
        self.properties.insert(key.into(), value);
        self
    }

    // Add a human-readable edge label
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    // Add one evidence reference
    pub fn evidence(mut self, evidence_ref: EvidenceRef) -> Self {
        self.evidence_refs.push(evidence_ref);
        self
    }
}

// Counts and paths returned by graph summary endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub graph_dir: String,
    pub nodes_path: String,
    pub edges_path: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub node_kinds: BTreeMap<String, usize>,
    pub edge_kinds: BTreeMap<String, usize>,
    pub sample_nodes: Vec<SecurityNode>,
}

// Neighbor direction in a bounded graph read
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborDirection {
    Incoming,
    Outgoing,
}

// One neighbor result with the connecting edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborRecord {
    pub direction: NeighborDirection,
    pub edge: SecurityEdge,
    pub node: SecurityNode,
}

// Bounded neighborhood returned by graph.neighbors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNeighbors {
    pub node: SecurityNode,
    pub neighbors: Vec<NeighborRecord>,
    pub truncated: bool,
}

// Ingestion report returned by graph.ingest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphIngestReport {
    pub engagement: String,
    pub graph_dir: String,
    pub nodes_before: usize,
    pub nodes_after: usize,
    pub edges_before: usize,
    pub edges_after: usize,
    pub sources: Vec<String>,
}

impl GraphIngestReport {
    // Return how many new nodes were materialized
    pub fn nodes_added(&self) -> usize {
        self.nodes_after.saturating_sub(self.nodes_before)
    }

    // Return how many new edges were materialized
    pub fn edges_added(&self) -> usize {
        self.edges_after.saturating_sub(self.edges_before)
    }
}

// Storage boundary for future file and Postgres graph adapters
pub trait GraphStore {
    fn upsert_node(&self, node: SecurityNode) -> Result<(), SecurityGraphError>;
    fn upsert_edge(&self, edge: SecurityEdge) -> Result<(), SecurityGraphError>;
    fn nodes(&self) -> Result<Vec<SecurityNode>, SecurityGraphError>;
    fn edges(&self) -> Result<Vec<SecurityEdge>, SecurityGraphError>;
    fn summary(&self, sample_limit: usize) -> Result<GraphSummary, SecurityGraphError>;
    fn neighbors(&self, node_id: &str, limit: usize) -> Result<GraphNeighbors, SecurityGraphError>;
}

// Local JSONL graph store under engagements/<name>/graph
#[derive(Debug, Clone)]
pub struct FileGraphStore {
    graph_dir: PathBuf,
}

impl FileGraphStore {
    // Build a store rooted in an engagement graph directory
    pub fn for_engagement(engagement: &Engagement) -> Self {
        Self {
            graph_dir: engagement.root.join("graph"),
        }
    }

    // Build a store rooted at an explicit graph directory
    pub fn new(graph_dir: impl Into<PathBuf>) -> Self {
        Self {
            graph_dir: graph_dir.into(),
        }
    }

    // Return the graph directory
    pub fn graph_dir(&self) -> &Path {
        &self.graph_dir
    }

    // Return the node JSONL path
    pub fn nodes_path(&self) -> PathBuf {
        self.graph_dir.join("nodes.jsonl")
    }

    // Return the edge JSONL path
    pub fn edges_path(&self) -> PathBuf {
        self.graph_dir.join("edges.jsonl")
    }

    // Ensure the graph directory exists
    fn ensure_dir(&self) -> Result<(), SecurityGraphError> {
        fs::create_dir_all(&self.graph_dir)?;
        Ok(())
    }
}

impl GraphStore for FileGraphStore {
    // Insert or merge one node and rewrite deterministic JSONL
    fn upsert_node(&self, node: SecurityNode) -> Result<(), SecurityGraphError> {
        self.ensure_dir()?;
        let mut nodes = load_node_map(&self.nodes_path())?;
        nodes
            .entry(node.id.clone())
            .and_modify(|existing| merge_node(existing, &node))
            .or_insert(node);
        write_jsonl(&self.nodes_path(), nodes.values())?;
        Ok(())
    }

    // Insert or merge one edge and rewrite deterministic JSONL
    fn upsert_edge(&self, edge: SecurityEdge) -> Result<(), SecurityGraphError> {
        self.ensure_dir()?;
        let mut edges = load_edge_map(&self.edges_path())?;
        edges
            .entry(edge.id.clone())
            .and_modify(|existing| merge_edge(existing, &edge))
            .or_insert(edge);
        write_jsonl(&self.edges_path(), edges.values())?;
        Ok(())
    }

    // Load all nodes sorted by ID
    fn nodes(&self) -> Result<Vec<SecurityNode>, SecurityGraphError> {
        Ok(load_node_map(&self.nodes_path())?.into_values().collect())
    }

    // Load all edges sorted by ID
    fn edges(&self) -> Result<Vec<SecurityEdge>, SecurityGraphError> {
        Ok(load_edge_map(&self.edges_path())?.into_values().collect())
    }

    // Summarize the graph contents
    fn summary(&self, sample_limit: usize) -> Result<GraphSummary, SecurityGraphError> {
        let nodes = self.nodes()?;
        let edges = self.edges()?;
        let mut node_kinds = BTreeMap::new();
        let mut edge_kinds = BTreeMap::new();
        for node in &nodes {
            *node_kinds
                .entry(node.kind.as_str().to_string())
                .or_insert(0) += 1;
        }
        for edge in &edges {
            *edge_kinds
                .entry(edge.kind.as_str().to_string())
                .or_insert(0) += 1;
        }
        Ok(GraphSummary {
            graph_dir: self.graph_dir.display().to_string(),
            nodes_path: self.nodes_path().display().to_string(),
            edges_path: self.edges_path().display().to_string(),
            node_count: nodes.len(),
            edge_count: edges.len(),
            node_kinds,
            edge_kinds,
            sample_nodes: nodes.into_iter().take(sample_limit).collect(),
        })
    }

    // Return a bounded incoming/outgoing neighborhood
    fn neighbors(&self, node_id: &str, limit: usize) -> Result<GraphNeighbors, SecurityGraphError> {
        let limit = limit.clamp(1, MAX_NEIGHBOR_LIMIT);
        let nodes = self.nodes()?;
        let edges = self.edges()?;
        let node_map: BTreeMap<_, _> = nodes
            .into_iter()
            .map(|node| (node.id.clone(), node))
            .collect();
        let Some(node) = node_map.get(node_id).cloned() else {
            return Err(SecurityGraphError::Invalid(format!(
                "graph node `{node_id}` not found"
            )));
        };

        let mut records = Vec::new();
        for edge in edges {
            if edge.from == node_id {
                if let Some(neighbor) = node_map.get(&edge.to) {
                    records.push(NeighborRecord {
                        direction: NeighborDirection::Outgoing,
                        edge,
                        node: neighbor.clone(),
                    });
                }
            } else if edge.to == node_id
                && let Some(neighbor) = node_map.get(&edge.from)
            {
                records.push(NeighborRecord {
                    direction: NeighborDirection::Incoming,
                    edge,
                    node: neighbor.clone(),
                });
            }
        }
        records.sort_by(|a, b| {
            a.edge
                .kind
                .cmp(&b.edge.kind)
                .then_with(|| a.node.id.cmp(&b.node.id))
                .then_with(|| a.edge.id.cmp(&b.edge.id))
        });
        let truncated = records.len() > limit;
        records.truncate(limit);

        Ok(GraphNeighbors {
            node,
            neighbors: records,
            truncated,
        })
    }
}

// Errors returned by graph model, storage, and ingestion code
#[derive(Debug, Error)]
pub enum SecurityGraphError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engagement: {0}")]
    Engagement(#[from] engagement::EngagementError),
    #[error("time format: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("invalid graph input: {0}")]
    Invalid(String),
}

// Build a deterministic node ID for kind and canonical key
pub fn node_id(kind: NodeKind, key: &str) -> String {
    format!("{}:{}", kind.as_str(), hash_hex(canonical_key(key)))
}

// Build a deterministic edge ID for kind and endpoints
pub fn edge_id(kind: EdgeKind, from: &str, to: &str, discriminator: &str) -> String {
    hash_id(
        "edge",
        &format!("{}|{}|{}|{}", kind.as_str(), from, to, discriminator),
    )
}

// Ingest existing engagement artifacts into the file-backed graph
pub fn ingest_engagement(engagement: &Engagement) -> Result<GraphIngestReport, SecurityGraphError> {
    let store = FileGraphStore::for_engagement(engagement);
    let before_nodes = store.nodes()?.len();
    let before_edges = store.edges()?.len();
    let timestamp = now_rfc3339()?;
    let mut sources = Vec::new();

    ingest_engagement_root(engagement, &store, &timestamp)?;

    let summary_path = engagement.recon_dir().join("summary.json");
    if summary_path.exists() {
        ingest_recon_summary(engagement, &store, &summary_path, &timestamp)?;
        sources.push(display_path(&summary_path));
    }

    for endpoints_path in crawl_endpoint_files(&engagement.crawl_dir())? {
        ingest_crawl_endpoints(engagement, &store, &endpoints_path, &timestamp)?;
        sources.push(display_path(&endpoints_path));
    }

    let probe_path = engagement.recon_dir().join("probe-report.json");
    if probe_path.exists() {
        ingest_probe_report(engagement, &store, &probe_path, &timestamp)?;
        sources.push(display_path(&probe_path));
    }

    for finding_path in finding_files(&engagement.findings_dir())? {
        ingest_finding(engagement, &store, &finding_path, &timestamp)?;
        sources.push(display_path(&finding_path));
    }

    let after_nodes = store.nodes()?.len();
    let after_edges = store.edges()?.len();
    Ok(GraphIngestReport {
        engagement: engagement.meta.name.clone(),
        graph_dir: display_path(store.graph_dir()),
        nodes_before: before_nodes,
        nodes_after: after_nodes,
        edges_before: before_edges,
        edges_after: after_edges,
        sources,
    })
}

// Ingest the engagement target as a root host node
fn ingest_engagement_root(
    engagement: &Engagement,
    store: &FileGraphStore,
    timestamp: &str,
) -> Result<(), SecurityGraphError> {
    let host =
        normalize_host(&engagement.meta.target).unwrap_or_else(|| engagement.meta.target.clone());
    let node = SecurityNode::new(NodeKind::Host, &host, &host, timestamp)
        .property("engagement", json!(engagement.meta.name))
        .property("role", json!("target"))
        .evidence(EvidenceRef::new(
            format!("evidence://{}/engagement", engagement.meta.name),
            Some(&engagement.root.join("engagement.json")),
        ));
    store.upsert_node(node)?;
    Ok(())
}

// Ingest recon/summary.json host and technology records
fn ingest_recon_summary(
    engagement: &Engagement,
    store: &FileGraphStore,
    path: &Path,
    timestamp: &str,
) -> Result<(), SecurityGraphError> {
    let value = read_json(path)?;
    let evidence = EvidenceRef::new(
        format!("evidence://{}/recon/summary", engagement.meta.name),
        Some(path),
    );
    let root_host =
        normalize_host(&engagement.meta.target).unwrap_or_else(|| engagement.meta.target.clone());
    let root_id = node_id(NodeKind::Host, &root_host);
    let Some(hosts) = value.get("hosts").and_then(Value::as_array) else {
        return Ok(());
    };

    for host in hosts {
        let Some(hostname) = host.get("hostname").and_then(Value::as_str) else {
            continue;
        };
        let normalized = normalize_host(hostname).unwrap_or_else(|| hostname.to_string());
        let host_id = node_id(NodeKind::Host, &normalized);
        let mut node = SecurityNode::new(NodeKind::Host, &normalized, &normalized, timestamp)
            .property("source", clone_or_null(host.get("source")))
            .property("ips", clone_or_empty_array(host.get("ips")))
            .property("services", clone_or_empty_array(host.get("services")))
            .property("open_ports", clone_or_empty_array(host.get("open_ports")))
            .property(
                "http_accessible",
                json!(
                    host.get("http_accessible")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                ),
            )
            .evidence(evidence.clone());
        if let Some(generated_at) = value.get("generated_at").and_then(Value::as_str) {
            node.properties
                .insert("source_generated_at".into(), json!(generated_at));
        }
        store.upsert_node(node)?;

        if root_id != host_id {
            store.upsert_edge(
                SecurityEdge::new(
                    EdgeKind::RelatedTo,
                    &root_id,
                    &host_id,
                    "recon_host",
                    timestamp,
                )
                .label("recon host")
                .evidence(evidence.clone()),
            )?;
        }

        if let Some(fingerprint) = host.get("fingerprint").and_then(Value::as_object) {
            for field in ["server", "framework", "cdn", "cms", "cloud", "powered_by"] {
                if let Some(value) = fingerprint.get(field).and_then(Value::as_str)
                    && !value.trim().is_empty()
                {
                    let tech_key = format!("{field}:{}", value.trim().to_lowercase());
                    let tech_id = node_id(NodeKind::Technology, &tech_key);
                    store.upsert_node(
                        SecurityNode::new(NodeKind::Technology, &tech_key, value, timestamp)
                            .property("category", json!(field))
                            .evidence(evidence.clone()),
                    )?;
                    store.upsert_edge(
                        SecurityEdge::new(
                            EdgeKind::RelatedTo,
                            &host_id,
                            &tech_id,
                            field,
                            timestamp,
                        )
                        .label(format!("technology:{field}"))
                        .evidence(evidence.clone()),
                    )?;
                }
            }
        }
    }
    Ok(())
}

// Ingest crawl/<host>/endpoints.json rows
fn ingest_crawl_endpoints(
    engagement: &Engagement,
    store: &FileGraphStore,
    path: &Path,
    timestamp: &str,
) -> Result<(), SecurityGraphError> {
    let value = read_json(path)?;
    let evidence = EvidenceRef::new(
        format!("evidence://{}/crawl/endpoints", engagement.meta.name),
        Some(path),
    );
    let host = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .and_then(normalize_host)
        .unwrap_or_else(|| engagement.meta.target.clone());
    let host_id = node_id(NodeKind::Host, &host);
    store.upsert_node(
        SecurityNode::new(NodeKind::Host, &host, &host, timestamp).evidence(evidence.clone()),
    )?;

    let Some(endpoints) = value.as_array() else {
        return Ok(());
    };
    for endpoint in endpoints {
        let Some(raw_path) = endpoint.get("path").and_then(Value::as_str) else {
            continue;
        };
        let source_url = endpoint
            .get("source_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let method = endpoint
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_uppercase();
        let absolute_url = endpoint_url(&host, raw_path, source_url);
        let url_id = node_id(NodeKind::Url, &absolute_url);
        store.upsert_node(
            SecurityNode::new(NodeKind::Url, &absolute_url, &absolute_url, timestamp)
                .property("method", json!(method))
                .property("path", json!(raw_path))
                .property("source", clone_or_null(endpoint.get("source")))
                .property("source_url", json!(source_url))
                .property("body_format", clone_or_null(endpoint.get("body_format")))
                .property(
                    "graphql",
                    json!(
                        endpoint
                            .get("graphql")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    ),
                )
                .evidence(evidence.clone()),
        )?;
        store.upsert_edge(
            SecurityEdge::new(EdgeKind::Calls, &host_id, &url_id, &method, timestamp)
                .property("method", json!(method))
                .evidence(evidence.clone()),
        )?;

        if let Some(source) = normalize_url(source_url) {
            let source_id = node_id(NodeKind::Url, &source);
            store.upsert_node(
                SecurityNode::new(NodeKind::Url, &source, &source, timestamp)
                    .property("source_role", json!("crawl_source"))
                    .evidence(evidence.clone()),
            )?;
            store.upsert_edge(
                SecurityEdge::new(
                    EdgeKind::References,
                    &source_id,
                    &url_id,
                    "crawl_source",
                    timestamp,
                )
                .evidence(evidence.clone()),
            )?;
        }

        if let Some(params) = endpoint.get("params").and_then(Value::as_array) {
            for param in params.iter().filter_map(Value::as_str) {
                let param_key = format!("{absolute_url}#{param}");
                let param_id = node_id(NodeKind::Parameter, &param_key);
                store.upsert_node(
                    SecurityNode::new(NodeKind::Parameter, &param_key, param, timestamp)
                        .property("url", json!(absolute_url))
                        .evidence(evidence.clone()),
                )?;
                store.upsert_edge(
                    SecurityEdge::new(
                        EdgeKind::References,
                        &url_id,
                        &param_id,
                        "parameter",
                        timestamp,
                    )
                    .evidence(evidence.clone()),
                )?;
            }
        }

        if endpoint
            .get("graphql")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let api_key = format!("graphql:{absolute_url}");
            let api_id = node_id(NodeKind::Api, &api_key);
            store.upsert_node(
                SecurityNode::new(NodeKind::Api, &api_key, "GraphQL endpoint", timestamp)
                    .property("url", json!(absolute_url))
                    .property("api_type", json!("graphql"))
                    .evidence(evidence.clone()),
            )?;
            store.upsert_edge(
                SecurityEdge::new(EdgeKind::References, &url_id, &api_id, "graphql", timestamp)
                    .evidence(evidence.clone()),
            )?;
        }
    }
    Ok(())
}

// Ingest recon/probe-report.json issue records
fn ingest_probe_report(
    engagement: &Engagement,
    store: &FileGraphStore,
    path: &Path,
    timestamp: &str,
) -> Result<(), SecurityGraphError> {
    let value = read_json(path)?;
    let evidence = EvidenceRef::new(
        format!("evidence://{}/recon/probe-report", engagement.meta.name),
        Some(path),
    );
    let Some(issues) = value.get("issues").and_then(Value::as_array) else {
        return Ok(());
    };
    for issue in issues {
        let Some(host_raw) = issue.get("host").and_then(Value::as_str) else {
            continue;
        };
        let host = normalize_host(host_raw).unwrap_or_else(|| host_raw.to_string());
        let title = issue
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("Probe issue");
        let check = issue
            .get("check")
            .and_then(Value::as_str)
            .unwrap_or("probe");
        let finding_key = format!("probe:{host}:{check}:{title}");
        let host_id = node_id(NodeKind::Host, &host);
        let finding_id = node_id(NodeKind::Finding, &finding_key);
        store.upsert_node(
            SecurityNode::new(NodeKind::Host, &host, &host, timestamp).evidence(evidence.clone()),
        )?;
        store.upsert_node(
            SecurityNode::new(NodeKind::Finding, &finding_key, title, timestamp)
                .property("source", json!("mg-probe"))
                .property("check", json!(check))
                .property("severity", clone_or_null(issue.get("severity")))
                .property("detail", clone_or_null(issue.get("detail")))
                .property(
                    "evidence_sha256",
                    json!(
                        issue
                            .get("evidence")
                            .and_then(Value::as_str)
                            .map(sha256_hex)
                    ),
                )
                .evidence(evidence.clone()),
        )?;
        store.upsert_edge(
            SecurityEdge::new(
                EdgeKind::VulnerableTo,
                &host_id,
                &finding_id,
                check,
                timestamp,
            )
            .evidence(evidence.clone()),
        )?;
    }
    Ok(())
}

// Ingest finding frontmatter from findings/*.md
fn ingest_finding(
    engagement: &Engagement,
    store: &FileGraphStore,
    path: &Path,
    timestamp: &str,
) -> Result<(), SecurityGraphError> {
    let raw = fs::read_to_string(path)?;
    let Some(frontmatter) = parse_frontmatter(&raw) else {
        return Ok(());
    };
    let finding_key = frontmatter.get("id").cloned().unwrap_or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("finding")
            .into()
    });
    let title = frontmatter
        .get("title")
        .cloned()
        .unwrap_or_else(|| finding_key.clone());
    let evidence = EvidenceRef::new(
        format!(
            "evidence://{}/finding/{}",
            engagement.meta.name, finding_key
        ),
        Some(path),
    );
    let finding_id = node_id(NodeKind::Finding, &finding_key);
    let mut node = SecurityNode::new(NodeKind::Finding, &finding_key, title, timestamp)
        .property("source", json!("finding"))
        .evidence(evidence.clone());
    for key in ["severity", "status", "target", "created"] {
        if let Some(value) = frontmatter.get(key) {
            node.properties.insert(key.into(), json!(value));
        }
    }
    store.upsert_node(node)?;

    if let Some(target) = frontmatter.get("target") {
        let (target_kind, target_key, target_label) = target_node_parts(target);
        let target_id = node_id(target_kind, &target_key);
        store.upsert_node(
            SecurityNode::new(target_kind, &target_key, target_label, timestamp)
                .evidence(evidence.clone()),
        )?;
        store.upsert_edge(
            SecurityEdge::new(
                EdgeKind::VulnerableTo,
                &target_id,
                &finding_id,
                "finding_frontmatter",
                timestamp,
            )
            .evidence(evidence),
        )?;
    }
    Ok(())
}

// Read a JSON file into a serde_json value
fn read_json(path: &Path) -> Result<Value, SecurityGraphError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

// Load nodes from JSONL into a sorted map
fn load_node_map(path: &Path) -> Result<BTreeMap<String, SecurityNode>, SecurityGraphError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path)?;
    let mut nodes = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let node: SecurityNode = serde_json::from_str(line)?;
        nodes.insert(node.id.clone(), node);
    }
    Ok(nodes)
}

// Load edges from JSONL into a sorted map
fn load_edge_map(path: &Path) -> Result<BTreeMap<String, SecurityEdge>, SecurityGraphError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path)?;
    let mut edges = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let edge: SecurityEdge = serde_json::from_str(line)?;
        edges.insert(edge.id.clone(), edge);
    }
    Ok(edges)
}

// Write sorted JSONL records
fn write_jsonl<'a, T, I>(path: &Path, records: I) -> Result<(), SecurityGraphError>
where
    T: Serialize + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut out = String::new();
    for record in records {
        out.push_str(&serde_json::to_string(record)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

// Merge a node into an existing node record
fn merge_node(existing: &mut SecurityNode, incoming: &SecurityNode) {
    existing.label = merge_label(&existing.label, &incoming.label);
    existing.first_seen = min_seen(&existing.first_seen, &incoming.first_seen);
    existing.last_seen = max_seen(&existing.last_seen, &incoming.last_seen);
    for (key, value) in &incoming.properties {
        existing.properties.insert(key.clone(), value.clone());
    }
    merge_evidence(&mut existing.evidence_refs, &incoming.evidence_refs);
}

// Merge an edge into an existing edge record
fn merge_edge(existing: &mut SecurityEdge, incoming: &SecurityEdge) {
    if existing.label.is_none() {
        existing.label = incoming.label.clone();
    }
    existing.first_seen = min_seen(&existing.first_seen, &incoming.first_seen);
    existing.last_seen = max_seen(&existing.last_seen, &incoming.last_seen);
    for (key, value) in &incoming.properties {
        existing.properties.insert(key.clone(), value.clone());
    }
    merge_evidence(&mut existing.evidence_refs, &incoming.evidence_refs);
}

// Prefer a non-empty incoming label when the existing one is empty
fn merge_label(existing: &str, incoming: &str) -> String {
    if existing.is_empty() {
        incoming.to_string()
    } else {
        existing.to_string()
    }
}

// Deduplicate evidence refs by URI and source path
fn merge_evidence(existing: &mut Vec<EvidenceRef>, incoming: &[EvidenceRef]) {
    let mut seen: BTreeSet<(String, Option<String>)> = existing
        .iter()
        .map(|item| (item.uri.clone(), item.source_path.clone()))
        .collect();
    for item in incoming {
        let key = (item.uri.clone(), item.source_path.clone());
        if seen.insert(key) {
            existing.push(item.clone());
        }
    }
}

// Pick the earliest non-empty timestamp
fn min_seen(left: &str, right: &str) -> String {
    if left.is_empty() || (!right.is_empty() && right < left) {
        right.to_string()
    } else {
        left.to_string()
    }
}

// Pick the latest non-empty timestamp
fn max_seen(left: &str, right: &str) -> String {
    if right > left {
        right.to_string()
    } else {
        left.to_string()
    }
}

// Return all crawl endpoint inventory files
fn crawl_endpoint_files(crawl_dir: &Path) -> Result<Vec<PathBuf>, SecurityGraphError> {
    let mut paths = Vec::new();
    if !crawl_dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(crawl_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let path = entry.path().join("endpoints.json");
            if path.exists() {
                paths.push(path);
            }
        }
    }
    paths.sort();
    Ok(paths)
}

// Return finding markdown files, excluding generated reports/disclosure drafts
fn finding_files(findings_dir: &Path) -> Result<Vec<PathBuf>, SecurityGraphError> {
    let mut paths = Vec::new();
    if !findings_dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(findings_dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".md") || name.ends_with("-report.md") || name.ends_with("-cve.md") {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

// Extract simple YAML-ish frontmatter fields from a finding file
fn parse_frontmatter(raw: &str) -> Option<BTreeMap<String, String>> {
    let mut lines = raw.lines();
    if lines.next()? != "---" {
        return None;
    }
    let mut map = BTreeMap::new();
    for line in lines {
        if line == "---" {
            return Some(map);
        }
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    None
}

// Decide whether a finding target should be a URL or host node
fn target_node_parts(target: &str) -> (NodeKind, String, String) {
    if let Some(url) = normalize_url(target) {
        (NodeKind::Url, url.clone(), url)
    } else {
        let host = normalize_host(target).unwrap_or_else(|| target.to_string());
        (NodeKind::Host, host.clone(), host)
    }
}

// Build an absolute endpoint URL from host, endpoint path, and source URL
fn endpoint_url(host: &str, raw_path: &str, source_url: &str) -> String {
    if let Some(url) = normalize_url(raw_path) {
        return url;
    }
    let scheme = Url::parse(source_url)
        .ok()
        .map(|url| url.scheme().to_string())
        .unwrap_or_else(|| "https".into());
    let path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    normalize_url(&format!("{scheme}://{host}{path}"))
        .unwrap_or_else(|| format!("{scheme}://{host}{path}"))
}

// Normalize a URL for graph keys
fn normalize_url(raw: &str) -> Option<String> {
    let mut url = Url::parse(raw).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_lowercase();
    url.set_host(Some(&host)).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

// Normalize a URL or host into a lower-case host
fn normalize_host(raw: &str) -> Option<String> {
    if let Ok(url) = Url::parse(raw) {
        return url
            .host_str()
            .map(|host| host.trim_end_matches('.').to_lowercase());
    }
    let host = raw
        .trim()
        .trim_start_matches("//")
        .split('/')
        .next()
        .unwrap_or(raw)
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(raw)
        .trim()
        .trim_end_matches('.')
        .to_lowercase();
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        None
    } else {
        Some(host)
    }
}

// Clone a JSON value or return null
fn clone_or_null(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

// Clone a JSON array value or return an empty array
fn clone_or_empty_array(value: Option<&Value>) -> Value {
    value
        .filter(|value| value.is_array())
        .cloned()
        .unwrap_or_else(|| json!([]))
}

// Return a path display string
fn display_path(path: &Path) -> String {
    path.display().to_string()
}

// Return the current UTC time formatted as RFC3339
fn now_rfc3339() -> Result<String, SecurityGraphError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

// Canonicalize a key before hashing
fn canonical_key(key: &str) -> String {
    key.trim().to_lowercase()
}

// Hash arbitrary data as a short graph ID component
fn hash_hex(data: impl AsRef<str>) -> String {
    sha256_hex(data)[..16].to_string()
}

// Hash arbitrary data as a full SHA-256 hex string
fn sha256_hex(data: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

// Build a prefixed hash ID
fn hash_id(prefix: &str, key: &str) -> String {
    format!("{prefix}:{}", hash_hex(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::EngagementMeta;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Create a unique temp directory for graph tests
    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("security-graph-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    // Create a test engagement
    fn test_engagement() -> Engagement {
        let parent = tmp_parent();
        Engagement::init(
            &parent,
            EngagementMeta {
                name: "acme".into(),
                target: "example.com".into(),
                created_at: String::new(),
                platform: None,
                url: None,
                tags: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn node_ids_are_deterministic() {
        assert_eq!(
            node_id(NodeKind::Host, "API.Example.com"),
            node_id(NodeKind::Host, "api.example.com")
        );
        assert_ne!(
            node_id(NodeKind::Host, "api.example.com"),
            node_id(NodeKind::Url, "api.example.com")
        );
    }

    #[test]
    fn file_store_upserts_and_deduplicates() {
        let dir = tmp_parent().join("graph");
        let store = FileGraphStore::new(&dir);
        let first = SecurityNode::new(
            NodeKind::Host,
            "api.example.com",
            "api.example.com",
            "2026-01-01T00:00:00Z",
        )
        .property("source", json!("recon"));
        let second = SecurityNode::new(
            NodeKind::Host,
            "api.example.com",
            "api.example.com",
            "2026-01-02T00:00:00Z",
        )
        .property("http_accessible", json!(true));
        store.upsert_node(first).unwrap();
        store.upsert_node(second).unwrap();

        let nodes = store.nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].properties["source"], "recon");
        assert_eq!(nodes[0].properties["http_accessible"], true);
        assert!(store.nodes_path().exists());
    }

    #[test]
    fn ingest_existing_artifacts_builds_graph() {
        let eng = test_engagement();
        fs::write(
            eng.recon_dir().join("summary.json"),
            r#"{
              "engagement":"acme",
              "target":"example.com",
              "generated_at":"2026-05-15T00:00:00Z",
              "host_count":1,
              "hosts":[{
                "hostname":"api.example.com",
                "ips":["127.0.0.1"],
                "source":"ct_log",
                "http_accessible":true,
                "fingerprint":{"server":"nginx","framework":"express","cdn":null,"cms":null,"cloud":null,"powered_by":"node"},
                "open_ports":[80,443],
                "services":["http","https"]
              }]
            }"#,
        )
        .unwrap();
        let crawl_host = eng.crawl_dir().join("api.example.com");
        fs::create_dir_all(&crawl_host).unwrap();
        fs::write(
            crawl_host.join("endpoints.json"),
            r#"[{
              "path":"/api/users?id=1",
              "source_url":"https://api.example.com/app.js",
              "method":"GET",
              "source":"js_static",
              "params":["id"],
              "graphql":false
            }]"#,
        )
        .unwrap();
        fs::write(
            eng.recon_dir().join("probe-report.json"),
            r#"{
              "engagement":"acme",
              "generated_at":"2026-05-15T00:00:00Z",
              "issue_count":1,
              "issues":[{
                "check":"cors",
                "host":"api.example.com",
                "severity":"high",
                "title":"CORS reflected origin",
                "detail":"origin reflected",
                "evidence":"Access-Control-Allow-Origin: evil"
              }]
            }"#,
        )
        .unwrap();
        fs::write(
            eng.findings_dir().join("2026-05-15-001-test.md"),
            "---\nid: 2026-05-15-001\ntitle: Test finding\nseverity: high\nstatus: confirmed\ntarget: https://api.example.com/api/users?id=2\ncreated: 2026-05-15T00:00:00Z\n---\n\nbody",
        )
        .unwrap();

        let report = ingest_engagement(&eng).unwrap();
        assert!(report.nodes_added() >= 6);
        assert!(report.edges_added() >= 4);

        let store = FileGraphStore::for_engagement(&eng);
        let summary = store.summary(10).unwrap();
        assert!(summary.node_kinds["host"] >= 2);
        assert!(summary.node_kinds["finding"] >= 2);
        assert!(summary.edge_kinds["vulnerable_to"] >= 2);
    }

    #[test]
    fn neighbors_are_bounded() {
        let dir = tmp_parent().join("graph");
        let store = FileGraphStore::new(&dir);
        let timestamp = "2026-01-01T00:00:00Z";
        let host = SecurityNode::new(
            NodeKind::Host,
            "api.example.com",
            "api.example.com",
            timestamp,
        );
        let host_id = host.id.clone();
        store.upsert_node(host).unwrap();
        for idx in 0..3 {
            let url = SecurityNode::new(
                NodeKind::Url,
                format!("https://api.example.com/{idx}"),
                format!("https://api.example.com/{idx}"),
                timestamp,
            );
            let url_id = url.id.clone();
            store.upsert_node(url).unwrap();
            store
                .upsert_edge(SecurityEdge::new(
                    EdgeKind::Calls,
                    &host_id,
                    &url_id,
                    idx.to_string(),
                    timestamp,
                ))
                .unwrap();
        }

        let neighbors = store.neighbors(&host_id, 2).unwrap();
        assert_eq!(neighbors.neighbors.len(), 2);
        assert!(neighbors.truncated);
    }
}
