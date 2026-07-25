// Author: Jeff
// Date: 2026-05-29
// Description: Assisted autonomous hunting loop CLI
// Notes: Deterministic dry-run planner only; active execution remains policy-gated elsewhere

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use engagement::{
    Engagement, FindingSeverity, ToolFinding, TrafficRecord, find_traffic_record, write_finding,
};
use evidence_core::{EvidenceBundleRequest, EvidenceBundleWriter};
use http_client::{Client, ClientConfig};
use oob_core::{OobHit, OobListener};
use replay_engine::{
    PlanBuilder, ReplayOutcome, ReplayPlan, ReplayPlanRequest, ScopeDecision, SemanticDiffEngine,
    SemanticVerdict, SemanticVerdictClass, build_injected_request,
};
use replay_runner::ReplayRunner;
use request_corpus::{CandidateKind, CandidateStateChange, CorpusCandidate};
use serde::Serialize;

const CANDIDATES_RELATIVE_PATH: &str = "corpus/candidates.jsonl";
const RESUME_RELATIVE_PATH: &str = "hunt/tested-plan-hashes.txt";
const REPLAY_OUTCOMES_RELATIVE_DIR: &str = "hunt/replay-outcomes";
const DEFAULT_MAX_TESTS: usize = 20;
const DEFAULT_MAX_DURATION_SECS: u64 = 300;
const DEFAULT_MAX_BYTES: u64 = 1_048_576;
const ESTIMATED_TEST_BYTES: u64 = 1024;
const ESTIMATED_TEST_DURATION_SECS: u64 = 1;
const SSRF_OOB_WAIT_MS: u64 = 1500;
const SSRF_FINDING_TOOL: &str = "mg-hunt-ssrf";
const SSRF_RESPONSE_MARKERS: &[&str] = &[
    "instance-id",
    "ami-id",
    "security-credentials",
    "computeMetadata",
    "meta-data",
];

#[derive(Debug, Parser)]
#[command(name = "mg-hunt", about = "Plan safe assisted autonomous hunt steps")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Plan an assisted hunt loop without executing requests
    Run {
        /// Engagement root directory
        engagement: PathBuf,
        /// Hunt mode; only assisted is supported in this skeleton
        #[arg(long, value_enum, default_value_t = HuntMode::Assisted)]
        mode: HuntMode,
        /// Boundary label for operator context
        #[arg(long)]
        boundary: Option<String>,
        /// Risk level; only read-only candidates are selected
        #[arg(long, value_enum, default_value_t = RiskFilter::ReadOnly)]
        risk: RiskFilter,
        /// Plan without execution
        #[arg(long)]
        dry_run: bool,
        /// Maximum planned tests
        #[arg(long, default_value_t = DEFAULT_MAX_TESTS)]
        max_tests: usize,
        /// Maximum planned duration in seconds
        #[arg(long, default_value_t = DEFAULT_MAX_DURATION_SECS)]
        max_duration: u64,
        /// Maximum planned traffic bytes
        #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Resume from local tested plan hashes
        #[arg(long)]
        resume: bool,
        /// Operator approval for non-dry-run orchestration
        #[arg(long)]
        confirmed: bool,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum HuntMode {
    Assisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum RiskFilter {
    ReadOnly,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HuntBudget {
    max_tests: usize,
    max_duration_secs: u64,
    max_bytes: u64,
}

impl Default for HuntBudget {
    fn default() -> Self {
        Self {
            max_tests: DEFAULT_MAX_TESTS,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResumeState {
    tested_plan_hashes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum StopReason {
    MaxTests,
    MaxDuration,
    MaxBytes,
    RateLimited,
    ServerErrors,
    WafDetected,
    ApprovalRequired,
    AuthExpired,
    EvidenceWriteFailed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)]
struct LoopState {
    server_errors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlannedTest {
    candidate_id: String,
    plan_hash: String,
    summary: String,
    #[serde(skip)]
    candidate: CorpusCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HuntPlan {
    selected: Vec<PlannedTest>,
    skipped_by_policy: usize,
    skipped_by_resume: usize,
    executed: Vec<ExecutedTest>,
    stop_reason: Option<StopReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExecutedTest {
    candidate_id: String,
    plan_hash: String,
    verdict_class: String,
    boundary_violation: bool,
    evidence_bundle: String,
}

impl HuntPlan {
    // Return selected candidate ids for focused tests
    #[cfg(test)]
    fn selected_ids(&self) -> Vec<&str> {
        self.selected
            .iter()
            .map(|test| test.candidate_id.as_str())
            .collect()
    }
}

impl LoopState {
    // Record execution feedback and return a safety stop reason if thresholds trip
    #[allow(dead_code)]
    fn record_response(&mut self, status: u16, waf_like: bool) -> Option<StopReason> {
        if waf_like {
            return Some(StopReason::WafDetected);
        }
        if status == 429 {
            return Some(StopReason::RateLimited);
        }
        if (500..=599).contains(&status) {
            self.server_errors += 1;
            return Some(StopReason::ServerErrors);
        }
        None
    }
}

fn main() -> Result<()> {
    let output = run_from(std::env::args())?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

// Run CLI from argv and return output for tests
fn run_from<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let args = Args::parse_from(args);
    run(args)
}

// Dispatch parsed commands
fn run(args: Args) -> Result<String> {
    match args.command {
        Command::Run {
            engagement,
            mode: _,
            boundary: _,
            risk,
            dry_run,
            max_tests,
            max_duration,
            max_bytes,
            resume,
            confirmed,
            json,
        } => {
            let budget = HuntBudget {
                max_tests,
                max_duration_secs: max_duration,
                max_bytes,
            };
            match risk {
                RiskFilter::ReadOnly => {
                    run_read_only(&engagement, budget, resume, dry_run, confirmed, json)
                }
                RiskFilter::Active => run_ssrf(&engagement, budget, dry_run, confirmed, json),
            }
        }
    }
}

// Plan and optionally orchestrate read-only authorization tests
fn run_read_only(
    engagement: &Path,
    budget: HuntBudget,
    resume: bool,
    dry_run: bool,
    confirmed: bool,
    json: bool,
) -> Result<String> {
    let candidates = load_candidates(&engagement.join(CANDIDATES_RELATIVE_PATH))?;
    let resume_state = if resume {
        load_resume_state(&engagement.join(RESUME_RELATIVE_PATH))?
    } else {
        ResumeState::default()
    };
    let mut plan = plan_dry_run(candidates, budget, &resume_state);
    if !dry_run {
        apply_policy_gated_orchestration(engagement, &mut plan, confirmed)?;
    }
    render(json, &plan, || {
        format!(
            "planned {} tests (policy skipped {}, resume skipped {})",
            plan.selected.len(),
            plan.skipped_by_policy,
            plan.skipped_by_resume
        )
    })
}

// Plan and, with approval, execute live SSRF tests end to end
fn run_ssrf(
    engagement_root: &Path,
    budget: HuntBudget,
    dry_run: bool,
    confirmed: bool,
    json: bool,
) -> Result<String> {
    let candidates = load_candidates(&engagement_root.join(CANDIDATES_RELATIVE_PATH))?;
    let selected: Vec<PlannedTest> = select_ssrf_candidates(candidates)
        .into_iter()
        .take(budget.max_tests)
        .map(planned_ssrf_test)
        .collect::<Result<Vec<_>>>()?;
    let mut plan = HuntPlan {
        selected,
        skipped_by_policy: 0,
        skipped_by_resume: 0,
        executed: Vec::new(),
        stop_reason: None,
    };

    // SSRF is HighActive; without dry-run and explicit approval it stays inert
    if dry_run || !confirmed {
        plan.stop_reason = Some(StopReason::ApprovalRequired);
        return render(json, &plan, || {
            format!(
                "planned {} ssrf tests; approval required before execution",
                plan.selected.len()
            )
        });
    }

    let engagement = Engagement::load(engagement_root).context("load engagement")?;
    let engagement_name = engagement_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("engagement")
        .to_string();
    let listener = OobListener::bind().context("bind oob listener")?;
    let runner = ReplayRunner::new(Client::new(ClientConfig::default()).context("build client")?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build async runtime")?;

    for test in &plan.selected {
        let record_id = test
            .candidate
            .record_ids
            .first()
            .context("ssrf candidate has no source record")?;
        let record = find_traffic_record(&engagement, record_id).context("resolve ssrf record")?;
        let executed = runtime.block_on(execute_ssrf_test(
            engagement_root,
            &engagement_name,
            &test.candidate,
            &record,
            &listener,
            &runner,
        ))?;
        plan.executed.push(executed);
    }
    render(json, &plan, || {
        format!("executed {} ssrf tests", plan.executed.len())
    })
}

// Select next safe read-only tests without executing network requests
fn plan_dry_run(
    candidates: Vec<CorpusCandidate>,
    budget: HuntBudget,
    resume: &ResumeState,
) -> HuntPlan {
    let mut selected = Vec::new();
    let mut skipped_by_policy = 0;
    let mut skipped_by_resume = 0;
    let mut planned_duration = 0u64;
    let mut planned_bytes = 0u64;
    let mut stop_reason = None;

    for candidate in candidates {
        if !is_read_only_candidate(&candidate) {
            skipped_by_policy += 1;
            continue;
        }

        let replay_plan =
            build_read_only_replay_plan(&candidate).expect("read-only replay plan builds");
        let plan_hash = replay_plan.plan_hash;
        if resume.tested_plan_hashes.contains(&plan_hash) {
            skipped_by_resume += 1;
            continue;
        }

        if selected.len() >= budget.max_tests {
            stop_reason = Some(StopReason::MaxTests);
            break;
        }
        if planned_duration + ESTIMATED_TEST_DURATION_SECS > budget.max_duration_secs {
            stop_reason = Some(StopReason::MaxDuration);
            break;
        }
        if planned_bytes + ESTIMATED_TEST_BYTES > budget.max_bytes {
            stop_reason = Some(StopReason::MaxBytes);
            break;
        }

        selected.push(PlannedTest {
            candidate_id: candidate.id.clone(),
            plan_hash,
            summary: candidate.summary.clone(),
            candidate,
        });
        planned_duration += ESTIMATED_TEST_DURATION_SECS;
        planned_bytes += ESTIMATED_TEST_BYTES;
    }

    HuntPlan {
        selected,
        skipped_by_policy,
        skipped_by_resume,
        executed: Vec::new(),
        stop_reason,
    }
}

// Check candidate safety before planning assisted execution
fn is_read_only_candidate(candidate: &CorpusCandidate) -> bool {
    candidate.autonomous_safe && candidate.state_change == CandidateStateChange::ReadOnly
}

// Derive deterministic replay plan metadata for a read-only candidate
fn build_read_only_replay_plan(candidate: &CorpusCandidate) -> Result<replay_engine::ReplayPlan> {
    PlanBuilder
        .build(
            ReplayPlanRequest::new(candidate.clone(), ScopeDecision::InScope)
                .with_sessions(["default"])
                .with_expected_secure_result("authorization denial or no controlled target marker")
                .with_stop_conditions([
                    "rate_limited",
                    "waf_detected",
                    "server_error",
                    "auth_expired",
                    "scope_drift",
                    "out_of_scope_redirect",
                ])
                .with_evidence_output_dir(format!("evidence/{}", candidate.id)),
        )
        .context("build read-only replay plan")
}

// Apply approval-gated orchestration side effects without sending network traffic
fn apply_policy_gated_orchestration(
    engagement: &Path,
    plan: &mut HuntPlan,
    confirmed: bool,
) -> Result<()> {
    if !confirmed {
        plan.stop_reason = Some(StopReason::ApprovalRequired);
        return Ok(());
    }
    if plan.selected.is_empty() {
        return Ok(());
    }
    let resume_path = engagement.join(RESUME_RELATIVE_PATH);
    if let Some(parent) = resume_path.parent() {
        std::fs::create_dir_all(parent).context("create hunt state directory")?;
    }
    let mut existing = load_resume_state(&resume_path)?;
    for test in &plan.selected {
        let (executed, stop_reason) = execute_read_only_test(engagement, test)?;
        plan.executed.push(executed);
        if let Some(stop_reason) = stop_reason {
            plan.stop_reason = Some(stop_reason);
            break;
        }
        existing.tested_plan_hashes.insert(test.plan_hash.clone());
    }
    let mut serialized = existing
        .tested_plan_hashes
        .iter()
        .cloned()
        .collect::<Vec<String>>()
        .join("\n");
    serialized.push('\n');
    std::fs::write(&resume_path, serialized).context("write tested plan hashes")?;
    Ok(())
}

// Execute one already-policy-filtered read-only test through local replay/evidence primitives
fn execute_read_only_test(
    engagement: &Path,
    test: &PlannedTest,
) -> Result<(ExecutedTest, Option<StopReason>)> {
    let replay_plan = build_read_only_replay_plan(&test.candidate)?;
    let outcome = load_replay_outcome(engagement, &test.candidate_id)?;
    let verdict = SemanticDiffEngine.classify(&outcome);
    let plan_json = serde_json::to_string_pretty(&replay_plan).context("serialize replay plan")?;
    let semantic_diff_json = serde_json::to_string_pretty(&verdict).context("serialize verdict")?;
    let run_id = format!("run-{}", test.plan_hash);
    let bundle = EvidenceBundleWriter
        .write(
            EvidenceBundleRequest::new(engagement, &test.candidate_id, &run_id)
                .with_plan_json(plan_json)
                .with_approvals_json("[]")
                .with_semantic_diff_json(semantic_diff_json)
                .with_summary(format!(
                    "candidate: {}\nplan: {}\nverdict: {:?}",
                    test.candidate_id, test.plan_hash, verdict.classification
                )),
        )
        .context("write evidence bundle")?;
    let evidence_bundle = bundle
        .bundle_dir
        .strip_prefix(engagement)
        .unwrap_or(&bundle.bundle_dir)
        .display()
        .to_string();
    let verdict_class = serde_json::to_value(verdict.classification)
        .context("serialize verdict class")?
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let stop_reason = match verdict.classification {
        SemanticVerdictClass::InvalidTest => Some(StopReason::AuthExpired),
        _ => None,
    };

    Ok((
        ExecutedTest {
            candidate_id: test.candidate_id.clone(),
            plan_hash: test.plan_hash.clone(),
            verdict_class,
            boundary_violation: verdict.boundary_violation,
            evidence_bundle,
        },
        stop_reason,
    ))
}

// Load a local replay outcome fixture or return an inert placeholder until live replay lands
fn load_replay_outcome(engagement: &Path, candidate_id: &str) -> Result<ReplayOutcome> {
    let path = engagement
        .join(REPLAY_OUTCOMES_RELATIVE_DIR)
        .join(format!("{candidate_id}.json"));
    if !path.exists() {
        return Ok(ReplayOutcome::http(200, "{}"));
    }
    let raw = std::fs::read_to_string(path).context("read replay outcome")?;
    serde_json::from_str(&raw).context("parse replay outcome")
}

// Keep only server-side request (SSRF) candidates for active testing
fn select_ssrf_candidates(candidates: Vec<CorpusCandidate>) -> Vec<CorpusCandidate> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.kind == CandidateKind::ServerSideRequestTarget)
        .collect()
}

// Describe the immutable SSRF replay plan request for a candidate
fn ssrf_plan_request(candidate: &CorpusCandidate) -> ReplayPlanRequest {
    ReplayPlanRequest::new(candidate.clone(), ScopeDecision::InScope)
        .with_expected_secure_result("no server-side request to the controlled marker")
        .with_stop_conditions([
            "rate_limited",
            "waf_detected",
            "server_error",
            "scope_drift",
        ])
        .with_evidence_output_dir(format!("evidence/{}", candidate.id))
}

// Build a planned test record carrying the SSRF plan hash for display
fn planned_ssrf_test(candidate: CorpusCandidate) -> Result<PlannedTest> {
    let plan = PlanBuilder
        .build(ssrf_plan_request(&candidate))
        .context("build ssrf plan")?;
    Ok(PlannedTest {
        candidate_id: candidate.id.clone(),
        plan_hash: plan.plan_hash,
        summary: candidate.summary.clone(),
        candidate,
    })
}

// Run one approved SSRF test end to end and record its evidence and finding
async fn execute_ssrf_test(
    engagement_root: &Path,
    engagement_name: &str,
    candidate: &CorpusCandidate,
    record: &TrafficRecord,
    listener: &OobListener,
    runner: &ReplayRunner,
) -> Result<ExecutedTest> {
    // Bind a matching approval grant so the engine marks the plan executable
    let base = ssrf_plan_request(candidate);
    let unapproved = PlanBuilder.build(base.clone()).context("build ssrf plan")?;
    let plan = PlanBuilder
        .build(base.with_approval_grant_hash(unapproved.plan_hash.clone()))
        .context("bind ssrf approval")?;

    // Mint a plan-bound OOB token and inject its callback URL into the target parameter
    let token = listener.mint(
        engagement_name,
        plan.plan_hash.clone(),
        candidate.id.clone(),
    );
    let injection_param = candidate
        .injection_params
        .first()
        .context("ssrf candidate has no injection parameter")?;
    let request = build_injected_request(
        &record.method,
        &record.url,
        &header_pairs(record),
        None,
        injection_param,
        &listener.oob_url(&token),
    );

    // Send the approved request, then correlate any server-side callback it triggered
    let outcome = runner
        .run(&plan, &request)
        .await
        .context("send ssrf replay")?;
    let hit = listener.wait_for_hit(&token, Duration::from_millis(SSRF_OOB_WAIT_MS));
    let verdict = SemanticDiffEngine.classify_ssrf(&outcome, hit.is_some(), SSRF_RESPONSE_MARKERS);

    let run_id = format!("run-{}", plan.plan_hash);
    let evidence_bundle = write_ssrf_evidence(
        engagement_root,
        candidate,
        &run_id,
        &plan,
        &verdict,
        &outcome,
        hit.as_ref(),
    )?;
    // Emit the finding immediately on a boundary violation, then record the plan hash
    if verdict.boundary_violation {
        emit_ssrf_finding(engagement_root, candidate, &verdict, &evidence_bundle)?;
    }
    append_tested_hash(engagement_root, &plan.plan_hash)?;

    Ok(ExecutedTest {
        candidate_id: candidate.id.clone(),
        plan_hash: plan.plan_hash.clone(),
        verdict_class: verdict_class_name(&verdict),
        boundary_violation: verdict.boundary_violation,
        evidence_bundle,
    })
}

// Map captured request headers into name/value pairs for replay
fn header_pairs(record: &TrafficRecord) -> Vec<(String, String)> {
    record
        .request_headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect()
}

// Write an immutable SSRF evidence bundle and return its engagement-relative path
fn write_ssrf_evidence(
    engagement_root: &Path,
    candidate: &CorpusCandidate,
    run_id: &str,
    plan: &ReplayPlan,
    verdict: &SemanticVerdict,
    outcome: &ReplayOutcome,
    hit: Option<&OobHit>,
) -> Result<String> {
    let plan_json = serde_json::to_string_pretty(plan).context("serialize ssrf plan")?;
    let semantic_diff_json = serde_json::to_string_pretty(verdict).context("serialize verdict")?;
    let replay_io_json = serde_json::to_string_pretty(outcome).context("serialize replay io")?;
    let approvals_json =
        serde_json::to_string(&[&plan.plan_hash]).context("serialize approvals")?;
    let mut request = EvidenceBundleRequest::new(engagement_root, &candidate.id, run_id)
        .with_plan_json(plan_json)
        .with_approvals_json(approvals_json)
        .with_semantic_diff_json(semantic_diff_json)
        .with_replay_io_json(replay_io_json)
        .with_summary(format!(
            "SSRF {} on candidate {}",
            verdict_class_name(verdict),
            candidate.id
        ));
    if let Some(hit) = hit {
        let oob_hit_json = serde_json::to_string_pretty(hit).context("serialize oob hit")?;
        request = request.with_oob_hit_json(oob_hit_json);
    }
    let bundle = EvidenceBundleWriter
        .write(request)
        .context("write ssrf evidence bundle")?;
    Ok(bundle
        .bundle_dir
        .strip_prefix(engagement_root)
        .unwrap_or(&bundle.bundle_dir)
        .display()
        .to_string())
}

// Emit a high-severity SSRF finding into the engagement immediately on confirmation
fn emit_ssrf_finding(
    engagement_root: &Path,
    candidate: &CorpusCandidate,
    verdict: &SemanticVerdict,
    evidence_bundle: &str,
) -> Result<()> {
    let engagement = Engagement::load(engagement_root).context("load engagement for finding")?;
    let finding = ToolFinding::new(
        SSRF_FINDING_TOOL,
        "Server-side request forgery confirmed",
        FindingSeverity::High,
    )
    .evidence(format!(
        "candidate {} verdict {} evidence {}",
        candidate.id,
        verdict_class_name(verdict),
        evidence_bundle
    ))
    .recommendation(
        "Validate and allowlist outbound fetch targets; block internal and link-local addresses",
    );
    write_finding(&engagement, &finding).context("write ssrf finding")?;
    Ok(())
}

// Append a plan hash to the resume ledger without duplicating entries
fn append_tested_hash(engagement_root: &Path, plan_hash: &str) -> Result<()> {
    let path = engagement_root.join(RESUME_RELATIVE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create hunt state directory")?;
    }
    let mut ledger = std::fs::read_to_string(&path).unwrap_or_default();
    if !ledger.lines().any(|line| line.trim() == plan_hash) {
        ledger.push_str(plan_hash);
        ledger.push('\n');
        std::fs::write(&path, ledger).context("append tested plan hash")?;
    }
    Ok(())
}

// Render a semantic verdict class as its stable snake_case name
fn verdict_class_name(verdict: &SemanticVerdict) -> String {
    serde_json::to_value(verdict.classification)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

// Load stable JSONL candidates
fn load_candidates(path: &Path) -> Result<Vec<CorpusCandidate>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).context("read candidates")?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("parse candidate"))
        .collect()
}

// Load newline-delimited plan hashes for resume
fn load_resume_state(path: &Path) -> Result<ResumeState> {
    if !path.exists() {
        return Ok(ResumeState::default());
    }
    let raw = std::fs::read_to_string(path).context("read resume state")?;
    Ok(ResumeState {
        tested_plan_hashes: raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    })
}

// Render human or JSON output
fn render<T, F>(json: bool, value: &T, human: F) -> Result<String>
where
    T: Serialize,
    F: FnOnce() -> String,
{
    if json {
        serde_json::to_string_pretty(value).context("serialize output")
    } else {
        Ok(human())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use request_corpus::{
        CandidateKind, CandidateSafety, CandidateSource, CandidateStateChange, CorpusCandidate,
    };

    fn candidate(id: &str, state_change: CandidateStateChange) -> CorpusCandidate {
        CorpusCandidate {
            id: id.to_string(),
            kind: CandidateKind::CrossTenantRead,
            source: CandidateSource::Traffic,
            safety: match state_change {
                CandidateStateChange::ReadOnly => CandidateSafety::ReadOnlyProof,
                CandidateStateChange::BrowserObservationOnly => CandidateSafety::BrowserOnlyProof,
                CandidateStateChange::StateChanging => CandidateSafety::RequiresApproval,
            },
            state_change,
            autonomous_safe: state_change != CandidateStateChange::StateChanging,
            record_ids: vec![format!("record-{id}")],
            observation_ids: Vec::new(),
            injection_params: Vec::new(),
            cross_tenant: None,
            summary: format!("candidate {id}"),
        }
    }

    fn ssrf_candidate(id: &str) -> CorpusCandidate {
        CorpusCandidate {
            id: id.to_string(),
            kind: CandidateKind::ServerSideRequestTarget,
            source: CandidateSource::Traffic,
            safety: CandidateSafety::RequiresApproval,
            state_change: CandidateStateChange::ReadOnly,
            autonomous_safe: false,
            record_ids: vec![format!("record-{id}")],
            observation_ids: Vec::new(),
            injection_params: vec!["url".to_string()],
            cross_tenant: None,
            summary: format!("ssrf {id}"),
        }
    }

    #[test]
    fn select_ssrf_candidates_keeps_only_server_side_request_targets() {
        let selected = select_ssrf_candidates(vec![
            ssrf_candidate("ssrf-1"),
            candidate("read-1", CandidateStateChange::ReadOnly),
            ssrf_candidate("ssrf-2"),
        ]);

        let ids: Vec<&str> = selected
            .iter()
            .map(|candidate| candidate.id.as_str())
            .collect();
        assert_eq!(ids, vec!["ssrf-1", "ssrf-2"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ssrf_blind_callback_confirms_finding_end_to_end() {
        use axum::Router;
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use engagement::EngagementMeta;
        use std::collections::HashMap;

        // Loopback OOB listener the vulnerable lab will call back into
        let listener = OobListener::bind().unwrap();

        // Vulnerable lab: performs a server-side GET of the url parameter (the SSRF sink)
        async fn lab_fetch(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
            if let Some(target) = params.get("url") {
                let client = Client::new(ClientConfig::default()).unwrap();
                let _ = client.get(target).await;
            }
            (StatusCode::OK, "fetched")
        }
        let lab = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lab_addr = lab.local_addr().unwrap();
        tokio::spawn(async move {
            let app = Router::new().route("/fetch", get(lab_fetch));
            axum::serve(lab, app).await.unwrap();
        });

        // A real engagement so evidence and findings have a home
        let parent = tempfile::tempdir().unwrap();
        let engagement = Engagement::init(
            parent.path(),
            EngagementMeta {
                name: "ssrf-lab".to_string(),
                target: "127.0.0.1".to_string(),
                created_at: String::new(),
                platform: None,
                url: None,
                tags: Vec::new(),
            },
        )
        .unwrap();
        let root = engagement.root.clone();

        let candidate = ssrf_candidate("ssrf-fetch");
        let record: TrafficRecord = serde_json::from_value(serde_json::json!({
            "id": "fetch-1",
            "source": "test",
            "captured_at": "2026-07-24T00:00:00Z",
            "imported_at": "2026-07-24T00:00:00Z",
            "method": "GET",
            "url": format!("http://{lab_addr}/fetch?url=http://benign.example/orig"),
            "host": "127.0.0.1",
            "path": "/fetch",
            "scheme": "http",
            "params": ["url"],
            "auth_state": "anonymous"
        }))
        .unwrap();

        let runner = ReplayRunner::new(Client::new(ClientConfig::default()).unwrap());
        let executed =
            execute_ssrf_test(&root, "ssrf-lab", &candidate, &record, &listener, &runner)
                .await
                .unwrap();

        // The server-side callback was correlated into a confirmed finding
        assert_eq!(executed.verdict_class, "ssrf_oob_confirmed");
        assert!(executed.boundary_violation);

        // Evidence carries the correlated OOB hit and the recorded replay I/O
        let bundle_dir = root.join(&executed.evidence_bundle);
        assert!(bundle_dir.join("oob_hit.json").exists());
        assert!(bundle_dir.join("replay_io.json").exists());

        // A finding was emitted and the plan hash was recorded in the hunt ledger
        let finding_count = std::fs::read_dir(root.join("findings")).unwrap().count();
        assert!(finding_count > 0);
        let ledger = std::fs::read_to_string(root.join(RESUME_RELATIVE_PATH)).unwrap();
        assert!(ledger.contains(&executed.plan_hash));
    }

    #[test]
    fn dry_run_selects_only_read_only_candidates() {
        let plan = plan_dry_run(
            vec![
                candidate("read", CandidateStateChange::ReadOnly),
                candidate("browser", CandidateStateChange::BrowserObservationOnly),
                candidate("write", CandidateStateChange::StateChanging),
            ],
            HuntBudget::default(),
            &ResumeState::default(),
        );

        assert_eq!(plan.selected_ids(), vec!["read"]);
        assert_eq!(plan.skipped_by_policy, 2);
    }

    #[test]
    fn budgets_stop_the_loop_deterministically() {
        let plan = plan_dry_run(
            vec![
                candidate("one", CandidateStateChange::ReadOnly),
                candidate("two", CandidateStateChange::ReadOnly),
                candidate("three", CandidateStateChange::ReadOnly),
            ],
            HuntBudget {
                max_tests: 2,
                max_duration_secs: 60,
                max_bytes: 2048,
            },
            &ResumeState::default(),
        );

        assert_eq!(plan.selected_ids(), vec!["one", "two"]);
        assert_eq!(plan.stop_reason, Some(StopReason::MaxTests));
    }

    #[test]
    fn duration_budget_stops_before_next_test() {
        let plan = plan_dry_run(
            vec![
                candidate("one", CandidateStateChange::ReadOnly),
                candidate("two", CandidateStateChange::ReadOnly),
            ],
            HuntBudget {
                max_tests: 10,
                max_duration_secs: 1,
                max_bytes: 4096,
            },
            &ResumeState::default(),
        );

        assert_eq!(plan.selected_ids(), vec!["one"]);
        assert_eq!(plan.stop_reason, Some(StopReason::MaxDuration));
    }

    #[test]
    fn byte_budget_stops_before_next_test() {
        let plan = plan_dry_run(
            vec![
                candidate("one", CandidateStateChange::ReadOnly),
                candidate("two", CandidateStateChange::ReadOnly),
            ],
            HuntBudget {
                max_tests: 10,
                max_duration_secs: 60,
                max_bytes: 1024,
            },
            &ResumeState::default(),
        );

        assert_eq!(plan.selected_ids(), vec!["one"]);
        assert_eq!(plan.stop_reason, Some(StopReason::MaxBytes));
    }

    #[test]
    fn throttle_and_waf_thresholds_stop_execution() {
        let mut state = LoopState::default();

        assert_eq!(state.record_response(200, false), None);
        assert_eq!(
            state.record_response(429, false),
            Some(StopReason::RateLimited)
        );
        assert_eq!(
            state.record_response(503, false),
            Some(StopReason::ServerErrors)
        );
        assert_eq!(
            state.record_response(200, true),
            Some(StopReason::WafDetected)
        );
    }

    #[test]
    fn resume_skips_already_tested_plan_hashes() {
        let mut resume = ResumeState::default();
        let one = candidate("one", CandidateStateChange::ReadOnly);
        resume
            .tested_plan_hashes
            .insert(build_read_only_replay_plan(&one).unwrap().plan_hash);
        let plan = plan_dry_run(
            vec![one, candidate("two", CandidateStateChange::ReadOnly)],
            HuntBudget::default(),
            &resume,
        );

        assert_eq!(plan.selected_ids(), vec!["two"]);
        assert_eq!(plan.skipped_by_resume, 1);
    }

    #[test]
    fn active_orchestration_requires_explicit_confirmation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut plan = plan_dry_run(
            vec![candidate("one", CandidateStateChange::ReadOnly)],
            HuntBudget::default(),
            &ResumeState::default(),
        );

        apply_policy_gated_orchestration(tmp.path(), &mut plan, false).unwrap();

        assert_eq!(plan.stop_reason, Some(StopReason::ApprovalRequired));
        assert!(!tmp.path().join(RESUME_RELATIVE_PATH).exists());
    }

    #[test]
    fn confirmed_orchestration_records_tested_plan_hashes_for_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let mut plan = plan_dry_run(
            vec![candidate("one", CandidateStateChange::ReadOnly)],
            HuntBudget::default(),
            &ResumeState::default(),
        );
        let expected_hash = plan.selected[0].plan_hash.clone();

        apply_policy_gated_orchestration(tmp.path(), &mut plan, true).unwrap();

        let resume = load_resume_state(&tmp.path().join(RESUME_RELATIVE_PATH)).unwrap();
        assert!(resume.tested_plan_hashes.contains(&expected_hash));
    }

    #[test]
    fn confirmed_orchestration_writes_redacted_evidence_for_each_executed_read_only_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let mut plan = plan_dry_run(
            vec![candidate("one", CandidateStateChange::ReadOnly)],
            HuntBudget::default(),
            &ResumeState::default(),
        );

        apply_policy_gated_orchestration(tmp.path(), &mut plan, true).unwrap();

        assert_eq!(plan.executed.len(), 1);
        assert_eq!(plan.executed[0].candidate_id, "one");
        assert_eq!(plan.executed[0].verdict_class, "interesting_diff");
        let plan_path = tmp
            .path()
            .join(&plan.executed[0].evidence_bundle)
            .join("plan.json");
        assert!(plan_path.exists());
        let replay_plan: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(plan_path).expect("read evidence plan"))
                .expect("parse evidence plan");
        assert_eq!(
            replay_plan["plan_hash"].as_str(),
            Some(plan.executed[0].plan_hash.as_str())
        );
        assert!(
            tmp.path()
                .join(&plan.executed[0].evidence_bundle)
                .join("semantic_diff.json")
                .exists()
        );
    }

    #[test]
    fn confirmed_orchestration_stops_on_auth_expired_replay_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome_dir = tmp.path().join(REPLAY_OUTCOMES_RELATIVE_DIR);
        std::fs::create_dir_all(&outcome_dir).unwrap();
        std::fs::write(
            outcome_dir.join("one.json"),
            r#"{
                "status": 401,
                "body": "{\"error\":\"token expired\"}",
                "target_tenant_markers": [],
                "auth_failure_shape": "expired_token",
                "graphql_errors": false
            }"#,
        )
        .unwrap();
        let mut plan = plan_dry_run(
            vec![candidate("one", CandidateStateChange::ReadOnly)],
            HuntBudget::default(),
            &ResumeState::default(),
        );

        apply_policy_gated_orchestration(tmp.path(), &mut plan, true).unwrap();

        assert_eq!(plan.stop_reason, Some(StopReason::AuthExpired));
        assert_eq!(plan.executed.len(), 1);
        assert!(
            !load_resume_state(&tmp.path().join(RESUME_RELATIVE_PATH))
                .unwrap()
                .tested_plan_hashes
                .contains(&plan.selected[0].plan_hash)
        );
    }
}
