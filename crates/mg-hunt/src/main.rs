// Author: Jeff
// Date: 2026-05-29
// Description: Assisted autonomous hunting loop CLI
// Notes: Deterministic dry-run planner only; active execution remains policy-gated elsewhere

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use evidence_core::{EvidenceBundleRequest, EvidenceBundleWriter};
use replay_engine::{
    PlanBuilder, ReplayOutcome, ReplayPlanRequest, ScopeDecision, SemanticDiffEngine,
    SemanticVerdictClass,
};
use request_corpus::{CandidateStateChange, CorpusCandidate};
use serde::Serialize;

const CANDIDATES_RELATIVE_PATH: &str = "corpus/candidates.jsonl";
const RESUME_RELATIVE_PATH: &str = "hunt/tested-plan-hashes.txt";
const REPLAY_OUTCOMES_RELATIVE_DIR: &str = "hunt/replay-outcomes";
const DEFAULT_MAX_TESTS: usize = 20;
const DEFAULT_MAX_DURATION_SECS: u64 = 300;
const DEFAULT_MAX_BYTES: u64 = 1_048_576;
const ESTIMATED_TEST_BYTES: u64 = 1024;
const ESTIMATED_TEST_DURATION_SECS: u64 = 1;

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
            risk: _,
            dry_run,
            max_tests,
            max_duration,
            max_bytes,
            resume,
            confirmed,
            json,
        } => {
            let candidates = load_candidates(&engagement.join(CANDIDATES_RELATIVE_PATH))?;
            let resume_state = if resume {
                load_resume_state(&engagement.join(RESUME_RELATIVE_PATH))?
            } else {
                ResumeState::default()
            };
            let mut plan = plan_dry_run(
                candidates,
                HuntBudget {
                    max_tests,
                    max_duration_secs: max_duration,
                    max_bytes,
                },
                &resume_state,
            );
            if !dry_run {
                apply_policy_gated_orchestration(&engagement, &mut plan, confirmed)?;
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
    }
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

        let plan_hash = plan_hash_for_candidate(&candidate.id);
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

// Derive deterministic local plan hash from candidate id
fn plan_hash_for_candidate(id: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("plan-{hash:016x}")
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
    let replay_plan = PlanBuilder
        .build(
            ReplayPlanRequest::new(test.candidate.clone(), ScopeDecision::InScope)
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
                .with_evidence_output_dir(format!("evidence/{}", test.candidate_id)),
        )
        .context("build read-only replay plan")?;
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
            summary: format!("candidate {id}"),
        }
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
        resume
            .tested_plan_hashes
            .insert(plan_hash_for_candidate("one"));
        let plan = plan_dry_run(
            vec![
                candidate("one", CandidateStateChange::ReadOnly),
                candidate("two", CandidateStateChange::ReadOnly),
            ],
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
        assert!(
            tmp.path()
                .join(&plan.executed[0].evidence_bundle)
                .join("plan.json")
                .exists()
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
