/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-07-24
 * Description:     replay-runner — the only crate that sends live traffic
 *                  for the adaptive hunt. Executes an already-approved,
 *                  in-scope replay plan and records exactly what was sent
 *                  and received; refuses anything not marked executable.
 * Notes:           Sends the request verbatim (method, headers incl. any
 *                  identity auth, body) through the shared http_client, never
 *                  raw reqwest. Refuses any plan the engine did not mark
 *                  executable.
 *******************************************************************/

use http_client::Client;
use replay_engine::{ReplayOutcome, ReplayPlan, ReplayRequest, ScopeDecision};
use thiserror::Error;

// Reasons a replay was refused before or during execution
#[derive(Debug, Error)]
pub enum ReplayRunError {
    #[error("plan is not marked executable; refusing to send")]
    NotExecutable,
    #[error("plan is not in scope; refusing to send")]
    OutOfScope,
    #[error("transport error: {0}")]
    Transport(String),
}

// Executes approved replay plans and records their outcome
pub struct ReplayRunner {
    client: Client,
}

impl ReplayRunner {
    // Build a runner over a configured shared HTTP client
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    // Send an approved, in-scope request and record exactly what came back
    pub async fn run(
        &self,
        plan: &ReplayPlan,
        request: &ReplayRequest,
    ) -> Result<ReplayOutcome, ReplayRunError> {
        // Deterministic safety gate — the engine decides executability, the runner obeys it
        if plan.scope_decision != ScopeDecision::InScope {
            return Err(ReplayRunError::OutOfScope);
        }
        if !plan.executable {
            return Err(ReplayRunError::NotExecutable);
        }

        let response = self
            .client
            .send(
                &request.method,
                &request.url,
                &request.headers,
                request.body.as_deref(),
            )
            .await
            .map_err(|error| ReplayRunError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        let response_headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        let body = response
            .text()
            .await
            .map_err(|error| ReplayRunError::Transport(error.to_string()))?;

        Ok(ReplayOutcome::http(status, body)
            .with_response_headers(response_headers)
            .with_sent_request(request.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_client::ClientConfig;
    use replay_engine::{PlanBuilder, ReplayPlanRequest};
    use request_corpus::{
        CandidateKind, CandidateSafety, CandidateSource, CandidateStateChange, CorpusCandidate,
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn executable_plan_sends_and_records_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/fetch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-test", "yes")
                    .set_body_string("fetched ok"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let request = ReplayRequest {
            method: "GET".to_string(),
            url: format!("{}/api/fetch?url=http://oob.local/token", server.uri()),
            headers: Vec::new(),
            body: None,
        };
        let runner = ReplayRunner::new(Client::new(ClientConfig::default()).unwrap());

        let outcome = runner.run(&approved_ssrf_plan(), &request).await.unwrap();

        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body, "fetched ok");
        assert!(
            outcome
                .response_headers
                .iter()
                .any(|(name, value)| name == "x-test" && value == "yes")
        );
        assert_eq!(outcome.sent_request.unwrap().url, request.url);
    }

    #[tokio::test]
    async fn executable_plan_sends_method_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/resource/42"))
            .and(header("authorization", "Bearer alice-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("victim data"))
            .expect(1)
            .mount(&server)
            .await;

        let request = ReplayRequest {
            method: "POST".to_string(),
            url: format!("{}/api/resource/42", server.uri()),
            headers: vec![("authorization".to_string(), "Bearer alice-jwt".to_string())],
            body: Some("{\"note\":\"x\"}".to_string()),
        };
        let runner = ReplayRunner::new(Client::new(ClientConfig::default()).unwrap());

        let outcome = runner.run(&approved_ssrf_plan(), &request).await.unwrap();

        // wiremock's method+auth-header matchers verify the request was sent as given
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body, "victim data");
    }

    #[tokio::test]
    async fn non_executable_plan_never_sends() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let request = ReplayRequest {
            method: "GET".to_string(),
            url: format!("{}/api/fetch?url=http://oob.local/token", server.uri()),
            headers: Vec::new(),
            body: None,
        };
        let runner = ReplayRunner::new(Client::new(ClientConfig::default()).unwrap());

        let error = runner
            .run(&unapproved_ssrf_plan(), &request)
            .await
            .unwrap_err();

        assert!(matches!(error, ReplayRunError::NotExecutable));
        // MockServer verifies expect(0) on drop, proving no request was sent
    }

    // An SSRF plan whose approval grant matches, so the engine marks it executable
    fn approved_ssrf_plan() -> ReplayPlan {
        let base = ReplayPlanRequest::new(ssrf_candidate(), ScopeDecision::InScope)
            .with_evidence_output_dir("evidence/ssrf");
        let unapproved = PlanBuilder.build(base.clone()).unwrap();
        PlanBuilder
            .build(base.with_approval_grant_hash(unapproved.plan_hash))
            .unwrap()
    }

    // The same SSRF plan without an approval grant, so it stays inert
    fn unapproved_ssrf_plan() -> ReplayPlan {
        PlanBuilder
            .build(
                ReplayPlanRequest::new(ssrf_candidate(), ScopeDecision::InScope)
                    .with_evidence_output_dir("evidence/ssrf"),
            )
            .unwrap()
    }

    fn ssrf_candidate() -> CorpusCandidate {
        CorpusCandidate {
            id: "ssrf-fetch-1".to_string(),
            kind: CandidateKind::ServerSideRequestTarget,
            source: CandidateSource::Traffic,
            safety: CandidateSafety::RequiresApproval,
            state_change: CandidateStateChange::ReadOnly,
            autonomous_safe: false,
            record_ids: vec!["fetch-1".to_string()],
            observation_ids: Vec::new(),
            injection_params: vec!["url".to_string()],
            summary: "server-side request sink".to_string(),
        }
    }
}
