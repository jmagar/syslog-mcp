use super::*;
use crate::app::llm_runner::{
    LlmCallerSurface, LlmDryRunOutcome, LlmEvidenceCounts, LlmInvocationSpec,
};

impl CortexService {
    pub async fn run_assess(&self, req: AiAssessRequest) -> ServiceResult<AiAssessResponse> {
        self.run_assess_with_delta(req, |_| Ok(())).await
    }

    /// Build the assessment prompt, evidence bundle, and `LlmInvocationSpec`
    /// that both `run_assess_with_delta` and `dry_run_assess`
    /// feed into `LlmRunner` — the only difference between the run and
    /// dry-run paths is `LlmRunner::run` vs `LlmRunner::dry_run`, so
    /// everything up to that point lives here to keep the two callers in
    /// lockstep. Returns the spec plus the summary the run path echoes back
    /// in `AiAssessResponse` (`spec.evidence_counts.truncated` carries the
    /// truncation flag the summary omits), and the resolved
    /// `LlmBackend` the run path needs to drive the subprocess.
    ///
    /// Eng review fix (Fix 1): `LlmBackend::from_env` is passed
    /// `LlmRunner`'s own resolved timeout instead of independently
    /// re-reading `CORTEX_LLM_COMPLETION_TIMEOUT_SECS`.
    async fn build_assess_spec(
        &self,
        req: &AiAssessRequest,
    ) -> ServiceResult<(LlmInvocationSpec, AiAssessEvidenceSummary, LlmBackend)> {
        let incident_id = req.incident_id.clone();
        let invest_req = AiInvestigateRequest {
            incident_id: Some(incident_id.clone()),
            project: req.project.clone(),
            tool: req.tool.clone(),
            since: req.since.clone(),
            until: req.until.clone(),
            limit: Some(req.limit.unwrap_or(200).max(200)),
            window_minutes: req.window_minutes,
            correlation_window_minutes: req.correlation_window_minutes,
            terms: req.terms.clone(),
        };
        let invest_resp = self.investigate_ai_incidents(invest_req).await?;

        let matching: Vec<_> = invest_resp
            .evidence
            .iter()
            .filter(|e| e.incident.incident_id == incident_id)
            .collect();

        if matching.is_empty() {
            return Err(ServiceError::InvalidInput(format!(
                "no incident found with id '{}'; run `cortex sessions incidents` to list available ids",
                incident_id
            )));
        }

        let backend = self
            .llm()
            .backend(req.model.clone())
            .map_err(|error| ServiceError::InvalidInput(error.to_string()))?;

        let evidence_json = serde_json::to_string_pretty(&matching)
            .map_err(|e| ServiceError::Internal(anyhow::anyhow!("json serialize failed: {e}")))?;
        let prompt = build_assessment_prompt(&evidence_json);
        let evidence_summary = AiAssessEvidenceSummary {
            total_incidents: invest_resp.total_incidents,
            evidence_bundle_count: matching.len(),
            total_anchors: matching.iter().map(|e| e.anchors.len()).sum(),
        };

        let spec = LlmInvocationSpec {
            caller_surface: LlmCallerSurface::Cli,
            action: "ai_assess".to_string(),
            incident_id: Some(incident_id),
            ai_tool: req.tool.clone(),
            ai_project: req.project.clone(),
            ai_session_id: None,
            evidence_counts: LlmEvidenceCounts {
                total_incidents: evidence_summary.total_incidents,
                evidence_bundle_count: evidence_summary.evidence_bundle_count,
                total_anchors: evidence_summary.total_anchors,
                truncated: invest_resp.truncated,
            },
            prompt,
            provider: backend.provider().to_string(),
            model: backend.model(),
            program: backend.program(),
            extra_metadata: serde_json::json!({}),
        };

        Ok((spec, evidence_summary, backend))
    }

    /// Preview the prompt/evidence bundle that `run_assess` would
    /// send to the selected LLM, WITHOUT invoking the LLM — routes through
    /// `LlmRunner::dry_run` (GH issue #94's acceptance criterion for a
    /// dry-run/preview mode). Still writes an audit row (status
    /// "dry_run"), same as `LlmRunner::dry_run` does for every other
    /// caller, but never spawns a provider subprocess.
    pub async fn dry_run_assess(&self, req: AiAssessRequest) -> ServiceResult<LlmDryRunOutcome> {
        let (spec, _summary, _backend) = self.build_assess_spec(&req).await?;
        self.llm()
            .dry_run(&spec)
            .await
            .map_err(|err| ServiceError::Internal(anyhow::anyhow!(err)))
    }

    pub async fn run_assess_with_delta<F>(
        &self,
        req: AiAssessRequest,
        mut on_delta: F,
    ) -> ServiceResult<AiAssessResponse>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let (spec, evidence_summary, backend) = self.build_assess_spec(&req).await?;
        let incident_id = spec.incident_id.clone().unwrap_or_default();
        let prompt_preview = spec.prompt.chars().take(500).collect::<String>();

        let assessment =
            super::run_llm_with_delta(self.llm(), spec, &backend, &mut on_delta).await?;

        Ok(AiAssessResponse {
            incident_id,
            assessment,
            prompt_preview,
            evidence_summary,
        })
    }

    /// UX wrapper for `cortex assess abuse`: auto-picks the top-priority
    /// matching abuse incident when `req.incident_id` is `None`, otherwise
    /// assesses the explicitly supplied incident id. Delegates the LLM
    /// path entirely to `run_assess_with_delta` (already
    /// `LlmRunner`-guarded) — this function adds no new LLM call site.
    pub async fn assess_top_abuse_incident_with_delta<F>(
        &self,
        req: AbuseAssessRequest,
        run_llm: bool,
        mut on_delta: F,
    ) -> ServiceResult<AbuseAssessResponse>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let (incident_id, other_matching_incidents) = match req.incident_id.clone() {
            Some(id) => (id, Vec::new()),
            None => {
                let list_req = AiIncidentRequest {
                    project: req.project.clone(),
                    tool: req.tool.clone(),
                    since: req.since.clone(),
                    until: req.until.clone(),
                    limit: req.limit,
                    window_minutes: req.window_minutes,
                    terms: req.terms.clone(),
                };
                let list_resp = self.list_ai_incidents(list_req).await?;
                if list_resp.incidents.is_empty() {
                    return Err(ServiceError::InvalidInput(
                        "no abuse incident found matching the given filters".to_string(),
                    ));
                }
                let mut sorted = list_resp.incidents.clone();
                sorted.sort_by(|a, b| {
                    b.priority_score
                        .partial_cmp(&a.priority_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let top = sorted[0].incident_id.clone();
                let others = sorted[1..].iter().map(|i| i.incident_id.clone()).collect();
                (top, others)
            }
        };

        let assess_req = AiAssessRequest {
            incident_id,
            model: req.model,
            project: req.project,
            tool: req.tool,
            since: req.since,
            until: req.until,
            window_minutes: req.window_minutes,
            correlation_window_minutes: req.correlation_window_minutes,
            terms: req.terms,
            limit: req.limit,
        };

        let assessed = if run_llm {
            // Already LlmRunner-guarded end to end (PR 1 Task 6) — no
            // additional spec/audit wiring needed here.
            self.run_assess_with_delta(assess_req, &mut on_delta)
                .await?
        } else {
            // Deterministic-only: reuse investigate_ai_incidents directly
            // rather than touching run_assess_with_delta at all, so
            // LlmRunner::run is never called. Build a minimal
            // AiAssessResponse shape with an empty assessment string so
            // callers (MCP/REST, --no-llm) get a consistent response type.
            let invest_req = AiInvestigateRequest {
                incident_id: Some(assess_req.incident_id.clone()),
                project: assess_req.project.clone(),
                tool: assess_req.tool.clone(),
                since: assess_req.since.clone(),
                until: assess_req.until.clone(),
                limit: Some(assess_req.limit.unwrap_or(200).max(200)),
                window_minutes: assess_req.window_minutes,
                correlation_window_minutes: assess_req.correlation_window_minutes,
                terms: assess_req.terms.clone(),
            };
            let invest_resp = self.investigate_ai_incidents(invest_req).await?;
            let matching: Vec<_> = invest_resp
                .evidence
                .iter()
                .filter(|e| e.incident.incident_id == assess_req.incident_id)
                .collect();
            if matching.is_empty() {
                return Err(ServiceError::InvalidInput(format!(
                    "no incident found with id '{}'; run `cortex sessions incidents` to list available ids",
                    assess_req.incident_id
                )));
            }
            AiAssessResponse {
                incident_id: assess_req.incident_id,
                assessment: String::new(),
                prompt_preview: String::new(),
                evidence_summary: AiAssessEvidenceSummary {
                    total_incidents: invest_resp.total_incidents,
                    evidence_bundle_count: matching.len(),
                    total_anchors: matching.iter().map(|e| e.anchors.len()).sum(),
                },
            }
        };

        Ok(AbuseAssessResponse {
            assessed,
            other_matching_incidents,
        })
    }
}

#[cfg(test)]
#[path = "assessment_tests.rs"]
mod tests;
