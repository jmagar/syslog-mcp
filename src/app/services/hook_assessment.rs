//! Service-layer hook assessment: resolves a hook filter to its
//! highest-priority (or all, with `--all`) matching `HookIncidentEvidence`
//! bundle(s) via `investigate_ai_hook_incidents`, and optionally runs the
//! guarded LLM assessment through `LlmRunner` using the inline hook
//! assessment prompt (`crate::hook_assessment::build_hook_assessment_prompt`).
//!
//! Mirrors `super::skill_assessment` one-for-one. LLM invocation is CLI-only:
//! `run_llm = false` is the mandatory path for MCP/REST callers (there is no
//! MCP action for hook assessment at all — see the regression test in
//! `src/mcp/actions_tests.rs`).

use super::*;
use crate::app::llm_runner::{LlmCallerSurface, LlmEvidenceCounts, LlmInvocationSpec};
use crate::app::models::{
    AiHookInvestigateRequest, HookAssessRequest, HookAssessResponse, HookAssessResult,
    HookIncidentEvidence,
};
use crate::hook_assessment::build_hook_assessment_prompt;
use crate::llm_backend::LlmBackend;

impl CortexService {
    pub async fn run_hook_assessment(
        &self,
        req: HookAssessRequest,
    ) -> ServiceResult<HookAssessResponse> {
        self.run_hook_assessment_with_delta(req, true, |_| Ok(()))
            .await
    }

    /// `run_llm = false` skips the `LlmRunner::run` call entirely and returns
    /// only deterministic findings — the path MCP/REST callers MUST use and
    /// the path the CLI uses when `--no-llm` is passed.
    pub async fn run_hook_assessment_with_delta<F>(
        &self,
        req: HookAssessRequest,
        run_llm: bool,
        mut on_delta: F,
    ) -> ServiceResult<HookAssessResponse>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let keep_limit = if req.all {
            req.limit
        } else {
            Some(req.limit.unwrap_or(1).max(1))
        };
        let invest_req = AiHookInvestigateRequest {
            incident_id: None,
            hook_event: req.hook_event.clone(),
            hook_name: req.hook_name.clone(),
            hook_source: req.hook_source.clone(),
            tool: req.tool.clone(),
            project: req.project.clone(),
            since: req.since.clone(),
            until: req.until.clone(),
            limit: keep_limit,
            window_minutes: req.window_minutes,
            correlation_window_minutes: req.correlation_window_minutes,
        };
        let invest_resp = self.investigate_ai_hook_incidents(invest_req).await?;

        if invest_resp.no_data || invest_resp.evidence.is_empty() {
            let hook_desc = req
                .hook_name
                .clone()
                .or_else(|| req.hook_event.clone())
                .unwrap_or_else(|| "any hook".to_string());
            return Err(ServiceError::InvalidInput(format!(
                "no hook incident found for '{hook_desc}'; try a wider --since/--until window or \
                 verify the hook name/event"
            )));
        }

        let backend = run_llm
            .then(|| self.llm().backend(req.model.clone()))
            .transpose()
            .map_err(|error| ServiceError::InvalidInput(error.to_string()))?;
        let mut results = Vec::with_capacity(invest_resp.evidence.len());
        for evidence in &invest_resp.evidence {
            let mut result = HookAssessResult {
                incident_id: evidence.incident.incident_id.clone(),
                findings: evidence.findings.clone(),
                assessment: None,
                prompt_preview: None,
            };
            if let Some(backend) = backend.as_ref() {
                result = self
                    .run_one_hook_assessment(evidence, backend, &mut on_delta)
                    .await?;
            }
            results.push(result);
        }

        Ok(HookAssessResponse {
            hook_event: req.hook_event,
            hook_name: req.hook_name,
            results,
            total_incidents: invest_resp.total_incidents,
            other_matching_incidents: invest_resp.other_matching_incidents,
            no_incident_low_severity_summary: invest_resp.no_incident_low_severity_summary,
        })
    }

    async fn run_one_hook_assessment<F>(
        &self,
        evidence: &HookIncidentEvidence,
        backend: &LlmBackend,
        on_delta: &mut F,
    ) -> ServiceResult<HookAssessResult>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let evidence_json = serde_json::to_string_pretty(evidence)
            .map_err(|e| ServiceError::Internal(anyhow::anyhow!("json serialize failed: {e}")))?;
        let prompt = build_hook_assessment_prompt(&evidence_json);
        let prompt_preview: String = prompt.chars().take(500).collect();

        let spec = LlmInvocationSpec {
            caller_surface: LlmCallerSurface::Cli, // hook assessment is CLI-only (safety invariant)
            action: "hook_assess".to_string(),
            incident_id: Some(evidence.incident.incident_id.clone()),
            ai_tool: Some(evidence.incident.tool.clone()),
            ai_project: Some(evidence.incident.project.clone()),
            ai_session_id: Some(evidence.incident.session_id.clone()),
            evidence_counts: LlmEvidenceCounts {
                total_incidents: 1,
                evidence_bundle_count: 1,
                total_anchors: evidence.signal_anchors.len(),
                truncated: evidence.signal_anchors_truncated
                    || evidence.transcript_before_truncated
                    || evidence.transcript_after_truncated
                    || evidence.hook_events_truncated
                    || evidence.nearby_tool_calls_truncated
                    || evidence.nearby_logs_truncated
                    || evidence.nearby_errors_truncated,
            },
            prompt,
            provider: backend.provider().to_string(),
            model: backend.model(),
            program: backend.program(),
            extra_metadata: serde_json::json!({
                "hook_event": evidence.incident.hook_event,
                "hook_name": evidence.incident.hook_name,
                "has_runtime_evidence": evidence.incident.has_runtime_evidence,
            }),
        };
        let output = super::run_llm_with_delta(self.llm(), spec, backend, on_delta).await?;

        Ok(HookAssessResult {
            incident_id: evidence.incident.incident_id.clone(),
            findings: evidence.findings.clone(),
            assessment: Some(output),
            prompt_preview: Some(prompt_preview),
        })
    }
}

#[cfg(test)]
#[path = "hook_assessment_tests.rs"]
mod tests;
