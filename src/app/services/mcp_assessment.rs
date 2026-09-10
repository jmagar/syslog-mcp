//! Service-layer MCP assessment: calls `CortexService::investigate_ai_mcp_incidents`
//! to resolve an MCP server/tool (or bare tool name) to its highest-priority
//! (or all, with `--all`) matching `McpIncidentEvidence` bundle(s), and
//! optionally runs the guarded LLM assessment through `LlmRunner` using
//! the MCP assessment prompt. Mirrors
//! `src/app/services/skill_assessment.rs` exactly.
//!
//! This module does NOT reimplement Gemini process spawning, an audit
//! table, or an MCP-incident schema — all three already exist upstream
//! (`LlmRunner`, `investigate_ai_mcp_incidents`).
use super::*;
use crate::app::llm_runner::{LlmCallerSurface, LlmEvidenceCounts, LlmInvocationSpec};
use crate::app::models::{
    AiMcpInvestigateRequest, McpAssessRequest, McpAssessResponse, McpAssessResult,
};
use crate::llm_backend::LlmBackend;
use crate::mcp_assessment::build_mcp_assessment_prompt;

impl CortexService {
    /// `run_llm = false` skips the `LlmRunner::run` call entirely and
    /// returns only deterministic findings — this is the path MCP/REST
    /// callers MUST use (mirrors the skill-assessment MCP-safety
    /// invariant, see `src/mcp/actions_tests.rs`'s
    /// `no_mcp_action_spec_invokes_gemini_assessment`) and the path the
    /// CLI uses when `--no-llm` is passed.
    pub async fn run_mcp_assessment_with_delta<F>(
        &self,
        req: McpAssessRequest,
        run_llm: bool,
        mut on_delta: F,
    ) -> ServiceResult<McpAssessResponse>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        if req.mcp_server.is_none() && req.mcp_tool.is_none() && req.tool_name.is_none() {
            return Err(ServiceError::InvalidInput(
                "assess mcp requires an mcp_server, mcp_tool, or tool_name".to_string(),
            ));
        }

        let keep_limit = if req.all {
            req.limit
        } else {
            Some(req.limit.unwrap_or(1).max(1))
        };
        let invest_req = AiMcpInvestigateRequest {
            incident_id: None,
            mcp_server: req.mcp_server.clone(),
            mcp_tool: req.mcp_tool.clone(),
            tool_name: req.tool_name.clone(),
            tool: req.tool.clone(),
            project: req.project.clone(),
            since: req.since.clone(),
            until: req.until.clone(),
            limit: keep_limit,
            window_minutes: req.window_minutes,
            correlation_window_minutes: req.correlation_window_minutes,
        };
        let invest_resp = self.investigate_ai_mcp_incidents(invest_req).await?;

        if invest_resp.no_data || invest_resp.evidence.is_empty() {
            let target_desc = req
                .mcp_server
                .clone()
                .or_else(|| req.mcp_tool.clone())
                .or_else(|| req.tool_name.clone())
                .unwrap_or_default();
            return Err(ServiceError::InvalidInput(format!(
                "no MCP incident found for '{target_desc}'; try a wider --since/--until window or verify the server/tool name"
            )));
        }

        let backend = run_llm
            .then(|| self.llm().backend(req.model.clone()))
            .transpose()
            .map_err(|error| ServiceError::InvalidInput(error.to_string()))?;
        let mut results = Vec::with_capacity(invest_resp.evidence.len());
        for evidence in &invest_resp.evidence {
            let mut result = McpAssessResult {
                incident_id: evidence.incident.incident_id.clone(),
                findings: evidence.findings.clone(),
                assessment: None,
                prompt_preview: None,
            };
            if let Some(backend) = backend.as_ref() {
                result = self
                    .run_one_mcp_assessment(evidence, backend, &mut on_delta)
                    .await?;
            }
            results.push(result);
        }

        Ok(McpAssessResponse {
            mcp_server: req.mcp_server,
            mcp_tool: req.mcp_tool,
            tool_name: req.tool_name,
            results,
            total_incidents: invest_resp.total_incidents,
            other_matching_incidents: invest_resp.other_matching_incidents,
            no_incident_low_severity_summary: invest_resp.no_incident_low_severity_summary,
        })
    }

    /// Runs one guarded LLM assessment for a single `McpIncidentEvidence`
    /// bundle via `LlmRunner::run`, forwarding deltas directly through the
    /// borrowed callback without an intermediate allocation or channel.
    async fn run_one_mcp_assessment<F>(
        &self,
        evidence: &McpIncidentEvidence,
        backend: &LlmBackend,
        on_delta: &mut F,
    ) -> ServiceResult<McpAssessResult>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let evidence_json = serde_json::to_string_pretty(evidence)
            .map_err(|e| ServiceError::Internal(anyhow::anyhow!("json serialize failed: {e}")))?;
        let prompt = build_mcp_assessment_prompt(&evidence_json);
        let prompt_preview: String = prompt.chars().take(500).collect();

        let spec = LlmInvocationSpec {
            caller_surface: LlmCallerSurface::Cli, // MCP assessment is CLI-only (safety invariant)
            action: "mcp_assess".to_string(),
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
                    || evidence.transcript_after_truncated,
            },
            prompt,
            provider: backend.provider().to_string(),
            model: backend.model(),
            program: backend.program(),
            extra_metadata: serde_json::json!({
                "mcp_server": evidence.incident.mcp_server,
                "mcp_tool": evidence.incident.mcp_tool,
            }),
        };
        let output = super::run_llm_with_delta(self.llm(), spec, backend, on_delta).await?;

        Ok(McpAssessResult {
            incident_id: evidence.incident.incident_id.clone(),
            findings: evidence.findings.clone(),
            assessment: Some(output),
            prompt_preview: Some(prompt_preview),
        })
    }
}

#[cfg(test)]
#[path = "mcp_assessment_tests.rs"]
mod tests;
