//! Source-specific normalization for Agent Observatory projections.

use crate::db::agent_observatory::{
    AgentEventKind, AgentHookSourceRow, AgentLlmSourceRow, AgentMcpSourceRow,
    AgentOtelMetricSourceRow, AgentOtelSpanSourceRow, AgentRepositoryObservationSourceRow,
    AgentSkillSourceRow, AgentSourceKind, AgentSourceRecord,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};

pub(super) const MAX_SUMMARY_BYTES: usize = 1024;
const MAX_FIELD_BYTES: usize = 4096;
pub(super) const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

pub(in crate::agent_observatory::projector) struct ProjectionParts {
    pub kind: AgentSourceKind,
    pub source_cursor: String,
    pub provider_sequence: Option<i64>,
    pub source_kind: &'static str,
    pub source_id: String,
    pub projection_variant: &'static str,
    pub event_kind: AgentEventKind,
    pub tool: Option<String>,
    pub provider_tool: Option<String>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub project: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub last_activity_at: String,
    pub source_log_id: Option<i64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub payload: Value,
    pub actor_id: String,
    pub actor_type: &'static str,
    pub actor_name: String,
}

pub(super) fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn bounded_optional(value: Option<&str>) -> Option<String> {
    value.map(|value| truncate_utf8(value, MAX_FIELD_BYTES))
}

fn bounded_json(value: Option<&str>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    if value.len() > MAX_FIELD_BYTES {
        return json!({ "truncated": true, "original_bytes": value.len() });
    }
    serde_json::from_str(value).unwrap_or_else(
        |_| json!({ "invalid_json": true, "preview": truncate_utf8(value, MAX_FIELD_BYTES) }),
    )
}

pub(super) fn bounded_payload(value: Value, event_label: &str, source_cursor: &str) -> String {
    let encoded = value.to_string();
    if encoded.len() <= MAX_PAYLOAD_BYTES {
        return encoded;
    }
    json!({
        "source_cursor": source_cursor,
        "event": truncate_utf8(event_label, MAX_SUMMARY_BYTES),
        "payload_truncated": true,
        "original_bytes": encoded.len(),
    })
    .to_string()
}

fn status_is_error(status: Option<&str>) -> bool {
    status.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "error" | "failed" | "failure" | "denied" | "timeout"
        )
    })
}

fn mcp_parts(row: &AgentMcpSourceRow) -> ProjectionParts {
    let label = row.event_kind.trim();
    let actor_name = row
        .mcp_server
        .as_deref()
        .zip(row.mcp_tool.as_deref())
        .map_or_else(
            || row.tool_name.clone(),
            |(server, tool)| format!("{server}/{tool}"),
        );
    let is_error = row.is_error == Some(true) || status_is_error(row.status.as_deref());
    ProjectionParts {
        kind: AgentSourceKind::Mcp,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "mcp_events",
        source_id: row.cursor_id.to_string(),
        projection_variant: "mcp",
        event_kind: AgentEventKind::Mcp,
        tool: Some(row.ai_tool.clone()),
        provider_tool: Some(row.ai_tool.clone()),
        session_id: row.ai_session_id.clone(),
        hostname: Some(row.hostname.clone()),
        project: row.ai_project.clone(),
        observed_at: row.timestamp.clone(),
        ingested_at: row.timestamp.clone(),
        last_activity_at: row.timestamp.clone(),
        source_log_id: row.call_log_id.or(row.result_log_id),
        trace_id: None,
        span_id: None,
        severity: if is_error { "err" } else { "info" }.to_string(),
        title: format!(
            "MCP {}: {}",
            if label.is_empty() { "event" } else { label },
            actor_name
        ),
        summary: truncate_utf8(
            row.error_text
                .as_deref()
                .or(row.output_preview.as_deref())
                .unwrap_or(&actor_name),
            MAX_SUMMARY_BYTES,
        ),
        payload: json!({
            "arguments": bounded_json(row.arguments_json.as_deref()),
            "call_id": row.call_id,
            "duration_ms": row.duration_ms,
            "error": bounded_optional(row.error_text.as_deref()),
            "event_kind": row.event_kind,
            "is_error": row.is_error,
            "mcp_server": row.mcp_server,
            "mcp_tool": row.mcp_tool,
            "metadata": bounded_json(row.metadata_json.as_deref()),
            "output_preview": bounded_optional(row.output_preview.as_deref()),
            "status": row.status,
            "tool_name": row.tool_name,
            "turn_id": row.turn_id,
        }),
        actor_id: format!("mcp:{}", row.call_id),
        actor_type: "mcp_tool",
        actor_name,
    }
}

fn hook_parts(row: &AgentHookSourceRow) -> ProjectionParts {
    let actor_name = row
        .hook_name
        .clone()
        .unwrap_or_else(|| row.hook_event.clone());
    let is_error =
        status_is_error(Some(&row.status)) || row.exit_code.is_some_and(|code| code != 0);
    ProjectionParts {
        kind: AgentSourceKind::Hook,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "hook_events",
        source_id: row.cursor_id.to_string(),
        projection_variant: "hook",
        event_kind: AgentEventKind::Hook,
        tool: Some(row.ai_tool.clone()),
        provider_tool: Some(row.ai_tool.clone()),
        session_id: row.ai_session_id.clone(),
        hostname: Some(row.hostname.clone()),
        project: row.ai_project.clone(),
        observed_at: row.timestamp.clone(),
        ingested_at: row.timestamp.clone(),
        last_activity_at: row.timestamp.clone(),
        source_log_id: row.log_id,
        trace_id: None,
        span_id: None,
        severity: if is_error { "err" } else { "info" }.to_string(),
        title: format!("Hook {}: {}", row.hook_event, actor_name),
        summary: truncate_utf8(
            row.stderr_preview
                .as_deref()
                .or(row.stdout_preview.as_deref())
                .unwrap_or(&row.status),
            MAX_SUMMARY_BYTES,
        ),
        payload: json!({
            "duration_ms": row.duration_ms,
            "evidence_kind": row.evidence_kind,
            "exit_code": row.exit_code,
            "hook_command": bounded_optional(row.hook_command.as_deref()),
            "hook_event": row.hook_event,
            "hook_name": row.hook_name,
            "hook_source": row.hook_source,
            "metadata": bounded_json(row.metadata_json.as_deref()),
            "status": row.status,
            "stderr_preview": bounded_optional(row.stderr_preview.as_deref()),
            "stdout_preview": bounded_optional(row.stdout_preview.as_deref()),
            "trusted_hash": row.trusted_hash,
        }),
        actor_id: format!("hook:{}", actor_name),
        actor_type: "hook",
        actor_name,
    }
}

fn skill_parts(row: &AgentSkillSourceRow) -> ProjectionParts {
    let actor_name = row.skill_plugin.as_deref().map_or_else(
        || row.skill_name.clone(),
        |plugin| format!("{plugin}/{}", row.skill_name),
    );
    ProjectionParts {
        kind: AgentSourceKind::Skill,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "skill_events",
        source_id: row.cursor_id.to_string(),
        projection_variant: "skill",
        event_kind: AgentEventKind::Skill,
        tool: Some(row.ai_tool.clone()),
        provider_tool: Some(row.ai_tool.clone()),
        session_id: row.ai_session_id.clone(),
        hostname: Some(row.hostname.clone()),
        project: row.ai_project.clone(),
        observed_at: row.timestamp.clone(),
        ingested_at: row.timestamp.clone(),
        last_activity_at: row.timestamp.clone(),
        source_log_id: Some(row.log_id),
        trace_id: None,
        span_id: None,
        severity: "info".to_string(),
        title: format!("Skill {}: {}", row.event_kind, actor_name),
        summary: truncate_utf8(&actor_name, MAX_SUMMARY_BYTES),
        payload: json!({
            "event_kind": row.event_kind,
            "evidence_kind": row.evidence_kind,
            "skill_name": row.skill_name,
            "skill_plugin": row.skill_plugin,
        }),
        actor_id: format!("skill:{}", actor_name),
        actor_type: "skill",
        actor_name,
    }
}

fn llm_parts(row: &AgentLlmSourceRow) -> ProjectionParts {
    let is_error = status_is_error(Some(&row.status)) || row.error.is_some();
    let actor_name = row.model.as_deref().map_or_else(
        || row.provider.clone(),
        |model| format!("{}/{}", row.provider, model),
    );
    ProjectionParts {
        kind: AgentSourceKind::Llm,
        source_cursor: json!({ "started_at": &row.started_at, "id": &row.id }).to_string(),
        provider_sequence: None,
        source_kind: "llm_invocations",
        source_id: row.id.clone(),
        projection_variant: "llm",
        event_kind: AgentEventKind::Llm,
        tool: row.ai_tool.clone(),
        provider_tool: row.ai_tool.clone(),
        session_id: row.ai_session_id.clone(),
        hostname: None,
        project: row.ai_project.clone(),
        observed_at: row.started_at.clone(),
        ingested_at: row
            .finished_at
            .clone()
            .unwrap_or_else(|| row.started_at.clone()),
        last_activity_at: row
            .finished_at
            .clone()
            .unwrap_or_else(|| row.started_at.clone()),
        source_log_id: None,
        trace_id: None,
        span_id: None,
        severity: if is_error { "err" } else { "info" }.to_string(),
        title: format!("LLM {}: {}", row.action, actor_name),
        summary: truncate_utf8(
            row.error.as_deref().unwrap_or(&row.status),
            MAX_SUMMARY_BYTES,
        ),
        payload: json!({
            "action": row.action,
            "caller_surface": row.caller_surface,
            "duration_ms": row.duration_ms,
            "error": bounded_optional(row.error.as_deref()),
            "evidence_counts": bounded_json(row.evidence_counts_json.as_deref()),
            "finished_at": row.finished_at,
            "incident_id": row.incident_id,
            "metadata": bounded_json(row.metadata_json.as_deref()),
            "model": row.model,
            "output_bytes": row.output_bytes,
            "program": row.program,
            "prompt_bytes": row.prompt_bytes,
            "provider": row.provider,
            "status": row.status,
        }),
        actor_id: format!("llm:{}", row.id),
        actor_type: "llm_invocation",
        actor_name,
    }
}

fn rfc3339_from_nanos(value: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp_nanos(value)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn otlp_span_parts(row: &AgentOtelSpanSourceRow) -> ProjectionParts {
    let observed_at = rfc3339_from_nanos(row.start_time_unix_nano);
    let is_error = row.status_code != 0;
    let actor_name = row
        .service_name
        .clone()
        .unwrap_or_else(|| "OTLP trace".to_string());
    ProjectionParts {
        kind: AgentSourceKind::OtelSpan,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "otel_spans",
        source_id: row.cursor_id.to_string(),
        projection_variant: "span",
        event_kind: AgentEventKind::OtlpSpan,
        tool: row.ai_tool.clone(),
        provider_tool: row.ai_tool.clone(),
        session_id: row.ai_session_id.clone(),
        hostname: Some(row.hostname.clone()),
        project: row.ai_project.clone(),
        observed_at: observed_at.clone(),
        ingested_at: row.received_at.clone(),
        last_activity_at: rfc3339_from_nanos(row.end_time_unix_nano),
        source_log_id: None,
        trace_id: Some(row.trace_id.clone()),
        span_id: Some(row.span_id.clone()),
        severity: if is_error { "err" } else { "info" }.to_string(),
        title: format!(
            "OTLP span: {}",
            truncate_utf8(&row.span_name, MAX_SUMMARY_BYTES)
        ),
        summary: truncate_utf8(
            row.status_message.as_deref().unwrap_or(&actor_name),
            MAX_SUMMARY_BYTES,
        ),
        payload: json!({
            "attributes": bounded_json(Some(row.attributes_json.as_str())),
            "end_time_unix_nano": row.end_time_unix_nano,
            "service_name": row.service_name,
            "span_kind": row.span_kind,
            "span_name": row.span_name,
            "status_code": row.status_code,
            "status_message": bounded_optional(row.status_message.as_deref()),
        }),
        actor_id: format!("otel-service:{actor_name}"),
        actor_type: "otel_service",
        actor_name,
    }
}

fn otlp_metric_parts(row: &AgentOtelMetricSourceRow) -> ProjectionParts {
    let observed_at = rfc3339_from_nanos(row.time_unix_nano);
    let actor_name = row
        .service_name
        .clone()
        .unwrap_or_else(|| "OTLP metrics".to_string());
    ProjectionParts {
        kind: AgentSourceKind::OtelMetric,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "otel_metric_points",
        source_id: row.cursor_id.to_string(),
        projection_variant: "metric",
        event_kind: AgentEventKind::OtlpMetric,
        tool: row.ai_tool.clone(),
        provider_tool: row.ai_tool.clone(),
        session_id: row.ai_session_id.clone(),
        hostname: Some(row.hostname.clone()),
        project: row.ai_project.clone(),
        observed_at: observed_at.clone(),
        ingested_at: row.received_at.clone(),
        last_activity_at: observed_at,
        source_log_id: None,
        trace_id: None,
        span_id: None,
        severity: "info".to_string(),
        title: format!(
            "OTLP metric: {}",
            truncate_utf8(&row.metric_name, MAX_SUMMARY_BYTES)
        ),
        summary: truncate_utf8(&row.instrument_kind, MAX_SUMMARY_BYTES),
        payload: json!({
            "attributes": bounded_json(Some(row.attributes_json.as_str())),
            "instrument_kind": row.instrument_kind,
            "metric_name": row.metric_name,
            "point_key": row.point_key,
            "value": bounded_json(Some(row.value_json.as_str())),
        }),
        actor_id: format!("otel-service:{actor_name}"),
        actor_type: "otel_service",
        actor_name,
    }
}

fn repository_observation_parts(row: &AgentRepositoryObservationSourceRow) -> ProjectionParts {
    let event_kind = match row.observation_kind.as_str() {
        "head" => AgentEventKind::GitHead,
        "error" => AgentEventKind::Error,
        _ => AgentEventKind::GitStatus,
    };
    let title = format!(
        "Repository {}: {}",
        truncate_utf8(&row.repository_name, MAX_SUMMARY_BYTES),
        truncate_utf8(&row.observation_kind, MAX_SUMMARY_BYTES),
    );
    ProjectionParts {
        kind: AgentSourceKind::RepositoryObservation,
        source_cursor: row.cursor_id.to_string(),
        provider_sequence: Some(row.cursor_id),
        source_kind: "repository_observations",
        source_id: row.observation_key.clone(),
        projection_variant: "repository_observation",
        event_kind,
        tool: None,
        provider_tool: None,
        session_id: None,
        hostname: Some(row.hostname.clone()),
        project: row.worktree_path.clone(),
        observed_at: row.observed_at.clone(),
        ingested_at: row.observed_at.clone(),
        last_activity_at: row.observed_at.clone(),
        source_log_id: None,
        trace_id: None,
        span_id: None,
        severity: if row.observation_kind == "error" {
            "err"
        } else {
            "info"
        }
        .to_string(),
        title,
        summary: truncate_utf8(&row.summary, MAX_SUMMARY_BYTES),
        payload: json!({
            "repository": {
                "hostname": row.hostname,
                "key": row.repository_key,
                "name": row.repository_name,
            },
            "observation": {
                "kind": row.observation_kind,
                "new_head_sha": row.new_head_sha,
                "old_head_sha": row.old_head_sha,
                "payload": bounded_json(Some(row.payload_json.as_str())),
                "worktree_key": row.worktree_key,
                "worktree_path": row.worktree_path,
            },
        }),
        actor_id: "git-observer".to_string(),
        actor_type: "repository_observer",
        actor_name: "Git observer".to_string(),
    }
}

pub(super) fn projection_parts(record: &AgentSourceRecord) -> ProjectionParts {
    match record {
        AgentSourceRecord::Mcp(row) => mcp_parts(row),
        AgentSourceRecord::Hook(row) => hook_parts(row),
        AgentSourceRecord::Skill(row) => skill_parts(row),
        AgentSourceRecord::Llm(row) => llm_parts(row),
        AgentSourceRecord::OtelSpan(row) => otlp_span_parts(row),
        AgentSourceRecord::OtelMetric(row) => otlp_metric_parts(row),
        AgentSourceRecord::RepositoryObservation(row) => repository_observation_parts(row),
    }
}
