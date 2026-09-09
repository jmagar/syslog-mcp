//! Handler implementations for the single action-dispatched `cortex` MCP tool
//! (log intelligence core).
//!
//! The authoritative action registry is `ACTION_SPECS` in `actions.rs`; this
//! module supplies the executable branch for each `ActionHandler`. Handlers
//! parse the tool arguments into typed `src/app` request models and delegate
//! to `CortexService` — business policy (limits, validation, correlation
//! rules) lives in the service layer so MCP, REST, and CLI stay consistent.
//!
//! Invariants: scope gating (`cortex:read` / `cortex:admin`) happens before
//! dispatch in `rmcp_server.rs`; unknown actions are denied fail-closed.
//! Handlers return typed service errors that the server maps to MCP error
//! classes (invalid_params / retryable / not_found / conflict / internal).

use lab_auth::AuthContext;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::app::{
    AbuseSearchRequest, AiCorrelateRequest, AiIncidentRequest, AiInvestigateRequest,
    AnomaliesRequest, ClockSkewRequest, CompareRequest, ContextRequest, CorrelateEventsRequest,
    CorrelateStateRequest, FilterLogsRequest, FleetStateRequest, GetErrorsRequest, GetLogRequest,
    HomelabMapRequest, HostStateRequest, IngestRateRequest, ListAiProjectsRequest,
    ListAiToolsRequest, ListAppsRequest, ListArtifactEvidenceRequest, ListHookEventsRequest,
    ListMcpEventsRequest, ListSessionsRequest, ListSkillEventsRequest, ListSourceIpsRequest,
    LlmInvocationsRequest, NotificationsRecentRequest, PatternsRequest, ProjectContextRequest,
    SearchLogsRequest, SearchSessionsRequest, SilentHostsRequest, TailLogsRequest, TimelineRequest,
    TopicCorrelateRequest, UnaddressedErrorsRequest, UsageBlocksRequest,
};

use crate::artifact_evidence::ArtifactEvidenceInput;

use super::AppState;
use super::actions;
#[cfg(test)]
use help::tool_cortex_help;

mod admin;
mod context;
mod help;
mod hook_incidents;
mod mcp_incidents;
mod skill_incidents;
mod status;

/// Execute a tool by name
pub(super) async fn execute_tool(
    state: &AppState,
    name: &str,
    args: Value,
    auth: Option<&AuthContext>,
) -> anyhow::Result<Value> {
    match name {
        "cortex" => tool_cortex(state, args, auth).await,
        _ => Err(anyhow::anyhow!("Unknown tool: {name}")),
    }
}

async fn tool_cortex(
    state: &AppState,
    args: Value,
    auth: Option<&AuthContext>,
) -> anyhow::Result<Value> {
    let action = string_arg(&args, "action")
        .ok_or_else(|| invalid_input("action is required".to_string()))?;
    let Some(handler) = actions::handler_for(&action) else {
        return Err(invalid_input(format!(
            "unknown cortex action: {action}; expected one of {}",
            actions::action_names().join(", ")
        )));
    };
    dispatch_cortex_action(handler, state, args, auth).await
}

async fn dispatch_cortex_action(
    handler: actions::ActionHandler,
    state: &AppState,
    args: Value,
    auth: Option<&AuthContext>,
) -> anyhow::Result<Value> {
    use actions::ActionHandler as H;

    match handler {
        H::SearchLogs => tool_search_logs(state, args).await,
        H::FilterLogs => tool_filter_logs(state, args).await,
        H::TailLogs => tool_tail_logs(state, args).await,
        H::GetErrors => tool_get_errors(state, args).await,
        H::ListHosts => tool_list_hosts(state, args).await,
        H::HomelabMap => tool_homelab_map(state, args).await,
        H::HostState => tool_host_state(state, args).await,
        H::FleetState => tool_fleet_state(state, args).await,
        H::CorrelateEvents => tool_correlate_events(state, args).await,
        H::CorrelateState => tool_correlate_state(state, args).await,
        H::GetStats => status::tool_get_stats(state, args).await,
        H::GetStatus => status::tool_get_status(state, args).await,
        H::ListApps => tool_list_apps(state, args).await,
        H::ListSessions => tool_list_sessions(state, args).await,
        H::SearchSessions => tool_search_sessions(state, args).await,
        H::SearchAbuse => tool_search_abuse(state, args).await,
        H::AbuseIncidents => tool_abuse_incidents(state, args).await,
        H::AbuseInvestigate => tool_abuse_investigate(state, args).await,
        H::AiCorrelate => tool_ai_correlate(state, args).await,
        H::TopicCorrelate => tool_topic_correlate(state, args).await,
        H::UsageBlocks => tool_usage_blocks(state, args).await,
        H::ProjectContext => tool_project_context(state, args).await,
        H::ListAiTools => tool_list_ai_tools(state, args).await,
        H::ListAiProjects => tool_list_ai_projects(state, args).await,
        H::ListSourceIps => tool_list_source_ips(state, args).await,
        H::Timeline => tool_timeline(state, args).await,
        H::Patterns => tool_patterns(state, args).await,
        H::Context => tool_context(state, args).await,
        H::GetLog => tool_get_log(state, args).await,
        H::IngestRate => tool_ingest_rate(state, args).await,
        H::SilentHosts => tool_silent_hosts(state, args).await,
        H::ClockSkew => tool_clock_skew(state, args).await,
        H::Anomalies => tool_anomalies(state, args).await,
        H::Compare => tool_compare(state, args).await,
        H::ComposeStatus => tool_compose_status(args).await,
        H::ComposeDoctor => tool_compose_doctor(args).await,
        H::UnaddressedErrors => tool_unaddressed_errors(state, args).await,
        H::AckError => admin::tool_ack_error(state, args, auth).await,
        H::UnackError => admin::tool_unack_error(state, args, auth).await,
        H::NotificationsRecent => tool_notifications_recent(state, args).await,
        H::FileTails => tool_file_tails(state, args).await,
        H::NotificationsTest => admin::tool_notifications_test(state, args, auth).await,
        H::LlmInvocations => tool_llm_invocations(state, args).await,
        H::SimilarIncidents => context::tool_similar_incidents(state, args).await,
        H::RecurringErrorComparison => context::tool_recurring_error_comparison(state, args).await,
        H::IncidentContext => context::tool_incident_context(state, args).await,
        H::Graph => context::tool_graph(state, args).await,
        H::ArtifactEvidence => tool_artifact_evidence(state, args).await,
        H::ArtifactEvidenceRecord => tool_artifact_evidence_record(state, args).await,
        H::SkillEvents => tool_skill_events(state, args).await,
        H::SkillIncidents => skill_incidents::tool_skill_incidents(state, args).await,
        H::SkillInvestigate => skill_incidents::tool_skill_investigate(state, args).await,
        H::McpEvents => tool_mcp_events(state, args).await,
        H::McpIncidents => mcp_incidents::tool_mcp_incidents(state, args).await,
        H::McpInvestigate => mcp_incidents::tool_mcp_investigate(state, args).await,
        H::HookEvents => tool_hook_events(state, args).await,
        H::HookIncidents => hook_incidents::tool_hook_incidents(state, args).await,
        H::HookInvestigate => hook_incidents::tool_hook_investigate(state, args).await,
        H::Help => help::tool_cortex_help().await,
    }
}

async fn tool_search_logs(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: SearchLogsRequest = action_payload(args, "search")?;
    let response = state.service.search_logs(req).await?;
    tracing::debug!(result_count = response.count, "search_logs completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_filter_logs(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: FilterLogsRequest = action_payload(args, "filter")?;
    let response = state.service.filter_logs(req).await?;
    tracing::debug!(result_count = response.count, "filter_logs completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_homelab_map(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: HomelabMapRequest = action_payload(args, "map")?;
    let response = state.service.homelab_map(req).await?;
    tracing::debug!(node_count = response.nodes.len(), "homelab_map completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_tail_logs(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: TailLogsRequest = action_payload(args, "tail")?;
    let response = state.service.tail_logs(req).await?;
    tracing::debug!(result_count = response.count, "tail_logs completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_get_errors(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: GetErrorsRequest = action_payload(args, "errors")?;
    let response = state.service.analysis().errors(req).await?;
    tracing::debug!(
        summary_rows = response.summary.len(),
        "get_errors completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_apps(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListAppsRequest = action_payload(args, "apps")?;
    let response = state.service.list_apps(req).await?;
    tracing::debug!(
        app_count = response.apps.len(),
        total = response.total,
        "list_apps completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_host_state(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: HostStateRequest = action_payload(args, "host_state")?;
    Ok(serde_json::to_value(
        state.service.state().host(req).await?,
    )?)
}

async fn tool_fleet_state(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: FleetStateRequest = action_payload(args, "fleet_state")?;
    Ok(serde_json::to_value(
        state.service.state().fleet(req).await?,
    )?)
}
async fn tool_correlate_state(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: CorrelateStateRequest = action_payload(args, "correlate_state")?;
    Ok(serde_json::to_value(
        state.service.correlate().state(req).await?,
    )?)
}

async fn tool_list_sessions(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListSessionsRequest = action_payload(args, "sessions")?;
    let response = state.service.list_sessions(req).await?;
    tracing::debug!(session_count = response.count, "list_sessions completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_search_sessions(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: SearchSessionsRequest = action_payload(args, "search_sessions")?;
    let response = state.service.search_sessions(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_search_abuse(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: AbuseSearchRequest = action_payload(args, "abuse")?;
    let response = state.service.search_abuse(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_abuse_incidents(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: AiIncidentRequest = action_payload(args, "abuse_incidents")?;
    let response = state.service.list_ai_incidents(req).await?;
    tracing::debug!(
        incident_count = response.incidents.len(),
        total = response.total_incidents,
        "abuse_incidents completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_abuse_investigate(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: AiInvestigateRequest = action_payload(args, "abuse_investigate")?;
    let response = state.service.investigate_ai_incidents(req).await?;
    tracing::debug!(
        evidence_count = response.evidence.len(),
        total_incidents = response.total_incidents,
        "abuse_investigate completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_ai_correlate(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: AiCorrelateRequest = action_payload(args, "ai_correlate")?;
    let response = state.service.correlate().ai(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_topic_correlate(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: TopicCorrelateRequest = action_payload(args, "topic_correlate")?;
    let response = state.service.correlate().topic(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_usage_blocks(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: UsageBlocksRequest = action_payload(args, "usage_blocks")?;
    let response = state.service.usage_blocks(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_project_context(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ProjectContextRequest = action_payload(args, "project_context")?;
    let response = state.service.project_context(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_ai_tools(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListAiToolsRequest = action_payload(args, "list_ai_tools")?;
    let response = state.service.list_ai_tools(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_artifact_evidence(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListArtifactEvidenceRequest = action_payload(args, "artifact_evidence")?;
    let response = state.service.list_artifact_evidence(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_artifact_evidence_record(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let input: ArtifactEvidenceInput = action_payload(args, "artifact_evidence_record")?;
    let response = state.service.record_artifact_evidence(input).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_skill_events(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListSkillEventsRequest = action_payload(args, "skill_events")?;
    let response = state.service.list_skill_events(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_mcp_events(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListMcpEventsRequest = action_payload(args, "mcp_events")?;
    let response = state.service.list_mcp_events(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_hook_events(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListHookEventsRequest = action_payload(args, "hook_events")?;
    let response = state.service.list_hook_events(req).await?;
    tracing::debug!(event_count = response.events.len(), "hook_events completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_ai_projects(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListAiProjectsRequest = action_payload(args, "list_ai_projects")?;
    let response = state.service.list_ai_projects(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_source_ips(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ListSourceIpsRequest = action_payload(args, "source_ips")?;
    let response = state.service.hosts().source_ips(req).await?;
    tracing::debug!(
        source_ip_count = response.source_ips.len(),
        total = response.total,
        "list_source_ips completed"
    );
    Ok(serde_json::to_value(response)?)
}

fn reject_compose_target_overrides(args: &Value) -> anyhow::Result<()> {
    for key in [
        "container",
        "container_name",
        "project_dir",
        "compose_file",
        "project_name",
        "service",
    ] {
        if args.get(key).is_some() {
            return Err(invalid_input(format!(
                "compose MCP actions do not accept target override: {key}"
            )));
        }
    }
    Ok(())
}

async fn tool_compose_status(args: Value) -> anyhow::Result<Value> {
    reject_compose_target_overrides(&args)?;
    let status = crate::app::run_compose_status().await?;
    Ok(serde_json::to_value(crate::compose::mcp_projection(
        &status,
    ))?)
}

async fn tool_compose_doctor(args: Value) -> anyhow::Result<Value> {
    reject_compose_target_overrides(&args)?;
    let status = crate::app::run_compose_status().await?;
    crate::compose::ensure_doctor_ready(&status)?;
    Ok(serde_json::to_value(crate::compose::mcp_projection(
        &status,
    ))?)
}

async fn tool_timeline(state: &AppState, args: Value) -> anyhow::Result<Value> {
    // Default lookback is centralized in `CortexService::timeline` (bead dyqw):
    // it applies a bucket-sized window only when neither `since` nor `until` is set,
    // preventing full table scans without recreating the logic per transport.
    let req: TimelineRequest = action_payload(args, "timeline")?;
    let response = state.service.stats().timeline(req).await?;
    tracing::debug!(point_count = response.points.len(), "timeline completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_patterns(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: PatternsRequest = action_payload(args, "patterns")?;
    let response = state.service.analysis().patterns(req).await?;
    tracing::debug!(
        pattern_count = response.patterns.len(),
        scanned = response.scanned,
        truncated = response.truncated,
        "patterns completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_context(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ContextRequest = action_payload(args, "context")?;
    let response = state.service.context(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_get_log(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: GetLogRequest = action_payload(args, "get")?;
    let response = state.service.get_log(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_ingest_rate(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: IngestRateRequest = action_payload(args, "ingest_rate")?;
    let response = state.service.stats().ingest_rate(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_silent_hosts(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: SilentHostsRequest = action_payload(args, "silent_hosts")?;
    let response = state.service.hosts().silent(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_clock_skew(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: ClockSkewRequest = action_payload(args, "clock_skew")?;
    let response = state.service.state().clock_skew(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_anomalies(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: AnomaliesRequest = action_payload(args, "anomalies")?;
    let response = state.service.analysis().anomalies(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_compare(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: CompareRequest = action_payload(args, "compare")?;
    let response = state.service.analysis().compare(req).await?;
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_hosts(state: &AppState, _args: Value) -> anyhow::Result<Value> {
    let response = state.service.hosts().list().await?;
    tracing::debug!(host_count = response.hosts.len(), "list_hosts completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_correlate_events(state: &AppState, args: Value) -> anyhow::Result<Value> {
    if args.get("topic").is_some() {
        let req: TopicCorrelateRequest = action_payload(args, "correlate")?;
        let response = state.service.correlate().topic(req).await?;
        return Ok(serde_json::to_value(response)?);
    }
    let req: CorrelateEventsRequest = action_payload(args, "correlate")?;
    let response = state.service.correlate().events(req).await?;
    Ok(serde_json::to_value(response)?)
}

pub(super) fn string_arg(args: &Value, name: &str) -> Option<String> {
    args.get(name).and_then(|v| v.as_str()).map(String::from)
}

/// Build a caller-input error that the MCP error classifier maps to
/// `invalid_params` (full-review AH1). All argument-shape failures in this
/// module MUST go through this so classification is type-driven, not
/// string-matched.
fn invalid_input(message: String) -> anyhow::Error {
    anyhow::Error::from(crate::app::ServiceError::InvalidInput(message))
}

pub(super) fn action_payload<T: DeserializeOwned>(args: Value, action: &str) -> anyhow::Result<T> {
    let mut object = args
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_input("tool arguments must be a JSON object".to_string()))?;
    object.remove("action");
    serde_json::from_value(Value::Object(object))
        .map_err(|err| invalid_input(format!("invalid {action} arguments: {err}")))
}

// ---------------------------------------------------------------------------
// Error detection actions

async fn tool_unaddressed_errors(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: UnaddressedErrorsRequest = action_payload(args, "unaddressed_errors")?;
    let resp = state.service.alerts().signatures(req).await?;
    Ok(serde_json::to_value(resp)?)
}

async fn tool_notifications_recent(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: NotificationsRecentRequest = action_payload(args, "notifications_recent")?;
    let firings = state.service.alerts().notifications(req).await?;
    Ok(serde_json::to_value(firings)?)
}

async fn tool_llm_invocations(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: LlmInvocationsRequest = action_payload(args, "llm_invocations")?;
    let rows = state.service.llm_invocations_checked(req).await?;
    Ok(serde_json::to_value(rows)?)
}

async fn tool_file_tails(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let req: crate::app::FileTailRequest = action_payload(args, "file_tails")?;
    let resp = state.service.ingest().file_tails(req).await?;
    Ok(serde_json::to_value(resp)?)
}

/// Parse an optional RFC3339 timestamp string and normalize it to UTC.
///
/// Returns `Ok(None)` when `raw` is `None`. Returns a descriptive error when
/// `raw` is `Some` but not valid RFC3339 — callers get a clear message rather
/// than a silent wrong-result query against UTC-stored timestamps.
#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
