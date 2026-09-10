use super::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiIncidentRequest {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    #[serde(default)]
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiIncidentResponse {
    pub incidents: Vec<AbuseIncident>,
    pub total_incidents: usize,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIncident {
    pub incident_id: String,
    pub project: String,
    pub tool: String,
    pub session_id: String,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub duration_secs: i64,
    pub abuse_count: usize,
    pub terms: Vec<String>,
    pub anchor_ids: Vec<i64>,
    pub priority_score: f64,
    pub priority_label: String,
    pub window_minutes: u32,
}

impl From<db::AbuseIncident> for AbuseIncident {
    fn from(v: db::AbuseIncident) -> Self {
        Self {
            incident_id: v.incident_id,
            project: v.project,
            tool: v.tool,
            session_id: v.session_id,
            hostname: v.hostname,
            first_seen: v.first_seen,
            last_seen: v.last_seen,
            duration_secs: v.duration_secs,
            abuse_count: v.abuse_count,
            terms: v.terms,
            anchor_ids: v.anchor_ids,
            priority_score: v.priority_score,
            priority_label: v.priority_label,
            window_minutes: v.window_minutes,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiInvestigateRequest {
    // `incident_id` exists on the service-layer request but is NOT part of the
    // `/api/sessions/investigate` query surface (`AiInvestigateQuery` in api.rs uses
    // `deny_unknown_fields`). serde_qs emits `None` options as a bare key
    // (`incident_id&project&...`), which the server rejects as an unknown
    // field. Skipping when `None` keeps the CLI HTTP path (which always sets
    // `None`) from emitting the param. See cortex-fzj7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    #[serde(default)]
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvidence {
    pub incident: AbuseIncident,
    pub transcript_before: Vec<LogEntry>,
    pub transcript_before_truncated: bool,
    pub transcript_after: Vec<LogEntry>,
    pub transcript_after_truncated: bool,
    pub anchors: Vec<LogEntry>,
    pub nearby_logs: Vec<LogEntry>,
    pub nearby_logs_truncated: bool,
    pub nearby_errors: Vec<LogEntry>,
    /// Deterministic, rule-based failure hypotheses and prevention hints
    /// derived from this bundle (bead kmib.4). Never an LLM summary — see
    /// [`crate::app::incident_findings`].
    pub findings: incident_findings::IncidentFindings,
}

impl From<db::IncidentEvidence> for IncidentEvidence {
    fn from(v: db::IncidentEvidence) -> Self {
        let incident: AbuseIncident = v.incident.into();
        let transcript_before: Vec<LogEntry> =
            v.transcript_before.into_iter().map(Into::into).collect();
        let transcript_after: Vec<LogEntry> =
            v.transcript_after.into_iter().map(Into::into).collect();
        let anchors: Vec<LogEntry> = v.anchors.into_iter().map(Into::into).collect();
        let nearby_logs: Vec<LogEntry> = v.nearby_logs.into_iter().map(Into::into).collect();
        let nearby_errors: Vec<LogEntry> = v.nearby_errors.into_iter().map(Into::into).collect();

        let findings = incident_findings::derive_incident_findings(
            &incident,
            &anchors,
            &transcript_before,
            &transcript_after,
            &nearby_logs,
            &nearby_errors,
        );

        Self {
            incident,
            transcript_before,
            transcript_before_truncated: v.transcript_before_truncated,
            transcript_after,
            transcript_after_truncated: v.transcript_after_truncated,
            anchors,
            nearby_logs,
            nearby_logs_truncated: v.nearby_logs_truncated,
            nearby_errors,
            findings,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigateResponse {
    pub evidence: Vec<IncidentEvidence>,
    pub total_incidents: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAssessRequest {
    pub incident_id: String,
    pub model: Option<String>,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    #[serde(default)]
    pub terms: Vec<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAssessEvidenceSummary {
    pub total_incidents: usize,
    pub evidence_bundle_count: usize,
    pub total_anchors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAssessResponse {
    pub incident_id: String,
    pub assessment: String,
    pub prompt_preview: String,
    pub evidence_summary: AiAssessEvidenceSummary,
}

/// Request for `cortex assess abuse` — a UX wrapper around the existing
/// `list_ai_incidents` + `run_assess_with_delta` pipeline (the
/// latter already routes through PR 1's `LlmRunner` internally — this
/// wrapper adds zero new LLM call sites). When `incident_id` is `None`,
/// the top-priority matching incident (by `AbuseIncident::priority_score`)
/// is auto-selected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseAssessRequest {
    pub incident_id: Option<String>,
    pub model: Option<String>,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    #[serde(default)]
    pub terms: Vec<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseAssessResponse {
    pub assessed: AiAssessResponse,
    /// Other candidate incident ids that matched the same filters but were
    /// not auto-selected (populated only on the auto-pick path, i.e. when
    /// `incident_id` was `None` in the request and more than one incident
    /// matched).
    pub other_matching_incidents: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiCorrelateRequest {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub session_id: Option<String>,
    pub ai_query: Option<String>,
    pub log_query: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub app: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub severity_min: Option<String>,
    pub limit: Option<u32>,
    pub events_per_anchor: Option<u32>,
}

impl AiCorrelateRequest {
    pub fn normalize_limits(mut self, policy: AiCorrelateLimitPolicy) -> (Self, Option<u32>) {
        let clamped_to = self
            .events_per_anchor
            .filter(|value| *value > policy.events_per_anchor_cap)
            .map(|_| policy.events_per_anchor_cap);
        if let Some(cap) = clamped_to {
            self.events_per_anchor = Some(cap);
        }
        let reported = if policy.report_events_per_anchor_clamp {
            clamped_to
        } else {
            None
        };
        (self, reported)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCorrelationAnchor {
    pub entry: LogEntry,
    pub window_from: String,
    pub window_to: String,
    pub related: Vec<LogEntry>,
    pub related_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCorrelateResponse {
    pub window_minutes: u32,
    pub severity_min: String,
    pub total_anchors: usize,
    pub anchor_rows: usize,
    pub anchor_limit: usize,
    pub anchors_truncated: bool,
    pub related_limit_per_anchor: usize,
    pub total_related_events: usize,
    pub anchors: Vec<AiCorrelationAnchor>,
    /// Set by the REST handler when the caller-supplied `events_per_anchor`
    /// exceeded the server-side hard cap of 50 and was clamped down. Omitted
    /// on MCP responses, which use the service-layer clamp (200) only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_per_anchor_clamped_to: Option<u32>,
    /// Graph-anchored, session-scoped correlation. Populated only when the
    /// request targets a specific `session_id`: the graph is traversed from the
    /// session entity to discover related hosts, and logs are fanned out across
    /// all source kinds within the session's time bounds. Additive — absent for
    /// project/tool/query correlations, which keep the time-windowed anchor path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_correlation: Option<GraphSessionCorrelation>,
}

/// Request for `topic_correlate`: a free-text topic resolved to graph entities,
/// expanded, and correlated across all source kinds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicCorrelateRequest {
    /// Topic string, e.g. `axon` or `devhost dns adguard` (terms OR-ed).
    pub topic: String,
    pub since: Option<String>,
    pub until: Option<String>,
    /// Graph traversal depth (default 2, clamped to 6).
    pub depth: Option<u8>,
    /// Restrict the timeline to these source kinds (kebab-case wire names).
    #[serde(default, deserialize_with = "deserialize_optional_string_vec")]
    pub source_kinds: Option<Vec<String>>,
    pub limit: Option<u32>,
}

/// Accept `source_kinds` as either a JSON string or an array of strings, for
/// CLI bridges that cannot emit arrays. `null`/absent → `None`; a single string
/// → a one-element vec. Non-string array elements (or any other scalar) are a
/// hard deserialization error. Element *validity* (kebab-case wire names) is
/// enforced later in `topic_correlate` against `SourceKind::from_wire`.
fn deserialize_optional_string_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<serde_json::Value> as serde::Deserialize>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(vec![value])),
        Some(serde_json::Value::Array(values)) => values
            .into_iter()
            .map(|value| match value {
                serde_json::Value::String(value) => Ok(value),
                _ => Err(serde::de::Error::custom(
                    "source_kinds must be a string or an array of strings",
                )),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(serde::de::Error::custom(
            "source_kinds must be a string or an array of strings",
        )),
    }
}

/// A graph entity a topic term resolved to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTopicEntity {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub key: String,
    /// How it matched: `exact`, `prefix`, `label`, or `alias`.
    pub match_kind: String,
    /// Resolver outcome: `resolved` for exact canonical-key and alias
    /// identity matches, `ambiguous` for weak label/prefix candidates that
    /// never drive log fan-out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_status: Option<String>,
}

/// An entity reached by graph expansion from the resolved seeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicExpansionEntity {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub key: String,
}

/// One unified-timeline row in a topic correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicTimelineEntry {
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
    /// Discovery lane: `agent_command`, `shell_history`, or `graph:host:<host>`.
    pub entity_path: String,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Why this row is in the timeline (`service_instance`, `graph_related`,
    /// `host_context`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_reason: Option<String>,
    /// Resolver outcome for this row's inclusion path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_status: Option<String>,
    /// Set when the row was included by an explicit degraded fallback
    /// (`explicit_degraded_host_context`), never silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_kind: Option<String>,
}

/// Response for `topic_correlate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicCorrelateResponse {
    pub topic: String,
    /// Current materialized graph state. Callers can distinguish a graph-backed
    /// result from an explicitly degraded direct-source fallback without
    /// inferring projection health from an empty entity list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_projection: Option<GraphProjectionStatusResponse>,
    pub resolved_entities: Vec<ResolvedTopicEntity>,
    pub graph_expansion: Vec<TopicExpansionEntity>,
    pub discovered_hosts: Vec<String>,
    pub timeline: Vec<TopicTimelineEntry>,
    pub heartbeat_summaries: Vec<db::HeartbeatWindowSummary>,
    /// `true` when the fanned-out log timeline hit `limit` and was cut off.
    pub truncated: bool,
    /// `true` when the service-topic graph walk hit its entity cap
    /// (`GRAPH_SERVICE_TOPIC_ENTITY_CAP`) and the discovered service-instance
    /// neighborhood was cut off rather than exhaustive. Independent of
    /// `truncated`, which reflects the log timeline, not the graph walk.
    pub graph_walk_truncated: bool,
}

/// One log row in a graph-anchored session correlation, annotated with how it
/// was reached and which source lane it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedLogRow {
    pub entry: LogEntry,
    /// Source kind parsed from the row (`agent-command`, `shell-history`,
    /// `syslog-udp`, `docker-stream`, …); `None` if not recorded on the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
    /// How the graph traversal reached this row: `agent_command`,
    /// `shell_history`, or `graph:host:<hostname>`.
    pub discovery: String,
}

/// Graph-anchored, session-scoped correlation result for `ai_correlate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSessionCorrelation {
    pub session_id: String,
    pub session_start: String,
    pub session_end: String,
    /// `true` when the session's `ai_session` graph entity was found and used to
    /// discover related hosts; `false` for the time-windowed fallback (session
    /// not yet projected into the graph).
    pub used_graph: bool,
    pub discovered_hosts: Vec<String>,
    pub discovered_entities: Vec<String>,
    pub logs: Vec<CorrelatedLogRow>,
    /// Count of agent-command rows (Claude's bash tool calls) in this session.
    pub agent_command_count: usize,
    /// Count of shell-history rows (the operator's own shell) in the window.
    pub shell_history_count: usize,
    /// Heartbeat pressure summaries for the discovered hosts over the window.
    pub heartbeat_summaries: Vec<db::HeartbeatWindowSummary>,
    pub truncated: bool,
}
