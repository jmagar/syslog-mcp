use super::*;

// ---------------------------------------------------------------------------
// RAG v1: similar_incidents, incident_context
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimilarIncidentsRequest {
    pub query: String,
    pub host: Option<String>,
    pub app: Option<String>,
    pub severity_min: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    /// Cluster window in minutes. Default 30, clamp 5..=120.
    pub window_minutes: Option<u32>,
    /// Max clusters to return. Default 10, clamp 1..=50.
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedSession {
    pub session_id: String,
    pub project: String,
    pub tool: String,
    pub match_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_snippet: Option<String>,
}

impl From<db::CorrelatedSession> for CorrelatedSession {
    fn from(v: db::CorrelatedSession) -> Self {
        Self {
            session_id: v.session_id,
            project: v.project,
            tool: v.tool,
            match_count: v.match_count,
            best_snippet: v.best_snippet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCluster {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    pub window_start: String,
    pub window_end: String,
    pub log_count: i64,
    pub severity_peak: String,
    pub representative_messages: Vec<String>,
    pub correlated_sessions: Vec<CorrelatedSession>,
}

impl From<db::IncidentCluster> for IncidentCluster {
    fn from(v: db::IncidentCluster) -> Self {
        Self {
            hostname: v.hostname,
            app_name: v.app_name,
            window_start: v.window_start,
            window_end: v.window_end,
            log_count: v.log_count,
            severity_peak: v.severity_peak,
            representative_messages: v.representative_messages,
            correlated_sessions: v.correlated_sessions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarIncidentsResponse {
    pub query: String,
    pub total_clusters: usize,
    pub truncated: bool,
    pub clusters: Vec<IncidentCluster>,
}

impl From<db::SimilarIncidentsResult> for SimilarIncidentsResponse {
    fn from(v: db::SimilarIncidentsResult) -> Self {
        Self {
            query: v.query,
            total_clusters: v.total_clusters,
            truncated: v.truncated,
            clusters: v.clusters.into_iter().map(Into::into).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Recurring error comparison — bounded, canonical-source evidence bundles
// ---------------------------------------------------------------------------

/// Compare recurring error signatures in a focal window with the immediately
/// preceding window of the same duration.  Supplying `until` makes replay
/// deterministic; without it, the server uses its current UTC clock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringErrorComparisonRequest {
    /// Restrict to one canonical signature hash when drilling down.
    pub signature_hash: Option<String>,
    /// Start of the focal comparison window. Defaults to `until - window_minutes`.
    pub since: Option<String>,
    /// End of the focal comparison window. Defaults to current UTC time.
    pub until: Option<String>,
    /// Focal-window width when `since` is omitted. Default 60, clamp 5..=1440.
    pub window_minutes: Option<u32>,
    /// Maximum ranked signatures. Default 10, clamp 1..=50.
    pub limit: Option<u32>,
    /// Include acknowledged signatures. Default false.
    pub include_acknowledged: Option<bool>,
}

/// Redaction/version policy applied before a bundle crosses the service
/// boundary.  The policy is part of both the response and bundle identity, so
/// a caller cannot confuse a raw or differently redacted projection with this
/// safe projection.
pub const RECURRING_ERROR_PRIVACY_POLICY_V1: &str = "irreversible_redaction/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecurringErrorEvidenceBundle {
    /// SHA-256 over canonical source keys, comparison bounds, evidence revision,
    /// and the privacy policy. Never derived from display/sample strings.
    pub bundle_id: String,
    pub schema_version: String,
    pub privacy_policy: String,
    pub source_key: String,
    pub evidence_revision: String,
    /// Graph provenance handles. Follow them through `graph` mode `evidence`;
    /// these are bounded and intentionally do not embed raw evidence payloads.
    pub graph_evidence_ids: Vec<i64>,
    pub graph_evidence_truncated: bool,
    pub retention_or_projection_gap: bool,
    pub focal_boundary_windows: i64,
    pub baseline_boundary_windows: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringErrorComparisonEntry {
    pub signature_hash: String,
    pub normalizer_version: i64,
    pub severity: String,
    pub focal_count: i64,
    pub baseline_count: i64,
    pub count_delta: i64,
    pub total_count: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
    /// Irreversibly scrubbed and bounded display fields. The raw source row is
    /// not placed in this model or a cache.
    pub safe_template: String,
    pub safe_sample_message: String,
    pub safe_hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_app_name: Option<String>,
    pub evidence: RecurringErrorEvidenceBundle,
    /// An actionable, bounded follow-up. It is evidence-ranked, not a causal
    /// explanation.
    pub next_query: RecurringErrorNextQuery,
    pub explanation: String,
    pub open_questions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecurringErrorNextQuery {
    pub action: String,
    pub mode: String,
    pub entity_type: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringErrorComparisonResponse {
    pub focal_from: String,
    pub focal_to: String,
    pub baseline_from: String,
    pub baseline_to: String,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub results_truncated: bool,
    pub privacy_policy: String,
    pub comparisons: Vec<RecurringErrorComparisonEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentContextRequest {
    /// Start of the incident window. Defaults to one hour before `until`.
    pub since: Option<String>,
    /// End of the incident window. Defaults to now.
    pub until: Option<String>,
    pub host: Option<String>,
    pub app: Option<String>,
    pub query: Option<String>,
    pub severity_min: Option<String>,
    /// Max error log rows. Default 50, clamp 1..=200.
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

impl From<db::SeverityCount> for SeverityCount {
    fn from(v: db::SeverityCount) -> Self {
        Self {
            severity: v.severity,
            count: v.count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLogCount {
    pub app_name: Option<String>,
    pub count: i64,
}

impl From<db::AppLogCount> for AppLogCount {
    fn from(v: db::AppLogCount) -> Self {
        Self {
            app_name: v.app_name,
            count: v.count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentContextResponse {
    pub window_from: String,
    pub window_to: String,
    pub total_logs: i64,
    pub by_severity: Vec<SeverityCount>,
    pub by_app: Vec<AppLogCount>,
    pub error_logs: Vec<LogEntry>,
    pub error_logs_truncated: bool,
    pub ai_sessions: Vec<AiSessionEntry>,
}

impl From<db::IncidentContextResult> for IncidentContextResponse {
    fn from(v: db::IncidentContextResult) -> Self {
        Self {
            window_from: v.window_from,
            window_to: v.window_to,
            total_logs: v.total_logs,
            by_severity: v.by_severity.into_iter().map(Into::into).collect(),
            by_app: v.by_app.into_iter().map(Into::into).collect(),
            error_logs: v.error_logs.into_iter().map(Into::into).collect(),
            error_logs_truncated: v.error_logs_truncated,
            ai_sessions: v.ai_sessions.into_iter().map(Into::into).collect(),
        }
    }
}
