use serde::{Deserialize, Serialize};

use super::{AiSessionEntry, LogEntry};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiIncidentParams {
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub terms: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiIncidentResult {
    pub incidents: Vec<AbuseIncident>,
    pub total_incidents: usize,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiInvestigateParams {
    pub incident_id: Option<String>,
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInvestigateResult {
    pub evidence: Vec<IncidentEvidence>,
    pub total_incidents: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SimilarIncidentsParams {
    pub query: String,
    pub host: Option<String>,
    pub app: Option<String>,
    pub severity_min: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCluster {
    pub hostname: String,
    pub app_name: Option<String>,
    pub window_start: String,
    pub window_end: String,
    pub log_count: i64,
    pub severity_peak: String,
    pub representative_messages: Vec<String>,
    pub correlated_sessions: Vec<CorrelatedSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedSession {
    pub session_id: String,
    pub project: String,
    pub tool: String,
    pub match_count: i64,
    pub best_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarIncidentsResult {
    pub query: String,
    pub total_clusters: usize,
    pub truncated: bool,
    pub clusters: Vec<IncidentCluster>,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentContextParams {
    pub since: String,
    pub until: String,
    pub host: Option<String>,
    pub app: Option<String>,
    pub query: Option<String>,
    pub severity_min: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLogCount {
    pub app_name: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentContextResult {
    pub window_from: String,
    pub window_to: String,
    pub total_logs: i64,
    pub by_severity: Vec<SeverityCount>,
    pub by_app: Vec<AppLogCount>,
    pub error_logs: Vec<LogEntry>,
    pub error_logs_truncated: bool,
    pub ai_sessions: Vec<AiSessionEntry>,
}
