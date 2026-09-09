use serde::{Deserialize, Serialize};

fn serialize_id<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_optional_id<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct RepositoryQuery {
    pub host: Option<String>,
    pub query: Option<String>,
    pub active_runs_only: bool,
    pub include_removed: bool,
    pub since: Option<String>,
    pub until: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentRunQuery {
    pub repository_id: Option<i64>,
    pub worktree_id: Option<i64>,
    pub branch: Option<String>,
    pub statuses: Vec<String>,
    pub tools: Vec<String>,
    pub host: Option<String>,
    pub query: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub active_only: bool,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentEventQuery {
    pub kinds: Vec<String>,
    pub severity_min: Option<i64>,
    pub actor_key: Option<String>,
    pub trace_id: Option<String>,
    pub query: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub include_payload: bool,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct TelemetryQuery {
    pub trace_id: Option<String>,
    pub metric_name: Option<String>,
    pub since_nano: Option<i64>,
    pub until_nano: Option<i64>,
}
#[derive(Debug, Clone)]
pub struct RunTelemetryIdentity {
    pub hostname: String,
    pub tool: String,
    pub provider_tool: Option<String>,
    pub native_session_id: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryRepositoryRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub key: String,
    pub hostname: String,
    pub primary_path: String,
    pub name: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub removed_at: Option<String>,
    pub worktree_count: i64,
    pub active_run_count: i64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryWorktreeRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub key: String,
    #[serde(serialize_with = "serialize_id")]
    pub repository_id: i64,
    pub hostname: String,
    pub path: String,
    pub branch_ref: Option<String>,
    pub branch: Option<String>,
    pub head_sha: Option<String>,
    pub upstream_ref: Option<String>,
    pub detached: bool,
    pub bare: bool,
    pub locked: bool,
    pub lock_reason: Option<String>,
    pub prunable: bool,
    pub prune_reason: Option<String>,
    pub dirty: bool,
    pub staged: i64,
    pub unstaged: i64,
    pub untracked: i64,
    pub ahead: Option<i64>,
    pub behind: Option<i64>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub removed_at: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryRunRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub run_key: String,
    pub native_session_id: String,
    pub tool: String,
    pub provider_tool: Option<String>,
    pub hostname: String,
    pub status: String,
    pub status_reason: String,
    pub status_observed_at: String,
    pub started_at: String,
    pub last_activity_at: String,
    pub ended_at: Option<String>,
    pub transcript_path: Option<String>,
    #[serde(serialize_with = "serialize_optional_id")]
    pub primary_worktree_id: Option<i64>,
    pub primary_branch: Option<String>,
    pub start_head_sha: Option<String>,
    pub current_head_sha: Option<String>,
    pub event_count: i64,
    pub error_count: i64,
    pub freshness_json: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryEventRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub event_key: String,
    pub run_key: String,
    pub actor_key: Option<String>,
    #[serde(serialize_with = "serialize_optional_id")]
    pub worktree_id: Option<i64>,
    pub commit_sha: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub kind: String,
    pub source_kind: String,
    pub source_id: String,
    #[serde(serialize_with = "serialize_optional_id")]
    pub source_log_id: Option<i64>,
    pub provider_sequence: Option<i64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub payload_json: Option<String>,
    pub content_scrubbed: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatorySpanRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: i64,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub duration_nano: i64,
    pub status_code: i64,
    pub status_message: Option<String>,
    pub service_name: Option<String>,
    pub attributes_json: String,
    pub relation_namespace: String,
    pub relation_evidence_kind: String,
    pub relation_confidence: f64,
    pub relation_reason: String,
    pub relation_candidate_count: i64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryMetricRow {
    #[serde(serialize_with = "serialize_id")]
    pub id: i64,
    pub point_key: String,
    pub metric_name: String,
    pub description: String,
    pub unit: String,
    pub instrument_kind: String,
    pub start_time_unix_nano: Option<i64>,
    pub time_unix_nano: i64,
    pub value_json: String,
    pub attributes_json: String,
    pub exemplars_json: String,
}
