use super::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSessionsRequest {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub host: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    pub count: usize,
    pub sessions: Vec<AiSessionEntry>,
    /// When the unbounded (no time-window) result was served from the
    /// periodically-refreshed AI session rollup, this is the RFC 3339 time of
    /// that rollup's last refresh — i.e. the data's `as_of` staleness bound.
    /// `None` means the result is live (a time-windowed query, or the rollup
    /// had not been refreshed yet so the live aggregation was used). See bead
    /// cortex-2vre.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollup_as_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSessionEntry {
    /// Stable response-local key for this host/tool/project/session tuple.
    pub session_key: String,
    pub project: String,
    pub tool: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_path: Option<String>,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_provenance: Option<String>,
}

impl From<db::AiSessionEntry> for AiSessionEntry {
    fn from(value: db::AiSessionEntry) -> Self {
        let session_key = ai_session_key(
            &value.hostname,
            &value.ai_tool,
            &value.ai_project,
            &value.ai_session_id,
        );
        Self {
            session_key,
            project: value.ai_project,
            tool: value.ai_tool,
            session_id: value.ai_session_id,
            transcript_path: value.ai_transcript_path,
            hostname: value.hostname,
            first_seen: value.first_seen,
            last_seen: value.last_seen,
            event_count: value.event_count,
            title: value.title,
            title_provenance: value.title_provenance,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchSessionsRequest {
    pub query: String,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchedSessionEntry {
    /// Stable response-local key for this host/tool/project/session tuple.
    pub session_key: String,
    pub project: String,
    pub tool: String,
    pub session_id: String,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
    pub match_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_provenance: Option<String>,
}

impl From<db::SearchedAiSessionEntry> for SearchedSessionEntry {
    fn from(value: db::SearchedAiSessionEntry) -> Self {
        let session_key = ai_session_key(
            &value.hostname,
            &value.ai_tool,
            &value.ai_project,
            &value.ai_session_id,
        );
        Self {
            session_key,
            project: value.ai_project,
            tool: value.ai_tool,
            session_id: value.ai_session_id,
            hostname: value.hostname,
            first_seen: value.first_seen,
            last_seen: value.last_seen,
            event_count: value.event_count,
            match_count: value.match_count,
            best_snippet: value.best_snippet,
            title: value.title,
            title_provenance: value.title_provenance,
        }
    }
}

fn ai_session_key(hostname: &str, tool: &str, project: &str, session_id: &str) -> String {
    [hostname, tool, project, session_id]
        .into_iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSessionsResponse {
    pub total_candidates: usize,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
    pub sessions: Vec<SearchedSessionEntry>,
    /// Set by the REST handler when the caller-supplied `limit` exceeded the
    /// server-side hard cap and was clamped down. Omitted from MCP/non-REST
    /// responses, where no clamp is applied at this layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_clamped_to: Option<u32>,
}

impl From<db::SearchAiSessionsResult> for SearchSessionsResponse {
    fn from(value: db::SearchAiSessionsResult) -> Self {
        Self {
            total_candidates: value.total_candidates,
            candidate_rows: value.candidate_rows,
            candidate_cap: value.candidate_cap,
            candidate_window_truncated: value.candidate_window_truncated,
            truncated: value.truncated,
            sessions: value.sessions.into_iter().map(Into::into).collect(),
            limit_clamped_to: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseSearchRequest {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub before: Option<u32>,
    pub after: Option<u32>,
    #[serde(default)]
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseMatch {
    pub term: String,
    pub entry: LogEntry,
    pub before: Vec<LogEntry>,
    pub after: Vec<LogEntry>,
}

impl From<db::AiAbuseMatch> for AbuseMatch {
    fn from(value: db::AiAbuseMatch) -> Self {
        Self {
            term: value.term,
            entry: value.entry.into(),
            before: value.before.into_iter().map(Into::into).collect(),
            after: value.after.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseSearchResponse {
    pub terms: Vec<String>,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
    pub matches: Vec<AbuseMatch>,
    /// Set by the REST handler when the caller-supplied `limit` exceeded the
    /// server-side hard cap and was clamped down. Omitted on MCP responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_clamped_to: Option<u32>,
}

impl From<db::AiAbuseResult> for AbuseSearchResponse {
    fn from(value: db::AiAbuseResult) -> Self {
        Self {
            terms: value.terms,
            candidate_rows: value.candidate_rows,
            candidate_cap: value.candidate_cap,
            candidate_window_truncated: value.candidate_window_truncated,
            truncated: value.truncated,
            matches: value.matches.into_iter().map(Into::into).collect(),
            limit_clamped_to: None,
        }
    }
}
