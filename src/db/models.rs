use serde::{Deserialize, Serialize};

mod incident;
pub use incident::*;
mod search;
pub use search::*;

/// Named struct for a log entry used in batch insertion and the syslog parse pipeline.
///
/// Replaces the former 8-tuple type alias; named fields prevent silent data corruption
/// from positional swaps between structurally identical `String`/`Option<String>` fields.
///
/// For syslog input, `source_ip` records the actual network sender address (IP:port)
/// independent of the hostname claimed in the syslog message body. OTLP stores the
/// peer IP without the ephemeral port. Docker ingest uses configured
/// `docker://host/container/stream` and `docker-event://host/container/action`
/// source identifiers instead.
#[derive(Debug, Clone)]
pub struct LogBatchEntry {
    pub timestamp: String,
    pub hostname: String,
    pub facility: Option<String>,
    pub severity: String,
    pub app_name: Option<String>,
    pub process_id: Option<String>,
    pub message: String,
    pub raw: String,
    /// Source identifier. Syslog input uses the actual network sender address
    /// (IP:port); OTLP uses peer IP; Docker ingest uses
    /// docker://host/container/stream and docker-event://host/container/action.
    pub source_ip: String,
    pub docker_checkpoint: Option<DockerCheckpoint>,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub ai_transcript_path: Option<String>,
    pub metadata_json: Option<String>,
    /// HTTP status code (3 digits). Indexed column. Set by `swag` parser.
    pub http_status: Option<i32>,

    /// Authentication outcome ("success" | "failure" | "denied" | "challenge").
    /// Indexed column. Set by `authelia` parser.
    pub auth_outcome: Option<&'static str>,

    /// DNS block decision. `Some(true)` = filtered/blocked, `Some(false)` = explicit
    /// allow, `None` = N/A (rewrites and non-DNS rows). Indexed column.
    pub dns_blocked: Option<bool>,

    /// Normalised event verb (closed enum per parser). Indexed column.
    pub event_action: Option<String>,

    /// Per-row parser diagnostic: "{parser_name}: {ParserError::Display}",
    /// truncated to 512 bytes. No index — diagnostic only.
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DockerCheckpoint {
    pub host_name: String,
    pub container_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default)]
pub struct ListAiSessionsParams {
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub host: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiSessionEntry {
    pub ai_project: String,
    pub ai_tool: String,
    pub ai_session_id: String,
    pub ai_transcript_path: Option<String>,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
    pub title: Option<String>,
    pub title_provenance: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RenderedSessionEventRow {
    pub id: i64,
    pub timestamp: String,
    pub message: String,
    pub metadata_json: Option<String>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RenderedSessionPageParams {
    pub ai_project: String,
    pub ai_tool: String,
    pub ai_session_id: String,
    pub host: String,
    pub after_id: i64,
    pub limit: u32,
}

#[derive(Debug, Clone)]
pub struct DurableStreamRow {
    pub id: i64,
    pub timestamp: String,
    pub hostname: String,
    pub severity: String,
    pub app_name: Option<String>,
    pub message: String,
    pub metadata_json: Option<String>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DurableStreamParams {
    pub after_id: i64,
    pub high_watermark: Option<i64>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub severity: Option<String>,
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub ai_session_id: Option<String>,
    pub limit: u32,
    /// Bounds are needed only during the initial snapshot/resume check.  The
    /// steady-state poll path must remain one indexed keyset query.
    pub include_bounds: bool,
}

#[derive(Debug, Clone)]
pub struct DurableStreamPage {
    pub rows: Vec<DurableStreamRow>,
    pub minimum_watermark: Option<i64>,
    pub high_watermark: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SearchAiSessionsParams {
    pub query: String,
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    /// Filter AI transcript sessions to those where the session's host matches.
    pub host: Option<String>,
    /// Filter AI transcript sessions to those where the session's app matches.
    pub app: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

/// Error/warning summary entry (one row per hostname+severity, plus optional app_name)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummaryEntry {
    pub hostname: String,
    /// Populated when the summary was requested with `group_by=app_name`.
    pub app_name: Option<String>,
    pub severity: String,
    pub count: i64,
}

/// Host registry entry with first/last seen and log count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub log_count: i64,
}

/// Database statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total_logs: i64,
    pub total_hosts: i64,
    pub oldest_log: Option<String>,
    pub newest_log: Option<String>,
    /// Formatted as "X.XX" MB
    pub logical_db_size_mb: String,
    /// Formatted as "X.XX" MB
    pub physical_db_size_mb: String,
    /// Formatted as "X.XX" MB when available
    pub free_disk_mb: Option<String>,
    pub max_db_size_mb: u64,
    pub min_free_disk_mb: u64,
    pub write_blocked: bool,
    /// Phantom FTS rows: entries in logs_fts that no longer have a matching log row.
    /// Accumulate between merge cycles; non-zero value is normal and cleaned up by
    /// periodic fts_incremental_merge. High values indicate merge is falling behind.
    ///
    /// `None` when the FTS diagnostic was skipped: computing it requires
    /// `COUNT(*) FROM logs_fts`, an external-content FTS5 index scan that is
    /// expensive on very large databases. The default `stats` path skips it;
    /// pass `include_fts_diagnostics` to compute it explicitly.
    pub phantom_fts_rows: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchedAiSessionEntry {
    pub ai_project: String,
    pub ai_tool: String,
    pub ai_session_id: String,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
    pub match_count: i64,
    pub best_snippet: Option<String>,
    pub title: Option<String>,
    pub title_provenance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchAiSessionsResult {
    pub total_candidates: usize,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
    pub sessions: Vec<SearchedAiSessionEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct AiAbuseParams {
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub before: Option<u32>,
    pub after: Option<u32>,
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAbuseMatch {
    pub term: String,
    pub entry: LogEntry,
    pub before: Vec<LogEntry>,
    pub after: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAbuseResult {
    pub terms: Vec<String>,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub truncated: bool,
    pub matches: Vec<AiAbuseMatch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiCorrelateParams {
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub ai_session_id: Option<String>,
    pub ai_query: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRelatedWindow {
    pub anchor_index: usize,
    pub anchor_time: String,
    pub window_from: String,
    pub window_to: String,
}

/// DB-layer carrier for graph-anchored session correlation: the session time
/// bounds, the entities/hosts discovered by traversing the graph from the
/// session entity, and the fanned-out logs. `used_graph` is false when no
/// `ai_session` graph entity exists for the session (time-windowed fallback).
#[derive(Debug, Clone, Default)]
pub struct SessionGraphInputs {
    pub bounds: Option<(String, String)>,
    pub discovered_hosts: Vec<String>,
    pub discovered_entities: Vec<String>,
    pub used_graph: bool,
    pub logs: Vec<LogEntry>,
}

/// A graph entity matched while resolving a topic string, with how it matched
/// (`exact` canonical key, `prefix` of a key, or `alias`).
#[derive(Debug, Clone)]
pub struct ResolvedTopicEntity {
    pub entity_type: String,
    pub canonical_key: String,
    pub match_kind: &'static str,
    /// Resolver outcome: `Resolved` for exact canonical-key and alias
    /// identity matches, `Ambiguous` for weak prefix/label candidates that
    /// never drive log fan-out. Stringified via
    /// [`super::entity_resolution::ResolverStatus::as_str`] only at the serde
    /// boundary.
    pub resolver_status: super::entity_resolution::ResolverStatus,
}

/// One correlated log row annotated with why it was included and the
/// resolver outcome for its inclusion path.
#[derive(Debug, Clone)]
pub struct GraphRelatedLogEntry {
    pub entry: LogEntry,
    pub inclusion_reason: String,
    pub resolver_status: super::entity_resolution::ResolverStatus,
    pub fallback_kind: Option<String>,
}

/// DB-layer carrier for topic correlation: the entities the topic resolved to,
/// the entities/hosts reached by graph expansion, and the fanned-out logs.
#[derive(Debug, Clone, Default)]
pub struct TopicGraphInputs {
    pub resolved: Vec<ResolvedTopicEntity>,
    /// Entities reached by traversal that were not themselves resolved seeds.
    pub expansion: Vec<(String, String)>,
    pub discovered_hosts: Vec<String>,
    pub logs: Vec<GraphRelatedLogEntry>,
    /// `true` when the service-topic graph walk
    /// ([`super::graph_resolver_projection::graph_walk_service_topic`]) hit
    /// `GRAPH_SERVICE_TOPIC_ENTITY_CAP` and the reached neighborhood was cut
    /// off rather than exhaustive.
    pub graph_walk_truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiRelatedLogsParams {
    pub windows: Vec<AiRelatedWindow>,
    pub query: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub severity_in: Vec<String>,
    pub app: Option<String>,
    pub limit_per_anchor: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRelatedLogsForAnchor {
    pub anchor_index: usize,
    pub logs: Vec<LogEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiUsageBlocksParams {
    pub ai_project: Option<String>,
    pub ai_tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiUsageBlock {
    pub bucket_start: String,
    pub bucket_end: String,
    pub project: String,
    pub tool: String,
    pub session_count: i64,
    pub event_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiUsageBlocksResult {
    pub total_blocks: usize,
    pub truncated: bool,
    pub blocks: Vec<AiUsageBlock>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiProjectContextParams {
    pub project: String,
    pub ai_tool: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProjectContext {
    pub project: String,
    pub tools: Vec<String>,
    pub sessions: Vec<String>,
    pub hostnames: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub event_count: i64,
    pub recent_entries_truncated: bool,
    pub recent_entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListAiToolsParams {
    pub ai_project: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiToolInventoryEntry {
    pub tool: String,
    pub event_count: i64,
    pub session_count: i64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAiToolsResult {
    pub total_tools: usize,
    pub truncated: bool,
    pub tools: Vec<AiToolInventoryEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListAiProjectsParams {
    pub ai_tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProjectInventoryEntry {
    pub project: String,
    pub tools: Vec<String>,
    pub event_count: i64,
    pub session_count: i64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAiProjectsResult {
    pub total_projects: usize,
    pub truncated: bool,
    pub projects: Vec<AiProjectInventoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub logical_db_size_bytes: u64,
    pub physical_db_size_bytes: u64,
    pub free_disk_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRecovery {
    pub logical_db_size_bytes: u64,
    pub free_disk_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEnforcementOutcome {
    pub metrics: StorageMetrics,
    pub recovery: StorageRecovery,
    pub deleted_rows: usize,
    pub write_blocked: bool,
}

#[derive(Debug, Clone)]
pub struct StorageBudgetState {
    pub metrics: StorageMetrics,
    pub write_blocked: bool,
}

/// A parsed and stored log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: String,
    pub hostname: String,
    pub facility: Option<String>,
    pub severity: String,
    pub app_name: Option<String>,
    pub process_id: Option<String>,
    pub message: String,
    pub received_at: String,
    /// Source identifier. Syslog entries use verified network sender address
    /// (IP:port); OTLP entries use peer IP; Docker ingest entries use
    /// docker://host/container/stream or docker-event://host/container/action.
    /// Empty string for legacy rows inserted before this column was added.
    pub source_ip: String,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub ai_transcript_path: Option<String>,
    pub metadata_json: Option<String>,
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod tests;
