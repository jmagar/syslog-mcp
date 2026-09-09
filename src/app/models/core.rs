use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestActor {
    pub surface: String,
    pub display: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl RequestActor {
    pub fn new(surface: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            surface: surface.into(),
            display: display.into(),
            subject: None,
            email: None,
        }
    }

    pub fn api() -> Self {
        Self::new("api", "api")
    }

    pub fn cli() -> Self {
        Self::new("cli", "cli")
    }

    pub fn mcp_loopback() -> Self {
        Self::new("mcp", "mcp:loopback")
    }

    pub fn mcp_bearer() -> Self {
        Self::new("mcp", "mcp:bearer")
    }

    pub fn mcp_oauth() -> Self {
        Self::new("mcp", "mcp:oauth")
    }

    pub fn mcp_identity(subject: Option<String>, email: Option<String>) -> Self {
        let display = email
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| subject.as_deref().filter(|value| !value.is_empty()))
            .unwrap_or("mcp:oauth")
            .to_string();
        Self {
            surface: "mcp".to_string(),
            display,
            subject,
            email,
        }
    }
}

impl From<&str> for RequestActor {
    fn from(value: &str) -> Self {
        Self::new("unknown", value)
    }
}

impl From<String> for RequestActor {
    fn from(value: String) -> Self {
        Self::new("unknown", value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AiCorrelateLimitPolicy {
    pub events_per_anchor_cap: u32,
    pub report_events_per_anchor_clamp: bool,
}

impl AiCorrelateLimitPolicy {
    pub const MCP: Self = Self {
        events_per_anchor_cap: 200,
        report_events_per_anchor_clamp: false,
    };

    pub const REST: Self = Self {
        events_per_anchor_cap: 50,
        report_events_per_anchor_clamp: true,
    };
}

#[derive(Debug, Clone, Copy)]
pub struct AiLimitPolicy {
    pub limit_cap: u32,
    pub report_limit_clamp: bool,
}

impl AiLimitPolicy {
    pub const REST: Self = Self {
        limit_cap: 500,
        report_limit_clamp: true,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMaintenanceStatus {
    pub db_path: PathBuf,
    pub page_count: i64,
    pub freelist_count: i64,
    pub page_size: i64,
    pub logical_size_bytes: u64,
    pub physical_size_bytes: u64,
    pub wal_size_bytes: Option<u64>,
    pub shm_size_bytes: Option<u64>,
    pub sqlite_page_cache_mb: u64,
    pub sqlite_page_cache_kib_per_connection: i64,
    pub sqlite_mmap_mb: u64,
    pub sqlite_mmap_bytes: u64,
    pub heavy_read_concurrency: usize,
    pub wal_checkpoint_mb: u64,
    pub wal_checkpoint_threshold_bytes: u64,
    pub cgroup_memory_status: String,
    pub cgroup_memory_max_bytes: Option<u64>,
    pub cgroup_memory_current_bytes: Option<u64>,
    pub cgroup_memory_peak_bytes: Option<u64>,
    pub auto_vacuum: i64,
    pub journal_mode: String,
    pub integrity_ok: Option<bool>,
    pub integrity_messages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCheckpointResult {
    pub mode: String,
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbVacuumResult {
    pub full: bool,
    pub incremental_pages: u32,
    pub before_physical_size_bytes: u64,
    pub after_physical_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbIntegrityResult {
    pub ok: bool,
    pub messages: Vec<String>,
}

/// Response from starting a background `db integrity` job (bead syslog-mcp-a4pd).
/// The full check (~147s on a multi-GB DB) runs server-side; the caller polls
/// `GET /api/db/integrity/jobs/:id` for the outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbIntegrityJobStarted {
    pub job_id: i64,
    /// Always `"running"` at start.
    pub status: String,
}

/// Status of a background maintenance job (poll response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceJobStatus {
    pub job_id: i64,
    pub kind: String,
    /// `running`, `done`, or `failed`.
    pub status: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Parsed integrity result, present once the job is terminal and was an
    /// integrity check. `None` while running or on a `failed` job (whose error
    /// is in `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<DbIntegrityResult>,
    /// Error message for a `failed` job.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request body for `POST /api/db/backup`.
///
/// `output_path` is **server-side** — it must be a path the server process can
/// write to (e.g. `/data/backup-20240101.db` via the Docker bind-mount). When
/// absent the server picks `<db_dir>/backups/syslog-<timestamp>.db`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbBackupRequest {
    /// Optional server-side destination path (file or directory).
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbBackupResult {
    pub db_path: PathBuf,
    pub backup_path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLogsRequest {
    pub service: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub tail: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLogsResponse {
    pub service: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub tail: Option<u32>,
    pub entries: Vec<ServiceJournalEntry>,
    /// Count of journal lines that failed JSON parsing and were skipped.
    /// Non-zero values indicate journal corruption or an unexpected format
    /// — the surface still returns the entries that did parse rather than
    /// failing the whole request.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped_lines: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceJournalEntry {
    pub timestamp: Option<String>,
    pub realtime_timestamp_us: Option<String>,
    pub unit: Option<String>,
    pub priority: Option<String>,
    pub syslog_identifier: Option<String>,
    pub pid: Option<String>,
    pub message: Option<String>,
    pub cursor: Option<String>,
}

/// Bounded, safe health data for the operator watch-status surface.
///
/// The scanner's internal health object retains source locators for local
/// doctor/checkpoint commands. This projection deliberately excludes those
/// locators and any underlying error text before the status can reach JSON or
/// human CLI output.
#[derive(Debug, Clone, Serialize)]
pub struct AiIndexingOperatorHealth {
    pub db_schema_version: i64,
    pub known_schema_version: i64,
    pub schema_current: bool,
    pub schema_drift_detected: bool,
    pub last_successful_ingest_at: Option<String>,
    pub recent_failure_count: i64,
    pub first_failure_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub recent_schema_error_count: i64,
    pub stale_indicators: Vec<String>,
    pub provider_coverage: Vec<crate::scanner::providers::ProviderRuntimeHealth>,
}

impl From<crate::scanner::AiIndexingHealth> for AiIndexingOperatorHealth {
    fn from(health: crate::scanner::AiIndexingHealth) -> Self {
        Self {
            db_schema_version: health.db_schema_version,
            known_schema_version: health.known_schema_version,
            schema_current: health.schema_current,
            schema_drift_detected: health.schema_drift_detected,
            last_successful_ingest_at: health.last_successful_ingest_at,
            recent_failure_count: health.recent_failure_count,
            first_failure_at: health.first_failure_at,
            last_failure_at: health.last_failure_at,
            recent_schema_error_count: health.recent_schema_error_count,
            stale_indicators: health.stale_indicators,
            provider_coverage: health.provider_coverage,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AiWatchStatusReport {
    pub service: String,
    pub active: Option<String>,
    pub enabled: Option<String>,
    pub main_pid: Option<u32>,
    pub exec_start: Option<String>,
    pub exec_main_start_timestamp: Option<String>,
    pub process_start_time: Option<String>,
    /// `None` when the DB was unavailable during collection; OS probe fields
    /// are still populated so the operator can diagnose the service state even
    /// during a DB outage. See `health_error` for the failure reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<AiIndexingOperatorHealth>,
    /// Set when `ai_indexing_health` failed; `health` will be `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_error: Option<String>,
    pub latest_journal: Vec<String>,
    /// Set when journalctl failed; distinguishes "no output" from "fetch error".
    /// At most one of `journal_error` and `latest_journal` carries data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentRequest {
    /// Incident anchor timestamp. Defaults to now.
    pub around: Option<String>,
    pub minutes: Option<u32>,
    pub service: Option<String>,
    pub host: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponse {
    pub around: String,
    pub window_minutes: u32,
    pub window_from: String,
    pub window_to: String,
    pub event_count: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub events: Vec<IncidentEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub timestamp: String,
    pub source: String,
    pub host: Option<String>,
    pub severity: Option<String>,
    pub app: Option<String>,
    pub message: String,
    pub log_id: Option<i64>,
}

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
    pub source_ip: String,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub ai_transcript_path: Option<String>,
    pub metadata_json: Option<String>,
}

impl From<db::LogEntry> for LogEntry {
    fn from(value: db::LogEntry) -> Self {
        Self {
            id: value.id,
            timestamp: value.timestamp,
            hostname: value.hostname,
            facility: value.facility,
            severity: value.severity,
            app_name: value.app_name,
            process_id: value.process_id,
            message: value.message,
            received_at: value.received_at,
            source_ip: value.source_ip,
            ai_tool: value.ai_tool,
            ai_project: value.ai_project,
            ai_session_id: value.ai_session_id,
            ai_transcript_path: value.ai_transcript_path,
            metadata_json: value.metadata_json,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStateRequest {
    pub host_id: Option<String>,
    pub host: Option<String>,
    pub since: Option<String>,
    pub limit: Option<u32>,
}

pub type HostStateResponse = Option<db::HeartbeatHostState>;

// ── fleet_state ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetStateRequest {
    /// When `false`, hosts with `status == "ok"` are excluded.
    /// Defaults to `true`.
    pub include_ok: Option<bool>,
    /// Sort order: `"pressure"` (default), `"freshness"`, `"hostname"`.
    pub sort: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStateHostRow {
    pub host_id: String,
    pub hostname: String,
    pub last_heartbeat_at: String,
    pub status: String,
    pub pressure: Vec<String>,
    pub partial: bool,
    pub clock_skew: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetStateSummary {
    pub total: usize,
    pub ok: usize,
    pub late: usize,
    pub partial: usize,
    pub pressure: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStateResponse {
    pub hosts: Vec<FleetStateHostRow>,
    pub summary: FleetStateSummary,
}

// ── correlate_state ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelateStateRequest {
    /// ISO-8601 reference timestamp. Defaults to now.
    pub reference_time: Option<String>,
    /// Window in minutes before and after `reference_time`. Defaults to 10,
    /// capped at 120.
    pub window_minutes: Option<u32>,
    /// Optional host filter (`host_id` or unique hostname).
    pub host: Option<String>,
    /// Minimum severity for log rows. Defaults to `"info"`.
    pub severity_min: Option<String>,
    /// Maximum log rows to return per host. Defaults to 100.
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateStateWindow {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateStateHostEntry {
    pub host_id: String,
    pub hostname: String,
    pub heartbeat_summary: db::HeartbeatWindowSummary,
    pub logs: Vec<crate::app::models::LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateStateResponse {
    pub window: CorrelateStateWindow,
    pub hosts: Vec<CorrelateStateHostEntry>,
    pub truncated: bool,
}
