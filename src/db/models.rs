use serde::{Deserialize, Serialize};

/// Named struct for a log entry used in batch insertion and the syslog parse pipeline.
///
/// Replaces the former 8-tuple type alias; named fields prevent silent data corruption
/// from positional swaps between structurally identical `String`/`Option<String>` fields.
///
/// `source_ip` records the actual network sender address (IP:port) independent of the
/// hostname claimed in the syslog message body. Any LAN host can UDP-spoof an arbitrary
/// hostname, so `source_ip` is the only trustworthy network identity for a log entry.
/// Log content (hostname, message, app_name) is untrusted user-controlled data.
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
    /// Actual network sender address (IP:port). Separate from the claimed hostname
    /// in the syslog message, which can be spoofed by any LAN device.
    pub source_ip: String,
}

/// Error/warning summary entry (one row per hostname+severity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummaryEntry {
    pub hostname: String,
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
    pub phantom_fts_rows: i64,
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
    /// Actual network sender address (IP:port). Separate from the claimed hostname,
    /// which can be spoofed by any LAN device via UDP. Empty string for legacy rows
    /// inserted before this column was added.
    pub source_ip: String,
}

/// Parameters for searching logs
#[derive(Debug, Clone, Deserialize)]
pub struct SearchParams {
    /// Full-text search query (FTS5 syntax)
    pub query: Option<String>,
    /// Filter by hostname
    pub hostname: Option<String>,
    /// Filter by severity (exact match: emerg, alert, crit, err, warning, notice, info, debug)
    pub severity: Option<String>,
    /// Filter by one of a set of severity levels (for threshold queries)
    pub severity_in: Option<Vec<String>>,
    /// Filter by app name
    pub app_name: Option<String>,
    /// Start of time range (ISO 8601)
    pub from: Option<String>,
    /// End of time range (ISO 8601)
    pub to: Option<String>,
    /// Max results to return
    pub limit: Option<u32>,
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod tests;
