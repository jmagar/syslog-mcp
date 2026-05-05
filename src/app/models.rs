use serde::{Deserialize, Serialize};

use crate::db;

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
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchLogsRequest {
    pub query: Option<String>,
    pub hostname: Option<String>,
    pub source_ip: Option<String>,
    pub severity: Option<String>,
    pub app_name: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchLogsResponse {
    pub count: usize,
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailLogsRequest {
    pub hostname: Option<String>,
    pub source_ip: Option<String>,
    pub app_name: Option<String>,
    pub n: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummaryEntry {
    pub hostname: String,
    pub severity: String,
    pub count: i64,
}

impl From<db::ErrorSummaryEntry> for ErrorSummaryEntry {
    fn from(value: db::ErrorSummaryEntry) -> Self {
        Self {
            hostname: value.hostname,
            severity: value.severity,
            count: value.count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetErrorsRequest {
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetErrorsResponse {
    pub summary: Vec<ErrorSummaryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub log_count: i64,
}

impl From<db::HostEntry> for HostEntry {
    fn from(value: db::HostEntry) -> Self {
        Self {
            hostname: value.hostname,
            first_seen: value.first_seen,
            last_seen: value.last_seen,
            log_count: value.log_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListHostsResponse {
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateEventsRequest {
    pub reference_time: String,
    pub window_minutes: Option<u32>,
    pub severity_min: Option<String>,
    pub hostname: Option<String>,
    pub source_ip: Option<String>,
    pub query: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedHost {
    pub hostname: String,
    pub event_count: usize,
    pub events: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateEventsResponse {
    pub reference_time: String,
    pub window_minutes: u32,
    pub window_from: String,
    pub window_to: String,
    pub severity_min: String,
    pub total_events: usize,
    pub truncated: bool,
    pub hosts_count: usize,
    pub hosts: Vec<CorrelatedHost>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total_logs: i64,
    pub total_hosts: i64,
    pub oldest_log: Option<String>,
    pub newest_log: Option<String>,
    pub logical_db_size_mb: String,
    pub physical_db_size_mb: String,
    pub free_disk_mb: Option<String>,
    pub max_db_size_mb: u64,
    pub min_free_disk_mb: u64,
    pub write_blocked: bool,
    pub phantom_fts_rows: i64,
}

impl From<db::DbStats> for DbStats {
    fn from(value: db::DbStats) -> Self {
        Self {
            total_logs: value.total_logs,
            total_hosts: value.total_hosts,
            oldest_log: value.oldest_log,
            newest_log: value.newest_log,
            logical_db_size_mb: value.logical_db_size_mb,
            physical_db_size_mb: value.physical_db_size_mb,
            free_disk_mb: value.free_disk_mb,
            max_db_size_mb: value.max_db_size_mb,
            min_free_disk_mb: value.min_free_disk_mb,
            write_blocked: value.write_blocked,
            phantom_fts_rows: value.phantom_fts_rows,
        }
    }
}
