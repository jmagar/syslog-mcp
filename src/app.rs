use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::config::StorageConfig;
use crate::db::{self, DbPool, SearchParams};

const DB_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct LogService {
    pool: Arc<DbPool>,
    storage: StorageConfig,
    db_permits: Arc<Semaphore>,
    acquire_timeout: Duration,
}

#[derive(Debug)]
pub enum ServiceError {
    InvalidInput(String),
    Busy(String),
    Internal(anyhow::Error),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) | Self::Busy(msg) => f.write_str(msg),
            Self::Internal(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(err) => err.source(),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for ServiceError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

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

impl LogService {
    pub(crate) fn new(pool: Arc<DbPool>, storage: StorageConfig) -> Self {
        let permits = storage.pool_size.max(1) as usize;
        Self {
            pool,
            storage,
            db_permits: Arc::new(Semaphore::new(permits)),
            acquire_timeout: DB_ACQUIRE_TIMEOUT,
        }
    }

    async fn run_db<F, T>(&self, f: F) -> ServiceResult<T>
    where
        F: FnOnce(&DbPool) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let permit = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.db_permits).acquire_owned(),
        )
        .await
        .map_err(|_| ServiceError::Busy("database worker limit reached".into()))?
        .map_err(|_| ServiceError::Busy("database worker limit closed".into()))?;
        let pool = Arc::clone(&self.pool);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f(&pool)
        })
        .await
        .map_err(|e| ServiceError::Internal(anyhow::anyhow!("Task join error: {e}")))?
        .map_err(ServiceError::Internal)
    }

    pub async fn health_check(&self) -> ServiceResult<()> {
        self.run_db(|pool| {
            let conn = pool.get()?;
            conn.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })
        .await
    }

    pub async fn search_logs(&self, req: SearchLogsRequest) -> ServiceResult<SearchLogsResponse> {
        let params = SearchParams {
            query: req.query,
            hostname: req.hostname,
            source_ip: req.source_ip,
            severity: req.severity,
            severity_in: None,
            app_name: req.app_name,
            from: parse_optional_timestamp(req.from.as_deref(), "from")?,
            to: parse_optional_timestamp(req.to.as_deref(), "to")?,
            limit: req.limit,
        };
        let logs = self
            .run_db(move |pool| db::search_logs(pool, &params))
            .await?;
        let logs: Vec<LogEntry> = logs.into_iter().map(Into::into).collect();
        Ok(SearchLogsResponse {
            count: logs.len(),
            logs,
        })
    }

    pub async fn tail_logs(&self, req: TailLogsRequest) -> ServiceResult<SearchLogsResponse> {
        let logs = self
            .run_db(move |pool| {
                db::tail_logs(
                    pool,
                    req.hostname.as_deref(),
                    req.source_ip.as_deref(),
                    req.app_name.as_deref(),
                    req.n.unwrap_or(50),
                )
            })
            .await?;
        let logs: Vec<LogEntry> = logs.into_iter().map(Into::into).collect();
        Ok(SearchLogsResponse {
            count: logs.len(),
            logs,
        })
    }

    pub async fn get_errors(&self, req: GetErrorsRequest) -> ServiceResult<GetErrorsResponse> {
        let from = parse_optional_timestamp(req.from.as_deref(), "from")?;
        let to = parse_optional_timestamp(req.to.as_deref(), "to")?;
        let rows = self
            .run_db(move |pool| db::get_error_summary(pool, from.as_deref(), to.as_deref()))
            .await?;
        Ok(GetErrorsResponse {
            summary: rows.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn list_hosts(&self) -> ServiceResult<ListHostsResponse> {
        let rows = self.run_db(db::list_hosts).await?;
        Ok(ListHostsResponse {
            hosts: rows.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn correlate_events(
        &self,
        req: CorrelateEventsRequest,
    ) -> ServiceResult<CorrelateEventsResponse> {
        let window = req.window_minutes.unwrap_or(5).min(60);
        let severity_min = req.severity_min.unwrap_or_else(|| "warning".into());
        let severity_levels = severity_at_or_above(&severity_min)?;
        let ref_dt = parse_required_timestamp(&req.reference_time, "reference_time")?;
        let delta = TimeDelta::try_minutes(i64::from(window))
            .ok_or_else(|| ServiceError::InvalidInput("duration overflow".into()))?;
        let from = (ref_dt - delta).to_rfc3339();
        let to = (ref_dt + delta).to_rfc3339();
        let limit = req.limit.unwrap_or(500).min(999);
        let params = SearchParams {
            query: req.query,
            hostname: req.hostname,
            source_ip: req.source_ip,
            severity: None,
            severity_in: Some(severity_levels),
            app_name: None,
            from: Some(from.clone()),
            to: Some(to.clone()),
            limit: Some(limit + 1),
        };
        let mut rows = self
            .run_db(move |pool| db::search_logs(pool, &params))
            .await?;
        let truncated = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let logs: Vec<LogEntry> = rows.into_iter().map(Into::into).collect();

        let mut by_host: BTreeMap<String, Vec<LogEntry>> = BTreeMap::new();
        for log in logs {
            by_host.entry(log.hostname.clone()).or_default().push(log);
        }
        let hosts: Vec<CorrelatedHost> = by_host
            .into_iter()
            .map(|(hostname, events)| CorrelatedHost {
                hostname,
                event_count: events.len(),
                events,
            })
            .collect();
        let total_events = hosts.iter().map(|h| h.event_count).sum();
        Ok(CorrelateEventsResponse {
            reference_time: req.reference_time,
            window_minutes: window,
            window_from: from,
            window_to: to,
            severity_min,
            total_events,
            truncated,
            hosts_count: hosts.len(),
            hosts,
        })
    }

    pub async fn get_stats(&self) -> ServiceResult<DbStats> {
        let storage = self.storage.clone();
        let stats = self
            .run_db(move |pool| db::get_stats(pool, &storage))
            .await?
            .into();
        Ok(stats)
    }
}

pub fn parse_optional_timestamp(
    raw: Option<&str>,
    field_name: &str,
) -> ServiceResult<Option<String>> {
    raw.map(|s| parse_required_timestamp(s, field_name).map(|dt| dt.to_rfc3339()))
        .transpose()
}

fn parse_required_timestamp(raw: &str, field_name: &str) -> ServiceResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map_err(|e| {
            ServiceError::InvalidInput(format!(
                "Invalid {field_name} '{}': {e}. Expected ISO 8601 / RFC3339 format, e.g. '2025-01-15T00:00:00Z'",
                raw
            ))
        })
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn severity_at_or_above(severity_min: &str) -> ServiceResult<Vec<String>> {
    let threshold = db::severity_to_num(severity_min).ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "Invalid severity_min '{}'. Must be one of: emerg, alert, crit, err, warning, notice, info, debug",
            severity_min
        ))
    })?;
    Ok(db::SEVERITY_LEVELS[..=threshold as usize]
        .iter()
        .map(|&s| s.to_string())
        .collect())
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
