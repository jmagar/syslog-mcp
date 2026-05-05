use std::sync::Arc;
use std::time::Duration;

use chrono::TimeDelta;
use tokio::sync::Semaphore;

use super::correlate::{group_by_host, severity_at_or_above};
use super::models::{
    CorrelateEventsRequest, CorrelateEventsResponse, DbStats, GetErrorsRequest, GetErrorsResponse,
    ListHostsResponse, LogEntry, SearchLogsRequest, SearchLogsResponse, TailLogsRequest,
};
use super::time::{parse_optional_timestamp, parse_required_timestamp};
use super::{ServiceError, ServiceResult};
use crate::config::StorageConfig;
use crate::db::{self, DbPool, SearchParams};

const DB_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct SyslogService {
    pool: Arc<DbPool>,
    storage: StorageConfig,
    db_permits: Arc<Semaphore>,
    acquire_timeout: Duration,
}

impl SyslogService {
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
        let hosts = group_by_host(logs);
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
