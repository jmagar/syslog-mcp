//! Handler-independent Agent Observatory read service.

use serde::{Deserialize, Serialize};

use super::cursor::{
    CursorDirection, CursorError, PageCursor, decode_cursor, encode_cursor, filter_fingerprint,
};
use super::{CortexService, ServiceError, ServiceResult};
use crate::db;
use crate::db::agent_observatory as ao;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: usize,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
    pub as_of: String,
    pub stream_cursor: String,
}

fn cursor_error(error: CursorError) -> ServiceError {
    ServiceError::InvalidInput(error.to_string())
}
fn limit(value: usize, maximum: usize) -> usize {
    value.clamp(1, maximum)
}
#[allow(clippy::too_many_arguments)]
fn page<T>(
    mut items: Vec<T>,
    requested: usize,
    maximum: usize,
    filters: &str,
    direction: CursorDirection,
    key: impl Fn(&T) -> (String, i64),
    as_of: String,
    stream_cursor: String,
    high_water: i64,
) -> ServiceResult<Page<T>> {
    let limit = limit(requested, maximum);
    let truncated = items.len() > limit;
    if truncated {
        items.truncate(limit);
    }
    let next_cursor = if truncated {
        items
            .last()
            .map(|item| {
                let (sort, id) = key(item);
                encode_cursor(&PageCursor {
                    sort,
                    id,
                    high_water,
                    as_of: as_of.clone(),
                    direction,
                    filters: filters.to_owned(),
                })
                .map_err(cursor_error)
            })
            .transpose()?
    } else {
        None
    };
    Ok(Page {
        items,
        pagination: Pagination {
            limit,
            next_cursor,
            truncated,
        },
        as_of,
        stream_cursor,
    })
}
fn decode(
    value: Option<&str>,
    fingerprint: &str,
    direction: CursorDirection,
) -> ServiceResult<Option<PageCursor>> {
    value
        .map(|v| decode_cursor(v, fingerprint, direction).map_err(cursor_error))
        .transpose()
}
fn snapshot(pool: &db::DbPool, table: &str) -> anyhow::Result<(String, String, i64)> {
    let conn = pool.get()?;
    let high_water = conn.query_row(
        &format!("SELECT COALESCE(MAX(id),0) FROM {table}"),
        [],
        |r| r.get(0),
    )?;
    Ok((
        conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| {
            r.get(0)
        })?,
        conn.query_row(
            "SELECT COALESCE(MAX(id),0) FROM agent_stream_outbox",
            [],
            |r| r.get::<_, i64>(0),
        )?
        .to_string(),
        high_water,
    ))
}

const MAX_FILTER_BYTES: usize = 512;
const MAX_FILTER_VALUES: usize = 32;
fn validate_text(value: &Option<String>, name: &str) -> ServiceResult<()> {
    if value
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > MAX_FILTER_BYTES)
    {
        return Err(ServiceError::InvalidInput(format!("invalid_{name}")));
    }
    Ok(())
}
fn validate_time(value: &Option<String>, name: &str) -> ServiceResult<()> {
    validate_text(value, name)?;
    if value
        .as_ref()
        .is_some_and(|v| chrono::DateTime::parse_from_rfc3339(v).is_err())
    {
        return Err(ServiceError::InvalidInput(format!("invalid_{name}")));
    }
    Ok(())
}
fn validate_range(since: &Option<String>, until: &Option<String>) -> ServiceResult<()> {
    validate_time(since, "since")?;
    validate_time(until, "until")?;
    if let (Some(a), Some(b)) = (since, until)
        && chrono::DateTime::parse_from_rfc3339(a).unwrap()
            > chrono::DateTime::parse_from_rfc3339(b).unwrap()
    {
        return Err(ServiceError::InvalidInput("invalid_time_range".into()));
    }
    Ok(())
}
fn validate_list(values: &[String], name: &str) -> ServiceResult<()> {
    if values.len() > MAX_FILTER_VALUES
        || values
            .iter()
            .any(|v| v.is_empty() || v.len() > MAX_FILTER_BYTES)
    {
        return Err(ServiceError::InvalidInput(format!("invalid_{name}")));
    }
    Ok(())
}

impl CortexService {
    pub async fn scoped_evidence(
        &self,
        query: ao::EvidenceScopeQuery,
        after_id: i64,
        requested: usize,
    ) -> ServiceResult<ao::EvidenceScopePage> {
        validate_text(&query.branch, "branch")?;
        validate_text(&query.worktree, "worktree")?;
        validate_list(&query.kinds, "kinds")?;
        validate_range(&query.since, &query.until)?;
        if query.branch.is_none() && query.worktree.is_none() {
            return Err(ServiceError::InvalidInput(
                "branch_or_worktree_required".into(),
            ));
        }
        if after_id < 0 {
            return Err(ServiceError::InvalidInput("invalid_after_id".into()));
        }
        self.run_db("observatory.scoped_evidence", move |pool| {
            ao::scoped_evidence_events(pool, &query, after_id, limit(requested, 500))
        })
        .await
    }

    pub async fn observatory_repositories(
        &self,
        query: ao::RepositoryQuery,
        cursor: Option<String>,
        requested: usize,
    ) -> ServiceResult<Page<ao::ObservatoryRepositoryRow>> {
        validate_text(&query.host, "host")?;
        validate_text(&query.query, "query")?;
        validate_range(&query.since, &query.until)?;
        let fingerprint = filter_fingerprint(&query).map_err(cursor_error)?;
        let decoded = decode(cursor.as_deref(), &fingerprint, CursorDirection::Desc)?;
        self.run_db("observatory.repositories", move |pool| {
            let snap = snapshot(pool, "repositories")?;
            let high_water = decoded.as_ref().map_or(snap.2, |c| c.high_water);
            let (rows, meta) = (
                ao::list_observatory_repositories(
                    pool,
                    &query,
                    decoded.as_ref().map(|c| (c.sort.as_str(), c.id)),
                    limit(requested, 200) + 1,
                    high_water,
                )?,
                snap,
            );
            page(
                rows,
                requested,
                200,
                &fingerprint,
                CursorDirection::Desc,
                |r| (r.last_seen_at.clone(), r.id),
                meta.0,
                meta.1,
                high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        })
        .await
    }
    pub async fn observatory_runs(
        &self,
        query: ao::AgentRunQuery,
        cursor: Option<String>,
        requested: usize,
    ) -> ServiceResult<Page<ao::ObservatoryRunRow>> {
        validate_text(&query.branch, "branch")?;
        validate_text(&query.host, "host")?;
        validate_text(&query.query, "query")?;
        validate_list(&query.statuses, "statuses")?;
        validate_list(&query.tools, "tools")?;
        validate_range(&query.since, &query.until)?;
        if query.repository_id.is_some_and(|id| id <= 0) {
            return Err(ServiceError::InvalidInput("invalid_repository_id".into()));
        }
        if query.worktree_id.is_some_and(|id| id <= 0) {
            return Err(ServiceError::InvalidInput("invalid_worktree_id".into()));
        }
        let fingerprint = filter_fingerprint(&query).map_err(cursor_error)?;
        let decoded = decode(cursor.as_deref(), &fingerprint, CursorDirection::Desc)?;
        self.run_db("observatory.runs", move |pool| {
            let snap = snapshot(pool, "agent_runs")?;
            let high_water = decoded.as_ref().map_or(snap.2, |c| c.high_water);
            let (rows, meta) = (
                ao::list_observatory_runs(
                    pool,
                    &query,
                    decoded.as_ref().map(|c| (c.sort.as_str(), c.id)),
                    limit(requested, 200) + 1,
                    high_water,
                )?,
                snap,
            );
            page(
                rows,
                requested,
                200,
                &fingerprint,
                CursorDirection::Desc,
                |r| (r.last_activity_at.clone(), r.id),
                meta.0,
                meta.1,
                high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        })
        .await
    }

    pub async fn observatory_worktrees(
        &self,
        repository_id: i64,
        branch: Option<String>,
        dirty: Option<bool>,
        include_removed: bool,
        cursor: Option<String>,
        requested: usize,
    ) -> ServiceResult<Page<ao::ObservatoryWorktreeRow>> {
        validate_text(&branch, "branch")?;
        if repository_id <= 0 {
            return Err(ServiceError::InvalidInput("invalid_repository_id".into()));
        }
        #[derive(Serialize)]
        struct Bound<'a> {
            repository_id: i64,
            branch: &'a Option<String>,
            dirty: Option<bool>,
            include_removed: bool,
        }
        let fingerprint = filter_fingerprint(&Bound {
            repository_id,
            branch: &branch,
            dirty,
            include_removed,
        })
        .map_err(cursor_error)?;
        let decoded = decode(cursor.as_deref(), &fingerprint, CursorDirection::Desc)?;
        self.run_db("observatory.worktrees", move |pool| {
            let snap = snapshot(pool, "repository_worktrees")?;
            let high_water = decoded.as_ref().map_or(snap.2, |c| c.high_water);
            let rows = ao::list_observatory_worktrees(
                pool,
                repository_id,
                branch.as_deref(),
                dirty,
                include_removed,
                decoded.as_ref().map(|c| (c.sort.as_str(), c.id)),
                limit(requested, 200) + 1,
                high_water,
            )?;
            let meta = snap;
            page(
                rows,
                requested,
                200,
                &fingerprint,
                CursorDirection::Desc,
                |row| (row.last_seen_at.clone(), row.id),
                meta.0,
                meta.1,
                high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        })
        .await
    }
    pub async fn observatory_events(
        &self,
        run_key: String,
        query: ao::AgentEventQuery,
        cursor: Option<String>,
        requested: usize,
        asc: bool,
    ) -> ServiceResult<Page<ao::ObservatoryEventRow>> {
        validate_list(&query.kinds, "kinds")?;
        validate_text(&query.actor_key, "actor_key")?;
        validate_text(&query.trace_id, "trace_id")?;
        validate_text(&query.query, "query")?;
        validate_range(&query.since, &query.until)?;
        if query.severity_min.is_some_and(|v| !(0..=7).contains(&v)) {
            return Err(ServiceError::InvalidInput("invalid_severity_min".into()));
        }
        if run_key.is_empty() || run_key.len() > MAX_FILTER_BYTES {
            return Err(ServiceError::InvalidInput("invalid_run_key".into()));
        }
        #[derive(Serialize)]
        struct Bound<'a> {
            run_key: &'a str,
            query: &'a ao::AgentEventQuery,
            asc: bool,
        }
        let fingerprint = filter_fingerprint(&Bound {
            run_key: &run_key,
            query: &query,
            asc,
        })
        .map_err(cursor_error)?;
        let direction = if asc {
            CursorDirection::Asc
        } else {
            CursorDirection::Desc
        };
        let decoded = decode(cursor.as_deref(), &fingerprint, direction)?;
        self.run_db("observatory.events", move |pool| {
            let snap = snapshot(pool, "agent_run_events")?;
            let high_water = decoded.as_ref().map_or(snap.2, |c| c.high_water);
            let (rows, meta) = (
                ao::list_observatory_events(
                    pool,
                    &run_key,
                    &query,
                    decoded.as_ref().map(|c| (c.sort.as_str(), c.id)),
                    limit(requested, 500) + 1,
                    asc,
                    high_water,
                )?,
                snap,
            );
            page(
                rows,
                requested,
                500,
                &fingerprint,
                direction,
                |r| (r.observed_at.clone(), r.id),
                meta.0,
                meta.1,
                high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        })
        .await
    }

    pub async fn observatory_telemetry(
        &self,
        run_key: String,
        query: ao::TelemetryQuery,
        span_cursor: Option<String>,
        metric_cursor: Option<String>,
        span_limit: usize,
        metric_limit: usize,
    ) -> ServiceResult<(Page<ao::ObservatorySpanRow>, Page<ao::ObservatoryMetricRow>)> {
        validate_text(&query.trace_id, "trace_id")?;
        validate_text(&query.metric_name, "metric_name")?;
        if query.since_nano.is_some_and(|v| v < 0)
            || query.until_nano.is_some_and(|v| v < 0)
            || matches!((query.since_nano, query.until_nano), (Some(a), Some(b)) if a > b)
        {
            return Err(ServiceError::InvalidInput("invalid_nano_range".into()));
        }
        if run_key.is_empty() || run_key.len() > MAX_FILTER_BYTES {
            return Err(ServiceError::InvalidInput("invalid_run_key".into()));
        }
        #[derive(Serialize)]
        struct Bound<'a> {
            run_key: &'a str,
            query: &'a ao::TelemetryQuery,
            signal: &'static str,
        }
        let span_fp = filter_fingerprint(&Bound {
            run_key: &run_key,
            query: &query,
            signal: "spans",
        })
        .map_err(cursor_error)?;
        let metric_fp = filter_fingerprint(&Bound {
            run_key: &run_key,
            query: &query,
            signal: "metrics",
        })
        .map_err(cursor_error)?;
        let spans_after = decode(span_cursor.as_deref(), &span_fp, CursorDirection::Desc)?;
        let metrics_after = decode(metric_cursor.as_deref(), &metric_fp, CursorDirection::Desc)?;
        self.run_db("observatory.telemetry", move |pool| {
            let conn = pool.get()?;
            let (run_id, identity) = conn
                .query_row(
                    "SELECT id,hostname,tool,provider_tool,native_session_id FROM agent_runs WHERE run_key=?1",
                    [&run_key],
                    |row| Ok((row.get::<_, i64>(0)?, ao::RunTelemetryIdentity { hostname: row.get(1)?, tool: row.get(2)?, provider_tool: row.get(3)?, native_session_id: row.get(4)? })),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        anyhow::anyhow!(ServiceError::NotFound("run_not_found".into()))
                    }
                    other => anyhow::Error::from(other),
                })?;
            drop(conn);
            let span_after = spans_after
                .as_ref()
                .map(|c| c.sort.parse::<i64>().map(|sort| (sort, c.id)))
                .transpose()
                .map_err(|_| anyhow::anyhow!(CursorError::Invalid))?;
            let metric_after = metrics_after
                .as_ref()
                .map(|c| c.sort.parse::<i64>().map(|sort| (sort, c.id)))
                .transpose()
                .map_err(|_| anyhow::anyhow!(CursorError::Invalid))?;
            let snap_spans = snapshot(pool, "otel_spans")?;
            let snap_metrics = snapshot(pool, "otel_metric_points")?;
            let span_high_water = spans_after.as_ref().map_or(snap_spans.2, |c| c.high_water);
            let metric_high_water = metrics_after.as_ref().map_or(snap_metrics.2, |c| c.high_water);
            let spans = ao::list_observatory_spans(
                pool,
                run_id,
                &identity,
                &query,
                span_after,
                limit(span_limit, 500) + 1,
                span_high_water,
            )?;
            let metrics = ao::list_observatory_metrics(
                pool,
                run_id,
                &identity,
                &query,
                metric_after,
                limit(metric_limit, 500) + 1,
                metric_high_water,
            )?;
            let meta = snapshot(pool, "agent_stream_outbox")?;
            let span_page = page(
                spans,
                span_limit,
                500,
                &span_fp,
                CursorDirection::Desc,
                |row| (row.start_time_unix_nano.to_string(), row.id),
                meta.0.clone(),
                meta.1.clone(),
                span_high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let metric_page = page(
                metrics,
                metric_limit,
                500,
                &metric_fp,
                CursorDirection::Desc,
                |row| (row.time_unix_nano.to_string(), row.id),
                meta.0,
                meta.1,
                metric_high_water,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Ok((span_page, metric_page))
        })
        .await
    }
}

#[cfg(test)]
#[path = "agent_observatory_tests.rs"]
mod tests;
