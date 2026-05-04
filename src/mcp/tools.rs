use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::{self, DbPool, SearchParams};

use super::AppState;

/// Run a blocking db operation on the threadpool, converting join errors to anyhow.
async fn run_db<F, T>(pool: &Arc<DbPool>, f: F) -> anyhow::Result<T>
where
    F: FnOnce(&DbPool) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = Arc::clone(pool);
    tokio::task::spawn_blocking(move || f(&pool))
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))?
}

/// Execute a tool by name
pub(super) async fn execute_tool(
    state: &AppState,
    name: &str,
    args: Value,
) -> anyhow::Result<Value> {
    match name {
        "search_logs" => tool_search_logs(&state.pool, args).await,
        "tail_logs" => tool_tail_logs(&state.pool, args).await,
        "get_errors" => tool_get_errors(&state.pool, args).await,
        "list_hosts" => tool_list_hosts(&state.pool, args).await,
        "correlate_events" => tool_correlate_events(&state.pool, args).await,
        "get_stats" => tool_get_stats(state, args).await,
        "syslog_help" => tool_syslog_help().await,
        _ => Err(anyhow::anyhow!("Unknown tool: {name}")),
    }
}

async fn tool_search_logs(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let params = SearchParams {
        query: args.get("query").and_then(|v| v.as_str()).map(String::from),
        hostname: args
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity: args
            .get("severity")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity_in: None,
        app_name: args
            .get("app_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        from: parse_optional_timestamp(args.get("from").and_then(|v| v.as_str()), "from")?,
        to: parse_optional_timestamp(args.get("to").and_then(|v| v.as_str()), "to")?,
        limit: args.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32),
    };
    let results = run_db(pool, move |pool| db::search_logs(pool, &params)).await?;
    tracing::debug!(result_count = results.len(), "search_logs completed");
    Ok(json!({
        "count": results.len(),
        "logs": results
    }))
}

async fn tool_tail_logs(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let hostname = args
        .get("hostname")
        .and_then(|v| v.as_str())
        .map(String::from);
    let app_name = args
        .get("app_name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let n = args.get("n").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
    let results = run_db(pool, move |pool| {
        db::tail_logs(pool, hostname.as_deref(), app_name.as_deref(), n)
    })
    .await?;
    tracing::debug!(result_count = results.len(), n, "tail_logs completed");
    Ok(json!({
        "count": results.len(),
        "logs": results
    }))
}

async fn tool_get_errors(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let from = parse_optional_timestamp(args.get("from").and_then(|v| v.as_str()), "from")?;
    let to = parse_optional_timestamp(args.get("to").and_then(|v| v.as_str()), "to")?;
    let results = run_db(pool, move |pool| {
        db::get_error_summary(pool, from.as_deref(), to.as_deref())
    })
    .await?;
    tracing::debug!(summary_rows = results.len(), "get_errors completed");
    Ok(json!({
        "summary": results
    }))
}

async fn tool_list_hosts(pool: &Arc<DbPool>, _args: Value) -> anyhow::Result<Value> {
    let results = run_db(pool, db::list_hosts).await?;
    tracing::debug!(host_count = results.len(), "list_hosts completed");
    Ok(json!({
        "hosts": results
    }))
}

async fn tool_correlate_events(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let reference_time = args
        .get("reference_time")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("reference_time is required"))?;

    let window = args
        .get("window_minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(5)
        .min(60) as i64;

    let severity_min = args
        .get("severity_min")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");

    // Validate severity_min before using it
    let sev_threshold = db::severity_to_num(severity_min).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid severity_min '{}'. Must be one of: emerg, alert, crit, err, warning, notice, info, debug",
            severity_min
        )
    })?;

    // Slice SEVERITY_LEVELS up to and including sev_threshold — lower index = more severe,
    // so levels[0..=threshold] gives everything at or above the requested minimum.
    let severity_levels: Vec<String> = db::SEVERITY_LEVELS[..=sev_threshold as usize]
        .iter()
        .map(|&s| s.to_string())
        .collect();

    // Parse reference time and normalize to UTC so window bounds compare
    // correctly against UTC-stored timestamps (mixed offsets misorder TEXT).
    let ref_dt = chrono::DateTime::parse_from_rfc3339(reference_time)
        .map_err(|e| anyhow::anyhow!("Invalid reference_time '{}': {e}", reference_time))?
        .with_timezone(&chrono::Utc);

    let delta = chrono::TimeDelta::try_minutes(window)
        .ok_or_else(|| anyhow::anyhow!("duration overflow"))?;
    let from = (ref_dt - delta).to_rfc3339();
    let to = (ref_dt + delta).to_rfc3339();

    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(500)
        // Cap at 999: search_logs hard-limits to 1000 rows, so limit+1 must
        // stay ≤ 1000 for the truncation sentinel to work correctly.
        .min(999) as u32;

    let search = SearchParams {
        query: args.get("query").and_then(|v| v.as_str()).map(String::from),
        hostname: args
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity: None,
        severity_in: Some(severity_levels),
        app_name: None,
        from: Some(from.clone()),
        to: Some(to.clone()),
        // Fetch one extra to detect truncation without a separate COUNT query
        limit: Some(limit + 1),
    };

    let mut results = run_db(pool, move |pool| db::search_logs(pool, &search)).await?;
    let truncated = results.len() > limit as usize;
    results.truncate(limit as usize);

    // Group by hostname, preserving time order within each host
    let mut by_host: std::collections::BTreeMap<String, Vec<&db::LogEntry>> = Default::default();
    for log in &results {
        by_host.entry(log.hostname.clone()).or_default().push(log);
    }

    let grouped: Vec<Value> = by_host
        .into_iter()
        .map(|(host, logs)| {
            json!({
                "hostname": host,
                "event_count": logs.len(),
                "events": logs
            })
        })
        .collect();

    Ok(json!({
        "reference_time": reference_time,
        "window_minutes": window,
        "window_from": from,
        "window_to": to,
        "severity_min": severity_min,
        "total_events": results.len(),
        "truncated": truncated,
        "hosts_count": grouped.len(),
        "hosts": grouped
    }))
}

pub(super) async fn tool_get_stats(state: &AppState, _args: Value) -> anyhow::Result<Value> {
    let pool = Arc::clone(&state.pool);
    let storage = state.storage.clone();
    let stats = tokio::task::spawn_blocking(move || db::get_stats(&pool, &storage))
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))??;
    tracing::debug!(
        total_logs = stats.total_logs,
        total_hosts = stats.total_hosts,
        logical_db_size_mb = %stats.logical_db_size_mb,
        physical_db_size_mb = %stats.physical_db_size_mb,
        write_blocked = stats.write_blocked,
        phantom_fts_rows = stats.phantom_fts_rows,
        "get_stats completed"
    );
    Ok(serde_json::to_value(&stats)?)
}

async fn tool_syslog_help() -> anyhow::Result<Value> {
    let help = r#"# syslog-mcp Tool Reference

## search_logs
Full-text search across all syslog messages with optional filters.
Uses SQLite FTS5 with porter stemming. Supports FTS5 query syntax: AND, OR, NOT,
phrase matching with quotes, prefix matching with *.

**Parameters:**
- `query` (string) — FTS5 search query, e.g. `'kernel panic'`, `'OOM AND killer'`, `'"connection refused"'`, `'error*'`
- `hostname` (string, optional) — filter by hostname (exact match); use `list_hosts` to enumerate
- `severity` (string, optional) — one of: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`
- `app_name` (string, optional) — filter by application name, e.g. `sshd`, `dockerd`, `kernel`
- `from` (string, optional) — start of time range (ISO 8601 / RFC3339, e.g. `2025-01-15T00:00:00Z`)
- `to` (string, optional) — end of time range (ISO 8601)
- `limit` (integer, optional) — max results (default 100, max 1000)

---

## tail_logs
Get the N most recent log entries, optionally filtered by host and/or application.
Equivalent to `tail -f` across all hosts.

**Parameters:**
- `hostname` (string, optional) — filter to a specific host
- `app_name` (string, optional) — filter to a specific application
- `n` (integer, optional) — number of recent entries (default 50, max 500)

---

## get_errors
Get a summary of errors and warnings across all hosts in a time window.
Groups by hostname and severity level, showing counts. Useful for quick health assessments.

**Parameters:**
- `from` (string, optional) — start of time range (ISO 8601); defaults to all time
- `to` (string, optional) — end of time range (ISO 8601); defaults to now

---

## list_hosts
List all hosts that have sent syslog messages, with first/last seen timestamps and total log counts.

**Parameters:** none

---

## correlate_events
Search for related events across multiple hosts within a time window.
Useful for debugging cascading failures — finds events on all hosts within ±N minutes
of a reference timestamp. Results are grouped by host and ordered by time.

**Parameters:**
- `reference_time` (string, **required**) — center timestamp (ISO 8601, e.g. `2025-01-15T14:30:00Z`)
- `window_minutes` (integer, optional) — minutes before and after reference_time to search (default 5, max 60)
- `severity_min` (string, optional) — minimum severity to include (default `warning`); `debug` returns everything
- `hostname` (string, optional) — limit correlation to a specific host
- `query` (string, optional) — optional FTS query to narrow results
- `limit` (integer, optional) — max total events to return (default 500, max 999)

---

## get_stats
Get database statistics: total logs, total hosts, time range covered, logical and physical
DB size, free disk, configured thresholds, and current write-block status.

**Parameters:** none

---

## syslog_help
Returns this markdown documentation for all available syslog-mcp tools.

**Parameters:** none
"#;
    Ok(json!({ "help": help }))
}

/// Parse an optional RFC3339 timestamp string and normalize it to UTC.
///
/// Returns `Ok(None)` when `raw` is `None`. Returns a descriptive error when
/// `raw` is `Some` but not valid RFC3339 — callers get a clear message rather
/// than a silent wrong-result query against UTC-stored timestamps.
fn parse_optional_timestamp(raw: Option<&str>, field_name: &str) -> anyhow::Result<Option<String>> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid {field_name} '{}': {e}. Expected ISO 8601 / RFC3339 format, e.g. '2025-01-15T00:00:00Z'",
                    s
                )
            })?;
            Ok(Some(dt.with_timezone(&chrono::Utc).to_rfc3339()))
        }
    }
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
