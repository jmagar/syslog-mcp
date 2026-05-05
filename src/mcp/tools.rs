use serde_json::{json, Value};

use crate::app::{CorrelateEventsRequest, GetErrorsRequest, SearchLogsRequest, TailLogsRequest};

use super::AppState;

/// Execute a tool by name
pub(super) async fn execute_tool(
    state: &AppState,
    name: &str,
    args: Value,
) -> anyhow::Result<Value> {
    match name {
        "search_logs" => tool_search_logs(state, args).await,
        "tail_logs" => tool_tail_logs(state, args).await,
        "get_errors" => tool_get_errors(state, args).await,
        "list_hosts" => tool_list_hosts(state, args).await,
        "correlate_events" => tool_correlate_events(state, args).await,
        "get_stats" => tool_get_stats(state, args).await,
        "syslog_help" => tool_syslog_help().await,
        _ => Err(anyhow::anyhow!("Unknown tool: {name}")),
    }
}

async fn tool_search_logs(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let response = state
        .service
        .search_logs(SearchLogsRequest {
            query: string_arg(&args, "query"),
            hostname: string_arg(&args, "hostname"),
            source_ip: string_arg(&args, "source_ip"),
            severity: string_arg(&args, "severity"),
            app_name: string_arg(&args, "app_name"),
            from: string_arg(&args, "from"),
            to: string_arg(&args, "to"),
            limit: u32_arg(&args, "limit")?,
        })
        .await?;
    tracing::debug!(result_count = response.count, "search_logs completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_tail_logs(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let response = state
        .service
        .tail_logs(TailLogsRequest {
            hostname: string_arg(&args, "hostname"),
            source_ip: string_arg(&args, "source_ip"),
            app_name: string_arg(&args, "app_name"),
            n: u32_arg(&args, "n")?,
        })
        .await?;
    tracing::debug!(result_count = response.count, "tail_logs completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_get_errors(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let response = state
        .service
        .get_errors(GetErrorsRequest {
            from: string_arg(&args, "from"),
            to: string_arg(&args, "to"),
        })
        .await?;
    tracing::debug!(
        summary_rows = response.summary.len(),
        "get_errors completed"
    );
    Ok(serde_json::to_value(response)?)
}

async fn tool_list_hosts(state: &AppState, _args: Value) -> anyhow::Result<Value> {
    let response = state.service.list_hosts().await?;
    tracing::debug!(host_count = response.hosts.len(), "list_hosts completed");
    Ok(serde_json::to_value(response)?)
}

async fn tool_correlate_events(state: &AppState, args: Value) -> anyhow::Result<Value> {
    let reference_time = string_arg(&args, "reference_time")
        .ok_or_else(|| anyhow::anyhow!("reference_time is required"))?;
    let response = state
        .service
        .correlate_events(CorrelateEventsRequest {
            reference_time,
            window_minutes: u32_arg(&args, "window_minutes")?,
            severity_min: string_arg(&args, "severity_min"),
            hostname: string_arg(&args, "hostname"),
            source_ip: string_arg(&args, "source_ip"),
            query: string_arg(&args, "query"),
            limit: u32_arg(&args, "limit")?,
        })
        .await?;
    Ok(serde_json::to_value(response)?)
}

pub(super) async fn tool_get_stats(state: &AppState, _args: Value) -> anyhow::Result<Value> {
    let stats = state.service.get_stats().await?;
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

fn string_arg(args: &Value, name: &str) -> Option<String> {
    args.get(name).and_then(|v| v.as_str()).map(String::from)
}

fn u32_arg(args: &Value, name: &str) -> anyhow::Result<Option<u32>> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let Some(unsigned) = value.as_u64() else {
        return Ok(None);
    };
    u32::try_from(unsigned)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{name} must be <= {}", u32::MAX))
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
- `source_ip` (string, optional) — filter by verified network sender address (`IP:port`)
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
- `source_ip` (string, optional) — filter by verified network sender address (`IP:port`)
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
- `source_ip` (string, optional) — limit correlation to a verified network sender address (`IP:port`)
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
#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
