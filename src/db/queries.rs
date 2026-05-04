use anyhow::Result;
use rusqlite::params;

use crate::config::StorageConfig;

use super::maintenance::{exceeds_trigger, get_storage_metrics};
use super::models::{DbStats, ErrorSummaryEntry, HostEntry, LogEntry, SearchParams};
use super::pool::DbPool;

/// Validate a user-supplied FTS5 query before execution.
///
/// Limits:
/// - Max 512 characters (prevents very long queries from taxing the FTS tokenizer)
/// - Max 16 whitespace-separated terms (prevents 28+ wildcard term DoS)
///
/// Returns a user-friendly error; the caller logs the details server-side.
pub fn validate_fts_query(query: &str) -> Result<()> {
    if query.len() > 512 {
        anyhow::bail!(
            "Search query too long ({} chars); maximum is 512 characters",
            query.len()
        );
    }
    let term_count = query.split_whitespace().count();
    if term_count > 16 {
        anyhow::bail!("Search query has too many terms ({term_count}); maximum is 16 terms");
    }
    Ok(())
}

/// Search logs with flexible filtering + FTS
pub fn search_logs(pool: &DbPool, params: &SearchParams) -> Result<Vec<LogEntry>> {
    let conn = pool.get()?;
    let limit = params.limit.unwrap_or(100).min(1000);

    // If we have a full-text query, use FTS5 join
    if let Some(ref query) = params.query {
        validate_fts_query(query)?;

        let mut sql = String::from(
            "SELECT l.id, l.timestamp, l.hostname, l.facility, l.severity,
                    l.app_name, l.process_id, l.message, l.received_at, l.source_ip
             FROM logs l
             JOIN logs_fts ON logs_fts.rowid = l.id
             WHERE logs_fts MATCH ?1",
        );
        let mut bindings: Vec<rusqlite::types::Value> =
            vec![rusqlite::types::Value::Text(query.clone())];
        let mut idx = 2;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bindings.iter()), map_row)
            .map_err(|e| {
                tracing::error!(error = %e, query = %query, "FTS5 MATCH query failed");
                anyhow::anyhow!("Search query failed")
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| {
            tracing::error!(error = %e, query = %query, "FTS5 row mapping failed");
            anyhow::anyhow!("Search query failed")
        })
    } else {
        let mut sql = String::from(
            "SELECT l.id, l.timestamp, l.hostname, l.facility, l.severity,
                    l.app_name, l.process_id, l.message, l.received_at, l.source_ip
             FROM logs l WHERE 1=1",
        );
        let mut bindings: Vec<rusqlite::types::Value> = vec![];
        let mut idx = 1;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(bindings.iter()), map_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

/// Get the N most recent logs for a host/service
pub fn tail_logs(
    pool: &DbPool,
    hostname: Option<&str>,
    app_name: Option<&str>,
    n: u32,
) -> Result<Vec<LogEntry>> {
    let conn = pool.get()?;
    let n = n.min(500);

    let mut sql = String::from(
        "SELECT id, timestamp, hostname, facility, severity,
                app_name, process_id, message, received_at, source_ip
         FROM logs WHERE 1=1",
    );
    let mut bindings: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
    let mut idx = 1;

    if let Some(h) = hostname {
        sql.push_str(&format!(" AND hostname = ?{idx}"));
        bindings.push(Box::new(h.to_string()));
        idx += 1;
    }
    if let Some(a) = app_name {
        sql.push_str(&format!(" AND app_name = ?{idx}"));
        bindings.push(Box::new(a.to_string()));
    }

    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT {n}"));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(bindings.iter().map(|b| b.as_ref())),
        map_row,
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Get error/warning summary per host in a time window
pub fn get_error_summary(
    pool: &DbPool,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<Vec<ErrorSummaryEntry>> {
    let conn = pool.get()?;

    let from = from.unwrap_or("1970-01-01T00:00:00Z");
    // Upper sentinel: any valid RFC 3339 timestamp will sort before this.
    let to = to.unwrap_or("9999-12-31T23:59:59Z");

    let mut stmt = conn.prepare(
        "SELECT hostname, severity, COUNT(*) as count
         FROM logs
         WHERE severity IN ('emerg', 'alert', 'crit', 'err', 'warning')
           AND timestamp BETWEEN ?1 AND ?2
         GROUP BY hostname, severity
         ORDER BY hostname, count DESC",
    )?;

    let rows = stmt.query_map(params![from, to], |row| {
        Ok(ErrorSummaryEntry {
            hostname: row.get(0)?,
            severity: row.get(1)?,
            count: row.get(2)?,
        })
    })?;

    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// List all known hosts with stats
pub fn list_hosts(pool: &DbPool) -> Result<Vec<HostEntry>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT hostname, first_seen, last_seen, log_count FROM hosts ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(HostEntry {
            hostname: row.get(0)?,
            first_seen: row.get(1)?,
            last_seen: row.get(2)?,
            log_count: row.get(3)?,
        })
    })?;

    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Get database stats
pub fn get_stats(pool: &DbPool, config: &StorageConfig) -> Result<DbStats> {
    let metrics = get_storage_metrics(pool, config)?;
    let write_blocked = exceeds_trigger(&metrics, config);
    let mut conn = pool.get()?;

    // Deferred read transaction ensures the log stats form a consistent snapshot
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let total_logs: i64 = tx.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))?;
    let total_hosts: i64 = tx.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))?;
    let fts_rows: i64 = tx
        .query_row("SELECT COUNT(*) FROM logs_fts", [], |r| r.get(0))
        .unwrap_or(0);
    let phantom_fts_rows = (fts_rows - total_logs).max(0);
    // MIN/MAX return a single nullable row; use get::<_, Option<_>> so NULL becomes
    // None while real query errors (e.g. missing table) still propagate via `?`.
    let oldest: Option<String> = tx.query_row("SELECT MIN(timestamp) FROM logs", [], |r| {
        r.get::<_, Option<String>>(0)
    })?;
    let newest: Option<String> = tx.query_row("SELECT MAX(timestamp) FROM logs", [], |r| {
        r.get::<_, Option<String>>(0)
    })?;
    tx.finish()?;

    Ok(DbStats {
        total_logs,
        total_hosts,
        oldest_log: oldest,
        newest_log: newest,
        logical_db_size_mb: format!("{:.2}", metrics.logical_db_size_bytes as f64 / 1_048_576.0),
        physical_db_size_mb: format!("{:.2}", metrics.physical_db_size_bytes as f64 / 1_048_576.0),
        free_disk_mb: metrics
            .free_disk_bytes
            .map(|bytes| format!("{:.2}", bytes as f64 / 1_048_576.0)),
        max_db_size_mb: config.max_db_size_mb,
        min_free_disk_mb: config.min_free_disk_mb,
        write_blocked,
        phantom_fts_rows,
    })
}

/// Syslog severity level names ordered by numeric value (0=emerg, 7=debug).
/// Used by both the MCP layer (for threshold filtering) and the syslog parser (for decoding).
pub const SEVERITY_LEVELS: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// Convert a severity name to its numeric syslog level (0=emerg, 7=debug).
/// Returns `None` for unrecognised names.
pub fn severity_to_num(s: &str) -> Option<u8> {
    SEVERITY_LEVELS
        .iter()
        .position(|&l| l == s)
        .map(|i| i as u8)
}

fn append_filters(
    sql: &mut String,
    bindings: &mut Vec<rusqlite::types::Value>,
    idx: &mut usize,
    params: &SearchParams,
) {
    if let Some(ref h) = params.hostname {
        sql.push_str(&format!(" AND l.hostname = ?{}", *idx));
        bindings.push(rusqlite::types::Value::Text(h.clone()));
        *idx += 1;
    }
    if let Some(ref s) = params.severity {
        sql.push_str(&format!(" AND l.severity = ?{}", *idx));
        bindings.push(rusqlite::types::Value::Text(s.clone()));
        *idx += 1;
    }
    if let Some(ref levels) = params.severity_in {
        if !levels.is_empty() {
            let placeholders: Vec<String> = levels
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", *idx + i))
                .collect();
            sql.push_str(&format!(" AND l.severity IN ({})", placeholders.join(", ")));
            for level in levels {
                bindings.push(rusqlite::types::Value::Text(level.clone()));
                *idx += 1;
            }
        }
    }
    if let Some(ref a) = params.app_name {
        sql.push_str(&format!(" AND l.app_name = ?{}", *idx));
        bindings.push(rusqlite::types::Value::Text(a.clone()));
        *idx += 1;
    }
    if let Some(ref from) = params.from {
        sql.push_str(&format!(" AND l.timestamp >= ?{}", *idx));
        bindings.push(rusqlite::types::Value::Text(from.clone()));
        *idx += 1;
    }
    if let Some(ref to) = params.to {
        sql.push_str(&format!(" AND l.timestamp <= ?{}", *idx));
        bindings.push(rusqlite::types::Value::Text(to.clone()));
        *idx += 1;
    }
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<LogEntry> {
    Ok(LogEntry {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        hostname: row.get(2)?,
        facility: row.get(3)?,
        severity: row.get(4)?,
        app_name: row.get(5)?,
        process_id: row.get(6)?,
        message: row.get(7)?,
        received_at: row.get(8)?,
        source_ip: row.get(9)?,
    })
}

#[cfg(test)]
#[path = "queries_tests.rs"]
mod tests;
