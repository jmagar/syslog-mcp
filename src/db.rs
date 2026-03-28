use anyhow::Result;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::config::StorageConfig;

pub type DbPool = Pool<SqliteConnectionManager>;

/// Tuple form of a log entry for batch insertion
pub type LogBatchEntry = (
    String,         // timestamp
    String,         // hostname
    Option<String>, // facility
    String,         // severity
    Option<String>, // app_name
    Option<String>, // process_id
    String,         // message
    String,         // raw
);

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

/// Initialize the database pool and schema
pub fn init_pool(config: &StorageConfig) -> Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = config.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let manager = SqliteConnectionManager::file(&config.db_path);
    let pool = Pool::builder()
        .max_size(config.pool_size)
        .build(manager)?;

    // Initialize schema
    let conn = pool.get()?;

    if config.wal_mode {
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    }
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;
    conn.execute_batch("PRAGMA cache_size=-64000;")?; // 64MB cache

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            hostname    TEXT NOT NULL,
            facility    TEXT,
            severity    TEXT NOT NULL,
            app_name    TEXT,
            process_id  TEXT,
            message     TEXT NOT NULL,
            raw         TEXT NOT NULL,
            received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_hostname  ON logs(hostname);
        CREATE INDEX IF NOT EXISTS idx_logs_severity  ON logs(severity);
        CREATE INDEX IF NOT EXISTS idx_logs_app_name  ON logs(app_name);
        CREATE INDEX IF NOT EXISTS idx_logs_host_time ON logs(hostname, timestamp);

        -- FTS5 virtual table for full-text search on messages
        CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
            message,
            content='logs',
            content_rowid='id',
            tokenize='porter unicode61'
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
            INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
        END;

        CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
            INSERT INTO logs_fts(logs_fts, rowid, message) VALUES('delete', old.id, old.message);
        END;

        CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN
            INSERT INTO logs_fts(logs_fts, rowid, message) VALUES('delete', old.id, old.message);
            INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
        END;

        -- Hostname registry for quick lookups
        CREATE TABLE IF NOT EXISTS hosts (
            hostname    TEXT PRIMARY KEY,
            first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            log_count   INTEGER NOT NULL DEFAULT 0
        );
        ",
    )?;

    tracing::info!(path = %config.db_path.display(), "Database initialized");
    Ok(pool)
}


/// Batch insert for higher throughput
pub fn insert_logs_batch(
    pool: &DbPool,
    entries: &[LogBatchEntry],
) -> Result<usize> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (timestamp, hostname, facility, severity, app_name, process_id, message, raw)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;

        for (ts, host, facility, severity, app, pid, msg, raw) in entries {
            stmt.execute(params![ts, host, facility, severity, app, pid, msg, raw])?;
        }

        // Batch upsert hosts — group by hostname to avoid one upsert per log entry
        let mut host_counts: std::collections::HashMap<&str, i64> = std::collections::HashMap::new();
        for entry in entries {
            *host_counts.entry(entry.1.as_str()).or_insert(0) += 1;
        }
        let mut host_stmt = tx.prepare_cached(
            "INSERT INTO hosts (hostname, log_count)
             VALUES (?1, ?2)
             ON CONFLICT(hostname) DO UPDATE SET
                 last_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 log_count = log_count + excluded.log_count",
        )?;
        for (hostname, count) in &host_counts {
            host_stmt.execute(params![hostname, count])?;
        }
    }

    tx.commit()?;
    Ok(entries.len())
}

/// Search logs with flexible filtering + FTS
pub fn search_logs(pool: &DbPool, params: &SearchParams) -> Result<Vec<LogEntry>> {
    let conn = pool.get()?;
    let limit = params.limit.unwrap_or(100).min(1000);

    // If we have a full-text query, use FTS5 join
    if let Some(ref query) = params.query {
        let mut sql = String::from(
            "SELECT l.id, l.timestamp, l.hostname, l.facility, l.severity,
                    l.app_name, l.process_id, l.message, l.received_at
             FROM logs l
             JOIN logs_fts ON logs_fts.rowid = l.id
             WHERE logs_fts MATCH ?1",
        );
        let mut bindings: Vec<Box<dyn rusqlite::types::ToSql + '_>> = vec![Box::new(query.as_str())];
        let mut idx = 2;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(bindings.iter().map(|b| b.as_ref())), map_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    } else {
        let mut sql = String::from(
            "SELECT l.id, l.timestamp, l.hostname, l.facility, l.severity,
                    l.app_name, l.process_id, l.message, l.received_at
             FROM logs l WHERE 1=1",
        );
        let mut bindings: Vec<Box<dyn rusqlite::types::ToSql + '_>> = vec![];
        let mut idx = 1;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(bindings.iter().map(|b| b.as_ref())), map_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

/// Get the N most recent logs for a host/service
pub fn tail_logs(pool: &DbPool, hostname: Option<&str>, app_name: Option<&str>, n: u32) -> Result<Vec<LogEntry>> {
    let conn = pool.get()?;
    let n = n.min(500);

    let mut sql = String::from(
        "SELECT id, timestamp, hostname, facility, severity,
                app_name, process_id, message, received_at
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
    let rows = stmt.query_map(rusqlite::params_from_iter(bindings.iter().map(|b| b.as_ref())), map_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Get error/warning summary per host in a time window
pub fn get_error_summary(pool: &DbPool, from: Option<&str>, to: Option<&str>) -> Result<Vec<serde_json::Value>> {
    let conn = pool.get()?;

    let from = from.unwrap_or("1970-01-01T00:00:00Z");
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
        Ok(serde_json::json!({
            "hostname": row.get::<_, String>(0)?,
            "severity": row.get::<_, String>(1)?,
            "count": row.get::<_, i64>(2)?,
        }))
    })?;

    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// List all known hosts with stats
pub fn list_hosts(pool: &DbPool) -> Result<Vec<serde_json::Value>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT hostname, first_seen, last_seen, log_count FROM hosts ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(serde_json::json!({
            "hostname": row.get::<_, String>(0)?,
            "first_seen": row.get::<_, String>(1)?,
            "last_seen": row.get::<_, String>(2)?,
            "log_count": row.get::<_, i64>(3)?,
        }))
    })?;

    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Purge logs older than N days
pub fn purge_old_logs(pool: &DbPool, retention_days: u32) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }

    let conn = pool.get()?;
    let cutoff = Utc::now()
        .checked_sub_signed(chrono::Duration::days(retention_days as i64))
        .ok_or_else(|| anyhow::anyhow!("date arithmetic overflow for retention_days={retention_days}"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let deleted = conn.execute("DELETE FROM logs WHERE timestamp < ?1", params![cutoff])?;

    // Rebuild FTS index after large deletes
    if deleted > 1000 {
        conn.execute_batch("INSERT INTO logs_fts(logs_fts) VALUES('rebuild');")?;
    }

    tracing::info!(deleted, cutoff = %cutoff, "Purged old logs");
    Ok(deleted)
}

/// Get database stats
pub fn get_stats(pool: &DbPool) -> Result<serde_json::Value> {
    let conn = pool.get()?;

    let total_logs: i64 = conn.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))?;
    let total_hosts: i64 = conn.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))?;
    let oldest: Option<String> =
        conn.query_row("SELECT MIN(timestamp) FROM logs", [], |r| r.get(0)).ok();
    let newest: Option<String> =
        conn.query_row("SELECT MAX(timestamp) FROM logs", [], |r| r.get(0)).ok();

    // DB file size
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let db_size_mb = (page_count * page_size) as f64 / 1_048_576.0;

    Ok(serde_json::json!({
        "total_logs": total_logs,
        "total_hosts": total_hosts,
        "oldest_log": oldest,
        "newest_log": newest,
        "db_size_mb": format!("{db_size_mb:.2}"),
    }))
}

// --- helpers ---

fn append_filters<'a>(
    sql: &mut String,
    bindings: &mut Vec<Box<dyn rusqlite::types::ToSql + 'a>>,
    idx: &mut usize,
    params: &'a SearchParams,
) {
    if let Some(ref h) = params.hostname {
        sql.push_str(&format!(" AND l.hostname = ?{}", *idx));
        bindings.push(Box::new(h.as_str()));
        *idx += 1;
    }
    if let Some(ref s) = params.severity {
        sql.push_str(&format!(" AND l.severity = ?{}", *idx));
        bindings.push(Box::new(s.as_str()));
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
                bindings.push(Box::new(level.as_str()));
                *idx += 1;
            }
        }
    }
    if let Some(ref a) = params.app_name {
        sql.push_str(&format!(" AND l.app_name = ?{}", *idx));
        bindings.push(Box::new(a.as_str()));
        *idx += 1;
    }
    if let Some(ref from) = params.from {
        sql.push_str(&format!(" AND l.timestamp >= ?{}", *idx));
        bindings.push(Box::new(from.as_str()));
        *idx += 1;
    }
    if let Some(ref to) = params.to {
        sql.push_str(&format!(" AND l.timestamp <= ?{}", *idx));
        bindings.push(Box::new(to.as_str()));
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
    })
}
