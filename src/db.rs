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
    pub db_size_mb: String,
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
    let pool = Pool::builder().max_size(config.pool_size).build(manager)?;

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
pub fn insert_logs_batch(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
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
        let mut host_counts: std::collections::HashMap<&str, i64> =
            std::collections::HashMap::new();
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
        let mut bindings: Vec<rusqlite::types::Value> =
            vec![rusqlite::types::Value::Text(query.clone())];
        let mut idx = 2;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(bindings.iter()),
            map_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    } else {
        let mut sql = String::from(
            "SELECT l.id, l.timestamp, l.hostname, l.facility, l.severity,
                    l.app_name, l.process_id, l.message, l.received_at
             FROM logs l WHERE 1=1",
        );
        let mut bindings: Vec<rusqlite::types::Value> = vec![];
        let mut idx = 1;

        append_filters(&mut sql, &mut bindings, &mut idx, params);
        sql.push_str(&format!(" ORDER BY l.timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(bindings.iter()),
            map_row,
        )?;
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

/// Purge logs older than N days.
///
/// Uses chunked DELETEs (10 000 rows per iteration) so the WAL write lock is
/// released between chunks, letting the batch writer proceed without timing out
/// or overflowing its 1 000-entry cap.  After all chunks complete, an
/// incremental FTS5 merge is issued instead of a full rebuild — `merge=500,250`
/// processes at most a bounded number of index pages per call and holds the
/// write lock for milliseconds rather than seconds.
pub fn purge_old_logs(pool: &DbPool, retention_days: u32) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }

    let conn = pool.get()?;
    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(retention_days as i64))
        .ok_or_else(|| {
            anyhow::anyhow!("date arithmetic overflow for retention_days={retention_days}")
        })?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Chunked DELETE: each iteration removes at most 10 000 rows and returns
    // quickly, releasing the write lock so the batch writer can proceed.
    let mut total_deleted: usize = 0;
    loop {
        let chunk = conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs WHERE timestamp < ?1 LIMIT 10000
             )",
            params![cutoff],
        )?;
        total_deleted += chunk;
        if chunk == 0 {
            break;
        }
    }

    // Incremental FTS merge — much shorter write-lock duration than full rebuild.
    // Best-effort: a small/empty index may return an error; log and continue.
    if total_deleted > 0 {
        if let Err(e) = conn.execute_batch("INSERT INTO logs_fts(logs_fts) VALUES('merge=500,250');") {
            tracing::warn!(error = %e, "FTS merge skipped (non-fatal)");
        }
    }

    tracing::info!(deleted = total_deleted, cutoff = %cutoff, "Purged old logs");
    Ok(total_deleted)
}

/// Get database stats
pub fn get_stats(pool: &DbPool) -> Result<DbStats> {
    let mut conn = pool.get()?;

    // PRAGMA queries can't run inside a transaction, so read them first
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let db_size_mb = (page_count * page_size) as f64 / 1_048_576.0;

    // Deferred read transaction ensures the log stats form a consistent snapshot
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let total_logs: i64 = tx.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))?;
    let total_hosts: i64 = tx.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))?;
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
        db_size_mb: format!("{db_size_mb:.2}"),
    })
}

/// Syslog severity level names ordered by numeric value (0=emerg, 7=debug).
/// Used by both the MCP layer (for threshold filtering) and the syslog parser (for decoding).
pub const SEVERITY_LEVELS: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

// --- helpers ---

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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an isolated test pool using a temp file (not :memory: — FTS5 needs file)
    fn test_pool() -> (DbPool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let config = StorageConfig {
            db_path,
            pool_size: 1,
            retention_days: 90,
            wal_mode: false, // WAL not needed for tests
        };
        let pool = init_pool(&config).unwrap();
        (pool, dir) // keep dir alive for test duration
    }

    fn make_entry(ts: &str, host: &str, severity: &str, msg: &str) -> LogBatchEntry {
        (
            ts.to_string(),
            host.to_string(),
            None,
            severity.to_string(),
            None,
            None,
            msg.to_string(),
            msg.to_string(),
        )
    }

    #[test]
    fn test_insert_and_tail() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-a", "err", "first error"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "second info"),
            make_entry("2026-01-01T00:00:03Z", "host-b", "warning", "third warning"),
        ];
        let n = insert_logs_batch(&pool, &entries).unwrap();
        assert_eq!(n, 3);

        let rows = tail_logs(&pool, None, None, 10).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_host_aggregation() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-a", "info", "msg1"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "msg2"),
            make_entry("2026-01-01T00:00:03Z", "host-b", "info", "msg3"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let hosts = list_hosts(&pool).unwrap();
        assert_eq!(hosts.len(), 2);
        // host-a should have log_count = 2
        let ha = hosts.iter().find(|h| h.hostname == "host-a").unwrap();
        assert_eq!(ha.log_count, 2);
    }

    #[test]
    fn test_search_fts() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-a", "err", "disk full on /dev/sda"),
            make_entry("2026-01-01T00:00:02Z", "host-b", "info", "connection established"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let params = SearchParams {
            query: Some("disk".to_string()),
            hostname: None,
            severity: None,
            severity_in: None,
            app_name: None,
            from: None,
            to: None,
            limit: None,
        };
        let results = search_logs(&pool, &params).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].message.contains("disk full"));
    }

    #[test]
    fn test_search_invalid_fts_returns_error() {
        let (pool, _dir) = test_pool();
        // FTS5 treats bare parentheses as a syntax error
        let params = SearchParams {
            query: Some("(invalid fts syntax".to_string()),
            hostname: None,
            severity: None,
            severity_in: None,
            app_name: None,
            from: None,
            to: None,
            limit: None,
        };
        let result = search_logs(&pool, &params);
        assert!(result.is_err(), "invalid FTS5 query should return Err");
    }

    #[test]
    fn test_purge_old_logs_removes_old() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            // Old entry — should be purged
            make_entry("2020-01-01T00:00:00Z", "host-a", "info", "old message"),
            // Recent entry — should survive
            make_entry("2099-01-01T00:00:00Z", "host-a", "info", "future message"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let deleted = purge_old_logs(&pool, 90).unwrap();
        assert_eq!(deleted, 1, "should have deleted exactly the old entry");

        let remaining = tail_logs(&pool, None, None, 10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].message, "future message");
    }

    #[test]
    fn test_purge_zero_retention_noop() {
        let (pool, _dir) = test_pool();
        let entries = vec![make_entry("2020-01-01T00:00:00Z", "host-a", "info", "old")];
        insert_logs_batch(&pool, &entries).unwrap();

        let deleted = purge_old_logs(&pool, 0).unwrap();
        assert_eq!(deleted, 0, "retention_days=0 should be a no-op");
    }

    #[test]
    fn test_get_stats_empty_db() {
        let (pool, _dir) = test_pool();
        let stats = get_stats(&pool).unwrap();
        assert_eq!(stats.total_logs, 0);
        assert_eq!(stats.total_hosts, 0);
        // oldest_log and newest_log should be None on empty DB
        assert!(stats.oldest_log.is_none());
        assert!(stats.newest_log.is_none());
    }

    #[test]
    fn test_tail_filter_by_host() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-a", "info", "from a"),
            make_entry("2026-01-01T00:00:02Z", "host-b", "info", "from b"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let rows = tail_logs(&pool, Some("host-a"), None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hostname, "host-a");
    }
}
