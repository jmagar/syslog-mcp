use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, Error as SqliteError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::config::StorageConfig;

pub type DbPool = Pool<SqliteConnectionManager>;

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

pub trait DiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64>;
}

struct SystemDiskSpaceProbe;

impl DiskSpaceProbe for SystemDiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64> {
        let stats = rustix::fs::statvfs(path)?;
        Ok(stats.f_bavail.saturating_mul(stats.f_bsize))
    }
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

/// Initialize the database pool and schema
pub fn init_pool(config: &StorageConfig) -> Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = config.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let wal_mode = config.wal_mode;
    let manager = SqliteConnectionManager::file(&config.db_path)
        .with_init(move |conn| configure_connection_pragmas(conn, wal_mode));
    let pool = Pool::builder().max_size(config.pool_size).build(manager)?;

    // Initialize schema
    let conn = pool.get()?;

    let auto_vacuum_mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
    if auto_vacuum_mode != 2 {
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        if page_count > 0 {
            conn.execute_batch("VACUUM;")?;
        }
    }

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
            received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            source_ip   TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_hostname  ON logs(hostname);
        CREATE INDEX IF NOT EXISTS idx_logs_severity  ON logs(severity);
        CREATE INDEX IF NOT EXISTS idx_logs_app_name  ON logs(app_name);
        CREATE INDEX IF NOT EXISTS idx_logs_host_time ON logs(hostname, timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_sev_time ON logs(severity, timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_received_at ON logs(received_at);

        -- FTS5 virtual table for full-text search on messages
        CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
            message,
            content='logs',
            content_rowid='id',
            tokenize='porter unicode61'
        );

        -- Trigger to keep FTS in sync on INSERT only.
        -- DELETE and UPDATE triggers are intentionally absent: bulk DELETEs during
        -- retention purge and storage-budget enforcement fire the trigger for every
        -- deleted row inside a single implicit transaction, holding the SQLite write
        -- lock long enough to starve the batch writer. FTS5 content tables tolerate
        -- phantom rows — stale entries are skipped at query time and cleaned up by
        -- periodic incremental merge (merge=500,250).
        CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
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

    // Migration: add source_ip column to existing databases that predate this column.
    // ALTER TABLE ADD COLUMN is a no-op if the column already exists in SQLite ≥ 3.37,
    // but older SQLite returns an error on duplicate columns, so we check first.
    let col_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name = 'source_ip'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !col_exists {
        conn.execute_batch("ALTER TABLE logs ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")?;
        tracing::info!("Migration: added source_ip column to logs table");
    }

    // Migration: drop FTS5 DELETE/UPDATE triggers from existing databases.
    // These triggers caused write-lock contention during bulk deletes (retention
    // purge, storage enforcement). See schema comment above for rationale.
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS logs_ad;
         DROP TRIGGER IF EXISTS logs_au;",
    )?;

    tracing::info!(path = %config.db_path.display(), "Database initialized");
    Ok(pool)
}

fn configure_connection_pragmas(conn: &mut Connection, wal_mode: bool) -> rusqlite::Result<()> {
    if wal_mode {
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    }
    conn.execute_batch(
        "PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA cache_size=-64000;",
    )?;
    Ok(())
}

pub fn get_storage_metrics(pool: &DbPool, config: &StorageConfig) -> Result<StorageMetrics> {
    get_storage_metrics_with_probe(pool, config, &SystemDiskSpaceProbe)
}

pub fn get_storage_metrics_with_probe(
    pool: &DbPool,
    config: &StorageConfig,
    probe: &impl DiskSpaceProbe,
) -> Result<StorageMetrics> {
    let conn = pool.get()?;
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let freelist_count: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    drop(conn);

    let logical_db_size_bytes = ((page_count - freelist_count).max(0) * page_size).max(0) as u64;
    let physical_db_size_bytes = physical_db_size_bytes(&config.db_path)?;
    let free_disk_bytes = probe
        .free_bytes(config.db_path.parent().unwrap_or_else(|| Path::new(".")))
        .ok();
    tracing::debug!(
        logical_db_size_bytes,
        physical_db_size_bytes,
        free_disk_bytes = ?free_disk_bytes,
        db_path = %config.db_path.display(),
        "Collected storage metrics"
    );

    Ok(StorageMetrics {
        logical_db_size_bytes,
        physical_db_size_bytes,
        free_disk_bytes,
    })
}

pub fn enforce_storage_budget(
    pool: &DbPool,
    config: &StorageConfig,
) -> Result<StorageEnforcementOutcome> {
    enforce_storage_budget_with_probe(pool, config, &SystemDiskSpaceProbe)
}

pub fn enforce_storage_budget_with_probe(
    pool: &DbPool,
    config: &StorageConfig,
    probe: &impl DiskSpaceProbe,
) -> Result<StorageEnforcementOutcome> {
    let recovery = recovery_targets(config);
    let mut deleted_rows = 0usize;

    let mut metrics = get_storage_metrics_with_probe(pool, config, probe)?;
    tracing::debug!(
        logical_db_size_bytes = metrics.logical_db_size_bytes,
        physical_db_size_bytes = metrics.physical_db_size_bytes,
        free_disk_bytes = ?metrics.free_disk_bytes,
        max_db_size_mb = config.max_db_size_mb,
        recovery_db_size_mb = config.recovery_db_size_mb,
        min_free_disk_mb = config.min_free_disk_mb,
        recovery_free_disk_mb = config.recovery_free_disk_mb,
        "Storage budget enforcement check started"
    );
    if !storage_limits_enabled(config) {
        tracing::debug!("Storage limits disabled — skipping enforcement");
        return Ok(StorageEnforcementOutcome {
            metrics,
            recovery,
            deleted_rows,
            write_blocked: false,
        });
    }

    while exceeds_trigger(&metrics, config) || !within_recovery(&metrics, &recovery, config) {
        tracing::warn!(
            logical_db_size_bytes = metrics.logical_db_size_bytes,
            physical_db_size_bytes = metrics.physical_db_size_bytes,
            free_disk_bytes = ?metrics.free_disk_bytes,
            deleted_rows,
            "Storage budget exceeded recovery target — deleting oldest logs chunk"
        );
        let deleted = delete_oldest_logs_chunk(pool, config.cleanup_chunk_size)?;
        if deleted.deleted_rows == 0 {
            metrics = get_storage_metrics_with_probe(pool, config, probe)?;
            let write_blocked = exceeds_trigger(&metrics, config);
            tracing::warn!(
                logical_db_size_bytes = metrics.logical_db_size_bytes,
                free_disk_bytes = ?metrics.free_disk_bytes,
                deleted_rows,
                write_blocked,
                "Storage budget enforcement could not delete more rows"
            );
            return Ok(StorageEnforcementOutcome {
                metrics,
                recovery,
                deleted_rows,
                write_blocked,
            });
        }

        deleted_rows += deleted.deleted_rows;
        tracing::info!(
            deleted_rows = deleted.deleted_rows,
            total_deleted_rows = deleted_rows,
            affected_hosts = deleted.hostnames.len(),
            "Deleted oldest log chunk for storage recovery"
        );
        reconcile_hosts(pool, &deleted.hostnames)?;
        metrics = get_storage_metrics_with_probe(pool, config, probe)?;
    }

    if deleted_rows > 0 {
        // Incremental FTS merge — clean up phantom rows left by bulk deletes
        // (DELETE trigger is intentionally absent). Best-effort, matching
        // the pattern in purge_old_logs.
        let conn = pool.get()?;
        if let Err(e) =
            conn.execute_batch("INSERT INTO logs_fts(logs_fts) VALUES('merge=500,250');")
        {
            tracing::warn!(error = %e, "FTS merge after storage enforcement skipped (non-fatal)");
        }
        drop(conn);

        checkpoint_wal_and_incremental_vacuum(pool)?;
    }

    tracing::debug!(
        deleted_rows,
        logical_db_size_bytes = metrics.logical_db_size_bytes,
        physical_db_size_bytes = metrics.physical_db_size_bytes,
        free_disk_bytes = ?metrics.free_disk_bytes,
        "Storage budget enforcement completed"
    );

    Ok(StorageEnforcementOutcome {
        metrics,
        recovery,
        deleted_rows,
        write_blocked: false,
    })
}

/// Batch insert for higher throughput
pub fn insert_logs_batch(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
    const RETRY_DELAYS_MS: &[u64] = &[25, 100, 250];

    let mut attempt = 0usize;
    loop {
        match insert_logs_batch_once(pool, entries) {
            Ok(inserted) => return Ok(inserted),
            Err(err) if is_transient_sqlite_lock(&err) && attempt < RETRY_DELAYS_MS.len() => {
                let delay_ms = RETRY_DELAYS_MS[attempt];
                tracing::warn!(
                    error = %err,
                    attempt = attempt + 1,
                    retry_delay_ms = delay_ms,
                    entry_count = entries.len(),
                    "Transient SQLite lock during batch insert — retrying"
                );
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn insert_logs_batch_once(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (timestamp, hostname, facility, severity, app_name, process_id, message, raw, source_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;

        for entry in entries {
            stmt.execute(params![
                entry.timestamp,
                entry.hostname,
                entry.facility,
                entry.severity,
                entry.app_name,
                entry.process_id,
                entry.message,
                entry.raw,
                entry.source_ip
            ])?;
        }

        // Batch upsert hosts — group by hostname to avoid one upsert per log entry
        let mut host_counts: HashMap<&str, i64> = HashMap::new();
        for entry in entries {
            *host_counts.entry(entry.hostname.as_str()).or_insert(0) += 1;
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
        tracing::debug!(
            entry_count = entries.len(),
            unique_hosts = host_counts.len(),
            "Prepared batch insert transaction"
        );
    }

    tx.commit()?;
    tracing::debug!(
        entry_count = entries.len(),
        "Committed batch insert transaction"
    );
    Ok(entries.len())
}

fn is_transient_sqlite_lock(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<SqliteError>(),
            Some(SqliteError::SqliteFailure(sql_err, _))
                if matches!(sql_err.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    })
}

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

    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(retention_days as i64))
        .ok_or_else(|| {
            anyhow::anyhow!("date arithmetic overflow for retention_days={retention_days}")
        })?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Chunked DELETE: each iteration acquires a fresh connection from the pool
    // and releases it (along with its write lock) before sleeping, giving the
    // batch writer a window to acquire a connection between chunks.
    // Use received_at (server clock) instead of timestamp (device clock) so that
    // a device with a misconfigured clock cannot cause its logs to be purged
    // immediately (future timestamp) or retained forever (past timestamp).
    let mut total_deleted: usize = 0;
    loop {
        let conn = pool.get()?;
        let chunk = conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs WHERE received_at < ?1 LIMIT 10000
             )",
            params![cutoff],
        )?;
        total_deleted += chunk;
        drop(conn); // release back to pool before sleeping
        if chunk == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Incremental FTS merge — much shorter write-lock duration than full rebuild.
    // Best-effort: a small/empty index may return an error; log and continue.
    if total_deleted > 0 {
        let conn = pool.get()?;
        if let Err(e) =
            conn.execute_batch("INSERT INTO logs_fts(logs_fts) VALUES('merge=500,250');")
        {
            tracing::warn!(error = %e, "FTS merge skipped (non-fatal)");
        }
    }

    // Passive WAL checkpoint: attempt to move WAL pages into the main DB file
    // without blocking writers. Prevents unbounded WAL growth between restarts.
    {
        let conn = pool.get()?;
        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
            tracing::warn!(error = %e, "WAL checkpoint skipped (non-fatal)");
        }
    }

    tracing::info!(deleted = total_deleted, cutoff = %cutoff, "Purged old logs");
    Ok(total_deleted)
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

#[derive(Debug)]
struct DeletedChunk {
    deleted_rows: usize,
    hostnames: Vec<String>,
}

fn delete_oldest_logs_chunk(pool: &DbPool, chunk_size: usize) -> Result<DeletedChunk> {
    let conn = pool.get()?;
    let mut stmt =
        conn.prepare("SELECT id, hostname FROM logs ORDER BY received_at ASC, id ASC LIMIT ?1")?;
    let selected: Vec<(i64, String)> = stmt
        .query_map([chunk_size as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    if selected.is_empty() {
        return Ok(DeletedChunk {
            deleted_rows: 0,
            hostnames: Vec::new(),
        });
    }

    let mut hostnames: Vec<String> = selected.iter().map(|(_, host)| host.clone()).collect();
    hostnames.sort();
    hostnames.dedup();

    let ids: Vec<i64> = selected.iter().map(|(id, _)| *id).collect();
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("DELETE FROM logs WHERE id IN ({placeholders})");
    let deleted_rows = conn.execute(&sql, rusqlite::params_from_iter(ids.iter()))?;
    tracing::debug!(
        selected_rows = selected.len(),
        deleted_rows,
        affected_hosts = hostnames.len(),
        chunk_size,
        "Deleted oldest logs chunk"
    );

    Ok(DeletedChunk {
        deleted_rows,
        hostnames,
    })
}

fn reconcile_hosts(pool: &DbPool, hostnames: &[String]) -> Result<()> {
    if hostnames.is_empty() {
        return Ok(());
    }

    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    for hostname in hostnames {
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;

        if count == 0 {
            tx.execute("DELETE FROM hosts WHERE hostname = ?1", [hostname])?;
            continue;
        }

        let first_seen: String = tx.query_row(
            "SELECT MIN(received_at) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;
        let last_seen: String = tx.query_row(
            "SELECT MAX(received_at) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;
        tx.execute(
            "UPDATE hosts
             SET first_seen = ?2, last_seen = ?3, log_count = ?4
             WHERE hostname = ?1",
            params![hostname, first_seen, last_seen, count],
        )?;
    }
    tx.commit()?;
    tracing::debug!(
        host_count = hostnames.len(),
        "Reconciled host aggregates after log deletion"
    );
    Ok(())
}

fn checkpoint_wal_and_incremental_vacuum(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;
    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
        tracing::warn!(error = %e, "WAL checkpoint skipped (non-fatal)");
    } else {
        tracing::debug!("WAL checkpoint completed");
    }
    if let Err(e) = conn.execute_batch("PRAGMA incremental_vacuum(1000);") {
        tracing::warn!(error = %e, "incremental vacuum skipped (non-fatal)");
    } else {
        tracing::debug!("Incremental vacuum completed");
    }
    Ok(())
}

fn storage_limits_enabled(config: &StorageConfig) -> bool {
    config.max_db_size_mb > 0 || config.min_free_disk_mb > 0
}

fn recovery_targets(config: &StorageConfig) -> StorageRecovery {
    StorageRecovery {
        logical_db_size_bytes: mb_to_bytes(config.recovery_db_size_mb),
        free_disk_bytes: (config.min_free_disk_mb > 0)
            .then(|| mb_to_bytes(config.recovery_free_disk_mb)),
    }
}

fn exceeds_trigger(metrics: &StorageMetrics, config: &StorageConfig) -> bool {
    (config.max_db_size_mb > 0
        && metrics.logical_db_size_bytes > mb_to_bytes(config.max_db_size_mb))
        || (config.min_free_disk_mb > 0
            && metrics.free_disk_bytes.unwrap_or(0) < mb_to_bytes(config.min_free_disk_mb))
}

fn within_recovery(
    metrics: &StorageMetrics,
    recovery: &StorageRecovery,
    config: &StorageConfig,
) -> bool {
    let db_ok = config.max_db_size_mb == 0
        || metrics.logical_db_size_bytes <= recovery.logical_db_size_bytes;
    let disk_ok = config.min_free_disk_mb == 0
        || metrics.free_disk_bytes.unwrap_or(0) >= recovery.free_disk_bytes.unwrap_or(0);
    db_ok && disk_ok
}

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1_048_576)
}

fn physical_db_size_bytes(db_path: &Path) -> Result<u64> {
    let mut total = file_size_if_exists(db_path)?;
    total += file_size_if_exists(&db_path.with_extension(format!(
        "{}-wal",
        db_path.extension().and_then(|ext| ext.to_str()).unwrap_or_default()
    )))?;
    total += file_size_if_exists(&db_path.with_extension(format!(
        "{}-shm",
        db_path.extension().and_then(|ext| ext.to_str()).unwrap_or_default()
    )))?;
    Ok(total)
}

fn file_size_if_exists(path: &Path) -> Result<u64> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err.into()),
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
mod tests {
    use super::*;
    use crate::config::StorageConfig;

    fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
        StorageConfig::for_test(db_path)
    }

    /// Create an isolated test pool using a temp file (not :memory: — FTS5 needs file)
    fn test_pool() -> (DbPool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let config = test_storage_config(db_path);
        let pool = init_pool(&config).unwrap();
        (pool, dir) // keep dir alive for test duration
    }

    fn make_entry(ts: &str, host: &str, severity: &str, msg: &str) -> LogBatchEntry {
        LogBatchEntry {
            timestamp: ts.to_string(),
            hostname: host.to_string(),
            facility: None,
            severity: severity.to_string(),
            app_name: None,
            process_id: None,
            message: msg.to_string(),
            raw: msg.to_string(),
            source_ip: "127.0.0.1:514".to_string(),
        }
    }

    fn update_received_at(pool: &DbPool, message: &str, received_at: &str) {
        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE logs SET received_at = ?1 WHERE message = ?2",
            params![received_at, message],
        )
        .unwrap();
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
    fn test_storage_metrics_report_logical_size() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_storage_config(dir.path().join("metrics.db"));
        let pool = init_pool(&config).unwrap();
        insert_logs_batch(
            &pool,
            &[make_entry(
                "2026-01-01T00:00:01Z",
                "host-a",
                "info",
                "hello",
            )],
        )
        .unwrap();

        let metrics = get_storage_metrics(&pool, &config).unwrap();
        assert!(metrics.logical_db_size_bytes > 0);
        assert!(metrics.physical_db_size_bytes >= metrics.logical_db_size_bytes);
        assert!(metrics.free_disk_bytes.is_some());
    }

    #[test]
    fn test_init_pool_enables_incremental_auto_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_storage_config(dir.path().join("autovac.db"));
        let pool = init_pool(&config).unwrap();
        let conn = pool.get().unwrap();
        let mode: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, 2);
    }

    #[test]
    fn test_init_pool_migrates_existing_db_to_incremental_auto_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA auto_vacuum=NONE;
             VACUUM;
             CREATE TABLE legacy_probe(id INTEGER PRIMARY KEY);",
        )
        .unwrap();
        drop(conn);

        let config = test_storage_config(db_path);
        let pool = init_pool(&config).unwrap();
        let conn = pool.get().unwrap();
        let mode: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, 2);
    }

    #[test]
    fn test_init_pool_applies_busy_timeout_to_each_pooled_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_storage_config(dir.path().join("busy-timeout.db"));
        config.pool_size = 2;
        let pool = init_pool(&config).unwrap();

        let conn1 = pool.get().unwrap();
        let conn2 = pool.get().unwrap();

        let busy_timeout_1: i64 = conn1
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        let busy_timeout_2: i64 = conn2
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();

        assert_eq!(busy_timeout_1, 5000);
        assert_eq!(busy_timeout_2, 5000);
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
            make_entry(
                "2026-01-01T00:00:01Z",
                "host-a",
                "err",
                "disk full on /dev/sda",
            ),
            make_entry(
                "2026-01-01T00:00:02Z",
                "host-b",
                "info",
                "connection established",
            ),
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
        // Error message must be generic — no schema details leaked
        let msg = result.unwrap_err().to_string();
        assert_eq!(msg, "Search query failed", "error must be generic");
    }

    // --- validate_fts_query unit tests ---

    #[test]
    fn test_validate_fts_query_valid() {
        assert!(validate_fts_query("disk error").is_ok());
        assert!(validate_fts_query("nginx AND 502").is_ok());
        // Exactly 16 terms should pass
        let sixteen = (0..16)
            .map(|i| format!("term{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(validate_fts_query(&sixteen).is_ok());
        // Exactly 512 chars should pass
        let at_limit = "a".repeat(512);
        assert!(validate_fts_query(&at_limit).is_ok());
    }

    #[test]
    fn test_validate_fts_query_too_long() {
        let long_query = "a".repeat(513);
        let result = validate_fts_query(&long_query);
        assert!(result.is_err(), "query > 512 chars should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("513"), "error should mention actual length");
        assert!(msg.contains("512"), "error should mention the limit");
    }

    #[test]
    fn test_validate_fts_query_too_many_terms() {
        let many_terms = (0..17)
            .map(|i| format!("term{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let result = validate_fts_query(&many_terms);
        assert!(result.is_err(), "query with 17 terms should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("17"), "error should mention actual term count");
        assert!(msg.contains("16"), "error should mention the limit");
    }

    #[test]
    fn test_purge_old_logs_removes_old() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2020-01-01T00:00:00Z", "host-a", "info", "old message"),
            make_entry("2099-01-01T00:00:00Z", "host-a", "info", "future message"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        // Purge uses received_at (server clock), not timestamp (device clock).
        // Backdate the first entry's received_at so it falls outside retention.
        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE logs SET received_at = '2020-01-01T00:00:00Z' WHERE message = 'old message'",
            [],
        )
        .unwrap();
        drop(conn);

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
        let (pool, dir) = test_pool();
        let stats = get_stats(&pool, &test_storage_config(dir.path().join("test.db"))).unwrap();
        assert_eq!(stats.total_logs, 0);
        assert_eq!(stats.total_hosts, 0);
        // oldest_log and newest_log should be None on empty DB
        assert!(stats.oldest_log.is_none());
        assert!(stats.newest_log.is_none());
        assert!(stats.free_disk_mb.is_some());
    }

    #[test]
    fn test_enforce_storage_budget_deletes_by_received_at_until_recovery_target() {
        let (pool, dir) = test_pool();
        let large_old = "oldest-".repeat(350_000);
        let large_new = "newest-".repeat(30_000);
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "deleted-host", "info", &large_old),
            make_entry("2026-01-01T00:00:02Z", "surviving-host", "info", &large_new),
        ];
        insert_logs_batch(&pool, &entries).unwrap();
        update_received_at(&pool, &large_old, "2026-01-01T00:00:00Z");
        update_received_at(&pool, &large_new, "2026-01-02T00:00:00Z");

        let mut config = test_storage_config(dir.path().join("test.db"));
        config.max_db_size_mb = 3;
        config.recovery_db_size_mb = 2;

        let outcome = enforce_storage_budget(&pool, &config).unwrap();
        assert!(outcome.deleted_rows > 0);
        assert!(outcome.metrics.logical_db_size_bytes <= outcome.recovery.logical_db_size_bytes);

        let rows = tail_logs(&pool, None, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, large_new);
    }

    #[test]
    fn test_enforce_storage_budget_reconciles_hosts_after_deletes() {
        let (pool, dir) = test_pool();
        let large_oldest = "delete-me-1-".repeat(150_000);
        let large_older = "delete-me-2-".repeat(150_000);
        let large_keep = "keep-me-".repeat(30_000);
        let entries = vec![
            make_entry(
                "2026-01-01T00:00:01Z",
                "deleted-host",
                "info",
                &large_oldest,
            ),
            make_entry("2026-01-01T00:00:02Z", "deleted-host", "info", &large_older),
            make_entry(
                "2026-01-01T00:00:03Z",
                "surviving-host",
                "info",
                &large_keep,
            ),
        ];
        insert_logs_batch(&pool, &entries).unwrap();
        update_received_at(&pool, &large_oldest, "2026-01-01T00:00:00Z");
        update_received_at(&pool, &large_older, "2026-01-01T00:00:01Z");
        update_received_at(&pool, &large_keep, "2026-01-02T00:00:00Z");

        let mut config = test_storage_config(dir.path().join("test.db"));
        config.max_db_size_mb = 3;
        config.recovery_db_size_mb = 2;

        enforce_storage_budget(&pool, &config).unwrap();

        let hosts = list_hosts(&pool).unwrap();
        assert!(hosts.iter().all(|host| host.hostname != "deleted-host"));
        let surviving = hosts
            .iter()
            .find(|host| host.hostname == "surviving-host")
            .unwrap();
        assert_eq!(surviving.log_count, 1);
    }

    #[derive(Clone)]
    struct FakeDiskSpaceProbe {
        values: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
    }

    impl FakeDiskSpaceProbe {
        fn new(values: Vec<u64>) -> Self {
            Self {
                values: std::sync::Arc::new(std::sync::Mutex::new(values)),
            }
        }
    }

    impl DiskSpaceProbe for FakeDiskSpaceProbe {
        fn free_bytes(&self, _path: &Path) -> Result<u64> {
            let mut values = self.values.lock().unwrap();
            let value = if values.len() > 1 {
                values.remove(0)
            } else {
                *values.first().unwrap_or(&0)
            };
            Ok(value)
        }
    }

    #[test]
    fn test_enforce_storage_budget_recovers_when_free_disk_threshold_is_breached() {
        let (pool, dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "deleted-host", "info", "older"),
            make_entry("2026-01-01T00:00:02Z", "surviving-host", "info", "newer"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();
        update_received_at(&pool, "older", "2026-01-01T00:00:00Z");
        update_received_at(&pool, "newer", "2026-01-02T00:00:00Z");

        let mut config = test_storage_config(dir.path().join("test.db"));
        config.max_db_size_mb = 0;
        config.recovery_db_size_mb = 0;
        config.min_free_disk_mb = 512;
        config.recovery_free_disk_mb = 768;

        let probe = FakeDiskSpaceProbe::new(vec![64 * 1_048_576, 900 * 1_048_576]);
        let outcome = enforce_storage_budget_with_probe(&pool, &config, &probe).unwrap();

        assert!(outcome.deleted_rows > 0);
        assert!(
            outcome.metrics.free_disk_bytes.unwrap() >= outcome.recovery.free_disk_bytes.unwrap()
        );
    }

    #[test]
    fn test_enforce_storage_budget_is_noop_when_limits_disabled() {
        let (pool, dir) = test_pool();
        let config = test_storage_config(dir.path().join("test.db"));
        let mut disabled = config.clone();
        disabled.max_db_size_mb = 0;
        disabled.recovery_db_size_mb = 0;
        disabled.min_free_disk_mb = 0;
        disabled.recovery_free_disk_mb = 0;

        let outcome = enforce_storage_budget(&pool, &disabled).unwrap();
        assert_eq!(outcome.deleted_rows, 0);
        assert!(!outcome.write_blocked);
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

    #[test]
    fn test_batch_multiple_entries_same_host() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-x", "info", "msg1"),
            make_entry("2026-01-01T00:00:02Z", "host-x", "info", "msg2"),
            make_entry("2026-01-01T00:00:03Z", "host-x", "err", "msg3"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let hosts = list_hosts(&pool).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "host-x");
        assert_eq!(hosts[0].log_count, 3);
    }

    #[test]
    fn test_batch_empty() {
        let (pool, _dir) = test_pool();
        let result = insert_logs_batch(&pool, &[]);
        assert!(result.is_ok(), "empty batch should not error");
        assert_eq!(result.unwrap(), 0);

        let rows = tail_logs(&pool, None, None, 10).unwrap();
        assert_eq!(rows.len(), 0, "no rows should exist after empty batch");

        let hosts = list_hosts(&pool).unwrap();
        assert_eq!(hosts.len(), 0, "no hosts should exist after empty batch");
    }

    #[test]
    fn test_search_timestamp_range_filtering() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:00Z", "host-a", "info", "early message"),
            make_entry("2026-06-15T12:00:00Z", "host-a", "info", "mid message"),
            make_entry("2026-12-31T23:59:59Z", "host-a", "info", "late message"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        // from only
        let params = SearchParams {
            query: None,
            hostname: None,
            severity: None,
            severity_in: None,
            app_name: None,
            from: Some("2026-06-01T00:00:00Z".into()),
            to: None,
            limit: None,
        };
        let results = search_logs(&pool, &params).unwrap();
        assert_eq!(results.len(), 2, "from filter should return mid + late");

        // to only
        let params = SearchParams {
            query: None,
            hostname: None,
            severity: None,
            severity_in: None,
            app_name: None,
            from: None,
            to: Some("2026-06-30T00:00:00Z".into()),
            limit: None,
        };
        let results = search_logs(&pool, &params).unwrap();
        assert_eq!(results.len(), 2, "to filter should return early + mid");

        // from + to (narrow window)
        let params = SearchParams {
            query: None,
            hostname: None,
            severity: None,
            severity_in: None,
            app_name: None,
            from: Some("2026-06-01T00:00:00Z".into()),
            to: Some("2026-06-30T00:00:00Z".into()),
            limit: None,
        };
        let results = search_logs(&pool, &params).unwrap();
        assert_eq!(results.len(), 1, "from+to filter should return only mid");
        assert_eq!(results[0].message, "mid message");
    }

    #[test]
    fn test_severity_to_num() {
        assert_eq!(severity_to_num("emerg"), Some(0));
        assert_eq!(severity_to_num("alert"), Some(1));
        assert_eq!(severity_to_num("crit"), Some(2));
        assert_eq!(severity_to_num("err"), Some(3));
        assert_eq!(severity_to_num("warning"), Some(4));
        assert_eq!(severity_to_num("notice"), Some(5));
        assert_eq!(severity_to_num("info"), Some(6));
        assert_eq!(severity_to_num("debug"), Some(7));
        // Edge cases
        assert_eq!(severity_to_num(""), None);
        assert_eq!(severity_to_num("ERROR"), None, "case sensitive");
        assert_eq!(severity_to_num("critical"), None, "not a valid syslog name");
        assert_eq!(
            severity_to_num("warn"),
            None,
            "must be 'warning' not 'warn'"
        );
    }

    #[test]
    fn test_error_summary_severity_filter() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:00Z", "host-a", "err", "error msg"),
            make_entry("2026-01-01T00:00:01Z", "host-a", "warning", "warn msg"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "info msg"),
            make_entry("2026-01-01T00:00:03Z", "host-a", "debug", "debug msg"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let summary = get_error_summary(&pool, None, None).unwrap();
        // Only err and warning should appear (not info, debug)
        assert_eq!(summary.len(), 2);
        let severities: Vec<&str> = summary.iter().map(|e| e.severity.as_str()).collect();
        assert!(severities.contains(&"err"));
        assert!(severities.contains(&"warning"));
    }

    #[test]
    fn test_search_severity_in_filter() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:00Z", "host-a", "emerg", "emerg msg"),
            make_entry("2026-01-01T00:00:01Z", "host-a", "err", "err msg"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "warning", "warn msg"),
            make_entry("2026-01-01T00:00:03Z", "host-a", "info", "info msg"),
            make_entry("2026-01-01T00:00:04Z", "host-a", "debug", "debug msg"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let params = SearchParams {
            query: None,
            hostname: None,
            severity: None,
            severity_in: Some(vec!["emerg".into(), "err".into(), "warning".into()]),
            app_name: None,
            from: None,
            to: None,
            limit: None,
        };
        let results = search_logs(&pool, &params).unwrap();
        assert_eq!(results.len(), 3, "severity_in should match exactly 3");
        for r in &results {
            assert!(
                ["emerg", "err", "warning"].contains(&r.severity.as_str()),
                "unexpected severity: {}",
                r.severity
            );
        }
    }

    #[test]
    fn test_batch_mixed_hosts() {
        let (pool, _dir) = test_pool();
        let entries = vec![
            make_entry("2026-01-01T00:00:01Z", "host-a", "info", "a msg1"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "a msg2"),
            make_entry("2026-01-01T00:00:03Z", "host-b", "info", "b msg1"),
        ];
        insert_logs_batch(&pool, &entries).unwrap();

        let hosts = list_hosts(&pool).unwrap();
        assert_eq!(hosts.len(), 2);

        let ha = hosts.iter().find(|h| h.hostname == "host-a").unwrap();
        assert_eq!(ha.log_count, 2);

        let hb = hosts.iter().find(|h| h.hostname == "host-b").unwrap();
        assert_eq!(hb.log_count, 1);
    }
}
