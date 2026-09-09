//! SQLite pool construction, schema, and migrations for the log intelligence
//! core.
//!
//! Owns the full schema: the `logs` table + FTS5 index, AI/graph/heartbeat
//! projections, and the sequential migrations tracked by
//! `KNOWN_SCHEMA_VERSION`. Migrations run at startup; heavy ones log
//! `Migration N: starting ...` lines, and the one-time
//! `auto_vacuum=INCREMENTAL` conversion VACUUM is logged loudly (it can take
//! minutes on large DBs).
//!
//! Invariants: SQLite allows a single writer — callers serialize writes via
//! the write-admission API, and the service layer issues only
//! `config::PoolBudget::read_permits()` read permits, holding the rest of the
//! pool back for the lanes enumerated in `config::UNPERMITTED_CONNECTION_LANES`
//! that acquire a connection without one. That budget is only true while the
//! lock is taken **before** the connection, which is what [`write_conn`] is
//! for. Graph projection uses a dedicated, non-pooled connection for its TEMP
//! staging, so it cannot participate in a pool/write-lock cycle. WAL mode plus
//! `synchronous=NORMAL` is the standing durability trade-off.

use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use scheduled_thread_pool::ScheduledThreadPool;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use crate::config::StorageConfig;

pub type DbPool = Pool<SqliteConnectionManager>;

/// True when `err` was caused by r2d2 failing to yield a pooled connection.
///
/// This deliberately matches structurally rather than parsing r2d2's display
/// text. Callers handle pool saturation and connection-establishment failures
/// identically at this boundary: retain work or return retryable backpressure.
///
/// A pool-acquisition failure produces an `r2d2::Error` and **no**
/// `rusqlite::Error` anywhere in the chain — the statement never reached
/// SQLite — so a predicate that only matches `rusqlite::ErrorCode` reads it as
/// an unrecoverable failure. Consult this alongside any such matching wherever
/// that distinction changes the outcome.
///
/// Consulted today by `ServiceError::classify_db_error`, the ingest batch
/// writer (`receiver::writer::is_retryable_write_error`), the OTLP HTTP
/// handlers, the notification digest, and the Agent Observatory projector.
/// Deliberately NOT consulted by `db::ingest::is_transient_sqlite_lock` — see
/// its doc for why.
pub(crate) fn is_pool_acquire_failure(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.is::<r2d2::Error>())
}

static WRITE_LOCK: parking_lot::ReentrantMutex<()> = parking_lot::ReentrantMutex::new(());
static WRITE_ADMISSION: parking_lot::ReentrantMutex<()> = parking_lot::ReentrantMutex::new(());

/// Admission gate used by ordinary lock-first writers.
fn write_admission() -> parking_lot::ReentrantMutexGuard<'static, ()> {
    WRITE_ADMISSION.lock()
}

/// Dedicated non-pooled connection used for graph TEMP staging.
pub(crate) struct GraphStagingConnection(Connection);

impl std::ops::Deref for GraphStagingConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for GraphStagingConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn graph_staging_conn(pool: &DbPool) -> Result<GraphStagingConnection> {
    let (db_path, synchronous, cache_size, mmap_size, analysis_limit, busy_timeout): (
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = {
        let conn = pool.get()?;
        let db_path = conn.query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )?;
        (
            db_path,
            conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?,
            conn.query_row("PRAGMA cache_size", [], |row| row.get(0))?,
            conn.query_row("PRAGMA mmap_size", [], |row| row.get(0))?,
            conn.query_row("PRAGMA analysis_limit", [], |row| row.get(0))?,
            conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?,
        )
    };
    anyhow::ensure!(
        !db_path.is_empty(),
        "graph staging requires a file-backed database"
    );
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "synchronous", synchronous)?;
    conn.pragma_update(None, "cache_size", cache_size)?;
    conn.pragma_update(None, "mmap_size", mmap_size)?;
    conn.pragma_update(None, "analysis_limit", analysis_limit)?;
    conn.pragma_update(None, "busy_timeout", busy_timeout)?;
    Ok(GraphStagingConnection(conn))
}

/// Process-wide SQLite **write serialization** lock.
///
/// SQLite permits only one writer at a time, but cortex runs an r2d2 pool of several
/// connections with multiple concurrent writer subsystems (syslog/docker ingest,
/// heartbeat, notifications, AI index, retention maintenance). Without serialization
/// these race SQLite's single write lock, exceed `busy_timeout`, and surface as
/// `database is locked` — dropping log batches. Every write transaction acquires this
/// guard so writers queue in-process instead of colliding at the SQLite layer; reads
/// stay concurrent on the pool (WAL allows many readers). Reentrant so a write path that
/// nests guarded helpers on a single thread cannot deadlock.
///
/// **Do not call this while holding a pooled connection.** Acquiring it can block
/// for as long as the current holder runs — 15m25s during the 2026-08-24 incident,
/// where an orphan sweep held it — and a caller queued here while holding a
/// connection keeps that connection checked out and unusable for the whole wait.
/// That is what `config::PoolBudget` cannot account for: the budget assumes a
/// connection is held only while work is being done. Pair the two through
/// [`write_conn`] instead, which takes the admission gate and lock first. The
/// raw lock is private; graph staging uses a dedicated non-pooled connection.
fn write_lock() -> parking_lot::ReentrantMutexGuard<'static, ()> {
    WRITE_LOCK.lock()
}

/// Lock live graph tables after building connection-local TEMP staging.
///
/// Requiring the opaque dedicated-connection type makes the connection-first
/// exception explicit. Because this connection is outside r2d2, holding it
/// while queued on the lock cannot starve a lock-first writer of pool capacity.
pub(crate) fn graph_staging_write_lock(
    _conn: &GraphStagingConnection,
) -> parking_lot::ReentrantMutexGuard<'static, ()> {
    write_lock()
}

#[cfg(test)]
pub(crate) fn test_write_lock() -> parking_lot::ReentrantMutexGuard<'static, ()> {
    write_lock()
}

/// A pooled connection that was acquired **after** the process-wide write lock,
/// holding both for as long as the value lives.
///
/// This is the only sanctioned way to pair the two. The ordering matters in one
/// direction only: a caller that takes the connection first pins a scarce pooled
/// connection for the entire time it is queued on [`write_lock`], which is
/// unbounded — it is however long the current writer runs. Taking the lock first
/// means a queued writer holds nothing, so the pool stays available to readers
/// and to the resident lanes `config::UNPERMITTED_CONNECTION_LANES` budgets for.
///
/// Field order is the drop order: `conn` returns to the pool before `_guard`
/// releases the lock, and `_guard` releases before `_admission` admits another
/// writer.
pub struct WriteConn {
    conn: r2d2::PooledConnection<SqliteConnectionManager>,
    _guard: parking_lot::ReentrantMutexGuard<'static, ()>,
    _admission: parking_lot::ReentrantMutexGuard<'static, ()>,
}

impl std::ops::Deref for WriteConn {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for WriteConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl std::fmt::Debug for WriteConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteConn")
    }
}

/// Take the write lock, then borrow a pooled connection for the guarded work.
///
/// Blocking in both stages, so callers must already be off the async runtime
/// (`spawn_blocking`, or a synchronous worker thread). The lock wait is
/// unbounded; the connection wait is bounded by the pool's `connection_timeout`,
/// and the guard is released if it expires. Request-scoped writers that must
/// answer "busy" rather than queue want [`try_write_conn_for`] instead.
///
/// Graph projection stages on a dedicated connection, so it cannot consume the
/// pooled connection this lock-first path is waiting to acquire.
pub fn write_conn(pool: &DbPool) -> Result<WriteConn> {
    let admission = write_admission();
    let guard = write_lock();
    let conn = pool.get()?;
    Ok(WriteConn {
        conn,
        _guard: guard,
        _admission: admission,
    })
}

/// Why a bounded [`try_write_conn_for`] gave up.
#[derive(Debug)]
pub(crate) enum WriteConnBusy {
    /// Another writer held admission for the whole budget.
    Admission,
    /// Another writer still held the process-wide write lock when the budget
    /// expired.
    Lock,
    /// The lock was acquired and released again; the pool yielded no connection.
    Pool(r2d2::Error),
}

/// Bounded [`write_conn`] for request-scoped writers that must report
/// backpressure instead of queueing behind an arbitrarily long write.
///
/// Admission, lock, and pool acquisition share one total `timeout`. Guards are
/// dropped before returning an error, so a caller that retries never sleeps
/// while holding either writer gate.
pub(crate) fn try_write_conn_for(
    pool: &DbPool,
    timeout: std::time::Duration,
) -> std::result::Result<WriteConn, WriteConnBusy> {
    let started = Instant::now();
    let admission = WRITE_ADMISSION
        .try_lock_for(timeout)
        .ok_or(WriteConnBusy::Admission)?;

    let remaining = timeout.saturating_sub(started.elapsed());
    let guard = WRITE_LOCK
        .try_lock_for(remaining)
        .ok_or(WriteConnBusy::Lock)?;

    let remaining = timeout.saturating_sub(started.elapsed());
    match pool.get_timeout(remaining) {
        Ok(conn) => Ok(WriteConn {
            conn,
            _guard: guard,
            _admission: admission,
        }),
        Err(error) => {
            drop(guard);
            Err(WriteConnBusy::Pool(error))
        }
    }
}

pub const KNOWN_SCHEMA_VERSION: i64 = 58;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SchemaVersionInfo {
    pub version: i64,
    pub last_migration_at: Option<String>,
    pub known_version: i64,
}

/// Process-wide r2d2 background thread pool, shared across every `DbPool`
/// this process creates.
///
/// In production a process holds exactly one `DbPool`, so a single thread
/// would suffice. But `cargo test` runs in one process and each test that
/// calls `init_pool()` creates its own independent `DbPool` sharing this same
/// static pool — under full test-suite parallelism, dozens of pools' worth
/// of background connection work queues behind a single thread, exceeding
/// the 6s `connection_timeout` and surfacing as spurious "timed out waiting
/// for connection" failures unrelated to any actual bug under test. Sized
/// with headroom for concurrent test execution, not just single-process
/// production use.
fn shared_scheduled_thread_pool() -> Arc<ScheduledThreadPool> {
    static POOL: OnceLock<Arc<ScheduledThreadPool>> = OnceLock::new();
    Arc::clone(POOL.get_or_init(|| Arc::new(ScheduledThreadPool::new(8))))
}

pub fn read_schema_version_info(pool: &DbPool) -> Result<SchemaVersionInfo> {
    let conn = pool.get()?;
    read_schema_version_info_conn(&conn)
}

/// Probe `schema_migrations` from an already-borrowed connection. Used by
/// callers that do not own a [`DbPool`] (e.g. the scanner's checkpoint store).
pub fn read_schema_version_info_conn(conn: &Connection) -> Result<SchemaVersionInfo> {
    let (version, last_migration_at): (Option<i64>, Option<String>) = conn
        .query_row(
            "SELECT MAX(version), MAX(applied_at) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|err| anyhow::anyhow!("schema_migrations probe failed: {err}"))?;
    Ok(SchemaVersionInfo {
        version: version.unwrap_or(0),
        last_migration_at,
        known_version: KNOWN_SCHEMA_VERSION,
    })
}

/// Initialize the database pool and schema
pub fn init_pool(config: &StorageConfig) -> Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = config.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let storage = config.clone();
    let manager = SqliteConnectionManager::file(&config.db_path)
        .with_init(move |conn| configure_connection_pragmas(conn, &storage));
    // connection_timeout is set to 6s — slightly above the service layer's 5s
    // DB_ACQUIRE_TIMEOUT so the semaphore fires first, giving a clean ServiceError::Busy
    // rather than an r2d2 timeout on the rare path where background tasks exhaust the pool.
    let pool = Pool::builder()
        .max_size(config.pool_size)
        .connection_timeout(std::time::Duration::from_secs(6))
        .thread_pool(shared_scheduled_thread_pool())
        .build(manager)?;

    // Initialize schema. `mut` so migration 25's backfill can open an explicit
    // transaction (`Connection::transaction_with_behavior` needs `&mut`).
    let mut conn = pool.get()?;

    let auto_vacuum_mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
    if auto_vacuum_mode != 2 {
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        if page_count > 0 {
            // One-time conversion: a full VACUUM rewrites the whole file with
            // the write lock held — minutes on a multi-GB DB. Log loudly so a
            // long first boot after this policy change is explainable and the
            // compose healthcheck start_period can be tuned (full-review PM7).
            let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            let db_mb = (page_count * page_size) / (1024 * 1024);
            tracing::info!(
                db_size_mb = db_mb,
                "Converting database to auto_vacuum=INCREMENTAL — one-time full \
                 VACUUM; this can take minutes on large databases"
            );
            let vacuum_started = std::time::Instant::now();
            conn.execute_batch("VACUUM;")?;
            tracing::info!(
                db_size_mb = db_mb,
                elapsed_ms = vacuum_started.elapsed().as_millis() as u64,
                "auto_vacuum conversion VACUUM complete"
            );
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
            source_ip   TEXT NOT NULL DEFAULT '',
            ai_tool            TEXT,
            ai_project         TEXT,
            ai_session_id      TEXT,
            ai_transcript_path TEXT,
            metadata_json      TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_hostname  ON logs(hostname);
        CREATE INDEX IF NOT EXISTS idx_logs_severity  ON logs(severity);
        CREATE INDEX IF NOT EXISTS idx_logs_app_name  ON logs(app_name);
        CREATE INDEX IF NOT EXISTS idx_logs_host_time ON logs(hostname, timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_sev_time ON logs(severity, timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_app_name_timestamp ON logs(app_name, timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_received_at ON logs(received_at);
        CREATE INDEX IF NOT EXISTS idx_logs_hostname_received_at ON logs(hostname, received_at);
        CREATE INDEX IF NOT EXISTS idx_logs_source_ip_timestamp ON logs(source_ip, timestamp);
        DROP INDEX IF EXISTS idx_logs_source_ip;

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

        -- Migration version table: each row records a completed schema migration.
        -- Guards migrations so they run exactly once per database, not on every startup.
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER PRIMARY KEY,
            applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
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

    // Migration 1: drop FTS5 DELETE/UPDATE triggers from existing databases.
    // These triggers caused write-lock contention during bulk deletes (retention
    // purge, storage enforcement). See schema comment above for rationale.
    // Guarded by schema_migrations so it runs exactly once per database.
    let migration_1_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_1_applied {
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS logs_ad;
             DROP TRIGGER IF EXISTS logs_au;
             INSERT INTO schema_migrations (version) VALUES (1);",
        )?;
        tracing::info!("Migration 1: dropped FTS5 DELETE/UPDATE triggers");
    }

    // Migration 2: store per Docker host/container checkpoints for optional
    // docker-socket-proxy log ingestion. This lets short cortex outages
    // replay from Docker's local log store with /containers/{id}/logs?since=.
    let migration_2_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 2",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_2_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS docker_ingest_checkpoints (
                 host_name      TEXT NOT NULL,
                 container_id   TEXT NOT NULL,
                 last_timestamp TEXT NOT NULL,
                 updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 PRIMARY KEY (host_name, container_id)
             );
             INSERT INTO schema_migrations (version) VALUES (2);",
        )?;
        tracing::info!("Migration 2: created docker_ingest_checkpoints table");
    }

    // Migration 3: composite index on (app_name, received_at).
    //
    // The new `purge_by_tag_window` function deletes rows by `app_name` within
    // a `received_at` window (e.g. all `adguard-allowed` older than 7 days).
    // Without this composite index, each chunked DELETE scans the entire
    // app_name partition before applying the time filter — pathological at
    // AdGuard volumes.
    //
    // First-run cost: on a multi-million-row database the CREATE INDEX may
    // take several minutes and holds the write lock for that duration. The
    // /health endpoint will not respond and syslog UDP packets may be dropped
    // at the kernel buffer during that window. Operators upgrading on a
    // populated DB should plan for a brief health-check gap.
    let migration_3_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 3",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_3_applied {
        tracing::info!(
            "Migration 3: starting CREATE INDEX idx_logs_app_name_received_at \
             — may take several minutes on large databases, write lock held"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_app_name_received_at \
                 ON logs(app_name, received_at);
             INSERT INTO schema_migrations (version) VALUES (3);",
        )?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 3: composite index (app_name, received_at) created"
        );
    }

    // Migration 4: add AI transcript metadata columns and indexes.
    let migration_4_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 4",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_4_applied {
        for (column, sql_type) in [
            ("ai_tool", "TEXT"),
            ("ai_project", "TEXT"),
            ("ai_session_id", "TEXT"),
            ("ai_transcript_path", "TEXT"),
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name = ?1",
                    [column],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0)
                > 0;
            if !exists {
                conn.execute_batch(&format!("ALTER TABLE logs ADD COLUMN {column} {sql_type}"))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_ai_project_time
                 ON logs(ai_project, timestamp)
                 WHERE ai_project IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_session
                 ON logs(ai_tool, ai_project, ai_session_id)
                 WHERE ai_tool IS NOT NULL;
             INSERT INTO schema_migrations (version) VALUES (4);",
        )?;
        tracing::info!("Migration 4: added AI transcript metadata columns and indexes");
    }

    let migration_5_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 5",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_5_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS transcript_sources (
                 id              INTEGER PRIMARY KEY AUTOINCREMENT,
                 canonical_path  TEXT NOT NULL UNIQUE,
                 source_kind     TEXT NOT NULL,
                 file_size       INTEGER,
                 file_mtime      INTEGER,
                 content_hash    TEXT,
                 last_offset     INTEGER NOT NULL DEFAULT 0,
                 last_indexed_at TEXT,
                 last_error      TEXT
             );
             INSERT INTO schema_migrations (version) VALUES (5);",
        )?;
        tracing::info!("Migration 5: created transcript_sources table");
    }

    let migration_6_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 6",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_6_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS transcript_import_records (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 source_id   INTEGER NOT NULL REFERENCES transcript_sources(id),
                 record_key  TEXT NOT NULL,
                 imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(source_id, record_key)
             );
             CREATE INDEX IF NOT EXISTS idx_transcript_import_records_source_id
                 ON transcript_import_records(source_id);
             INSERT INTO schema_migrations (version) VALUES (6);",
        )?;
        tracing::info!("Migration 6: created transcript_import_records table");
    }

    let migration_7_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 7",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_7_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS transcript_parse_errors (
                 id             INTEGER PRIMARY KEY AUTOINCREMENT,
                 source_id      INTEGER NOT NULL REFERENCES transcript_sources(id),
                 line_no        INTEGER NOT NULL,
                 error          TEXT NOT NULL,
                 record_preview TEXT NOT NULL,
                 seen_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(source_id, line_no, error, record_preview)
             );
             CREATE INDEX IF NOT EXISTS idx_transcript_parse_errors_source_seen
                 ON transcript_parse_errors(source_id, seen_at DESC);
             CREATE INDEX IF NOT EXISTS idx_transcript_parse_errors_seen
                 ON transcript_parse_errors(seen_at DESC);
             INSERT INTO schema_migrations (version) VALUES (7);",
        )?;
        tracing::info!("Migration 7: created transcript_parse_errors table");
    }

    let migration_8_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 8",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_8_applied {
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_logs_ai_project_time;
             DROP INDEX IF EXISTS idx_logs_ai_session;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_project_time
                 ON logs(ai_project, timestamp)
                 WHERE ai_project IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_session
                 ON logs(ai_tool, ai_project, ai_session_id)
                 WHERE ai_tool IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_transcript_path
                 ON logs(ai_transcript_path)
                 WHERE ai_transcript_path IS NOT NULL;
             INSERT INTO schema_migrations (version) VALUES (8);",
        )?;
        tracing::info!("Migration 8: rebuilt AI metadata indexes as partial indexes");
    }

    let migration_9_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 9",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_9_applied {
        let metadata_col_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name = 'metadata_json'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if !metadata_col_exists {
            conn.execute_batch("ALTER TABLE logs ADD COLUMN metadata_json TEXT")?;
        }
        conn.execute_batch("INSERT INTO schema_migrations (version) VALUES (9);")?;
        tracing::info!("Migration 9: added logs.metadata_json");
    }

    // Migration 10: error signature detection tables.
    let migration_10_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 10",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_10_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS error_signatures (
                 signature_hash      TEXT NOT NULL,
                 normalizer_version  INTEGER NOT NULL,
                 template            TEXT NOT NULL,
                 sample_message      TEXT NOT NULL,
                 sample_hostname     TEXT NOT NULL,
                 sample_app_name     TEXT,
                 severity            TEXT NOT NULL,
                 first_seen_at       TEXT NOT NULL,
                 last_seen_at        TEXT NOT NULL,
                 total_count         INTEGER NOT NULL DEFAULT 0,
                 acknowledged_at     TEXT,
                 acknowledged_by     TEXT,
                 PRIMARY KEY (signature_hash, normalizer_version)
             );
             CREATE INDEX IF NOT EXISTS idx_error_sigs_last_seen
                 ON error_signatures(last_seen_at DESC);
             CREATE INDEX IF NOT EXISTS idx_error_sigs_ack
                 ON error_signatures(acknowledged_at)
                 WHERE acknowledged_at IS NULL;

             CREATE TABLE IF NOT EXISTS error_signature_windows (
                 signature_hash      TEXT NOT NULL,
                 normalizer_version  INTEGER NOT NULL,
                 window_start        TEXT NOT NULL,
                 window_end          TEXT NOT NULL,
                 count_in_window     INTEGER NOT NULL,
                 PRIMARY KEY (signature_hash, normalizer_version, window_start, window_end)
             );

             CREATE TABLE IF NOT EXISTS error_signature_ack_events (
                 id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                 signature_hash      TEXT NOT NULL,
                 normalizer_version  INTEGER NOT NULL,
                 event_type          TEXT NOT NULL CHECK (event_type IN ('ack','unack')),
                 actor               TEXT NOT NULL,
                 notes               TEXT CHECK (notes IS NULL OR length(notes) <= 4096),
                 created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
             );
             CREATE INDEX IF NOT EXISTS idx_ack_events_sig
                 ON error_signature_ack_events(signature_hash, created_at DESC);

             CREATE TABLE IF NOT EXISTS error_scan_cursor (
                 id                      INTEGER PRIMARY KEY CHECK (id = 1),
                 last_scanned_log_id     INTEGER NOT NULL DEFAULT 0,
                 last_scan_completed_at  TEXT
             );
             INSERT OR IGNORE INTO error_scan_cursor (id, last_scanned_log_id) VALUES (1, 0);

             INSERT INTO schema_migrations (version) VALUES (10);",
        )?;
        tracing::info!("Migration 10: created error signature detection tables");
    }

    // Migration 11: notifications outbox and firings tables.
    let migration_11_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 11",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_11_applied {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notifications_outbox (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 dedup_key TEXT NOT NULL,
                 rule_id TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 hostname TEXT NOT NULL,
                 title TEXT NOT NULL,
                 body TEXT NOT NULL,
                 apprise_urls_json TEXT NOT NULL,
                 apprise_tags TEXT,
                 enqueued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                 next_attempt_at TEXT NOT NULL,
                 attempt_count INTEGER NOT NULL DEFAULT 0,
                 last_status_code INTEGER,
                 last_error TEXT,
                 status TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','sent','dead','dropped'))
             );
             CREATE INDEX IF NOT EXISTS idx_outbox_pending
                 ON notifications_outbox(status, next_attempt_at)
                 WHERE status = 'pending';
             CREATE INDEX IF NOT EXISTS idx_outbox_dedup
                 ON notifications_outbox(dedup_key, enqueued_at DESC);

             CREATE TABLE IF NOT EXISTS notification_firings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 outbox_id INTEGER NOT NULL,
                 rule_id TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 hostname TEXT NOT NULL,
                 fired_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                 status_code INTEGER,
                 notes TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_firings_fired_at
                 ON notification_firings(fired_at DESC);
             CREATE INDEX IF NOT EXISTS idx_firings_rule
                 ON notification_firings(rule_id, fired_at DESC);

             INSERT INTO schema_migrations (version) VALUES (11);",
        )?;
        tracing::info!("Migration 11: created notifications outbox and firings tables");
    }

    // Migration 12: add dedup_key column to notification_firings and unique partial
    // index on notifications_outbox to fix TOCTOU on outbox_insert.
    let migration_12_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 12",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !migration_12_applied {
        // Add dedup_key to notification_firings so dedup checks are scoped per
        // (rule_id, hostname, dedup_key) rather than just (rule_id, hostname).
        // Without this, all error_sig firings share rule_id='unaddressed_error_signature'
        // and the first firing suppresses all subsequent ones regardless of signature.
        let dedup_col_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('notification_firings') WHERE name = 'dedup_key'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if !dedup_col_exists {
            conn.execute_batch(
                "ALTER TABLE notification_firings ADD COLUMN dedup_key TEXT NOT NULL DEFAULT '';",
            )?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_dedup_pending
                 ON notifications_outbox(dedup_key) WHERE status = 'pending';
             INSERT INTO schema_migrations (version) VALUES (12);",
        )?;
        tracing::info!(
            "Migration 12: added notification_firings.dedup_key, unique partial index on outbox"
        );
    }

    // Migration 13: enrichment-framework columns + partial indexes.
    // Spec: docs/superpowers/specs/2026-05-16-enrichment-framework-design.md §5
    // Contract: docs/contracts/db-additions.sql Epic B section
    if !migration_applied(&conn, 13)? {
        apply_migration_13(&conn)?;
        tracing::info!("Migration 13: added enrichment columns + partial indexes");
    }

    let already_applied_14: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 14",
        [],
        |r| r.get(0),
    )?;
    if already_applied_14 == 0 {
        tracing::info!(
            "Migration 14: starting CREATE INDEX idx_logs_ai_session_host_time \
             — may take time on large AI transcript databases"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_ai_session_host_time
                 ON logs(ai_project, ai_tool, ai_session_id, hostname, timestamp)
                 WHERE ai_project IS NOT NULL
                   AND ai_tool IS NOT NULL
                   AND ai_session_id IS NOT NULL;
             INSERT INTO schema_migrations (version) VALUES (14);",
        )?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 14: AI session host/time index created"
        );
    }

    // Migration 15: first-class heartbeat telemetry storage.
    // Contract: docs/contracts/heartbeat-telemetry.md
    if !migration_applied(&conn, 15)? {
        apply_migration_15_heartbeat(&conn)?;
        tracing::info!("Migration 15: created heartbeat telemetry tables and indexes");
    }

    if !migration_applied(&conn, 16)? {
        tracing::info!(
            "Migration 16: starting CREATE INDEX idx_logs_app_name_timestamp \
             — may take time on large databases"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_app_name_timestamp
                 ON logs(app_name, timestamp);
             INSERT INTO schema_migrations (version) VALUES (16);",
        )?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 16: app_name/timestamp search index created"
        );
    }

    if !migration_applied(&conn, 17)? {
        apply_migration_17_inventory_stats(&conn)?;
        tracing::info!("Migration 17: created app/source inventory stats");
    }

    // Migration 18: add restarting column to heartbeat_containers.
    if !migration_applied(&conn, 18)? {
        apply_migration_18_heartbeat_restarting(&conn)?;
        tracing::info!("Migration 18: added restarting column to heartbeat_containers");
    }

    // Migration 19: add host_heartbeats_latest fleet cache table.
    if !migration_applied(&conn, 19)? {
        apply_migration_19_heartbeat_latest(&conn)?;
        tracing::info!("Migration 19: created host_heartbeats_latest fleet cache table");
    }

    // Migration 20: composite index on error_signature_windows(window_end, ...) for sig list queries.
    // The `sig list` action filters unaddressed signatures by recency, ordering on window_end DESC.
    // Without this index, every query does a full scan of error_signature_windows.
    if !migration_applied(&conn, 20)? {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_error_sig_windows_end
                 ON error_signature_windows(window_end, signature_hash, normalizer_version);
             INSERT INTO schema_migrations (version) VALUES (20);",
        )?;
        tracing::info!("Migration 20: added index on error_signature_windows(window_end)");
    }

    // Migration 21: AI session rollup table (bead cortex-2vre).
    // `list_ai_sessions` aggregates GROUP BY (project, tool, session, hostname)
    // over the full AI-row partition then sorts by MAX(timestamp) — an
    // unavoidable temp-btree that grows with AI-row count (~4s at 10M rows).
    // The rollup is a periodically-refreshed materialization read in O(#sessions)
    // via idx, decoupling read latency from row count. It is REFRESH-based, not
    // trigger-based: trigger-maintained MIN/MAX is wrong on DELETE (deleting the
    // row holding the current MAX can't recover the new extreme without a rescan,
    // and that rescan reintroduces bulk-purge lock contention). Staleness is
    // exposed via ai_session_rollup_meta.refreshed_at.
    if !migration_applied(&conn, 21)? {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ai_session_rollup (
                 ai_project         TEXT NOT NULL,
                 ai_tool            TEXT NOT NULL,
                 ai_session_id      TEXT NOT NULL,
                 hostname           TEXT NOT NULL,
                 ai_transcript_path TEXT,
                 first_seen         TEXT NOT NULL,
                 last_seen          TEXT NOT NULL,
                 event_count        INTEGER NOT NULL,
                 PRIMARY KEY (ai_project, ai_tool, ai_session_id, hostname)
             );
             CREATE INDEX IF NOT EXISTS idx_ai_session_rollup_last_seen
                 ON ai_session_rollup(last_seen DESC);
             CREATE TABLE IF NOT EXISTS ai_session_rollup_meta (
                 id           INTEGER PRIMARY KEY CHECK (id = 1),
                 refreshed_at TEXT,
                 row_count    INTEGER NOT NULL DEFAULT 0
             );
             INSERT OR IGNORE INTO ai_session_rollup_meta (id, refreshed_at, row_count)
                 VALUES (1, NULL, 0);
             INSERT INTO schema_migrations (version) VALUES (21);",
        )?;
        tracing::info!("Migration 21: created AI session rollup table");
    }

    // Migration 22: source watermark for the AI session rollup (bead
    // cortex-g33v). The background refresh recomputed the full GROUP-BY
    // over `logs` every cadence even when no AI rows had changed. These two
    // columns record the source-side `(COUNT(*), MAX(id))` of AI rows captured
    // by the last refresh; the refresh task compares the live watermark against
    // them and skips the recompute entirely when nothing changed. Both default
    // to 0 so the first post-migration refresh always runs (live watermark > 0
    // whenever AI rows exist, and `refreshed_at` is still NULL regardless).
    if !migration_applied(&conn, 22)? {
        apply_migration_22(&conn)?;
        tracing::info!("Migration 22: added AI session rollup source watermark");
    }

    // Migration 23: covering indexes for the `errors` summary and `ai projects`
    // aggregation. Both previously read every matching row from the table to
    // fetch columns absent from the leading index (hostname for the error
    // GROUP BY; ai_tool / ai_session_id for the project rollup), making them
    // O(matching-rows) table-lookup scans (~10s and ~48s on a multi-million-row
    // DB). These covering indexes make both aggregations index-only — verified
    // via EXPLAIN QUERY PLAN flipping to `USING COVERING INDEX`.
    //
    // First-run cost: building these on a populated DB scans the table and
    // holds the write lock for the duration (seconds to minutes at multi-
    // million-row volumes); /health may gap and syslog packets may drop during
    // that window — the same one-time cost as the earlier index migrations.
    if !migration_applied(&conn, 23)? {
        tracing::info!(
            "Migration 23: building covering indexes (idx_logs_ai_project_cover, \
             idx_logs_sev_host_time) — may take minutes on large DBs, write lock held"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_ai_project_cover
                 ON logs(ai_project, ai_tool, ai_session_id, timestamp)
                 WHERE ai_project IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_sev_host_time
                 ON logs(severity, hostname, timestamp);
             INSERT INTO schema_migrations (version) VALUES (23);",
        )?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 23: covering indexes for errors + ai projects created"
        );
    }

    // Migration 24: timestamp-positioned covering indexes for the AI
    // aggregations, plus baseline ANALYZE stats.
    //
    // Migration 23's idx_logs_ai_project_cover (ai_project, ai_tool,
    // ai_session_id, timestamp) made `ai projects` index-only, but with a
    // timestamp-range filter (e.g. `ai blocks`'s 30-day default) the planner
    // can't use its trailing `timestamp` as a seek and instead chose
    // idx_logs_timestamp — scanning all recent high-volume syslog and filtering
    // AI rows out one by one (~28s). Putting `timestamp` SECOND
    // (ai_project, timestamp, ai_tool, ai_session_id) gives both a seekable
    // range and full coverage, and supersedes the old index for every AI query
    // (verified: nothing picks idx_logs_ai_project_cover once this exists), so
    // it is dropped. idx_logs_ai_tool_cover does the same for `ai tools`
    // (GROUP BY ai_tool needs session_id + timestamp).
    //
    // CRITICAL: these indexes are only *chosen* when ANALYZE statistics exist —
    // without `sqlite_stat1`, the planner's no-stats heuristics still pick
    // idx_logs_timestamp (verified empirically). So this migration also runs an
    // initial ANALYZE (bounded by the connection's analysis_limit=400), and the
    // optimize maintenance task keeps stats fresh as the DB grows. Same first-
    // run write-lock cost as the other index migrations.
    if !migration_applied(&conn, 24)? {
        tracing::info!(
            "Migration 24: rebuilding AI covering indexes (timestamp-positioned) \
             + initial ANALYZE — may take minutes on large DBs, write lock held"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_logs_ai_project_cover;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_project_ts_cover
                 ON logs(ai_project, timestamp, ai_tool, ai_session_id)
                 WHERE ai_project IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_tool_cover
                 ON logs(ai_tool, ai_session_id, timestamp)
                 WHERE ai_tool IS NOT NULL;",
        )?;
        // Only seed stats when the table already has data. ANALYZE on an empty
        // `logs` (fresh install / tests) records "0 rows", which mis-guides the
        // planner once rows arrive; an empty DB instead gets its first stats
        // from the optimize maintenance task (or the next restart) once
        // populated. The existing populated DB analyzes immediately here.
        let has_rows: bool =
            conn.query_row("SELECT EXISTS(SELECT 1 FROM logs)", [], |r| r.get(0))?;
        if has_rows {
            conn.execute_batch("ANALYZE;")?;
        }
        conn.execute_batch("INSERT INTO schema_migrations (version) VALUES (24);")?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 24: AI covering indexes rebuilt + baseline ANALYZE done"
        );
    }

    // Migration 25: timeline_hourly rollup (bead syslog-mcp-kcvq).
    //
    // `timeline` (bucket=hour/day/week/month) and `stats.total_logs` previously
    // scanned the whole `logs` table (`strftime` GROUP BY ~3s; `COUNT(*)` ~7s on
    // a multi-million-row DB). This table materializes per-hour event counts at
    // grain (bucket_hour, hostname, app_name, severity) — ~9.3k rows over 2.65M
    // raw logs (~280x reduction), so timeline/stats reads become O(#buckets).
    //
    // INCREMENTAL, not full-recompute (contrast ai_session_rollup): a full
    // recompute is the 63s `strftime`-over-2.65M scan. The rollup holds ONLY
    // COUNT(*) — no MIN/MAX — so it is self-maintainable for ADDs: aggregate only
    // `logs WHERE id > source_max_id` and upsert-add into existing buckets. A
    // late-arriving high-id row with an old timestamp correctly lands in its old
    // bucket. The only incremental hazard is DELETEs (retention purges oldest
    // rows by received_at); the retention task prunes stale low buckets after
    // each purge (see spawn_retention_task), accepting a transient overcount only
    // in the single boundary hour.
    //
    // `app_name` is stored NOT NULL via COALESCE(app_name,'') — SQLite treats
    // NULLs as DISTINCT in UNIQUE/PK indexes, so a nullable column would make
    // ON CONFLICT never match for null-app grains and double-count every tick.
    //
    // First-run backfill is the one-time 63s scan, guarded by a has_rows check so
    // empty/test DBs skip it. It runs at server STARTUP before ingest begins, so
    // holding the write lock here is acceptable (same pattern as migration 24).
    if !migration_applied(&conn, 25)? {
        tracing::info!(
            "Migration 25: creating timeline_hourly rollup + backfill — backfill is \
             a one-time full scan (~60s on large DBs, write lock held)"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS timeline_hourly (
                 bucket      TEXT NOT NULL,
                 hostname    TEXT NOT NULL,
                 app_name    TEXT NOT NULL,
                 severity    TEXT NOT NULL,
                 event_count INTEGER NOT NULL,
                 PRIMARY KEY (bucket, hostname, app_name, severity)
             );
             CREATE TABLE IF NOT EXISTS timeline_hourly_meta (
                 id            INTEGER PRIMARY KEY CHECK (id = 1),
                 refreshed_at  TEXT,
                 source_max_id INTEGER NOT NULL DEFAULT 0
             );
             INSERT OR IGNORE INTO timeline_hourly_meta (id, refreshed_at, source_max_id)
                 VALUES (1, NULL, 0);",
        )?;
        // Backfill only when the table has data (fresh installs / tests skip the
        // scan and start from an empty rollup at watermark 0).
        let has_rows: bool =
            conn.query_row("SELECT EXISTS(SELECT 1 FROM logs)", [], |r| r.get(0))?;
        if has_rows {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let max_id: i64 =
                tx.query_row("SELECT COALESCE(MAX(id), 0) FROM logs", [], |r| r.get(0))?;
            tx.execute(
                "INSERT INTO timeline_hourly (bucket, hostname, app_name, severity, event_count)
                 SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS bucket,
                        hostname,
                        COALESCE(app_name, '') AS app_name,
                        severity,
                        COUNT(*) AS event_count
                 FROM logs
                 WHERE id <= ?1
                 GROUP BY bucket, hostname, app_name, severity
                 ON CONFLICT(bucket, hostname, app_name, severity)
                     DO UPDATE SET event_count = event_count + excluded.event_count",
                [max_id],
            )?;
            tx.execute(
                "UPDATE timeline_hourly_meta
                    SET refreshed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        source_max_id = ?1
                  WHERE id = 1",
                [max_id],
            )?;
            tx.commit()?;
        }
        conn.execute_batch("INSERT INTO schema_migrations (version) VALUES (25);")?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 25: timeline_hourly rollup created + backfilled"
        );
    }

    // Migration 26: maintenance_jobs table (bead syslog-mcp-a4pd).
    //
    // `db integrity` on a 5GB DB is ~147s (PRAGMA quick_check reads every page —
    // unfixable). This table backs a server-side background job: the HTTP path
    // inserts a 'running' row, spawns the check on a blocking thread, and updates
    // the row to 'done'/'failed' + result_json; clients poll by id. quick_check
    // is read-only so it never blocks ingest writes.
    if !migration_applied(&conn, 26)? {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS maintenance_jobs (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind        TEXT NOT NULL,
                 status      TEXT NOT NULL,
                 started_at  TEXT NOT NULL,
                 finished_at TEXT,
                 result_json TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_maintenance_jobs_kind_status
                 ON maintenance_jobs(kind, status);
             INSERT INTO schema_migrations (version) VALUES (26);",
        )?;
        tracing::info!("Migration 26: created maintenance_jobs table");
    }

    // Migration 27: derived investigation graph projection (bead syslog-mcp-24vc.1).
    //
    // This is schema only: no ingest-path graph writes, no triggers, and no
    // service/API behavior. Raw logs, heartbeats, signatures, inventory, and AI
    // session rows remain authoritative; graph rows are rebuildable projection
    // data. Source references are intentionally soft references because this
    // process does not enable PRAGMA foreign_keys on pooled connections.
    if !migration_applied(&conn, 27)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS graph_entities (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             CREATE INDEX IF NOT EXISTS idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);

             CREATE TABLE IF NOT EXISTS graph_entity_aliases (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_id     INTEGER NOT NULL,
                 alias_type    TEXT NOT NULL,
                 alias_key     TEXT NOT NULL,
                 alias_value   TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_id, alias_type, alias_key, source_kind)
             );
             CREATE INDEX IF NOT EXISTS idx_graph_aliases_lookup
                 ON graph_entity_aliases(alias_type, alias_key);
             CREATE INDEX IF NOT EXISTS idx_graph_aliases_entity
                 ON graph_entity_aliases(entity_id);

             CREATE TABLE IF NOT EXISTS graph_relationships (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             CREATE INDEX IF NOT EXISTS idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX IF NOT EXISTS idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX IF NOT EXISTS idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE IF NOT EXISTS graph_relationship_evidence (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             CREATE INDEX IF NOT EXISTS idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX IF NOT EXISTS idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX IF NOT EXISTS idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             CREATE TABLE IF NOT EXISTS graph_projection_meta (
                 id                 INTEGER PRIMARY KEY CHECK (id = 1),
                 projection_status  TEXT NOT NULL CHECK (projection_status IN (
                     'never_built', 'building', 'ready', 'stale', 'failed'
                 )),
                 last_started_at    TEXT,
                 last_completed_at  TEXT,
                 source_watermark   TEXT NOT NULL DEFAULT '',
                 source_row_count   INTEGER NOT NULL DEFAULT 0 CHECK (source_row_count >= 0),
                 entity_count       INTEGER NOT NULL DEFAULT 0 CHECK (entity_count >= 0),
                 relationship_count INTEGER NOT NULL DEFAULT 0 CHECK (relationship_count >= 0),
                 evidence_count     INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 is_degraded        INTEGER NOT NULL DEFAULT 0 CHECK (is_degraded IN (0, 1)),
                 last_error         TEXT CHECK (last_error IS NULL OR length(last_error) <= 2048),
                 updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             INSERT OR IGNORE INTO graph_projection_meta
                 (id, projection_status, source_watermark)
                 VALUES (1, 'never_built', '');

             INSERT INTO schema_migrations (version) VALUES (27);

             COMMIT;",
        )?;
        tracing::info!("Migration 27: created graph projection schema");
    }

    // Migration 28: add graph rebuild runtime metrics.
    if !migration_applied(&conn, 28)? {
        let tx = conn.transaction()?;
        add_column_if_missing(
            &tx,
            "graph_projection_meta",
            "last_runtime_ms",
            "INTEGER NOT NULL DEFAULT 0 CHECK (last_runtime_ms >= 0)",
        )?;
        add_column_if_missing(
            &tx,
            "graph_projection_meta",
            "last_chunk_count",
            "INTEGER NOT NULL DEFAULT 0 CHECK (last_chunk_count >= 0)",
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (28)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 28: added graph projection runtime metrics");
    }

    // Migration 29: add covering indexes for get_error_summary (group_by_app path),
    // tail_logs severity filter, and extend the ai_session index to include timestamp
    // so ORDER BY timestamp DESC is index-sortable without a temp b-tree.
    if !migration_applied(&conn, 29)? {
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_logs_ai_session;
             CREATE INDEX IF NOT EXISTS idx_logs_ai_session
                 ON logs(ai_tool, ai_project, ai_session_id, timestamp)
                 WHERE ai_tool IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_sev_app_hostname_time
                 ON logs(severity, app_name, hostname, timestamp);
             CREATE INDEX IF NOT EXISTS idx_logs_sev_time_id
                 ON logs(severity, timestamp, id);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (29);",
        )?;
        tracing::info!(
            "Migration 29: added covering indexes for error_summary, tail_logs, and ai_session sort"
        );
    }

    // Migration 30: widen graph vocabulary for homelab inventory topology.
    //
    // SQLite CHECK constraints are part of the table definition, so adding
    // entity/relationship/reason values requires rebuilding the constrained
    // graph tables. The migration is a strict superset and preserves existing
    // ids so aliases and evidence references remain valid.
    if !migration_applied(&conn, 30)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entities_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             INSERT INTO graph_entities_new
                 (id, entity_type, canonical_key, display_label, source_kind,
                  source_id, trust_level, first_seen_at, last_seen_at,
                  created_at, updated_at)
             SELECT id, entity_type, canonical_key, display_label, source_kind,
                    source_id, trust_level, first_seen_at, last_seen_at,
                    created_at, updated_at
               FROM graph_entities;
             DROP TABLE graph_entities;
             ALTER TABLE graph_entities_new RENAME TO graph_entities;
             CREATE INDEX idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships;
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence;
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (30);
             COMMIT;",
        )?;
        tracing::info!("Migration 30: widened graph vocabulary for inventory topology");
    }

    // Migration 31: relationship-type covering index for bounded topology
    // findings. Findings ask for all relationships of one graph vocabulary
    // type, so the src/dst-specific graph indexes are not sufficient.
    if !migration_applied(&conn, 31)? {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (31);",
        )?;
        tracing::info!("Migration 31: added graph relationship type index for topology findings");
    }

    // Migration 32: covering index for the graph→log join used by graph-anchored
    // correlation (topic_correlate, ai_correlate rewrite). N-hop graph traversal
    // resolves to a set of entity canonical keys, which become a
    // `hostname IN (...)` filter over a bounded time window, frequently further
    // narrowed by app_name. The existing idx_logs_host_time (hostname, timestamp)
    // seeks the hostname+time range but must then fetch each candidate row from
    // the heap to evaluate app_name — pathological across 5+ hostnames on wide
    // windows. (hostname, app_name, timestamp) lets the planner satisfy the inner
    // filter index-only. The second index covers the session_id-anchored fan-out
    // (all logs for one AI session ordered by time) without touching the heap.
    //
    // First-run cost: building these on a populated DB scans the table and holds
    // the write lock for the duration (seconds to minutes at multi-million-row
    // volumes); /health may gap and syslog packets may drop during that window —
    // the same one-time cost as the earlier index migrations.
    if !migration_applied(&conn, 32)? {
        tracing::info!(
            "Migration 32: building graph→log covering indexes \
             (idx_logs_hostname_appname_time, idx_logs_ai_session_time) \
             — may take minutes on large DBs, write lock held"
        );
        let started = std::time::Instant::now();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_hostname_appname_time
                 ON logs(hostname, app_name, timestamp);
             CREATE INDEX IF NOT EXISTS idx_logs_ai_session_time
                 ON logs(ai_session_id, timestamp)
                 WHERE ai_session_id IS NOT NULL;
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (32);",
        )?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Migration 32: graph→log covering indexes created"
        );
    }

    // Migration 33: widen graph reason-code vocabulary for agent-command
    // projection (agent_command_session, agent_command_cwd_infer).
    //
    // SQLite CHECK constraints are part of the table definition, so adding
    // reason_code values requires rebuilding the two constrained graph tables.
    // The migration is a strict superset and preserves existing ids so evidence
    // references remain valid. Mirrors migration 30's rebuild shape.
    if !migration_applied(&conn, 33)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships;
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence;
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (33);
             COMMIT;",
        )?;
        tracing::info!("Migration 33: widened graph reason-code vocabulary for agent commands");
    }

    // Migration 34: add the `git_commit` entity type and the two git-commit
    // reason codes (agent_command_git_commit, shell_history_git_commit).
    // Rebuilds the three constrained graph tables; strict superset, ids
    // preserved. Mirrors migrations 30/33.
    if !migration_applied(&conn, 34)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entities_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact', 'git_commit'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             INSERT INTO graph_entities_new
                 (id, entity_type, canonical_key, display_label, source_kind,
                  source_id, trust_level, first_seen_at, last_seen_at,
                  created_at, updated_at)
             SELECT id, entity_type, canonical_key, display_label, source_kind,
                    source_id, trust_level, first_seen_at, last_seen_at,
                    created_at, updated_at
               FROM graph_entities;
             DROP TABLE graph_entities;
             ALTER TABLE graph_entities_new RENAME TO graph_entities;
             CREATE INDEX idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships;
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence;
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (34);
             COMMIT;",
        )?;
        tracing::info!("Migration 34: added git_commit entity type and git-commit reason codes");
    }

    // Migration 35: add the `refuted` trust level to the three graph tables'
    // trust_level CHECK. Refuted edges record disproved/retracted relationships
    // (manual override) and are excluded from every traversal result. Rebuilds
    // the constrained tables; strict superset, ids preserved.
    if !migration_applied(&conn, 35)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entities_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact', 'git_commit'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             INSERT INTO graph_entities_new
                 (id, entity_type, canonical_key, display_label, source_kind,
                  source_id, trust_level, first_seen_at, last_seen_at,
                  created_at, updated_at)
             SELECT id, entity_type, canonical_key, display_label, source_kind,
                    source_id, trust_level, first_seen_at, last_seen_at,
                    created_at, updated_at
               FROM graph_entities;
             DROP TABLE graph_entities;
             ALTER TABLE graph_entities_new RENAME TO graph_entities;
             CREATE INDEX idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships;
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence;
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (35);
             COMMIT;",
        )?;
        tracing::info!("Migration 35: added refuted trust level to graph tables");
    }

    // Migration 36: add user/device entity types, the authenticated_as/accessed/
    // communicates_with relationship types, and the three identity reason codes
    // (adguard_client_query, shell_history_user, authelia_auth). Rebuilds the
    // constrained graph tables; strict superset, ids preserved.
    if !migration_applied(&conn, 36)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entities_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact', 'git_commit', 'user', 'device'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             INSERT INTO graph_entities_new
                 (id, entity_type, canonical_key, display_label, source_kind,
                  source_id, trust_level, first_seen_at, last_seen_at,
                  created_at, updated_at)
             SELECT id, entity_type, canonical_key, display_label, source_kind,
                    source_id, trust_level, first_seen_at, last_seen_at,
                    created_at, updated_at
               FROM graph_entities;
             DROP TABLE graph_entities;
             ALTER TABLE graph_entities_new RENAME TO graph_entities;
             CREATE INDEX idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact', 'authenticated_as', 'accessed',
                     'communicates_with'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit', 'adguard_client_query',
                     'shell_history_user', 'authelia_auth'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships;
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit', 'adguard_client_query',
                     'shell_history_user', 'authelia_auth'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence;
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (36);
             COMMIT;",
        )?;
        tracing::info!("Migration 36: added user/device entities and identity relationships");
    }

    // Migration 37: create llm_invocations, the shared audit table for every
    // LLM-backed assessment call (ai_assess today; skill_assess/mcp_assess/
    // hook_assess in later phases). A start row is written before the
    // process/API call begins (status='running') and updated on completion.
    // Concurrency/rate-limit/circuit-open/disabled denials also write a row
    // (status set to the denial reason) so the audit trail covers every call
    // attempt, not just ones that reached the LLM.
    if !migration_applied(&conn, 37)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS llm_invocations (
               id                 TEXT PRIMARY KEY,
               started_at         TEXT NOT NULL,
               finished_at        TEXT,
               duration_ms        INTEGER,
               caller_surface     TEXT NOT NULL,
               action             TEXT NOT NULL,
               provider           TEXT NOT NULL,
               model              TEXT,
               program            TEXT,
               incident_id        TEXT,
               ai_tool            TEXT,
               ai_project         TEXT,
               ai_session_id      TEXT,
               evidence_counts_json TEXT,
               prompt_bytes       INTEGER,
               output_bytes       INTEGER,
               status             TEXT NOT NULL,
               error              TEXT,
               metadata_json      TEXT
             );

             CREATE INDEX IF NOT EXISTS idx_llm_invocations_started
                 ON llm_invocations(started_at);
             CREATE INDEX IF NOT EXISTS idx_llm_invocations_action_started
                 ON llm_invocations(action, started_at);
             CREATE INDEX IF NOT EXISTS idx_llm_invocations_status_started
                 ON llm_invocations(status, started_at);

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (37);
             COMMIT;",
        )?;
        tracing::info!("Migration 37: created llm_invocations audit table");
    }

    // Migration 38: ai_skill_events — one row per detected skill invocation
    // extracted from an AI transcript log row (Claude `attributionSkill` /
    // `attributionPlugin` structured fields, Codex `<skill><name>` transcript
    // tags). UNIQUE(log_id, skill_name, event_kind, evidence_kind) makes
    // INSERT OR IGNORE idempotent across re-ingest and backfill re-runs.
    // Eng review Fix 2: no skill_path/metadata_json — neither extractor sets
    // them in this PR, so they are not part of the shipped schema.
    // Eng review Fix 4: index set matches the actual shipped CLI filter
    // surface (--skill, --plugin, --tool, --project, --session-id, --host,
    // plus the unfiltered default `ORDER BY timestamp DESC`).
    // Eng review Fix 5: idx_logs_ai_tool_id is added on the EXISTING `logs`
    // table in this same migration batch — the backfill's `id > ?` keyset
    // scan needs it and idx_logs_ai_tool_cover (ai_tool, ai_session_id,
    // timestamp) doesn't include `id`.
    if !migration_applied(&conn, 38)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS ai_skill_events (
               id                 INTEGER PRIMARY KEY AUTOINCREMENT,
               log_id             INTEGER NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
               ai_tool            TEXT NOT NULL,
               ai_project         TEXT,
               ai_session_id      TEXT,
               hostname           TEXT NOT NULL,
               timestamp          TEXT NOT NULL,
               skill_name         TEXT NOT NULL,
               skill_plugin       TEXT,
               event_kind         TEXT NOT NULL,
               evidence_kind      TEXT NOT NULL,
               created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
               UNIQUE(log_id, skill_name, event_kind, evidence_kind)
             );

             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_timestamp
                 ON ai_skill_events(timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_skill_time
                 ON ai_skill_events(skill_name, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_plugin_time
                 ON ai_skill_events(skill_plugin, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_hostname_time
                 ON ai_skill_events(hostname, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_session_time
                 ON ai_skill_events(ai_tool, ai_project, ai_session_id, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_skill_events_project_skill_time
                 ON ai_skill_events(ai_project, skill_name, timestamp)
                 WHERE ai_project IS NOT NULL;

             CREATE INDEX IF NOT EXISTS idx_logs_ai_tool_id
                 ON logs(ai_tool, id)
                 WHERE ai_tool IN ('claude', 'codex');

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (38);
             COMMIT;",
        )?;
        tracing::info!("Migration 38: created ai_skill_events table + idx_logs_ai_tool_id");
    }

    // Migration 39: ai_mcp_events — one row per normalized MCP/tool-call
    // event extracted from an AI transcript log row (Claude `tool_use` /
    // `tool_result` content items linked by `id`/`tool_use_id`; Codex
    // `response_item.payload.type = "function_call"` /
    // `"function_call_output"` linked by `payload.call_id`). Schema matches
    // GH #94's "MCP assessment design" section verbatim.
    //
    // Idempotency key is `(ai_tool, ai_session_id, call_id, event_kind)`,
    // enforced via an expression index over `COALESCE(ai_session_id, '')`
    // rather than a plain `UNIQUE(...)` table constraint — SQLite (like
    // standard SQL) never treats two NULLs as equal in a UNIQUE index, so a
    // plain constraint on a nullable `ai_session_id` would silently let
    // duplicate rows back in for sessionless transcripts (verified by a
    // regression test in `mcp_events_tests.rs`). This makes `INSERT OR
    // IGNORE` idempotent across re-ingest and backfill re-runs, mirroring
    // the ai_skill_events idempotency pattern from migration 38 (whose own
    // UNIQUE key is safe because its `log_id` column is NOT NULL).
    //
    // Index set is designed against the actual shipped query filter surface
    // (search_ai_mcp_incidents groups/filters on mcp_server+mcp_tool+time,
    // list_mcp_events filters on tool_name+time and the session tuple) —
    // deliberately NOT copy-pasted blind from the skill_events index set,
    // per the eng-review lesson called out in GH #104 (PR1/PR2 both shipped
    // indexes that didn't match their query's actual filter/sort shape).
    if !migration_applied(&conn, 39)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS ai_mcp_events (
               id                 INTEGER PRIMARY KEY AUTOINCREMENT,
               call_log_id        INTEGER REFERENCES logs(id) ON DELETE CASCADE,
               result_log_id      INTEGER REFERENCES logs(id) ON DELETE SET NULL,
               ai_tool            TEXT NOT NULL,
               ai_project         TEXT,
               ai_session_id      TEXT,
               hostname           TEXT NOT NULL,
               timestamp          TEXT NOT NULL,
               turn_id            TEXT,
               call_id            TEXT NOT NULL,
               tool_name          TEXT NOT NULL,
               mcp_server         TEXT,
               mcp_tool           TEXT,
               event_kind         TEXT NOT NULL,
               status             TEXT,
               duration_ms        INTEGER,
               is_error           INTEGER,
               arguments_json     TEXT,
               output_preview     TEXT,
               error_text         TEXT,
               metadata_json      TEXT,
               created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );

             CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_mcp_events_dedupe
                 ON ai_mcp_events(ai_tool, COALESCE(ai_session_id, ''), call_id, event_kind);
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_hostname_time
                 ON ai_mcp_events(hostname, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_tool_time
                 ON ai_mcp_events(tool_name, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_server_time
                 ON ai_mcp_events(mcp_server, timestamp)
                 WHERE mcp_server IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_server_tool_time
                 ON ai_mcp_events(mcp_server, mcp_tool, timestamp)
                 WHERE mcp_server IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_session_time
                 ON ai_mcp_events(ai_tool, ai_project, ai_session_id, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_mcp_events_error_time
                 ON ai_mcp_events(is_error, timestamp)
                 WHERE is_error = 1;

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (39);
             COMMIT;",
        )?;
        tracing::info!("Migration 39: created ai_mcp_events table");
    }

    // Migration 40: ai_hook_events — one row per detected hook signal, either
    // a Claude runtime hook-execution attachment (`evidence_kind =
    // 'runtime_transcript'`) or a Claude/Codex hook config-inventory /
    // trust-state entry (`evidence_kind = 'config_inventory'` /
    // `'trusted_hash_state'`). `log_id` is nullable because config-inventory
    // rows are collected from local host config files, not a transcript log
    // row — see GH #105's "Hook assessment design" section.
    //
    // Uniqueness is enforced via a UNIQUE INDEX over
    // ai_tool, hostname, COALESCE(ai_session_id, ''), hook_event,
    // COALESCE(hook_name, ''), timestamp, evidence_kind rather than a
    // table-level UNIQUE(...) constraint: SQLite treats every NULL as
    // distinct from every other NULL in a UNIQUE constraint, and
    // config-inventory rows always have `ai_session_id = NULL` (they are
    // host-global, not session-scoped) — a bare UNIQUE(ai_session_id, ...)
    // would let `collect_and_store` insert an unbounded number of duplicate
    // rows on every repeated collection instead of deduping via
    // `INSERT OR IGNORE`. Wrapping the nullable columns in COALESCE collapses
    // NULL to a consistent sentinel so repeated collections at the same
    // hook_event/hook_name/timestamp/evidence_kind correctly dedupe.
    // `hostname` is part of the key so two different hosts collecting
    // identical config/trust-state rows at the same timestamp (both with
    // `ai_session_id = NULL`) don't collide and silently drop one host's row.
    if !migration_applied(&conn, 40)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS ai_hook_events (
               id                     INTEGER PRIMARY KEY AUTOINCREMENT,
               log_id                 INTEGER REFERENCES logs(id) ON DELETE SET NULL,
               ai_tool                TEXT NOT NULL,
               ai_project             TEXT,
               ai_session_id          TEXT,
               hostname               TEXT NOT NULL,
               timestamp              TEXT NOT NULL,
               hook_event             TEXT NOT NULL,
               hook_name              TEXT,
               hook_source            TEXT,
               hook_command           TEXT,
               status                 TEXT NOT NULL,
               exit_code              INTEGER,
               duration_ms            INTEGER,
               stdout_preview         TEXT,
               stderr_preview         TEXT,
               persisted_output_path  TEXT,
               trusted_hash           TEXT,
               evidence_kind          TEXT NOT NULL,
               metadata_json          TEXT,
               created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );

             CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_hook_events_unique
                 ON ai_hook_events(
                   ai_tool,
                   hostname,
                   COALESCE(ai_session_id, ''),
                   hook_event,
                   COALESCE(hook_name, ''),
                   timestamp,
                   evidence_kind
                 );

             CREATE INDEX IF NOT EXISTS idx_ai_hook_events_hostname_time
                 ON ai_hook_events(hostname, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_hook_events_hook_time
                 ON ai_hook_events(hook_event, hook_name, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_hook_events_status_time
                 ON ai_hook_events(status, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_hook_events_session_time
                 ON ai_hook_events(ai_tool, ai_project, ai_session_id, timestamp);
             CREATE INDEX IF NOT EXISTS idx_ai_hook_events_evidence_time
                 ON ai_hook_events(evidence_kind, timestamp);

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (40);
             COMMIT;",
        )?;
        tracing::info!("Migration 40: created ai_hook_events table");
    }

    // Migration 41: canonical entity-resolution graph contract
    // (entity_resolution_v2). Adds the `logical_service` / `service_instance`
    // entity types, the `instance_of` relationship type, and the three
    // resolver reason codes to the constrained graph tables (rebuild, strict
    // superset, ids preserved — mirrors migrations 33/34/35/36). The
    // hard-break cutover for old populated DBs happens inside the copy
    // itself: legacy `service` topology rows and nested `app` labels
    // (`plex/plex/plex`) are excluded from the `INSERT … SELECT` (never
    // migrated, no copy-then-delete), a `projection_contract` column records
    // the active contract, and any previously-ready projection is marked
    // stale so the next rebuild reprojects through the resolver.
    if !migration_applied(&conn, 41)? {
        conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entities_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type   TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature',
                     'compose_project', 'reverse_proxy', 'domain', 'network',
                     'storage', 'config_artifact', 'git_commit', 'user', 'device',
                     'logical_service', 'service_instance'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 source_id     TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             INSERT INTO graph_entities_new
                 (id, entity_type, canonical_key, display_label, source_kind,
                  source_id, trust_level, first_seen_at, last_seen_at,
                  created_at, updated_at)
             SELECT id, entity_type, canonical_key, display_label, source_kind,
                    source_id, trust_level, first_seen_at, last_seen_at,
                    created_at, updated_at
               FROM graph_entities
              WHERE entity_type != 'service'
                AND NOT (entity_type = 'app' AND canonical_key LIKE '%/%/%');
             DROP TABLE graph_entities;
             ALTER TABLE graph_entities_new RENAME TO graph_entities;
             CREATE INDEX idx_graph_entities_type_key
                 ON graph_entities(entity_type, canonical_key);
             CREATE INDEX idx_graph_entities_canonical_key
                 ON graph_entities(canonical_key);

             CREATE TABLE graph_relationships_new (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key  TEXT NOT NULL UNIQUE,
                 src_entity_id     INTEGER NOT NULL,
                 dst_entity_id     INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature', 'defines_service', 'routes_to',
                     'exposes_domain', 'attached_to', 'mounts', 'backed_by',
                     'has_artifact', 'authenticated_as', 'accessed',
                     'communicates_with', 'instance_of'
                 )),
                 reason_code       TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit', 'adguard_client_query',
                     'shell_history_user', 'authelia_auth',
                     'resolver_instance_of', 'resolver_service_instance',
                     'resolver_raw_app_label'
                 )),
                 trust_level       TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 confidence        REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count    INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at     TEXT,
                 last_seen_at      TEXT,
                 created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             INSERT INTO graph_relationships_new
                 (id, relationship_key, src_entity_id, dst_entity_id,
                  relationship_type, reason_code, trust_level, confidence,
                  evidence_count, first_seen_at, last_seen_at, created_at,
                  updated_at)
             SELECT id, relationship_key, src_entity_id, dst_entity_id,
                    relationship_type, reason_code, trust_level, confidence,
                    evidence_count, first_seen_at, last_seen_at, created_at,
                    updated_at
               FROM graph_relationships
              WHERE src_entity_id IN (SELECT id FROM graph_entities)
                AND dst_entity_id IN (SELECT id FROM graph_entities);
             DROP TABLE graph_relationships;
             ALTER TABLE graph_relationships_new RENAME TO graph_relationships;
             CREATE INDEX idx_graph_relationships_src_type_seen
                 ON graph_relationships(src_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_dst_type_seen
                 ON graph_relationships(dst_entity_id, relationship_type, last_seen_at DESC);
             CREATE INDEX idx_graph_relationships_type_seen
                 ON graph_relationships(relationship_type, last_seen_at DESC);

             CREATE TABLE graph_relationship_evidence_new (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id    INTEGER NOT NULL,
                 evidence_key       TEXT NOT NULL,
                 source_kind        TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'source_inventory',
                     'app_inventory', 'error_signature'
                 )),
                 source_id          TEXT NOT NULL DEFAULT '',
                 source_log_id      INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at        TEXT NOT NULL,
                 reason_code        TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match', 'inventory_node',
                     'inventory_service', 'compose_config',
                     'reverse_proxy_config', 'docker_network', 'storage_probe',
                     'config_artifact', 'agent_command_session',
                     'agent_command_cwd_infer', 'agent_command_git_commit',
                     'shell_history_git_commit', 'adguard_client_query',
                     'shell_history_user', 'authelia_auth',
                     'resolver_instance_of', 'resolver_service_instance',
                     'resolver_raw_app_label'
                 )),
                 reason_text        TEXT,
                 confidence_delta   REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= -1.0 AND confidence_delta <= 1.0),
                 trust_level        TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 safe_excerpt       TEXT CHECK (safe_excerpt IS NULL OR length(safe_excerpt) <= 512),
                 metadata_path      TEXT,
                 evidence_count     INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             INSERT INTO graph_relationship_evidence_new
                 (id, relationship_id, evidence_key, source_kind, source_id,
                  source_log_id, source_heartbeat_id, source_signature_hash,
                  observed_at, reason_code, reason_text, confidence_delta,
                  trust_level, safe_excerpt, metadata_path, evidence_count,
                  created_at)
             SELECT id, relationship_id, evidence_key, source_kind, source_id,
                    source_log_id, source_heartbeat_id, source_signature_hash,
                    observed_at, reason_code, reason_text, confidence_delta,
                    trust_level, safe_excerpt, metadata_path, evidence_count,
                    created_at
               FROM graph_relationship_evidence
              WHERE relationship_id IN (SELECT id FROM graph_relationships);
             DROP TABLE graph_relationship_evidence;
             ALTER TABLE graph_relationship_evidence_new RENAME TO graph_relationship_evidence;
             CREATE INDEX idx_graph_evidence_relationship_seen
                 ON graph_relationship_evidence(relationship_id, observed_at DESC);
             CREATE INDEX idx_graph_evidence_source_ref
                 ON graph_relationship_evidence(source_kind, source_id);
             CREATE INDEX idx_graph_evidence_log_id
                 ON graph_relationship_evidence(source_log_id)
                 WHERE source_log_id IS NOT NULL;
             CREATE INDEX idx_graph_evidence_heartbeat_id
                 ON graph_relationship_evidence(source_heartbeat_id)
                 WHERE source_heartbeat_id IS NOT NULL;

             DELETE FROM graph_entity_aliases
              WHERE entity_id NOT IN (SELECT id FROM graph_entities);

             ALTER TABLE graph_projection_meta
                 ADD COLUMN projection_contract TEXT NOT NULL DEFAULT '{contract_v2}';
             UPDATE graph_projection_meta
                SET projection_status = 'stale',
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1 AND projection_status = 'ready';

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (41);
             COMMIT;",
            contract_v2 = crate::db::entity_resolution::vocab::GRAPH_PROJECTION_CONTRACT_V2,
        ))?;
        tracing::info!(
            contract_key = crate::db::entity_resolution::vocab::GRAPH_PROJECTION_CONTRACT_KEY,
            contract = crate::db::entity_resolution::vocab::GRAPH_PROJECTION_CONTRACT_V2,
            "Migration 41: canonical entity-resolution graph contract"
        );
    }

    // Migration 42: add the `refuted` trust level to graph_entity_aliases'
    // trust_level CHECK. Migrations 35 and 41 added `refuted` to
    // graph_entities, graph_relationships, and graph_relationship_evidence,
    // but graph_entity_aliases was missed — an alias write at `refuted`
    // trust fails this CHECK. Rebuilds the constrained table; strict
    // superset, ids preserved (mirrors migrations 33/34/35/36/41).
    if !migration_applied(&conn, 42)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE graph_entity_aliases_new (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_id     INTEGER NOT NULL,
                 alias_type    TEXT NOT NULL,
                 alias_key     TEXT NOT NULL,
                 alias_value   TEXT NOT NULL,
                 source_kind   TEXT NOT NULL DEFAULT '',
                 trust_level   TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated', 'refuted'
                 )),
                 first_seen_at TEXT,
                 last_seen_at  TEXT,
                 created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_id, alias_type, alias_key, source_kind)
             );
             INSERT INTO graph_entity_aliases_new
                 (id, entity_id, alias_type, alias_key, alias_value, source_kind,
                  trust_level, first_seen_at, last_seen_at, created_at, updated_at)
             SELECT id, entity_id, alias_type, alias_key, alias_value, source_kind,
                    trust_level, first_seen_at, last_seen_at, created_at, updated_at
               FROM graph_entity_aliases;
             DROP TABLE graph_entity_aliases;
             ALTER TABLE graph_entity_aliases_new RENAME TO graph_entity_aliases;
             CREATE INDEX idx_graph_aliases_lookup
                 ON graph_entity_aliases(alias_type, alias_key);
             CREATE INDEX idx_graph_aliases_entity
                 ON graph_entity_aliases(entity_id);

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (42);
             COMMIT;",
        )?;
        tracing::info!("Migration 42: added refuted trust level to graph_entity_aliases");
    }

    // Migration 43: `stream_last_seen` — one row per (hostname, source_kind),
    // maintained by the notification evaluator each cycle. Foundation for the
    // stream_silence rule: alerting needs "newest row per host + source kind"
    // and the logs table cannot answer that cheaply (source kind lives inside
    // metadata_json). No backfill here — the evaluator seeds the table from a
    // bounded window on its first cycle, keeping migration time flat.
    if !migration_applied(&conn, 43)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS stream_last_seen (
                 hostname     TEXT NOT NULL,
                 source_kind  TEXT NOT NULL,
                 last_seen_at TEXT NOT NULL,
                 PRIMARY KEY (hostname, source_kind)
             ) WITHOUT ROWID;
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (43);
             COMMIT;",
        )?;
        tracing::info!("Migration 43: stream_last_seen rollup for stream-silence alerting");
    }

    // Migration 44: Agent Observatory repository, worktree, observation,
    // and exact-commit topology. The DDL and version marker share one
    // transaction so startup never reports a partially applied migration.
    if !migration_applied(&conn, 44)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS repositories (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             repository_key      TEXT NOT NULL UNIQUE,
             hostname            TEXT NOT NULL,
             common_git_dir      TEXT NOT NULL,
             primary_path        TEXT NOT NULL,
             display_name        TEXT NOT NULL,
             remote_url_hash     TEXT,
             first_seen_at       TEXT NOT NULL,
             last_seen_at        TEXT NOT NULL,
             removed_at          TEXT,
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(hostname, common_git_dir)
         );
         CREATE INDEX IF NOT EXISTS idx_repositories_host_seen
             ON repositories(hostname, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_repositories_display
             ON repositories(display_name COLLATE NOCASE);

         CREATE TABLE IF NOT EXISTS repository_worktrees (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             worktree_key        TEXT NOT NULL UNIQUE,
             repository_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
             hostname            TEXT NOT NULL,
             path                TEXT NOT NULL,
             git_dir             TEXT NOT NULL,
             branch_ref          TEXT,
             branch_name         TEXT,
             head_sha            TEXT,
             upstream_ref        TEXT,
             detached            INTEGER NOT NULL DEFAULT 0 CHECK (detached IN (0, 1)),
             bare                INTEGER NOT NULL DEFAULT 0 CHECK (bare IN (0, 1)),
             locked              INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
             lock_reason         TEXT,
             prunable            INTEGER NOT NULL DEFAULT 0 CHECK (prunable IN (0, 1)),
             prune_reason        TEXT,
             dirty               INTEGER NOT NULL DEFAULT 0 CHECK (dirty IN (0, 1)),
             staged_count        INTEGER NOT NULL DEFAULT 0 CHECK (staged_count >= 0),
             unstaged_count      INTEGER NOT NULL DEFAULT 0 CHECK (unstaged_count >= 0),
             untracked_count     INTEGER NOT NULL DEFAULT 0 CHECK (untracked_count >= 0),
             ahead               INTEGER CHECK (ahead IS NULL OR ahead >= 0),
             behind              INTEGER CHECK (behind IS NULL OR behind >= 0),
             status_hash         TEXT,
             first_seen_at       TEXT NOT NULL,
             last_seen_at        TEXT NOT NULL,
             removed_at          TEXT,
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(hostname, path)
         );
         CREATE INDEX IF NOT EXISTS idx_worktrees_repo_active
             ON repository_worktrees(repository_id, removed_at, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_worktrees_branch
             ON repository_worktrees(branch_name, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_worktrees_head
             ON repository_worktrees(repository_id, head_sha);

         CREATE TABLE IF NOT EXISTS repository_observations (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             observation_key     TEXT NOT NULL UNIQUE,
             repository_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
             worktree_id         INTEGER REFERENCES repository_worktrees(id) ON DELETE CASCADE,
             observed_at         TEXT NOT NULL,
             observation_kind    TEXT NOT NULL CHECK (observation_kind IN (
                 'discovered', 'status', 'head', 'branch', 'worktree_added',
                 'worktree_removed', 'overflow_reconcile', 'periodic_reconcile', 'error'
             )),
             old_head_sha        TEXT,
             new_head_sha        TEXT,
             summary             TEXT NOT NULL DEFAULT '',
             payload_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         );
         CREATE INDEX IF NOT EXISTS idx_repository_observations_worktree_time
             ON repository_observations(worktree_id, observed_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_repository_observations_repo_time
             ON repository_observations(repository_id, observed_at DESC, id DESC);

         CREATE TABLE IF NOT EXISTS git_commits (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             repository_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
             sha                 TEXT NOT NULL,
             parent_shas_json    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(parent_shas_json)),
             author_name         TEXT,
             author_email_hash   TEXT,
             authored_at         TEXT,
             committed_at        TEXT,
             subject             TEXT NOT NULL DEFAULT '',
             changed_files       INTEGER CHECK (changed_files IS NULL OR changed_files >= 0),
             insertions          INTEGER CHECK (insertions IS NULL OR insertions >= 0),
             deletions           INTEGER CHECK (deletions IS NULL OR deletions >= 0),
             changed_paths_json  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(changed_paths_json)),
             first_observed_at   TEXT NOT NULL,
             last_observed_at    TEXT NOT NULL,
             reachable           INTEGER NOT NULL DEFAULT 1 CHECK (reachable IN (0, 1)),
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             UNIQUE(repository_id, sha)
         );
         CREATE INDEX IF NOT EXISTS idx_git_commits_repo_time
             ON git_commits(repository_id, committed_at DESC, id DESC);
         INSERT OR IGNORE INTO schema_migrations (version) VALUES (44);
         COMMIT;",
        )?;
        tracing::info!("Migration 44: Agent Observatory repository topology");
    }

    // Agent Observatory migration 45: run events, evidence, cursors, and outbox.
    // This migration is wrapped in a transaction with the version marker.
    let migration_45_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 45",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if !migration_45_applied {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS agent_runs (
             id                      INTEGER PRIMARY KEY AUTOINCREMENT,
             run_key                 TEXT NOT NULL UNIQUE,
             native_session_id       TEXT NOT NULL,
             tool                    TEXT NOT NULL,
             provider_tool           TEXT,
             hostname                TEXT NOT NULL,
             parent_run_id           INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
             previous_run_id         INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
             primary_worktree_id     INTEGER REFERENCES repository_worktrees(id) ON DELETE SET NULL,
             transcript_path         TEXT,
             process_id              TEXT,
             status                  TEXT NOT NULL CHECK (status IN (
                 'starting', 'active', 'waiting', 'idle', 'stale',
                 'completed', 'failed', 'abandoned'
             )),
             status_reason           TEXT NOT NULL DEFAULT '',
             status_observed_at      TEXT NOT NULL,
             started_at              TEXT NOT NULL,
             last_activity_at        TEXT NOT NULL,
             ended_at                TEXT,
             first_source_log_id     INTEGER,
             last_source_log_id      INTEGER,
             last_event_id           INTEGER,
             event_count             INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
             error_count             INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
             primary_branch          TEXT,
             start_head_sha          TEXT,
             current_head_sha        TEXT,
             projection_version      INTEGER NOT NULL DEFAULT 1,
             freshness_json          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(freshness_json)),
             metadata_json           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(hostname, tool, native_session_id)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_runs_activity
             ON agent_runs(last_activity_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_runs_status_activity
             ON agent_runs(status, last_activity_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_runs_worktree_activity
             ON agent_runs(primary_worktree_id, last_activity_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_runs_tool_host
             ON agent_runs(tool, hostname, last_activity_at DESC);

         CREATE TABLE IF NOT EXISTS agent_run_actors (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             actor_key           TEXT NOT NULL UNIQUE,
             run_id              INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
             native_actor_id     TEXT NOT NULL,
             actor_type          TEXT,
             display_name        TEXT,
             started_at          TEXT,
             last_activity_at    TEXT,
             ended_at            TEXT,
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             UNIQUE(run_id, native_actor_id)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_run_actors_run
             ON agent_run_actors(run_id, last_activity_at DESC);

         CREATE TABLE IF NOT EXISTS agent_run_worktrees (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             relation_key        TEXT NOT NULL UNIQUE,
             run_id              INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
             worktree_id         INTEGER NOT NULL REFERENCES repository_worktrees(id) ON DELETE CASCADE,
             evidence_kind       TEXT NOT NULL,
             evidence_source     TEXT NOT NULL,
             trust_level         TEXT NOT NULL CHECK (trust_level IN (
                 'verified', 'claimed', 'correlated', 'inferred', 'refuted'
             )),
             confidence          REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
             is_primary          INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
             first_seen_at       TEXT NOT NULL,
             last_seen_at        TEXT NOT NULL,
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             UNIQUE(run_id, worktree_id, evidence_kind, evidence_source)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_run_worktrees_run
             ON agent_run_worktrees(run_id, is_primary DESC, confidence DESC, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_run_worktrees_worktree
             ON agent_run_worktrees(worktree_id, last_seen_at DESC, run_id);

         CREATE TABLE IF NOT EXISTS agent_run_events (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             event_key           TEXT NOT NULL UNIQUE,
             run_id              INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
             actor_id            INTEGER REFERENCES agent_run_actors(id) ON DELETE SET NULL,
             worktree_id         INTEGER REFERENCES repository_worktrees(id) ON DELETE SET NULL,
             commit_id           INTEGER REFERENCES git_commits(id) ON DELETE SET NULL,
             observed_at         TEXT NOT NULL,
             ingested_at         TEXT NOT NULL,
             event_kind          TEXT NOT NULL CHECK (event_kind IN (
                 'lifecycle', 'transcript', 'command', 'shell_history',
                 'git_status', 'git_head', 'git_commit', 'file_operation',
                 'mcp', 'hook', 'skill', 'llm', 'otlp_log', 'otlp_span',
                 'otlp_metric', 'heartbeat', 'error', 'provider_event'
             )),
             source_kind         TEXT NOT NULL,
             source_id           TEXT NOT NULL,
             source_log_id       INTEGER,
             provider_sequence   INTEGER,
             trace_id            TEXT,
             span_id             TEXT,
             severity            TEXT NOT NULL DEFAULT 'info',
             title               TEXT NOT NULL DEFAULT '',
             summary             TEXT NOT NULL DEFAULT '',
             payload_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
             content_scrubbed    INTEGER NOT NULL DEFAULT 1 CHECK (content_scrubbed IN (0, 1)),
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         );
         CREATE INDEX IF NOT EXISTS idx_agent_run_events_run_order
             ON agent_run_events(run_id, observed_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_run_events_run_kind
             ON agent_run_events(run_id, event_kind, observed_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_run_events_trace
             ON agent_run_events(trace_id, span_id);
         CREATE INDEX IF NOT EXISTS idx_agent_run_events_source_log
             ON agent_run_events(source_log_id) WHERE source_log_id IS NOT NULL;

         CREATE TABLE IF NOT EXISTS agent_run_commits (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             relation_key        TEXT NOT NULL UNIQUE,
             run_id              INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
             commit_id           INTEGER NOT NULL REFERENCES git_commits(id) ON DELETE CASCADE,
             worktree_id         INTEGER REFERENCES repository_worktrees(id) ON DELETE SET NULL,
             evidence_kind       TEXT NOT NULL,
             evidence_source     TEXT NOT NULL,
             trust_level         TEXT NOT NULL CHECK (trust_level IN (
                 'verified', 'claimed', 'correlated', 'inferred', 'refuted'
             )),
             confidence          REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
             first_seen_at       TEXT NOT NULL,
             last_seen_at        TEXT NOT NULL,
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             UNIQUE(run_id, commit_id, evidence_kind, evidence_source)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_run_commits_run
             ON agent_run_commits(run_id, last_seen_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_agent_run_commits_commit
             ON agent_run_commits(commit_id, last_seen_at DESC, run_id);

         CREATE TABLE IF NOT EXISTS agent_projection_cursors (
             id              INTEGER PRIMARY KEY AUTOINCREMENT,
             cursor_type     TEXT NOT NULL,
             source_name     TEXT NOT NULL DEFAULT 'default',
             cursor_value    TEXT NOT NULL DEFAULT '',
             updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(cursor_type, source_name)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_projection_cursors_type
             ON agent_projection_cursors(cursor_type, source_name);

         INSERT OR IGNORE INTO agent_projection_cursors (cursor_type, source_name, cursor_value) VALUES
             ('repositories', 'default', ''),
             ('repository_worktrees', 'default', ''),
             ('repository_observations', 'default', ''),
             ('git_commits', 'default', ''),
             ('agent_runs', 'default', ''),
             ('agent_run_events', 'default', ''),
             ('otel_spans', 'default', ''),
             ('otel_metric_points', 'default', '');

	         CREATE TABLE IF NOT EXISTS agent_stream_outbox (
	             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	             outbox_key          TEXT NOT NULL UNIQUE,
	             run_id              INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
	             stream_event_type   TEXT NOT NULL,
	             expires_at          TEXT NOT NULL,
	             payload_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
	             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	         );
	         CREATE INDEX IF NOT EXISTS idx_agent_stream_outbox_run
	             ON agent_stream_outbox(run_id, id ASC);
	         CREATE INDEX IF NOT EXISTS idx_agent_stream_outbox_expiry
	             ON agent_stream_outbox(expires_at ASC);

	     INSERT OR IGNORE INTO schema_migrations (version) VALUES (45);
	     COMMIT;",
        )?;
        tracing::info!("Migration 45: Agent Observatory run events, evidence, cursors, and outbox");
    }

    // Migration 46: OTLP traces.
    // The DDL and version marker share one transaction for atomicity.
    if !migration_applied(&conn, 46)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS otel_spans (
                 id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                 trace_id            TEXT NOT NULL CHECK (length(trace_id) = 32),
                 span_id             TEXT NOT NULL CHECK (length(span_id) = 16),
                 parent_span_id      TEXT CHECK (parent_span_id IS NULL OR length(parent_span_id) = 16),
                 trace_state         TEXT,
                 flags               INTEGER NOT NULL DEFAULT 0,
                 span_name           TEXT NOT NULL,
                 span_kind           INTEGER NOT NULL,
                 start_time_unix_nano INTEGER NOT NULL,
                 end_time_unix_nano  INTEGER NOT NULL,
                 duration_nano       INTEGER NOT NULL CHECK (duration_nano >= 0),
                 status_code         INTEGER NOT NULL DEFAULT 0,
                 status_message      TEXT,
                 hostname            TEXT NOT NULL DEFAULT '',
                 service_name        TEXT,
                 service_version     TEXT,
                 scope_name          TEXT,
                 scope_version       TEXT,
                 ai_tool             TEXT,
                 ai_project          TEXT,
                 ai_session_id       TEXT,
                 run_id              INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                 resource_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(resource_json)),
                 attributes_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes_json)),
                 events_json         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(events_json)),
                 links_json          TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(links_json)),
                 received_at         TEXT NOT NULL,
                 content_scrubbed    INTEGER NOT NULL DEFAULT 1 CHECK (content_scrubbed IN (0, 1)),
                 UNIQUE(trace_id, span_id)
             );
             CREATE INDEX IF NOT EXISTS idx_otel_spans_run_time
                 ON otel_spans(run_id, start_time_unix_nano DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_otel_spans_session_time
                 ON otel_spans(hostname, ai_tool, ai_session_id, start_time_unix_nano DESC);
             CREATE INDEX IF NOT EXISTS idx_otel_spans_trace
                 ON otel_spans(trace_id, start_time_unix_nano, span_id);
             CREATE INDEX IF NOT EXISTS idx_otel_spans_service_time
                 ON otel_spans(service_name, start_time_unix_nano DESC);

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (46);
             COMMIT;",
        )?;
        tracing::info!("Migration 46: OTLP traces");
    }

    // Agent Observatory migration 47: OTLP metric points.
    // This migration is wrapped in a transaction with the version marker.
    let migration_47_applied: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 47",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if !migration_47_applied {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE TABLE IF NOT EXISTS otel_metric_points (
                 id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                 point_key               TEXT NOT NULL UNIQUE,
                 metric_name             TEXT NOT NULL,
                 description             TEXT NOT NULL DEFAULT '',
                 unit                    TEXT NOT NULL DEFAULT '',
                 instrument_kind         TEXT NOT NULL CHECK (instrument_kind IN (
                     'gauge', 'sum', 'histogram', 'exponential_histogram', 'summary'
                 )),
                 aggregation_temporality INTEGER,
                 monotonic               INTEGER CHECK (monotonic IS NULL OR monotonic IN (0, 1)),
                 start_time_unix_nano    INTEGER,
                 time_unix_nano          INTEGER NOT NULL,
                 hostname                TEXT NOT NULL DEFAULT '',
                 service_name            TEXT,
                 service_version         TEXT,
                 scope_name              TEXT,
                 scope_version           TEXT,
                 ai_tool                 TEXT,
                 ai_project              TEXT,
                 ai_session_id           TEXT,
                 run_id                  INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                 resource_json           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(resource_json)),
                 attributes_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes_json)),
                 value_json              TEXT NOT NULL CHECK (json_valid(value_json)),
                 exemplars_json          TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(exemplars_json)),
                 received_at             TEXT NOT NULL,
                 content_scrubbed        INTEGER NOT NULL DEFAULT 1 CHECK (content_scrubbed IN (0, 1))
             );

             CREATE INDEX IF NOT EXISTS idx_otel_metric_points_run_time
                 ON otel_metric_points(run_id, time_unix_nano DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_otel_metric_points_name_time
                 ON otel_metric_points(metric_name, time_unix_nano DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_otel_metric_points_session_time
                 ON otel_metric_points(hostname, ai_tool, ai_session_id, time_unix_nano DESC);

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (47);
             COMMIT;",
        )?;
        tracing::info!("Migration 47: OTLP metric points");
    }

    // Migration 48: terminal-time paging for Agent Observatory LLM source rows.
    // Running invocations are mutable; paging by started_at can permanently skip
    // an older invocation that completes after the cursor has passed newer rows.
    if !migration_applied(&conn, 48)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;

             CREATE INDEX IF NOT EXISTS idx_llm_invocations_finished_id
                 ON llm_invocations(finished_at, id)
                 WHERE finished_at IS NOT NULL;

             UPDATE agent_projection_cursors SET source_name = 'mcp_events'
              WHERE cursor_type = 'source' AND source_name = 'mcp'
                AND NOT EXISTS (
                    SELECT 1 FROM agent_projection_cursors
                     WHERE cursor_type = 'source' AND source_name = 'mcp_events'
                );
             UPDATE agent_projection_cursors SET source_name = 'hook_events'
              WHERE cursor_type = 'source' AND source_name = 'hook'
                AND NOT EXISTS (
                    SELECT 1 FROM agent_projection_cursors
                     WHERE cursor_type = 'source' AND source_name = 'hook_events'
                );
             UPDATE agent_projection_cursors SET source_name = 'skill_events'
              WHERE cursor_type = 'source' AND source_name = 'skill'
                AND NOT EXISTS (
                    SELECT 1 FROM agent_projection_cursors
                     WHERE cursor_type = 'source' AND source_name = 'skill_events'
                );
             UPDATE agent_projection_cursors SET source_name = 'llm_invocations'
              WHERE cursor_type = 'source' AND source_name = 'llm'
                AND NOT EXISTS (
                    SELECT 1 FROM agent_projection_cursors
                     WHERE cursor_type = 'source' AND source_name = 'llm_invocations'
                );

             INSERT OR IGNORE INTO schema_migrations (version) VALUES (48);
             COMMIT;",
        )?;
        tracing::info!("Migration 48: indexed terminal LLM invocation paging");
    }

    // Migration 49: retain filter-qualified deletion lineage for the cursor
    // TTL so an entirely-deleted stream can distinguish a real retention gap
    // from unrelated gaps in the global logs id sequence.
    if !migration_applied(&conn, 49)? {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE stream_deleted_log_lineage (
               id INTEGER PRIMARY KEY,
               hostname TEXT NOT NULL,
               app_name TEXT,
               severity TEXT NOT NULL,
               ai_project TEXT,
               ai_tool TEXT,
               ai_session_id TEXT,
               deleted_at INTEGER NOT NULL
             );
             CREATE INDEX idx_stream_deleted_lineage_expiry
               ON stream_deleted_log_lineage(deleted_at);
             CREATE INDEX idx_logs_stream_host_id ON logs(hostname,id);
             CREATE INDEX idx_logs_stream_app_id ON logs(app_name,id);
             CREATE INDEX idx_logs_stream_severity_id ON logs(severity,id);
             CREATE INDEX idx_logs_stream_session_id
               ON logs(ai_project,ai_tool,ai_session_id,hostname,id)
               WHERE ai_project IS NOT NULL AND ai_tool IS NOT NULL
                 AND ai_session_id IS NOT NULL;
             CREATE TRIGGER logs_stream_retention_lineage BEFORE DELETE ON logs
             BEGIN
               DELETE FROM stream_deleted_log_lineage WHERE deleted_at < unixepoch() - 900;
               INSERT OR REPLACE INTO stream_deleted_log_lineage
                 (id,hostname,app_name,severity,ai_project,ai_tool,ai_session_id,deleted_at)
               VALUES (OLD.id,OLD.hostname,OLD.app_name,OLD.severity,OLD.ai_project,
                       OLD.ai_tool,OLD.ai_session_id,unixepoch());
             END;
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (49);
             COMMIT;",
        )?;
        tracing::info!("Migration 49: durable stream retention lineage");
    }

    if !migration_applied(&conn, 50)? {
        conn.execute_batch(
            "BEGIN;
             CREATE INDEX idx_logs_stream_host_app_id ON logs(hostname,app_name,id);
             CREATE INDEX idx_logs_stream_host_severity_id ON logs(hostname,severity,id);
             CREATE INDEX idx_logs_stream_app_severity_id ON logs(app_name,severity,id);
             CREATE INDEX idx_logs_stream_host_app_severity_id ON logs(hostname,app_name,severity,id);
             CREATE INDEX idx_stream_deleted_lineage_host_id ON stream_deleted_log_lineage(hostname,id);
             CREATE INDEX idx_stream_deleted_lineage_app_id ON stream_deleted_log_lineage(app_name,id);
             CREATE INDEX idx_stream_deleted_lineage_severity_id ON stream_deleted_log_lineage(severity,id);
             CREATE INDEX idx_stream_deleted_lineage_host_app_id ON stream_deleted_log_lineage(hostname,app_name,id);
             CREATE INDEX idx_stream_deleted_lineage_host_severity_id ON stream_deleted_log_lineage(hostname,severity,id);
             CREATE INDEX idx_stream_deleted_lineage_app_severity_id ON stream_deleted_log_lineage(app_name,severity,id);
             CREATE INDEX idx_stream_deleted_lineage_host_app_severity_id ON stream_deleted_log_lineage(hostname,app_name,severity,id);
             CREATE INDEX idx_stream_deleted_lineage_session_id ON stream_deleted_log_lineage(ai_project,ai_tool,ai_session_id,hostname,id);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (50);
             COMMIT;",
        )?;
        tracing::info!("Migration 50: indexed every durable stream filter shape");
    }

    // Migration 51: transcript scans can now distinguish a completed source
    // revision from a checkpoint at a record boundary.  The columns are
    // additive so older databases retain their imported-record identities;
    // existing rows are deliberately treated as complete because that was the
    // only state representable before this migration.
    if !migration_applied(&conn, 51)? {
        // Some historical recovery fixtures (and databases restored from an
        // interrupted early migration) retain the migration marker but not
        // the original transcript source table.  Migration 51 must converge
        // those databases instead of assuming every earlier table exists.
        let transcript_sources_exists = table_exists(&conn, "transcript_sources")?;
        let tx = conn.transaction()?;
        if !transcript_sources_exists {
            // With foreign-key enforcement disabled, damaged/restored databases
            // can retain children after the identity-bearing parent vanished.
            // Recreated parent IDs begin at 1, so retaining those rows would let
            // a new source inherit old dedupe receipts and parse errors.
            for child in ["transcript_import_records", "transcript_parse_errors"] {
                if table_exists(&tx, child)? {
                    tx.execute(&format!("DELETE FROM {child}"), [])?;
                }
            }
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS transcript_sources (
                     id              INTEGER PRIMARY KEY AUTOINCREMENT,
                     canonical_path  TEXT NOT NULL UNIQUE,
                     source_kind     TEXT NOT NULL,
                     file_size       INTEGER,
                     file_mtime      INTEGER,
                     content_hash    TEXT,
                     last_offset     INTEGER NOT NULL DEFAULT 0,
                     last_indexed_at TEXT,
                     last_error      TEXT
                 );",
            )?;
        }
        add_column_if_missing(&tx, "transcript_sources", "source_revision", "TEXT")?;
        add_column_if_missing(
            &tx,
            "transcript_sources",
            "scan_state",
            "TEXT NOT NULL DEFAULT 'complete' CHECK (scan_state IN ('restart', 'boundary', 'discard_until_newline', 'complete'))",
        )?;
        tx.execute(
            "UPDATE transcript_sources
             SET scan_state = 'complete'
             WHERE scan_state IS NULL
                OR scan_state NOT IN ('restart', 'boundary', 'discard_until_newline', 'complete')",
            [],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (51)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 51: added transcript scan revisions and states");
    }

    // Migration 52: receipt ledger for replay-safe agent syslog forwarding.
    //
    // The idempotency key is source-local and stable across reconnects.  The
    // receiver writes the canonical log and this receipt in the same SQLite
    // transaction; replay after a lost response therefore returns the old
    // receipt instead of creating a second canonical evidence row.
    if !migration_applied(&conn, 52)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS syslog_forward_receipts (
                 idempotency_key TEXT PRIMARY KEY,
                 source_instance TEXT NOT NULL,
                 source_epoch    INTEGER NOT NULL,
                 sequence        INTEGER NOT NULL,
                 canonical_log_id INTEGER NOT NULL,
                 receipt_kind    TEXT NOT NULL CHECK (receipt_kind IN ('record', 'gap')),
                 request_fingerprint TEXT NOT NULL,
                 received_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             CREATE INDEX IF NOT EXISTS idx_syslog_forward_receipts_source_sequence
               ON syslog_forward_receipts(source_instance, source_epoch, sequence);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (52);
             COMMIT;",
        )?;
        tracing::info!("Migration 52: created syslog forward receipt ledger");
    }

    // Migration 53: durable idempotency receipts for versioned AI transcript
    // evidence envelopes. The receipt belongs in the same transaction as the
    // canonical log row, so a sender can retry safely after losing a response.
    if !migration_applied(&conn, 53)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS ai_transcript_forward_receipts (
                 source_record_id TEXT PRIMARY KEY,
                 envelope_version INTEGER NOT NULL,
                 log_id INTEGER NOT NULL UNIQUE REFERENCES logs(id) ON DELETE CASCADE,
                 provider TEXT NOT NULL,
                 source_identity TEXT NOT NULL,
                 source_epoch TEXT NOT NULL,
                 source_revision TEXT NOT NULL,
                 received_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_ai_transcript_forward_receipts_source
               ON ai_transcript_forward_receipts
                  (provider, source_identity, source_epoch, source_revision);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (53);
             COMMIT;",
        )?;
        tracing::info!("Migration 53: created transcript evidence receipt ledger");
    }

    // Migration 54: explicit, versioned OTLP span-to-run association evidence.
    // The row records uncertainty rather than allowing read paths to turn a
    // host/session coincidence into a causal claim.
    if !migration_applied(&conn, 54)? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS agent_run_trace_relations (
                 id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                 relation_key         TEXT NOT NULL UNIQUE,
                 trace_id             TEXT NOT NULL CHECK (length(trace_id) = 32),
                 span_id              TEXT NOT NULL CHECK (length(span_id) = 16),
                 run_id               INTEGER REFERENCES agent_runs(id) ON DELETE SET NULL,
                 identifier_namespace TEXT NOT NULL,
                 provider             TEXT,
                 evidence_kind        TEXT NOT NULL CHECK (evidence_kind IN (
                     'exact_provider_id', 'trace_context', 'claimed', 'ambiguous', 'no_match'
                 )),
                 confidence           REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 reason               TEXT NOT NULL,
                 projection_version   INTEGER NOT NULL CHECK (projection_version > 0),
                 candidate_count      INTEGER NOT NULL DEFAULT 0 CHECK (candidate_count BETWEEN 0 AND 8),
                 observed_at          TEXT NOT NULL,
                 metadata_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
             );
             CREATE INDEX IF NOT EXISTS idx_agent_run_trace_relations_run_span
                 ON agent_run_trace_relations(run_id, observed_at DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_agent_run_trace_relations_trace_span
                 ON agent_run_trace_relations(trace_id, span_id, id);
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (54);
             COMMIT;",
        )?;
        tracing::info!("Migration 54: created versioned OTLP trace/run relations");
    }

    // Migration 55: keep bounded session-title provenance in the materialized
    // rollup. Reading it from raw logs per returned session would make the
    // indexed rollup path scale with transcript event volume again.
    if !migration_applied(&conn, 55)? {
        let tx = conn.transaction()?;
        // The rollup is a rebuildable cache. Legacy recovery databases can
        // carry the migration-21 marker without the optional table, so an
        // additive cache migration must not block the rest of their recovery.
        if table_exists(&tx, "ai_session_rollup")? {
            add_column_if_missing(&tx, "ai_session_rollup", "title", "TEXT")?;
            add_column_if_missing(&tx, "ai_session_rollup", "title_provenance", "TEXT")?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (55)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 55: added session title provenance to AI session rollup");
    }

    // Migration 56: bind syslog-forward replay receipts to the authenticated
    // request tuple so conflicting idempotency-key reuse cannot drop evidence.
    if !migration_applied(&conn, 56)? {
        let tx = conn.transaction()?;
        if table_exists(&tx, "syslog_forward_receipts")? {
            add_column_if_missing(
                &tx,
                "syslog_forward_receipts",
                "request_fingerprint",
                "TEXT NOT NULL DEFAULT ''",
            )?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (56)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 56: bound syslog forwarding receipts to request fingerprints");
    }

    // Migration 57: bind transcript replay receipts to the complete scrubbed
    // evidence envelope. The idempotency key alone cannot distinguish an
    // exact retry from a buggy or hostile sender reusing the ID for new data.
    if !migration_applied(&conn, 57)? {
        let tx = conn.transaction()?;
        if table_exists(&tx, "ai_transcript_forward_receipts")? {
            add_column_if_missing(
                &tx,
                "ai_transcript_forward_receipts",
                "request_fingerprint",
                "TEXT",
            )?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (57)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 57: bound transcript receipts to request fingerprints");
    }

    // Migration 58: recurring-error enrichment looks up evidence for a
    // bounded set of signature hashes in one query.
    if !migration_applied(&conn, 58)? {
        let tx = conn.transaction()?;
        if table_exists(&tx, "graph_relationship_evidence")? {
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_graph_evidence_error_signature_hash_id
                 ON graph_relationship_evidence(source_signature_hash, id)
                 WHERE source_kind = 'error_signature';",
            )?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (58)",
            [],
        )?;
        tx.commit()?;
        tracing::info!("Migration 58: indexed recurring-error graph evidence lookup");
    }

    if table_exists(&conn, "host_heartbeats")? && table_exists(&conn, "host_heartbeats_latest")? {
        let deleted_heartbeat_latest = conn.execute(
            "DELETE FROM host_heartbeats_latest
             WHERE NOT EXISTS (
                 SELECT 1 FROM host_heartbeats
                 WHERE host_heartbeats.id = host_heartbeats_latest.heartbeat_id
             )",
            [],
        )?;
        if deleted_heartbeat_latest > 0 {
            tracing::info!(
                deleted_rows = deleted_heartbeat_latest,
                "Reconciled orphan heartbeat latest cache rows"
            );
        }
    }

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_logs_ai_project_time
             ON logs(ai_project, timestamp)
             WHERE ai_project IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_logs_ai_session
             ON logs(ai_tool, ai_project, ai_session_id)
             WHERE ai_tool IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_logs_ai_session_host_time
             ON logs(ai_project, ai_tool, ai_session_id, hostname, timestamp)
             WHERE ai_project IS NOT NULL
               AND ai_tool IS NOT NULL
               AND ai_session_id IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_logs_ai_transcript_path
             ON logs(ai_transcript_path)
             WHERE ai_transcript_path IS NOT NULL;",
    )?;

    tracing::info!(path = %config.db_path.display(), "Database initialized");
    Ok(pool)
}

/// Reconcile work that could only remain `running` after the authoritative
/// server process exited. Query-only CLI processes may open the same live
/// database concurrently, so this must be called by server startup rather
/// than by [`init_pool`].
pub fn reconcile_interrupted_server_work(pool: &DbPool) -> Result<()> {
    let conn = crate::db::write_conn(pool)?;
    conn.execute_batch(
        "UPDATE maintenance_jobs
            SET status = 'failed',
                finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                result_json = json_object('error', \"interrupted by server restart\")
          WHERE status = 'running';

         UPDATE llm_invocations
            SET status = 'interrupted',
                finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                error = 'interrupted by server restart'
          WHERE status = 'running';",
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn migration_applied(conn: &Connection, version: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [version],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        [table, column],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    column_type: &str,
) -> rusqlite::Result<()> {
    if !column_exists(conn, table, column)? {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {column_type};"
        ))?;
    }
    Ok(())
}

fn apply_migration_17_inventory_stats(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "BEGIN IMMEDIATE;

         CREATE TABLE IF NOT EXISTS app_inventory_stats (
             app_name   TEXT PRIMARY KEY,
             log_count  INTEGER NOT NULL DEFAULT 0,
             first_seen TEXT NOT NULL,
             last_seen  TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_app_inventory_last_seen
             ON app_inventory_stats(last_seen DESC, app_name ASC);

         CREATE TABLE IF NOT EXISTS app_host_inventory_stats (
             app_name   TEXT NOT NULL,
             hostname   TEXT NOT NULL,
             log_count  INTEGER NOT NULL DEFAULT 0,
             first_seen TEXT NOT NULL,
             last_seen  TEXT NOT NULL,
             PRIMARY KEY (app_name, hostname)
         );
         CREATE INDEX IF NOT EXISTS idx_app_host_inventory_count
             ON app_host_inventory_stats(app_name, log_count DESC, hostname ASC);

         CREATE TABLE IF NOT EXISTS source_ip_inventory_stats (
             source_ip  TEXT PRIMARY KEY,
             log_count  INTEGER NOT NULL DEFAULT 0,
             first_seen TEXT NOT NULL,
             last_seen  TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_source_ip_inventory_count
             ON source_ip_inventory_stats(log_count DESC, source_ip ASC);

         CREATE TABLE IF NOT EXISTS source_ip_host_inventory_stats (
             source_ip  TEXT NOT NULL,
             hostname   TEXT NOT NULL,
             log_count  INTEGER NOT NULL DEFAULT 0,
             first_seen TEXT NOT NULL,
             last_seen  TEXT NOT NULL,
             PRIMARY KEY (source_ip, hostname)
         );
         CREATE INDEX IF NOT EXISTS idx_source_ip_host_inventory_count
             ON source_ip_host_inventory_stats(source_ip, log_count DESC, hostname ASC);

         CREATE TABLE IF NOT EXISTS inventory_backfill_state (
             name         TEXT PRIMARY KEY,
             completed_at TEXT,
             last_error   TEXT,
             last_log_id  INTEGER NOT NULL DEFAULT 0,
             high_watermark_id INTEGER
         );
         INSERT OR IGNORE INTO inventory_backfill_state(name)
         VALUES ('app_source_inventory');

         DROP TRIGGER IF EXISTS logs_inventory_app_ai;
         DROP TRIGGER IF EXISTS logs_inventory_app_ad;
         DROP TRIGGER IF EXISTS logs_inventory_source_ip_ai;
         DROP TRIGGER IF EXISTS logs_inventory_source_ip_ad;

         CREATE TRIGGER logs_inventory_app_ai AFTER INSERT ON logs
         WHEN NEW.app_name IS NOT NULL AND NEW.app_name != ''
         BEGIN
             INSERT INTO app_inventory_stats(app_name, log_count, first_seen, last_seen)
             VALUES (NEW.app_name, 1, NEW.received_at, NEW.received_at)
             ON CONFLICT(app_name) DO UPDATE SET
                 log_count = log_count + 1,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen);

             INSERT INTO app_host_inventory_stats(app_name, hostname, log_count, first_seen, last_seen)
             VALUES (NEW.app_name, NEW.hostname, 1, NEW.received_at, NEW.received_at)
             ON CONFLICT(app_name, hostname) DO UPDATE SET
                 log_count = log_count + 1,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen);
         END;

         CREATE TRIGGER logs_inventory_app_ad AFTER DELETE ON logs
         WHEN OLD.app_name IS NOT NULL AND OLD.app_name != ''
         BEGIN
             UPDATE app_inventory_stats
             SET log_count = log_count - 1
             WHERE app_name = OLD.app_name;
             DELETE FROM app_inventory_stats
             WHERE app_name = OLD.app_name AND log_count <= 0;

             UPDATE app_host_inventory_stats
             SET log_count = log_count - 1
             WHERE app_name = OLD.app_name AND hostname = OLD.hostname;
             DELETE FROM app_host_inventory_stats
             WHERE app_name = OLD.app_name AND hostname = OLD.hostname AND log_count <= 0;
         END;

         CREATE TRIGGER logs_inventory_source_ip_ai AFTER INSERT ON logs
         WHEN NEW.source_ip != ''
         BEGIN
             INSERT INTO source_ip_inventory_stats(source_ip, log_count, first_seen, last_seen)
             VALUES (NEW.source_ip, 1, NEW.received_at, NEW.received_at)
             ON CONFLICT(source_ip) DO UPDATE SET
                 log_count = log_count + 1,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen);

             INSERT INTO source_ip_host_inventory_stats(source_ip, hostname, log_count, first_seen, last_seen)
             VALUES (NEW.source_ip, NEW.hostname, 1, NEW.received_at, NEW.received_at)
             ON CONFLICT(source_ip, hostname) DO UPDATE SET
                 log_count = log_count + 1,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen);
         END;

         CREATE TRIGGER logs_inventory_source_ip_ad AFTER DELETE ON logs
         WHEN OLD.source_ip != ''
         BEGIN
             UPDATE source_ip_inventory_stats
             SET log_count = log_count - 1
             WHERE source_ip = OLD.source_ip;
             DELETE FROM source_ip_inventory_stats
             WHERE source_ip = OLD.source_ip AND log_count <= 0;

             UPDATE source_ip_host_inventory_stats
             SET log_count = log_count - 1
             WHERE source_ip = OLD.source_ip AND hostname = OLD.hostname;
             DELETE FROM source_ip_host_inventory_stats
             WHERE source_ip = OLD.source_ip AND hostname = OLD.hostname AND log_count <= 0;
         END;

         INSERT OR IGNORE INTO schema_migrations (version) VALUES (17);
         COMMIT;",
    )?;
    tracing::info!("Migration 17: created app/source inventory stats tables and triggers");
    Ok(())
}

pub fn inventory_backfill_complete(pool: &DbPool) -> Result<bool> {
    let conn = pool.get()?;
    let complete = conn.query_row(
        "SELECT completed_at IS NOT NULL
         FROM inventory_backfill_state
         WHERE name = 'app_source_inventory'",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(complete)
}

fn ensure_inventory_backfill_state_columns(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_missing(
        conn,
        "inventory_backfill_state",
        "last_log_id",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        conn,
        "inventory_backfill_state",
        "high_watermark_id",
        "INTEGER",
    )?;
    Ok(())
}

pub fn backfill_inventory_stats(pool: &DbPool) -> Result<()> {
    const CHUNK_SIZE: i64 = 25_000;
    const BETWEEN_CHUNKS: std::time::Duration = std::time::Duration::from_millis(25);

    if inventory_backfill_complete(pool)? {
        return Ok(());
    }
    let conn = pool.get()?;
    ensure_inventory_backfill_state_columns(&conn)?;
    tracing::info!(
        "Inventory stats backfill starting — queries may fall back to logs until this completes"
    );
    let started = std::time::Instant::now();

    loop {
        let (last_log_id, high_watermark_id): (i64, Option<i64>) = conn.query_row(
            "SELECT last_log_id, high_watermark_id
             FROM inventory_backfill_state
             WHERE name = 'app_source_inventory'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let high_watermark_id = match high_watermark_id {
            Some(id) => id,
            None => {
                let high: i64 =
                    conn.query_row("SELECT COALESCE(MAX(id), 0) FROM logs", [], |row| {
                        row.get(0)
                    })?;
                conn.execute_batch(
                    "BEGIN IMMEDIATE;
                     DELETE FROM app_inventory_stats;
                     DELETE FROM app_host_inventory_stats;
                     DELETE FROM source_ip_inventory_stats;
                     DELETE FROM source_ip_host_inventory_stats;",
                )?;
                conn.execute(
                    "UPDATE inventory_backfill_state
                     SET last_log_id = 0,
                         high_watermark_id = ?1,
                         completed_at = NULL,
                         last_error = NULL
                     WHERE name = 'app_source_inventory'",
                    [high],
                )?;
                conn.execute_batch("COMMIT;")?;
                high
            }
        };

        if last_log_id >= high_watermark_id {
            conn.execute(
                "UPDATE inventory_backfill_state
                 SET completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     last_error = NULL
                 WHERE name = 'app_source_inventory'",
                [],
            )?;
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                high_watermark_id,
                "Inventory stats backfill completed"
            );
            return Ok(());
        }

        let next_log_id = (last_log_id + CHUNK_SIZE).min(high_watermark_id);
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        let result = (|| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO app_inventory_stats(app_name, log_count, first_seen, last_seen)
                 SELECT app_name, COUNT(*), MIN(received_at), MAX(received_at)
                 FROM logs
                 WHERE id > ?1
                   AND id <= ?2
                   AND app_name IS NOT NULL
                   AND app_name != ''
                 GROUP BY app_name
                 ON CONFLICT(app_name) DO UPDATE SET
                     log_count = log_count + excluded.log_count,
                     first_seen = min(first_seen, excluded.first_seen),
                     last_seen = max(last_seen, excluded.last_seen)",
                (last_log_id, next_log_id),
            )?;
            conn.execute(
                "INSERT INTO app_host_inventory_stats(app_name, hostname, log_count, first_seen, last_seen)
                 SELECT app_name, hostname, COUNT(*), MIN(received_at), MAX(received_at)
                 FROM logs
                 WHERE id > ?1
                   AND id <= ?2
                   AND app_name IS NOT NULL
                   AND app_name != ''
                 GROUP BY app_name, hostname
                 ON CONFLICT(app_name, hostname) DO UPDATE SET
                     log_count = log_count + excluded.log_count,
                     first_seen = min(first_seen, excluded.first_seen),
                     last_seen = max(last_seen, excluded.last_seen)",
                (last_log_id, next_log_id),
            )?;
            conn.execute(
                "INSERT INTO source_ip_inventory_stats(source_ip, log_count, first_seen, last_seen)
                 SELECT source_ip, COUNT(*), MIN(received_at), MAX(received_at)
                 FROM logs
                 WHERE id > ?1
                   AND id <= ?2
                   AND source_ip != ''
                 GROUP BY source_ip
                 ON CONFLICT(source_ip) DO UPDATE SET
                     log_count = log_count + excluded.log_count,
                     first_seen = min(first_seen, excluded.first_seen),
                     last_seen = max(last_seen, excluded.last_seen)",
                (last_log_id, next_log_id),
            )?;
            conn.execute(
                "INSERT INTO source_ip_host_inventory_stats(source_ip, hostname, log_count, first_seen, last_seen)
                 SELECT source_ip, hostname, COUNT(*), MIN(received_at), MAX(received_at)
                 FROM logs
                 WHERE id > ?1
                   AND id <= ?2
                   AND source_ip != ''
                 GROUP BY source_ip, hostname
                 ON CONFLICT(source_ip, hostname) DO UPDATE SET
                     log_count = log_count + excluded.log_count,
                     first_seen = min(first_seen, excluded.first_seen),
                     last_seen = max(last_seen, excluded.last_seen)",
                (last_log_id, next_log_id),
            )?;
            conn.execute(
                "UPDATE inventory_backfill_state
                 SET last_log_id = ?1,
                     last_error = NULL
                 WHERE name = 'app_source_inventory'",
                [next_log_id],
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => conn.execute_batch("COMMIT;")?,
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK;");
                let _ = conn.execute(
                    "UPDATE inventory_backfill_state
                     SET last_error = ?1
                     WHERE name = 'app_source_inventory'",
                    [error.to_string()],
                );
                return Err(error.into());
            }
        }
        tracing::debug!(
            last_log_id = next_log_id,
            high_watermark_id,
            "Inventory stats backfill chunk completed"
        );
        std::thread::sleep(BETWEEN_CHUNKS);
    }
}

fn apply_migration_13(conn: &Connection) -> rusqlite::Result<()> {
    // Explicit transaction keeps index/version updates atomic, while each ALTER is
    // guarded so manually repaired or partially migrated DBs can converge instead
    // of failing on duplicate columns with no version row.
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        add_column_if_missing(conn, "logs", "http_status", "INTEGER")?;
        add_column_if_missing(conn, "logs", "auth_outcome", "TEXT")?;
        add_column_if_missing(conn, "logs", "dns_blocked", "INTEGER")?;
        add_column_if_missing(conn, "logs", "event_action", "TEXT")?;
        add_column_if_missing(conn, "logs", "parse_error", "TEXT")?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_logs_http_status_time
                 ON logs(http_status, timestamp) WHERE http_status IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_auth_outcome_time
                 ON logs(auth_outcome, timestamp) WHERE auth_outcome IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_dns_blocked_time
                 ON logs(dns_blocked, timestamp) WHERE dns_blocked IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_logs_event_action_time
                 ON logs(event_action, timestamp) WHERE event_action IS NOT NULL;
             INSERT OR IGNORE INTO schema_migrations (version) VALUES (13);",
        )
    })();

    match result {
        Ok(()) => conn.execute_batch("COMMIT;"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

// Migration 22: source watermark for the AI session rollup (bead cortex-g33v).
// The background refresh recomputed the full GROUP-BY over `logs` every cadence
// even when no AI rows had changed. These two columns record the source-side
// `(COUNT(*), MAX(id))` of AI rows captured by the last refresh; the refresh
// task compares the live watermark against them and skips the recompute when
// nothing changed. Both default to 0 so the first post-migration refresh always
// runs (live watermark > 0 whenever AI rows exist, and `refreshed_at` is still
// NULL regardless).
//
// Wrapped in an explicit BEGIN IMMEDIATE / COMMIT-or-ROLLBACK transaction so a
// crash between the two ALTERs and the version marker rolls back BOTH columns
// and the marker atomically — the previous bare `execute_batch` auto-committed
// each statement, leaving a half-applied DB that bricked `init_pool` on restart
// with "duplicate column name". Each ALTER is guarded with `add_column_if_missing`
// so a partially-applied DB (columns present, marker absent) converges on retry.
fn apply_migration_22(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        add_column_if_missing(
            conn,
            "ai_session_rollup_meta",
            "source_row_count",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            conn,
            "ai_session_rollup_meta",
            "source_max_id",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        conn.execute_batch("INSERT OR IGNORE INTO schema_migrations (version) VALUES (22);")
    })();

    match result {
        Ok(()) => conn.execute_batch("COMMIT;"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

fn apply_migration_15_heartbeat(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS host_heartbeats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id         TEXT NOT NULL,
            hostname        TEXT NOT NULL,
            source_ip       TEXT NOT NULL DEFAULT '',
            sampled_at      TEXT NOT NULL,
            received_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            boot_id         TEXT NOT NULL,
            uptime_secs     INTEGER NOT NULL,
            sequence        INTEGER NOT NULL,
            collection_ms   INTEGER NOT NULL,
            push_latency_ms INTEGER,
            partial         INTEGER NOT NULL DEFAULT 0,
            agent_version   TEXT NOT NULL,
            os              TEXT NOT NULL,
            kernel          TEXT,
            architecture    TEXT NOT NULL,
            metadata_json   TEXT,
            UNIQUE(host_id, boot_id, sequence)
        );

        CREATE INDEX IF NOT EXISTS idx_host_heartbeats_host_sampled
            ON host_heartbeats(host_id, sampled_at);
        CREATE INDEX IF NOT EXISTS idx_host_heartbeats_received
            ON host_heartbeats(received_at);
        CREATE INDEX IF NOT EXISTS idx_host_heartbeats_hostname_sampled
            ON host_heartbeats(hostname, sampled_at);

        CREATE TABLE IF NOT EXISTS heartbeat_cpu (
            heartbeat_id      INTEGER NOT NULL,
            load1             REAL,
            load5             REAL,
            load15            REAL,
            usage_percent     REAL,
            steal_percent     REAL,
            io_wait_percent   REAL
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_cpu_heartbeat_id
            ON heartbeat_cpu(heartbeat_id);

        CREATE TABLE IF NOT EXISTS heartbeat_memory (
            heartbeat_id      INTEGER NOT NULL,
            total_bytes       INTEGER,
            available_bytes   INTEGER,
            used_percent      REAL,
            swap_total_bytes  INTEGER,
            swap_used_bytes   INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_memory_heartbeat_id
            ON heartbeat_memory(heartbeat_id);

        CREATE TABLE IF NOT EXISTS heartbeat_disks (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            heartbeat_id        INTEGER NOT NULL,
            mountpoint          TEXT,
            filesystem          TEXT,
            total_bytes         INTEGER,
            available_bytes     INTEGER,
            used_percent        REAL,
            read_bytes_per_sec  REAL,
            write_bytes_per_sec REAL
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_disks_heartbeat_id
            ON heartbeat_disks(heartbeat_id);

        CREATE TABLE IF NOT EXISTS heartbeat_network (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            heartbeat_id     INTEGER NOT NULL,
            interface        TEXT NOT NULL,
            rx_bytes_per_sec REAL,
            tx_bytes_per_sec REAL,
            rx_errors        INTEGER,
            tx_errors        INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_network_heartbeat_id
            ON heartbeat_network(heartbeat_id);

        CREATE TABLE IF NOT EXISTS heartbeat_processes (
            heartbeat_id    INTEGER NOT NULL,
            total           INTEGER,
            running         INTEGER,
            sleeping        INTEGER,
            zombie          INTEGER,
            top_cpu_json    TEXT,
            top_memory_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_processes_heartbeat_id
            ON heartbeat_processes(heartbeat_id);

        CREATE TABLE IF NOT EXISTS heartbeat_containers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            heartbeat_id  INTEGER NOT NULL,
            runtime       TEXT,
            running       INTEGER,
            stopped       INTEGER,
            restarting    INTEGER,
            unhealthy     INTEGER,
            summary_json  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_heartbeat_containers_heartbeat_id
            ON heartbeat_containers(heartbeat_id);

        INSERT OR IGNORE INTO schema_migrations (version) VALUES (15);
        ",
    );

    match result {
        Ok(()) => conn.execute_batch("COMMIT;"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

fn apply_migration_18_heartbeat_restarting(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        add_column_if_missing(conn, "heartbeat_containers", "restarting", "INTEGER")?;
        conn.execute_batch("INSERT OR IGNORE INTO schema_migrations (version) VALUES (18);")
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT;"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

/// Migration 19: `host_heartbeats_latest` — one row per host_id, updated on
/// every new accepted heartbeat. This is the foundation for `fleet_state`
/// queries: instead of scanning `host_heartbeats` for the latest row per host
/// (O(heartbeats)), fleet queries scan this small table (O(hosts)).
///
/// Backfill on first apply: for each distinct `host_id`, find the row with the
/// highest `id` (proxy for latest, since `id` is AUTOINCREMENT) and seed the
/// cache. The GROUP BY scan happens once at migration time, not per query.
fn apply_migration_19_heartbeat_latest(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS host_heartbeats_latest (
                 host_id       TEXT PRIMARY KEY,
                 heartbeat_id  INTEGER NOT NULL,
                 hostname      TEXT NOT NULL,
                 sampled_at    TEXT NOT NULL,
                 received_at   TEXT NOT NULL,
                 partial       INTEGER NOT NULL DEFAULT 0,
                 agent_version TEXT NOT NULL DEFAULT '',
                 os            TEXT NOT NULL DEFAULT '',
                 architecture  TEXT NOT NULL DEFAULT '',
                 metadata_json TEXT
             );
             INSERT OR IGNORE INTO host_heartbeats_latest
                 (host_id, heartbeat_id, hostname, sampled_at, received_at,
                  partial, agent_version, os, architecture, metadata_json)
             SELECT h.host_id, h.id, h.hostname, h.sampled_at, h.received_at,
                    h.partial, h.agent_version, h.os, h.architecture, h.metadata_json
             FROM host_heartbeats h
             INNER JOIN (
                 SELECT host_id, MAX(id) AS max_id
                 FROM host_heartbeats
                 GROUP BY host_id
             ) latest ON h.id = latest.max_id;",
        )?;
        conn.execute_batch("INSERT OR IGNORE INTO schema_migrations (version) VALUES (19);")
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT;"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

fn configure_connection_pragmas(
    conn: &mut Connection,
    storage: &StorageConfig,
) -> rusqlite::Result<()> {
    if storage.wal_mode {
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5000_i64)?;
    let cache_size = storage
        .sqlite_page_cache_kib_per_connection()
        .map_err(|error| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            )))
        })?;
    conn.pragma_update(None, "cache_size", cache_size)?;
    let mmap_size = storage.sqlite_mmap_bytes_i64().map_err(|error| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            error.to_string(),
        )))
    })?;
    conn.pragma_update(None, "mmap_size", mmap_size)?;
    conn.pragma_update(None, "analysis_limit", 400_i64)?;
    Ok(())
}

#[cfg(test)]
#[path = "pool_tests.rs"]
mod tests;
