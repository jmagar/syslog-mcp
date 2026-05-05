use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::config::StorageConfig;

pub type DbPool = Pool<SqliteConnectionManager>;

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

#[cfg(test)]
#[path = "pool_tests.rs"]
mod tests;
