use super::*;

use crate::config::StorageConfig;
use crate::db::{
    ENTITY_TYPES, EVIDENCE_SOURCE_KINDS, LogBatchEntry, REASON_CODES, RELATIONSHIP_TYPES,
    TRUST_LEVELS, insert_logs_batch, is_known_entity_type, is_known_evidence_source_kind,
    is_known_reason_code, is_known_relationship_type, is_known_trust_level,
};
use rusqlite::OptionalExtension;

#[test]
fn documented_schema_count_matches_known_version() {
    assert_eq!(KNOWN_SCHEMA_VERSION, 58);
    assert!(include_str!("../../README.md").contains("58 sequential schema migrations"));
    assert!(include_str!("../../docs/architecture.md").contains("58 sequential migrations"));
}

#[test]
fn migration_57_adds_transcript_receipt_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&test_storage_config(dir.path().join("migration-57.db"))).unwrap();
    let conn = pool.get().unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(ai_transcript_forward_receipts)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "request_fingerprint"));

    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 57",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1);
}

fn migration_test_log() -> LogBatchEntry {
    LogBatchEntry {
        timestamp: "2026-01-01T00:00:00Z".into(),
        hostname: "migration-host".into(),
        facility: None,
        severity: "info".into(),
        app_name: Some("migration-test".into()),
        process_id: None,
        message: "preserved migration evidence".into(),
        raw: "preserved migration evidence".into(),
        source_ip: "127.0.0.1".into(),
        docker_checkpoint: None,
        ai_tool: Some("codex".into()),
        ai_project: Some("migration-project".into()),
        ai_session_id: Some("migration-session".into()),
        ai_transcript_path: None,
        metadata_json: None,
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

#[test]
fn populated_pre_56_syslog_receipts_upgrade_and_reopen_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("populated-pre-56.db");
    let config = test_storage_config(db_path.clone());
    let pool = init_pool(&config).unwrap();
    insert_logs_batch(&pool, &[migration_test_log()]).unwrap();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF;
         ALTER TABLE syslog_forward_receipts RENAME TO syslog_forward_receipts_new;
         CREATE TABLE syslog_forward_receipts (
             idempotency_key TEXT PRIMARY KEY,
             source_instance TEXT NOT NULL,
             source_epoch INTEGER NOT NULL,
             sequence INTEGER NOT NULL,
             canonical_log_id INTEGER NOT NULL,
             receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('record', 'gap')),
             received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         );
         INSERT INTO syslog_forward_receipts
             (idempotency_key, source_instance, source_epoch, sequence, canonical_log_id, receipt_kind, received_at)
         VALUES ('legacy-syslog', 'legacy-host', 7, 42, 1, 'record', '2026-01-01T00:00:00Z');
         DROP TABLE syslog_forward_receipts_new;
         CREATE INDEX idx_syslog_forward_receipts_source_sequence
             ON syslog_forward_receipts(source_instance, source_epoch, sequence);
         DELETE FROM schema_migrations WHERE version = 56;
         PRAGMA foreign_keys = ON;",
    )
    .unwrap();
    drop(conn);
    drop(pool);

    for reopen in 0..2 {
        let pool = init_pool(&config).unwrap();
        let conn = pool.get().unwrap();
        let receipt: (String, String, i64, i64, String) = conn
            .query_row(
                "SELECT source_instance, request_fingerprint, source_epoch, sequence, receipt_kind
                 FROM syslog_forward_receipts WHERE idempotency_key = 'legacy-syslog'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            receipt,
            ("legacy-host".into(), "".into(), 7, 42, "record".into())
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 56",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1,
            "reopen {reopen}"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM logs WHERE message = 'preserved migration evidence'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }
}

#[test]
fn populated_pre_57_transcript_receipts_upgrade_and_reopen_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("populated-pre-57.db");
    let config = test_storage_config(db_path.clone());
    let pool = init_pool(&config).unwrap();
    insert_logs_batch(&pool, &[migration_test_log()]).unwrap();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF;
         ALTER TABLE ai_transcript_forward_receipts RENAME TO ai_transcript_forward_receipts_new;
         CREATE TABLE ai_transcript_forward_receipts (
             source_record_id TEXT PRIMARY KEY,
             envelope_version INTEGER NOT NULL,
             log_id INTEGER NOT NULL UNIQUE REFERENCES logs(id) ON DELETE CASCADE,
             provider TEXT NOT NULL,
             source_identity TEXT NOT NULL,
             source_epoch TEXT NOT NULL,
             source_revision TEXT NOT NULL,
             received_at TEXT NOT NULL
         );
         INSERT INTO ai_transcript_forward_receipts
             (source_record_id, envelope_version, log_id, provider, source_identity, source_epoch, source_revision, received_at)
         VALUES ('legacy-record', 1, 1, 'codex', 'legacy-source', 'legacy-epoch', 'legacy-revision', '2026-01-01T00:00:00Z');
         DROP TABLE ai_transcript_forward_receipts_new;
         CREATE INDEX idx_ai_transcript_forward_receipts_source
             ON ai_transcript_forward_receipts(provider, source_identity, source_epoch, source_revision);
         DELETE FROM schema_migrations WHERE version = 57;
         PRAGMA foreign_keys = ON;",
    )
    .unwrap();
    drop(conn);
    drop(pool);

    for reopen in 0..2 {
        let pool = init_pool(&config).unwrap();
        let conn = pool.get().unwrap();
        let receipt: (String, i64, Option<String>, String) = conn
            .query_row(
                "SELECT provider, log_id, request_fingerprint, source_revision
                 FROM ai_transcript_forward_receipts WHERE source_record_id = 'legacy-record'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(receipt, ("codex".into(), 1, None, "legacy-revision".into()));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 57",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1,
            "reopen {reopen}"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM logs WHERE message = 'preserved migration evidence'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }
}

fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
    StorageConfig::for_test(db_path)
}

#[test]
fn is_pool_acquire_failure_detects_connection_acquisition_failures() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("pool-timeout.db"));
    let pool = init_pool(&config).unwrap();
    // `StorageConfig::for_test` uses `pool_size: 1`, so holding the only
    // connection guarantees the next acquisition times out.
    let _held = pool.get().unwrap();

    let timeout = anyhow::Error::new(
        pool.get_timeout(std::time::Duration::from_millis(50))
            .expect_err("exhausted pool must time out"),
    );

    assert!(is_pool_acquire_failure(&timeout));
    // Still detected once the writer/service layers add context on top.
    assert!(is_pool_acquire_failure(
        &timeout.context("insert log batch")
    ));
}

#[test]
fn is_pool_acquire_failure_ignores_sqlite_and_plain_errors() {
    let sqlite = anyhow::Error::new(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
        Some("UNIQUE constraint failed: logs.id".to_string()),
    ));

    assert!(!is_pool_acquire_failure(&sqlite));
    assert!(!is_pool_acquire_failure(&anyhow::anyhow!(
        "some other failure"
    )));
}

#[test]
fn pool_acquire_failure_detects_connection_establishment_errors() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SqliteConnectionManager::file(dir.path().join("missing").join("db.sqlite"));
    let broken = Pool::builder()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_millis(100))
        .thread_pool(shared_scheduled_thread_pool())
        .build_unchecked(manager);
    let error = anyhow::Error::new(
        broken
            .get_timeout(std::time::Duration::from_millis(100))
            .unwrap_err(),
    );
    assert!(is_pool_acquire_failure(&error));
}

#[test]
fn graph_temp_staging_does_not_reserve_writer_admission() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_storage_config(dir.path().join("graph-staging.db"));
    config.pool_size = 1;
    let pool = init_pool(&config).unwrap();
    let graph_pool = pool.clone();
    let (staged_tx, staged_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let graph = std::thread::spawn(move || {
        let conn = graph_staging_conn(&graph_pool).unwrap();
        conn.execute_batch("CREATE TEMP TABLE staging_probe(id INTEGER);")
            .unwrap();
        staged_tx.send(()).unwrap();
        finish_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let _lock = graph_staging_write_lock(&conn);
        conn.execute("INSERT INTO staging_probe VALUES (1)", [])
            .unwrap();
        done_tx.send(()).unwrap();
    });
    staged_rx.recv().unwrap();

    let writer = try_write_conn_for(&pool, std::time::Duration::from_secs(1))
        .expect("ordinary writer must proceed during graph staging");
    writer
        .execute_batch("CREATE TABLE writer_probe(id INTEGER);")
        .unwrap();
    drop(writer);
    finish_tx.send(()).unwrap();
    done_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    graph.join().unwrap();
}

#[test]
fn graph_staging_connection_inherits_pool_pragmas() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph-pragmas.db"));
    let pool = init_pool(&config).unwrap();
    let pooled = pool.get().unwrap();
    let pragmas = [
        "journal_mode",
        "synchronous",
        "cache_size",
        "mmap_size",
        "analysis_limit",
        "busy_timeout",
    ];
    let expected: Vec<rusqlite::types::Value> = pragmas
        .iter()
        .map(|pragma| {
            let sql = format!("PRAGMA {pragma}");
            pooled.query_row(&sql, [], |row| row.get(0)).unwrap()
        })
        .collect();
    drop(pooled);
    let staging = graph_staging_conn(&pool).unwrap();

    for (pragma, expected) in pragmas.into_iter().zip(expected) {
        let sql = format!("PRAGMA {pragma}");
        let actual: rusqlite::types::Value = staging.query_row(&sql, [], |row| row.get(0)).unwrap();
        assert_eq!(actual, expected, "staging connection drifted for {pragma}");
    }
}

#[test]
fn bounded_write_acquisition_uses_one_total_timeout_budget() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("bounded-write.db"));
    let pool = init_pool(&config).unwrap();
    let _only_connection = pool.get().unwrap();

    let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let _admission = write_admission();
        admitted_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
    });
    admitted_rx.recv().unwrap();

    let timeout = std::time::Duration::from_millis(1_000);
    let started = std::time::Instant::now();
    let result = try_write_conn_for(&pool, timeout);
    let elapsed = started.elapsed();

    assert!(matches!(result, Err(WriteConnBusy::Pool(_))));
    assert!(
        elapsed < std::time::Duration::from_millis(1_150),
        "admission and pool waits exceeded one timeout budget: {elapsed:?}"
    );
    blocker.join().unwrap();
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
fn init_pool_applies_sqlite_cache_budget_to_each_pooled_connection() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_storage_config(dir.path().join("cache-budget.db"));
    config.pool_size = 2;
    config.sqlite_page_cache_mb = 128;

    let pool = init_pool(&config).unwrap();
    let conn1 = pool.get().unwrap();
    let conn2 = pool.get().unwrap();

    let cache_1: i64 = conn1
        .query_row("PRAGMA cache_size", [], |row| row.get(0))
        .unwrap();
    let cache_2: i64 = conn2
        .query_row("PRAGMA cache_size", [], |row| row.get(0))
        .unwrap();

    assert_eq!(cache_1, -65_536);
    assert_eq!(cache_2, -65_536);
}

#[test]
fn init_pool_applies_sqlite_mmap_to_each_pooled_connection() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_storage_config(dir.path().join("mmap.db"));
    config.pool_size = 2;
    config.sqlite_mmap_mb = 32;

    let pool = init_pool(&config).unwrap();
    let conn1 = pool.get().unwrap();
    let conn2 = pool.get().unwrap();

    let mmap_1: i64 = conn1
        .query_row("PRAGMA mmap_size", [], |row| row.get(0))
        .unwrap();
    let mmap_2: i64 = conn2
        .query_row("PRAGMA mmap_size", [], |row| row.get(0))
        .unwrap();

    assert_eq!(mmap_1, 32 * 1024 * 1024);
    assert_eq!(mmap_2, 32 * 1024 * 1024);
}

#[test]
fn init_db_creates_heartbeat_schema_migration_15() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("heartbeat.db");
    let config = test_storage_config(db_path);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 15",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(applied, 1);

    for table in [
        "host_heartbeats",
        "heartbeat_cpu",
        "heartbeat_memory",
        "heartbeat_disks",
        "heartbeat_network",
        "heartbeat_processes",
        "heartbeat_containers",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing heartbeat table {table}");
    }

    for index in [
        "idx_host_heartbeats_host_sampled",
        "idx_host_heartbeats_received",
        "idx_host_heartbeats_hostname_sampled",
        "idx_heartbeat_cpu_heartbeat_id",
        "idx_heartbeat_memory_heartbeat_id",
        "idx_heartbeat_disks_heartbeat_id",
        "idx_heartbeat_network_heartbeat_id",
        "idx_heartbeat_processes_heartbeat_id",
        "idx_heartbeat_containers_heartbeat_id",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing heartbeat index {index}");
    }
}

#[test]
fn init_db_creates_timeline_and_jobs_schema_migrations_25_26() {
    // Validate migrations 25 + 26 on a CLEAN temp DB (never touch prod).
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("mig25_26.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    for version in [25, 26] {
        let applied: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(applied, 1, "migration {version} not recorded");
    }

    for table in [
        "timeline_hourly",
        "timeline_hourly_meta",
        "maintenance_jobs",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing table {table}");
    }

    // Meta row is seeded with watermark 0 / never-refreshed on a fresh DB.
    let (refreshed, max_id): (Option<String>, i64) = conn
        .query_row(
            "SELECT refreshed_at, source_max_id FROM timeline_hourly_meta WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(refreshed.is_none());
    assert_eq!(max_id, 0);

    // Empty DB => backfill skipped => rollup empty.
    let rollup_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM timeline_hourly", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rollup_rows, 0);
}

#[test]
fn init_db_creates_graph_schema_migration_27() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 27",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(applied, 1, "migration 27 not recorded");

    for table in [
        "graph_entities",
        "graph_entity_aliases",
        "graph_relationships",
        "graph_relationship_evidence",
        "graph_projection_meta",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing graph table {table}");
    }

    let (status, degraded): (String, i64) = conn
        .query_row(
            "SELECT projection_status, is_degraded FROM graph_projection_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "never_built");
    assert_eq!(degraded, 0);
}

#[test]
fn graph_migration_is_idempotent_and_preserves_raw_logs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph-idempotent.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).unwrap();

    let inserted = insert_logs_batch(
        &pool,
        &[LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "claimed-host".to_string(),
            facility: None,
            severity: "info".to_string(),
            app_name: Some("sshd".to_string()),
            process_id: None,
            message: "accepted publickey".to_string(),
            raw: "accepted publickey".to_string(),
            source_ip: "10.0.0.1:514".to_string(),
            docker_checkpoint: None,
            ai_tool: None,
            ai_project: None,
            ai_session_id: None,
            ai_transcript_path: None,
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        }],
    )
    .unwrap();
    assert_eq!(inserted, 1);
    drop(pool);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let log_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(log_count, 1, "graph migration must not mutate raw logs");

    let migration_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 27",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        migration_count, 1,
        "graph migration marker must remain idempotent"
    );
}

#[test]
fn graph_migration_converges_after_schema_exists_without_marker() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph-partial.db"));
    let pool = init_pool(&config).unwrap();
    {
        let conn = pool.get().unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 27", [])
            .unwrap();
    }
    drop(pool);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let migration_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 27",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        migration_count, 1,
        "migration 27 must converge when DDL already exists"
    );
}

#[test]
fn known_schema_version_matches_migration_head() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("schema-head.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let max_version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(max_version, KNOWN_SCHEMA_VERSION);
    drop(conn);

    let info = read_schema_version_info(&pool).unwrap();
    assert_eq!(info.version, KNOWN_SCHEMA_VERSION);
    assert_eq!(info.known_version, KNOWN_SCHEMA_VERSION);
}

#[test]
fn init_pool_creates_agent_observatory_repository_schema_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-repositories.db"));

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(repositories)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "repository_key",
            "hostname",
            "common_git_dir",
            "primary_path",
            "display_name",
            "remote_url_hash",
            "first_seen_at",
            "last_seen_at",
            "removed_at",
            "metadata_json",
            "created_at",
            "updated_at",
        ]
    );

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND tbl_name = 'repositories'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_repositories_display")
    );
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_repositories_host_seen")
    );

    conn.execute(
        "INSERT INTO repositories
            (repository_key, hostname, common_git_dir, primary_path, display_name,
             first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        rusqlite::params![
            "v1|6:devhost|20:/workspace/cortex/.git",
            "devhost",
            "/workspace/cortex/.git",
            "/workspace/cortex",
            "cortex",
            "2026-07-31T23:00:00.000Z",
        ],
    )
    .unwrap();
    assert!(
        conn.execute(
            "INSERT INTO repositories
                (repository_key, hostname, common_git_dir, primary_path, display_name,
                 first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![
                "v1|6:devhost|20:/workspace/cortex/.git",
                "other-host",
                "/workspace/other/.git",
                "/workspace/other",
                "other",
                "2026-07-31T23:00:00.000Z",
            ],
        )
        .is_err(),
        "repository_key must be globally unique"
    );
    assert!(
        conn.execute(
            "INSERT INTO repositories
                (repository_key, hostname, common_git_dir, primary_path, display_name,
                 first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![
                "different-key",
                "devhost",
                "/workspace/cortex/.git",
                "/workspace/cortex-copy",
                "cortex-copy",
                "2026-07-31T23:00:00.000Z",
            ],
        )
        .is_err(),
        "hostname/common_git_dir must identify one repository"
    );
    drop(conn);
    drop(pool);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM repositories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(row_count, 1, "reopening must preserve repository rows");
    let migration_44_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 44",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        migration_44_count, 1,
        "completed migration 44 must remain marked exactly once"
    );
}

#[test]
fn init_pool_creates_agent_observatory_worktree_schema_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-worktrees.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO repositories
            (repository_key, hostname, common_git_dir, primary_path, display_name,
             first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        rusqlite::params![
            "repo-key",
            "devhost",
            "/workspace/cortex/.git",
            "/workspace/cortex",
            "cortex",
            "2026-08-01T01:00:00.000Z",
        ],
    )
    .unwrap();
    let repository_id = conn.last_insert_rowid();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(repository_worktrees)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "worktree_key",
            "repository_id",
            "hostname",
            "path",
            "git_dir",
            "branch_ref",
            "branch_name",
            "head_sha",
            "upstream_ref",
            "detached",
            "bare",
            "locked",
            "lock_reason",
            "prunable",
            "prune_reason",
            "dirty",
            "staged_count",
            "unstaged_count",
            "untracked_count",
            "ahead",
            "behind",
            "status_hash",
            "first_seen_at",
            "last_seen_at",
            "removed_at",
            "created_at",
            "updated_at",
        ]
    );

    conn.execute(
        "INSERT INTO repository_worktrees
            (worktree_key, repository_id, hostname, path, git_dir, branch_ref,
             branch_name, head_sha, upstream_ref, dirty, staged_count,
             unstaged_count, untracked_count, ahead, behind, first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 2, 3, 4, 5, 6, ?10, ?10)",
        rusqlite::params![
            "worktree-key",
            repository_id,
            "devhost",
            "/workspace/cortex",
            "/workspace/cortex/.git",
            "refs/heads/feat/agent-observatory",
            "feat/agent-observatory",
            "0123456789012345678901234567890123456789",
            "refs/remotes/origin/feat/agent-observatory",
            "2026-08-01T01:00:00.000Z",
        ],
    )
    .unwrap();

    assert!(
        conn.execute(
            "INSERT INTO repository_worktrees
                (worktree_key, repository_id, hostname, path, git_dir, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![
                "different-key",
                repository_id,
                "devhost",
                "/workspace/cortex",
                "/workspace/cortex/.git/worktrees/duplicate",
                "2026-08-01T01:00:00.000Z",
            ],
        )
        .is_err(),
        "hostname/path must identify one worktree"
    );

    let state: (String, String, i64, i64, i64, i64, i64) = conn
        .query_row(
            "SELECT branch_name, head_sha, dirty, staged_count, unstaged_count,
                    untracked_count, ahead
             FROM repository_worktrees WHERE worktree_key = 'worktree-key'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        state,
        (
            "feat/agent-observatory".to_string(),
            "0123456789012345678901234567890123456789".to_string(),
            1,
            2,
            3,
            4,
            5,
        )
    );

    conn.execute("DELETE FROM repositories WHERE id = ?1", [repository_id])
        .unwrap();
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM repository_worktrees", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        remaining, 0,
        "repository deletion must cascade to worktrees"
    );

    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert_eq!(foreign_key_violation, None);
}

#[test]
fn init_pool_creates_agent_observatory_observation_schema_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-observations.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO repositories
            (repository_key, hostname, common_git_dir, primary_path, display_name,
             first_seen_at, last_seen_at)
         VALUES ('repo-key', 'devhost', '/workspace/cortex/.git',
                 '/workspace/cortex', 'cortex', ?1, ?1)",
        ["2026-08-01T01:00:00.000Z"],
    )
    .unwrap();
    let repository_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO repository_worktrees
            (worktree_key, repository_id, hostname, path, git_dir, first_seen_at, last_seen_at)
         VALUES ('worktree-key', ?1, 'devhost', '/workspace/cortex',
                 '/workspace/cortex/.git', ?2, ?2)",
        rusqlite::params![repository_id, "2026-08-01T01:00:00.000Z"],
    )
    .unwrap();
    let worktree_id = conn.last_insert_rowid();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(repository_observations)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "observation_key",
            "repository_id",
            "worktree_id",
            "observed_at",
            "observation_kind",
            "old_head_sha",
            "new_head_sha",
            "summary",
            "payload_json",
            "created_at",
        ]
    );

    let insert = |key: &str, observed_at: &str, kind: &str| {
        conn.execute(
            "INSERT INTO repository_observations
                (observation_key, repository_id, worktree_id, observed_at,
                 observation_kind, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '{}')",
            rusqlite::params![key, repository_id, worktree_id, observed_at, kind, key],
        )
    };
    insert("obs-1", "2026-08-01T01:00:00.000Z", "discovered").unwrap();
    insert("obs-2", "2026-08-01T01:00:01.000Z", "status").unwrap();
    insert("obs-3", "2026-08-01T01:00:01.000Z", "head").unwrap();

    assert!(
        insert("obs-1", "2026-08-01T01:00:02.000Z", "status").is_err(),
        "observation_key must be globally unique"
    );
    assert!(
        conn.execute(
            "INSERT INTO repository_observations
                (observation_key, repository_id, observed_at, observation_kind, payload_json)
             VALUES ('bad-json', ?1, ?2, 'error', '{')",
            rusqlite::params![repository_id, "2026-08-01T01:00:03.000Z"],
        )
        .is_err(),
        "payload_json must be valid JSON"
    );

    let ordered: Vec<String> = conn
        .prepare(
            "SELECT observation_key FROM repository_observations
             WHERE repository_id = ?1
             ORDER BY observed_at DESC, id DESC",
        )
        .unwrap()
        .query_map([repository_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ordered, vec!["obs-3", "obs-2", "obs-1"]);

    let repo_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM repository_observations
             WHERE repository_id = ?1
             ORDER BY observed_at DESC, id DESC LIMIT 10",
        )
        .unwrap()
        .query_map([repository_id], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        repo_plan
            .iter()
            .any(|detail| detail.contains("idx_repository_observations_repo_time")),
        "repository timeline query must use its chronological index: {repo_plan:?}"
    );

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND tbl_name = 'repository_observations'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_repository_observations_repo_time")
    );
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_repository_observations_worktree_time")
    );
}

#[test]
fn init_pool_creates_agent_observatory_git_commit_schema_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-commits.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    for (key, common_dir, path, name) in [
        ("repo-1", "/workspace/one/.git", "/workspace/one", "one"),
        ("repo-2", "/workspace/two/.git", "/workspace/two", "two"),
    ] {
        conn.execute(
            "INSERT INTO repositories
                (repository_key, hostname, common_git_dir, primary_path, display_name,
                 first_seen_at, last_seen_at)
             VALUES (?1, 'devhost', ?2, ?3, ?4, ?5, ?5)",
            rusqlite::params![key, common_dir, path, name, "2026-08-01T01:00:00.000Z"],
        )
        .unwrap();
    }
    let repo_one: i64 = conn
        .query_row(
            "SELECT id FROM repositories WHERE repository_key = 'repo-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let repo_two: i64 = conn
        .query_row(
            "SELECT id FROM repositories WHERE repository_key = 'repo-2'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(git_commits)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "repository_id",
            "sha",
            "parent_shas_json",
            "author_name",
            "author_email_hash",
            "authored_at",
            "committed_at",
            "subject",
            "changed_files",
            "insertions",
            "deletions",
            "changed_paths_json",
            "first_observed_at",
            "last_observed_at",
            "reachable",
            "metadata_json",
        ]
    );
    assert!(
        !columns
            .iter()
            .any(|name| matches!(name.as_str(), "diff" | "patch" | "blob" | "author_email"))
    );

    let sha = "0123456789012345678901234567890123456789";
    let insert_commit = |repository_id: i64| {
        conn.execute(
            "INSERT INTO git_commits
                (repository_id, sha, parent_shas_json, author_name, author_email_hash,
                 authored_at, committed_at, subject, changed_files, insertions,
                 deletions, changed_paths_json, first_observed_at, last_observed_at,
                 metadata_json)
             VALUES (?1, ?2, '[]', 'Cortex Test', 'sha256:test', ?3, ?3,
                     'test commit', 2, 10, 3, '[\"src/lib.rs\"]', ?3, ?3, '{}')",
            rusqlite::params![repository_id, sha, "2026-08-01T01:00:00.000Z"],
        )
    };
    insert_commit(repo_one).unwrap();
    assert!(
        insert_commit(repo_one).is_err(),
        "same SHA must dedupe within a repository"
    );
    insert_commit(repo_two).unwrap();

    assert!(
        conn.execute(
            "INSERT INTO git_commits
                (repository_id, sha, parent_shas_json, changed_paths_json,
                 first_observed_at, last_observed_at)
             VALUES (?1, 'bad-json', '{', '[]', ?2, ?2)",
            rusqlite::params![repo_one, "2026-08-01T01:00:00.000Z"],
        )
        .is_err(),
        "commit JSON columns must reject invalid JSON"
    );

    conn.execute(
        "UPDATE git_commits
         SET reachable = 0, last_observed_at = ?1
         WHERE repository_id = ?2 AND sha = ?3",
        rusqlite::params!["2026-08-01T02:00:00.000Z", repo_one, sha],
    )
    .unwrap();
    let state: (i64, String, String) = conn
        .query_row(
            "SELECT reachable, subject, last_observed_at FROM git_commits
             WHERE repository_id = ?1 AND sha = ?2",
            rusqlite::params![repo_one, sha],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        state,
        (
            0,
            "test commit".to_string(),
            "2026-08-01T02:00:00.000Z".to_string()
        )
    );

    let repo_one_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM git_commits WHERE repository_id = ?1",
            [repo_one],
            |row| row.get(0),
        )
        .unwrap();
    let repo_two_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM git_commits WHERE repository_id = ?1",
            [repo_two],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((repo_one_count, repo_two_count), (1, 1));

    let index_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'idx_git_commits_repo_time'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(index_exists, 1);
}

#[test]
fn migration_44_applies_from_schema_43_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("observatory-migration-44.db");
    let config = test_storage_config(db_path.clone());

    {
        let pool = init_pool(&config).unwrap();
        drop(pool);
    }

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE IF EXISTS git_commits;
             DROP TABLE IF EXISTS repository_observations;
             DROP TABLE IF EXISTS repository_worktrees;
             DROP TABLE IF EXISTS repositories;
             DELETE FROM schema_migrations WHERE version = 44;
             INSERT OR REPLACE INTO stream_last_seen
                 (hostname, source_kind, last_seen_at)
             VALUES ('legacy-host', 'syslog-tcp', '2026-08-01T01:00:00.000Z');
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
    }

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let max_version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        max_version, KNOWN_SCHEMA_VERSION,
        "schema 43 should upgrade to the current schema"
    );
    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 44",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1);

    for table in [
        "repositories",
        "repository_worktrees",
        "repository_observations",
        "git_commits",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "migration 44 must create {table}");
    }

    let legacy_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM stream_last_seen
             WHERE hostname = 'legacy-host' AND source_kind = 'syslog-tcp'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy_rows, 1, "migration must preserve schema-43 data");
    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert_eq!(foreign_key_violation, None);
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    drop(conn);
    drop(pool);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 44",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1, "reopening must not duplicate migration 44");
}

#[test]
fn init_pool_creates_agent_observatory_run_schema_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-runs.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_runs)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "run_key",
            "native_session_id",
            "tool",
            "provider_tool",
            "hostname",
            "parent_run_id",
            "previous_run_id",
            "primary_worktree_id",
            "transcript_path",
            "process_id",
            "status",
            "status_reason",
            "status_observed_at",
            "started_at",
            "last_activity_at",
            "ended_at",
            "first_source_log_id",
            "last_source_log_id",
            "last_event_id",
            "event_count",
            "error_count",
            "primary_branch",
            "start_head_sha",
            "current_head_sha",
            "projection_version",
            "freshness_json",
            "metadata_json",
            "created_at",
            "updated_at",
        ]
    );

    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5, ?5)",
        rusqlite::params![
            "v1|6:devhost|6:claude|9:session-1",
            "session-1",
            "claude",
            "devhost",
            "2026-08-01T02:00:00.000Z",
        ],
    )
    .unwrap();

    let primary_worktree_id: Option<i64> = conn
        .query_row(
            "SELECT primary_worktree_id FROM agent_runs WHERE native_session_id = 'session-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(primary_worktree_id, None);

    assert!(
        conn.execute(
            "INSERT INTO agent_runs
                (run_key, native_session_id, tool, hostname, status,
                 status_observed_at, started_at, last_activity_at)
             VALUES ('bad-status', 'session-2', 'claude', 'devhost',
                     'running-ish', ?1, ?1, ?1)",
            ["2026-08-01T02:00:01.000Z"],
        )
        .is_err(),
        "unknown lifecycle status must be rejected"
    );

    assert!(
        conn.execute(
            "INSERT INTO agent_runs
                (run_key, native_session_id, tool, hostname, status,
                 status_observed_at, started_at, last_activity_at)
             VALUES ('different-run-key', 'session-1', 'claude', 'devhost',
                     'idle', ?1, ?1, ?1)",
            ["2026-08-01T02:00:02.000Z"],
        )
        .is_err(),
        "host/tool/native-session identity must be unique"
    );

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND tbl_name = 'agent_runs'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for expected in [
        "idx_agent_runs_activity",
        "idx_agent_runs_status_activity",
        "idx_agent_runs_worktree_activity",
        "idx_agent_runs_tool_host",
    ] {
        assert!(
            indexes.iter().any(|name| name == expected),
            "missing {expected}"
        );
    }

    let query_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM agent_runs
             WHERE status = 'active'
             ORDER BY last_activity_at DESC, id DESC
             LIMIT 50",
        )
        .unwrap()
        .query_map([], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        query_plan
            .iter()
            .any(|detail| detail.contains("idx_agent_runs_status_activity")),
        "active-run query must use status/activity index: {query_plan:?}"
    );

    // Verify migration 47 is applied (schema includes OTLP tables)
    let migration_47_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 47",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        migration_47_count, 1,
        "migration 47 should be applied (OTLP metric points)"
    );
}

#[test]
fn init_pool_creates_agent_observatory_actor_and_worktree_evidence_schema() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-run-evidence.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO repositories
            (repository_key, hostname, common_git_dir, primary_path, display_name,
             first_seen_at, last_seen_at)
         VALUES ('repo-evidence', 'devhost', '/workspace/cortex/.git',
                 '/workspace/cortex', 'cortex', ?1, ?1)",
        ["2026-08-01T02:30:00.000Z"],
    )
    .unwrap();
    let repository_id = conn.last_insert_rowid();
    for (key, path) in [
        ("wt-main", "/workspace/cortex"),
        ("wt-feature", "/workspace/cortex/.worktrees/feature"),
    ] {
        conn.execute(
            "INSERT INTO repository_worktrees
                (worktree_key, repository_id, hostname, path, git_dir,
                 first_seen_at, last_seen_at)
             VALUES (?1, ?2, 'devhost', ?3, ?4, ?5, ?5)",
            rusqlite::params![
                key,
                repository_id,
                path,
                format!("{path}/.git"),
                "2026-08-01T02:30:00.000Z",
            ],
        )
        .unwrap();
    }
    let main_worktree: i64 = conn
        .query_row(
            "SELECT id FROM repository_worktrees WHERE worktree_key = 'wt-main'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let feature_worktree: i64 = conn
        .query_row(
            "SELECT id FROM repository_worktrees WHERE worktree_key = 'wt-feature'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('run-evidence', 'session-evidence', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T02:30:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    let actor_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_run_actors)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        actor_columns,
        vec![
            "id",
            "actor_key",
            "run_id",
            "native_actor_id",
            "actor_type",
            "display_name",
            "started_at",
            "last_activity_at",
            "ended_at",
            "metadata_json",
        ]
    );
    let evidence_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_run_worktrees)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        evidence_columns,
        vec![
            "id",
            "relation_key",
            "run_id",
            "worktree_id",
            "evidence_kind",
            "evidence_source",
            "trust_level",
            "confidence",
            "is_primary",
            "first_seen_at",
            "last_seen_at",
            "metadata_json",
        ]
    );

    conn.execute(
        "INSERT INTO agent_run_actors
            (actor_key, run_id, native_actor_id, actor_type, started_at, metadata_json)
         VALUES ('actor-key-1', ?1, 'subagent-1', 'subagent', ?2, '{}')",
        rusqlite::params![run_id, "2026-08-01T02:30:01.000Z"],
    )
    .unwrap();
    assert!(
        conn.execute(
            "INSERT INTO agent_run_actors
                (actor_key, run_id, native_actor_id, metadata_json)
             VALUES ('actor-key-2', ?1, 'subagent-1', '{}')",
            [run_id],
        )
        .is_err(),
        "native actor identity must dedupe within one run"
    );
    assert!(
        conn.execute(
            "INSERT INTO agent_run_actors
                (actor_key, run_id, native_actor_id, metadata_json)
             VALUES ('actor-bad-json', ?1, 'subagent-2', '{')",
            [run_id],
        )
        .is_err(),
        "actor metadata must be valid JSON"
    );

    let insert_relation = |relation_key: &str,
                           worktree_id: i64,
                           evidence_kind: &str,
                           evidence_source: &str,
                           trust: &str,
                           confidence: f64,
                           is_primary: i64,
                           last_seen: &str| {
        conn.execute(
            "INSERT INTO agent_run_worktrees
                (relation_key, run_id, worktree_id, evidence_kind, evidence_source,
                 trust_level, confidence, is_primary, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            rusqlite::params![
                relation_key,
                run_id,
                worktree_id,
                evidence_kind,
                evidence_source,
                trust,
                confidence,
                is_primary,
                last_seen,
            ],
        )
    };
    insert_relation(
        "rel-verified",
        main_worktree,
        "hook_cwd",
        "hook:1",
        "verified",
        1.0,
        1,
        "2026-08-01T02:30:02.000Z",
    )
    .unwrap();
    insert_relation(
        "rel-claimed",
        feature_worktree,
        "transcript_project_path",
        "log:2",
        "claimed",
        0.8,
        0,
        "2026-08-01T02:30:03.000Z",
    )
    .unwrap();

    assert!(
        insert_relation(
            "rel-duplicate",
            main_worktree,
            "hook_cwd",
            "hook:1",
            "verified",
            0.9,
            0,
            "2026-08-01T02:30:04.000Z",
        )
        .is_err(),
        "the same evidence tuple must not create a second relation"
    );
    assert!(
        insert_relation(
            "rel-confidence-high",
            main_worktree,
            "other",
            "source:high",
            "inferred",
            1.01,
            0,
            "2026-08-01T02:30:04.000Z",
        )
        .is_err(),
        "confidence above one must be rejected"
    );
    assert!(
        insert_relation(
            "rel-confidence-low",
            main_worktree,
            "other",
            "source:low",
            "inferred",
            -0.01,
            0,
            "2026-08-01T02:30:04.000Z",
        )
        .is_err(),
        "negative confidence must be rejected"
    );
    assert!(
        insert_relation(
            "rel-bad-trust",
            main_worktree,
            "other",
            "source:trust",
            "magical",
            0.5,
            0,
            "2026-08-01T02:30:04.000Z",
        )
        .is_err(),
        "unknown trust levels must be rejected"
    );

    let ordered: Vec<String> = conn
        .prepare(
            "SELECT relation_key FROM agent_run_worktrees
             WHERE run_id = ?1
             ORDER BY is_primary DESC, confidence DESC, last_seen_at DESC, id",
        )
        .unwrap()
        .query_map([run_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ordered, vec!["rel-verified", "rel-claimed"]);
    let distinct_worktrees: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT worktree_id) FROM agent_run_worktrees WHERE run_id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(distinct_worktrees, 2, "one run may have worktree history");

    for expected in [
        "idx_agent_run_actors_run",
        "idx_agent_run_worktrees_run",
        "idx_agent_run_worktrees_worktree",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [expected],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing {expected}");
    }
}

#[test]
fn schema_43_fixture_upgrades_to_48_and_preserves_legacy_rows() {
    const FIXTURE: &str = include_str!("../../tests/fixtures/schema-43.sql");
    assert!(!FIXTURE.contains("jmagar"));
    assert!(!FIXTURE.contains("/home/"));

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("schema-43-upgrade.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(FIXTURE).unwrap();
        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 43);
        let llm_table: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'llm_invocations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(llm_table, 1, "schema-43 fixture must include migration 37");
    }

    let config = test_storage_config(db_path);
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, KNOWN_SCHEMA_VERSION);

    let legacy_log: (String, String, String) = conn
        .query_row(
            "SELECT hostname, message, ai_session_id FROM logs WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        legacy_log,
        (
            "fixture-host".to_string(),
            "synthetic legacy log".to_string(),
            "fixture-session".to_string(),
        )
    );

    let rollup_count: i64 = conn
        .query_row(
            "SELECT event_count FROM ai_session_rollup
             WHERE ai_project = 'fixture-project'
               AND ai_tool = 'fixture-tool'
               AND ai_session_id = 'fixture-session'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rollup_count, 1);

    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert_eq!(foreign_key_violation, None);
}

#[test]
fn migration_51_recovers_a_missing_transcript_sources_table() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("missing-transcript-sources.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             WITH RECURSIVE versions(version) AS (
                 SELECT 1 UNION ALL SELECT version + 1 FROM versions WHERE version < 50
             )
             INSERT INTO schema_migrations(version) SELECT version FROM versions;
             CREATE TABLE logs (
                 id INTEGER PRIMARY KEY,
                 timestamp TEXT NOT NULL,
                 hostname TEXT NOT NULL,
                 facility TEXT,
                 severity TEXT NOT NULL,
                 app_name TEXT,
                 process_id TEXT,
                 message TEXT NOT NULL,
                 raw TEXT NOT NULL,
                 received_at TEXT NOT NULL,
                 source_ip TEXT NOT NULL DEFAULT '',
                 ai_project TEXT,
                 ai_tool TEXT,
                 ai_session_id TEXT,
                 ai_transcript_path TEXT,
                 metadata_json TEXT
             );
             CREATE TABLE transcript_import_records (
                 id INTEGER PRIMARY KEY,
                 source_id INTEGER NOT NULL,
                 record_key TEXT NOT NULL,
                 UNIQUE(source_id, record_key)
             );
             CREATE TABLE transcript_parse_errors (
                 id INTEGER PRIMARY KEY,
                 source_id INTEGER NOT NULL,
                 line_no INTEGER NOT NULL,
                 error TEXT NOT NULL,
                 record_preview TEXT NOT NULL,
                 UNIQUE(source_id, line_no, error, record_preview)
             );
             INSERT INTO transcript_import_records VALUES (1, 1, 'stale-record');
             INSERT INTO transcript_parse_errors VALUES (1, 1, 1, 'stale-error', 'secret');",
        )
        .unwrap();
    }

    let pool = init_pool(&test_storage_config(db_path)).unwrap();
    let conn = pool.get().unwrap();
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('transcript_sources') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert!(columns.contains(&"canonical_path".to_string()));
    assert!(columns.contains(&"source_revision".to_string()));
    assert!(columns.contains(&"scan_state".to_string()));
    for child in ["transcript_import_records", "transcript_parse_errors"] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {child}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "orphan rows in {child} must be swept");
    }
    conn.execute(
        "INSERT INTO transcript_sources (canonical_path, source_kind) VALUES ('new', 'codex_session')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO transcript_import_records (source_id, record_key) VALUES (1, 'stale-record')",
        [],
    )
    .expect("a new source must not collide with an orphaned dedupe receipt");
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        KNOWN_SCHEMA_VERSION
    );
}

#[test]
fn graph_schema_enforces_vocabulary_and_dedup_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph-dedup.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, trust_level)
         VALUES ('source_ip', '10.0.0.1:514', '10.0.0.1:514', 'verified')",
        [],
    )
    .unwrap();
    let duplicate = conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, trust_level)
         VALUES ('source_ip', '10.0.0.1:514', 'duplicate', 'verified')",
        [],
    );
    assert!(duplicate.is_err(), "canonical entity identity must dedupe");

    let bad_type = conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, trust_level)
         VALUES ('same_window', 'bad', 'bad', 'verified')",
        [],
    );
    assert!(bad_type.is_err(), "unknown entity types must be rejected");

    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, trust_level)
         VALUES ('host', 'claimed-host', 'claimed-host', 'claimed')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
         VALUES ('reverse_proxy', 'proxy:example.test', 'example.test',
             'app_inventory', 'proxy:example.test', 'verified')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
         VALUES ('domain', 'example.test', 'example.test',
             'app_inventory', 'example.test', 'verified')",
        [],
    )
    .unwrap();
    let source_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'source_ip'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let host_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'host'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let proxy_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'reverse_proxy'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let domain_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'domain'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    conn.execute(
        "INSERT INTO graph_entity_aliases
            (entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
         VALUES (?1, 'hostname', 'claimed-host', 'claimed-host', 'log', 'claimed')",
        [host_id],
    )
    .unwrap();
    let duplicate_alias = conn.execute(
        "INSERT INTO graph_entity_aliases
            (entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
         VALUES (?1, 'hostname', 'claimed-host', 'claimed-host', 'log', 'claimed')",
        [host_id],
    );
    assert!(duplicate_alias.is_err(), "alias identity must dedupe");

    conn.execute(
        "INSERT INTO graph_relationships
            (relationship_key, src_entity_id, dst_entity_id, relationship_type,
             reason_code, trust_level, confidence, evidence_count)
         VALUES ('source_ip:10.0.0.1:514->host:claimed-host', ?1, ?2,
             'observed_as', 'syslog_claimed_hostname', 'claimed', 0.60, 1)",
        rusqlite::params![source_id, host_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO graph_relationships
            (relationship_key, src_entity_id, dst_entity_id, relationship_type,
             reason_code, trust_level, confidence, evidence_count)
         VALUES ('reverse_proxy:example.test->domain:example.test',
             ?1, ?2, 'exposes_domain', 'reverse_proxy_config',
             'verified', 0.90, 1)",
        rusqlite::params![proxy_id, domain_id],
    )
    .unwrap();
    let duplicate_rel = conn.execute(
        "INSERT INTO graph_relationships
            (relationship_key, src_entity_id, dst_entity_id, relationship_type,
             reason_code, trust_level, confidence, evidence_count)
         VALUES ('source_ip:10.0.0.1:514->host:claimed-host', ?1, ?2,
             'observed_as', 'syslog_claimed_hostname', 'claimed', 0.60, 1)",
        rusqlite::params![source_id, host_id],
    );
    assert!(duplicate_rel.is_err(), "relationship key must dedupe");

    let rel_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_relationships
             WHERE relationship_key = 'source_ip:10.0.0.1:514->host:claimed-host'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO graph_relationship_evidence
            (relationship_id, evidence_key, source_kind, source_id, observed_at,
             reason_code, trust_level, safe_excerpt, evidence_count)
         VALUES (?1, 'log:1:hostname:2026-01-01T00', 'log', '1',
             '2026-01-01T00:00:00Z', 'syslog_claimed_hostname',
             'claimed', 'claimed-host', 3)",
        [rel_id],
    )
    .unwrap();
    let proxy_rel_id: i64 = conn
        .query_row(
            "SELECT id FROM graph_relationships
             WHERE relationship_key = 'reverse_proxy:example.test->domain:example.test'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO graph_relationship_evidence
            (relationship_id, evidence_key, source_kind, source_id, observed_at,
             reason_code, trust_level, safe_excerpt, evidence_count)
         VALUES (?1, 'proxy:example.test:route',
             'app_inventory', 'proxy:example.test',
             '2026-01-01T00:00:00Z', 'reverse_proxy_config',
             'verified', 'example.test routes through proxy config', 1)",
        [proxy_rel_id],
    )
    .unwrap();
    let duplicate_evidence = conn.execute(
        "INSERT INTO graph_relationship_evidence
            (relationship_id, evidence_key, source_kind, source_id, observed_at,
             reason_code, trust_level, safe_excerpt, evidence_count)
         VALUES (?1, 'log:1:hostname:2026-01-01T00', 'log', '1',
             '2026-01-01T00:00:00Z', 'syslog_claimed_hostname',
             'claimed', 'claimed-host', 3)",
        [rel_id],
    );
    assert!(
        duplicate_evidence.is_err(),
        "evidence key must dedupe repeated samples"
    );

    let bad_same_window = conn.execute(
        "INSERT INTO graph_relationships
            (relationship_key, src_entity_id, dst_entity_id, relationship_type,
             reason_code, trust_level)
         VALUES ('bad-same-window', ?1, ?2, 'same_window',
             'syslog_claimed_hostname', 'correlated')",
        rusqlite::params![source_id, host_id],
    );
    assert!(
        bad_same_window.is_err(),
        "same_window must not be a persisted v1 relationship type"
    );
}

#[test]
fn recurring_error_evidence_lookup_has_covering_partial_index() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&test_storage_config(dir.path().join("evidence-index.db"))).unwrap();
    let conn = pool.get().unwrap();
    let plan = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM graph_relationship_evidence
             WHERE source_kind = 'error_signature'
               AND source_signature_hash = 'hash'
             ORDER BY id",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|detail| { detail.contains("idx_graph_evidence_error_signature_hash_id") }),
        "recurring-error evidence must use the covering index: {plan:?}"
    );
}

#[test]
fn migration_58_recovers_when_index_exists_without_marker() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("migration-58-recovery.db"));
    let pool = init_pool(&config).unwrap();
    pool.get()
        .unwrap()
        .execute("DELETE FROM schema_migrations WHERE version = 58", [])
        .unwrap();
    drop(pool);

    let reopened = init_pool(&config).unwrap();
    let conn = reopened.get().unwrap();
    let markers: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 58",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(markers, 1);
}

#[test]
fn migration_30_widens_old_graph_constraints_and_preserves_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph-migration-30.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             WITH RECURSIVE versions(version) AS (
                 SELECT 1 UNION ALL SELECT version + 1 FROM versions WHERE version < 29
             )
             INSERT INTO schema_migrations(version) SELECT version FROM versions;
             CREATE TABLE maintenance_jobs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind TEXT NOT NULL,
                 status TEXT NOT NULL,
                 started_at TEXT NOT NULL,
                 finished_at TEXT,
                 result_json TEXT
             );
             CREATE TABLE graph_entities (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_type TEXT NOT NULL CHECK (entity_type IN (
                     'host', 'container', 'service', 'app', 'source_ip',
                     'ai_project', 'ai_session', 'error_signature'
                 )),
                 canonical_key TEXT NOT NULL,
                 display_label TEXT NOT NULL,
                 source_kind TEXT NOT NULL DEFAULT '',
                 source_id TEXT NOT NULL DEFAULT '',
                 trust_level TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at TEXT,
                 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_type, canonical_key)
             );
             CREATE TABLE graph_entity_aliases (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 entity_id INTEGER NOT NULL,
                 alias_type TEXT NOT NULL,
                 alias_key TEXT NOT NULL,
                 alias_value TEXT NOT NULL,
                 source_kind TEXT NOT NULL DEFAULT '',
                 trust_level TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 first_seen_at TEXT,
                 last_seen_at TEXT,
                 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(entity_id, alias_type, alias_key, source_kind)
             );
             CREATE TABLE graph_relationships (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_key TEXT NOT NULL UNIQUE,
                 src_entity_id INTEGER NOT NULL,
                 dst_entity_id INTEGER NOT NULL,
                 relationship_type TEXT NOT NULL CHECK (relationship_type IN (
                     'observed_as', 'runs_on', 'emitted_by', 'worked_on',
                     'matches_signature'
                 )),
                 reason_code TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match'
                 )),
                 trust_level TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 confidence REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
                 evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 first_seen_at TEXT,
                 last_seen_at TEXT,
                 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(src_entity_id, dst_entity_id, relationship_type, relationship_key)
             );
             CREATE TABLE graph_relationship_evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 relationship_id INTEGER NOT NULL,
                 evidence_key TEXT NOT NULL,
                 source_kind TEXT NOT NULL CHECK (source_kind IN (
                     'log', 'heartbeat', 'ai_session_rollup', 'error_signature'
                 )),
                 source_id TEXT NOT NULL DEFAULT '',
                 source_log_id INTEGER,
                 source_heartbeat_id INTEGER,
                 source_signature_hash TEXT,
                 observed_at TEXT NOT NULL,
                 reason_code TEXT NOT NULL CHECK (reason_code IN (
                     'syslog_claimed_hostname', 'log_app_name',
                     'docker_container_id', 'docker_service_label',
                     'ai_session_project', 'heartbeat_host_state',
                     'error_signature_match'
                 )),
                 reason_text TEXT,
                 confidence_delta REAL NOT NULL DEFAULT 0.0 CHECK (confidence_delta >= 0.0 AND confidence_delta <= 1.0),
                 trust_level TEXT NOT NULL CHECK (trust_level IN (
                     'verified', 'claimed', 'inferred', 'correlated'
                 )),
                 safe_excerpt TEXT,
                 metadata_path TEXT,
                 evidence_count INTEGER NOT NULL DEFAULT 1 CHECK (evidence_count >= 1),
                 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 UNIQUE(relationship_id, evidence_key)
             );
             CREATE TABLE graph_projection_meta (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 projection_status TEXT NOT NULL DEFAULT 'pending',
                 last_started_at TEXT,
                 last_completed_at TEXT,
                 source_watermark TEXT NOT NULL DEFAULT '',
                 source_row_count INTEGER NOT NULL DEFAULT 0 CHECK (source_row_count >= 0),
                 entity_count INTEGER NOT NULL DEFAULT 0 CHECK (entity_count >= 0),
                 relationship_count INTEGER NOT NULL DEFAULT 0 CHECK (relationship_count >= 0),
                 evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
                 is_degraded INTEGER NOT NULL DEFAULT 0 CHECK (is_degraded IN (0, 1)),
                 last_error TEXT,
                 last_runtime_ms INTEGER NOT NULL DEFAULT 0 CHECK (last_runtime_ms >= 0),
                 last_chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (last_chunk_count >= 0),
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             INSERT INTO graph_projection_meta(id) VALUES (1);
             INSERT INTO graph_entities
                 (id, entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
             VALUES
                 (1, 'source_ip', '10.0.0.1:514', '10.0.0.1:514', 'log', '1', 'verified'),
                 (2, 'host', 'claimed-host', 'claimed-host', 'log', '1', 'claimed');
             INSERT INTO graph_entity_aliases
                 (id, entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
             VALUES (1, 2, 'hostname', 'claimed-host', 'claimed-host', 'log', 'claimed');
             INSERT INTO graph_relationships
                 (id, relationship_key, src_entity_id, dst_entity_id, relationship_type,
                  reason_code, trust_level, confidence, evidence_count)
             VALUES (1, 'source_ip:10.0.0.1:514->host:claimed-host', 1, 2,
                 'observed_as', 'syslog_claimed_hostname', 'claimed', 0.60, 1);
             INSERT INTO graph_relationship_evidence
                 (id, relationship_id, evidence_key, source_kind, source_id, observed_at,
                  reason_code, trust_level, safe_excerpt, evidence_count)
             VALUES (1, 1, 'log:1:hostname', 'log', '1', '2026-01-01T00:00:00Z',
                 'syslog_claimed_hostname', 'claimed', 'claimed-host', 1);",
        )
        .unwrap();
    }

    let pool = init_pool(&test_storage_config(db_path)).unwrap();
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM graph_relationship_evidence WHERE evidence_key = 'log:1:hostname'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
         VALUES ('compose_project', 'edgehost:edge', 'edge',
             'app_inventory', 'compose:edgehost', 'verified')",
        [],
    )
    .unwrap();
    let relationship_id = conn
        .query_row(
            "SELECT id FROM graph_relationships
              WHERE relationship_key = 'source_ip:10.0.0.1:514->host:claimed-host'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO graph_relationship_evidence
            (relationship_id, evidence_key, source_kind, source_id, observed_at,
             reason_code, trust_level, safe_excerpt, evidence_count)
         VALUES (?1, 'inventory:route', 'app_inventory', 'proxy:edgehost',
             '2026-01-01T00:00:00Z', 'reverse_proxy_config',
             'verified', 'proxy route', 1)",
        rusqlite::params![relationship_id],
    )
    .unwrap();
}

#[test]
fn graph_vocabulary_helpers_cover_schema_values() {
    for value in ENTITY_TYPES {
        assert!(is_known_entity_type(value), "missing entity type {value}");
    }
    for value in RELATIONSHIP_TYPES {
        assert!(
            is_known_relationship_type(value),
            "missing relationship type {value}"
        );
    }
    for value in REASON_CODES {
        assert!(is_known_reason_code(value), "missing reason code {value}");
    }
    for value in TRUST_LEVELS {
        assert!(is_known_trust_level(value), "missing trust level {value}");
    }
    for value in EVIDENCE_SOURCE_KINDS {
        assert!(
            is_known_evidence_source_kind(value),
            "missing evidence source kind {value}"
        );
    }

    assert!(!is_known_relationship_type("same_window"));
    assert!(!is_known_entity_type("unknown"));
    assert!(!is_known_evidence_source_kind("source_table"));
}

#[test]
fn graph_lookup_indexes_support_expected_query_plans() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph-query-plan.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let plan_details = |sql: &str| -> Vec<String> {
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };

    let entity_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM graph_entities
         WHERE entity_type = 'host' AND canonical_key = 'devhost'",
    );
    assert!(
        entity_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_entities")),
        "entity lookup must use an indexed search: {entity_plan:?}"
    );

    let alias_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT entity_id FROM graph_entity_aliases
         WHERE alias_type = 'hostname' AND alias_key = 'devhost'",
    );
    assert!(
        alias_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_entity_aliases")),
        "alias lookup must use an indexed search: {alias_plan:?}"
    );

    let outgoing_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM graph_relationships
         WHERE src_entity_id = 1 AND relationship_type = 'observed_as'
         ORDER BY last_seen_at DESC LIMIT 50",
    );
    assert!(
        outgoing_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_relationships")),
        "outgoing relationship lookup must use an indexed search: {outgoing_plan:?}"
    );
    assert!(
        !outgoing_plan
            .iter()
            .any(|p| p == "SCAN graph_relationships"),
        "outgoing relationship lookup must not full-scan relationship table: {outgoing_plan:?}"
    );

    let incoming_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM graph_relationships
         WHERE dst_entity_id = 2 AND relationship_type = 'observed_as'
         ORDER BY last_seen_at DESC LIMIT 50",
    );
    assert!(
        incoming_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_relationships")),
        "incoming relationship lookup must use an indexed search: {incoming_plan:?}"
    );
    assert!(
        !incoming_plan
            .iter()
            .any(|p| p == "SCAN graph_relationships"),
        "incoming relationship lookup must not full-scan relationship table: {incoming_plan:?}"
    );

    let evidence_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM graph_relationship_evidence
         WHERE relationship_id = 1
         ORDER BY observed_at DESC LIMIT 3",
    );
    assert!(
        evidence_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_relationship_evidence")),
        "evidence lookup must use an indexed search: {evidence_plan:?}"
    );
    assert!(
        !evidence_plan
            .iter()
            .any(|p| p == "SCAN graph_relationship_evidence"),
        "evidence lookup must not full-scan evidence table: {evidence_plan:?}"
    );

    let source_cleanup_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM graph_relationship_evidence
         WHERE source_kind = 'log' AND source_id = '1'",
    );
    assert!(
        source_cleanup_plan
            .iter()
            .any(|p| p.contains("SEARCH graph_relationship_evidence")),
        "source cleanup lookup must use an indexed search: {source_cleanup_plan:?}"
    );
}

#[test]
fn heartbeat_schema_enforces_idempotency_key() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("heartbeat-unique.db");
    let config = test_storage_config(db_path);

    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let insert = "INSERT INTO host_heartbeats (
        host_id, hostname, source_ip, sampled_at, received_at, boot_id,
        uptime_secs, sequence, collection_ms, partial, agent_version, os, architecture
    ) VALUES (
        'host-1', 'box-a', '127.0.0.1:3100', '2026-05-25T00:00:00Z',
        '2026-05-25T00:00:01Z', 'boot-a', 60, 1, 12, 0, '0.1.0', 'linux', 'x86_64'
    )";
    conn.execute(insert, []).unwrap();
    let duplicate = conn.execute(insert, []);
    assert!(
        duplicate.is_err(),
        "duplicate heartbeat key must be rejected"
    );
}

#[test]
fn init_db_adds_ai_session_metadata_columns() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = crate::config::StorageConfig {
        db_path,
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();
    for column in [
        "ai_tool",
        "ai_project",
        "ai_session_id",
        "ai_transcript_path",
        "metadata_json",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name = ?1",
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing column {column}");
    }
}

#[test]
fn init_db_creates_partial_ai_metadata_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = crate::config::StorageConfig {
        db_path,
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();
    let indexes: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT name, sql FROM sqlite_schema
                 WHERE type = 'index'
                   AND name IN (
                     'idx_logs_ai_project_time',
                     'idx_logs_ai_session',
                     'idx_logs_ai_transcript_path'
                   )
                 ORDER BY name",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };

    assert_eq!(indexes.len(), 3);
    for (_, sql) in indexes {
        assert!(sql.contains("WHERE"));
        assert!(sql.contains("IS NOT NULL"));
    }
}

#[test]
fn migrations_23_24_yield_final_covering_index_set() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = crate::config::StorageConfig {
        db_path,
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();

    let index_sql = |name: &str| -> Option<String> {
        conn.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1",
            [name],
            |row| row.get::<_, String>(0),
        )
        .ok()
    };

    // Migration 23's interim AI index is superseded and DROPped by migration 24.
    assert!(
        index_sql("idx_logs_ai_project_cover").is_none(),
        "migration 24 must drop the superseded idx_logs_ai_project_cover"
    );

    // errors covering index (migration 23) survives.
    let sev_cover = index_sql("idx_logs_sev_host_time").expect("severity/host covering index");
    assert!(sev_cover.contains("severity"));
    assert!(sev_cover.contains("hostname"));
    assert!(sev_cover.contains("timestamp"));

    // Timestamp-positioned AI covering index (migration 24) serves ai projects + ai blocks.
    let ts_cover = index_sql("idx_logs_ai_project_ts_cover").expect("ai project ts-covering index");
    // Column order matters: ai_project, THEN timestamp (seekable), then the covered cols.
    let p = ts_cover.find("ai_project").unwrap();
    let t = ts_cover.find("timestamp").unwrap();
    let tool = ts_cover.find("ai_tool").unwrap();
    assert!(
        p < t && t < tool,
        "order must be ai_project, timestamp, ai_tool, ..."
    );
    assert!(ts_cover.contains("ai_session_id"));
    assert!(ts_cover.contains("ai_project IS NOT NULL"));

    // ai tools covering index (migration 24).
    let tool_cover = index_sql("idx_logs_ai_tool_cover").expect("ai tool covering index");
    assert!(tool_cover.contains("ai_tool"));
    assert!(tool_cover.contains("ai_session_id"));
    assert!(tool_cover.contains("timestamp"));

    // Migration 24 only ANALYZEs when `logs` already has rows, so this empty
    // fresh DB writes no `sqlite_stat1` (by design — empty-table stats mislead
    // the planner). The populated-DB ANALYZE path is covered by live validation.

    for v in [23, 24] {
        let applied: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
                [v],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(applied, 1, "migration {v} must be recorded");
    }
}

#[test]
fn migration_32_covers_graph_to_log_join() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("graph-log-cover.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    // Index DDL is present and carries the expected column order.
    let index_sql = |name: &str| -> Option<String> {
        conn.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1",
            [name],
            |row| row.get::<_, String>(0),
        )
        .ok()
    };

    let cover = index_sql("idx_logs_hostname_appname_time")
        .expect("graph→log covering index must exist after migration 32");
    let h = cover.find("hostname").unwrap();
    let a = cover.find("app_name").unwrap();
    let t = cover.find("timestamp").unwrap();
    assert!(
        h < a && a < t,
        "column order must be hostname, app_name, timestamp: {cover}"
    );

    let session_cover = index_sql("idx_logs_ai_session_time")
        .expect("session-anchored covering index must exist after migration 32");
    assert!(session_cover.contains("ai_session_id"));
    assert!(session_cover.contains("timestamp"));
    assert!(session_cover.contains("ai_session_id IS NOT NULL"));

    // The planner must pick the covering index for the topic_correlate join shape:
    // hostname IN (...) AND timestamp BETWEEN ... AND app_name = ...
    let plan_details = |sql: &str| -> Vec<String> {
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let join_plan = plan_details(
        "EXPLAIN QUERY PLAN
         SELECT id FROM logs
         WHERE hostname IN ('devhost', 'edgehost')
           AND app_name = 'swag'
           AND timestamp BETWEEN '2026-06-18T00:00:00Z' AND '2026-06-18T01:00:00Z'",
    );
    assert!(
        join_plan
            .iter()
            .any(|p| p.contains("idx_logs_hostname_appname_time")),
        "graph→log join must use idx_logs_hostname_appname_time: {join_plan:?}"
    );

    let applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 32",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(applied, 1, "migration 32 must be recorded");
}

#[test]
fn init_db_creates_inventory_stats_tables_and_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = crate::config::StorageConfig {
        db_path,
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();
    for table in [
        "app_inventory_stats",
        "app_host_inventory_stats",
        "source_ip_inventory_stats",
        "source_ip_host_inventory_stats",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing table {table}");
    }
    for trigger in [
        "logs_inventory_app_ai",
        "logs_inventory_app_ad",
        "logs_inventory_source_ip_ai",
        "logs_inventory_source_ip_ad",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing trigger {trigger}");
    }
}

#[test]
fn inventory_backfill_processes_existing_logs_in_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::config::StorageConfig {
        db_path: dir.path().join("test.db"),
        ..Default::default()
    };
    let pool = init_pool(&config).unwrap();
    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(LogBatchEntry {
            timestamp: format!("2026-01-01T00:00:0{i}Z"),
            hostname: format!("host-{i}"),
            facility: None,
            severity: "info".to_string(),
            app_name: Some("nginx".to_string()),
            process_id: None,
            message: "hello".to_string(),
            raw: "hello".to_string(),
            source_ip: "10.0.0.1:514".to_string(),
            docker_checkpoint: None,
            ai_tool: None,
            ai_project: None,
            ai_session_id: None,
            ai_transcript_path: None,
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        });
    }
    insert_logs_batch(&pool, &entries).unwrap();

    let conn = pool.get().unwrap();
    conn.execute("DELETE FROM app_inventory_stats", []).unwrap();
    conn.execute("DELETE FROM app_host_inventory_stats", [])
        .unwrap();
    conn.execute("DELETE FROM source_ip_inventory_stats", [])
        .unwrap();
    conn.execute("DELETE FROM source_ip_host_inventory_stats", [])
        .unwrap();
    drop(conn);

    backfill_inventory_stats(&pool).unwrap();

    let conn = pool.get().unwrap();
    let complete: bool = conn
        .query_row(
            "SELECT completed_at IS NOT NULL
             FROM inventory_backfill_state
             WHERE name = 'app_source_inventory'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(complete);
    let app_count: i64 = conn
        .query_row(
            "SELECT log_count FROM app_inventory_stats WHERE app_name = 'nginx'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(app_count, 3);
    let source_count: i64 = conn
        .query_row(
            "SELECT log_count FROM source_ip_inventory_stats WHERE source_ip = '10.0.0.1:514'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source_count, 3);
}

#[test]
fn init_db_adds_transcript_checkpoint_tables() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = crate::config::StorageConfig {
        db_path,
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();
    for table in [
        "transcript_sources",
        "transcript_import_records",
        "transcript_parse_errors",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing table {table}");
    }
    let preview_not_null: i64 = conn
        .query_row(
            "SELECT [notnull] FROM pragma_table_info('transcript_parse_errors') WHERE name = 'record_preview'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preview_not_null, 1);
}

#[test]
fn init_db_migrates_legacy_ai_schema_without_losing_logs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("legacy-ai.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "
        CREATE TABLE logs (
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
        CREATE VIRTUAL TABLE logs_fts USING fts5(
            message,
            content='logs',
            content_rowid='id',
            tokenize='porter unicode61'
        );
        CREATE TABLE hosts (
            hostname    TEXT PRIMARY KEY,
            first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            log_count   INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE schema_migrations (
            version     INTEGER PRIMARY KEY,
            applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        INSERT INTO schema_migrations(version) VALUES (1), (2), (3);
        INSERT INTO logs(timestamp, hostname, facility, severity, app_name, process_id, message, raw, source_ip)
        VALUES ('2026-05-11T00:00:00Z', 'legacy-host', 'local0', 'info', 'legacy', NULL, 'legacy preserved', 'legacy preserved', '127.0.0.1:514');
        INSERT INTO logs_fts(rowid, message) VALUES (1, 'legacy preserved');
        INSERT INTO hosts(hostname, log_count) VALUES ('legacy-host', 1);
        ",
    )
    .unwrap();
    drop(conn);

    let pool = init_pool(&test_storage_config(db_path)).unwrap();
    let conn = pool.get().unwrap();
    for column in [
        "ai_tool",
        "ai_project",
        "ai_session_id",
        "ai_transcript_path",
        "metadata_json",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name = ?1",
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "missing migrated column {column}");
    }
    for version in [4, 5, 6] {
        let applied: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(applied, 1, "missing migration {version}");
    }
    let preserved: String = conn
        .query_row(
            "SELECT message FROM logs WHERE hostname = 'legacy-host'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, "legacy preserved");
}

#[test]
fn migration_13_adds_enrichment_columns() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::config::StorageConfig {
        db_path: dir.path().join("test.db"),
        wal_mode: true,
        pool_size: 1,
        ..Default::default()
    };
    let pool = init_pool(&config).expect("init_pool ok");
    let conn = pool.get().unwrap();

    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(logs)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    for expected in [
        "http_status",
        "auth_outcome",
        "dns_blocked",
        "event_action",
        "parse_error",
    ] {
        assert!(
            cols.contains(&expected.to_string()),
            "missing column {expected}"
        );
    }

    let indices: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='logs'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    for expected in [
        "idx_logs_http_status_time",
        "idx_logs_auth_outcome_time",
        "idx_logs_dns_blocked_time",
        "idx_logs_event_action_time",
    ] {
        assert!(
            indices.contains(&expected.to_string()),
            "missing index {expected}"
        );
    }

    let version_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 13",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version_count, 1, "migration 13 row not recorded");
}

#[test]
fn migration_13_tolerates_existing_columns_without_version_row() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-13-drift.db");
    let config = crate::config::StorageConfig {
        db_path: db_path.clone(),
        wal_mode: true,
        pool_size: 1,
        ..Default::default()
    };
    let pool = init_pool(&config).expect("initial init_pool ok");
    drop(pool);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("DELETE FROM schema_migrations WHERE version = 13", [])
        .unwrap();
    conn.execute("DROP INDEX idx_logs_event_action_time", [])
        .unwrap();
    drop(conn);

    let pool = init_pool(&config).expect("re-init should repair migration drift");
    let conn = pool.get().unwrap();
    let version_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 13",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version_count, 1, "migration 13 row not restored");

    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_logs_event_action_time'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(index_count, 1, "migration 13 index not restored");
}

#[test]
fn transcript_import_identity_enforces_uniqueness() {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::config::StorageConfig {
        db_path: dir.path().join("test.db"),
        ..Default::default()
    };

    let _pool = init_pool(&config).unwrap();
    let conn = rusqlite::Connection::open(&config.db_path).unwrap();
    conn.execute(
        "INSERT INTO transcript_sources (canonical_path, source_kind) VALUES (?1, ?2)",
        rusqlite::params!["/tmp/session.jsonl", "explicit_file"],
    )
    .unwrap();
    let source_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO transcript_import_records (source_id, record_key) VALUES (?1, ?2)",
        rusqlite::params![source_id, "record-1"],
    )
    .unwrap();
    let err = conn
        .execute(
            "INSERT INTO transcript_import_records (source_id, record_key) VALUES (?1, ?2)",
            rusqlite::params![source_id, "record-1"],
        )
        .unwrap_err();
    assert!(matches!(err, rusqlite::Error::SqliteFailure(_, _)));
}

/// Reproduces the post-crash state of Migration 22 (bead syslog-mcp-tfr0): a
/// crash between the `ALTER TABLE ... ADD COLUMN` statements and the version
/// marker leaves the watermark columns present but version 22 absent from
/// `schema_migrations`. We reach that identical on-disk state cheaply by
/// migrating clean to head, then deleting only the version-22 marker row.
///
/// On the pre-fix (bare `execute_batch`) code this FAILS: re-running `init_pool`
/// re-issues the unguarded ALTERs and aborts with "duplicate column name". The
/// Style-C rewrite guards each ALTER with `add_column_if_missing` and stamps the
/// version with `INSERT OR IGNORE`, so `init_pool` converges (reentrant) and the
/// partial state becomes crash-impossible (a real mid-tx crash now rolls back
/// both columns and the marker atomically).
#[test]
fn migration_22_converges_from_partial_apply() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("partial_m22.db");
    let config = test_storage_config(db_path.clone());

    // 1. Migrate a clean DB to head (version 22, both columns present).
    let pool = init_pool(&config).unwrap();
    {
        let conn = pool.get().unwrap();
        // Sanity: migration 22 specifically is applied, with the columns present.
        // Assert on version 22 directly (not MAX(version)) so a future migration 23
        // cannot break this test even though migration 22 is correctly applied.
        let m22_applied: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 22",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(m22_applied, 1, "fixture must reach migration 22");
        for column in ["source_row_count", "source_max_id"] {
            assert!(
                column_exists(&conn, "ai_session_rollup_meta", column).unwrap(),
                "fixture must have column {column}"
            );
        }
        // 2. Recreate the post-crash state: columns present, marker absent.
        conn.execute("DELETE FROM schema_migrations WHERE version = 22", [])
            .unwrap();
    }
    drop(pool); // release the pooled connections / file handles

    // 3. Re-running init_pool must converge, not brick on "duplicate column name".
    let pool =
        init_pool(&config).expect("init_pool must be reentrant after a partial migration 22 apply");
    let conn = pool.get().unwrap();

    // Assert migration 22 specifically was re-stamped (not MAX(version)) so a
    // future migration 23 cannot mask a missing 22 marker / break this test.
    let m22_applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 22",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(m22_applied, 1, "version marker must be re-stamped to 22");

    for column in ["source_row_count", "source_max_id"] {
        assert!(
            column_exists(&conn, "ai_session_rollup_meta", column).unwrap(),
            "watermark column {column} must remain present after convergence"
        );
    }
}

/// Regression guard (bead syslog-mcp-tfr0): running `init_pool` twice against the
/// same file must both succeed. This passes on the pre-fix code too — it is NOT
/// the bug-prover (`migration_22_converges_from_partial_apply` is) — it just pins
/// the idempotent-on-clean-reopen behaviour so a future migration change can't
/// silently break it.
#[test]
fn init_pool_is_idempotent_when_run_twice() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("idempotent.db");
    let config = test_storage_config(db_path);

    let pool = init_pool(&config).expect("first init_pool must succeed");
    drop(pool);

    let pool = init_pool(&config).expect("second init_pool on same file must succeed");
    let conn = pool.get().unwrap();
    // Assert migration 22 specifically is applied (not MAX(version)) so a future
    // migration 23 cannot break this test even though 22 is correctly applied.
    let m22_applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 22",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(m22_applied, 1);
}

#[test]
fn migration_18_re_stamps_when_restarting_column_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("partial-m18.db");
    let config = test_storage_config(db_path.clone());

    let pool = init_pool(&config).unwrap();
    {
        let conn = pool.get().unwrap();
        assert!(
            column_exists(&conn, "heartbeat_containers", "restarting").unwrap(),
            "fixture must have heartbeat_containers.restarting"
        );
        conn.execute("DELETE FROM schema_migrations WHERE version = 18", [])
            .unwrap();
    }
    drop(pool);

    let pool = init_pool(&config).expect("migration 18 must converge with existing column");
    let conn = pool.get().unwrap();
    assert!(
        column_exists(&conn, "heartbeat_containers", "restarting").unwrap(),
        "restarting column must remain present"
    );
    let version_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 18",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version_count, 1, "migration 18 marker must be restored");
}

#[test]
fn migration_28_repairs_missing_runtime_metric_column_without_duplicate_marker() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("partial-m28.db");
    let config = test_storage_config(db_path.clone());

    let pool = init_pool(&config).unwrap();
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE graph_projection_meta
                SET last_runtime_ms = 4242,
                    last_chunk_count = 7
              WHERE id = 1",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 28", [])
            .unwrap();
        conn.execute(
            "ALTER TABLE graph_projection_meta DROP COLUMN last_chunk_count",
            [],
        )
        .unwrap();
    }
    drop(pool);

    let pool = init_pool(&config).expect("migration 28 must repair a missing runtime column");
    let conn = pool.get().unwrap();
    assert!(
        column_exists(&conn, "graph_projection_meta", "last_runtime_ms").unwrap(),
        "existing metric column must remain present"
    );
    assert!(
        column_exists(&conn, "graph_projection_meta", "last_chunk_count").unwrap(),
        "missing metric column must be restored"
    );
    let version_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 28",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        version_count, 1,
        "migration 28 marker must be restored exactly once"
    );
    let runtime_ms: i64 = conn
        .query_row(
            "SELECT last_runtime_ms FROM graph_projection_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(runtime_ms, 4242, "existing metric data must survive repair");
}

/// Golden old-schema fixture: the exact v0.2.6 schema (pre-migration-framework
/// — no schema_migrations table, no ai_* columns, no metadata_json). Frozen
/// from `git show v0.2.6:src/db.rs`; do not "modernize" it — its purpose is to
/// represent a real old installation.
const V0_2_6_SCHEMA: &str = "
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

    CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
        message,
        content='logs',
        content_rowid='id',
        tokenize='porter unicode61'
    );

    CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
        INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
    END;

    CREATE TABLE IF NOT EXISTS hosts (
        hostname    TEXT PRIMARY KEY,
        first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        log_count   INTEGER NOT NULL DEFAULT 0
    );
";

/// full-review TH2: every migration was previously tested only from CLEAN
/// temp DBs, so a migration that works against `CREATE`-fresh state but
/// breaks against populated old-shape tables would pass CI and brick real
/// upgrades. This walks the ENTIRE chain against a populated v0.2.6 database
/// and asserts: head version reached, pre-existing rows survive and remain
/// FTS-searchable, and a second run is a no-op.
#[test]
fn full_migration_chain_upgrades_populated_v0_2_6_database() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("v0_2_6-upgrade.db");

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(V0_2_6_SCHEMA).unwrap();
        for (ts, host, msg) in [
            (
                "2025-06-01T00:00:00Z",
                "old-host-a",
                "legacy kernel panic message",
            ),
            (
                "2025-06-02T00:00:00Z",
                "old-host-b",
                "legacy nginx upstream error",
            ),
        ] {
            conn.execute(
                "INSERT INTO logs (timestamp, hostname, severity, message, raw, received_at, source_ip)
                 VALUES (?1, ?2, 'err', ?3, ?3, ?1, '192.168.1.50:514')",
                rusqlite::params![ts, host, msg],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO hosts (hostname, first_seen, last_seen, log_count)
                 VALUES (?1, ?2, ?2, 1)
                 ON CONFLICT(hostname) DO NOTHING",
                rusqlite::params![host, ts],
            )
            .unwrap();
        }
    }

    // Walk the full migration chain (plus the auto_vacuum conversion VACUUM).
    let config = test_storage_config(db_path.clone());
    let pool = init_pool(&config).expect("full migration chain must apply to a populated old DB");

    let head_version: i64 = {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert!(
        head_version >= 31,
        "expected migration head >= 31, got {head_version}"
    );

    // Pre-existing rows survived and the FTS index still finds them.
    {
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "old rows must survive the migration chain");
    }
    let results = crate::db::search_logs(
        &pool,
        &crate::db::SearchParams {
            query: Some("legacy".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(results.len(), 2, "migrated rows must stay FTS-searchable");

    // New-schema columns are live: a current-shape insert works.
    insert_logs_batch(
        &pool,
        &[LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "new-host".to_string(),
            facility: None,
            severity: "info".to_string(),
            app_name: Some("upgrade-test".to_string()),
            process_id: None,
            message: "post-upgrade insert".to_string(),
            raw: "post-upgrade insert".to_string(),
            source_ip: "127.0.0.1:514".to_string(),
            docker_checkpoint: None,
            ai_tool: Some("claude-code".to_string()),
            ai_project: Some("/tmp/project".to_string()),
            ai_session_id: None,
            ai_transcript_path: None,
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        }],
    )
    .expect("current-shape insert must work after upgrade");

    drop(pool);

    // Idempotency: a second init on the upgraded DB is a clean no-op.
    let pool2 = init_pool(&config).expect("re-running init on an upgraded DB must succeed");
    let conn = pool2.get().unwrap();
    let head_again: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(head_again, head_version);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn migration_37_creates_llm_invocations_table() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).expect("init_pool should succeed");
    let conn = pool.get().unwrap();

    // Table exists with the exact locked column set.
    let mut stmt = conn
        .prepare(
            "SELECT COUNT(*) FROM pragma_table_info('llm_invocations') WHERE name IN (
                'id','started_at','finished_at','duration_ms','caller_surface','action',
                'provider','model','program','incident_id','ai_tool','ai_project',
                'ai_session_id','evidence_counts_json','prompt_bytes','output_bytes',
                'status','error','metadata_json'
            )",
        )
        .unwrap();
    let count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    assert_eq!(count, 19, "llm_invocations must have all 19 locked columns");
    drop(stmt);

    // Migration is recorded and idempotent.
    let version: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 37",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 1);

    // Re-running init_pool (simulating a restart) must not error or duplicate the row.
    drop(conn);
    drop(pool);
    let pool2 = init_pool(&config).expect("second init_pool should succeed");
    let conn2 = pool2.get().unwrap();
    let version2: i64 = conn2
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 37",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        version2, 1,
        "migration 37 must be idempotent across restarts"
    );
}

#[test]
fn migration_37_indexes_exist() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).expect("init_pool should succeed");
    let conn = pool.get().unwrap();
    for idx in [
        "idx_llm_invocations_started",
        "idx_llm_invocations_action_started",
        "idx_llm_invocations_status_started",
    ] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?1",
                [idx],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "expected index {idx} to exist");
    }
}

// PR #106 reconciliation fix (code-reviewer): if the process is killed
// between `LlmRunner::write_start_row` (status='running') and the matching
// finish-row write, the audit row is orphaned in 'running' forever — no
// process is left to finish it. Authoritative server startup reconciles
// orphaned rows after opening the pool. Query-only CLI processes deliberately
// skip this step because they can coexist with live server-owned work.
#[test]
fn server_start_reconciles_orphaned_running_work_without_pool_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).expect("init_pool should succeed");
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO llm_invocations
            (id, started_at, caller_surface, action, provider, status)
         VALUES ('llm-orphan', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'test', 'ai_assess', 'gemini-cli', 'running')",
        [],
    )
    .expect("seed orphaned running row");

    // A concurrently-'success' row (as if it finished cleanly before the
    // crash) must be left untouched by the reconciliation.
    conn.execute(
        "INSERT INTO llm_invocations
            (id, started_at, finished_at, caller_surface, action, provider, status)
         VALUES ('llm-clean', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'test', 'ai_assess', 'gemini-cli', 'success')",
        [],
    )
    .expect("seed clean success row");

    conn.execute(
        "INSERT INTO maintenance_jobs (kind, status, started_at)
         VALUES ('db_integrity', 'running', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        [],
    )
    .expect("seed running maintenance job");

    drop(conn);
    drop(pool);

    // Merely opening another pool, as a local CLI does, must not alter work
    // still owned by the running server.
    let pool2 = init_pool(&config).expect("second init_pool should succeed");
    let conn2 = pool2.get().unwrap();

    let untouched: String = conn2
        .query_row(
            "SELECT status FROM llm_invocations WHERE id = 'llm-orphan'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(untouched, "running");
    let maintenance_untouched: String = conn2
        .query_row(
            "SELECT status FROM maintenance_jobs WHERE kind = 'db_integrity'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(maintenance_untouched, "running");
    drop(conn2);

    reconcile_interrupted_server_work(&pool2).unwrap();
    let conn2 = pool2.get().unwrap();

    let (status, finished_at, error): (String, Option<String>, Option<String>) = conn2
        .query_row(
            "SELECT status, finished_at, error FROM llm_invocations WHERE id = 'llm-orphan'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "interrupted");
    assert!(
        finished_at.is_some(),
        "reconciled row must get a finished_at timestamp"
    );
    assert_eq!(error.as_deref(), Some("interrupted by server restart"));

    let (maintenance_status, maintenance_error): (String, String) = conn2
        .query_row(
            "SELECT status, json_extract(result_json, '$.error')
             FROM maintenance_jobs WHERE kind = 'db_integrity'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(maintenance_status, "failed");
    assert_eq!(maintenance_error, "interrupted by server restart");

    let clean_status: String = conn2
        .query_row(
            "SELECT status FROM llm_invocations WHERE id = 'llm-clean'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        clean_status, "success",
        "reconciliation must not touch rows that already reached a terminal status"
    );
}

#[test]
fn migration_38_creates_ai_skill_events_table() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).expect("init_pool should succeed");
    let conn = pool.get().unwrap();

    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ai_skill_events'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(table_exists, 1);

    let indexes: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ai_skill_events' ORDER BY name",
            )
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    assert!(indexes.contains(&"idx_ai_skill_events_timestamp".to_string()));
    assert!(indexes.contains(&"idx_ai_skill_events_skill_time".to_string()));
    assert!(indexes.contains(&"idx_ai_skill_events_plugin_time".to_string()));
    assert!(indexes.contains(&"idx_ai_skill_events_hostname_time".to_string()));
    assert!(indexes.contains(&"idx_ai_skill_events_session_time".to_string()));
    assert!(indexes.contains(&"idx_ai_skill_events_project_skill_time".to_string()));

    // Eng review Fix 5: idx_logs_ai_tool_id lives on the EXISTING `logs`
    // table (backfill keyset-pagination support), not `ai_skill_events`.
    let logs_index_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_logs_ai_tool_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(logs_index_exists, 1);

    // UNIQUE constraint + idempotent re-run of the whole insert on identical
    // (log_id, skill_name, event_kind, evidence_kind) is exercised in Task 6;
    // here we only assert the migration ran and the schema is fully caught up
    // (later migrations, e.g. 39/40, run in the same init_db pass).
    let version = crate::db::read_schema_version_info_conn(&conn)
        .unwrap()
        .version;
    assert_eq!(version, KNOWN_SCHEMA_VERSION);
}

#[test]
fn graph_schema_accepts_entity_resolution_vocabulary() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(
        dir.path().join("resolver-vocab.db"),
    ))
    .unwrap();
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
         VALUES
            ('logical_service', 'plex', 'plex', 'resolver', 'fixture', 'verified'),
            ('service_instance', 'nashost/plex', 'nashost/plex', 'resolver', 'fixture', 'verified')",
        [],
    )
    .unwrap();
    let service = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'logical_service'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    let instance = conn
        .query_row(
            "SELECT id FROM graph_entities WHERE entity_type = 'service_instance'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO graph_relationships
            (relationship_key, src_entity_id, dst_entity_id, relationship_type,
             reason_code, trust_level, confidence)
         VALUES (?1, ?2, ?3, 'instance_of', 'resolver_instance_of', 'verified', 1.0)",
        rusqlite::params![
            format!("{instance}:instance_of:{service}"),
            instance,
            service
        ],
    )
    .unwrap();
}

#[test]
fn migration_41_cleans_legacy_service_rows_from_populated_db() {
    // Simulate a populated pre-41 DB: run all migrations, then re-insert the
    // old-shaped rows a v40 DB could contain and re-run the 41 cleanup SQL by
    // reverting the migration marker before a second init_pool pass.
    //
    // NOTE: this replay runs on a post-41 schema (the CHECK constraints
    // already include the v41 vocabulary), not a byte-faithful v40 schema.
    // The migration's INSERT…SELECT filters are what is under test.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-41-cutover.db");
    {
        let pool = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO graph_entities
                (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
             VALUES
                ('service', 'nashost:plex', 'plex', 'log', 'fixture', 'inferred'),
                ('service', 'nashost:plex:plex', 'nashost/plex/plex', 'log', 'fixture', 'inferred'),
                ('app', 'plex/plex/plex', 'plex/plex/plex', 'log', 'fixture', 'claimed'),
                ('app', 'kernel', 'kernel', 'log', 'fixture', 'claimed')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 41", [])
            .unwrap();
        // Drop the 41-added column so the ALTER TABLE in the replayed
        // migration does not collide.
        conn.execute_batch("ALTER TABLE graph_projection_meta DROP COLUMN projection_contract;")
            .unwrap();
    }
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let conn = pool.get().unwrap();
    let stale: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM graph_entities
              WHERE entity_type = 'service'
                 OR (entity_type = 'app' AND canonical_key LIKE '%/%/%')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stale, 0);
    // Plain app labels survive the cutover; only nested defect shapes go.
    let plain_app: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM graph_entities WHERE entity_type = 'app' AND canonical_key = 'kernel'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(plain_app, 1);
    let contract: String = conn
        .query_row(
            "SELECT projection_contract FROM graph_projection_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        contract,
        crate::db::entity_resolution::vocab::GRAPH_PROJECTION_CONTRACT_V2
    );
}

#[test]
fn migration_41_prunes_relationships_evidence_and_aliases_touching_legacy_entities() {
    // Same replay technique as the cleanup test above (post-41 schema, see
    // its NOTE): seed a legacy `service` entity wired to a surviving host
    // via a relationship with evidence plus an alias, and an unrelated
    // surviving app→host relationship with evidence. Migration 41 must
    // prune everything touching the legacy entity and nothing else, leaving
    // no evidence row pointing at a dead relationship id, and flip a ready
    // projection to stale.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-41-prune.db");
    {
        let pool = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
        let conn = pool.get().unwrap();
        let insert_entity = |entity_type: &str, key: &str| -> i64 {
            conn.execute(
                "INSERT INTO graph_entities
                    (entity_type, canonical_key, display_label, source_kind,
                     source_id, trust_level)
                 VALUES (?1, ?2, ?2, 'log', 'fixture', 'inferred')",
                rusqlite::params![entity_type, key],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let insert_rel = |key: &str, src: i64, dst: i64| -> i64 {
            conn.execute(
                "INSERT INTO graph_relationships
                    (relationship_key, src_entity_id, dst_entity_id,
                     relationship_type, reason_code, trust_level, confidence,
                     evidence_count)
                 VALUES (?1, ?2, ?3, 'runs_on', 'log_app_name', 'inferred',
                         0.5, 1)",
                rusqlite::params![key, src, dst],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let insert_evidence = |rel_id: i64, evidence_key: &str| {
            conn.execute(
                "INSERT INTO graph_relationship_evidence
                    (relationship_id, evidence_key, source_kind, source_id,
                     observed_at, reason_code, trust_level, evidence_count)
                 VALUES (?1, ?2, 'log', 'fixture', '2026-01-01T00:00:00Z',
                         'log_app_name', 'inferred', 1)",
                rusqlite::params![rel_id, evidence_key],
            )
            .unwrap();
        };

        let legacy = insert_entity("service", "nashost:plex");
        let host = insert_entity("host", "nashost");
        let app = insert_entity("app", "kernel");
        let legacy_rel = insert_rel("legacy:runs_on:host", legacy, host);
        insert_evidence(legacy_rel, "legacy-evidence");
        conn.execute(
            "INSERT INTO graph_entity_aliases
                (entity_id, alias_type, alias_key, alias_value, trust_level)
             VALUES (?1, 'service_name', 'plex-legacy', 'plex-legacy',
                     'inferred')",
            [legacy],
        )
        .unwrap();
        let surviving_rel = insert_rel("app:runs_on:host", app, host);
        insert_evidence(surviving_rel, "surviving-evidence");

        conn.execute(
            "UPDATE graph_projection_meta SET projection_status = 'ready' WHERE id = 1",
            [],
        )
        .unwrap();

        conn.execute("DELETE FROM schema_migrations WHERE version = 41", [])
            .unwrap();
        conn.execute_batch("ALTER TABLE graph_projection_meta DROP COLUMN projection_contract;")
            .unwrap();
    }
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let conn = pool.get().unwrap();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).unwrap() };

    // Legacy entity and everything touching it are gone.
    assert_eq!(
        count("SELECT COUNT(*) FROM graph_entities WHERE entity_type = 'service'"),
        0
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM graph_relationships
              WHERE relationship_key = 'legacy:runs_on:host'"
        ),
        0
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM graph_relationship_evidence
              WHERE evidence_key = 'legacy-evidence'"
        ),
        0
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM graph_entity_aliases WHERE alias_key = 'plex-legacy'"),
        0
    );

    // The unrelated app→host relationship and its evidence survive.
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM graph_relationships
              WHERE relationship_key = 'app:runs_on:host'"
        ),
        1
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM graph_relationship_evidence
              WHERE evidence_key = 'surviving-evidence'"
        ),
        1
    );

    // Referential integrity: no evidence row references a dead relationship.
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM graph_relationship_evidence e
              WHERE e.relationship_id NOT IN (SELECT id FROM graph_relationships)"
        ),
        0
    );

    // A previously-ready projection is flipped to stale by the migration.
    let status: String = conn
        .query_row(
            "SELECT projection_status FROM graph_projection_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "stale");
}

#[test]
fn migration_42_allows_refuted_alias_trust_level() {
    // Migrations 35/41 added 'refuted' to graph_entities, graph_relationships,
    // and graph_relationship_evidence but missed graph_entity_aliases.
    // Migration 42 widens that CHECK too; assert a fresh DB accepts an alias
    // write at 'refuted' trust without violating the constraint.
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("migration-42-refuted-alias.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO graph_entities
            (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
         VALUES ('host', 'refuted-alias-host', 'refuted-alias-host', 'log', 'fixture', 'verified')",
        [],
    )
    .unwrap();
    let entity_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO graph_entity_aliases
            (entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
         VALUES (?1, 'hostname', 'refuted-alias-host', 'refuted-alias-host', 'log', 'refuted')",
        rusqlite::params![entity_id],
    )
    .unwrap();

    let stored_trust: String = conn
        .query_row(
            "SELECT trust_level FROM graph_entity_aliases WHERE entity_id = ?1",
            rusqlite::params![entity_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_trust, "refuted");
}

#[test]
fn migration_42_widens_old_aliases_constraint_and_preserves_rows() {
    // Simulate a populated pre-42 DB: run all migrations, seed an alias row
    // at a pre-refuted trust level, revert the migration 42 marker, then
    // re-run init_pool. The rebuilt table must preserve the existing row and
    // accept a subsequent 'refuted' write.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-42-widen.db");
    let entity_id;
    {
        let pool = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO graph_entities
                (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
             VALUES ('host', 'pre42-host', 'pre42-host', 'log', 'fixture', 'verified')",
            [],
        )
        .unwrap();
        entity_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO graph_entity_aliases
                (entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
             VALUES (?1, 'hostname', 'pre42-host', 'pre42-host', 'log', 'claimed')",
            rusqlite::params![entity_id],
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 42", [])
            .unwrap();
    }

    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let conn = pool.get().unwrap();

    let preserved: String = conn
        .query_row(
            "SELECT trust_level FROM graph_entity_aliases WHERE entity_id = ?1",
            rusqlite::params![entity_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, "claimed");

    conn.execute(
        "INSERT INTO graph_entity_aliases
            (entity_id, alias_type, alias_key, alias_value, source_kind, trust_level)
         VALUES (?1, 'service_name', 'pre42-host-refuted', 'pre42-host-refuted', 'log', 'refuted')",
        rusqlite::params![entity_id],
    )
    .unwrap();
}

#[test]
fn init_pool_creates_agent_observatory_run_events_schema() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-events.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    // RED: table does not exist yet
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_run_events)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        columns,
        vec![
            "id",
            "event_key",
            "run_id",
            "actor_id",
            "worktree_id",
            "commit_id",
            "observed_at",
            "ingested_at",
            "event_kind",
            "source_kind",
            "source_id",
            "source_log_id",
            "provider_sequence",
            "trace_id",
            "span_id",
            "severity",
            "title",
            "summary",
            "payload_json",
            "content_scrubbed",
            "created_at",
        ]
    );

    // Insert a test run first for foreign key constraint
    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('run-events-test', 'session-events', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T02:40:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    // Test unique event key constraint
    conn.execute(
        "INSERT INTO agent_run_events
            (event_key, run_id, observed_at, ingested_at, event_kind,
             source_kind, source_id, payload_json)
         VALUES ('evt-1', ?1, ?2, ?2, 'lifecycle', 'test', 'src-1', '{}')",
        rusqlite::params![run_id, "2026-08-01T02:40:01.000Z"],
    )
    .unwrap();

    assert!(
        conn.execute(
            "INSERT INTO agent_run_events
                (event_key, run_id, observed_at, ingested_at, event_kind,
                 source_kind, source_id, payload_json)
             VALUES ('evt-1', ?1, ?2, ?2, 'command', 'test', 'src-2', '{}')",
            rusqlite::params![run_id, "2026-08-01T02:40:02.000Z"],
        )
        .is_err(),
        "duplicate event key must be rejected"
    );

    // Test invalid event kind rejection
    assert!(
        conn.execute(
            "INSERT INTO agent_run_events
                (event_key, run_id, observed_at, ingested_at, event_kind,
                 source_kind, source_id, payload_json)
             VALUES ('evt-2', ?1, ?2, ?2, 'invalid_kind', 'test', 'src-3', '{}')",
            rusqlite::params![run_id, "2026-08-01T02:40:03.000Z"],
        )
        .is_err(),
        "invalid event kind must be rejected"
    );

    // Test JSON validation on payload
    assert!(
        conn.execute(
            "INSERT INTO agent_run_events
                (event_key, run_id, observed_at, ingested_at, event_kind,
                 source_kind, source_id, payload_json)
             VALUES ('evt-3', ?1, ?2, ?2, 'command', 'test', 'src-4', '{invalid')",
            rusqlite::params![run_id, "2026-08-01T02:40:04.000Z"],
        )
        .is_err(),
        "invalid payload JSON must be rejected"
    );

    // Test 1000-event fixture for query plan and ordering
    let mut events = Vec::new();
    for i in 0..1000 {
        let event_key = format!("evt-batch-{}", i);
        events.push((event_key, run_id));
    }

    for (event_key, run_id) in &events {
        conn.execute(
            "INSERT INTO agent_run_events
                (event_key, run_id, observed_at, ingested_at, event_kind,
                 source_kind, source_id, payload_json)
             VALUES (?1, ?2, datetime('now'), datetime('now'), 'command', 'test', ?3, '{}')",
            rusqlite::params![event_key, run_id, format!("src-{}", event_key)],
        )
        .unwrap();
    }

    // Verify query uses index and returns stable ordering
    let query_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
                  SELECT id, observed_at FROM agent_run_events
                  WHERE run_id = ?1
                  ORDER BY observed_at DESC, id DESC
                  LIMIT 10",
        )
        .unwrap()
        .query_map(rusqlite::params![run_id], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert!(
        query_plan
            .iter()
            .any(|detail| detail.contains("idx_agent_run_events_run_order")),
        "query plan should use idx_agent_run_events_run_order index"
    );

    // Verify stable ordering
    let mut prev_observed_at: Option<String> = None;
    let mut prev_id: Option<i64> = None;

    let results: Vec<(i64, String)> = conn
        .prepare(
            "SELECT id, observed_at FROM agent_run_events
                  WHERE run_id = ?1
                  ORDER BY observed_at DESC, id DESC
                  LIMIT 100",
        )
        .unwrap()
        .query_map(rusqlite::params![run_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    for (id, observed_at) in results {
        if let (Some(prev_id), Some(prev_observed)) = (prev_id, prev_observed_at) {
            assert!(
                observed_at <= prev_observed || (observed_at == prev_observed && id < prev_id),
                "results should be ordered by observed_at DESC, id DESC"
            );
        }
        prev_observed_at = Some(observed_at);
        prev_id = Some(id);
    }

    // Verify indexes exist (excluding autoindexes created by UNIQUE constraints)
    let indexes: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'agent_run_events' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        indexes,
        vec![
            "idx_agent_run_events_run_kind",
            "idx_agent_run_events_run_order",
            "idx_agent_run_events_source_log",
            "idx_agent_run_events_trace",
        ]
    );
}

#[test]
fn init_pool_creates_agent_stream_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-outbox.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    // RED: table does not exist yet
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_stream_outbox)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        columns,
        vec![
            "id",
            "outbox_key",
            "run_id",
            "stream_event_type",
            "expires_at",
            "payload_json",
            "created_at",
        ]
    );

    // Insert test data for foreign key constraint
    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('run-outbox-test', 'session-outbox', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T03:00:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    // Test unique outbox_key constraint
    conn.execute(
        "INSERT INTO agent_stream_outbox
            (outbox_key, run_id, stream_event_type, expires_at, payload_json)
         VALUES ('outbox-1', ?1, 'lifecycle', ?2, '{}')",
        rusqlite::params![run_id, "2026-08-01T03:01:00.000Z"],
    )
    .unwrap();

    assert!(
        conn.execute(
            "INSERT INTO agent_stream_outbox
                (outbox_key, run_id, stream_event_type, expires_at, payload_json)
             VALUES ('outbox-1', ?1, 'command', ?2, '{}')",
            rusqlite::params![run_id, "2026-08-01T03:02:00.000Z"],
        )
        .is_err(),
        "duplicate outbox key must be rejected"
    );

    // Test JSON validation on payload
    assert!(
        conn.execute(
            "INSERT INTO agent_stream_outbox
                (outbox_key, run_id, stream_event_type, expires_at, payload_json)
             VALUES ('outbox-2', ?1, 'command', ?2, '{invalid')",
            rusqlite::params![run_id, "2026-08-01T03:03:00.000Z"],
        )
        .is_err(),
        "invalid payload JSON must be rejected"
    );

    // Test cascade delete: when run is deleted, outbox rows are removed
    conn.execute(
        "INSERT INTO agent_stream_outbox
            (outbox_key, run_id, stream_event_type, expires_at, payload_json)
         VALUES ('outbox-3', ?1, 'skill', ?2, '{}')",
        rusqlite::params![run_id, "2026-08-01T03:04:00.000Z"],
    )
    .unwrap();

    let outbox_count_before: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_stream_outbox WHERE run_id = ?1",
            rusqlite::params![run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        outbox_count_before, 2,
        "should have 2 outbox rows (one duplicate failed)"
    );

    // Delete the run
    conn.execute(
        "DELETE FROM agent_runs WHERE id = ?1",
        rusqlite::params![run_id],
    )
    .unwrap();

    let outbox_count_after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_stream_outbox WHERE run_id = ?1",
            rusqlite::params![run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        outbox_count_after, 0,
        "all outbox rows should be cascade deleted"
    );

    // Verify query uses index and returns ascending order
    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('run-outbox-query', 'session-outbox-query', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T03:05:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    // Insert 100 outbox events
    for i in 0..100 {
        let outbox_key = format!("outbox-query-{}", i);
        conn.execute(
            "INSERT INTO agent_stream_outbox
                (outbox_key, run_id, stream_event_type, expires_at, payload_json)
             VALUES (?1, ?2, 'command', datetime('now', '+1 hour'), '{}')",
            rusqlite::params![outbox_key, run_id],
        )
        .unwrap();
    }

    let query_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
                  SELECT id FROM agent_stream_outbox
                  WHERE run_id = ?1
                  ORDER BY id ASC
                  LIMIT 10",
        )
        .unwrap()
        .query_map(rusqlite::params![run_id], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert!(
        query_plan
            .iter()
            .any(|detail| detail.contains("idx_agent_stream_outbox_run")),
        "query plan should use idx_agent_stream_outbox_run index"
    );

    // Verify indexes exist
    let indexes: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'agent_stream_outbox' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        indexes,
        vec![
            "idx_agent_stream_outbox_expiry",
            "idx_agent_stream_outbox_run",
        ]
    );
}

#[test]
fn init_pool_creates_agent_run_commits_and_projection_cursors() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("observatory-commits.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    // RED: tables do not exist yet
    let commit_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_run_commits)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        commit_columns,
        vec![
            "id",
            "relation_key",
            "run_id",
            "commit_id",
            "worktree_id",
            "evidence_kind",
            "evidence_source",
            "trust_level",
            "confidence",
            "first_seen_at",
            "last_seen_at",
            "metadata_json",
        ]
    );

    let cursor_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(agent_projection_cursors)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        cursor_columns,
        vec![
            "id",
            "cursor_type",
            "source_name",
            "cursor_value",
            "updated_at",
        ]
    );

    // Insert test data for foreign key constraints
    conn.execute(
        "INSERT INTO repositories (repository_key, hostname, common_git_dir, primary_path, display_name, first_seen_at, last_seen_at)
         VALUES ('repo-test', 'devhost', '/tmp/repo', '/tmp/repo', 'Test Repo', ?1, ?2)",
        ["2026-08-01T02:50:00.000Z", "2026-08-01T02:50:00.000Z"],
    )
    .unwrap();
    let repo_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO repository_worktrees
            (worktree_key, repository_id, hostname, path, git_dir, first_seen_at, last_seen_at)
         VALUES ('wt-main', ?1, 'devhost', '/tmp/repo', '/tmp/repo/.git', ?2, ?2)",
        rusqlite::params![repo_id, "2026-08-01T02:50:01.000Z"],
    )
    .unwrap();
    let worktree_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO git_commits
            (repository_id, sha, parent_shas_json, subject, author_name,
             first_observed_at, last_observed_at)
         VALUES (?1, 'abc123', '[]', 'Test commit', 'Test Author', ?2, ?2)",
        rusqlite::params![repo_id, "2026-08-01T02:50:02.000Z"],
    )
    .unwrap();
    let commit_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('run-commits-test', 'session-commits', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T02:50:03.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    // Test unique relation_key constraint
    conn.execute(
        "INSERT INTO agent_run_commits
            (relation_key, run_id, commit_id, worktree_id, evidence_kind,
             evidence_source, trust_level, confidence, first_seen_at, last_seen_at)
         VALUES ('rel-1', ?1, ?2, ?3, 'git_head', 'git', 'verified', 0.95, ?4, ?4)",
        rusqlite::params![run_id, commit_id, worktree_id, "2026-08-01T02:50:04.000Z"],
    )
    .unwrap();

    assert!(
        conn.execute(
            "INSERT INTO agent_run_commits
                (relation_key, run_id, commit_id, worktree_id, evidence_kind,
                 evidence_source, trust_level, confidence, first_seen_at, last_seen_at)
             VALUES ('rel-1', ?1, ?2, ?3, 'git_status', 'git', 'claimed', 0.5, ?4, ?4)",
            rusqlite::params![run_id, commit_id, worktree_id, "2026-08-01T02:50:05.000Z"],
        )
        .is_err(),
        "duplicate relation key must be rejected"
    );

    // Test trust level constraint
    assert!(
        conn.execute(
            "INSERT INTO agent_run_commits
                (relation_key, run_id, commit_id, worktree_id, evidence_kind,
                 evidence_source, trust_level, confidence, first_seen_at, last_seen_at)
             VALUES ('rel-2', ?1, ?2, ?3, 'git_head', 'git', 'invalid_trust', 0.9, ?4, ?4)",
            rusqlite::params![run_id, commit_id, worktree_id, "2026-08-01T02:50:06.000Z"],
        )
        .is_err(),
        "invalid trust level must be rejected"
    );

    // Test confidence range constraint
    assert!(
        conn.execute(
            "INSERT INTO agent_run_commits
                (relation_key, run_id, commit_id, worktree_id, evidence_kind,
                 evidence_source, trust_level, confidence, first_seen_at, last_seen_at)
             VALUES ('rel-3', ?1, ?2, ?3, 'git_head', 'git', 'verified', 1.5, ?4, ?4)",
            rusqlite::params![run_id, commit_id, worktree_id, "2026-08-01T02:50:07.000Z"],
        )
        .is_err(),
        "confidence > 1.0 must be rejected"
    );

    // Verify seeded projection cursors (exactly 8 rows)
    let cursor_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM agent_projection_cursors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        cursor_count, 8,
        "should have exactly 8 seeded projection cursors"
    );

    // Verify cursor types are correct
    let cursor_types: Vec<String> = conn
        .prepare("SELECT DISTINCT cursor_type FROM agent_projection_cursors ORDER BY cursor_type")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        cursor_types,
        vec![
            "agent_run_events",
            "agent_runs",
            "git_commits",
            "otel_metric_points",
            "otel_spans",
            "repositories",
            "repository_observations",
            "repository_worktrees",
        ]
    );

    // Verify INSERT OR IGNORE preserves existing cursors on repeated open
    drop(conn);
    drop(pool);

    let pool2 = init_pool(&config).unwrap();
    let conn2 = pool2.get().unwrap();

    let cursor_count2: i64 = conn2
        .query_row("SELECT COUNT(*) FROM agent_projection_cursors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        cursor_count2, 8,
        "should still have exactly 8 cursors after reopen"
    );

    // Verify we can advance a cursor
    conn2
        .execute(
            "UPDATE agent_projection_cursors
                SET cursor_value = 'advanced-123', updated_at = '2026-08-01T03:00:00.000Z'
              WHERE cursor_type = 'agent_runs' AND source_name = 'default'",
            [],
        )
        .unwrap();

    // Reopen again and verify the advanced cursor is preserved
    drop(conn2);
    drop(pool2);

    let pool3 = init_pool(&config).unwrap();
    let conn3 = pool3.get().unwrap();

    let advanced_value: String = conn3
        .query_row(
            "SELECT cursor_value FROM agent_projection_cursors
              WHERE cursor_type = 'agent_runs' AND source_name = 'default'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        advanced_value, "advanced-123",
        "advanced cursor should be preserved"
    );

    // Verify indexes exist
    let commit_indexes: Vec<String> = conn3
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'agent_run_commits' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        commit_indexes,
        vec!["idx_agent_run_commits_commit", "idx_agent_run_commits_run",]
    );

    let cursor_indexes: Vec<String> = conn3
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'agent_projection_cursors' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(cursor_indexes, vec!["idx_agent_projection_cursors_type"]);
}

#[test]
fn migration_45_completes_transactionally_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-45.db");

    // Manually create a schema-44 database by stopping before migration 45
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    // Apply the base schema
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS logs (
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

         CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
             message,
             content='logs',
             content_rowid='id',
             tokenize='porter unicode61'
         );

         CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
             INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
         END;

         CREATE TABLE IF NOT EXISTS hosts (
             hostname    TEXT PRIMARY KEY,
             first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             log_count   INTEGER NOT NULL DEFAULT 0
         );

         CREATE TABLE IF NOT EXISTS schema_migrations (
             version     INTEGER PRIMARY KEY,
             applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         );",
    )
    .unwrap();

    // Manually insert migration 44 marker (simulating migration 44 was applied)
    conn.execute("INSERT INTO schema_migrations (version) VALUES (44)", [])
        .unwrap();

    // Apply migration 44 tables manually
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS repositories (
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
             metadata_json       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(repository_id, path),
             UNIQUE(repository_id, hostname, git_dir)
         );
         CREATE INDEX IF NOT EXISTS idx_repository_worktrees_repo
             ON repository_worktrees(repository_id, last_seen_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_repository_worktrees_host
             ON repository_worktrees(hostname, path);

         CREATE TABLE IF NOT EXISTS repository_observations (
             id                  INTEGER PRIMARY KEY AUTOINCREMENT,
             observation_key    TEXT NOT NULL UNIQUE,
             repository_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
             worktree_id         INTEGER REFERENCES repository_worktrees(id) ON DELETE SET NULL,
             observed_at         TEXT NOT NULL,
             observed_from       TEXT NOT NULL,
             payload_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
             created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         );
         CREATE INDEX IF NOT EXISTS idx_repository_observations_repo_time
             ON repository_observations(repository_id, observed_at DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_repository_observations_worktree_time
             ON repository_observations(worktree_id, observed_at DESC, id DESC);

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
             ON agent_run_worktrees(worktree_id, last_seen_at DESC, run_id);",
    )
    .unwrap();

    drop(conn);

    // Now reopen the database - migration 45 should apply transactionally
    let pool_45 = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
    let conn_45 = pool_45.get().unwrap();

    // Verify all later migrations are applied automatically.
    let schema_version_final: i64 = conn_45
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        schema_version_final, KNOWN_SCHEMA_VERSION,
        "should upgrade from schema 44 to the current schema"
    );

    // Verify all migration 45 tables now exist
    let tables_45: Vec<String> = conn_45
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'agent_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        tables_45,
        vec![
            "agent_projection_cursors",
            "agent_run_actors",
            "agent_run_commits",
            "agent_run_events",
            "agent_run_trace_relations",
            "agent_run_worktrees",
            "agent_runs",
            "agent_stream_outbox",
        ],
        "should have all migration 45 agent tables"
    );

    // Verify seeded cursors exist
    let cursor_count: i64 = conn_45
        .query_row("SELECT COUNT(*) FROM agent_projection_cursors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(cursor_count, 8, "should have 8 seeded cursors");

    drop(conn_45);
    drop(pool_45);

    // Verify idempotency: reopening should keep the latest schema and not reapply migrations
    let pool_again = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
    let conn_again = pool_again.get().unwrap();

    let schema_version_again: i64 = conn_again
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        schema_version_again, KNOWN_SCHEMA_VERSION,
        "should remain at the current schema after reopen"
    );

    let cursor_count_again: i64 = conn_again
        .query_row("SELECT COUNT(*) FROM agent_projection_cursors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        cursor_count_again, 8,
        "should still have 8 cursors (not duplicated)"
    );

    // Verify migration 45 marker exists only once
    let migration_45_count: i64 = conn_again
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 45",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        migration_45_count, 1,
        "should have exactly one migration 45 marker"
    );

    // Verify foreign key checks pass
    let fk_check: String = conn_again
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .unwrap_or("ok".to_string());
    assert_eq!(fk_check, "ok", "foreign key checks should pass");

    // Verify integrity checks pass
    let integrity_result: String = conn_again
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity_result, "ok", "integrity checks should pass");
}

#[test]
fn migration_45_fresh_database_applies_transactionally() {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::for_test(dir.path().join("migration-45-fresh.db"));
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    // Fresh database should be at schema 45
    let schema_version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        schema_version, KNOWN_SCHEMA_VERSION,
        "fresh database should be current"
    );

    // Verify all migration 45 tables still exist (additive migrations preserve them)
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'agent_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    assert_eq!(
        tables,
        vec![
            "agent_projection_cursors",
            "agent_run_actors",
            "agent_run_commits",
            "agent_run_events",
            "agent_run_trace_relations",
            "agent_run_worktrees",
            "agent_runs",
            "agent_stream_outbox",
        ],
        "migration 47 should preserve all migration 45 tables"
    );
}

// AO-014: migration 46 OTLP span table contract.
#[test]
fn migration_46_creates_otel_spans_table_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-46-otel-spans.db");
    let config = StorageConfig::for_test(db_path.clone());
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(otel_spans)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "trace_id",
            "span_id",
            "parent_span_id",
            "trace_state",
            "flags",
            "span_name",
            "span_kind",
            "start_time_unix_nano",
            "end_time_unix_nano",
            "duration_nano",
            "status_code",
            "status_message",
            "hostname",
            "service_name",
            "service_version",
            "scope_name",
            "scope_version",
            "ai_tool",
            "ai_project",
            "ai_session_id",
            "run_id",
            "resource_json",
            "attributes_json",
            "events_json",
            "links_json",
            "received_at",
            "content_scrubbed",
        ]
    );

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND tbl_name = 'otel_spans'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for expected in [
        "idx_otel_spans_run_time",
        "idx_otel_spans_service_time",
        "idx_otel_spans_session_time",
        "idx_otel_spans_trace",
    ] {
        assert!(
            indexes.iter().any(|name| name == expected),
            "missing {expected}: {indexes:?}"
        );
    }

    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('span-run', 'span-session', 'claude', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T03:00:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    let insert_span = |span_id: &str, start: i64| {
        conn.execute(
            "INSERT INTO otel_spans
                (trace_id, span_id, parent_span_id, span_name, span_kind,
                 start_time_unix_nano, end_time_unix_nano, duration_nano,
                 hostname, service_name, ai_tool, ai_session_id, run_id,
                 resource_json, attributes_json, events_json, links_json,
                 received_at, content_scrubbed)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, 100,
                     'devhost', 'cortex', 'claude', 'span-session', ?7,
                     '{}', '{\"worktree\":\"cortex\"}', '[]', '[]', ?8, 1)",
            rusqlite::params![
                "0123456789abcdef0123456789abcdef",
                span_id,
                "1111111111111111",
                format!("span-{span_id}"),
                start,
                start + 100,
                run_id,
                "2026-08-01T03:00:00.000Z",
            ],
        )
    };
    insert_span("2222222222222222", 100).unwrap();
    insert_span("3333333333333333", 200).unwrap();

    assert!(
        insert_span("2222222222222222", 300).is_err(),
        "trace/span identity must deduplicate"
    );
    for (label, sql) in [
        (
            "trace length",
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, received_at)
             VALUES ('short', '4444444444444444', 'bad-trace', 1, 1, 2, 1, 'now')",
        ),
        (
            "span length",
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, received_at)
             VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'short', 'bad-span', 1, 1, 2, 1, 'now')",
        ),
        (
            "parent length",
            "INSERT INTO otel_spans
                (trace_id, span_id, parent_span_id, span_name, span_kind,
                 start_time_unix_nano, end_time_unix_nano, duration_nano, received_at)
             VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '5555555555555555', 'short',
                     'bad-parent', 1, 1, 2, 1, 'now')",
        ),
        (
            "negative duration",
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, received_at)
             VALUES ('cccccccccccccccccccccccccccccccc', '6666666666666666',
                     'bad-duration', 1, 2, 1, -1, 'now')",
        ),
        (
            "invalid JSON",
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, resource_json, received_at)
             VALUES ('dddddddddddddddddddddddddddddddd', '7777777777777777',
                     'bad-json', 1, 1, 2, 1, '{', 'now')",
        ),
        (
            "scrub flag",
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, received_at, content_scrubbed)
             VALUES ('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', '8888888888888888',
                     'bad-scrub', 1, 1, 2, 1, 'now', 2)",
        ),
    ] {
        assert!(conn.execute(sql, []).is_err(), "{label} must be rejected");
    }

    let ordered: Vec<String> = conn
        .prepare(
            "SELECT span_id FROM otel_spans
             WHERE run_id = ?1
             ORDER BY start_time_unix_nano DESC, id DESC",
        )
        .unwrap()
        .query_map([run_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ordered, vec!["3333333333333333", "2222222222222222"]);

    let run_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM otel_spans
             WHERE run_id = ?1
             ORDER BY start_time_unix_nano DESC, id DESC LIMIT 10",
        )
        .unwrap()
        .query_map([run_id], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        run_plan
            .iter()
            .any(|detail| detail.contains("idx_otel_spans_run_time")),
        "run timeline query must use its index: {run_plan:?}"
    );

    let trace_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT span_id FROM otel_spans
             WHERE trace_id = ?1
             ORDER BY start_time_unix_nano, span_id",
        )
        .unwrap()
        .query_map(["0123456789abcdef0123456789abcdef"], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        trace_plan
            .iter()
            .any(|detail| detail.contains("idx_otel_spans_trace")),
        "trace query must use its index: {trace_plan:?}"
    );

    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 46",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1);

    conn.execute("DELETE FROM agent_runs WHERE id = ?1", [run_id])
        .unwrap();
    let null_run_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM otel_spans WHERE run_id IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(null_run_count, 2, "run deletion must preserve spans");

    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert_eq!(foreign_key_violation, None);
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");

    drop(conn);
    drop(pool);
    let reopened = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let reopened_conn = reopened.get().unwrap();
    let marker_count: i64 = reopened_conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 46",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1, "migration 46 must be idempotent");
}

#[test]
fn migration_48_preserves_legacy_projector_cursors_and_adds_llm_index() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-48.db");
    let pool = init_pool(&StorageConfig::for_test(db_path.clone())).unwrap();
    let conn = pool.get().unwrap();

    for (name, cursor) in [
        ("mcp", "101"),
        ("hook", "102"),
        ("skill", "103"),
        (
            "llm",
            r#"{"started_at":"2026-08-05T12:00:00.000Z","id":"llm-old"}"#,
        ),
    ] {
        conn.execute(
            "INSERT INTO agent_projection_cursors (cursor_type, source_name, cursor_value)
             VALUES ('source', ?1, ?2)",
            rusqlite::params![name, cursor],
        )
        .unwrap();
    }
    conn.execute("DELETE FROM schema_migrations WHERE version = 48", [])
        .unwrap();
    drop(conn);
    drop(pool);

    let reopened = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let conn = reopened.get().unwrap();
    for (name, expected) in [
        ("mcp_events", "101"),
        ("hook_events", "102"),
        ("skill_events", "103"),
        (
            "llm_invocations",
            r#"{"started_at":"2026-08-05T12:00:00.000Z","id":"llm-old"}"#,
        ),
    ] {
        let cursor: String = conn
            .query_row(
                "SELECT cursor_value FROM agent_projection_cursors
                 WHERE cursor_type = 'source' AND source_name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, expected);
    }
    let legacy_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_projection_cursors
             WHERE cursor_type = 'source' AND source_name IN ('mcp', 'hook', 'skill', 'llm')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy_count, 0);

    let llm_index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'idx_llm_invocations_finished_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(llm_index, 1);
    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 48",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1);
}

// AO-015: migration 47 OTLP metric-point table contract.
#[test]
fn migration_47_creates_otel_metric_points_table_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("migration-47-otel-metrics.db");
    let config = StorageConfig::for_test(db_path.clone());
    let pool = init_pool(&config).unwrap();
    let conn = pool.get().unwrap();

    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(otel_metric_points)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "point_key",
            "metric_name",
            "description",
            "unit",
            "instrument_kind",
            "aggregation_temporality",
            "monotonic",
            "start_time_unix_nano",
            "time_unix_nano",
            "hostname",
            "service_name",
            "service_version",
            "scope_name",
            "scope_version",
            "ai_tool",
            "ai_project",
            "ai_session_id",
            "run_id",
            "resource_json",
            "attributes_json",
            "value_json",
            "exemplars_json",
            "received_at",
            "content_scrubbed",
        ]
    );

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND tbl_name = 'otel_metric_points'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for expected in [
        "idx_otel_metric_points_name_time",
        "idx_otel_metric_points_run_time",
        "idx_otel_metric_points_session_time",
    ] {
        assert!(
            indexes.iter().any(|name| name == expected),
            "missing {expected}: {indexes:?}"
        );
    }

    conn.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, hostname, status,
             status_observed_at, started_at, last_activity_at)
         VALUES ('metric-run', 'metric-session', 'codex', 'devhost',
                 'active', ?1, ?1, ?1)",
        ["2026-08-01T03:30:00.000Z"],
    )
    .unwrap();
    let run_id = conn.last_insert_rowid();

    let insert_point = |point_key: &str, metric_name: &str, kind: &str, time: i64| {
        conn.execute(
            "INSERT INTO otel_metric_points
                (point_key, metric_name, description, unit, instrument_kind,
                 aggregation_temporality, monotonic, start_time_unix_nano,
                 time_unix_nano, hostname, service_name, ai_tool,
                 ai_session_id, run_id, resource_json, attributes_json,
                 value_json, exemplars_json, received_at, content_scrubbed)
             VALUES (?1, ?2, 'fixture', 'ms', ?3, 2, 0, ?4, ?5,
                     'devhost', 'cortex', 'codex', 'metric-session', ?6,
                     '{}', '{}', ?7, '[]', ?8, 1)",
            rusqlite::params![
                point_key,
                metric_name,
                kind,
                time - 10,
                time,
                run_id,
                "{\"value\":42.0}",
                "2026-08-01T03:30:00.000Z",
            ],
        )
    };
    insert_point("point-1", "agent.latency", "gauge", 100).unwrap();
    insert_point("point-2", "agent.latency", "histogram", 200).unwrap();

    assert!(
        insert_point("point-1", "agent.latency", "gauge", 300).is_err(),
        "point_key must deduplicate"
    );
    assert!(
        insert_point("bad-kind", "agent.latency", "invalid_kind", 300).is_err(),
        "unknown instrument kind must be rejected"
    );

    for (label, sql, params) in [
        (
            "resource JSON",
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, time_unix_nano,
                 resource_json, value_json, received_at)
             VALUES (?1, 'agent.bad', 'gauge', 300, ?2, '{}', 'now')",
            ("bad-resource", "{"),
        ),
        (
            "value JSON",
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, time_unix_nano,
                 value_json, received_at)
             VALUES (?1, 'agent.bad', 'sum', 301, ?2, 'now')",
            ("bad-value", "{"),
        ),
        (
            "exemplars JSON",
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, time_unix_nano,
                 value_json, exemplars_json, received_at)
             VALUES (?1, 'agent.bad', 'summary', 302, '{}', ?2, 'now')",
            ("bad-exemplars", "{"),
        ),
    ] {
        assert!(
            conn.execute(sql, rusqlite::params![params.0, params.1])
                .is_err(),
            "{label} must be rejected"
        );
    }

    assert!(
        conn.execute(
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, monotonic,
                 time_unix_nano, value_json, received_at)
             VALUES ('bad-monotonic', 'agent.bad', 'sum', 2, 303, '{}', 'now')",
            [],
        )
        .is_err(),
        "monotonic must be null, zero, or one"
    );
    assert!(
        conn.execute(
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, time_unix_nano,
                 value_json, received_at, content_scrubbed)
             VALUES ('bad-scrub', 'agent.bad', 'gauge', 304, '{}', 'now', 2)",
            [],
        )
        .is_err(),
        "content_scrubbed must be zero or one"
    );

    let ordered: Vec<String> = conn
        .prepare(
            "SELECT point_key FROM otel_metric_points
             WHERE run_id = ?1
             ORDER BY time_unix_nano DESC, id DESC",
        )
        .unwrap()
        .query_map([run_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ordered, vec!["point-2", "point-1"]);

    let run_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM otel_metric_points
             WHERE run_id = ?1
             ORDER BY time_unix_nano DESC, id DESC LIMIT 10",
        )
        .unwrap()
        .query_map([run_id], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        run_plan
            .iter()
            .any(|detail| detail.contains("idx_otel_metric_points_run_time")),
        "run metric query must use its index: {run_plan:?}"
    );

    let name_plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM otel_metric_points
             WHERE metric_name = ?1
             ORDER BY time_unix_nano DESC, id DESC LIMIT 10",
        )
        .unwrap()
        .query_map(["agent.latency"], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        name_plan
            .iter()
            .any(|detail| detail.contains("idx_otel_metric_points_name_time")),
        "metric-name query must use its index: {name_plan:?}"
    );

    let marker_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 47",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1);

    conn.execute("DELETE FROM agent_runs WHERE id = ?1", [run_id])
        .unwrap();
    let null_run_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM otel_metric_points WHERE run_id IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        null_run_count, 2,
        "run deletion must preserve metric points"
    );

    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert_eq!(foreign_key_violation, None);
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");

    drop(conn);
    drop(pool);
    let reopened = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let reopened_conn = reopened.get().unwrap();
    let marker_count: i64 = reopened_conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 47",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1, "migration 47 must be idempotent");
}
