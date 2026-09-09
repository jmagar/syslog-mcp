use rusqlite::params;
use std::collections::HashSet;

use super::*;
use crate::config::StorageConfig;
use crate::db::init_pool;

fn test_pool() -> (DbPool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    (pool, dir)
}

#[test]
fn ensure_source_reuses_existing_source_id() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);

    let first = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();
    let second = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    assert_eq!(first, second);

    // Migration 51 gives legacy-style source rows a completed state until a
    // bounded scanner explicitly records a resumable checkpoint.
    assert_eq!(
        store.source_metadata(first).unwrap().unwrap(),
        SourceMetadata {
            file_size: None,
            file_mtime: None,
            content_hash: None,
            last_offset: Some(0),
            last_error: None,
            source_revision: None,
            scan_state: SourceScanState::Complete,
        }
    );
}

#[test]
fn ensure_source_updates_source_kind_for_existing_path() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);

    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();
    assert_eq!(
        store
            .ensure_source("/tmp/session.jsonl", "codex_session")
            .unwrap(),
        source_id
    );

    let source_kind: String = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT source_kind FROM transcript_sources WHERE id = ?1",
            [source_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source_kind, "codex_session");
}

#[test]
fn parse_error_without_preview_is_deduplicated() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    store
        .record_parse_error(source_id, 7, "record too large", None)
        .unwrap();
    store
        .record_parse_error(source_id, 7, "record too large", None)
        .unwrap();

    let count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM transcript_parse_errors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn doctor_counts_all_missing_checkpoints_beyond_display_limit() {
    let (pool, dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let missing_dir = dir.path().join("missing");
    for index in 0..75 {
        store
            .ensure_source(
                &missing_dir
                    .join(format!("session-{index}.jsonl"))
                    .display()
                    .to_string(),
                "explicit_file",
            )
            .unwrap();
    }

    let report = store.doctor(std::path::Path::new("/tmp/test.db")).unwrap();

    assert_eq!(report.checkpoint_count, 75);
    assert_eq!(report.missing_checkpoint_count, 75);
}

#[test]
fn source_creation_and_parse_errors_do_not_advance_last_indexed_at() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    let initial: Option<String> = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT last_indexed_at FROM transcript_sources WHERE id = ?1",
            [source_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(initial, None);

    store.mark_error(source_id, "bad json").unwrap();
    let after_error: Option<String> = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT last_indexed_at FROM transcript_sources WHERE id = ?1",
            [source_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after_error, None);
}

#[test]
fn record_keys_returns_imported_record_keys() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    {
        let mut conn = pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        let metadata = crate::scanner::FileMetadata {
            size: 42,
            mtime: Some(123),
            content_hash: "abc123".to_string(),
        };
        record_imports_in_tx(
            &tx,
            source_id,
            &["record-1".to_string(), "record-2".to_string()],
            &metadata,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    let conn = pool.get().unwrap();
    let mut stmt = conn
        .prepare("SELECT record_key FROM transcript_import_records WHERE source_id = ?1")
        .unwrap();
    let keys = stmt
        .query_map([source_id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<std::collections::HashSet<_>>>()
        .unwrap();

    assert_eq!(
        keys,
        HashSet::from(["record-1".to_string(), "record-2".to_string()])
    );
}

#[test]
fn mark_error_sets_last_error_and_successful_import_clears_it() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    store.mark_error(source_id, "bad json").unwrap();

    {
        let conn = pool.get().unwrap();
        let last_error: String = conn
            .query_row(
                "SELECT last_error FROM transcript_sources WHERE id = ?1",
                [source_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_error, "bad json");
    }

    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();
    let metadata = crate::scanner::FileMetadata {
        size: 99,
        mtime: Some(456),
        content_hash: "content-hash".to_string(),
    };
    record_imports_in_tx(&tx, source_id, &["record-1".to_string()], &metadata).unwrap();
    tx.commit().unwrap();

    let row = conn
        .query_row(
            "SELECT file_size, file_mtime, content_hash, last_offset, last_error
             FROM transcript_sources WHERE id = ?1",
            [source_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(row, (99, 456, "content-hash".to_string(), 99, None));
}

#[test]
fn partial_checkpoint_persists_full_source_metadata_and_recovery_state() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/bounded-session.jsonl", "codex_session")
        .unwrap();
    store
        .record_parse_error(source_id, 4, "invalid record", None)
        .unwrap();

    let metadata = FileMetadata {
        size: 8_192,
        mtime: Some(1_700_000_000),
        content_hash: "prefix-hash-at-boundary".to_string(),
    };
    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();
    update_partial_source_metadata_in_tx(
        &tx,
        source_id,
        &metadata,
        "revision-1",
        SourceScanState::Boundary,
        4_096,
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);

    assert_eq!(
        store.source_metadata(source_id).unwrap(),
        Some(SourceMetadata {
            file_size: Some(8_192),
            file_mtime: Some(1_700_000_000),
            content_hash: Some("prefix-hash-at-boundary".to_string()),
            last_offset: Some(4_096),
            last_error: None,
            source_revision: Some("revision-1".to_string()),
            scan_state: SourceScanState::Boundary,
        })
    );

    let conn = pool.get().unwrap();
    let parse_errors: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_parse_errors WHERE source_id = ?1",
            [source_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(parse_errors, 1, "partial progress must retain diagnostics");
    drop(conn);
    assert!(
        !store
            .source_matches_metadata(source_id, 8_192, Some(1_700_000_000))
            .unwrap(),
        "a partial checkpoint must never be treated as a completed source"
    );
}

#[test]
fn complete_checkpoint_marks_revision_complete_and_clears_diagnostics() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/completed-session.jsonl", "claude_session")
        .unwrap();
    store
        .record_parse_error(source_id, 2, "invalid record", None)
        .unwrap();

    let metadata = FileMetadata {
        size: 1_024,
        mtime: Some(1_700_000_001),
        content_hash: "full-source-hash".to_string(),
    };
    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();
    update_complete_source_metadata_in_tx(&tx, source_id, &metadata, "revision-2").unwrap();
    tx.commit().unwrap();
    drop(conn);

    let source = store.source_metadata(source_id).unwrap().unwrap();
    assert_eq!(source.file_size, Some(1_024));
    assert_eq!(source.file_mtime, Some(1_700_000_001));
    assert_eq!(source.content_hash.as_deref(), Some("full-source-hash"));
    assert_eq!(source.last_offset, Some(1_024));
    assert_eq!(source.source_revision.as_deref(), Some("revision-2"));
    assert_eq!(source.scan_state, SourceScanState::Complete);
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM transcript_parse_errors WHERE source_id = ?1",
            [source_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
}

#[test]
fn partial_checkpoint_rejects_complete_state() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/invalid-partial-session.jsonl", "codex_session")
        .unwrap();
    let metadata = FileMetadata {
        size: 1,
        mtime: None,
        content_hash: "h".to_string(),
    };
    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();
    let error = update_partial_source_metadata_in_tx(
        &tx,
        source_id,
        &metadata,
        "revision",
        SourceScanState::Complete,
        1,
    )
    .unwrap_err();

    assert!(error.to_string().contains("non-complete scan state"));
}

#[test]
fn indexing_health_reports_schema_drift_and_recent_failures() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();
    store
        .mark_error(source_id, "no such table: transcript_sources")
        .unwrap();
    store
        .record_parse_error(source_id, 1, "no such table: transcript_sources", None)
        .unwrap();

    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE schema_migrations SET applied_at = ?1",
        params!["2025-12-31T23:59:00.000Z"],
    )
    .unwrap();
    conn.execute(
        "UPDATE schema_migrations SET applied_at = ?1 WHERE version = ?2",
        params!["2026-01-01T00:10:00.000Z", crate::db::KNOWN_SCHEMA_VERSION],
    )
    .unwrap();
    conn.execute(
        "UPDATE transcript_parse_errors SET seen_at = ?1 WHERE source_id = ?2",
        params!["9999-01-01T00:00:00.000Z", source_id],
    )
    .unwrap();
    drop(conn);

    let health = store.indexing_health(Some("2026-01-01T00:00:00Z")).unwrap();

    assert!(health.schema_current);
    assert!(health.schema_drift_detected);
    assert_eq!(health.schema_drift_migrations.len(), 1);
    assert_eq!(health.recent_failure_count, 1);
    assert_eq!(health.recent_schema_error_count, 2);
    assert_eq!(health.affected_paths, vec!["/tmp/session.jsonl"]);
    assert!(
        health
            .stale_indicators
            .contains(&"schema_drift".to_string())
    );
    assert!(
        health
            .stale_indicators
            .contains(&"recent_schema_errors".to_string())
    );
}

#[test]
fn record_imports_ignores_duplicate_record_keys() {
    let (pool, _dir) = test_pool();
    let store = CheckpointStore::new(&pool);
    let source_id = store
        .ensure_source("/tmp/session.jsonl", "explicit_file")
        .unwrap();

    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();
    let metadata = crate::scanner::FileMetadata {
        size: 12,
        mtime: None,
        content_hash: "hash".to_string(),
    };
    record_imports_in_tx(
        &tx,
        source_id,
        &["same".to_string(), "same".to_string()],
        &metadata,
    )
    .unwrap();
    tx.commit().unwrap();

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_import_records WHERE source_id = ?1",
            params![source_id],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(count, 1);
}
