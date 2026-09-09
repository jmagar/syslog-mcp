use super::*;
use crate::config::StorageConfig;
use tempfile::TempDir;

fn test_pool() -> (DbPool, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = StorageConfig {
        db_path: dir.path().join("test.db"),
        pool_size: 1,
        wal_mode: false,
        ..Default::default()
    };
    let pool = crate::db::init_pool(&storage).unwrap();
    (pool, dir)
}

fn insert_sig(conn: &rusqlite::Connection, hash: &str, version: i64, last_seen_at: &str) {
    upsert_signature(
        conn,
        UpsertSignatureParams {
            hash,
            normalizer_version: version,
            template: &format!("template {hash}"),
            sample_message: &format!("sample {hash}"),
            sample_hostname: "host1",
            sample_app_name: Some("sshd"),
            severity: "err",
            first_seen_at: "2026-06-13T00:00:00.000Z",
            last_seen_at,
            delta: 1,
        },
    )
    .unwrap();
}

fn recent_timestamp(minutes_ago: i64) -> String {
    chrono::Utc::now()
        .checked_sub_signed(chrono::TimeDelta::minutes(minutes_ago))
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[test]
fn cursor_get_and_advance_round_trip() {
    let (pool, _dir) = test_pool();
    assert_eq!(cursor_get(&pool).unwrap(), 0);

    {
        let conn = pool.get().unwrap();
        cursor_advance(&conn, 42).unwrap();
    }

    assert_eq!(cursor_get(&pool).unwrap(), 42);
    let conn = pool.get().unwrap();
    let completed_at: Option<String> = conn
        .query_row(
            "SELECT last_scan_completed_at FROM error_scan_cursor WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(completed_at.is_some());
}

#[test]
fn insert_window_merges_conflicting_counts_and_keeps_dimensions_separate() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();

    insert_window(
        &conn,
        "deadbeef",
        1,
        "2026-06-13T00:00:00.000Z",
        "2026-06-13T01:00:00.000Z",
        2,
    )
    .unwrap();
    insert_window(
        &conn,
        "deadbeef",
        1,
        "2026-06-13T00:00:00.000Z",
        "2026-06-13T01:00:00.000Z",
        3,
    )
    .unwrap();
    insert_window(
        &conn,
        "deadbeef",
        2,
        "2026-06-13T00:00:00.000Z",
        "2026-06-13T01:00:00.000Z",
        11,
    )
    .unwrap();

    let count_v1: i64 = conn
        .query_row(
            "SELECT count_in_window FROM error_signature_windows
             WHERE signature_hash = 'deadbeef' AND normalizer_version = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let count_v2: i64 = conn
        .query_row(
            "SELECT count_in_window FROM error_signature_windows
             WHERE signature_hash = 'deadbeef' AND normalizer_version = 2",
            [],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(count_v1, 5);
    assert_eq!(count_v2, 11);
}

#[test]
fn recurring_error_comparison_is_bounded_stable_and_marks_boundary_windows() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();
    for hash in ["alpha", "beta", "boundary", "acked"] {
        insert_sig(&conn, hash, 1, "2026-01-01T02:50:00.000Z");
    }
    // alpha and beta intentionally tie on all ranking dimensions. Canonical
    // source hash, not sample/template text, must make the answer stable.
    for hash in ["alpha", "beta"] {
        insert_window(
            &conn,
            hash,
            1,
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T01:00:00.000Z",
            3,
        )
        .unwrap();
        insert_window(
            &conn,
            hash,
            1,
            "2026-01-01T01:00:00.000Z",
            "2026-01-01T02:00:00.000Z",
            10,
        )
        .unwrap();
    }
    // This interval overlaps the focal window but is not wholly contained;
    // it must be disclosed rather than counted as an exact sample.
    insert_window(
        &conn,
        "boundary",
        1,
        "2026-01-01T01:30:00.000Z",
        "2026-01-01T02:30:00.000Z",
        999,
    )
    .unwrap();
    update_ack_projection(
        &conn,
        "acked",
        1,
        Some("2026-01-01T01:00:00.000Z"),
        Some("operator"),
    )
    .unwrap();
    drop(conn);

    let result = compare_recurring_errors(
        &pool,
        RecurringErrorComparisonParams {
            normalizer_version: 1,
            focal_from: "2026-01-01T01:00:00.000Z",
            focal_to: "2026-01-01T02:00:00.000Z",
            baseline_from: "2026-01-01T00:00:00.000Z",
            baseline_to: "2026-01-01T01:00:00.000Z",
            signature_hash: None,
            include_acknowledged: false,
            limit: 50,
        },
    )
    .unwrap();
    assert_eq!(result.candidate_cap, RECURRING_ERROR_CANDIDATE_CAP);
    assert_eq!(
        result
            .rows
            .iter()
            .map(|row| row.signature_hash.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta", "boundary"],
        "equal ranking must use canonical hash as the final tie break"
    );
    assert_eq!(result.rows[0].current_count, 10);
    assert_eq!(result.rows[0].baseline_count, 3);
    assert_eq!(result.rows[2].current_count, 0);
    assert_eq!(result.rows[2].focal_boundary_windows, 1);
    assert!(!result.rows.iter().any(|row| row.signature_hash == "acked"));
}

#[test]
fn recurring_error_comparison_reports_high_cardinality_candidate_truncation() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();
    for index in 0..=RECURRING_ERROR_CANDIDATE_CAP {
        let hash = format!("high-cardinality-{index:04}");
        insert_sig(&conn, &hash, 1, "2026-01-01T01:30:00.000Z");
        insert_window(
            &conn,
            &hash,
            1,
            "2026-01-01T01:00:00.000Z",
            "2026-01-01T02:00:00.000Z",
            1,
        )
        .unwrap();
    }
    drop(conn);

    let result = compare_recurring_errors(
        &pool,
        RecurringErrorComparisonParams {
            normalizer_version: 1,
            focal_from: "2026-01-01T01:00:00.000Z",
            focal_to: "2026-01-01T02:00:00.000Z",
            baseline_from: "2026-01-01T00:00:00.000Z",
            baseline_to: "2026-01-01T01:00:00.000Z",
            signature_hash: None,
            include_acknowledged: false,
            limit: 50,
        },
    )
    .unwrap();
    assert!(result.candidate_window_truncated);
    assert_eq!(result.candidate_rows, RECURRING_ERROR_CANDIDATE_CAP);
    assert_eq!(result.rows.len(), 50);
}

#[test]
fn read_unaddressed_filters_acknowledged_and_sums_recent_windows() {
    let (pool, _dir) = test_pool();
    let newer = recent_timestamp(5);
    let older = recent_timestamp(10);
    let stale = recent_timestamp(120);

    {
        let conn = pool.get().unwrap();
        insert_sig(&conn, "unacked", 1, &newer);
        insert_window(&conn, "unacked", 1, &older, &newer, 4).unwrap();
        insert_window(&conn, "unacked", 1, &stale, &stale, 99).unwrap();

        insert_sig(&conn, "acked", 1, &older);
        insert_window(&conn, "acked", 1, &older, &newer, 7).unwrap();

        // Historical/foreign normalizer versions remain durable for audit, but
        // must not surface in the actionable list because ack/unack only targets
        // the active normalizer version.
        insert_sig(&conn, "other-version", 2, &newer);
        insert_window(&conn, "other-version", 2, &older, &newer, 11).unwrap();
        update_ack_projection(
            &conn,
            "acked",
            1,
            Some("2026-06-13T00:30:00.000Z"),
            Some("admin"),
        )
        .unwrap();
    }

    let unaddressed = read_unaddressed_page(&pool, 1, 10, 0, false).unwrap();
    assert_eq!(unaddressed.len(), 1);
    assert_eq!(unaddressed[0].signature_hash, "unacked");
    assert_eq!(unaddressed[0].count_last_1h, 4);
    assert!(unaddressed[0].acknowledged_at.is_none());

    let with_acknowledged = read_unaddressed_page(&pool, 1, 10, 0, true).unwrap();
    assert_eq!(
        with_acknowledged
            .iter()
            .map(|row| row.signature_hash.as_str())
            .collect::<Vec<_>>(),
        vec!["unacked", "acked"]
    );
    let acked = with_acknowledged
        .iter()
        .find(|row| row.signature_hash == "acked")
        .unwrap();
    assert_eq!(acked.count_last_1h, 7);
    assert!(acked.acknowledged_at.is_some());
}

#[test]
fn read_signature_by_hash_returns_none_for_missing_or_wrong_version() {
    let (pool, _dir) = test_pool();
    let recent = recent_timestamp(5);
    {
        let conn = pool.get().unwrap();
        insert_sig(&conn, "look-me-up", 3, &recent);
        insert_window(&conn, "look-me-up", 3, &recent, &recent, 6).unwrap();
    }

    assert!(
        read_signature_by_hash(&pool, "look-me-up", 2)
            .unwrap()
            .is_none()
    );
    assert!(
        read_signature_by_hash(&pool, "missing", 3)
            .unwrap()
            .is_none()
    );

    let row = read_signature_by_hash(&pool, "look-me-up", 3)
        .unwrap()
        .unwrap();
    assert_eq!(row.signature_hash, "look-me-up");
    assert_eq!(row.count_last_1h, 6);
}

#[test]
fn update_ack_projection_unknown_hash_touches_no_rows() {
    let (pool, _dir) = test_pool();
    {
        let conn = pool.get().unwrap();
        insert_sig(&conn, "real", 1, "2026-06-13T00:00:00.000Z");

        update_ack_projection(
            &conn,
            "forged",
            1,
            Some("2026-06-13T00:30:00.000Z"),
            Some("attacker"),
        )
        .unwrap();

        assert_eq!(conn.changes(), 0);
    }
    assert!(
        read_signature_by_hash(&pool, "forged", 1)
            .unwrap()
            .is_none()
    );
    let real = read_signature_by_hash(&pool, "real", 1).unwrap().unwrap();
    assert!(real.acknowledged_at.is_none());
}

#[test]
fn upsert_idempotency() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();

    // First insert
    upsert_signature(
        &conn,
        UpsertSignatureParams {
            hash: "aabbcc",
            normalizer_version: 1,
            template: "template text",
            sample_message: "sample msg",
            sample_hostname: "host1",
            sample_app_name: Some("sshd"),
            severity: "err",
            first_seen_at: "2024-01-01T00:00:00.000Z",
            last_seen_at: "2024-01-01T00:00:00.000Z",
            delta: 5,
        },
    )
    .unwrap();

    // Second insert (same hash+version) should increment count and update last_seen_at
    upsert_signature(
        &conn,
        UpsertSignatureParams {
            hash: "aabbcc",
            normalizer_version: 1,
            template: "template text",
            sample_message: "sample msg",
            sample_hostname: "host2",
            sample_app_name: Some("sshd"),
            severity: "err",
            first_seen_at: "2024-01-01T00:05:00.000Z",
            last_seen_at: "2024-01-01T00:05:00.000Z",
            delta: 3,
        },
    )
    .unwrap();

    let total: i64 = conn
        .query_row(
            "SELECT total_count FROM error_signatures WHERE signature_hash = 'aabbcc'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(total, 8, "total_count should be 5+3=8");

    // sample_hostname should be the FIRST one (not overwritten)
    let hostname: String = conn
        .query_row(
            "SELECT sample_hostname FROM error_signatures WHERE signature_hash = 'aabbcc'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        hostname, "host1",
        "sample_hostname should not be overwritten on update"
    );
}

#[test]
fn test_ack_event_appends_to_audit_chain() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();

    // First insert a signature to satisfy the ack_events foreign-key-style constraints
    upsert_signature(
        &conn,
        UpsertSignatureParams {
            hash: "deadbeef",
            normalizer_version: 1,
            template: "template",
            sample_message: "sample",
            sample_hostname: "host1",
            sample_app_name: None,
            severity: "err",
            first_seen_at: "2024-01-01T00:00:00.000Z",
            last_seen_at: "2024-01-01T00:00:00.000Z",
            delta: 1,
        },
    )
    .unwrap();

    // Record ack then unack
    record_ack_event(&conn, "deadbeef", 1, "ack", "admin", None).unwrap();
    record_ack_event(&conn, "deadbeef", 1, "unack", "admin", Some("reopening")).unwrap();

    // Both events should be present (audit chain — no row deleted)
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM error_signature_ack_events
             WHERE signature_hash = 'deadbeef'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(count, 2, "audit chain should have 2 events, not 1");

    // Both event types present
    let ack_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM error_signature_ack_events
             WHERE signature_hash = 'deadbeef' AND event_type = 'ack'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    let unack_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM error_signature_ack_events
             WHERE signature_hash = 'deadbeef' AND event_type = 'unack'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(ack_count, 1, "one 'ack' event");
    assert_eq!(unack_count, 1, "one 'unack' event");
}

#[test]
fn test_update_ack_projection_sets_and_clears() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();

    upsert_signature(
        &conn,
        UpsertSignatureParams {
            hash: "cafebabe",
            normalizer_version: 1,
            template: "template",
            sample_message: "sample",
            sample_hostname: "host1",
            sample_app_name: None,
            severity: "err",
            first_seen_at: "2024-01-01T00:00:00.000Z",
            last_seen_at: "2024-01-01T00:00:00.000Z",
            delta: 1,
        },
    )
    .unwrap();

    // Acknowledge: set acknowledged_at and acknowledged_by
    update_ack_projection(
        &conn,
        "cafebabe",
        1,
        Some("2024-06-01T12:00:00.000Z"),
        Some("admin"),
    )
    .unwrap();

    let acked_at: Option<String> = conn
        .query_row(
            "SELECT acknowledged_at FROM error_signatures WHERE signature_hash = 'cafebabe'",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap();
    assert!(
        acked_at.is_some(),
        "acknowledged_at should be set after ack"
    );

    // Unacknowledge: clear both columns
    update_ack_projection(&conn, "cafebabe", 1, None, None).unwrap();

    let acked_at_after: Option<String> = conn
        .query_row(
            "SELECT acknowledged_at FROM error_signatures WHERE signature_hash = 'cafebabe'",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap();
    assert!(
        acked_at_after.is_none(),
        "acknowledged_at should be NULL after unack"
    );
}
