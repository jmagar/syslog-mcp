use super::*;
use crate::config::StorageConfig;
use crate::db::init_pool;
use crate::db::notifications::{AttemptCount, outbox_insert};

fn open_test_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE notifications_outbox (
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
         CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_dedup_pending
             ON notifications_outbox(dedup_key) WHERE status = 'pending';
         CREATE TABLE notification_firings (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             outbox_id INTEGER NOT NULL,
             rule_id TEXT NOT NULL,
             severity TEXT NOT NULL,
             hostname TEXT NOT NULL,
             fired_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
             status_code INTEGER,
             notes TEXT,
             dedup_key TEXT NOT NULL DEFAULT ''
         );
         CREATE TABLE error_signatures (
             signature_hash TEXT NOT NULL,
             normalizer_version INTEGER NOT NULL,
             template TEXT NOT NULL,
             sample_message TEXT NOT NULL,
             sample_hostname TEXT NOT NULL,
             sample_app_name TEXT,
             severity TEXT NOT NULL,
             first_seen_at TEXT NOT NULL,
             last_seen_at TEXT NOT NULL,
             total_count INTEGER NOT NULL DEFAULT 0,
             acknowledged_at TEXT,
             acknowledged_by TEXT,
             PRIMARY KEY (signature_hash, normalizer_version)
         );",
    )
    .unwrap();
    conn
}

#[test]
fn backoff_schedule_is_increasing() {
    let delays: Vec<_> = (0i64..5)
        .map(|i| {
            let s = backoff_next_attempt_at(AttemptCount::from_stored(i));
            chrono::DateTime::parse_from_rfc3339(&s).unwrap()
        })
        .collect();
    for window in delays.windows(2) {
        assert!(
            window[1] >= window[0],
            "backoff should be non-decreasing: {:?} >= {:?}",
            window[1],
            window[0]
        );
    }
}

#[test]
fn severity_to_notify_type_mapping() {
    assert_eq!(severity_to_notify_type("crit"), NotifyType::Failure);
    assert_eq!(severity_to_notify_type("critical"), NotifyType::Failure);
    assert_eq!(severity_to_notify_type("warning"), NotifyType::Warning);
    assert_eq!(severity_to_notify_type("err"), NotifyType::Warning);
    assert_eq!(severity_to_notify_type("notice"), NotifyType::Info);
    assert_eq!(severity_to_notify_type("info"), NotifyType::Info);
}

#[test]
fn only_silence_rules_are_deduplicated_for_the_full_outage() {
    assert!(is_once_per_outage_rule("heartbeat_silence"));
    assert!(is_once_per_outage_rule("stream_silence"));
    assert!(!is_once_per_outage_rule("oom_kill"));
    assert!(!is_once_per_outage_rule("unaddressed_error_signature"));
}

#[test]
fn signature_ack_check_distinguishes_missing_pending_and_acknowledged() {
    let conn = open_test_db();
    let version = crate::app::error_detection::NORMALIZER_VERSION;

    assert!(!is_signature_acked(&conn, "missing", version).unwrap());

    conn.execute(
        "INSERT INTO error_signatures (
             signature_hash, normalizer_version, template, sample_message,
             sample_hostname, severity, first_seen_at, last_seen_at, acknowledged_at
         ) VALUES (?1, ?2, 'template', 'sample', 'host1', 'err',
                   '2026-06-13T00:00:00.000Z', '2026-06-13T00:00:00.000Z', NULL)",
        rusqlite::params!["pending", version],
    )
    .unwrap();
    assert!(!is_signature_acked(&conn, "pending", version).unwrap());

    conn.execute(
        "INSERT INTO error_signatures (
             signature_hash, normalizer_version, template, sample_message,
             sample_hostname, severity, first_seen_at, last_seen_at, acknowledged_at
         ) VALUES (?1, ?2, 'template', 'sample', 'host1', 'err',
                   '2026-06-13T00:00:00.000Z', '2026-06-13T00:00:00.000Z',
                   '2026-06-13T00:01:00.000Z')",
        rusqlite::params!["acked", version],
    )
    .unwrap();
    assert!(is_signature_acked(&conn, "acked", version).unwrap());
    assert!(!is_signature_acked(&conn, "acked", version + 1).unwrap());
}

#[test]
fn outbox_row_dedup_suppressed() {
    let conn = open_test_db();
    // Insert a firing first (simulating a previous delivery)
    let params = crate::db::notifications::OutboxInsertParams {
        dedup_key: "oom_kill:host1:ts".to_string(),
        rule_id: "oom_kill".to_string(),
        severity: "critical".to_string(),
        hostname: "host1".to_string(),
        title: "OOM".to_string(),
        body: "body".to_string(),
        apprise_urls_json: "[]".to_string(),
        next_attempt_at: "2000-01-01T00:00:00.000Z".to_string(),
    };
    outbox_insert(&conn, &params).unwrap();
    let id: i64 = conn
        .query_row("SELECT id FROM notifications_outbox LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    // Insert a firing within the dedup window
    firings_insert(
        &conn,
        FiringInsertParams {
            outbox_id: id,
            rule_id: "oom_kill",
            severity: "critical",
            hostname: "host1",
            status_code: Some(200),
            notes: None,
            dedup_key: "oom_kill:host1:ts",
        },
    )
    .unwrap();

    let is_dedup =
        firings_recent_dedup_check(&conn, "oom_kill", "host1", "oom_kill:host1:ts", 3600).unwrap();
    assert!(
        is_dedup,
        "should detect existing firing within dedup window"
    );
}

#[test]
fn dead_letter_after_max_retries() {
    let conn = open_test_db();
    let params = crate::db::notifications::OutboxInsertParams {
        dedup_key: "test:dl".to_string(),
        rule_id: "oom_kill".to_string(),
        severity: "critical".to_string(),
        hostname: "host1".to_string(),
        title: "Title".to_string(),
        body: "Body".to_string(),
        apprise_urls_json: "[]".to_string(),
        next_attempt_at: "2000-01-01T00:00:00.000Z".to_string(),
    };
    outbox_insert(&conn, &params).unwrap();
    let id: i64 = conn
        .query_row("SELECT id FROM notifications_outbox LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();

    // Simulate 8 failed delivery cycles. Each real cycle claims the row first —
    // and the claim is what consumes the attempt — then records the failure via
    // outbox_schedule_retry, which no longer increments. Resetting
    // next_attempt_at between iterations clears both the claim lease and the
    // backoff so the row is immediately claimable again; the backoff deadline
    // itself is asserted by outbox_schedule_retry_test, not here.
    let max_retries: u8 = 8;
    for attempt in 0u8..max_retries {
        conn.execute(
            "UPDATE notifications_outbox SET next_attempt_at = '2000-01-01T00:00:00.000Z'",
            [],
        )
        .unwrap();
        let claimed = crate::db::notifications::outbox_claim_pending(&conn, 10).unwrap();
        assert_eq!(claimed.len(), 1, "row should be claimable each cycle");
        let next_at = backoff_next_attempt_at(AttemptCount::from_stored(i64::from(attempt)));
        outbox_schedule_retry(&conn, id, &next_at, "timeout", None).unwrap();
    }

    let attempt_count: i64 = conn
        .query_row(
            "SELECT attempt_count FROM notifications_outbox WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap();

    // Exact, not >=: a future change that made BOTH the claim and the
    // write-back increment would still satisfy >=, and that double-count is
    // precisely the hazard of having moved the increment into the claim.
    assert_eq!(
        attempt_count, max_retries as i64,
        "each cycle must consume exactly one attempt (claim increments, write-back must not)"
    );

    // Mark dead
    outbox_mark_dead(&conn, id, None, "exhausted").unwrap();
    let status: String = conn
        .query_row(
            "SELECT status FROM notifications_outbox WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "dead");
}

#[tokio::test]
async fn dispatch_cycle_drops_pending_row_when_no_apprise_urls_exist() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        init_pool(&StorageConfig::for_test(
            dir.path().join("notifications.db"),
        ))
        .unwrap(),
    );
    let conn = pool.get().unwrap();
    outbox_insert(
        &conn,
        &crate::db::notifications::OutboxInsertParams {
            dedup_key: "no-url:test".to_string(),
            rule_id: "oom_kill".to_string(),
            severity: "critical".to_string(),
            hostname: "host1".to_string(),
            title: "Title".to_string(),
            body: "Body".to_string(),
            apprise_urls_json: "[]".to_string(),
            next_attempt_at: "2000-01-01T00:00:00.000Z".to_string(),
        },
    )
    .unwrap();
    drop(conn);

    let dispatched = run_dispatch_cycle(
        Arc::clone(&pool),
        Arc::new(Semaphore::new(1)),
        &AppriseClient::new("http://127.0.0.1:1"),
        &NotificationsConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(dispatched, 0);
    let conn = pool.get().unwrap();
    let (status, error): (String, Option<String>) = conn
        .query_row(
            "SELECT status, last_error FROM notifications_outbox WHERE dedup_key = 'no-url:test'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "dropped");
    assert_eq!(error.as_deref(), Some("no_apprise_urls"));
    let firing_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notification_firings", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(firing_count, 0, "drops must not create firing history");
}

#[tokio::test]
async fn dispatch_cycle_suppresses_old_firing_for_same_stream_outage() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        init_pool(&StorageConfig::for_test(
            dir.path().join("notifications.db"),
        ))
        .unwrap(),
    );
    let dedup_key = "stream_silence:nashost:agent-docker:2026-07-17T02:43:30.292Z";
    let conn = pool.get().unwrap();
    let params = crate::db::notifications::OutboxInsertParams {
        dedup_key: dedup_key.to_string(),
        rule_id: "stream_silence".to_string(),
        severity: "warning".to_string(),
        hostname: "nashost".to_string(),
        title: "Silent stream".to_string(),
        body: "Body".to_string(),
        apprise_urls_json: "[]".to_string(),
        next_attempt_at: "2000-01-01T00:00:00.000Z".to_string(),
    };
    outbox_insert(&conn, &params).unwrap();
    let first_id: i64 = conn
        .query_row(
            "SELECT id FROM notifications_outbox WHERE dedup_key = ?1",
            [dedup_key],
            |row| row.get(0),
        )
        .unwrap();
    outbox_mark_sent(&conn, first_id, Some(200)).unwrap();
    firings_insert(
        &conn,
        FiringInsertParams {
            outbox_id: first_id,
            rule_id: "stream_silence",
            severity: "warning",
            hostname: "nashost",
            status_code: Some(200),
            notes: None,
            dedup_key,
        },
    )
    .unwrap();
    conn.execute(
        "UPDATE notification_firings SET fired_at = '2000-01-01T00:00:00.000Z' WHERE outbox_id = ?1",
        [first_id],
    )
    .unwrap();
    outbox_insert(&conn, &params).unwrap();
    drop(conn);

    let dispatched = run_dispatch_cycle(
        Arc::clone(&pool),
        Arc::new(Semaphore::new(1)),
        &AppriseClient::new("http://127.0.0.1:1"),
        &NotificationsConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(dispatched, 0);
    let conn = pool.get().unwrap();
    let (status, reason): (String, Option<String>) = conn
        .query_row(
            "SELECT status, last_error FROM notifications_outbox WHERE id != ?1 AND dedup_key = ?2",
            rusqlite::params![first_id, dedup_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "dropped");
    assert_eq!(reason.as_deref(), Some("dedup_suppressed"));
}

/// Insert a due outbox row with the given dedup key and Apprise URL payload.
fn insert_due_row(conn: &rusqlite::Connection, dedup_key: &str, apprise_urls_json: &str) {
    outbox_insert(
        conn,
        &crate::db::notifications::OutboxInsertParams {
            dedup_key: dedup_key.to_string(),
            rule_id: "oom_kill".to_string(),
            severity: "critical".to_string(),
            hostname: "host1".to_string(),
            title: "Title".to_string(),
            body: "Body".to_string(),
            apprise_urls_json: apprise_urls_json.to_string(),
            next_attempt_at: "2000-01-01T00:00:00.000Z".to_string(),
        },
    )
    .unwrap();
}

fn outbox_state(conn: &rusqlite::Connection, dedup_key: &str) -> (String, i64) {
    conn.query_row(
        "SELECT status, attempt_count FROM notifications_outbox WHERE dedup_key = ?1",
        [dedup_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn corrupt_persisted_routing_fails_closed_without_global_fallback() {
    for (key, routing) in [
        ("malformed", "not-json"),
        ("wrong-type", r#"{"url":"json://unexpected"}"#),
        ("invalid-element", r#"[42]"#),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            init_pool(&StorageConfig::for_test(
                dir.path().join("notifications.db"),
            ))
            .unwrap(),
        );
        let conn = pool.get().unwrap();
        insert_due_row(&conn, key, routing);
        drop(conn);

        let cfg = NotificationsConfig {
            apprise_urls: vec!["json://global-destination.invalid".to_string()],
            ..NotificationsConfig::default()
        };
        let dispatched = run_dispatch_cycle(
            Arc::clone(&pool),
            Arc::new(Semaphore::new(1)),
            &AppriseClient::new("http://127.0.0.1:1"),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(dispatched, 0);

        let conn = pool.get().unwrap();
        let (status, reason): (String, Option<String>) = conn
            .query_row(
                "SELECT status, last_error FROM notifications_outbox WHERE dedup_key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "dropped");
        assert_eq!(reason.as_deref(), Some("invalid_apprise_urls_json"));
    }
}

#[tokio::test]
async fn dispatch_cycle_isolates_a_failing_row_instead_of_abandoning_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        init_pool(&StorageConfig::for_test(
            dir.path().join("notifications.db"),
        ))
        .unwrap(),
    );
    let conn = pool.get().unwrap();
    for key in ["burn-1", "burn-2", "burn-3"] {
        insert_due_row(&conn, key, "[]");
    }
    // Deterministic mid-loop failure on the middle row only. `OF status`
    // restricts the trigger to the write-back UPDATE, so the claim — which
    // sets attempt_count and next_attempt_at — still succeeds for all three.
    conn.execute_batch(
        "CREATE TRIGGER fail_middle_row
             BEFORE UPDATE OF status ON notifications_outbox
             WHEN OLD.dedup_key = 'burn-2'
         BEGIN
             SELECT RAISE(ABORT, 'injected write-back failure');
         END;",
    )
    .unwrap();
    drop(conn);

    let dispatched = run_dispatch_cycle(
        Arc::clone(&pool),
        Arc::new(Semaphore::new(1)),
        &AppriseClient::new("http://127.0.0.1:1"),
        &NotificationsConfig::default(),
    )
    .await
    .expect("one failing row must not fail the whole cycle");
    assert_eq!(dispatched, 0);

    let conn = pool.get().unwrap();

    // The claim leased and charged an attempt to every row in the batch up
    // front. A row after the failure must therefore still be processed in this
    // same cycle — otherwise it has burnt an attempt, holds a 300s lease, and
    // was never attempted even once.
    assert_eq!(
        outbox_state(&conn, "burn-3"),
        ("dropped".to_string(), 1),
        "rows after the failing one must be processed, not abandoned"
    );
    assert_eq!(outbox_state(&conn, "burn-1").0, "dropped");

    // The failing row keeps its lease and is reclaimed when the lease expires.
    assert_eq!(outbox_state(&conn, "burn-2"), ("pending".to_string(), 1));
}

#[tokio::test]
async fn dispatch_cycle_dead_letters_a_row_whose_attempt_counter_saturated() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        init_pool(&StorageConfig::for_test(
            dir.path().join("notifications.db"),
        ))
        .unwrap(),
    );
    let conn = pool.get().unwrap();
    insert_due_row(&conn, "saturated", r#"["json://127.0.0.1:1/"]"#);
    // Far past the u8 domain the retry counter is clamped into. A `+ 1` on the
    // clamped u8::MAX wraps to 0 in release builds, which would leave this row
    // below the dead-letter threshold forever.
    conn.execute(
        "UPDATE notifications_outbox SET attempt_count = ?1 WHERE dedup_key = 'saturated'",
        [i64::from(u8::MAX) + 45],
    )
    .unwrap();
    drop(conn);

    let dispatched = run_dispatch_cycle(
        Arc::clone(&pool),
        Arc::new(Semaphore::new(1)),
        &AppriseClient::new("http://127.0.0.1:1"),
        &NotificationsConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(dispatched, 0);
    let conn = pool.get().unwrap();
    assert_eq!(
        outbox_state(&conn, "saturated").0,
        "dead",
        "a saturated attempt counter must still dead-letter, not retry forever"
    );
}
