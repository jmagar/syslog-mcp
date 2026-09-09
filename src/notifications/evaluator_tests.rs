use super::*;
use crate::config::StorageConfig;
use crate::db::{LogBatchEntry, init_pool, insert_logs_batch};

fn test_pool() -> (DbPool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::for_test(dir.path().join("test.db"));
    let pool = init_pool(&config).unwrap();
    (pool, dir)
}

fn log_entry(timestamp: &str, hostname: &str, message: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: timestamp.to_string(),
        hostname: hostname.to_string(),
        facility: None,
        severity: "info".to_string(),
        app_name: Some("app".to_string()),
        process_id: None,
        message: message.to_string(),
        raw: message.to_string(),
        source_ip: "127.0.0.1:1514".to_string(),
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
    }
}

fn log_entry_with_app(
    timestamp: &str,
    hostname: &str,
    app_name: &str,
    severity: &str,
    message: &str,
) -> LogBatchEntry {
    LogBatchEntry {
        app_name: Some(app_name.to_string()),
        severity: severity.to_string(),
        ..log_entry(timestamp, hostname, message)
    }
}

#[test]
fn build_urls_json_serializes_configured_apprise_urls() {
    let cfg = NotificationsConfig {
        apprise_urls: vec![
            "gotify://token@example.test".to_string(),
            "mailto://ops@example.test".to_string(),
        ],
        ..NotificationsConfig::default()
    };

    assert_eq!(
        build_urls_json(&cfg),
        r#"["gotify://token@example.test","mailto://ops@example.test"]"#
    );
}

#[test]
fn fetch_recent_logs_respects_limit_offset_and_newest_first_order() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            log_entry("2999-01-01T00:00:01Z", "host-a", "first"),
            log_entry("2999-01-01T00:00:02Z", "host-b", "second"),
            log_entry("2999-01-01T00:00:03Z", "host-c", "third"),
        ],
    )
    .unwrap();

    let conn = pool.get().unwrap();
    let rows = fetch_recent_logs(&conn, 60, 2, 1).unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].message, "second");
    assert_eq!(rows[1].message, "first");
}

#[test]
fn fetch_recent_logs_orders_by_received_at_not_row_id() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            log_entry("2999-01-01T00:00:01Z", "host-a", "oldest-received"),
            log_entry("2999-01-01T00:00:02Z", "host-b", "newest-received"),
            log_entry("2999-01-01T00:00:03Z", "host-c", "middle-received"),
        ],
    )
    .unwrap();

    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE logs SET received_at = CASE message
             WHEN 'oldest-received' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 seconds')
             WHEN 'newest-received' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-10 seconds')
             WHEN 'middle-received' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-20 seconds')
             ELSE received_at
         END",
        [],
    )
    .unwrap();

    let rows = fetch_recent_logs(&conn, 60, 3, 0).unwrap();

    assert_eq!(
        rows.iter()
            .map(|row| row.message.as_str())
            .collect::<Vec<_>>(),
        vec!["newest-received", "middle-received", "oldest-received"]
    );
}

#[test]
fn newest_row_age_secs_returns_none_for_empty_logs_table() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();

    assert_eq!(newest_row_age_secs(&conn).unwrap(), None);
}

#[test]
fn newest_row_age_secs_clamps_future_rows_to_zero() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[log_entry("2999-01-01T00:00:00Z", "future-host", "future")],
    )
    .unwrap();

    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE logs SET received_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+1 day')",
        [],
    )
    .unwrap();
    assert_eq!(newest_row_age_secs(&conn).unwrap(), Some(0));
}

#[tokio::test]
async fn spawn_evaluator_returns_none_when_notifications_disabled() {
    let (pool, _dir) = test_pool();
    let cfg = NotificationsConfig {
        enabled: false,
        ..NotificationsConfig::default()
    };

    let handle = spawn_evaluator(
        Arc::new(pool),
        Arc::new(Semaphore::new(1)),
        cfg,
        tokio_util::sync::CancellationToken::new(),
    );

    assert!(handle.is_none());
}

#[tokio::test]
async fn evaluation_cycle_inserts_matching_rows_once_by_pending_dedup_key() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            log_entry_with_app(
                "2999-01-01T00:00:00Z",
                "host-a",
                "kernel",
                "crit",
                "Out of memory: Killed process 1234 (nginx)",
            ),
            log_entry_with_app(
                "2999-01-01T00:00:01Z",
                "host-a",
                "kernel",
                "crit",
                "Out of memory: Killed process 5678 (postgres)",
            ),
        ],
    )
    .unwrap();
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_urls: vec!["gotify://token@example.test".to_string()],
        ..NotificationsConfig::default()
    };

    let first = run_evaluation_cycle(Arc::new(pool.clone()), Arc::new(Semaphore::new(1)), cfg)
        .await
        .unwrap();
    let conn = pool.get().unwrap();
    let pending: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications_outbox
             WHERE status = 'pending' AND rule_id = 'oom_kill'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(first, 1);
    assert_eq!(pending, 1);
}

#[tokio::test]
async fn evaluation_cycle_skips_inserts_when_maintenance_semaphore_is_closed() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[log_entry_with_app(
            "2999-01-01T00:00:00Z",
            "host-a",
            "kernel",
            "crit",
            "Out of memory: Killed process 1234 (nginx)",
        )],
    )
    .unwrap();
    let sem = Arc::new(Semaphore::new(1));
    sem.close();
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_urls: vec!["gotify://token@example.test".to_string()],
        ..NotificationsConfig::default()
    };

    let inserted = run_evaluation_cycle(Arc::new(pool.clone()), sem, cfg)
        .await
        .unwrap();
    let conn = pool.get().unwrap();
    let pending: i64 = conn
        .query_row("SELECT COUNT(*) FROM notifications_outbox", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(inserted, 0);
    assert_eq!(pending, 0);
}
