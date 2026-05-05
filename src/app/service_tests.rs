use std::sync::Arc;

use crate::config::StorageConfig;
use crate::db::{init_pool, insert_logs_batch, DbPool, LogBatchEntry};

use super::*;

fn test_service() -> (SyslogService, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("app-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    (SyslogService::new(Arc::clone(&pool), storage), pool, dir)
}

fn entry(ts: &str, host: &str, severity: &str, msg: &str, source_ip: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: None,
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: source_ip.to_string(),
    }
}

#[tokio::test]
async fn correlate_events_normalizes_window_groups_and_truncates() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00+00:00",
                "host-a",
                "err",
                "disk full",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:01:00+00:00",
                "host-b",
                "warning",
                "service slow",
                "10.0.0.2:514",
            ),
            entry(
                "2026-01-01T00:02:00+00:00",
                "host-b",
                "info",
                "ignored info",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_events(CorrelateEventsRequest {
            reference_time: "2026-01-01T01:00:00+01:00".into(),
            window_minutes: Some(2),
            severity_min: Some("warning".into()),
            hostname: None,
            source_ip: None,
            query: None,
            limit: Some(1),
        })
        .await
        .unwrap();

    assert_eq!(response.window_from, "2025-12-31T23:58:00+00:00");
    assert_eq!(response.window_to, "2026-01-01T00:02:00+00:00");
    assert!(response.truncated);
    assert_eq!(response.total_events, 1);
    assert_eq!(response.hosts_count, 1);
}

#[tokio::test]
async fn source_ip_filter_uses_network_sender_identity() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "spoofed-host",
                "err",
                "from one",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "spoofed-host",
                "err",
                "from two",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .search_logs(SearchLogsRequest {
            source_ip: Some("10.0.0.2:514".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(response.count, 1);
    assert_eq!(response.logs[0].message, "from two");
}

#[tokio::test]
async fn health_check_runs_simple_database_query() {
    let (service, _pool, _dir) = test_service();

    service.health_check().await.unwrap();
}
