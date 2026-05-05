use super::*;
use crate::config::StorageConfig;
use crate::db::{init_pool, list_hosts, tail_logs, DbPool, LogBatchEntry};

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

    let rows = tail_logs(&pool, None, None, None, 10).unwrap();
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

    let rows = tail_logs(&pool, None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 0, "no rows should exist after empty batch");

    let hosts = list_hosts(&pool).unwrap();
    assert_eq!(hosts.len(), 0, "no hosts should exist after empty batch");
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
