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
    assert!(outcome.metrics.free_disk_bytes.unwrap() >= outcome.recovery.free_disk_bytes.unwrap());
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
