use super::*;
use crate::config::StorageConfig;
use crate::db::{init_pool, insert_logs_batch, list_hosts, tail_logs, DbPool, LogBatchEntry};
use anyhow::Result;
use rusqlite::params;
use std::path::Path;

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
        docker_checkpoint: None,
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

    let remaining = tail_logs(&pool, None, None, None, 10).unwrap();
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

    let rows = tail_logs(&pool, None, None, None, 10).unwrap();
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
