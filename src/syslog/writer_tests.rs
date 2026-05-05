use super::*;
use crate::config::StorageConfig;
use crate::db::{self, DbPool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
    StorageConfig::for_test(db_path)
}

fn test_pool() -> (Arc<DbPool>, StorageConfig, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = test_storage_config(dir.path().join("syslog-test.db"));
    let pool = Arc::new(db::init_pool(&config).unwrap());
    (pool, config, dir)
}

fn make_entry(message: &str) -> db::LogBatchEntry {
    db::LogBatchEntry {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        hostname: "mymachine".to_string(),
        facility: Some("auth".to_string()),
        severity: "crit".to_string(),
        app_name: Some("su".to_string()),
        process_id: None,
        message: message.to_string(),
        raw: message.to_string(),
        source_ip: "127.0.0.1:514".to_string(),
        docker_checkpoint: None,
    }
}

#[tokio::test]
async fn flush_batch_retains_entries_while_storage_is_write_blocked() {
    let (pool, mut storage, _dir) = test_pool();
    let storage_state = Arc::new(Mutex::new(None));
    let free_disk_mb = db::get_storage_metrics(&pool, &storage)
        .unwrap()
        .free_disk_bytes
        .unwrap()
        / 1_048_576;
    storage.min_free_disk_mb = free_disk_mb + 1024;
    storage.recovery_free_disk_mb = free_disk_mb + 2048;
    *storage_state.lock().unwrap() = Some(db::StorageBudgetState {
        metrics: db::get_storage_metrics(&pool, &storage).unwrap(),
        write_blocked: true,
    });
    let mut batch = vec![make_entry("blocked write")];
    let mut storage_blocked = false;
    let mut summary = IngestSummary::default();

    flush_batch(
        &pool,
        &storage,
        &storage_state,
        &mut batch,
        &mut storage_blocked,
        &mut summary,
    )
    .await;

    assert_eq!(batch.len(), 1);
    assert!(storage_blocked);
}

#[tokio::test]
async fn flush_batch_resumes_after_storage_recovers() {
    let (pool, storage, _dir) = test_pool();
    let storage_state = Arc::new(Mutex::new(Some(db::StorageBudgetState {
        metrics: db::get_storage_metrics(&pool, &storage).unwrap(),
        write_blocked: false,
    })));
    let mut batch = vec![make_entry("resumed write")];
    let mut storage_blocked = true;
    let mut summary = IngestSummary::default();

    flush_batch(
        &pool,
        &storage,
        &storage_state,
        &mut batch,
        &mut storage_blocked,
        &mut summary,
    )
    .await;

    assert!(batch.is_empty());
    assert!(!storage_blocked);
    let rows = db::tail_logs(&pool, None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 1);
}
#[test]
fn source_addr_ip_strips_socket_ports() {
    assert_eq!(source_addr_ip("100.75.111.118:49238"), "100.75.111.118");
    assert_eq!(
        source_addr_ip("[fd7a:115c:a1e0::4f32:104f]:1514"),
        "fd7a:115c:a1e0::4f32:104f"
    );
    assert_eq!(source_addr_ip("unknown-source"), "unknown-source");
}

#[test]
fn summarize_top_senders_pairs_hostnames_with_source_ips() {
    let counts = HashMap::from([
        (("dookie".to_string(), "172.19.0.1".to_string()), 29),
        (("squirts".to_string(), "100.75.111.118".to_string()), 15),
        (("vivobook".to_string(), "100.104.50.17".to_string()), 28),
    ]);

    assert_eq!(
        summarize_top_senders(&counts, 2),
        "dookie@172.19.0.1=29, vivobook@100.104.50.17=28"
    );
}
