use std::sync::Arc;

use crate::config::StorageConfig;
use crate::db::{self, LogBatchEntry};

use super::*;

fn test_pool() -> (Arc<db::DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("docker-checkpoint.db"));
    (Arc::new(db::init_pool(&storage).unwrap()), dir)
}

#[test]
fn checkpoint_round_trip() {
    let (pool, _dir) = test_pool();
    db::insert_logs_batch(
        &pool,
        &[entry_with_checkpoint(
            "edge-host-a",
            "abc123",
            "2026-05-05T01:02:03.456789Z",
        )],
    )
    .unwrap();
    let loaded = load_checkpoint(&pool, "edge-host-a", "abc123").unwrap();
    assert_eq!(loaded.as_deref(), Some("2026-05-05T01:02:03.456789Z"));
}

#[test]
fn checkpoint_is_scoped_by_host_and_container() {
    let (pool, _dir) = test_pool();
    db::insert_logs_batch(
        &pool,
        &[entry_with_checkpoint(
            "edge-host-a",
            "abc123",
            "2026-05-05T01:02:03Z",
        )],
    )
    .unwrap();
    assert_eq!(
        load_checkpoint(&pool, "app-host-b", "abc123").unwrap(),
        None
    );
    assert_eq!(
        load_checkpoint(&pool, "edge-host-a", "def456").unwrap(),
        None
    );
}

fn entry_with_checkpoint(host_name: &str, container_id: &str, timestamp: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: timestamp.into(),
        hostname: host_name.into(),
        facility: Some("local0".into()),
        severity: "info".into(),
        app_name: Some("docker-test".into()),
        process_id: Some(container_id.chars().take(12).collect()),
        message: "checkpointed".into(),
        raw: format!("{timestamp} checkpointed"),
        source_ip: format!("docker://{host_name}/{container_id}/stdout"),
        docker_checkpoint: Some(db::DockerCheckpoint {
            host_name: host_name.into(),
            container_id: container_id.into(),
            timestamp: timestamp.into(),
        }),
    }
}
