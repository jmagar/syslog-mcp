use super::*;
use crate::config::StorageConfig;

fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
    StorageConfig::for_test(db_path)
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
