use super::*;
use crate::config::StorageConfig;
use crate::db::{DbPool, LogBatchEntry, init_pool, insert_logs_batch, list_hosts, tail_logs};
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

fn update_received_at(pool: &DbPool, message: &str, received_at: &str) {
    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE logs SET received_at = ?1 WHERE message = ?2",
        params![received_at, message],
    )
    .unwrap();
}

fn insert_heartbeat(pool: &DbPool, hostname: &str, received_at: &str) -> i64 {
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO host_heartbeats (
            host_id, hostname, source_ip, sampled_at, received_at, boot_id, uptime_secs,
            sequence, collection_ms, agent_version, os, architecture
        ) VALUES (
            ?1, ?2, '127.0.0.1', ?3, ?3, ?4, 1, 1, 1, 'test', 'linux', 'x86_64'
        )",
        params![hostname, hostname, received_at, format!("boot-{hostname}")],
    )
    .unwrap();
    conn.last_insert_rowid()
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
fn physical_db_size_counts_extensionless_sqlite_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex");
    std::fs::write(&db_path, b"db").unwrap();
    std::fs::write(sqlite_sidecar_path(&db_path, "wal"), b"wal").unwrap();
    std::fs::write(sqlite_sidecar_path(&db_path, "shm"), b"shm").unwrap();

    let total = physical_db_size_bytes(&db_path).unwrap();
    assert_eq!(total, 2 + 3 + 3);
}

#[test]
fn maybe_checkpoint_wal_by_size_skips_missing_disabled_and_below_threshold_wal() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("missing.db");
    let config = test_storage_config(db_path.clone());
    let pool = init_pool(&config).unwrap();

    assert!(
        maybe_checkpoint_wal_by_size(&pool, &db_path, 0)
            .unwrap()
            .is_none()
    );
    assert!(
        maybe_checkpoint_wal_by_size(&pool, &db_path, u64::MAX)
            .unwrap()
            .is_none()
    );
}

#[test]
fn maybe_checkpoint_wal_by_size_runs_when_wal_exceeds_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wal-threshold.db");
    let mut config = test_storage_config(db_path.clone());
    config.pool_size = 2;
    config.wal_mode = true;
    let pool = init_pool(&config).unwrap();
    let held_conn = pool.get().unwrap();
    held_conn
        .execute_batch(
            "CREATE TABLE wal_threshold_probe(id INTEGER PRIMARY KEY, value TEXT);
             INSERT INTO wal_threshold_probe(value) VALUES ('x');",
        )
        .unwrap();
    assert!(
        sqlite_sidecar_path(&db_path, "wal").exists(),
        "test setup should create a WAL sidecar"
    );

    let checkpoint = maybe_checkpoint_wal_by_size(&pool, &db_path, 1)
        .unwrap()
        .expect("WAL above tiny threshold should checkpoint");
    assert!(checkpoint.1 >= checkpoint.2);
    drop(held_conn);
}

#[test]
fn threshold_maintenance_truncates_a_fully_checkpointed_wal() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wal-truncate.db");
    let mut config = test_storage_config(db_path.clone());
    config.pool_size = 2;
    config.wal_mode = true;
    config.wal_checkpoint_mb = 1;
    let pool = init_pool(&config).unwrap();
    {
        let conn = pool.get().unwrap();
        conn.execute_batch("CREATE TABLE wal_truncate_probe(id INTEGER PRIMARY KEY, value BLOB);")
            .unwrap();
        let payload = vec![b'x'; 64 * 1024];
        for _ in 0..32 {
            conn.execute(
                "INSERT INTO wal_truncate_probe(value) VALUES (?1)",
                [&payload],
            )
            .unwrap();
        }
    }
    let wal_path = sqlite_sidecar_path(&db_path, "wal");
    let before = std::fs::metadata(&wal_path).unwrap().len();
    assert!(before > config.wal_checkpoint_threshold_bytes());

    checkpoint_wal_and_incremental_vacuum(&pool, &config).unwrap();

    let after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    assert!(
        after < before,
        "fully checkpointed WAL should be truncated below its high-water size: before={before} after={after}"
    );
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

    let deleted = purge_old_logs(&pool, 90, 0).unwrap();
    assert_eq!(deleted, 1, "should have deleted exactly the old entry");

    let remaining = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].message, "future message");
}

#[test]
fn test_purge_zero_retention_noop() {
    let (pool, _dir) = test_pool();
    let entries = vec![make_entry("2020-01-01T00:00:00Z", "host-a", "info", "old")];
    insert_logs_batch(&pool, &entries).unwrap();

    let deleted = purge_old_logs(&pool, 0, 0).unwrap();
    assert_eq!(deleted, 0, "retention_days=0 should be a no-op");
}

#[test]
fn test_purge_old_heartbeats_removes_children_before_parent() {
    let (pool, _dir) = test_pool();
    let old_id = insert_heartbeat(&pool, "host-old", "2020-01-01T00:00:00Z");
    let new_id = insert_heartbeat(&pool, "host-new", "2099-01-01T00:00:00Z");
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO heartbeat_cpu (heartbeat_id, usage_percent) VALUES (?1, 10.0)",
        [old_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_cpu (heartbeat_id, usage_percent) VALUES (?1, 20.0)",
        [new_id],
    )
    .unwrap();
    drop(conn);

    let deleted = purge_old_heartbeats(&pool, 90, 100, OrphanSweep::Run).unwrap();
    assert_eq!(deleted, 1);

    let conn = pool.get().unwrap();
    let old_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM host_heartbeats WHERE hostname = 'host-old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let old_child_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM heartbeat_cpu WHERE heartbeat_id = ?1",
            [old_id],
            |row| row.get(0),
        )
        .unwrap();
    let new_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM host_heartbeats WHERE hostname = 'host-new'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let new_child_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM heartbeat_cpu WHERE heartbeat_id = ?1",
            [new_id],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(old_rows, 0);
    assert_eq!(old_child_rows, 0);
    assert_eq!(new_rows, 1);
    assert_eq!(new_child_rows, 1);
}

#[test]
fn test_heartbeat_cleanup_removes_all_child_tables_and_orphans() {
    let (pool, _dir) = test_pool();
    let heartbeat_id = insert_heartbeat(&pool, "host-old", "2020-01-01T00:00:00Z");
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO heartbeat_cpu (heartbeat_id, usage_percent) VALUES (?1, 10.0)",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_memory (heartbeat_id, total_bytes) VALUES (?1, 1024)",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_disks (heartbeat_id, mountpoint) VALUES (?1, '/dev/sda')",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_network (heartbeat_id, interface) VALUES (?1, 'eth0')",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_processes (heartbeat_id, total) VALUES (?1, 10)",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_containers (heartbeat_id, running) VALUES (?1, 1)",
        [heartbeat_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO heartbeat_cpu (heartbeat_id, usage_percent) VALUES (999999, 99.0)",
        [],
    )
    .unwrap();
    drop(conn);

    let deleted = purge_old_heartbeats(&pool, 90, 100, OrphanSweep::Run).unwrap();
    assert_eq!(deleted, 2);

    let conn = pool.get().unwrap();
    for table in HEARTBEAT_CHILD_TABLES {
        let remaining: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 0, "{table} should be empty after cleanup");
    }
}

#[test]
fn test_enforce_storage_budget_keeps_recent_heartbeats_when_logs_are_older() {
    let (pool, dir) = test_pool();
    let large_old = "old-log-".repeat(350_000);
    let entries = vec![make_entry(
        "2026-01-01T00:00:01Z",
        "deleted-host",
        "info",
        &large_old,
    )];
    insert_logs_batch(&pool, &entries).unwrap();
    update_received_at(&pool, &large_old, "2020-01-01T00:00:00Z");
    let heartbeat_id = insert_heartbeat(&pool, "recent-heartbeat", "2099-01-01T00:00:00Z");

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 3;
    config.recovery_db_size_mb = 2;

    let outcome = enforce_storage_budget(&pool, &config).unwrap();
    assert!(outcome.deleted_rows > 0);

    let conn = pool.get().unwrap();
    let heartbeats: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM host_heartbeats WHERE id = ?1",
            [heartbeat_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(heartbeats, 1);
    drop(conn);

    let logs = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert!(logs.is_empty());
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

    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message, large_new);
}

#[test]
fn test_enforce_storage_budget_reconciles_hosts_after_deletes() {
    let (pool, dir) = test_pool();
    let large_oldest = "delete-me-1-".repeat(150_000);
    let large_older = "delete-me-2-".repeat(150_000);
    // Deliberately small relative to `recovery_db_size_mb` below: after both
    // `deleted-host` rows are trimmed, this row alone (plus fixed schema/
    // index overhead, which grows slowly as the schema gains tables/indexes
    // over time) must land comfortably under the 3MB recovery target with
    // real headroom — not within a single SQLite page (4096 bytes) of it.
    // A prior version of this fixture sized `large_keep` right at that
    // boundary, so an unrelated schema change (e.g. a new index) could tip
    // post-delete size a few KB over the target and cause the loop to trim
    // one extra (wrongly "surviving") row. See PR2 (GH #94) investigation.
    let large_keep = "keep-me-".repeat(5_000);
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
    config.max_db_size_mb = 4;
    config.recovery_db_size_mb = 3;

    enforce_storage_budget(&pool, &config).unwrap();

    let hosts = list_hosts(&pool).unwrap();
    assert!(hosts.iter().all(|host| host.hostname != "deleted-host"));
    let surviving = hosts
        .iter()
        .find(|host| host.hostname == "surviving-host")
        .unwrap();
    assert_eq!(surviving.log_count, 1);
}

#[test]
fn delete_orphan_heartbeat_latest_removes_cache_rows_without_parent_sample() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO host_heartbeats_latest
             (host_id, heartbeat_id, hostname, sampled_at, received_at,
              partial, agent_version, os, architecture, metadata_json)
         VALUES ('host-a', 12345, 'devhost', '2026-07-16T00:00:00Z',
                 '2026-07-16T00:00:00Z', 0, '0.1.0', 'linux', 'x86_64', '{}')",
        [],
    )
    .unwrap();
    drop(conn);

    let deleted = delete_orphan_heartbeat_latest(&pool).unwrap();

    assert_eq!(deleted, 1);
    let remaining: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM host_heartbeats_latest", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(remaining, 0);
}

/// Insert one child row for `table`, using the minimum column set each table
/// accepts (`heartbeat_network.interface` is the only NOT NULL extra).
fn insert_child_row(pool: &DbPool, table: &str, heartbeat_id: i64) {
    let sql = if table == "heartbeat_network" {
        format!("INSERT INTO {table} (heartbeat_id, interface) VALUES (?1, 'eth0')")
    } else {
        format!("INSERT INTO {table} (heartbeat_id) VALUES (?1)")
    };
    pool.get().unwrap().execute(&sql, [heartbeat_id]).unwrap();
}

fn count_rows(pool: &DbPool, table: &str) -> i64 {
    pool.get()
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// The P1 property: finding orphans is a full scan of each child table, so it
/// must happen as a READER. Only the bounded delete may take the write lock.
///
/// A second thread holds the global write lock for the whole sweep; if the
/// sweep needs that lock just to discover there is nothing to delete, it can
/// only return after the holder releases, and the happens-before flag is set.
#[test]
fn orphan_child_sweep_scans_without_the_global_write_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (pool, _dir) = test_pool();
    let heartbeat_id = insert_heartbeat(&pool, "host-live", "2099-01-01T00:00:00Z");
    for table in HEARTBEAT_CHILD_TABLES {
        for _ in 0..8 {
            insert_child_row(&pool, table, heartbeat_id);
        }
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Arc::new(AtomicBool::new(false));
    let holder_released = std::sync::Arc::clone(&released);
    let holder = std::thread::spawn(move || {
        let _write_guard = crate::db::pool::test_write_lock();
        ready_tx.send(()).unwrap();
        // Bounded so a regression fails the assertion instead of hanging.
        let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
        holder_released.store(true, Ordering::SeqCst);
    });
    ready_rx.recv().unwrap();

    let deleted = delete_orphan_heartbeat_children(&pool, 4).unwrap();
    let finished_before_lock_released = !released.load(Ordering::SeqCst);
    let _ = release_tx.send(());
    holder.join().unwrap();

    assert_eq!(deleted, 0, "there are no orphans to delete");
    assert!(
        finished_before_lock_released,
        "orphan sweep must scan for orphans without waiting on the global write lock"
    );
    for table in HEARTBEAT_CHILD_TABLES {
        assert_eq!(count_rows(&pool, table), 8, "{table} rows must survive");
    }
}

/// A chunk size smaller than the orphan count must still drain every orphan:
/// the sweep loops until the scan comes back empty rather than stopping after
/// one bounded DELETE.
#[test]
fn orphan_child_sweep_drains_orphans_in_chunks_smaller_than_the_backlog() {
    let (pool, _dir) = test_pool();
    for _ in 0..5 {
        insert_child_row(&pool, "heartbeat_cpu", 999_999);
    }

    let deleted = delete_orphan_heartbeat_children(&pool, 2).unwrap();

    assert_eq!(deleted, 5, "every orphan must be deleted across chunks");
    assert_eq!(count_rows(&pool, "heartbeat_cpu"), 0);
}

/// Chunking must not change what gets deleted: every orphan in every child
/// table goes, live children stay, and the returned count is exact.
#[test]
fn orphan_child_sweep_deletes_all_orphans_across_chunks() {
    let (pool, _dir) = test_pool();
    let heartbeat_id = insert_heartbeat(&pool, "host-live", "2099-01-01T00:00:00Z");
    for table in HEARTBEAT_CHILD_TABLES {
        insert_child_row(&pool, table, heartbeat_id);
        for _ in 0..3 {
            insert_child_row(&pool, table, 999_999);
        }
        insert_child_row(&pool, table, heartbeat_id);
    }

    let deleted = delete_orphan_heartbeat_children(&pool, 2).unwrap();

    assert_eq!(deleted, 3 * HEARTBEAT_CHILD_TABLES.len());
    for table in HEARTBEAT_CHILD_TABLES {
        assert_eq!(
            count_rows(&pool, table),
            2,
            "{table} live rows must survive"
        );
        let orphans: i64 = pool
            .get()
            .unwrap()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE heartbeat_id = 999999"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "{table} orphans must be gone");
    }
}

/// Orphan cleanup is a repair mechanism, not per-tick retention work: the
/// caller decides when it is due, and a skipped sweep leaves orphans alone.
#[test]
fn purge_old_heartbeats_sweeps_orphans_only_when_the_caller_says_it_is_due() {
    let (pool, _dir) = test_pool();
    insert_child_row(&pool, "heartbeat_cpu", 999_999);

    let skipped = purge_old_heartbeats(&pool, 90, 100, OrphanSweep::Skip).unwrap();
    assert_eq!(skipped, 0);
    assert_eq!(count_rows(&pool, "heartbeat_cpu"), 1);

    let swept = purge_old_heartbeats(&pool, 90, 100, OrphanSweep::Run).unwrap();
    assert_eq!(swept, 1);
    assert_eq!(count_rows(&pool, "heartbeat_cpu"), 0);
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

/// syslog-mcp-w4hh: low whole-filesystem free space is an EXTERNAL condition.
/// Cortex must NOT delete its own data to chase it — it blocks writes instead.
#[test]
fn external_disk_pressure_does_not_delete() {
    let (pool, dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:01Z", "host-a", "info", "older"),
        make_entry("2026-01-01T00:00:02Z", "host-b", "info", "newer"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();
    update_received_at(&pool, "older", "2026-01-01T00:00:00Z");
    update_received_at(&pool, "newer", "2026-01-02T00:00:00Z");

    // DB-size limit disabled; only the free-disk floor is active. The DB itself
    // is tiny, so the disk pressure is genuinely external.
    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 0;
    config.recovery_db_size_mb = 0;
    config.min_free_disk_mb = 512;
    config.recovery_free_disk_mb = 768;

    // Probe reports a persistently low free-disk value (well below the trigger).
    let probe = FakeDiskSpaceProbe::new(vec![64 * 1_048_576]);
    let outcome = enforce_storage_budget_with_probe(&pool, &config, &probe).unwrap();

    assert_eq!(
        outcome.deleted_rows, 0,
        "must NOT delete own data under external disk pressure"
    );
    assert!(
        outcome.write_blocked,
        "must block writes while free disk is below the floor"
    );

    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 2, "both rows must survive — nothing deleted");

    // The disk_fill alert decision is made in runtime.rs from the same metrics;
    // verify the evaluator fires Some(..) at this free-disk level (the alert).
    let critical = config.min_free_disk_mb * 1_048_576;
    let warn = config.recovery_free_disk_mb * 1_048_576;
    let params = crate::notifications::rules::evaluate_disk_fill(
        "test-host",
        64 * 1_048_576,
        critical,
        warn,
        "[]",
    );
    assert!(
        params.is_some(),
        "disk_fill alert must fire at this free-disk level"
    );
}

/// syslog-mcp-w4hh: when the DB grows past max_db_size_mb but the only remaining
/// rows are floor-protected err+ (recent window + within per-source cap), self-trim
/// must STOP at the floor and convert to write_blocked rather than wiping err+.
#[test]
fn self_trim_respects_err_floor() {
    let (pool, dir) = test_pool();
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    // One large, deletable info row (oldest) + several recent err+ rows that the
    // floor protects. The err rows are big enough that, even after the info row is
    // trimmed, the DB stays over the recovery target.
    let big_info = "info-junk-".repeat(120_000);
    let big_err1 = "err-keep-1-".repeat(120_000);
    let big_err2 = "err-keep-2-".repeat(120_000);
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T00:00:01Z", "host-a", "info", &big_info),
            make_entry("2026-01-01T00:00:02Z", "host-a", "err", &big_err1),
            make_entry("2026-01-01T00:00:03Z", "host-a", "crit", &big_err2),
        ],
    )
    .unwrap();
    // info row is oldest; err rows are received "now" so they are inside the window.
    update_received_at(&pool, &big_info, "2026-01-01T00:00:00Z");
    update_received_at(&pool, &big_err1, &now);
    update_received_at(&pool, &big_err2, &now);

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 2;
    config.recovery_db_size_mb = 1; // recovery target the err rows alone exceed
    config.min_free_disk_mb = 0;
    config.recovery_free_disk_mb = 0;
    config.cleanup_chunk_size = 1;
    config.err_floor_window_hours = 24;
    config.err_floor_per_source_cap = 10_000;

    let outcome = enforce_storage_budget(&pool, &config).unwrap();

    // err+ rows must survive — the floor protected them.
    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    assert!(
        messages.contains(&big_err1.as_str()),
        "err row must survive the floor"
    );
    assert!(
        messages.contains(&big_err2.as_str()),
        "crit row must survive the floor"
    );
    assert!(
        !messages.contains(&big_info.as_str()),
        "the deletable info row should have been trimmed"
    );
    // DB is still over cap (err+ retained), so writes must be blocked rather than
    // the err+ history wiped.
    assert!(
        outcome.write_blocked,
        "must block writes once trim reaches the err+ floor while still over cap"
    );
}

/// Helper: insert a log with an explicit source_ip (the socket peer), used by the
/// W1 bound tests below to exercise the per-source partition.
fn make_entry_from(
    ts: &str,
    host: &str,
    severity: &str,
    source_ip: &str,
    msg: &str,
) -> LogBatchEntry {
    let mut e = make_entry(ts, host, severity, msg);
    e.source_ip = source_ip.to_string();
    e
}

/// syslog-mcp-w4hh W1 (monopolization defense): the per-source cap BOUNDS how
/// much err+ a single source IP can keep in the protected set. With cap=2, only
/// the 2 newest err+ rows from one source survive self-trim; the rest are
/// deletable even though they are inside the time window and high severity.
#[test]
fn err_floor_per_source_cap_evicts_excess() {
    let (pool, dir) = test_pool();
    let now = chrono::Utc::now();
    // Five large err rows from the SAME source IP, all recent, staggered by second.
    let mut msgs = Vec::new();
    for i in 0..5 {
        let ts = (now - chrono::TimeDelta::seconds(10 - i))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let msg = format!("err-{i}-{}", "z".repeat(700_000));
        insert_logs_batch(
            &pool,
            &[make_entry_from(&ts, "host-a", "err", "10.0.0.5:5000", &msg)],
        )
        .unwrap();
        update_received_at(&pool, &msg, &ts);
        msgs.push(msg);
    }

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 2;
    config.recovery_db_size_mb = 1;
    config.min_free_disk_mb = 0;
    config.recovery_free_disk_mb = 0;
    config.cleanup_chunk_size = 1;
    config.err_floor_window_hours = 24;
    config.err_floor_per_source_cap = 2; // only 2 protected per source IP

    enforce_storage_budget(&pool, &config).unwrap();

    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let surviving: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    // The 2 NEWEST err rows (indices 3,4) must survive; older ones evicted.
    assert!(
        surviving.contains(&msgs[4].as_str()) && surviving.contains(&msgs[3].as_str()),
        "the 2 newest err rows from the source must be protected"
    );
    assert!(
        surviving.len() <= 2,
        "per-source cap=2 must bound the source's protected err+; got {} survivors",
        surviving.len()
    );
    assert!(
        !surviving.contains(&msgs[0].as_str()),
        "the oldest err row must be evicted beyond the cap (monopolization bound)"
    );
}

/// syslog-mcp-w4hh W1 (unbounded-pin defense): the time window BOUNDS how far
/// back the floor protects. err+ rows received OUTSIDE the window are deletable
/// by self-trim, so a hostile source cannot pin the DB at max with stale err spam.
#[test]
fn err_floor_window_evicts_stale_err() {
    let (pool, dir) = test_pool();
    let big_stale_err = "stale-err-".repeat(120_000);
    let big_recent_err = "recent-err-".repeat(120_000);
    insert_logs_batch(
        &pool,
        &[
            make_entry_from(
                "2026-01-01T00:00:01Z",
                "host-a",
                "err",
                "10.0.0.9:6000",
                &big_stale_err,
            ),
            make_entry_from(
                "2026-01-01T00:00:02Z",
                "host-a",
                "err",
                "10.0.0.9:6000",
                &big_recent_err,
            ),
        ],
    )
    .unwrap();
    let now = chrono::Utc::now();
    // Stale err: 48h ago, well outside a 1h window → NOT protected → deletable.
    let stale_ts = (now - chrono::TimeDelta::hours(48))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let recent_ts = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    update_received_at(&pool, &big_stale_err, &stale_ts);
    update_received_at(&pool, &big_recent_err, &recent_ts);

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 2;
    config.recovery_db_size_mb = 1;
    config.min_free_disk_mb = 0;
    config.recovery_free_disk_mb = 0;
    config.cleanup_chunk_size = 1;
    config.err_floor_window_hours = 1; // 1h window — stale err falls outside
    config.err_floor_per_source_cap = 10_000;

    enforce_storage_budget(&pool, &config).unwrap();

    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let surviving: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    assert!(
        !surviving.contains(&big_stale_err.as_str()),
        "stale err+ outside the window must be deletable (unbounded-pin bound)"
    );
    assert!(
        surviving.contains(&big_recent_err.as_str()),
        "recent err+ inside the window must still be protected"
    );
}

/// syslog-mcp-w4hh: hysteresis. The external disk-pressure block engages at
/// min_free_disk_mb and clears only at recovery_free_disk_mb — in the band between
/// them the prior state is carried forward (latch, no flap).
#[test]
fn disk_pressure_write_block_uses_hysteresis() {
    let (pool, dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_entry("2026-01-01T00:00:01Z", "host-a", "info", "x")],
    )
    .unwrap();

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 0;
    config.recovery_db_size_mb = 0;
    config.min_free_disk_mb = 512;
    config.recovery_free_disk_mb = 768;

    // Below trigger (512MB): engages regardless of prior state.
    let low = FakeDiskSpaceProbe::new(vec![100 * 1_048_576]);
    let blocked = enforce_storage_budget_with_state(&pool, &config, &low, false).unwrap();
    assert!(blocked.write_blocked, "below min: must block");
    assert_eq!(blocked.deleted_rows, 0, "must not delete on disk pressure");

    // In the hysteresis band (600MB, between 512 and 768): keep prior state.
    let band = FakeDiskSpaceProbe::new(vec![600 * 1_048_576]);
    let still_blocked = enforce_storage_budget_with_state(&pool, &config, &band, true).unwrap();
    assert!(
        still_blocked.write_blocked,
        "in band with prev=true: stay blocked (latch)"
    );
    let stays_clear = enforce_storage_budget_with_state(&pool, &config, &band, false).unwrap();
    assert!(
        !stays_clear.write_blocked,
        "in band with prev=false: stay clear (no premature engage)"
    );

    // At/above recovery (800MB): clear regardless of prior state.
    let high = FakeDiskSpaceProbe::new(vec![800 * 1_048_576]);
    let cleared = enforce_storage_budget_with_state(&pool, &config, &high, true).unwrap();
    assert!(
        !cleared.write_blocked,
        "at recovery threshold: must clear even if prev=true"
    );
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

// ---- purge_by_tag_window ----

fn make_tagged(ts: &str, host: &str, severity: &str, app: &str, msg: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: Some(app.to_string()),
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: "127.0.0.1:514".to_string(),
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

#[test]
fn test_purge_by_tag_window_zero_days_is_noop() {
    let (pool, _dir) = test_pool();
    let entries = vec![make_tagged(
        "2020-01-01T00:00:00Z",
        "h",
        "info",
        "adguard-allowed",
        "old",
    )];
    insert_logs_batch(&pool, &entries).unwrap();

    let deleted = super::purge_by_tag_window(&pool, "adguard-allowed", 0, 0).unwrap();
    assert_eq!(deleted, 0, "max_days=0 must be a no-op");

    let remaining = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert_eq!(remaining.len(), 1, "row must still be present");
}

#[test]
fn test_purge_by_tag_window_only_targets_named_tag() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "info",
                "adguard-allowed",
                "old-allowed",
            ),
            make_tagged("2020-01-01T00:00:00Z", "h", "info", "nginx", "old-nginx"),
            make_tagged("2020-01-01T00:00:00Z", "h", "info", "kernel", "old-kernel"),
        ],
    )
    .unwrap();
    // Backdate received_at past the 7-day window
    update_received_at(&pool, "old-allowed", "2020-01-01T00:00:00Z");
    update_received_at(&pool, "old-nginx", "2020-01-01T00:00:00Z");
    update_received_at(&pool, "old-kernel", "2020-01-01T00:00:00Z");

    let deleted = super::purge_by_tag_window(&pool, "adguard-allowed", 7, 0).unwrap();
    assert_eq!(deleted, 1, "only the adguard-allowed row must be deleted");

    let remaining = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let messages: Vec<&str> = remaining.iter().map(|r| r.message.as_str()).collect();
    assert!(messages.contains(&"old-nginx"), "nginx must survive");
    assert!(messages.contains(&"old-kernel"), "kernel must survive");
    assert!(
        !messages.contains(&"old-allowed"),
        "adguard-allowed must be gone"
    );
}

#[test]
fn test_purge_by_tag_window_excludes_high_severity_rows() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "info",
                "adguard-allowed",
                "info-old",
            ),
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "err",
                "adguard-allowed",
                "err-old",
            ),
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "crit",
                "adguard-allowed",
                "crit-old",
            ),
        ],
    )
    .unwrap();
    update_received_at(&pool, "info-old", "2020-01-01T00:00:00Z");
    update_received_at(&pool, "err-old", "2020-01-01T00:00:00Z");
    update_received_at(&pool, "crit-old", "2020-01-01T00:00:00Z");

    let deleted = super::purge_by_tag_window(&pool, "adguard-allowed", 7, 0).unwrap();
    assert_eq!(deleted, 1, "only the info row should be purged");

    let remaining = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let messages: Vec<&str> = remaining.iter().map(|r| r.message.as_str()).collect();
    assert!(
        messages.contains(&"err-old"),
        "err must be exempt from time-based purge"
    );
    assert!(
        messages.contains(&"crit-old"),
        "crit must be exempt from time-based purge"
    );
}

#[test]
fn test_purge_by_tag_window_respects_cutoff_boundary() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "info",
                "adguard-allowed",
                "old",
            ),
            make_tagged(
                "2020-01-01T00:00:00Z",
                "h",
                "info",
                "adguard-allowed",
                "fresh",
            ),
        ],
    )
    .unwrap();
    // 'old' is past the 7-day window, 'fresh' is well inside it
    update_received_at(&pool, "old", "2020-01-01T00:00:00Z");
    update_received_at(
        &pool,
        "fresh",
        &chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );

    let deleted = super::purge_by_tag_window(&pool, "adguard-allowed", 7, 0).unwrap();
    assert_eq!(deleted, 1, "only the old row should be deleted");

    let remaining = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let messages: Vec<&str> = remaining.iter().map(|r| r.message.as_str()).collect();
    assert!(messages.contains(&"fresh"), "fresh row must survive");
}

/// A disk-space probe that always fails (simulates a statvfs/ENOENT error).
/// `get_storage_metrics_with_probe` maps the `Err` to `free_disk_bytes == None`.
#[derive(Clone)]
struct FailingDiskSpaceProbe;

impl DiskSpaceProbe for FailingDiskSpaceProbe {
    fn free_bytes(&self, _path: &Path) -> Result<u64> {
        anyhow::bail!("simulated statvfs probe failure")
    }
}

/// syslog-mcp-w4hh (review bug #1 — FAIL-CLOSED): when the free-disk guardrail is
/// ENABLED but the disk-space probe fails (`free_disk_bytes == None`), the guardrail
/// must engage conservatively (treat unknown free space as the worst case) instead
/// of failing open. Previously `unwrap_or(u64::MAX)` made a probe failure look like
/// infinite free space, so the block NEVER engaged — defeating the safety behavior.
#[test]
fn probe_failure_engages_write_block_does_not_fail_open() {
    let (pool, dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:01Z", "host-a", "info", "older"),
        make_entry("2026-01-01T00:00:02Z", "host-b", "info", "newer"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    // DB-size limit disabled; only the free-disk guardrail is active and ENABLED.
    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 0;
    config.recovery_db_size_mb = 0;
    config.min_free_disk_mb = 512;
    config.recovery_free_disk_mb = 768;

    // The probe fails on every call → free_disk_bytes is None.
    let probe = FailingDiskSpaceProbe;
    let outcome = enforce_storage_budget_with_probe(&pool, &config, &probe).unwrap();

    assert!(
        outcome.metrics.free_disk_bytes.is_none(),
        "probe failure must surface as None, not a fabricated value"
    );
    assert!(
        outcome.write_blocked,
        "FAIL-CLOSED: an enabled free-disk guardrail must block writes when the \
         probe fails (unknown == worst case), not fail open"
    );
    // External pressure must never delete cortex's own data.
    assert_eq!(
        outcome.deleted_rows, 0,
        "probe-failure pressure is external — must not delete own data"
    );
    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 2, "both rows must survive — nothing deleted");
}

/// syslog-mcp-w4hh (review bug #1, unit-level): with the guardrail DISABLED
/// (`min_free_disk_mb == 0`), a probe failure must NOT engage the block — the
/// fail-closed behavior is scoped to the case where the operator asked for the
/// guardrail. This pins both halves of the trigger/write-block decision.
#[test]
fn probe_failure_with_guardrail_disabled_does_not_block() {
    let metrics = StorageMetrics {
        logical_db_size_bytes: 0,
        physical_db_size_bytes: 0,
        free_disk_bytes: None, // probe failed
    };
    let mut config = StorageConfig::for_test(std::path::PathBuf::from("/tmp/x.db"));
    config.min_free_disk_mb = 0;
    config.recovery_free_disk_mb = 0;

    assert!(
        !super::disk_free_below_trigger(&metrics, &config),
        "disabled guardrail must not trigger on a failed probe"
    );
    assert!(
        !super::disk_pressure_write_blocked(&metrics, &config, false),
        "disabled guardrail must not write-block on a failed probe"
    );

    // And with the guardrail ENABLED, the same None must engage both.
    config.min_free_disk_mb = 512;
    config.recovery_free_disk_mb = 768;
    assert!(
        super::disk_free_below_trigger(&metrics, &config),
        "enabled guardrail must treat a failed probe as below the floor"
    );
    assert!(
        super::disk_pressure_write_blocked(&metrics, &config, false),
        "enabled guardrail must write-block on a failed probe"
    );
}

/// syslog-mcp-w4hh (review bug #2 — TIMESTAMP FORMAT): `received_at` is stored with
/// MILLISECOND precision (e.g. "...:27.680Z"). The err+ floor `window_start` must be
/// formatted the same way. A second-precision cutoff like "...:27Z" sorts AFTER
/// "...:27.680Z" lexicographically ('Z'=0x5A > '.'=0x2E), so a row that is genuinely
/// inside the window would be judged outside it and lose protection. This test pins
/// a recent err row whose received_at carries fractional seconds and verifies it is
/// protected by the floor (deleted_rows comes only from the deletable info row).
#[test]
fn err_floor_window_matches_fractional_second_received_at() {
    let window_hours = 1i64;
    let big_info = "info-junk-".repeat(120_000);
    let big_err = "err-keep-".repeat(120_000);

    // Place the protected err row's received_at in the SAME WHOLE SECOND as the
    // floor cutoff, with a `.999` fractional part. The cutoff is computed inside
    // the function as `Utc::now() - window_hours`; we mirror that here. This is
    // the only arrangement that exercises bug #2: a row a few seconds inside the
    // window never reaches the fractional position (the date/second fields
    // differ), so it passes under BOTH formats and proves nothing.
    //
    // Discrimination at the boundary second "HH:MM:SS":
    //   - Correct (Millis) cutoff "HH:MM:SS.mmmZ" with mmm < 999 → row ".999Z" >=
    //     cutoff → PROTECTED (this is the fix).
    //   - Buggy (second) cutoff "HH:MM:SSZ" → comparing "...SS.999Z" vs "...SSZ",
    //     the char after "SS" is '.'(0x2E) < 'Z'(0x5A), so row < cutoff → NOT
    //     protected → deleted.
    //
    // Determinism: the function captures its OWN `Utc::now()` between our two
    // bracket reads (`now_before` … `enforce_storage_budget` … `now_after`).
    // We only assert when BOTH brackets floor `(now − window)` to the SAME whole
    // second — which, since the function's `now` lies between them and floor is
    // monotonic, proves the function shared that boundary second. If a
    // whole-second boundary was crossed mid-op (possible under heavy parallel
    // load), the arrangement is invalid, so we retry with fresh data instead of
    // flaking — no wall-clock-headroom guessing.
    let floor_minus_window = |t: chrono::DateTime<chrono::Utc>| {
        (t - chrono::TimeDelta::hours(window_hours))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string()
    };

    for _ in 0..200 {
        let (pool, dir) = test_pool();
        insert_logs_batch(
            &pool,
            &[
                make_entry("2026-01-01T00:00:01Z", "host-a", "info", &big_info),
                make_entry("2026-01-01T00:00:02Z", "host-a", "err", &big_err),
            ],
        )
        .unwrap();
        // Oldest, deletable info row.
        update_received_at(&pool, &big_info, "2026-01-01T00:00:00Z");

        let now_before = chrono::Utc::now();
        let boundary_second = floor_minus_window(now_before);
        let recent_ts = format!("{boundary_second}.999Z");
        update_received_at(&pool, &big_err, &recent_ts);

        let mut config = test_storage_config(dir.path().join("test.db"));
        config.max_db_size_mb = 2;
        config.recovery_db_size_mb = 1;
        config.min_free_disk_mb = 0;
        config.recovery_free_disk_mb = 0;
        config.cleanup_chunk_size = 1;
        config.err_floor_window_hours = window_hours as u64;
        config.err_floor_per_source_cap = 10_000;

        let outcome = enforce_storage_budget(&pool, &config).unwrap();
        let now_after = chrono::Utc::now();

        // Boundary crossed during the op → the function's cutoff second may not
        // match our fixture. Discard this attempt and rebuild.
        if floor_minus_window(now_after) != boundary_second {
            continue;
        }

        let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
        let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
        assert!(
            messages.contains(&big_err.as_str()),
            "recent err+ with fractional-second received_at must be protected by the floor"
        );
        assert!(
            !messages.contains(&big_info.as_str()),
            "the deletable info row should have been trimmed"
        );
        assert!(
            outcome.write_blocked,
            "still over cap after floor protected the err row → writes blocked"
        );
        return;
    }

    panic!(
        "could not align the cutoff whole-second within 200 attempts (excessive scheduling jitter)"
    );
}

/// syslog-mcp-w4hh (review bug #3 — heartbeat fallthrough): during a DB-SIZE breach,
/// when the OLDEST telemetry is logs but that chunk is fully err+-floor-protected
/// (delete returns 0), deletable heartbeats may still remain (newer than the
/// protected logs). The self-trim loop must fall through to trimming heartbeats
/// before declaring write_blocked, rather than blocking prematurely.
#[test]
fn self_trim_falls_through_to_heartbeats_when_logs_floor_protected() {
    let (pool, dir) = test_pool();
    // A large, recent, floor-protected err log is the OLDEST telemetry. Heartbeats
    // are NEWER, so oldest_telemetry_source picks logs first — and that chunk is
    // fully protected (0 deleted). Deletable heartbeats remain.
    let big_err = "err-protected-".repeat(120_000);
    let now = chrono::Utc::now();
    let err_ts =
        (now - chrono::TimeDelta::minutes(10)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let hb_ts = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    insert_logs_batch(&pool, &[make_entry(&err_ts, "host-a", "err", &big_err)]).unwrap();
    update_received_at(&pool, &big_err, &err_ts);
    // Insert several heartbeats (newer than the err row) — these are deletable.
    for i in 0..5 {
        insert_heartbeat(&pool, &format!("hb-host-{i}"), &hb_ts);
    }

    let mut config = test_storage_config(dir.path().join("test.db"));
    config.max_db_size_mb = 1;
    config.recovery_db_size_mb = 1;
    config.min_free_disk_mb = 0;
    config.recovery_free_disk_mb = 0;
    config.cleanup_chunk_size = 1;
    config.err_floor_window_hours = 24; // protects the err row
    config.err_floor_per_source_cap = 10_000;

    let hb_before: i64 = {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT COUNT(*) FROM host_heartbeats", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(hb_before, 5);

    let outcome = enforce_storage_budget(&pool, &config).unwrap();

    // The protected err log must survive.
    let rows = tail_logs(&pool, None, None, None, None, 10).unwrap();
    let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    assert!(
        messages.contains(&big_err.as_str()),
        "floor-protected err row must survive"
    );
    // At least one heartbeat must have been trimmed (the fallthrough engaged)
    // rather than the loop blocking immediately on the 0-deleted log chunk.
    let hb_after: i64 = {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT COUNT(*) FROM host_heartbeats", [], |r| r.get(0))
            .unwrap()
    };
    assert!(
        hb_after < hb_before,
        "deletable heartbeats must be trimmed via fallthrough (before: {hb_before}, after: {hb_after})"
    );
    assert!(
        outcome.deleted_rows > 0,
        "fallthrough must report the heartbeat rows it trimmed"
    );
}

fn insert_llm_invocation(pool: &DbPool, id: &str, started_at: &str) {
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO llm_invocations (id, started_at, caller_surface, action, provider, status)
         VALUES (?1, ?2, 'cli', 'ai_assess', 'gemini-cli', 'completed')",
        params![id, started_at],
    )
    .unwrap();
}

fn count_llm_invocations(pool: &DbPool) -> i64 {
    let conn = pool.get().unwrap();
    conn.query_row("SELECT COUNT(*) FROM llm_invocations", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn test_purge_old_llm_invocations_removes_old() {
    let (pool, _dir) = test_pool();
    insert_llm_invocation(&pool, "old-1", "2020-01-01T00:00:00.000Z");
    insert_llm_invocation(&pool, "new-1", "2099-01-01T00:00:00.000Z");

    let deleted = purge_old_llm_invocations(&pool, 90, 1000).unwrap();
    assert_eq!(deleted, 1, "should delete exactly the old row");
    assert_eq!(count_llm_invocations(&pool), 1);
}

#[test]
fn test_purge_old_llm_invocations_zero_retention_noop() {
    let (pool, _dir) = test_pool();
    insert_llm_invocation(&pool, "old-1", "2020-01-01T00:00:00.000Z");

    let deleted = purge_old_llm_invocations(&pool, 0, 1000).unwrap();
    assert_eq!(deleted, 0, "retention_days=0 should be a no-op");
    assert_eq!(count_llm_invocations(&pool), 1);
}

#[test]
fn test_purge_old_llm_invocations_chunked() {
    let (pool, _dir) = test_pool();
    for i in 0..5 {
        insert_llm_invocation(&pool, &format!("old-{i}"), "2020-01-01T00:00:00.000Z");
    }
    insert_llm_invocation(&pool, "new-1", "2099-01-01T00:00:00.000Z");

    // chunk_size smaller than the deletable set exercises the loop-until-empty path.
    let deleted = purge_old_llm_invocations(&pool, 90, 2).unwrap();
    assert_eq!(deleted, 5);
    assert_eq!(count_llm_invocations(&pool), 1);
}

/// Regression test for the lexicographic-cutoff bug: a cutoff formatted
/// without fractional seconds (e.g. `...:50Z`) does not sort consistently
/// against `started_at` values that DO carry fractional seconds (SQLite
/// writes `started_at` via `strftime('%Y-%m-%dT%H:%M:%fZ','now')`). Seed two
/// rows within the same wall-clock second that straddle a
/// millisecond-precision cutoff, and confirm the purge honors true
/// chronological order rather than string comparison.
#[test]
fn test_purge_old_llm_invocations_millisecond_precision_ordering() {
    let (pool, _dir) = test_pool();

    // Two rows within the same wall-clock second, one just after and one
    // just before a cutoff that sits between them.
    insert_llm_invocation(&pool, "just-before-cutoff", "2020-01-01T00:00:50.000001Z");
    insert_llm_invocation(&pool, "just-after-cutoff", "2020-01-01T00:00:50.999999Z");

    // Directly exercise the cutoff-comparison SQL with a hand-built cutoff
    // straddling the two rows, to pin down true chronological behavior
    // independent of `Utc::now()` in the production function.
    let cutoff = "2020-01-01T00:00:50.500000Z";
    let conn = pool.get().unwrap();
    let deleted = conn
        .execute(
            "DELETE FROM llm_invocations WHERE id IN (
                 SELECT id FROM llm_invocations
                 WHERE started_at < ?1
                 LIMIT 1000
             )",
            params![cutoff],
        )
        .unwrap();
    drop(conn);

    assert_eq!(
        deleted, 1,
        "exactly the row before the cutoff must be deleted"
    );

    let conn = pool.get().unwrap();
    let remaining_id: String = conn
        .query_row("SELECT id FROM llm_invocations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        remaining_id, "just-after-cutoff",
        "the row chronologically after the cutoff must survive"
    );
}

/// End-to-end regression test through the real production function: the
/// cutoff it formats must retain millisecond precision so that a row
/// inserted a fraction of a second before `Utc::now() - retention_days` is
/// correctly purged instead of surviving due to a lexicographic-comparison
/// mismatch against a coarser cutoff string.
#[test]
fn test_purge_old_llm_invocations_cutoff_has_fractional_seconds() {
    let (pool, _dir) = test_pool();

    // A row just past the retention boundary, 1s before now-90days (a 1ms
    // margin would be too tight here: both the stored timestamp and the
    // cutoff are formatted at millisecond precision, so rounding/truncation
    // could collapse a 1ms delta to zero and make this test flaky).
    let boundary =
        (chrono::Utc::now() - chrono::TimeDelta::days(90) - chrono::TimeDelta::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    insert_llm_invocation(&pool, "at-boundary", &boundary);

    let deleted = purge_old_llm_invocations(&pool, 90, 1000).unwrap();
    assert_eq!(
        deleted, 1,
        "row just past the retention boundary must be purged; a cutoff \
         missing fractional-second precision could misorder it"
    );
    assert_eq!(count_llm_invocations(&pool), 0);
}

/// `delete_orphan_heartbeat_children` scans for orphan rowids in one statement
/// and deletes them in another, which is only safe because a deleted
/// heartbeat's id is never reissued — otherwise a rowid could gain a live
/// parent between the two phases and take a real row with it.
///
/// `AUTOINCREMENT` is what guarantees that. Pin it, so rebuilding the table
/// without it fails here instead of silently deleting live metric rows.
#[test]
fn host_heartbeats_id_is_autoincrement_so_orphan_rowids_stay_orphans() {
    let (pool, _dir) = test_pool();
    let conn = pool.get().unwrap();
    let schema: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'host_heartbeats'",
            [],
            |row| row.get(0),
        )
        .expect("host_heartbeats table should exist");

    assert!(
        schema.to_ascii_uppercase().contains("AUTOINCREMENT"),
        "host_heartbeats.id must stay AUTOINCREMENT: the two-phase orphan sweep \
         relies on ids never being reused. Without it, revert \
         delete_orphan_heartbeat_children to a single atomic \
         DELETE ... WHERE NOT EXISTS. Schema was: {schema}"
    );
}
