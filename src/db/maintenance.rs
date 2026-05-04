use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use rusqlite::params;

use crate::config::StorageConfig;

use super::models::{StorageEnforcementOutcome, StorageMetrics, StorageRecovery};
use super::pool::DbPool;

pub trait DiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64>;
}

struct SystemDiskSpaceProbe;

impl DiskSpaceProbe for SystemDiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64> {
        let stats = rustix::fs::statvfs(path)?;
        Ok(stats.f_bavail.saturating_mul(stats.f_bsize))
    }
}

pub fn get_storage_metrics(pool: &DbPool, config: &StorageConfig) -> Result<StorageMetrics> {
    get_storage_metrics_with_probe(pool, config, &SystemDiskSpaceProbe)
}

pub fn get_storage_metrics_with_probe(
    pool: &DbPool,
    config: &StorageConfig,
    probe: &impl DiskSpaceProbe,
) -> Result<StorageMetrics> {
    let conn = pool.get()?;
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let freelist_count: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    drop(conn);

    let logical_db_size_bytes = ((page_count - freelist_count).max(0) * page_size).max(0) as u64;
    let physical_db_size_bytes = physical_db_size_bytes(&config.db_path)?;
    let free_disk_bytes = probe
        .free_bytes(config.db_path.parent().unwrap_or_else(|| Path::new(".")))
        .ok();
    tracing::debug!(
        logical_db_size_bytes,
        physical_db_size_bytes,
        free_disk_bytes = ?free_disk_bytes,
        db_path = %config.db_path.display(),
        "Collected storage metrics"
    );

    Ok(StorageMetrics {
        logical_db_size_bytes,
        physical_db_size_bytes,
        free_disk_bytes,
    })
}

pub fn enforce_storage_budget(
    pool: &DbPool,
    config: &StorageConfig,
) -> Result<StorageEnforcementOutcome> {
    enforce_storage_budget_with_probe(pool, config, &SystemDiskSpaceProbe)
}

pub fn enforce_storage_budget_with_probe(
    pool: &DbPool,
    config: &StorageConfig,
    probe: &impl DiskSpaceProbe,
) -> Result<StorageEnforcementOutcome> {
    let recovery = recovery_targets(config);
    let mut deleted_rows = 0usize;
    let mut all_hosts: std::collections::HashSet<String> = Default::default();

    let mut metrics = get_storage_metrics_with_probe(pool, config, probe)?;
    tracing::debug!(
        logical_db_size_bytes = metrics.logical_db_size_bytes,
        physical_db_size_bytes = metrics.physical_db_size_bytes,
        free_disk_bytes = ?metrics.free_disk_bytes,
        max_db_size_mb = config.max_db_size_mb,
        recovery_db_size_mb = config.recovery_db_size_mb,
        min_free_disk_mb = config.min_free_disk_mb,
        recovery_free_disk_mb = config.recovery_free_disk_mb,
        "Storage budget enforcement check started"
    );
    if !storage_limits_enabled(config) {
        tracing::debug!("Storage limits disabled — skipping enforcement");
        return Ok(StorageEnforcementOutcome {
            metrics,
            recovery,
            deleted_rows,
            write_blocked: false,
        });
    }

    while exceeds_trigger(&metrics, config) || !within_recovery(&metrics, &recovery, config) {
        tracing::warn!(
            logical_db_size_bytes = metrics.logical_db_size_bytes,
            physical_db_size_bytes = metrics.physical_db_size_bytes,
            free_disk_bytes = ?metrics.free_disk_bytes,
            deleted_rows,
            "Storage budget exceeded recovery target — deleting oldest logs chunk"
        );
        let deleted = delete_oldest_logs_chunk(pool, config.cleanup_chunk_size)?;
        if deleted.deleted_rows == 0 {
            metrics = get_storage_metrics_with_probe(pool, config, probe)?;
            let write_blocked = exceeds_trigger(&metrics, config);
            tracing::warn!(
                logical_db_size_bytes = metrics.logical_db_size_bytes,
                free_disk_bytes = ?metrics.free_disk_bytes,
                deleted_rows,
                write_blocked,
                "Storage budget enforcement could not delete more rows"
            );
            return Ok(StorageEnforcementOutcome {
                metrics,
                recovery,
                deleted_rows,
                write_blocked,
            });
        }

        deleted_rows += deleted.deleted_rows;
        tracing::info!(
            deleted_rows = deleted.deleted_rows,
            total_deleted_rows = deleted_rows,
            affected_hosts = deleted.hostnames.len(),
            "Deleted oldest log chunk for storage recovery"
        );
        all_hosts.extend(deleted.hostnames);
        metrics = get_storage_metrics_with_probe(pool, config, probe)?;
    }

    if deleted_rows > 0 {
        // Reconcile hosts once after all chunks — avoids N×3 SQL round-trips
        // (one per chunk × 3 queries per hostname) competing with the batch writer.
        let host_list: Vec<String> = all_hosts.into_iter().collect();
        reconcile_hosts(pool, &host_list)?;

        // Incremental FTS merge — clean up phantom rows left by bulk deletes
        // (DELETE trigger is intentionally absent).
        // drop the connection before checkpoint_wal_and_incremental_vacuum to
        // avoid pool exhaustion when pool_size = 1.
        fts_incremental_merge(pool, deleted_rows);

        checkpoint_wal_and_incremental_vacuum(pool)?;
    }

    tracing::debug!(
        deleted_rows,
        logical_db_size_bytes = metrics.logical_db_size_bytes,
        physical_db_size_bytes = metrics.physical_db_size_bytes,
        free_disk_bytes = ?metrics.free_disk_bytes,
        "Storage budget enforcement completed"
    );

    Ok(StorageEnforcementOutcome {
        metrics,
        recovery,
        deleted_rows,
        write_blocked: false,
    })
}

/// Run an incremental FTS5 merge to clean up phantom rows left by bulk DELETEs.
///
/// A single `merge=500,250` call processes at most ~500 FTS index pages, which
/// covers <1% of phantoms after a 500k-row delete. This function scales the
/// number of merge iterations proportionally to `deleted_rows` (one iteration
/// per 5 000 rows, capped at 20) and falls back to a forced `rebuild` after
/// 3 consecutive failures — a last-resort recovery for a corrupt or severely
/// fragmented FTS index.
///
/// Best-effort: errors are logged but never propagated.
fn fts_incremental_merge(pool: &DbPool, deleted_rows: usize) {
    // Budget one merge=500,250 call per 5 000 deleted rows (rough heuristic),
    // with a floor of 1 and a ceiling of 20 to bound wall-clock time.
    let iterations = deleted_rows.div_ceil(5000).clamp(1, 20);
    let mut consecutive_failures: u32 = 0;

    for i in 0..iterations {
        match pool.get() {
            Ok(conn) => {
                match conn.execute_batch("INSERT INTO logs_fts(logs_fts) VALUES('merge=500,250');")
                {
                    Ok(()) => {
                        consecutive_failures = 0;
                        tracing::trace!(
                            iteration = i + 1,
                            total_iterations = iterations,
                            "FTS incremental merge iteration"
                        );
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        tracing::warn!(
                            error = %e,
                            iteration = i + 1,
                            consecutive_failures,
                            "FTS incremental merge failed"
                        );
                        if consecutive_failures >= 3 {
                            // Escalate to full rebuild — last-resort recovery for a
                            // corrupt or severely fragmented FTS index.
                            match pool.get() {
                                Ok(rebuild_conn) => {
                                    if let Err(e) = rebuild_conn.execute_batch(
                                        "INSERT INTO logs_fts(logs_fts) VALUES('rebuild');",
                                    ) {
                                        tracing::error!(error = %e, "FTS forced rebuild failed");
                                    } else {
                                        tracing::error!(
                                            "FTS incremental merge failed 3 times; forced rebuild completed"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "FTS forced rebuild: failed to get connection"
                                    );
                                }
                            }
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "FTS incremental merge: failed to get connection");
                consecutive_failures += 1;
                if consecutive_failures >= 3 {
                    tracing::error!(
                        "FTS incremental merge: 3 consecutive connection failures, giving up"
                    );
                    return;
                }
            }
        }
    }
}

/// Purge logs older than N days.
///
/// Uses chunked DELETEs (10 000 rows per iteration) so the WAL write lock is
/// released between chunks, letting the batch writer proceed without timing out
/// or overflowing its 1 000-entry cap.  After all chunks complete, an
/// incremental FTS5 merge is issued instead of a full rebuild — `merge=500,250`
/// processes at most a bounded number of index pages per call and holds the
/// write lock for milliseconds rather than seconds.
pub fn purge_old_logs(pool: &DbPool, retention_days: u32) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }

    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(retention_days as i64))
        .ok_or_else(|| {
            anyhow::anyhow!("date arithmetic overflow for retention_days={retention_days}")
        })?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Chunked DELETE: each iteration acquires a fresh connection from the pool
    // and releases it (along with its write lock) before sleeping, giving the
    // batch writer a window to acquire a connection between chunks.
    // Use received_at (server clock) instead of timestamp (device clock) so that
    // a device with a misconfigured clock cannot cause its logs to be purged
    // immediately (future timestamp) or retained forever (past timestamp).
    let mut total_deleted: usize = 0;
    loop {
        let conn = pool.get()?;
        let chunk = conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs WHERE received_at < ?1 LIMIT 10000
             )",
            params![cutoff],
        )?;
        total_deleted += chunk;
        drop(conn); // release back to pool before sleeping
        if chunk == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Incremental FTS merge — much shorter write-lock duration than full rebuild.
    if total_deleted > 0 {
        fts_incremental_merge(pool, total_deleted);
    }

    // Passive WAL checkpoint: attempt to move WAL pages into the main DB file
    // without blocking writers. Prevents unbounded WAL growth between restarts.
    {
        let conn = pool.get()?;
        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
            tracing::warn!(error = %e, "WAL checkpoint skipped (non-fatal)");
        }
    }

    tracing::info!(deleted = total_deleted, cutoff = %cutoff, "Purged old logs");
    Ok(total_deleted)
}

#[derive(Debug)]
struct DeletedChunk {
    deleted_rows: usize,
    hostnames: Vec<String>,
}

fn delete_oldest_logs_chunk(pool: &DbPool, chunk_size: usize) -> Result<DeletedChunk> {
    let conn = pool.get()?;

    // Collect distinct hostnames from the chunk we're about to delete.
    // Use a subquery instead of a dynamic IN-list to avoid SQLite expression
    // depth limit (default 1000) at large chunk sizes.
    let hostnames: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT hostname FROM logs \
             WHERE id IN (SELECT id FROM logs ORDER BY received_at ASC, id ASC LIMIT ?1)",
        )?;
        let result = stmt
            .query_map([chunk_size as i64], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        result
    };

    // Delete the oldest chunk using a subquery — O(1) SQL string size regardless
    // of chunk_size, no expression depth issues.
    let deleted_rows = conn.execute(
        "DELETE FROM logs \
         WHERE id IN (SELECT id FROM logs ORDER BY received_at ASC, id ASC LIMIT ?1)",
        [chunk_size as i64],
    )?;

    tracing::debug!(
        deleted_rows,
        affected_hosts = hostnames.len(),
        chunk_size,
        "Deleted oldest logs chunk"
    );

    Ok(DeletedChunk {
        deleted_rows,
        hostnames,
    })
}

fn reconcile_hosts(pool: &DbPool, hostnames: &[String]) -> Result<()> {
    if hostnames.is_empty() {
        return Ok(());
    }

    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    for hostname in hostnames {
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;

        if count == 0 {
            tx.execute("DELETE FROM hosts WHERE hostname = ?1", [hostname])?;
            continue;
        }

        let first_seen: String = tx.query_row(
            "SELECT MIN(received_at) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;
        let last_seen: String = tx.query_row(
            "SELECT MAX(received_at) FROM logs WHERE hostname = ?1",
            [hostname],
            |row| row.get(0),
        )?;
        tx.execute(
            "UPDATE hosts
             SET first_seen = ?2, last_seen = ?3, log_count = ?4
             WHERE hostname = ?1",
            params![hostname, first_seen, last_seen, count],
        )?;
    }
    tx.commit()?;
    tracing::debug!(
        host_count = hostnames.len(),
        "Reconciled host aggregates after log deletion"
    );
    Ok(())
}

fn checkpoint_wal_and_incremental_vacuum(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;
    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
        tracing::warn!(error = %e, "WAL checkpoint skipped (non-fatal)");
    } else {
        tracing::debug!("WAL checkpoint completed");
    }
    if let Err(e) = conn.execute_batch("PRAGMA incremental_vacuum(1000);") {
        tracing::warn!(error = %e, "incremental vacuum skipped (non-fatal)");
    } else {
        tracing::debug!("Incremental vacuum completed");
    }
    Ok(())
}

fn storage_limits_enabled(config: &StorageConfig) -> bool {
    config.max_db_size_mb > 0 || config.min_free_disk_mb > 0
}

fn recovery_targets(config: &StorageConfig) -> StorageRecovery {
    StorageRecovery {
        logical_db_size_bytes: mb_to_bytes(config.recovery_db_size_mb),
        free_disk_bytes: (config.min_free_disk_mb > 0)
            .then(|| mb_to_bytes(config.recovery_free_disk_mb)),
    }
}

pub(crate) fn exceeds_trigger(metrics: &StorageMetrics, config: &StorageConfig) -> bool {
    (config.max_db_size_mb > 0
        && metrics.logical_db_size_bytes > mb_to_bytes(config.max_db_size_mb))
        || (config.min_free_disk_mb > 0
            && metrics.free_disk_bytes.unwrap_or(0) < mb_to_bytes(config.min_free_disk_mb))
}

fn within_recovery(
    metrics: &StorageMetrics,
    recovery: &StorageRecovery,
    config: &StorageConfig,
) -> bool {
    let db_ok = config.max_db_size_mb == 0
        || metrics.logical_db_size_bytes <= recovery.logical_db_size_bytes;
    let disk_ok = config.min_free_disk_mb == 0
        || metrics.free_disk_bytes.unwrap_or(0) >= recovery.free_disk_bytes.unwrap_or(0);
    db_ok && disk_ok
}

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1_048_576)
}

fn physical_db_size_bytes(db_path: &Path) -> Result<u64> {
    let mut total = file_size_if_exists(db_path)?;
    total += file_size_if_exists(&db_path.with_extension(format!(
        "{}-wal",
        db_path.extension().and_then(|ext| ext.to_str()).unwrap_or_default()
    )))?;
    total += file_size_if_exists(&db_path.with_extension(format!(
        "{}-shm",
        db_path.extension().and_then(|ext| ext.to_str()).unwrap_or_default()
    )))?;
    Ok(total)
}

fn file_size_if_exists(path: &Path) -> Result<u64> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
