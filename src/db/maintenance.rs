use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::config::StorageConfig;

use super::models::{StorageEnforcementOutcome, StorageMetrics, StorageRecovery};
use super::pool::DbPool;

/// Supported idempotent replay window for authenticated forwarding clients.
pub const FORWARD_RECEIPT_REPLAY_HORIZON_DAYS: u32 = 7;

/// Bound forwarding ledgers and remove receipts whose canonical evidence no
/// longer exists. Agents keep unacknowledged records in their durable spool;
/// after this horizon a retry is intentionally ingested as new evidence.
pub fn purge_forward_receipts(pool: &DbPool, chunk_size: usize) -> Result<usize> {
    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(i64::from(
            FORWARD_RECEIPT_REPLAY_HORIZON_DAYS,
        )))
        .ok_or_else(|| anyhow::anyhow!("receipt replay horizon overflow"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let limit = chunk_size.max(1).min(i64::MAX as usize) as i64;
    let mut total = 0;
    loop {
        let conn = crate::db::write_conn(pool)?;
        let syslog = conn.execute(
            "DELETE FROM syslog_forward_receipts WHERE rowid IN (
                 SELECT r.rowid FROM syslog_forward_receipts r
                 LEFT JOIN logs l ON l.id = r.canonical_log_id
                 WHERE r.received_at < ?1 OR l.id IS NULL LIMIT ?2)",
            params![cutoff, limit],
        )?;
        let transcripts = conn.execute(
            "DELETE FROM ai_transcript_forward_receipts WHERE rowid IN (
                 SELECT r.rowid FROM ai_transcript_forward_receipts r
                 LEFT JOIN logs l ON l.id = r.log_id
                 WHERE r.received_at < ?1 OR l.id IS NULL LIMIT ?2)",
            params![cutoff, limit],
        )?;
        total += syslog + transcripts;
        if syslog < limit as usize && transcripts < limit as usize {
            break;
        }
        drop(conn);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(total)
}

pub trait DiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64>;
}

pub struct SystemDiskSpaceProbe;

impl DiskSpaceProbe for SystemDiskSpaceProbe {
    fn free_bytes(&self, path: &Path) -> Result<u64> {
        free_bytes_impl(path)
    }
}

#[cfg(unix)]
fn free_bytes_impl(path: &Path) -> Result<u64> {
    let stats = rustix::fs::statvfs(path)?;
    Ok(stats.f_bavail.saturating_mul(stats.f_bsize))
}

#[cfg(windows)]
fn free_bytes_impl(path: &Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;

    // Declare GetDiskFreeSpaceExW inline — avoids adding a windows-sys dep.
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free_bytes: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        return Ok(free_bytes);
    }
    anyhow::bail!(
        "GetDiskFreeSpaceExW failed: {}",
        std::io::Error::last_os_error()
    )
}

#[cfg(not(any(unix, windows)))]
fn free_bytes_impl(path: &Path) -> Result<u64> {
    let _ = path;
    anyhow::bail!("free_bytes: unsupported platform")
}

pub fn get_storage_metrics(pool: &DbPool, config: &StorageConfig) -> Result<StorageMetrics> {
    get_storage_metrics_with_probe(pool, config, &SystemDiskSpaceProbe)
}

pub fn physical_size_bytes(path: &Path) -> Result<u64> {
    physical_db_size_bytes(path)
}

pub fn db_wal_checkpoint(pool: &DbPool, mode: &str) -> Result<(i64, i64, i64)> {
    let mode = match mode {
        "passive" => "PASSIVE",
        "full" => "FULL",
        "restart" => "RESTART",
        "truncate" => "TRUNCATE",
        other => anyhow::bail!("unsupported WAL checkpoint mode: {other}"),
    };
    let sql = format!("PRAGMA wal_checkpoint({mode})");
    let conn = pool.get()?;
    let result = conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    Ok(result)
}

pub fn wal_checkpoint_complete(busy: i64, log_frames: i64, checkpointed_frames: i64) -> bool {
    busy == 0 && checkpointed_frames >= log_frames
}

pub fn db_incremental_vacuum(pool: &DbPool, pages: u32) -> Result<()> {
    let conn = crate::db::write_conn(pool)?;
    conn.execute_batch(&format!("PRAGMA incremental_vacuum({pages});"))?;
    Ok(())
}

pub fn db_full_vacuum(pool: &DbPool) -> Result<()> {
    let conn = crate::db::write_conn(pool)?;
    conn.execute_batch("VACUUM;")?;
    Ok(())
}

/// Run `PRAGMA integrity_check` (full) or `PRAGMA quick_check` (skips
/// cross-row consistency, ~10x faster on multi-GB databases).
pub fn db_integrity_check(pool: &DbPool, quick: bool) -> Result<Vec<String>> {
    let conn = pool.get()?;
    let pragma = if quick {
        "quick_check"
    } else {
        "integrity_check"
    };
    let mut stmt = conn.prepare(&format!("PRAGMA {pragma}"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let messages = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(messages)
}

/// A row from the `maintenance_jobs` table (bead syslog-mcp-a4pd).
#[derive(Debug, Clone)]
pub struct MaintenanceJob {
    pub id: i64,
    pub kind: String,
    /// One of `running`, `done`, `failed`.
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// JSON-encoded result payload (present once terminal), e.g.
    /// `{"ok":true,"messages":["ok"]}` or `{"error":"..."}`.
    pub result_json: Option<String>,
}

/// Insert a new `running` maintenance job and return its id. Used by the
/// background `db integrity` path to record a job before spawning the check.
pub fn insert_maintenance_job(pool: &DbPool, kind: &str) -> Result<i64> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO maintenance_jobs (kind, status, started_at)
         VALUES (?1, 'running', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        [kind],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert a running maintenance job with an initial durable JSON payload.
pub fn insert_maintenance_job_with_result(
    pool: &DbPool,
    kind: &str,
    result_json: &str,
) -> Result<i64> {
    serde_json::from_str::<serde_json::Value>(result_json)
        .context("maintenance job result_json must be valid JSON")?;
    let conn = crate::db::write_conn(pool)?;
    conn.execute(
        "INSERT INTO maintenance_jobs (kind, status, started_at, result_json)
         VALUES (?1, 'running', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?2)",
        rusqlite::params![kind, result_json],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Update the durable progress payload for a running maintenance job.
pub fn update_maintenance_job_progress(pool: &DbPool, id: i64, result_json: &str) -> Result<()> {
    serde_json::from_str::<serde_json::Value>(result_json)
        .context("maintenance job result_json must be valid JSON")?;
    let conn = crate::db::write_conn(pool)?;
    let changed = conn.execute(
        "UPDATE maintenance_jobs SET result_json = ?2 WHERE id = ?1 AND status = 'running'",
        rusqlite::params![id, result_json],
    )?;
    anyhow::ensure!(changed == 1, "running maintenance job not found");
    Ok(())
}

/// Mark a maintenance job terminal (`done`/`failed`) with its JSON result.
pub fn finish_maintenance_job(
    pool: &DbPool,
    id: i64,
    status: &str,
    result_json: &str,
) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE maintenance_jobs
            SET status = ?2,
                finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                result_json = ?3
          WHERE id = ?1",
        rusqlite::params![id, status, result_json],
    )?;
    Ok(())
}

/// Fetch a maintenance job by id, or `None` if no such job exists.
pub fn get_maintenance_job(pool: &DbPool, id: i64) -> Result<Option<MaintenanceJob>> {
    let conn = pool.get()?;
    let job = conn
        .query_row(
            "SELECT id, kind, status, started_at, finished_at, result_json
             FROM maintenance_jobs WHERE id = ?1",
            [id],
            |r| {
                Ok(MaintenanceJob {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    status: r.get(2)?,
                    started_at: r.get(3)?,
                    finished_at: r.get(4)?,
                    result_json: r.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(job)
}

/// Type-safe PRAGMA identifier. The `pub(crate)` field prevents external crates
/// from constructing arbitrary values — only crate-internal code can build one,
/// and only from `'static` str literals, enforcing the SQL interpolation contract.
pub(crate) struct PragmaName(pub(crate) &'static str);

/// Reads a trusted, hardcoded integer PRAGMA.
pub(crate) fn db_pragma_i64(pool: &DbPool, pragma: PragmaName) -> Result<i64> {
    let conn = pool.get()?;
    Ok(conn.query_row(&format!("PRAGMA {}", pragma.0), [], |row| row.get(0))?)
}

/// Reads a trusted, hardcoded string PRAGMA.
pub(crate) fn db_pragma_string(pool: &DbPool, pragma: PragmaName) -> Result<String> {
    let conn = pool.get()?;
    Ok(conn.query_row(&format!("PRAGMA {}", pragma.0), [], |row| row.get(0))?)
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
    // No prior write-block state — used by the initial enforcement call at
    // startup, before any tick has run. Hysteresis is a no-op on the first call.
    enforce_storage_budget_with_state(pool, config, probe, false)
}

/// Storage-budget enforcement with the previous tick's `write_blocked` state
/// threaded in for hysteresis on the EXTERNAL disk-pressure path.
///
/// Two INDEPENDENT policies (syslog-mcp-w4hh):
///   - **DB-size (self-trim):** `max_db_size_mb` measures cortex's OWN logical
///     bytes. Cortex can resolve this by trimming its own oldest data, so it
///     loops `delete_oldest_*_chunk` down to `recovery_db_size_mb` — UNLESS doing
///     so would breach the err+ retention floor, in which case it stops and sets
///     `write_blocked` rather than wiping irreplaceable high-severity history.
///   - **Free-disk (external pressure):** `min_free_disk_mb` measures the WHOLE
///     filesystem (statvfs). A neighbour process filling the shared volume is not
///     something cortex can fix by deleting its own rows, so it NEVER deletes for
///     this trigger — it sets `write_blocked` and relies on ingest back-pressure
///     (receiver/writer.rs) until free disk recovers. Hysteresis: block engages at
///     `min_free_disk_mb`, clears only at `recovery_free_disk_mb`.
pub fn enforce_storage_budget_with_state(
    pool: &DbPool,
    config: &StorageConfig,
    probe: &impl DiskSpaceProbe,
    prev_write_blocked: bool,
) -> Result<StorageEnforcementOutcome> {
    let recovery = recovery_targets(config);
    let mut deleted_rows = 0usize;
    let mut deleted_log_rows = 0usize;
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

    // EXTERNAL disk-pressure decision (no deletion). Evaluated with hysteresis
    // from the previous tick's state so the block engages at `min_free_disk_mb`
    // and clears only once free disk has climbed back to `recovery_free_disk_mb`.
    // The self-trim loop below runs INDEPENDENTLY of this — both can be active in
    // the same tick (DB over its cap AND the filesystem low on free space).
    let mut disk_write_blocked = disk_pressure_write_blocked(&metrics, config, prev_write_blocked);
    if disk_write_blocked {
        tracing::warn!(
            free_disk_bytes = ?metrics.free_disk_bytes,
            min_free_disk_mb = config.min_free_disk_mb,
            recovery_free_disk_mb = config.recovery_free_disk_mb,
            "Free-disk pressure detected — blocking writes WITHOUT deleting own data \
             (external whole-filesystem condition; cortex cannot resolve it by self-trim)"
        );
    }

    // SELF-TRIM loop: only the DB-size trigger drives deletion. Its recovery exit
    // is `logical <= recovery_db_size_mb` (the free-disk arm never gates it).
    if db_size_exceeds_trigger(&metrics, config) {
        // Orphan child rows are free space, so reclaim them before trimming
        // real telemetry. Hoisted out of the trim loop below: each sweep is a
        // full scan of all six heartbeat child tables, and
        // `delete_orphan_heartbeat_children` already loops internally until no
        // orphans remain — so running it per iteration re-scanned every table
        // on each pass even once the first call had drained them, on exactly
        // the code path that runs when the database is already under pressure.
        // Log-and-continue rather than `?`: reclaiming orphans is an
        // optimisation, and a transient pool timeout here must not abort the
        // trim that is supposed to relieve a full disk.
        let deleted_orphan_children =
            match delete_orphan_heartbeat_children(pool, config.cleanup_chunk_size) {
                Ok(deleted) => deleted,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Orphan heartbeat sweep failed during storage recovery; continuing to trim"
                    );
                    0
                }
            };
        if deleted_orphan_children > 0 {
            deleted_rows += deleted_orphan_children;
            tracing::info!(
                deleted_rows = deleted_orphan_children,
                total_deleted_rows = deleted_rows,
                "Deleted orphan heartbeat child rows for storage recovery"
            );
            metrics = get_storage_metrics_with_probe(pool, config, probe)?;
        }

        while !db_size_within_recovery(&metrics, &recovery, config) {
            tracing::warn!(
                logical_db_size_bytes = metrics.logical_db_size_bytes,
                physical_db_size_bytes = metrics.physical_db_size_bytes,
                deleted_rows,
                "DB-size budget exceeded — self-trimming oldest telemetry chunk"
            );

            let deleted = match oldest_telemetry_source(pool)? {
                Some(TelemetrySource::Heartbeats) => {
                    let deleted = delete_oldest_heartbeats_chunk(pool, config.cleanup_chunk_size)?;
                    DeletedTelemetryChunk {
                        deleted_rows: deleted,
                        log_hostnames: Vec::new(),
                        source: TelemetrySource::Heartbeats,
                    }
                }
                Some(TelemetrySource::Logs) => {
                    let deleted =
                        delete_oldest_logs_chunk(pool, config.cleanup_chunk_size, config)?;
                    DeletedTelemetryChunk {
                        deleted_rows: deleted.deleted_rows,
                        log_hostnames: deleted.hostnames,
                        source: TelemetrySource::Logs,
                    }
                }
                None => DeletedTelemetryChunk {
                    deleted_rows: 0,
                    log_hostnames: Vec::new(),
                    source: TelemetrySource::Logs,
                },
            };
            // Floor-protection fallthrough: if the OLDEST source was logs but the
            // chunk was fully err+-floor-protected (0 deleted), deletable heartbeats
            // may still exist (they are simply newer than the protected logs, so
            // `oldest_telemetry_source` picked logs). Trim a heartbeat chunk before
            // concluding nothing is deletable — otherwise a DB-size breach would
            // prematurely block writes while reclaimable heartbeat space remains.
            let deleted = if deleted.deleted_rows == 0 && deleted.source == TelemetrySource::Logs {
                let hb = delete_oldest_heartbeats_chunk(pool, config.cleanup_chunk_size)?;
                if hb > 0 {
                    tracing::info!(
                        deleted_rows = hb,
                        "Oldest logs were floor-protected; trimmed heartbeat chunk instead"
                    );
                }
                DeletedTelemetryChunk {
                    deleted_rows: hb,
                    log_hostnames: Vec::new(),
                    source: TelemetrySource::Heartbeats,
                }
            } else {
                deleted
            };

            if deleted.deleted_rows == 0 {
                // Could not delete any more deletable rows. This is either an empty
                // DB or — the case the err+ floor exists for — every remaining row
                // is floor-protected AND no heartbeats remain to trim. Either way we
                // stop trimming and BLOCK writes rather than wiping protected err+
                // history to chase the DB cap.
                metrics = get_storage_metrics_with_probe(pool, config, probe)?;
                let still_over = db_size_exceeds_trigger(&metrics, config);
                tracing::warn!(
                    logical_db_size_bytes = metrics.logical_db_size_bytes,
                    free_disk_bytes = ?metrics.free_disk_bytes,
                    deleted_rows,
                    db_size_still_over = still_over,
                    "Self-trim halted — no further deletable rows (err+ floor reached \
                     or DB empty); blocking writes instead of deleting protected data"
                );
                return Ok(StorageEnforcementOutcome {
                    metrics,
                    recovery,
                    deleted_rows,
                    // Block if EITHER the DB is still over cap with nothing left to
                    // safely trim, OR the external disk pressure was already latched.
                    write_blocked: still_over || disk_write_blocked,
                });
            }

            deleted_rows += deleted.deleted_rows;
            if deleted.source == TelemetrySource::Logs {
                deleted_log_rows += deleted.deleted_rows;
            }
            tracing::info!(
                deleted_rows = deleted.deleted_rows,
                total_deleted_rows = deleted_rows,
                source = ?deleted.source,
                affected_hosts = deleted.log_hostnames.len(),
                "Self-trimmed oldest telemetry chunk for storage recovery"
            );
            all_hosts.extend(deleted.log_hostnames);
            metrics = get_storage_metrics_with_probe(pool, config, probe)?;
        }
    }

    // Re-evaluate disk pressure against fresh metrics after any self-trim above
    // (self-trim frees real bytes, which can lift free disk back over recovery).
    disk_write_blocked = disk_pressure_write_blocked(&metrics, config, prev_write_blocked);

    if deleted_rows > 0 {
        // Reconcile hosts once after all chunks — avoids N×3 SQL round-trips
        // (one per chunk × 3 queries per hostname) competing with the batch writer.
        let host_list: Vec<String> = all_hosts.into_iter().collect();
        reconcile_hosts(pool, &host_list)?;

        // Incremental FTS merge — clean up phantom rows left by bulk deletes
        // (DELETE trigger is intentionally absent).
        // drop the connection before checkpoint_wal_and_incremental_vacuum to
        // avoid pool exhaustion when pool_size = 1.
        // Pass 0 here so the merge uses DEFAULT_FTS_MERGE_PAGES — storage
        // enforcement is rare and the tunable page budget only matters for the
        // regular retention path.
        if deleted_log_rows > 0 {
            fts_incremental_merge(pool, deleted_log_rows, 0);
        }

        checkpoint_wal_and_incremental_vacuum(pool, config)?;
    }

    tracing::debug!(
        deleted_rows,
        logical_db_size_bytes = metrics.logical_db_size_bytes,
        physical_db_size_bytes = metrics.physical_db_size_bytes,
        free_disk_bytes = ?metrics.free_disk_bytes,
        write_blocked = disk_write_blocked,
        "Storage budget enforcement completed"
    );

    Ok(StorageEnforcementOutcome {
        metrics,
        recovery,
        deleted_rows,
        // The DB-size path resolves by self-trim and never blocks here; the only
        // reason to block on a clean completion is unresolved EXTERNAL disk pressure.
        write_blocked: disk_write_blocked,
    })
}

/// Run an incremental FTS5 merge to clean up phantom rows left by bulk DELETEs.
///
/// Uses the only valid FTS5 incremental-merge API — the two-column form
/// `INSERT INTO logs_fts(logs_fts, rank) VALUES('merge', N)` — where `N` is a
/// page budget: the merge processes at most ~N pages of the index and then
/// returns, holding the write lock for milliseconds rather than rewriting the
/// whole index. (The older `'merge=B,M'` STRING syntax this code used does not
/// exist in modern FTS5 and errors on every call.)
///
/// This function scales the number of merge iterations proportionally to
/// `deleted_rows` (one iteration per 5 000 rows, capped at 20) so a large bulk
/// delete reclaims more phantom space without any single call running long.
///
/// `merge_pages` is the per-call page budget (from `CORTEX_FTS_MERGE_PAGES`). A
/// value of 0 is treated as the default `DEFAULT_FTS_MERGE_PAGES` because 0
/// pages is a no-op in the two-arg API.
///
/// Best-effort: errors are logged but never propagated. A merge that finds
/// nothing to do returns OK (not an error), so ordinary "no phantoms" cycles do
/// not trigger any fallback. On a genuine error (e.g. a busy/locked DB, or real
/// index corruption) we log and stop — we deliberately do NOT auto-escalate to
/// `optimize` or `rebuild`, both of which are O(index-size) under the write lock
/// and were the source of the hourly OOM. Heavy repair is left to an
/// operator-initiated path (see `db_integrity_check`).
fn fts_incremental_merge(pool: &DbPool, deleted_rows: usize, merge_pages: u32) {
    // Budget one merge call per 5 000 deleted rows (rough heuristic), with a
    // floor of 1 and a ceiling of 20 to bound wall-clock time.
    let iterations = deleted_rows.div_ceil(5000).clamp(1, 20);
    // 0 pages is a no-op in the two-arg API, so map the "unconditional" sentinel
    // to a sane bounded budget. 500 matches the old block-size default.
    let pages: i64 = if merge_pages == 0 {
        DEFAULT_FTS_MERGE_PAGES
    } else {
        merge_pages as i64
    };

    for i in 0..iterations {
        match crate::db::write_conn(pool) {
            Ok(conn) => {
                match conn.execute(
                    "INSERT INTO logs_fts(logs_fts, rank) VALUES('merge', ?1)",
                    [pages],
                ) {
                    Ok(_) => {
                        tracing::trace!(
                            iteration = i + 1,
                            total_iterations = iterations,
                            pages,
                            "FTS incremental merge iteration"
                        );
                    }
                    Err(e) => {
                        // A correctly-formed merge only errors on a genuine
                        // operational problem (busy/locked) or real corruption.
                        // Log and stop — never auto-escalate to optimize/rebuild,
                        // which rewrite the entire index under the write lock.
                        tracing::warn!(
                            error = %e,
                            iteration = i + 1,
                            "FTS incremental merge failed; stopping (no auto optimize/rebuild)"
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "FTS incremental merge: failed to acquire the write lock and a connection"
                );
                return;
            }
        }
    }
}

/// Default per-call FTS5 merge page budget when `CORTEX_FTS_MERGE_PAGES` is 0.
/// 500 mirrors the historical block-size default and keeps each merge bounded.
const DEFAULT_FTS_MERGE_PAGES: i64 = 500;

/// Purge logs older than N days.
///
/// Uses chunked DELETEs (10 000 rows per iteration) so the WAL write lock is
/// released between chunks, letting the batch writer proceed without timing out
/// or overflowing its 1 000-entry cap.  After all chunks complete, an
/// incremental FTS5 merge is issued instead of a full rebuild — a bounded
/// `VALUES('merge', N)` call processes at most N index pages per call and holds
/// the write lock for milliseconds rather than seconds.
///
/// **High-severity exemption:** rows with `severity IN ('err','crit','alert','emerg')`
/// are excluded from time-based purge — they are never aged out by retention.
/// They CAN still be deleted by `enforce_storage_budget` under disk pressure
/// (oldest-first, no severity filter). Permanent err+ retention is therefore
/// only guaranteed if the DB never breaches `max_db_size_mb` or
/// `min_free_disk_mb`. See CLAUDE.md "Retention" for the policy interaction.
pub fn purge_old_logs(pool: &DbPool, retention_days: u32, fts_merge_pages: u32) -> Result<usize> {
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
        let conn = crate::db::write_conn(pool)?;
        let chunk = conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs
                 WHERE received_at < ?1
                   AND severity NOT IN ('err', 'crit', 'alert', 'emerg')
                 LIMIT 10000
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
        fts_incremental_merge(pool, total_deleted, fts_merge_pages);
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

/// Purge heartbeat samples older than N days.
///
/// Heartbeat tables do not rely on global SQLite foreign-key enforcement, so
/// child metric rows are deleted explicitly before their parent heartbeat rows.
/// Each chunk is its own short transaction to avoid starving log ingest.
pub fn purge_old_heartbeats(
    pool: &DbPool,
    retention_days: u32,
    chunk_size: usize,
    orphan_sweep: OrphanSweep,
) -> Result<usize> {
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

    let mut total_deleted = 0usize;
    let (orphan_children, orphan_latest) = match orphan_sweep {
        OrphanSweep::Run => (
            delete_orphan_heartbeat_children(pool, chunk_size)?,
            delete_orphan_heartbeat_latest(pool)?,
        ),
        OrphanSweep::Skip => (0, 0),
    };
    if orphan_children > 0 {
        tracing::warn!(
            deleted_rows = orphan_children,
            "Purged orphan heartbeat child rows"
        );
        total_deleted += orphan_children;
    }
    if orphan_latest > 0 {
        tracing::warn!(
            deleted_rows = orphan_latest,
            "Purged orphan heartbeat latest cache rows"
        );
        total_deleted += orphan_latest;
    }
    loop {
        let deleted = delete_heartbeat_chunk_before(pool, &cutoff, chunk_size)?;
        total_deleted += deleted;
        if deleted == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    tracing::info!(
        deleted = total_deleted,
        cutoff = %cutoff,
        orphan_sweep = ?orphan_sweep,
        "Purged old heartbeats"
    );
    Ok(total_deleted)
}

/// Delete rows for a single `app_name` older than `max_days`.
///
/// Same chunked-DELETE pattern as [`purge_old_logs`] (10 000 rows per
/// iteration with the WAL lock released between chunks). Rows with
/// `severity IN ('err','crit','alert','emerg')` are excluded — high-severity
/// log entries are protected from time-based purge regardless of source.
///
/// Designed for short-retention tags (e.g. `adguard-allowed` at 7 days)
/// running on the new composite index `(app_name, received_at)` introduced
/// by Migration 3. **MUST run before [`purge_old_logs`]** in the maintenance
/// task to avoid SQLite write-lock contention from concurrent chunked
/// DELETEs over the same table.
///
/// Uses [`fts_incremental_merge`] after the loop because FTS5 DELETE triggers
/// were intentionally dropped in Migration 1 — phantoms otherwise accumulate.
pub fn purge_by_tag_window(
    pool: &DbPool,
    app_name: &str,
    max_days: u32,
    fts_merge_pages: u32,
) -> Result<usize> {
    if max_days == 0 {
        return Ok(0);
    }

    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(max_days as i64))
        .ok_or_else(|| anyhow::anyhow!("date arithmetic overflow for max_days={max_days}"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let mut total_deleted: usize = 0;
    loop {
        let conn = crate::db::write_conn(pool)?;
        let chunk = conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs
                 WHERE app_name = ?1
                   AND received_at < ?2
                   AND severity NOT IN ('err', 'crit', 'alert', 'emerg')
                 LIMIT 10000
             )",
            params![app_name, cutoff],
        )?;
        total_deleted += chunk;
        drop(conn);
        if chunk == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    if total_deleted > 0 {
        fts_incremental_merge(pool, total_deleted, fts_merge_pages);
    }

    tracing::info!(
        app_name,
        max_days,
        deleted = total_deleted,
        cutoff = %cutoff,
        "Purged tag window"
    );
    Ok(total_deleted)
}

/// Purge `llm_invocations` audit rows older than N days.
///
/// `llm_invocations` (migration 37, `src/db/llm_invocations.rs`) is the
/// shared audit trail for every LLM-backed assessment call (`ai_assess`
/// today; `skill_assess`/`mcp_assess`/`hook_assess` in later phases). Unlike
/// `logs`, rows here carry no severity concept, so there is no err+-style
/// exemption — retention applies uniformly to every row. Reuses the global
/// `CORTEX_RETENTION_DAYS` setting (0 disables, same as [`purge_old_logs`])
/// rather than a dedicated hardcoded cap like the AdGuard tags or heartbeats:
/// those exist to override the global policy because their volume would
/// otherwise dominate it, but invocation volume is bounded by `LlmRunner`'s
/// own per-minute/per-hour caps and is far lower than logs/heartbeats.
///
/// Same chunked-DELETE pattern as [`purge_old_logs`] (`chunk_size` rows per
/// iteration, WAL write lock released between chunks) keyed on `started_at`
/// (set from the server clock at invocation start, not a caller-supplied
/// value) rather than a client-controlled field. No FTS5 merge is needed —
/// `llm_invocations` is not indexed by `logs_fts`.
pub fn purge_old_llm_invocations(
    pool: &DbPool,
    retention_days: u32,
    chunk_size: usize,
) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }

    // `llm_invocations.started_at` is written by SQLite as
    // `strftime('%Y-%m-%dT%H:%M:%fZ','now')`, which includes millisecond
    // fractional seconds (e.g. `2026-07-01T20:09:50.850Z`). The cutoff must
    // carry the same precision: since the comparison is a lexicographic
    // string compare (`started_at < cutoff`), a cutoff formatted without
    // fractional seconds (e.g. `...:50Z`) does NOT sort the same as it would
    // as a real timestamp comparison — `"...:50Z"` can compare greater OR
    // less than `"...:50.850Z"` depending on the next byte (`Z` (0x5A) vs
    // `.` (0x2E)), misordering rows within the same second. Use
    // `SecondsFormat::Millis` (matches `%f`'s 3-digit precision) so the
    // comparison is safe.
    let cutoff = Utc::now()
        .checked_sub_signed(chrono::TimeDelta::days(retention_days as i64))
        .ok_or_else(|| {
            anyhow::anyhow!("date arithmetic overflow for retention_days={retention_days}")
        })?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut total_deleted: usize = 0;
    loop {
        let conn = crate::db::write_conn(pool)?;
        let chunk = conn.execute(
            "DELETE FROM llm_invocations WHERE id IN (
                 SELECT id FROM llm_invocations
                 WHERE started_at < ?1
                 LIMIT ?2
             )",
            params![cutoff, chunk_size as i64],
        )?;
        total_deleted += chunk;
        drop(conn); // release back to pool before sleeping
        if chunk == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    tracing::info!(
        deleted = total_deleted,
        cutoff = %cutoff,
        "Purged old llm_invocations rows"
    );
    Ok(total_deleted)
}

#[derive(Debug)]
struct DeletedChunk {
    deleted_rows: usize,
    hostnames: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelemetrySource {
    Logs,
    Heartbeats,
}

#[derive(Debug)]
struct DeletedTelemetryChunk {
    deleted_rows: usize,
    log_hostnames: Vec<String>,
    source: TelemetrySource,
}

fn oldest_telemetry_source(pool: &DbPool) -> Result<Option<TelemetrySource>> {
    let conn = pool.get()?;
    let oldest_log: Option<String> =
        conn.query_row("SELECT MIN(received_at) FROM logs", [], |row| row.get(0))?;
    let oldest_heartbeat: Option<String> =
        conn.query_row("SELECT MIN(received_at) FROM host_heartbeats", [], |row| {
            row.get(0)
        })?;

    Ok(match (oldest_log, oldest_heartbeat) {
        (Some(log), Some(heartbeat)) if heartbeat <= log => Some(TelemetrySource::Heartbeats),
        (Some(_), Some(_)) | (Some(_), None) => Some(TelemetrySource::Logs),
        (None, Some(_)) => Some(TelemetrySource::Heartbeats),
        (None, None) => None,
    })
}

/// Delete the oldest chunk of log rows for DB-size self-trim, honouring the
/// err+ retention FLOOR (syslog-mcp-w4hh).
///
/// The floor protects, per source IP, the most-recent `err_floor_per_source_cap`
/// rows whose `severity IN ('err','crit','alert','emerg')` received within the
/// last `err_floor_window_hours`. Those rows are EXCLUDED from the deletable set,
/// so self-trim destroys low-value telemetry first and never wipes recent,
/// per-source-bounded high-severity history to chase the DB-size cap.
///
/// Two security bounds (W1) make this safe against unauthenticated syslog:
///   - **time window** — only recent err+ is protected, so a hostile source
///     cannot pin the floor indefinitely with old severity=err spam;
///   - **per-source cap** — keyed on `source_ip` (the socket peer, which the
///     sender cannot freely vary per packet), NOT the payload `hostname` (which
///     is attacker-controlled), so no single source can monopolise the floor.
///
/// Returning `deleted_rows == 0` while the DB is still over cap is the signal to
/// the caller that the floor (or an empty deletable set) has been reached; the
/// caller converts that to `write_blocked` instead of deleting protected rows.
fn delete_oldest_logs_chunk(
    pool: &DbPool,
    chunk_size: usize,
    config: &StorageConfig,
) -> Result<DeletedChunk> {
    // Lock first, then borrow — and hold both across the whole chunk. The
    // protected-id set below is materialized into a TEMP table, which lives on
    // the connection that created it, so the DELETE that reads it cannot run on
    // a different connection. That rules out the usual split (read on one
    // connection, release it, take the lock and a second connection), and
    // blocking on the lock while holding the connection is the pin this
    // ordering exists to prevent. The trade is one bounded err+ window scan
    // per chunk under the lock. The recovery loop calls this once per chunk and
    // both resources are released on return, so queued writers still get a
    // window between chunks; and this is half the pre-PM3 cost, which ran the
    // same scan twice per chunk under the lock.
    let conn = crate::db::write_conn(pool)?;

    // Build the protected-id CTE + the deletable selection. When the floor is
    // disabled (window or cap == 0) we fall back to the original unfiltered
    // oldest-first selection.
    let floor_enabled = config.err_floor_window_hours > 0 && config.err_floor_per_source_cap > 0;

    // Window start as an RFC3339 string comparable to `received_at`.
    //
    // `received_at` is stored with MILLISECOND precision and a `Z` suffix (see
    // `app::time::rfc3339_z`, the syslog/docker/OTLP ingest paths). We MUST format
    // `window_start` the same way: a second-precision string like
    // "...:27Z" sorts AFTER "...:27.680Z" lexicographically (because 'Z'=0x5A >
    // '.'=0x2E), so a coarser format would silently protect the wrong rows.
    //
    // Overflow handling: `err_floor_window_hours` is a u64 and `TimeDelta` is
    // i64-hours-bounded. A pathological value would overflow the conversion or the
    // subtraction. The old code mapped that to `None`, which downstream collapsed
    // to `""` — and `received_at >= ""` is always true, so EVERY err+ row would be
    // protected, defeating the trim entirely. Fail fast instead.
    let window_start = if floor_enabled {
        let hours = i64::try_from(config.err_floor_window_hours).map_err(|_| {
            anyhow::anyhow!(
                "err_floor_window_hours ({}) is too large to represent as a time delta",
                config.err_floor_window_hours
            )
        })?;
        let delta = chrono::TimeDelta::try_hours(hours).ok_or_else(|| {
            anyhow::anyhow!(
                "err_floor_window_hours ({hours}) overflows the supported time-delta range"
            )
        })?;
        let start = Utc::now().checked_sub_signed(delta).ok_or_else(|| {
            anyhow::anyhow!(
                "err_floor_window_hours ({hours}) underflows the representable timestamp range"
            )
        })?;
        Some(start.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    } else {
        None
    };

    // Materialize the protected-id set ONCE per chunk into a TEMP table.
    // Previously the window-function subquery (a full err+ window scan) was
    // embedded in BOTH the hostnames SELECT and the DELETE, executing twice
    // per 1000-row chunk inside the recovery loop while holding the write
    // lock (full-review PM3). The DELETE now collects hostnames via
    // RETURNING, so the whole chunk costs one window-fn pass and one
    // delete-select pass.
    //
    // `source_ip` is stored as `ip:port`; we PARTITION on the IP portion only
    // (strip the ephemeral port) so all packets from one peer share a single
    // per-source budget. Window functions require SQLite >= 3.25 and
    // RETURNING requires >= 3.35 (rusqlite `bundled` ships 3.4x).
    if floor_enabled {
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS _err_floor_protected (id INTEGER PRIMARY KEY);
             DELETE FROM _err_floor_protected;",
        )?;
        conn.prepare_cached(
            "INSERT INTO _err_floor_protected (id)
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY substr(source_ip, 1,
                         CASE WHEN instr(source_ip, ':') > 0
                              THEN instr(source_ip, ':') - 1
                              ELSE length(source_ip) END)
                     ORDER BY received_at DESC, id DESC
                 ) AS rn
                 FROM logs
                 WHERE severity IN ('err','crit','alert','emerg')
                   AND received_at >= :window_start
             ) WHERE rn <= :cap",
        )?
        .execute(rusqlite::named_params! {
            ":window_start": window_start.as_deref().unwrap_or(""),
            ":cap": config.err_floor_per_source_cap as i64,
        })?;
    }

    // Delete the deletable chunk, collecting hostnames from the deleted rows
    // via RETURNING. When the floor is active, protected err+ rows are never
    // in this set — so this path never overrides the err+ exemption.
    // Serialize the DELETE behind the process-wide write lock (v1.1.3) so it
    // never races other writers against SQLite's single write lock.
    let delete_sql = if floor_enabled {
        "DELETE FROM logs WHERE id IN (
             SELECT id FROM logs
             WHERE id NOT IN (SELECT id FROM _err_floor_protected)
             ORDER BY received_at ASC, id ASC LIMIT :chunk)
         RETURNING hostname"
    } else {
        "DELETE FROM logs WHERE id IN (
             SELECT id FROM logs ORDER BY received_at ASC, id ASC LIMIT :chunk)
         RETURNING hostname"
    };
    let deleted_hostnames: Vec<String> = conn
        .prepare_cached(delete_sql)?
        .query_map(
            rusqlite::named_params! { ":chunk": chunk_size as i64 },
            |row| row.get(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let deleted_rows = deleted_hostnames.len();
    let hostnames: Vec<String> = deleted_hostnames
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    tracing::debug!(
        deleted_rows,
        affected_hosts = hostnames.len(),
        chunk_size,
        floor_enabled,
        "Deleted oldest deletable logs chunk (err+ floor honoured)"
    );

    Ok(DeletedChunk {
        deleted_rows,
        hostnames,
    })
}

fn delete_oldest_heartbeats_chunk(pool: &DbPool, chunk_size: usize) -> Result<usize> {
    delete_heartbeat_chunk_where(pool, "", &[], chunk_size)
}

fn delete_heartbeat_chunk_before(pool: &DbPool, cutoff: &str, chunk_size: usize) -> Result<usize> {
    delete_heartbeat_chunk_where(pool, "WHERE received_at < ?1", &[cutoff], chunk_size)
}

fn delete_heartbeat_chunk_where(
    pool: &DbPool,
    where_clause: &str,
    params: &[&str],
    chunk_size: usize,
) -> Result<usize> {
    let mut conn = crate::db::write_conn(pool)?;
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS temp_heartbeat_delete_ids (
             id INTEGER PRIMARY KEY
         );
         DELETE FROM temp_heartbeat_delete_ids;",
    )?;

    let insert_sql = format!(
        "INSERT INTO temp_heartbeat_delete_ids (id)
         SELECT id FROM host_heartbeats
         {where_clause}
         ORDER BY received_at ASC, id ASC
         LIMIT ?{}",
        params.len() + 1
    );
    let mut values: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let chunk_limit = chunk_size as i64;
    values.push(&chunk_limit);
    tx.execute(&insert_sql, rusqlite::params_from_iter(values))?;

    let selected: usize = tx.query_row(
        "SELECT COUNT(*) FROM temp_heartbeat_delete_ids",
        [],
        |row| row.get::<_, i64>(0),
    )? as usize;
    if selected == 0 {
        tx.execute_batch("DELETE FROM temp_heartbeat_delete_ids;")?;
        tx.commit()?;
        return Ok(0);
    }

    for table in HEARTBEAT_CHILD_TABLES {
        tx.execute(
            &format!(
                "DELETE FROM {table}
                 WHERE heartbeat_id IN (SELECT id FROM temp_heartbeat_delete_ids)"
            ),
            [],
        )?;
    }
    let deleted = tx.execute(
        "DELETE FROM host_heartbeats
         WHERE id IN (SELECT id FROM temp_heartbeat_delete_ids)",
        [],
    )?;
    tx.execute_batch("DELETE FROM temp_heartbeat_delete_ids;")?;
    tx.commit()?;

    tracing::debug!(
        deleted_rows = deleted,
        child_tables = HEARTBEAT_CHILD_TABLES.len(),
        chunk_size,
        "Deleted heartbeat chunk"
    );
    Ok(deleted)
}

/// Whether [`purge_old_heartbeats`] should also sweep for orphan child rows.
///
/// The sweep is a full scan of every heartbeat child table, so it is far more
/// expensive than the retention delete it accompanies, while the orphans it
/// looks for are rare (both the write and delete paths are single
/// transactions). Callers therefore decide the cadence: `runtime.rs` runs it on
/// the first retention tick after start and daily thereafter.
///
/// Note this only gates the sweep inside `purge_old_heartbeats`.
/// `enforce_storage_budget_with_state` sweeps unconditionally, because there
/// reclaiming orphan rows is the cheapest way to recover space before trimming
/// live telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanSweep {
    /// Scan for and delete orphan child rows.
    Run,
    /// Skip the scan entirely; orphan counts are reported as zero.
    Skip,
}

/// Delete child metric rows whose parent `host_heartbeats` row is gone.
///
/// **The scan runs without the global write lock.** Identifying orphans means
/// examining every row of the child table, and on a production-sized DB that
/// takes time proportional to child-table size; the previous implementation did
/// it as one unchunked `DELETE ... WHERE NOT EXISTS` per table while holding
/// `write_lock()` for the whole statement, which blocked every other writer in the process — heartbeat
/// ingest, the syslog batch writer, notifications — long enough to exhaust the
/// r2d2 pool and surface as fleet-wide 5xx. One production retention tick
/// (~79 GB database, 2026-08-24) spent 15m25s here, of which the whole-table
/// scans were the dominant cost.
///
/// Chunking alone would not have fixed it: with zero orphans (the steady state,
/// since the normal delete path removes children before parents) a `LIMIT`ed
/// `DELETE` still scans the entire table before returning nothing. So the phases
/// are split — the expensive scan is a plain read, which WAL lets run alongside
/// writers, and the lock is taken only for a bounded `DELETE` of rowids that
/// are already known.
///
/// **Depends on `host_heartbeats.id` being `AUTOINCREMENT`.** Splitting the
/// scan from the delete opens a window where a rowid identified as an orphan
/// could, in principle, acquire a live parent before the delete runs — which
/// would delete a row belonging to a real heartbeat. That cannot happen here
/// because `AUTOINCREMENT` makes ids strictly monotonic and never reuses one
/// (SQLite keeps the high-water mark in `sqlite_sequence`), so a deleted
/// parent's id is never reissued and an orphan stays an orphan. A plain
/// `INTEGER PRIMARY KEY` would reuse `max(rowid) + 1` after a delete and make
/// this unsafe. If that column is ever rebuilt without `AUTOINCREMENT`, this
/// function must go back to a single atomic `DELETE ... WHERE NOT EXISTS`.
///
/// The reverse races are benign: a rowid deleted by the parent-side purge
/// between the phases simply matches nothing, and orphans created after the
/// scan are picked up on the next iteration.
fn delete_orphan_heartbeat_children(pool: &DbPool, chunk_size: usize) -> Result<usize> {
    // Phase 2 binds one parameter per rowid, so the chunk must stay under
    // SQLite's SQLITE_MAX_VARIABLE_NUMBER (32766 on the bundled 3.32+ build,
    // and rusqlite is built with `bundled`). `cleanup_chunk_size` is only
    // validated as 1..=1_000_000, so an operator-set value can legally exceed
    // that and would fail the DELETE with "too many SQL variables" — aborting
    // the whole retention pass, and via `enforce_storage_budget_with_state`
    // the storage-budget recovery loop, precisely when orphans exist.
    //
    // 500 is well under the bind ceiling and also keeps each lock hold short,
    // which is the point of chunking here. Nothing is lost by capping: the
    // loop simply runs more iterations.
    const MAX_ROWIDS_PER_DELETE: usize = 500;
    let chunk_limit = chunk_size.clamp(1, MAX_ROWIDS_PER_DELETE) as i64;
    let mut total_deleted = 0usize;

    for table in HEARTBEAT_CHILD_TABLES {
        loop {
            // Phase 1 — identify orphans. No write lock: readers do not block
            // writers under WAL, so this may take as long as it needs.
            let orphan_rowids: Vec<i64> = {
                let conn = pool.get()?;
                let mut stmt = conn.prepare(&format!(
                    "SELECT rowid FROM {table}
                     WHERE NOT EXISTS (
                         SELECT 1 FROM host_heartbeats
                         WHERE host_heartbeats.id = {table}.heartbeat_id
                     )
                     LIMIT ?1"
                ))?;
                let rows = stmt.query_map([chunk_limit], |row| row.get::<_, i64>(0))?;
                rows.collect::<rusqlite::Result<Vec<i64>>>()?
            };

            if orphan_rowids.is_empty() {
                break;
            }

            // Phase 2 — delete exactly those rowids. The lock is held only for
            // this bounded statement, never for a scan.
            let deleted = {
                let placeholders = std::iter::repeat_n("?", orphan_rowids.len())
                    .collect::<Vec<_>>()
                    .join(",");
                let conn = crate::db::write_conn(pool)?;
                conn.execute(
                    &format!("DELETE FROM {table} WHERE rowid IN ({placeholders})"),
                    rusqlite::params_from_iter(orphan_rowids.iter()),
                )?
            };
            total_deleted += deleted;

            if deleted == 0 {
                // Phase 1 found rowids but phase 2 removed none. Not reachable
                // with the current schema, but without this guard the loop
                // would spin on the same rowids, re-scanning the table each
                // time while holding the maintenance permit.
                tracing::warn!(
                    table,
                    candidates = orphan_rowids.len(),
                    "Orphan sweep made no progress; stopping to avoid a spin"
                );
                break;
            }

            tracing::debug!(
                table,
                deleted_rows = deleted,
                chunk_size,
                "Deleted orphan heartbeat child chunk"
            );

            // Yield so queued writers get the lock between chunks, matching
            // `purge_old_logs` and `purge_by_tag_window`.
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    Ok(total_deleted)
}

/// Delete `host_heartbeats_latest` rows whose heartbeat is gone.
///
/// Deliberately left as a single unchunked `DELETE ... WHERE NOT EXISTS` under
/// the write lock, unlike [`delete_orphan_heartbeat_children`]: this table
/// holds one row per host, so the scan is bounded by host count (tens) rather
/// than by heartbeat volume (millions), and the lock hold is negligible.
pub fn delete_orphan_heartbeat_latest(pool: &DbPool) -> Result<usize> {
    let conn = crate::db::write_conn(pool)?;
    let deleted = conn.execute(
        "DELETE FROM host_heartbeats_latest
         WHERE NOT EXISTS (
             SELECT 1 FROM host_heartbeats
             WHERE host_heartbeats.id = host_heartbeats_latest.heartbeat_id
         )",
        [],
    )?;
    Ok(deleted)
}

const HEARTBEAT_CHILD_TABLES: &[&str] = &[
    "heartbeat_cpu",
    "heartbeat_memory",
    "heartbeat_disks",
    "heartbeat_network",
    "heartbeat_processes",
    "heartbeat_containers",
];

fn reconcile_hosts(pool: &DbPool, hostnames: &[String]) -> Result<()> {
    if hostnames.is_empty() {
        return Ok(());
    }

    let mut conn = crate::db::write_conn(pool)?;
    let tx = conn.transaction()?;
    for hostname in hostnames {
        // One query: count + timestamp bounds in a single pass over the index.
        // MIN/MAX return NULL when count=0, so timestamps are Option<String>.
        let (count, first_seen, last_seen): (i64, Option<String>, Option<String>) = tx.query_row(
            "SELECT COUNT(*), MIN(received_at), MAX(received_at)
                 FROM logs WHERE hostname = ?1",
            [hostname],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        match (count, first_seen, last_seen) {
            (0, _, _) | (_, None, _) | (_, _, None) => {
                tx.execute("DELETE FROM hosts WHERE hostname = ?1", [hostname])?;
            }
            (count, Some(first_seen), Some(last_seen)) => {
                tx.execute(
                    "UPDATE hosts
                     SET first_seen = ?2, last_seen = ?3, log_count = ?4
                     WHERE hostname = ?1",
                    params![hostname, first_seen, last_seen, count],
                )?;
            }
        }
    }
    tx.commit()?;
    tracing::debug!(
        host_count = hostnames.len(),
        "Reconciled host aggregates after log deletion"
    );
    Ok(())
}

pub fn maybe_checkpoint_wal_by_size(
    pool: &DbPool,
    db_path: &Path,
    threshold_bytes: u64,
) -> Result<Option<(i64, i64, i64)>> {
    if threshold_bytes == 0 {
        return Ok(None);
    }
    let wal_path = sqlite_sidecar_path(db_path, "wal");
    let wal_size = match std::fs::metadata(&wal_path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if wal_size < threshold_bytes {
        return Ok(None);
    }
    let passive = db_wal_checkpoint(pool, "passive")?;
    if wal_checkpoint_complete(passive.0, passive.1, passive.2) {
        // PASSIVE copies frames into the main database but deliberately keeps
        // the WAL file at its high-water size. Once every frame is checkpointed,
        // a bounded TRUNCATE checkpoint can safely release that disk space.
        let truncate = db_wal_checkpoint(pool, "truncate")?;
        if !wal_checkpoint_complete(truncate.0, truncate.1, truncate.2) {
            tracing::warn!(
                busy = truncate.0,
                log_frames = truncate.1,
                checkpointed_frames = truncate.2,
                "WAL truncate checkpoint incomplete"
            );
        }
    }
    Ok(Some(passive))
}

pub fn checkpoint_wal_and_incremental_vacuum(pool: &DbPool, config: &StorageConfig) -> Result<()> {
    match maybe_checkpoint_wal_by_size(
        pool,
        &config.db_path,
        config.wal_checkpoint_threshold_bytes(),
    ) {
        Ok(Some((busy, log_frames, checkpointed_frames))) => {
            if busy != 0 || checkpointed_frames < log_frames {
                tracing::warn!(
                    busy,
                    log_frames,
                    checkpointed_frames,
                    "WAL threshold checkpoint incomplete"
                );
            } else {
                tracing::debug!(
                    busy,
                    log_frames,
                    checkpointed_frames,
                    "WAL threshold checkpoint completed"
                );
            }
        }
        Ok(None) => tracing::debug!("WAL threshold checkpoint skipped"),
        Err(error) => {
            tracing::warn!(error = %error, "WAL threshold checkpoint skipped (non-fatal)");
        }
    }
    let conn = crate::db::write_conn(pool)?;
    match conn.execute_batch("PRAGMA incremental_vacuum(1000);") {
        Err(e) => {
            tracing::warn!(error = %e, "incremental vacuum skipped (non-fatal)");
        }
        _ => {
            tracing::debug!("Incremental vacuum completed");
        }
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

/// Combined trigger: true if EITHER the DB-size cap or the free-disk floor is
/// breached. Retained for the read-only health/stats surfaces (queries.rs,
/// service.rs) that report whether writes are currently constrained — they want
/// the OR of both conditions. Enforcement itself uses the split helpers below so
/// the two pressures get distinct remediation.
pub fn exceeds_trigger(metrics: &StorageMetrics, config: &StorageConfig) -> bool {
    db_size_exceeds_trigger(metrics, config) || disk_free_below_trigger(metrics, config)
}

/// DB-size trigger: cortex's OWN logical bytes exceed `max_db_size_mb`.
/// Resolvable by self-trim.
fn db_size_exceeds_trigger(metrics: &StorageMetrics, config: &StorageConfig) -> bool {
    config.max_db_size_mb > 0 && metrics.logical_db_size_bytes > mb_to_bytes(config.max_db_size_mb)
}

/// Free-disk trigger: whole-filesystem free space is below `min_free_disk_mb`.
/// EXTERNAL — never resolved by deleting cortex's own data.
fn disk_free_below_trigger(metrics: &StorageMetrics, config: &StorageConfig) -> bool {
    // FAIL-CLOSED: when the free-disk guardrail is enabled (`min_free_disk_mb > 0`)
    // but the statvfs probe failed (`free_disk_bytes == None`), treat free space as
    // 0 (unknown == worst case) so the guardrail engages conservatively instead of
    // silently disabling itself. With the guardrail disabled the function short-
    // circuits on `> 0` and never inspects the probe at all.
    config.min_free_disk_mb > 0
        && metrics.free_disk_bytes.unwrap_or(0) < mb_to_bytes(config.min_free_disk_mb)
}

/// Self-trim recovery exit: the DB-size loop stops once logical size is at or
/// below `recovery_db_size_mb`. Deliberately ignores the free-disk arm so the
/// self-trim loop is NOT gated by an external condition it cannot fix.
fn db_size_within_recovery(
    metrics: &StorageMetrics,
    recovery: &StorageRecovery,
    config: &StorageConfig,
) -> bool {
    config.max_db_size_mb == 0 || metrics.logical_db_size_bytes <= recovery.logical_db_size_bytes
}

/// Hysteresis decision for the external free-disk write-block.
///
/// - Below `min_free_disk_mb` → engage the block.
/// - At/above `recovery_free_disk_mb` → clear the block.
/// - In the (min, recovery) hysteresis band → keep whatever the previous tick
///   decided (`prev`). This needs prior state: the answer in the band is not a
///   pure function of current metrics, which is exactly why the block latches
///   instead of flapping at the trigger threshold.
fn disk_pressure_write_blocked(
    metrics: &StorageMetrics,
    config: &StorageConfig,
    prev: bool,
) -> bool {
    if config.min_free_disk_mb == 0 {
        return false;
    }
    // FAIL-CLOSED: the guardrail is enabled here, so a failed statvfs probe
    // (`None`) is treated as 0 free bytes (worst case) — the block engages rather
    // than fails open. Mirrors `disk_free_below_trigger`.
    let free = metrics.free_disk_bytes.unwrap_or(0);
    if free < mb_to_bytes(config.min_free_disk_mb) {
        true
    } else if free >= mb_to_bytes(config.recovery_free_disk_mb) {
        false
    } else {
        prev
    }
}

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1_048_576)
}

fn physical_db_size_bytes(db_path: &Path) -> Result<u64> {
    let mut total = file_size_if_exists(db_path)?;
    total += file_size_if_exists(&sqlite_sidecar_path(db_path, "wal"))?;
    total += file_size_if_exists(&sqlite_sidecar_path(db_path, "shm"))?;
    Ok(total)
}

pub(crate) fn sqlite_sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut path = db_path.as_os_str().to_os_string();
    path.push("-");
    path.push(suffix);
    PathBuf::from(path)
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
