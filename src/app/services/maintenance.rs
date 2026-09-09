use super::*;

impl CortexService {
    pub async fn get_stats(&self) -> ServiceResult<DbStats> {
        let storage = self.storage.clone();
        let stats = self
            .run_heavy_db("get_stats", move |pool| db::get_stats(pool, &storage))
            .await?
            .into();
        Ok(stats)
    }

    pub async fn db_status(&self) -> ServiceResult<DbMaintenanceStatus> {
        let storage = self.storage.clone();
        self.run_db("db_status", move |pool| {
            let page_count = db::db_pragma_i64(pool, db::PragmaName("page_count"))?;
            let freelist_count = db::db_pragma_i64(pool, db::PragmaName("freelist_count"))?;
            let page_size = db::db_pragma_i64(pool, db::PragmaName("page_size"))?;
            let auto_vacuum = db::db_pragma_i64(pool, db::PragmaName("auto_vacuum"))?;
            let journal_mode = db::db_pragma_string(pool, db::PragmaName("journal_mode"))?;
            let sqlite_page_cache_kib_per_connection =
                db::db_pragma_i64(pool, db::PragmaName("cache_size"))?;
            let sqlite_mmap_bytes =
                db::db_pragma_i64(pool, db::PragmaName("mmap_size"))?.max(0) as u64;
            let logical_size_bytes =
                ((page_count - freelist_count).max(0) * page_size).max(0) as u64;
            let physical_size_bytes = db::physical_size_bytes(&storage.db_path)?;
            let wal_size_bytes =
                std::fs::metadata(db::sqlite_sidecar_path(&storage.db_path, "wal"))
                    .ok()
                    .map(|metadata| metadata.len());
            let shm_size_bytes =
                std::fs::metadata(db::sqlite_sidecar_path(&storage.db_path, "shm"))
                    .ok()
                    .map(|metadata| metadata.len());
            let cgroup = read_cgroup_memory_snapshot();
            Ok(DbMaintenanceStatus {
                db_path: storage.db_path.clone(),
                page_count,
                freelist_count,
                page_size,
                logical_size_bytes,
                physical_size_bytes,
                wal_size_bytes,
                shm_size_bytes,
                sqlite_page_cache_mb: storage.sqlite_page_cache_mb,
                sqlite_page_cache_kib_per_connection,
                sqlite_mmap_mb: storage.sqlite_mmap_mb,
                sqlite_mmap_bytes,
                heavy_read_concurrency: storage.heavy_read_concurrency,
                wal_checkpoint_mb: storage.wal_checkpoint_mb,
                wal_checkpoint_threshold_bytes: storage.wal_checkpoint_threshold_bytes(),
                cgroup_memory_status: cgroup.status,
                cgroup_memory_max_bytes: cgroup.max_bytes,
                cgroup_memory_current_bytes: cgroup.current_bytes,
                cgroup_memory_peak_bytes: cgroup.peak_bytes,
                auto_vacuum,
                journal_mode,
                integrity_ok: None,
                integrity_messages: Vec::new(),
            })
        })
        .await
    }

    pub async fn db_integrity(&self, quick: bool) -> ServiceResult<DbIntegrityResult> {
        let _permit = Arc::clone(&self.maintenance_permit)
            .try_acquire_owned()
            .map_err(|_| ServiceError::Busy("db maintenance already in progress".to_string()))?;
        self.run_db("db_integrity", move |pool| {
            let messages = db::db_integrity_check(pool, quick)?;
            Ok(DbIntegrityResult {
                ok: messages.len() == 1 && messages.first().is_some_and(|value| value == "ok"),
                messages,
            })
        })
        .await
    }

    /// Start a background `db integrity` job (bead syslog-mcp-a4pd). Inserts a
    /// `running` job row, spawns the (~147s) check on a detached task, and
    /// returns the job id IMMEDIATELY. The caller polls
    /// [`db_integrity_job_status`](Self::db_integrity_job_status).
    ///
    /// The check runs on its OWN pooled connection in an independently managed
    /// OS thread — deliberately NOT via `run_db` (which
    /// would hold a `db_permits` slot for the whole 147s and starve other reads)
    /// and NOT via the maintenance permit (which would serialize behind retention
    /// / optimize). `quick_check` is read-only, so it never blocks the ingest
    /// writer. The outer `tokio::spawn` is what lets this method return now and
    /// update the job row when the check finishes.
    pub async fn db_integrity_start_background(
        &self,
        quick: bool,
    ) -> ServiceResult<DbIntegrityJobStarted> {
        let permit = Arc::clone(&self.maintenance_permit)
            .try_acquire_owned()
            .map_err(|_| ServiceError::Busy("db maintenance already in progress".to_string()))?;
        let job_id = self
            .run_db("db_integrity_start", move |pool| {
                db::insert_maintenance_job(pool, "db_integrity")
            })
            .await?;

        let pool = Arc::clone(&self.pool);
        let worker_pool = Arc::clone(&pool);
        #[cfg(test)]
        let test_hook = self.integrity_test_hook.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        #[cfg(test)]
        if self.integrity_test_spawn_failure {
            let error = "injected integrity worker spawn failure";
            let payload = serde_json::json!({ "error": error }).to_string();
            db::finish_maintenance_job(&pool, job_id, "failed", &payload).map_err(
                |finish_error| {
                    ServiceError::Internal(anyhow::anyhow!(
                        "{error}; additionally failed to mark job {job_id} failed: {finish_error}"
                    ))
                },
            )?;
            return Err(ServiceError::Internal(anyhow::anyhow!(error)));
        }
        let spawn_result = std::thread::Builder::new()
            .name(format!("cortex-integrity-{job_id}"))
            .spawn(move || {
                let _permit = permit;
                let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some(hook) = test_hook {
                        return hook();
                    }
                    db::db_integrity_check(&worker_pool, quick)
                }));
                let (status, result_json) = match checked {
                    Err(payload) => {
                        let detail = payload
                            .downcast_ref::<&str>()
                            .map(|value| (*value).to_string())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown panic payload".to_string());
                        (
                            "failed",
                            serde_json::json!({ "error": format!("integrity worker panicked: {detail}") })
                                .to_string(),
                        )
                    }
                    Ok(Ok(messages)) => {
                        let ok = messages.len() == 1
                            && messages.first().is_some_and(|value| value == "ok");
                        let payload = serde_json::json!({ "ok": ok, "messages": messages });
                        ("done", payload.to_string())
                    }
                    Ok(Err(e)) => (
                        "failed",
                        serde_json::json!({ "error": e.to_string() }).to_string(),
                    ),
                };
                let completion = db::finish_maintenance_job(&worker_pool, job_id, status, &result_json)
                    .map_err(|error| error.to_string());
                if let Err(e) = &completion {
                    tracing::error!(job_id, error = %e, "failed to record integrity job result");
                }
                let _ = done_tx.send(completion);
            });
        let worker = match spawn_result {
            Ok(worker) => worker,
            Err(error) => {
                let message = format!("spawn integrity worker: {error}");
                let payload = serde_json::json!({ "error": message }).to_string();
                db::finish_maintenance_job(&pool, job_id, "failed", &payload).map_err(|finish_error| {
                    ServiceError::Internal(anyhow::anyhow!(
                        "{message}; additionally failed to mark job {job_id} failed: {finish_error}"
                    ))
                })?;
                return Err(ServiceError::Internal(anyhow::anyhow!(message)));
            }
        };
        drop(worker);
        // Tokio owns only this lightweight completion waiter. On a bounded
        // shutdown it can be aborted without making the runtime wait for the
        // independently managed OS thread; normal shutdown still joins it.
        let task = tokio::spawn(async move {
            match done_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    panic!("integrity worker could not persist terminal state: {error}")
                }
                Err(_) => panic!("integrity worker exited without reporting completion"),
            }
        });
        let completed = {
            let mut integrity_tasks = self
                .integrity_tasks
                .lock()
                .expect("integrity task registry mutex poisoned");
            let mut completed = Vec::new();
            let mut pending = Vec::new();
            for existing in std::mem::take(&mut *integrity_tasks) {
                if existing.is_finished() {
                    completed.push(existing);
                } else {
                    pending.push(existing);
                }
            }
            *integrity_tasks = pending;
            completed
        };
        for completed_task in completed {
            if let Err(error) = completed_task.await {
                self.integrity_task_failed
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::error!(%error, "Integrity completion task failed before next job");
            }
        }
        self.integrity_tasks
            .lock()
            .expect("integrity task registry mutex poisoned")
            .push(task);

        Ok(DbIntegrityJobStarted {
            job_id,
            status: "running".to_string(),
        })
    }

    /// Poll a background maintenance job by id.
    pub async fn db_integrity_job_status(&self, id: i64) -> ServiceResult<MaintenanceJobStatus> {
        let job = self
            .run_db("db_integrity_job_status", move |pool| {
                db::get_maintenance_job(pool, id)
            })
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("maintenance job {id} not found")))?;

        // Parse the terminal result payload into typed fields.
        let mut integrity = None;
        let mut error = None;
        if let Some(raw) = &job.result_json {
            match job.status.as_str() {
                "done" => {
                    integrity = serde_json::from_str::<DbIntegrityResult>(raw).ok();
                }
                "failed" => {
                    error = serde_json::from_str::<serde_json::Value>(raw)
                        .ok()
                        .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)));
                }
                _ => {}
            }
        }

        Ok(MaintenanceJobStatus {
            job_id: job.id,
            kind: job.kind,
            status: job.status,
            started_at: job.started_at,
            finished_at: job.finished_at,
            integrity,
            error,
        })
    }

    async fn db_checkpoint(&self, mode: String) -> ServiceResult<DbCheckpointResult> {
        self.run_db("db_checkpoint", move |pool| {
            let (busy, log_frames, checkpointed_frames) = db::db_wal_checkpoint(pool, &mode)?;
            let complete = db::wal_checkpoint_complete(busy, log_frames, checkpointed_frames);
            if !complete && mode != "passive" {
                return Err(ServiceError::Busy(format!(
                    "wal_checkpoint_incomplete busy={busy} checkpointed_frames={checkpointed_frames} log_frames={log_frames}"
                ))
                .into());
            }
            Ok(DbCheckpointResult {
                mode,
                busy,
                log_frames,
                checkpointed_frames,
                complete,
            })
        })
        .await
    }

    pub async fn db_checkpoint_checked(
        &self,
        req: DbCheckpointRequest,
    ) -> ServiceResult<DbCheckpointResult> {
        let mode = req.normalized_mode()?;
        self.db_checkpoint(mode).await
    }

    /// Read the live `page_count * page_size` (logical size, in bytes) via a
    /// fresh PRAGMA pair. Used by the `POST /api/db/vacuum` pre-flight in
    /// `src/api.rs::db_vacuum` so the 2GB guard cannot be defeated by a stale
    /// startup snapshot (bead 0p8r.17). Cheap enough to call per-request:
    /// two `PRAGMA` reads on a held connection inside `spawn_blocking`.
    pub async fn db_logical_size_bytes(&self) -> ServiceResult<u64> {
        self.run_db("db_logical_size_bytes", move |pool| {
            let page_count = db::db_pragma_i64(pool, db::PragmaName("page_count"))?;
            let page_size = db::db_pragma_i64(pool, db::PragmaName("page_size"))?;
            Ok((page_count.max(0) as u64).saturating_mul(page_size.max(0) as u64))
        })
        .await
    }

    async fn db_vacuum(&self, full: bool, incremental_pages: u32) -> ServiceResult<DbVacuumResult> {
        let storage = self.storage.clone();
        self.run_db("db_vacuum", move |pool| {
            let before_physical_size_bytes = db::physical_size_bytes(&storage.db_path)?;
            if full {
                db::db_full_vacuum(pool)?;
            } else {
                db::db_incremental_vacuum(pool, incremental_pages)?;
            }
            let after_physical_size_bytes = db::physical_size_bytes(&storage.db_path)?;
            Ok(DbVacuumResult {
                full,
                incremental_pages,
                before_physical_size_bytes,
                after_physical_size_bytes,
            })
        })
        .await
    }

    pub async fn db_vacuum_checked(
        &self,
        req: DbVacuumRequest,
        full_vacuum_size_guard_bytes: u64,
    ) -> ServiceResult<DbVacuumResult> {
        if req.full && !req.force_enabled() {
            let size = self.db_logical_size_bytes().await?;
            if size > full_vacuum_size_guard_bytes {
                let gb = size as f64 / (1024.0 * 1024.0 * 1024.0);
                return Err(ServiceError::Busy(format!(
                    "DB size {gb:.2} GB; full VACUUM would block ingest. Pass {{\"force\":true}} or use incremental"
                )));
            }
        }
        self.db_vacuum(req.full, req.incremental_pages).await
    }

    pub async fn db_backup(&self, output: Option<PathBuf>) -> ServiceResult<DbBackupResult> {
        let db_path = self.storage.db_path.clone();
        self.run_db("db_backup", move |pool| {
            let backup_path = backup_path_for(&db_path, output)?;
            if let Some(parent) = backup_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Use rusqlite's online backup API (sqlite3_backup_*) rather than
            // the external `sqlite3` CLI.  The external process opens its own
            // connection with busy_timeout=0 and immediately hits SQLITE_BUSY
            // when the container's WAL writer holds any lock.  The pool
            // connection inherits busy_timeout=5000 and the backup API reads
            // through WAL snapshots cooperatively — no lock contention.
            let src_conn = pool.get()?;
            let mut dst_conn = rusqlite::Connection::open(&backup_path)?;
            // Wrap the backup in a closure so we can remove the partial file on
            // error rather than leaving a truncated or corrupted backup behind.
            let backup_result = (|| -> anyhow::Result<()> {
                let backup = rusqlite::backup::Backup::new(&src_conn, &mut dst_conn)?;
                // 100 pages per step, 50 ms sleep between steps — lets ingest
                // writers proceed between steps (same cadence as the rusqlite docs
                // "Online Backup of a Running Database" example).
                backup.run_to_completion(100, std::time::Duration::from_millis(50), None)?;
                drop(backup);
                Ok(())
            })();
            drop(dst_conn);
            drop(src_conn);
            if let Err(e) = backup_result {
                let _ = std::fs::remove_file(&backup_path);
                return Err(e);
            }
            let size_bytes = std::fs::metadata(&backup_path)?.len();
            Ok(DbBackupResult {
                db_path,
                backup_path,
                size_bytes,
            })
        })
        .await
    }
}

#[derive(Debug, Clone, Default)]
struct CgroupMemorySnapshot {
    status: String,
    max_bytes: Option<u64>,
    current_bytes: Option<u64>,
    peak_bytes: Option<u64>,
}

fn read_cgroup_memory_snapshot() -> CgroupMemorySnapshot {
    fn read_value(path: &str) -> std::io::Result<Option<u64>> {
        let raw = std::fs::read_to_string(path)?;
        let trimmed = raw.trim();
        if trimmed == "max" {
            return Ok(None);
        }
        trimmed.parse::<u64>().map(Some).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })
    }

    let max = read_value("/sys/fs/cgroup/memory.max");
    let current = read_value("/sys/fs/cgroup/memory.current");
    let peak = read_value("/sys/fs/cgroup/memory.peak");

    let peak_missing = matches!(
        &peak,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );

    let status = match (&max, &current, &peak) {
        (Err(max_err), Err(current_err), _)
            if max_err.kind() == std::io::ErrorKind::NotFound
                && current_err.kind() == std::io::ErrorKind::NotFound =>
        {
            "unavailable"
        }
        (Ok(None), Ok(Some(_)), _) if peak.is_ok() || peak_missing => "unlimited",
        (Ok(Some(_)), Ok(Some(_)), _) if peak.is_ok() || peak_missing => "ok",
        _ => {
            tracing::warn!("cgroup memory diagnostics could not be read cleanly");
            "error"
        }
    }
    .to_string();

    CgroupMemorySnapshot {
        status,
        max_bytes: max.ok().flatten(),
        current_bytes: current.ok().flatten(),
        peak_bytes: peak.ok().flatten(),
    }
}

fn backup_path_for(db_path: &std::path::Path, output: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let allowed_root = db_path.parent().unwrap_or(std::path::Path::new("/data"));
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S");
    let raw_path = match output {
        Some(path) if path.extension().is_some() => path,
        Some(dir) => dir.join(format!("syslog-{timestamp}.db")),
        None => db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("backups")
            .join(format!("syslog-{timestamp}.db")),
    };

    // Resolve the parent directory for path traversal validation.
    // The file may not exist yet, so we canonicalize the parent rather than
    // the full path to avoid ENOENT.
    let parent = raw_path.parent().unwrap_or(raw_path.as_path());
    std::fs::create_dir_all(parent)?;
    let canonical_parent = parent.canonicalize()?;
    let canonical_allowed = allowed_root
        .canonicalize()
        .unwrap_or_else(|_| allowed_root.to_path_buf());

    if !canonical_parent.starts_with(&canonical_allowed) {
        anyhow::bail!(
            "output_path must be within the data directory ({})",
            canonical_allowed.display()
        );
    }
    Ok(raw_path)
}
