use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::app::SyslogService;
use crate::config::Config;
use crate::db::{self, DbPool, StorageBudgetState};
use crate::ingest::IngestTx;
use crate::{docker_ingest, mcp, syslog};

pub struct RuntimeCore {
    pub config: Config,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<StorageBudgetState>>>,
    service: SyslogService,
    maintenance_permit: Arc<Semaphore>,
    ingest: IngestTx,
}

pub struct MaintenanceHandles {
    purge: Option<JoinHandle<()>>,
    storage: Option<JoinHandle<()>>,
    docker_ingest: Vec<JoinHandle<()>>,
}

impl Drop for MaintenanceHandles {
    fn drop(&mut self) {
        if let Some(handle) = &self.purge {
            handle.abort();
        }
        if let Some(handle) = &self.storage {
            handle.abort();
        }
        for handle in &self.docker_ingest {
            handle.abort();
        }
    }
}

pub(crate) fn background_interval(period: tokio::time::Duration) -> tokio::time::Interval {
    tokio::time::interval_at(tokio::time::Instant::now() + period, period)
}

impl RuntimeCore {
    pub fn load() -> Result<Self> {
        Self::for_server(Config::load()?)
    }

    pub fn load_query_only() -> Result<Self> {
        Self::query_only(Config::load()?)
    }

    pub fn for_server(config: Config) -> Result<Self> {
        Self::from_config(config, true)
    }

    pub fn query_only(config: Config) -> Result<Self> {
        Self::from_config(config, false)
    }

    fn from_config(config: Config, enforce_initial_storage_budget: bool) -> Result<Self> {
        let pool = Arc::new(db::init_pool(&config.storage)?);
        let storage_state = Arc::new(Mutex::new(None));
        if enforce_initial_storage_budget
            && (config.storage.max_db_size_mb > 0 || config.storage.min_free_disk_mb > 0)
        {
            let initial_outcome = db::enforce_storage_budget(&pool, &config.storage)?;
            *storage_state.lock().expect("storage state mutex poisoned") =
                Some(StorageBudgetState {
                    metrics: initial_outcome.metrics.clone(),
                    write_blocked: initial_outcome.write_blocked,
                });
            tracing::info!(
                deleted_rows = initial_outcome.deleted_rows,
                logical_db_size_bytes = initial_outcome.metrics.logical_db_size_bytes,
                physical_db_size_bytes = initial_outcome.metrics.physical_db_size_bytes,
                free_disk_bytes = ?initial_outcome.metrics.free_disk_bytes,
                write_blocked = initial_outcome.write_blocked,
                "Initial storage budget check completed"
            );
        }
        let service = SyslogService::new(Arc::clone(&pool), config.storage.clone());
        let ingest = crate::ingest::start_writer_from_syslog_config(
            &config.syslog,
            config.storage.clone(),
            Arc::clone(&pool),
            Arc::clone(&storage_state),
        );
        Ok(Self {
            config,
            pool,
            storage_state,
            service,
            maintenance_permit: Arc::new(Semaphore::new(1)),
            ingest,
        })
    }

    pub fn service(&self) -> SyslogService {
        self.service.clone()
    }

    pub fn mcp_state(&self) -> mcp::AppState {
        mcp::AppState {
            service: self.service(),
            config: self.config.mcp.clone(),
        }
    }

    pub async fn start_syslog(&self) -> Result<()> {
        syslog::start_listeners(self.config.syslog.clone(), self.ingest.sender()).await
    }

    pub fn spawn_maintenance_tasks(&self) -> MaintenanceHandles {
        let purge = self.spawn_retention_task();
        let storage = self.spawn_storage_task();
        let docker_ingest = docker_ingest::spawn_all(
            self.config.docker_ingest.clone(),
            Arc::clone(&self.pool),
            self.ingest.clone(),
        );
        MaintenanceHandles {
            purge,
            storage,
            docker_ingest,
        }
    }

    fn spawn_retention_task(&self) -> Option<JoinHandle<()>> {
        let retention_days = self.config.storage.retention_days;
        if retention_days == 0 {
            return None;
        }
        let purge_pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let started = Instant::now();
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("Maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&purge_pool);
                tracing::debug!(retention_days, "Retention purge tick started");
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    db::purge_old_logs(&pool, retention_days)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok(deleted) => tracing::info!(
                        retention_days,
                        deleted,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Retention purge tick completed"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        retention_days,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to purge old logs"
                    ),
                }
            }
        });
        tracing::info!(retention_days, "Log retention purge task started (hourly)");
        Some(handle)
    }

    fn spawn_storage_task(&self) -> Option<JoinHandle<()>> {
        if self.config.storage.max_db_size_mb == 0 && self.config.storage.min_free_disk_mb == 0 {
            return None;
        }
        let storage_pool = Arc::clone(&self.pool);
        let storage_config = self.config.storage.clone();
        let shared_storage_state = Arc::clone(&self.storage_state);
        let limiter = Arc::clone(&self.maintenance_permit);
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(
                storage_config.cleanup_interval_secs,
            ));
            loop {
                interval.tick().await;
                let started = Instant::now();
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("Maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&storage_pool);
                let storage = storage_config.clone();
                tracing::debug!(
                    cleanup_interval_secs = storage_config.cleanup_interval_secs,
                    "Storage budget enforcement tick started"
                );
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    db::enforce_storage_budget(&pool, &storage)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok(outcome) => {
                        let previous_blocked = {
                            let mut state = shared_storage_state
                                .lock()
                                .expect("storage state mutex poisoned");
                            let previous_blocked = state.as_ref().map(|s| s.write_blocked);
                            *state = Some(StorageBudgetState {
                                metrics: outcome.metrics.clone(),
                                write_blocked: outcome.write_blocked,
                            });
                            previous_blocked
                        };

                        if outcome.deleted_rows > 0
                            || outcome.write_blocked
                            || previous_blocked != Some(outcome.write_blocked)
                        {
                            tracing::info!(
                                deleted_rows = outcome.deleted_rows,
                                logical_db_size_bytes = outcome.metrics.logical_db_size_bytes,
                                physical_db_size_bytes = outcome.metrics.physical_db_size_bytes,
                                free_disk_bytes = ?outcome.metrics.free_disk_bytes,
                                write_blocked = outcome.write_blocked,
                                elapsed_ms = started.elapsed().as_millis(),
                                "Storage budget enforcement tick completed"
                            );
                        } else {
                            tracing::debug!(
                                deleted_rows = outcome.deleted_rows,
                                logical_db_size_bytes = outcome.metrics.logical_db_size_bytes,
                                physical_db_size_bytes = outcome.metrics.physical_db_size_bytes,
                                free_disk_bytes = ?outcome.metrics.free_disk_bytes,
                                write_blocked = outcome.write_blocked,
                                elapsed_ms = started.elapsed().as_millis(),
                                "Storage budget enforcement tick completed"
                            );
                        }
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to enforce storage budget"
                    ),
                }
            }
        });
        tracing::info!(
            cleanup_interval_secs = self.config.storage.cleanup_interval_secs,
            "Storage budget enforcement task started"
        );
        Some(handle)
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
