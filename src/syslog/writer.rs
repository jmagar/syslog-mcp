use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::StorageConfig;
use crate::db::{self, DbPool};

use super::WRITE_CHANNEL_CAPACITY;

const INGEST_SUMMARY_INTERVAL_SECS: u64 = 60;

/// Batch writer — collects messages and writes in batches for throughput.
pub(crate) async fn batch_writer(
    mut rx: mpsc::Receiver<db::LogBatchEntry>,
    pool: Arc<DbPool>,
    storage: StorageConfig,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
    batch_size: usize,
    flush_interval: tokio::time::Duration,
) {
    let mut batch: Vec<db::LogBatchEntry> = Vec::with_capacity(batch_size);
    let mut storage_blocked = false;
    let mut summary = IngestSummary::default();
    let mut summary_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(INGEST_SUMMARY_INTERVAL_SECS);
    info!(
        batch_size,
        flush_interval_ms = flush_interval.as_millis(),
        "Batch writer started"
    );

    loop {
        let deadline = tokio::time::sleep(flush_interval);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(parsed) => {
                            batch.push(parsed);
                            debug!(
                                batch_len = batch.len(),
                                queue_depth = rx.max_capacity().saturating_sub(rx.capacity()),
                                queue_capacity = rx.max_capacity(),
                                "Queued parsed syslog entry"
                            );
                            if !batch.is_empty() && batch.len() % batch_size == 0 {
                                break;
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                flush_batch(
                                    &pool,
                                    &storage,
                                    &storage_state,
                                    &mut batch,
                                    &mut storage_blocked,
                                    &mut summary,
                                )
                                .await;
                            }
                            emit_ingest_summary(&mut summary);
                            info!("Write channel closed, exiting batch writer");
                            return;
                        }
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        if !batch.is_empty() {
            flush_batch(
                &pool,
                &storage,
                &storage_state,
                &mut batch,
                &mut storage_blocked,
                &mut summary,
            )
            .await;
        }

        if tokio::time::Instant::now() >= summary_deadline {
            emit_ingest_summary(&mut summary);
            summary_deadline = tokio::time::Instant::now()
                + tokio::time::Duration::from_secs(INGEST_SUMMARY_INTERVAL_SECS);
        }
    }
}

pub(super) async fn flush_batch(
    pool: &Arc<DbPool>,
    storage: &StorageConfig,
    storage_state: &Arc<Mutex<Option<db::StorageBudgetState>>>,
    batch: &mut Vec<db::LogBatchEntry>,
    storage_blocked: &mut bool,
    summary: &mut IngestSummary,
) {
    let pool = Arc::clone(pool);
    let batch_to_write = std::mem::take(batch);
    let count = batch_to_write.len();
    let started = Instant::now();
    debug!(count, "Attempting batch flush");
    let enforcement = storage_state
        .lock()
        .expect("storage state mutex poisoned")
        .clone();
    if let Some(state) = enforcement {
        if state.write_blocked {
            let err = anyhow::anyhow!(
                "storage budget exceeded: logical_db_size_bytes={}, free_disk_bytes={:?}",
                state.metrics.logical_db_size_bytes,
                state.metrics.free_disk_bytes
            );
            if !*storage_blocked {
                error!(
                    error = %err,
                    count,
                    retained_batch = batch_to_write.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    max_db_size_mb = storage.max_db_size_mb,
                    min_free_disk_mb = storage.min_free_disk_mb,
                    "Storage budget exceeded — retaining batch until space recovers"
                );
                *storage_blocked = true;
            }
            *batch = batch_to_write;
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            return;
        }
    }
    match tokio::task::spawn_blocking(
        move || match db::insert_logs_batch(&pool, &batch_to_write) {
            Ok(n) => Ok((n, batch_to_write)),
            Err(e) => Err((e, batch_to_write, false)),
        },
    )
    .await
    {
        Ok(Ok((n, inserted_batch))) => {
            summary.record_batch(&inserted_batch[..n.min(inserted_batch.len())]);
            if *storage_blocked {
                info!(
                    count = n,
                    elapsed_ms = started.elapsed().as_millis(),
                    "storage budget recovered — writes resumed"
                );
                *storage_blocked = false;
            }
            debug!(
                count = n,
                elapsed_ms = started.elapsed().as_millis(),
                "Flushed log batch"
            );
        }
        Ok(Err((e, failed_batch, blocked_by_storage))) => {
            if failed_batch.len() < 1000 {
                if blocked_by_storage {
                    if !*storage_blocked {
                        error!(
                            error = %e,
                            count,
                            retained_batch = failed_batch.len(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "Storage budget exceeded — retaining batch until space recovers"
                        );
                        *storage_blocked = true;
                    }
                } else {
                    error!(
                        error = %e,
                        count,
                        retained_batch = failed_batch.len(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to flush log batch — retaining for next flush"
                    );
                }
                *batch = failed_batch;
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            } else {
                error!(
                    error = %e,
                    count,
                    retained_batch = failed_batch.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "Failed to flush log batch — batch too large to retain, discarding"
                );
            }
        }
        Err(e) => {
            error!(
                error = %e,
                count,
                elapsed_ms = started.elapsed().as_millis(),
                "spawn_blocking panicked during flush — batch discarded"
            );
        }
    }
}

pub(super) fn queue_depth<T>(tx: &mpsc::Sender<T>) -> usize {
    WRITE_CHANNEL_CAPACITY.saturating_sub(tx.capacity())
}

#[derive(Default)]
pub(super) struct IngestSummary {
    total_logs: usize,
    host_counts: HashMap<String, usize>,
    source_ip_counts: HashMap<String, usize>,
    sender_counts: HashMap<(String, String), usize>,
}

impl IngestSummary {
    fn record_batch(&mut self, entries: &[db::LogBatchEntry]) {
        self.total_logs += entries.len();
        for entry in entries {
            *self.host_counts.entry(entry.hostname.clone()).or_insert(0) += 1;
            let source_ip = source_addr_ip(&entry.source_ip);
            *self.source_ip_counts.entry(source_ip.clone()).or_insert(0) += 1;
            *self
                .sender_counts
                .entry((entry.hostname.clone(), source_ip))
                .or_insert(0) += 1;
        }
    }

    fn reset(&mut self) {
        self.total_logs = 0;
        self.host_counts.clear();
        self.source_ip_counts.clear();
        self.sender_counts.clear();
    }
}

fn emit_ingest_summary(summary: &mut IngestSummary) {
    if summary.total_logs == 0 {
        return;
    }

    let top_senders = summarize_top_senders(&summary.sender_counts, 5);
    info!(
        interval_secs = INGEST_SUMMARY_INTERVAL_SECS,
        total_logs = summary.total_logs,
        unique_hosts = summary.host_counts.len(),
        unique_source_ips = summary.source_ip_counts.len(),
        top_senders = %top_senders,
        "Syslog ingest summary"
    );
    summary.reset();
}

pub(super) fn summarize_top_senders(
    counts: &HashMap<(String, String), usize>,
    limit: usize,
) -> String {
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|a, b| {
        b.1.cmp(a.1)
            .then_with(|| a.0 .0.cmp(&b.0 .0))
            .then_with(|| a.0 .1.cmp(&b.0 .1))
    });
    entries
        .into_iter()
        .take(limit)
        .map(|((host, source_ip), count)| format!("{host}@{source_ip}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn source_addr_ip(source_addr: &str) -> String {
    source_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| source_addr.to_string())
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
