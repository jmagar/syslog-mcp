use std::collections::HashMap;

use anyhow::Result;
use rusqlite::{params, Error as SqliteError, ErrorCode};

use super::models::LogBatchEntry;
use super::pool::DbPool;

/// Batch insert for higher throughput
pub fn insert_logs_batch(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
    const RETRY_DELAYS_MS: &[u64] = &[25, 100, 250];

    let mut attempt = 0usize;
    loop {
        match insert_logs_batch_once(pool, entries) {
            Ok(inserted) => return Ok(inserted),
            Err(err) if is_transient_sqlite_lock(&err) && attempt < RETRY_DELAYS_MS.len() => {
                let delay_ms = RETRY_DELAYS_MS[attempt];
                tracing::warn!(
                    error = %err,
                    attempt = attempt + 1,
                    retry_delay_ms = delay_ms,
                    entry_count = entries.len(),
                    "Transient SQLite lock during batch insert — retrying"
                );
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn insert_logs_batch_once(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (timestamp, hostname, facility, severity, app_name, process_id, message, raw, source_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;

        for entry in entries {
            stmt.execute(params![
                entry.timestamp,
                entry.hostname,
                entry.facility,
                entry.severity,
                entry.app_name,
                entry.process_id,
                entry.message,
                entry.raw,
                entry.source_ip
            ])?;
        }

        // Batch upsert hosts — group by hostname to avoid one upsert per log entry
        let mut host_counts: HashMap<&str, i64> = HashMap::new();
        for entry in entries {
            *host_counts.entry(entry.hostname.as_str()).or_insert(0) += 1;
        }
        let mut host_stmt = tx.prepare_cached(
            "INSERT INTO hosts (hostname, log_count)
             VALUES (?1, ?2)
             ON CONFLICT(hostname) DO UPDATE SET
                 last_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 log_count = log_count + excluded.log_count",
        )?;
        for (hostname, count) in &host_counts {
            host_stmt.execute(params![hostname, count])?;
        }
        let mut checkpoint_stmt = tx.prepare_cached(
            "INSERT INTO docker_ingest_checkpoints (host_name, container_id, last_timestamp)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(host_name, container_id) DO UPDATE SET
                 last_timestamp = excluded.last_timestamp,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )?;
        let mut checkpoint_count = 0usize;
        for entry in entries {
            if let Some(checkpoint) = &entry.docker_checkpoint {
                checkpoint_stmt.execute(params![
                    checkpoint.host_name,
                    checkpoint.container_id,
                    checkpoint.timestamp
                ])?;
                checkpoint_count += 1;
            }
        }

        tracing::debug!(
            entry_count = entries.len(),
            unique_hosts = host_counts.len(),
            checkpoint_count,
            "Prepared batch insert transaction"
        );
    }

    tx.commit()?;
    tracing::debug!(
        entry_count = entries.len(),
        "Committed batch insert transaction"
    );
    Ok(entries.len())
}

fn is_transient_sqlite_lock(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<SqliteError>(),
            Some(SqliteError::SqliteFailure(sql_err, _))
                if matches!(sql_err.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    })
}

#[cfg(test)]
#[path = "ingest_tests.rs"]
mod tests;
