use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::Result;
use rusqlite::{Error as SqliteError, ErrorCode, Transaction, params};

use super::models::LogBatchEntry;
use super::pool::DbPool;

pub(crate) const TRANSIENT_SQLITE_RETRY_DELAYS_MS: &[u64] = &[25, 100, 250];

/// Batch insert for higher throughput.
///
/// Keep the public API concrete so callers can pass `&[]` without type
/// annotations. The ingest writer uses the crate-private borrowed variant to
/// persist `IngestEnvelope` values without cloning their `LogBatchEntry`.
pub fn insert_logs_batch(pool: &DbPool, entries: &[LogBatchEntry]) -> Result<usize> {
    insert_logs_batch_borrowed(pool, entries)
}

pub(crate) fn insert_logs_batch_borrowed<T>(pool: &DbPool, entries: &[T]) -> Result<usize>
where
    T: Borrow<LogBatchEntry>,
{
    let mut attempt = 0usize;
    loop {
        match insert_logs_batch_once(pool, entries) {
            Ok(inserted) => return Ok(inserted),
            Err(err)
                if is_transient_sqlite_lock(&err)
                    && attempt < TRANSIENT_SQLITE_RETRY_DELAYS_MS.len() =>
            {
                let delay_ms = TRANSIENT_SQLITE_RETRY_DELAYS_MS[attempt];
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

fn insert_logs_batch_once<T>(pool: &DbPool, entries: &[T]) -> Result<usize>
where
    T: Borrow<LogBatchEntry>,
{
    let mut conn = crate::db::write_conn(pool)?;
    let tx = conn.transaction()?;
    insert_logs_batch_in_tx_with_ids(&tx, entries, None)?;
    tx.commit()?;
    if !entries.is_empty() {
        super::agent_observatory::notify_projection_work();
    }
    tracing::debug!(
        entry_count = entries.len(),
        "Committed batch insert transaction"
    );
    Ok(entries.len())
}

pub(crate) fn insert_logs_batch_in_tx<T>(tx: &Transaction<'_>, entries: &[T]) -> Result<Vec<i64>>
where
    T: Borrow<LogBatchEntry>,
{
    let mut ids = Vec::with_capacity(entries.len());
    insert_logs_batch_in_tx_with_ids(tx, entries, Some(&mut ids))?;
    Ok(ids)
}

fn insert_logs_batch_in_tx_with_ids<T>(
    tx: &Transaction<'_>,
    entries: &[T],
    mut ids: Option<&mut Vec<i64>>,
) -> Result<()>
where
    T: Borrow<LogBatchEntry>,
{
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (
                timestamp, hostname, facility, severity, app_name, process_id,
                message, raw, source_ip, ai_tool, ai_project, ai_session_id, ai_transcript_path,
                metadata_json, http_status, auth_outcome, dns_blocked, event_action, parse_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )?;

        for entry in entries {
            let entry = entry.borrow();
            stmt.execute(params![
                entry.timestamp,
                entry.hostname,
                entry.facility,
                entry.severity,
                entry.app_name,
                entry.process_id,
                entry.message,
                entry.raw,
                entry.source_ip,
                entry.ai_tool,
                entry.ai_project,
                entry.ai_session_id,
                entry.ai_transcript_path,
                entry.metadata_json,
                entry.http_status,
                entry.auth_outcome,
                entry.dns_blocked.map(|b| b as i64),
                entry.event_action,
                entry.parse_error,
            ])?;
            if let Some(ids) = ids.as_deref_mut() {
                ids.push(tx.last_insert_rowid());
            }
        }

        // Batch upsert hosts — group by hostname to avoid one upsert per log entry
        let mut host_counts: HashMap<&str, i64> = HashMap::new();
        for entry in entries {
            let entry = entry.borrow();
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
            let entry = entry.borrow();
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
    Ok(())
}

/// True only for SQLite BUSY/LOCKED — the conditions worth a short sleep and
/// an immediate in-thread retry.
///
/// Deliberately excludes r2d2 pool-acquisition timeouts even though those are
/// also transient: a pool timeout means every connection was busy for the full
/// `connection_timeout` (6s), so the retry ladder here would block a thread for
/// ~24s before giving up. Pool exhaustion is handled one layer up instead,
/// where the batch writer retains the batch and retries on a later flush. Use
/// `crate::db::is_pool_acquire_failure` for that classification.
pub(crate) fn is_transient_sqlite_lock(err: &anyhow::Error) -> bool {
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
