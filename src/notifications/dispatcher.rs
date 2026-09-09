//! Notification dispatcher — drains the outbox and delivers via Apprise.
//!
//! Runs on a 30-second cadence (configurable). Each cycle begins by *claiming*
//! a batch of up to [`CLAIM_LIMIT`] due rows in one statement: the claim is a
//! write, and it both consumes one attempt per row and stamps a
//! [`CLAIM_LEASE_SECS`](crate::db::notifications::CLAIM_LEASE_SECS) lease into
//! `next_attempt_at` so no concurrent or subsequent cycle picks the same row up
//! while delivery is in flight. Everything downstream therefore works from an
//! already-incremented counter, which is why the write-back helpers never touch
//! `attempt_count` again and why the dispatcher reasons in
//! [`AttemptCount`](crate::db::notifications::AttemptCount) rather than a bare
//! integer.
//!
//! Then, for each claimed row:
//!   1. Check dedup against notification_firings
//!   2. Check ack against error_signatures (for error_sig rules)
//!   3. POST to Apprise (5s timeout)
//!   4. Update outbox status
//!   5. Insert into notification_firings
//!
//! Those steps are fallible, and their failures are isolated *per row*: a row
//! that fails is logged and skipped, never propagated out of the cycle. That
//! isolation is load-bearing, not tidiness. Because the claim already spent an
//! attempt and leased every row in the batch, an error escaping mid-loop would
//! abandon each remaining row with an attempt burnt and a lease held, having
//! never attempted delivery once — so a run of failing cycles could dead-letter
//! alerts that were never sent.
//!
//! Backoff: 1s → 5s → 30s → 5min → 30min cap.
//! Dead-letter after 8 attempts.
//! 207 = partial success, mark sent, do NOT retry.
//! 424 = delivery failed, treat as permanent error (dead-letter).
//!
//! Security: NEVER log Apprise URLs.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::NotificationsConfig;
use crate::db::DbPool;
use crate::db::notifications::{
    FiringInsertParams, OutboxRow, backoff_next_attempt_at, firings_any_dedup_check,
    firings_insert, firings_recent_dedup_check, outbox_claim_pending, outbox_mark_dead,
    outbox_mark_dropped, outbox_mark_sent, outbox_schedule_retry,
};
use crate::notifications::apprise::{AppriseClient, AppriseError, NotifyType};

const CLAIM_LIMIT: i64 = 50;
const SLOW_DB_MS: u128 = 500;

/// Run a blocking read-only DB operation on a pooled connection.
///
/// Centralizes the `Arc::clone` + `spawn_blocking` + `pool.get()` boilerplate
/// for read-only operations that do not need a transaction.
async fn db_read<F, T>(pool: &Arc<DbPool>, op: &'static str, f: F) -> Result<T>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = Arc::clone(pool);
    run_timed(op, move || {
        let conn = pool.get()?;
        f(&conn)
    })
    .await
}

/// `spawn_blocking` + slow-op timing, shared by the three DB entry points here.
/// Each supplies its own acquisition; only that differs between them.
async fn run_timed<F, T>(op: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let exec_start = Instant::now();
    let join_result = tokio::task::spawn_blocking(f).await;
    let exec_ms = exec_start.elapsed().as_millis();
    let result = join_result.map_err(|e| anyhow::anyhow!("db task join error: {e}"))?;
    if exec_ms > SLOW_DB_MS {
        match &result {
            Ok(_) => tracing::warn!(op, exec_ms, "db op ok"),
            Err(e) => tracing::warn!(op, exec_ms, error = %e, "db op err"),
        }
    } else {
        match &result {
            Ok(_) => tracing::debug!(op, exec_ms, "db op ok"),
            Err(e) => tracing::debug!(op, exec_ms, error = %e, "db op err"),
        }
    }
    result
}

/// Like [`db_read`], but holds the process-wide write lock for the operation.
///
/// For single auto-committed writes that still return rows, so they cannot use
/// the unit-returning [`db_tx`]. `outbox_claim_pending` is the motivating case:
/// it is an `UPDATE ... RETURNING`, and `src/db/pool.rs` documents that every
/// write must take this guard so writers queue in-process rather than colliding
/// at the SQLite layer and burning their 5s `busy_timeout`.
///
/// Acquires through `db::write_conn`, so the lock is taken before the
/// connection — see its doc for why the other order pins a connection for the
/// whole queue wait. That is also why this cannot delegate to [`db_read`].
async fn db_write<F, T>(pool: &Arc<DbPool>, op: &'static str, f: F) -> Result<T>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = Arc::clone(pool);
    run_timed(op, move || {
        let conn = crate::db::write_conn(&pool)?;
        f(&conn)
    })
    .await
}

/// Run a blocking DB operation inside an explicit transaction.
///
/// Centralizes the `Arc::clone` + `spawn_blocking` + `pool.get()` +
/// `conn.transaction()` + `tx.commit()` boilerplate for multi-statement
/// writes that must be atomic.
async fn db_tx<F>(pool: &Arc<DbPool>, op: &'static str, f: F) -> Result<()>
where
    F: FnOnce(&rusqlite::Transaction<'_>) -> Result<()> + Send + 'static,
{
    let pool = Arc::clone(pool);
    run_timed(op, move || {
        let mut conn = crate::db::write_conn(&pool)?;
        let tx = conn.transaction()?;
        f(&tx)?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// What one claimed row's turn through the dispatcher produced.
enum RowOutcome {
    /// Delivered to Apprise and marked sent.
    Sent,
    /// Resolved without delivery — dropped, dead-lettered, or retry scheduled.
    Settled,
    /// The maintenance semaphore is closed; the whole cycle should stop.
    SemaphoreClosed,
}

/// Run one dispatcher cycle.
pub(crate) async fn run_dispatch_cycle(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    apprise: &AppriseClient,
    cfg: &NotificationsConfig,
) -> Result<u64> {
    // Claim pending rows. This is a WRITE — `outbox_claim_pending` is an
    // `UPDATE ... RETURNING` that leases the rows and consumes an attempt — so
    // it must serialize on the process-wide write lock like every other writer.
    let rows = db_write(&pool, "notif.claim_pending", |conn| {
        outbox_claim_pending(conn, CLAIM_LIMIT).map_err(anyhow::Error::from)
    })
    .await?;

    let mut dispatched = 0u64;
    let mut failed = 0u64;

    for row in &rows {
        match dispatch_row(&pool, &permit_sem, apprise, cfg, row).await {
            Ok(RowOutcome::Sent) => dispatched += 1,
            Ok(RowOutcome::Settled) => {}
            Ok(RowOutcome::SemaphoreClosed) => {
                tracing::error!("dispatcher: maintenance semaphore closed, aborting");
                break;
            }
            // Deliberately swallowed. The claim already spent this batch's
            // attempts and leased every row; propagating here would abandon
            // every row after this one with an attempt burnt and no delivery
            // attempted. The failed row keeps its lease and is reclaimed once
            // it expires.
            Err(e) => {
                failed += 1;
                tracing::error!(
                    row_id = row.id,
                    rule_id = %row.rule_id,
                    hostname = %row.hostname,
                    error = %e,
                    "dispatcher: row failed, continuing with the rest of the batch"
                );
            }
        }
    }

    if failed > 0 {
        tracing::warn!(
            failed,
            claimed = rows.len(),
            "dispatcher: cycle finished with failed rows"
        );
    }

    Ok(dispatched)
}

/// Deliver one claimed outbox row and record the result.
///
/// Every error path returns `Err` rather than aborting the batch; see the
/// module docs for why that distinction matters.
async fn dispatch_row(
    pool: &Arc<DbPool>,
    permit_sem: &Arc<Semaphore>,
    apprise: &AppriseClient,
    cfg: &NotificationsConfig,
    row: &OutboxRow,
) -> Result<RowOutcome> {
    // ----------------------------------------------------------------
    // Phase 1: acquire permit → run dedup + ack checks → drop permit.
    // The permit must NOT be held across the HTTP call (5s timeout).
    // ----------------------------------------------------------------
    let Ok(permit) = Arc::clone(permit_sem).acquire_owned().await else {
        return Ok(RowOutcome::SemaphoreClosed);
    };

    // --- Dedup check (within permit) ---
    let is_dedup = {
        let rule_id = row.rule_id.clone();
        let hostname = row.hostname.clone();
        let dedup_key = row.dedup_key.clone();
        let dedup_secs = cfg.dedup_window_secs;
        db_read(pool, "notif.dedup_check", move |conn| {
            if is_once_per_outage_rule(&rule_id) {
                firings_any_dedup_check(conn, &rule_id, &hostname, &dedup_key)
                    .map_err(anyhow::Error::from)
            } else {
                firings_recent_dedup_check(conn, &rule_id, &hostname, &dedup_key, dedup_secs)
                    .map_err(anyhow::Error::from)
            }
        })
        .await?
    };

    if is_dedup {
        let row_id = row.id;
        db_write(pool, "notif.mark_dropped", move |conn| {
            outbox_mark_dropped(conn, row_id, "dedup_suppressed")?;
            Ok(())
        })
        .await?;
        drop(permit);
        tracing::debug!(
            rule_id = %row.rule_id,
            hostname = %row.hostname,
            "dispatcher: suppressed (dedup)"
        );
        return Ok(RowOutcome::Settled);
    }

    // --- Check ack for error signature rules ---
    if row.rule_id == "unaddressed_error_signature" {
        // dedup_key = "error_sig:{hash}"
        if let Some(hash) = row.dedup_key.strip_prefix("error_sig:") {
            let hash_owned = hash.to_string();
            let normalizer_version = crate::app::error_detection::NORMALIZER_VERSION;
            let is_acked = db_read(pool, "notif.sig_acked_check", move |conn| {
                is_signature_acked(conn, &hash_owned, normalizer_version)
                    .map_err(anyhow::Error::from)
            })
            .await?;

            if is_acked {
                let row_id = row.id;
                db_write(pool, "notif.mark_dropped", move |conn| {
                    outbox_mark_dropped(conn, row_id, "error_signature_acked")?;
                    Ok(())
                })
                .await?;
                drop(permit);
                tracing::debug!(
                    rule_id = %row.rule_id,
                    hostname = %row.hostname,
                    "dispatcher: suppressed (error signature acked)"
                );
                return Ok(RowOutcome::Settled);
            }
        }
    }

    // Phase 1 complete — drop permit before the HTTP call.
    drop(permit);

    // ----------------------------------------------------------------
    // Phase 2: Deliver via Apprise — NO permit held during HTTP call.
    // ----------------------------------------------------------------

    // Parse the destination snapshot fail-closed. Malformed persisted data
    // must not be confused with the intentional `[]` compatibility case.
    let urls: Vec<String> = match serde_json::from_str(&row.apprise_urls_json) {
        Ok(urls) => urls,
        Err(error) => {
            tracing::error!(
                rule_id = %row.rule_id,
                error = %error,
                "dispatcher: invalid persisted apprise routing; dropping notification"
            );
            let Ok(permit3) = Arc::clone(permit_sem).acquire_owned().await else {
                return Ok(RowOutcome::SemaphoreClosed);
            };
            let row_id = row.id;
            db_write(pool, "notif.mark_dropped", move |conn| {
                outbox_mark_dropped(conn, row_id, "invalid_apprise_urls_json")?;
                Ok(())
            })
            .await?;
            drop(permit3);
            return Ok(RowOutcome::Settled);
        }
    };
    // Override with config URLs if outbox has empty list (e.g. from error scanner)
    let effective_urls = if urls.is_empty() {
        cfg.apprise_urls.clone()
    } else {
        urls
    };

    if effective_urls.is_empty() {
        tracing::warn!(
            rule_id = %row.rule_id,
            "dispatcher: no apprise URLs configured, dropping notification"
        );
        // Phase 3: re-acquire permit for DB write-back.
        let Ok(permit3) = Arc::clone(permit_sem).acquire_owned().await else {
            return Ok(RowOutcome::SemaphoreClosed);
        };
        let row_id = row.id;
        db_write(pool, "notif.mark_dropped", move |conn| {
            outbox_mark_dropped(conn, row_id, "no_apprise_urls")?;
            Ok(())
        })
        .await?;
        drop(permit3);
        return Ok(RowOutcome::Settled);
    }

    let notify_type = severity_to_notify_type(&row.severity);
    let delivery_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        apprise.notify(&effective_urls, &row.title, &row.body, notify_type),
    )
    .await;

    let row_id = row.id;
    let attempt_count = row.attempt_count;
    let rule_id = row.rule_id.clone();
    let severity = row.severity.clone();
    let hostname = row.hostname.clone();
    let dedup_key = row.dedup_key.clone();

    // ----------------------------------------------------------------
    // Phase 3: re-acquire permit → write outbox status + firing → drop.
    // ----------------------------------------------------------------
    let Ok(permit3) = Arc::clone(permit_sem).acquire_owned().await else {
        return Ok(RowOutcome::SemaphoreClosed);
    };

    match delivery_result {
        Ok(Ok(resp)) => {
            // Success (200/207)
            let sc = resp.status_code as i64;
            let (rid, sev, host, dk) = (
                rule_id.clone(),
                severity.clone(),
                hostname.clone(),
                dedup_key.clone(),
            );
            db_tx(pool, "notif.mark_sent", move |tx| {
                outbox_mark_sent(tx, row_id, Some(sc))?;
                firings_insert(
                    tx,
                    FiringInsertParams {
                        outbox_id: row_id,
                        rule_id: &rid,
                        severity: &sev,
                        hostname: &host,
                        status_code: Some(sc),
                        notes: None,
                        dedup_key: &dk,
                    },
                )?;
                Ok(())
            })
            .await?;
            drop(permit3);
            tracing::info!(
                rule_id = %rule_id,
                hostname = %hostname,
                status_code = resp.status_code,
                "dispatcher: notification sent"
            );
            Ok(RowOutcome::Sent)
        }
        Ok(Err(AppriseError::Permanent { code, .. })) => {
            // 4xx — dead-letter immediately
            let error_msg = format!("permanent HTTP {code}");
            let (rid, sev, host, dk) = (
                rule_id.clone(),
                severity.clone(),
                hostname.clone(),
                dedup_key.clone(),
            );
            db_tx(pool, "notif.mark_dead", move |tx| {
                outbox_mark_dead(tx, row_id, Some(code as i64), &error_msg)?;
                firings_insert(
                    tx,
                    FiringInsertParams {
                        outbox_id: row_id,
                        rule_id: &rid,
                        severity: &sev,
                        hostname: &host,
                        status_code: Some(code as i64),
                        notes: Some(&error_msg),
                        dedup_key: &dk,
                    },
                )?;
                Ok(())
            })
            .await?;
            drop(permit3);
            tracing::warn!(
                rule_id = %rule_id,
                hostname = %hostname,
                status_code = code,
                "dispatcher: permanent failure, dead-lettered"
            );
            Ok(RowOutcome::Settled)
        }
        transient_or_timeout => {
            // Extract a human-readable error string
            let error_msg = match &transient_or_timeout {
                Ok(Err(e)) => format!("{e}"),
                Err(_) => "timeout".to_string(),
                Ok(Ok(_)) => unreachable!("handled above"),
            };

            if attempt_count.consumed() >= cfg.max_retry_attempts {
                // Exhausted retries — dead-letter
                let dead_msg = format!("max retries: {error_msg}");
                let (rid, sev, host, dk) = (
                    rule_id.clone(),
                    severity.clone(),
                    hostname.clone(),
                    dedup_key.clone(),
                );
                db_tx(pool, "notif.mark_dead", move |tx| {
                    outbox_mark_dead(tx, row_id, None, &dead_msg)?;
                    firings_insert(
                        tx,
                        FiringInsertParams {
                            outbox_id: row_id,
                            rule_id: &rid,
                            severity: &sev,
                            hostname: &host,
                            status_code: None,
                            notes: Some(&dead_msg),
                            dedup_key: &dk,
                        },
                    )?;
                    Ok(())
                })
                .await?;
                drop(permit3);
                tracing::warn!(
                    rule_id = %rule_id,
                    hostname = %hostname,
                    attempts = attempt_count.consumed(),
                    "dispatcher: dead-lettered after max retries"
                );
            } else {
                // Transient — schedule retry with backoff (no firing inserted).
                // The tier comes from the pre-claim count, so the first retry
                // uses the 1s tier, not 5s.
                let next_at = backoff_next_attempt_at(attempt_count);
                let next_at_log = next_at.clone();
                let err_clone = error_msg.clone();
                db_write(pool, "notif.schedule_retry", move |conn| {
                    outbox_schedule_retry(conn, row_id, &next_at, &err_clone, None)?;
                    Ok(())
                })
                .await?;
                drop(permit3);
                tracing::debug!(
                    rule_id = %rule_id,
                    hostname = %hostname,
                    attempt = attempt_count.consumed(),
                    next_at = %next_at_log,
                    "dispatcher: scheduled retry"
                );
            }
            Ok(RowOutcome::Settled)
        }
    }
}

/// Check whether an error signature has been acknowledged in the database.
///
/// Returns `true` when the signature is found with a non-NULL `acknowledged_at`.
/// Returns `false` for not-found or un-acknowledged signatures.
fn is_signature_acked(
    conn: &rusqlite::Connection,
    dedup_key: &str,
    normalizer_version: i64,
) -> rusqlite::Result<bool> {
    use rusqlite::OptionalExtension;
    // .optional() converts "no rows" into None (as opposed to
    // Err(QueryReturnedNoRows)). The row's acknowledged_at column
    // is itself nullable, so we get Option<Option<String>>:
    // - None          → signature not found → not acked
    // - Some(None)    → found but acknowledged_at IS NULL → not acked
    // - Some(Some(_)) → found and acknowledged_at is set → acked
    let acked: Option<Option<String>> = conn
        .query_row(
            "SELECT acknowledged_at FROM error_signatures
             WHERE signature_hash = ?1 AND normalizer_version = ?2 LIMIT 1",
            rusqlite::params![dedup_key, normalizer_version],
            |row| row.get(0),
        )
        .optional()?;
    Ok(matches!(acked, Some(Some(_))))
}

fn severity_to_notify_type(severity: &str) -> NotifyType {
    match severity {
        "emerg" | "alert" | "crit" | "critical" => NotifyType::Failure,
        "err" | "error" | "warning" | "warn" => NotifyType::Warning,
        _ => NotifyType::Info,
    }
}

fn is_once_per_outage_rule(rule_id: &str) -> bool {
    matches!(rule_id, "heartbeat_silence" | "stream_silence")
}

/// Spawn the dispatcher task.
pub(crate) fn spawn_dispatcher(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    cfg: NotificationsConfig,
    token: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let apprise = AppriseClient::new(&cfg.apprise_url);
    let interval_secs = cfg.dispatcher_interval_secs;
    let handle = tokio::spawn(async move {
        let mut interval =
            crate::runtime::background_interval(tokio::time::Duration::from_secs(interval_secs));
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = interval.tick() => {}
            }
            tracing::debug!("notification_dispatcher: cycle starting");
            match run_dispatch_cycle(Arc::clone(&pool), Arc::clone(&permit_sem), &apprise, &cfg)
                .await
            {
                Ok(n) => tracing::debug!(dispatched = n, "notification_dispatcher: cycle complete"),
                Err(e) => {
                    tracing::error!(error = %e, "notification_dispatcher: cycle failed")
                }
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
