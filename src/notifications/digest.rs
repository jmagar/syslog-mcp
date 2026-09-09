//! Daily digest builder.
//!
//! Queries the last 24h of logs to produce a per-host summary, then inserts
//! a single outbox row with rule_id='daily_digest'.
//!
//! Scheduling: checks every 60s whether the configured digest hour/minute has
//! been reached and hasn't fired today. No cron crate needed.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

// Digest runs two aggregate queries over a 24h window — allow 5s before warning.
const SLOW_DB_MS: u128 = 5_000;

use crate::config::NotificationsConfig;
use crate::db::DbPool;
use crate::db::notifications::{
    AttemptCount, OutboxInsertParams, backoff_next_attempt_at, outbox_insert,
};
use crate::notifications::apprise::escape_for_notification;

/// Summary for one host in the digest.
#[derive(Debug, Clone)]
pub struct HostDigestEntry {
    pub hostname: String,
    pub total_logs: i64,
    pub error_count: i64,
    pub warning_count: i64,
    pub top_app: Option<String>,
}

/// Build a markdown digest body from per-host entries.
pub fn build_digest_body(entries: &[HostDigestEntry], window_hours: u32) -> String {
    if entries.is_empty() {
        return format!("No log activity in the last {window_hours}h.");
    }

    let mut lines = vec![format!("## Daily Digest — last {window_hours}h\n")];
    lines.push("| Host | Total | Errors | Warnings | Top App |".to_string());
    lines.push("|------|-------|--------|----------|---------|".to_string());

    for e in entries {
        let app = e.top_app.as_deref().unwrap_or("—");
        lines.push(format!(
            "| {} | {} | {} | {} | {} |",
            escape_for_notification(&e.hostname),
            e.total_logs,
            e.error_count,
            e.warning_count,
            escape_for_notification(app),
        ));
    }

    let total_errors: i64 = entries.iter().map(|e| e.error_count).sum();
    let total_warnings: i64 = entries.iter().map(|e| e.warning_count).sum();
    lines.push(String::new());
    lines.push(format!(
        "**{} hosts** — {} errors, {} warnings",
        entries.len(),
        total_errors,
        total_warnings
    ));

    lines.join("\n")
}

/// Fetch per-host stats for the last `window_hours` hours.
///
/// Uses a single query with a window function to find the top app per host,
/// avoiding the previous N+1 query pattern (one per-host subquery per host).
/// Requires SQLite 3.25+ (window function support).
pub fn fetch_host_stats(
    conn: &rusqlite::Connection,
    window_hours: u32,
) -> rusqlite::Result<Vec<HostDigestEntry>> {
    let window_secs = window_hours as i64 * 3600;

    // Fetch per-host totals + top_app in two queries (no N+1).
    // Query 1: per-host aggregate stats.
    let mut stmt = conn.prepare(
        "SELECT
             hostname,
             COUNT(*) AS total,
             SUM(CASE WHEN severity IN ('err','crit','alert','emerg') THEN 1 ELSE 0 END) AS errors,
             SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) AS warnings
         FROM logs
         WHERE received_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('-%d seconds', ?1))
         GROUP BY hostname
         ORDER BY total DESC
         -- Top 50 hosts by log volume. Sufficient for homelab scale.
         LIMIT 50",
    )?;
    let mut entries: Vec<HostDigestEntry> = stmt
        .query_map(rusqlite::params![window_secs], |row| {
            Ok(HostDigestEntry {
                hostname: row.get(0)?,
                total_logs: row.get(1)?,
                error_count: row.get(2)?,
                warning_count: row.get(3)?,
                top_app: None, // populated below
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    // Query 2: top app per host using a window function (SQLite 3.25+).
    // Returns one row per hostname with the highest-count app_name.
    let mut top_app_stmt = conn.prepare(
        "SELECT hostname, app_name
         FROM (
             SELECT hostname, app_name,
                    ROW_NUMBER() OVER (PARTITION BY hostname ORDER BY COUNT(*) DESC) AS rn
             FROM logs
             WHERE received_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('-%d seconds', ?1))
               AND app_name IS NOT NULL
             GROUP BY hostname, app_name
         )
         WHERE rn = 1",
    )?;
    // Collect into a HashMap for O(1) lookup when merging.
    let top_apps: std::collections::HashMap<String, String> = top_app_stmt
        .query_map(rusqlite::params![window_secs], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()?;

    for entry in &mut entries {
        entry.top_app = top_apps.get(&entry.hostname).cloned();
    }
    Ok(entries)
}

/// Build and enqueue a daily digest notification.
pub(crate) async fn run_digest(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    cfg: &NotificationsConfig,
) -> Result<()> {
    let Ok(_permit) = Arc::clone(&permit_sem).acquire_owned().await else {
        tracing::error!("digest: maintenance semaphore closed, skipping");
        return Ok(());
    };

    let apprise_urls_json =
        serde_json::to_string(&cfg.apprise_urls).unwrap_or_else(|_| "[]".to_string());

    let exec_start = Instant::now();
    let join_result = tokio::task::spawn_blocking(move || -> Result<()> {
        let conn = pool.get()?;
        let entries = fetch_host_stats(&conn, 24).map_err(anyhow::Error::from)?;
        let body = build_digest_body(&entries, 24);
        let title = format!(
            "Daily Digest — {} hosts, {} total logs",
            entries.len(),
            entries.iter().map(|e| e.total_logs).sum::<i64>()
        );

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let params = OutboxInsertParams {
            dedup_key: format!("daily_digest:{today}"),
            rule_id: "daily_digest".to_string(),
            severity: "info".to_string(),
            hostname: "all".to_string(),
            title,
            body,
            apprise_urls_json,
            next_attempt_at: backoff_next_attempt_at(AttemptCount::NONE),
        };
        outbox_insert(&conn, &params).map_err(anyhow::Error::from)?;
        tracing::info!(date = %today, "digest: daily digest queued");
        Ok(())
    })
    .await;
    let exec_ms = exec_start.elapsed().as_millis();
    let result = join_result.map_err(|e| anyhow::anyhow!("db task join error: {e}"))?;
    if exec_ms > SLOW_DB_MS {
        match &result {
            Ok(_) => tracing::warn!(op = "notif.digest_write", exec_ms, "db op ok"),
            Err(e) => tracing::warn!(op = "notif.digest_write", exec_ms, error = %e, "db op err"),
        }
    } else {
        match &result {
            Ok(_) => tracing::debug!(op = "notif.digest_write", exec_ms, "db op ok"),
            Err(e) => tracing::debug!(op = "notif.digest_write", exec_ms, error = %e, "db op err"),
        }
    }
    result?;

    Ok(())
}

/// Retryable failures tolerated inside one day's firing window.
///
/// The scheduler already wakes on minute boundaries and the window spans five
/// ticks (`minutes_diff <= 2`), so retries are paced at ~60s with no extra
/// sleeping. Bounding them at three keeps a persistently broken pool from
/// consuming the whole window and makes the give-up decision explicit.
/// Retrying is safe because `outbox_insert` is idempotent on the digest's
/// `daily_digest:<date>` dedup key, so a duplicate attempt cannot double-send.
const MAX_RETRYABLE_DIGEST_ATTEMPTS: u32 = 3;

/// What the scheduler should do after a failed digest attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestFailureAction {
    /// Leave the day open so the next minute tick tries again.
    Retry,
    /// Permanent failure, or the retry budget is spent: give up for today.
    SuppressForToday,
}

/// True when the failure is transient and another attempt today is worthwhile.
///
/// An r2d2 pool timeout means the statement never reached SQLite, so it never
/// downcasts to `rusqlite::Error`: a rusqlite-only predicate would misread a
/// 6s pool timeout as a permanent failure.
fn is_retryable_digest_error(error: &anyhow::Error) -> bool {
    crate::db::is_transient_sqlite_lock(error) || crate::db::is_pool_acquire_failure(error)
}

/// Decide whether a failed attempt keeps the day open or closes it.
///
/// `failed_attempts` counts today's failures including the current one.
fn digest_failure_action(error: &anyhow::Error, failed_attempts: u32) -> DigestFailureAction {
    if is_retryable_digest_error(error) && failed_attempts < MAX_RETRYABLE_DIGEST_ATTEMPTS {
        DigestFailureAction::Retry
    } else {
        DigestFailureAction::SuppressForToday
    }
}

/// Parse hour and minute from a cron string (fields 0 and 1).
/// Returns `(hour, minute)` or defaults `(8, 0)` on parse failure.
///
/// Only the first two fields of a 5-field cron expression are used.
fn parse_cron_hour_minute(cron: &str) -> (u32, u32) {
    let mut parts = cron.split_whitespace();
    let minute_field = parts.next();
    let hour_field = parts.next();

    let minute_parsed = minute_field.and_then(|s| s.parse::<u32>().ok());
    let hour_parsed = hour_field.and_then(|s| s.parse::<u32>().ok());

    if minute_parsed.is_none() {
        tracing::warn!(
            input = %cron,
            "digest_cron_local minute field missing or unparseable; defaulting to 0"
        );
    }
    if hour_parsed.is_none() {
        tracing::warn!(
            input = %cron,
            "digest_cron_local hour field missing or unparseable; defaulting to 8"
        );
    }

    let minute = minute_parsed.unwrap_or(0).min(59);
    let hour = hour_parsed.unwrap_or(8).min(23);
    (hour, minute)
}

/// Spawn the digest task.
///
/// Wakes every 60s and fires when the local clock matches the cron
/// hour:minute, at most once per calendar day.
///
/// Quiet hours are intentionally unsupported today. Config loading rejects
/// `[notifications.quiet_hours]` explicitly so operators cannot mistake this
/// planned policy for active behavior. Add the table only when
/// chrono-tz is available.
pub(crate) fn spawn_digest(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    cfg: NotificationsConfig,
    token: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let (target_hour, target_minute) = parse_cron_hour_minute(&cfg.digest_cron_local);
    let handle = tokio::spawn(async move {
        let mut last_fired_date: Option<chrono::NaiveDate> = None;
        // Retryable failures recorded for `retry_date`; both reset when the
        // calendar day rolls over so each day gets a fresh budget.
        let mut retry_date: Option<chrono::NaiveDate> = None;
        let mut failed_attempts: u32 = 0;
        loop {
            // Align sleep to the next minute boundary to avoid slowly drifting
            // away from the configured time. Uses a minimum of 100ms to prevent
            // tight loops near the boundary.
            let now = chrono::Local::now();
            let seconds_into_minute = now.second() as u64;
            let millis_into_second = now.timestamp_subsec_millis() as u64;
            let sleep_ms = if seconds_into_minute == 0 && millis_into_second == 0 {
                60_000u64
            } else {
                (60 - seconds_into_minute) * 1000 - millis_into_second
            };
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms.max(100))) => {}
            }

            let now = chrono::Local::now();
            let today = now.date_naive();
            let already_fired = last_fired_date == Some(today);
            let minutes_now = now.hour() * 60 + now.minute();
            let minutes_target = target_hour * 60 + target_minute;
            let minutes_diff = minutes_now.abs_diff(minutes_target);
            if !already_fired && minutes_diff <= 2 {
                match run_digest(Arc::clone(&pool), Arc::clone(&permit_sem), &cfg).await {
                    Ok(()) => last_fired_date = Some(today),
                    Err(e) => {
                        if retry_date != Some(today) {
                            retry_date = Some(today);
                            failed_attempts = 0;
                        }
                        failed_attempts += 1;
                        match digest_failure_action(&e, failed_attempts) {
                            DigestFailureAction::Retry => {
                                tracing::warn!(
                                    error = %e,
                                    attempt = failed_attempts,
                                    max_attempts = MAX_RETRYABLE_DIGEST_ATTEMPTS,
                                    "digest: transient failure, retrying on the next tick"
                                );
                            }
                            DigestFailureAction::SuppressForToday => {
                                tracing::error!(
                                    error = %e,
                                    attempt = failed_attempts,
                                    "digest: failed to build/queue daily digest"
                                );
                                // Give up for today: permanent failure, or the
                                // retry budget is spent.
                                last_fired_date = Some(today);
                            }
                        }
                    }
                }
            }
        }
    });
    Some(handle)
}

use chrono::Timelike;

#[cfg(test)]
#[path = "digest_tests.rs"]
mod tests;
