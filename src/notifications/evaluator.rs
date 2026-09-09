//! Periodic log evaluator — scans recent logs and applies alert rules.
//!
//! Runs on a 5-minute cadence (configurable via NotificationsConfig).
//! Each cycle fetches logs from the last evaluator window and feeds them
//! to each enabled rule function.
//!
//! MUST NOT be imported from src/syslog/, src/ingest.rs, or src/syslog/writer.rs.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

// Phase 1 scans up to 50,000 rows in one blocking call — allow 10s before warning.
const SLOW_EVAL_SCAN_MS: u128 = 10_000;
// Phase 2 inserts are bounded by matched rules (typically single-digit rows).
const SLOW_DB_MS: u128 = 500;

use crate::config::NotificationsConfig;
use crate::db::DbPool;
use crate::notifications::rules::{
    LogRow, evaluate_authelia_mfa_fail, evaluate_container_die_nonzero, evaluate_fail2ban_ban,
    evaluate_heartbeat_silence, evaluate_ingest_silence, evaluate_oom_kill,
    evaluate_stream_silence,
};

/// Run one evaluation cycle.
///
/// Phase 1 (no permit): fetch recent logs and evaluate rules in memory.
/// Phase 2 (permit held): insert matched rows into the notifications outbox.
///
/// Separating the two phases prevents the evaluator's DB read (fetching up to
/// 5000 rows) from blocking the maintenance semaphore across the entire cycle.
pub(crate) async fn run_evaluation_cycle(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    cfg: NotificationsConfig,
) -> Result<u64> {
    let apprise_urls_json = build_urls_json(&cfg);
    let window_secs = cfg.evaluators.evaluator_interval_secs * 2; // look back 2x interval

    // --- Phase 0: stream rollup maintenance (write — permit held) ------------
    // Fold the newest row per (hostname, source kind) from the recent window
    // into `stream_last_seen`, then prune entries past the forget horizon.
    // Runs BEFORE evaluation so silence checks see the freshest state — a
    // stream that resumed inside this window must not alert from its stale
    // rollup entry. On failure the stream rule is skipped for this cycle
    // rather than evaluated against stale data.
    let mut stream_rollup_ok = false;
    if cfg.evaluators.stream_silence {
        let Ok(_permit) = Arc::clone(&permit_sem).acquire_owned().await else {
            tracing::error!("evaluator: maintenance semaphore closed, skipping stream rollup");
            return Ok(0);
        };
        let pool_m = Arc::clone(&pool);
        let forget_secs = cfg.evaluators.silence_forget_secs;
        let exec_start = Instant::now();
        let rollup_result = tokio::task::spawn_blocking(move || -> Result<()> {
            let _permit = _permit;
            let conn = pool_m.get()?;
            let window = if crate::db::stream_health::stream_last_seen_is_empty(&conn)? {
                tracing::info!(
                    seed_window_secs = crate::db::stream_health::STREAM_SEED_WINDOW_SECS,
                    "stream_last_seen is empty; seeding from bounded window"
                );
                crate::db::stream_health::STREAM_SEED_WINDOW_SECS
            } else {
                window_secs
            };
            crate::db::stream_health::refresh_stream_last_seen(&conn, window)?;
            crate::db::stream_health::prune_stream_last_seen(&conn, forget_secs)?;
            Ok(())
        })
        .await;
        let exec_ms = exec_start.elapsed().as_millis();
        match rollup_result {
            Ok(Ok(())) => {
                stream_rollup_ok = true;
                if exec_ms > SLOW_DB_MS {
                    tracing::warn!(op = "notif.stream_rollup", exec_ms, "db op ok");
                } else {
                    tracing::debug!(op = "notif.stream_rollup", exec_ms, "db op ok");
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(op = "notif.stream_rollup", exec_ms, error = %e, "stream rollup failed; skipping stream_silence this cycle");
            }
            Err(e) => {
                tracing::warn!(op = "notif.stream_rollup", exec_ms, error = %e, "stream rollup join error; skipping stream_silence this cycle");
            }
        }
    }

    // --- Phase 1: fetch + evaluate (NO permit needed — read-only DB access) ---
    // Paginate in batches of 1,000 rows up to a 50,000 row total cap to avoid
    // truncating high-volume cycles at 5,000.
    const BATCH_SIZE: u64 = 1_000;
    const MAX_ROWS: u64 = 50_000;
    let pool_r = Arc::clone(&pool);
    let exec_start = Instant::now();
    let phase1_result = tokio::task::spawn_blocking(
        move || -> Result<Vec<crate::db::notifications::OutboxInsertParams>> {
            let conn = pool_r.get()?;

            let mut out = Vec::new();
            let mut offset: u64 = 0;
            loop {
                let rows = fetch_recent_logs(&conn, window_secs, BATCH_SIZE, offset)?;
                let is_last = rows.len() < BATCH_SIZE as usize;

                if cfg.evaluators.oom_kill {
                    out.extend(evaluate_oom_kill(&rows, &apprise_urls_json));
                }
                if cfg.evaluators.container_die_nonzero {
                    out.extend(evaluate_container_die_nonzero(&rows, &apprise_urls_json));
                }
                if cfg.evaluators.fail2ban_ban {
                    out.extend(evaluate_fail2ban_ban(&rows, &apprise_urls_json));
                }
                if cfg.evaluators.authelia_mfa_fail {
                    out.extend(evaluate_authelia_mfa_fail(&rows, &apprise_urls_json));
                }

                offset += BATCH_SIZE;
                if is_last || offset >= MAX_ROWS {
                    break;
                }
            }

            // Metric rule: ingest silence. Unlike the log-scan rules above it
            // needs the age of the newest row across the whole table, not the
            // recent window (a silent ingest pipeline has no recent rows at
            // all). MAX(received_at) is an O(1) reverse index probe.
            if cfg.evaluators.ingest_silence {
                let newest_row_age_secs = newest_row_age_secs(&conn)?;
                let hostname = crate::env::var("HOSTNAME").unwrap_or_else(|_| {
                    tracing::warn!("HOSTNAME env var not set; using 'localhost' for notification dedup keys — multi-host deployments may suppress alerts");
                    "localhost".to_string()
                });
                out.extend(evaluate_ingest_silence(
                    &hostname,
                    newest_row_age_secs,
                    cfg.evaluators.ingest_silence_threshold_secs,
                    &apprise_urls_json,
                ));
            }

            // Metric rule: heartbeat silence. O(hosts) scan of the
            // host_heartbeats_latest cache; threshold and forget bounds are
            // applied in SQL, so every returned host fires.
            if cfg.evaluators.heartbeat_silence {
                let stale = crate::db::stale_heartbeat_hosts(
                    &conn,
                    cfg.evaluators.heartbeat_silence_threshold_secs,
                    cfg.evaluators.silence_forget_secs,
                )?;
                for host in stale {
                    out.push(evaluate_heartbeat_silence(
                        &host.host_id,
                        &host.hostname,
                        &host.received_at,
                        host.age_secs,
                        cfg.evaluators.heartbeat_silence_threshold_secs,
                        &apprise_urls_json,
                    ));
                }
            }

            // Metric rule: stream silence. Reads the rollup phase 0 just
            // refreshed; skipped when the refresh failed so stale entries
            // cannot false-positive.
            if stream_rollup_ok {
                let silent = crate::db::stream_health::silent_streams(
                    &conn,
                    &cfg.evaluators.stream_silence_kinds,
                    cfg.evaluators.stream_silence_threshold_secs,
                    cfg.evaluators.silence_forget_secs,
                )?;
                for stream in silent {
                    out.push(evaluate_stream_silence(
                        &stream.hostname,
                        &stream.source_kind,
                        &stream.last_seen_at,
                        stream.age_secs,
                        cfg.evaluators.stream_silence_threshold_secs,
                        &apprise_urls_json,
                    ));
                }
            }
            drop(conn);
            Ok(out)
        },
    )
    .await;
    let exec_ms = exec_start.elapsed().as_millis();
    let phase1_inner = phase1_result.map_err(|e| anyhow::anyhow!("db task join error: {e}"))?;
    if exec_ms > SLOW_EVAL_SCAN_MS {
        match &phase1_inner {
            Ok(_) => tracing::warn!(op = "notif.eval_phase1_scan", exec_ms, "db op ok"),
            Err(e) => {
                tracing::warn!(op = "notif.eval_phase1_scan", exec_ms, error = %e, "db op err")
            }
        }
    } else {
        match &phase1_inner {
            Ok(_) => tracing::debug!(op = "notif.eval_phase1_scan", exec_ms, "db op ok"),
            Err(e) => {
                tracing::debug!(op = "notif.eval_phase1_scan", exec_ms, error = %e, "db op err")
            }
        }
    }
    let all_params = phase1_inner?;

    if all_params.is_empty() {
        return Ok(0);
    }

    // --- Phase 2: insert into outbox (permit held only during DB writes) ---
    let Ok(_permit) = Arc::clone(&permit_sem).acquire_owned().await else {
        tracing::error!("evaluator: maintenance semaphore closed, skipping inserts");
        return Ok(0);
    };

    let pool_w = Arc::clone(&pool);
    let exec_start = Instant::now();
    let phase2_result = tokio::task::spawn_blocking(move || -> Result<u64> {
        let _permit = _permit; // keep permit alive for the duration of the write block
        let conn = pool_w.get()?;
        let mut total = 0u64;
        for params in &all_params {
            match crate::db::notifications::outbox_insert(&conn, params) {
                Ok(()) => {
                    // INSERT OR IGNORE: only count actual inserts, not silent no-ops.
                    if conn.changes() > 0 {
                        total += 1;
                    }
                }
                Err(e) => tracing::warn!(
                    rule_id = %params.rule_id,
                    hostname = %params.hostname,
                    error = %e,
                    "evaluator: outbox_insert failed (non-fatal)"
                ),
            }
        }
        Ok(total)
    })
    .await;
    let exec_ms = exec_start.elapsed().as_millis();
    let phase2_inner = phase2_result.map_err(|e| anyhow::anyhow!("db task join error: {e}"))?;
    if exec_ms > SLOW_DB_MS {
        match &phase2_inner {
            Ok(_) => tracing::warn!(op = "notif.eval_phase2_insert", exec_ms, "db op ok"),
            Err(e) => {
                tracing::warn!(op = "notif.eval_phase2_insert", exec_ms, error = %e, "db op err")
            }
        }
    } else {
        match &phase2_inner {
            Ok(_) => tracing::debug!(op = "notif.eval_phase2_insert", exec_ms, "db op ok"),
            Err(e) => {
                tracing::debug!(op = "notif.eval_phase2_insert", exec_ms, error = %e, "db op err")
            }
        }
    }
    let count = phase2_inner?;

    Ok(count)
}

fn build_urls_json(cfg: &NotificationsConfig) -> String {
    serde_json::to_string(&cfg.apprise_urls).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to serialize apprise_urls — notifications will be dropped");
        "[]".to_string()
    })
}

/// Age in seconds of the newest row in `logs`, or `None` when the table is
/// empty. Served by a reverse probe of `idx_logs_received_at` — O(1).
fn newest_row_age_secs(conn: &rusqlite::Connection) -> rusqlite::Result<Option<u64>> {
    let age: Option<i64> = conn.query_row(
        "SELECT CAST(strftime('%s','now') AS INTEGER) -
                CAST(strftime('%s', MAX(received_at)) AS INTEGER)
         FROM logs",
        [],
        |row| row.get(0),
    )?;
    // Clock skew can make the newest row appear to be from the future;
    // clamp to 0 rather than reporting a huge unsigned wraparound.
    Ok(age.map(|a| a.max(0) as u64))
}

/// Fetch log rows from the last `window_secs` seconds for rule evaluation.
///
/// `limit` and `offset` enable pagination — callers should iterate until a
/// batch smaller than `limit` is returned (or a total row cap is reached).
fn fetch_recent_logs(
    conn: &rusqlite::Connection,
    window_secs: u64,
    limit: u64,
    offset: u64,
) -> rusqlite::Result<Vec<LogRow>> {
    let mut stmt = conn.prepare(
        "SELECT app_name, message, hostname, metadata_json, timestamp
         FROM logs
         WHERE received_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('-%d seconds', ?1))
         ORDER BY received_at DESC
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt
        .query_map(
            rusqlite::params![window_secs as i64, limit as i64, offset as i64],
            |row| {
                Ok(LogRow {
                    app_name: row.get(0)?,
                    message: row.get(1)?,
                    hostname: row.get(2)?,
                    metadata_json: row.get(3)?,
                    timestamp: row.get(4)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Spawn the evaluator task. Returns None if notifications are disabled.
pub(crate) fn spawn_evaluator(
    pool: Arc<DbPool>,
    permit_sem: Arc<Semaphore>,
    cfg: NotificationsConfig,
    token: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let interval_secs = cfg.evaluators.evaluator_interval_secs;
    let handle = tokio::spawn(async move {
        let mut interval =
            crate::runtime::background_interval(tokio::time::Duration::from_secs(interval_secs));
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = interval.tick() => {}
            }
            tracing::debug!("notification_evaluator: cycle starting");
            match run_evaluation_cycle(Arc::clone(&pool), Arc::clone(&permit_sem), cfg.clone())
                .await
            {
                Ok(n) => tracing::info!(queued = n, "notification_evaluator: cycle complete"),
                Err(e) => tracing::error!(
                    error = %e,
                    "notification_evaluator: cycle failed"
                ),
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
#[path = "evaluator_tests.rs"]
mod tests;
