//! Per-stream last-seen rollup for stream-silence alerting.
//!
//! `stream_last_seen` (migration 43) holds one row per `(hostname,
//! source_kind)` with the newest `received_at` observed for that stream. The
//! notification evaluator refreshes it each cycle from a bounded window of
//! recent rows, then alerts on entries whose age crosses
//! `stream_silence_threshold_secs` — "this stream used to produce logs and
//! stopped". The logs table itself cannot answer that cheaply: source kind
//! lives inside `metadata_json`, so a direct newest-row-per-stream query
//! would scan and JSON-parse the whole window every cycle.
//!
//! The rollup tracks ALL kinds it observes; the alert query applies the
//! configured kind allowlist. Entries older than the forget horizon are
//! pruned so decommissioned streams stop being alert-eligible.

use anyhow::Result;
use rusqlite::Connection;

/// Window used to seed an empty rollup on the evaluator's first cycle.
/// Bounded so the one-time seed scan stays predictable; streams already
/// silent for longer than this at seed time never enter the rollup and
/// therefore never alert (documented tradeoff vs. a startup-blocking
/// backfill over the full retention window).
pub const STREAM_SEED_WINDOW_SECS: u64 = 86_400;

/// Classify a log row's source kind. Single source of truth shared with
/// `ingest_health::ingest_source_kind_health` — prefix-mapped synthetic
/// sources first, then the denormalised `metadata_json.source_kind`.
const SOURCE_KIND_CASE: &str = "CASE
        WHEN ai_transcript_path IS NOT NULL OR source_ip LIKE 'transcript://%' THEN 'transcript'
        WHEN source_ip LIKE 'docker://%' THEN 'docker-stream'
        WHEN source_ip LIKE 'docker-event://%' THEN 'docker-event'
        WHEN source_ip LIKE 'agent-command://%' THEN 'agent-command'
        WHEN source_ip LIKE 'shell-history://%' THEN 'shell-history'
        WHEN source_ip LIKE 'file-tail://%' THEN 'file-tail'
        WHEN source_ip LIKE 'agent-file-tail://%' THEN 'agent-file-tail'
        ELSE json_extract(metadata_json, '$.source_kind')
    END";

/// A stream that was active in the past but has gone silent.
#[derive(Debug, Clone)]
pub struct SilentStream {
    pub hostname: String,
    pub source_kind: String,
    pub last_seen_at: String,
    pub age_secs: u64,
}

/// True when the rollup has no rows yet (fresh migration) — the caller
/// should refresh with [`STREAM_SEED_WINDOW_SECS`] instead of the cycle
/// window.
pub fn stream_last_seen_is_empty(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM stream_last_seen", [], |row| {
        row.get(0)
    })?;
    Ok(count == 0)
}

/// Fold the newest `received_at` per `(hostname, source_kind)` from the last
/// `window_secs` seconds of logs into the rollup. Monotonic: a conflict only
/// moves `last_seen_at` forward, so overlapping or stale windows can never
/// regress an entry.
pub fn refresh_stream_last_seen(conn: &Connection, window_secs: u64) -> Result<usize> {
    let sql = format!(
        "INSERT INTO stream_last_seen (hostname, source_kind, last_seen_at)
         SELECT hostname, kind, MAX(received_at)
         FROM (
             SELECT hostname, {SOURCE_KIND_CASE} AS kind, received_at
             FROM logs
             WHERE received_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('-%d seconds', ?1))
         )
         WHERE kind IS NOT NULL AND kind != ''
         GROUP BY hostname, kind
         ON CONFLICT (hostname, source_kind) DO UPDATE SET
             last_seen_at = CASE
                 WHEN excluded.last_seen_at > stream_last_seen.last_seen_at
                 THEN excluded.last_seen_at
                 ELSE stream_last_seen.last_seen_at
             END"
    );
    let changed = conn.execute(&sql, rusqlite::params![window_secs as i64])?;
    Ok(changed)
}

/// Streams whose newest row is older than `threshold_secs` but younger than
/// `forget_secs`, restricted to the configured kind allowlist. The forget
/// bound keeps long-dead streams from re-alerting after every dedup window
/// until pruning catches up.
pub fn silent_streams(
    conn: &Connection,
    kinds: &[String],
    threshold_secs: u64,
    forget_secs: u64,
) -> Result<Vec<SilentStream>> {
    if kinds.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = (1..=kinds.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    // Threshold and forget are trusted u64 config values, inlined because
    // SQLite does not allow SELECT aliases in WHERE; the sender-controlled
    // kind strings stay bound as parameters.
    let age_expr = "CAST(strftime('%s','now') AS INTEGER) - \
                    CAST(strftime('%s', last_seen_at) AS INTEGER)";
    let sql = format!(
        "SELECT hostname, source_kind, last_seen_at, {age_expr} AS age_secs
         FROM stream_last_seen
         WHERE ({age_expr}) > {threshold_secs} AND ({age_expr}) < {forget_secs}
           AND source_kind IN ({placeholders})
         ORDER BY hostname ASC, source_kind ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(kinds.iter()), |row| {
            Ok(SilentStream {
                hostname: row.get(0)?,
                source_kind: row.get(1)?,
                last_seen_at: row.get(2)?,
                age_secs: row.get::<_, i64>(3)?.max(0) as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Drop rollup entries older than the forget horizon.
pub fn prune_stream_last_seen(conn: &Connection, forget_secs: u64) -> Result<usize> {
    let deleted = conn.execute(
        "DELETE FROM stream_last_seen
         WHERE CAST(strftime('%s','now') AS INTEGER) -
               CAST(strftime('%s', last_seen_at) AS INTEGER) >= ?1",
        rusqlite::params![forget_secs as i64],
    )?;
    Ok(deleted)
}

#[cfg(test)]
#[path = "stream_health_tests.rs"]
mod tests;
