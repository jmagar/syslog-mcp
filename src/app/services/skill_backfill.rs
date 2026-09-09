//! `sessions skills backfill` — scans existing `logs` rows with `ai_tool IN
//! ('claude','codex')` and extracts/persists `ai_skill_events` for rows that
//! predate this phase's ingest-time wiring (`src/scanner.rs::flush_chunk`).
//!
//! Chunked scan-and-release: each chunk acquires a fresh pool connection,
//! processes up to `CHUNK_SIZE` rows, and drops the connection before
//! continuing — mirrors `purge_old_logs` in `src/db/maintenance.rs` so a
//! large historical backfill never starves the ingest writer of a pool
//! connection for more than one chunk's duration.
//!
//! **Eng review Fix 6**: unlike `purge_old_logs` (which DELETEs and
//! correctly holds `write_lock()`), `fetch_candidate_chunk` here is a pure
//! `SELECT` — WAL mode already gives readers a consistent snapshot without
//! the write lock, so it is NOT held around the fetch. Only
//! `insert_skill_events` (a real write) acquires the lock, and it does so
//! internally (see the DB layer).
//!
//! **Eng review Fix 7**: `limit` is hard-clamped to `[1, 1_000_000]` (an
//! operator/caller cannot drive an unbounded scan), and a process-wide
//! single-flight guard (`backfill_guard`) ensures only one backfill runs at
//! a time — a second concurrent call fails fast with `ServiceError::Busy`
//! instead of both holding a `run_db` semaphore permit for the whole
//! multi-chunk scan. The guard is service-scoped (not REST-scoped like
//! `api.rs`'s `SHARED_MAINTENANCE_PERMIT`) because this method is also
//! reachable from the CLI's local mode and MCP, neither of which goes
//! through `api.rs`.
//!
//! **Claude row recovery**: `logs.message` for a Claude row is
//! `claude::extract_message()`'s plain-text `content` extraction (e.g. "hi")
//! — it never carries the raw `attributionSkill`/`attributionPlugin` JSON
//! fields, unlike Codex where the transcript text itself (including the
//! `<skill><name>` tag) survives `scrub_ai_message` intact. The only place
//! that data still exists is the original JSONL file on disk, so Claude rows
//! are recovered by re-reading the specific source line (via the shared
//! `scanner::read_transcript_lines` helper, which applies the same bounded,
//! newline-delimited record semantics as the ingest path) located by the
//! persisted `ai_transcript_path` column and the `line_no` scanner.rs recorded
//! in `metadata_json` at ingest time. Rows whose source file or line can no
//! longer be located (deleted/rotated/legacy metadata predating `line_no`, or
//! a line now exceeding the record-size bound) are counted in
//! `source_unavailable` rather than treated as an error.
//!
//! **Idempotency caveat**: re-running the backfill is a no-op *only while the
//! source transcript files are unchanged*. Because the recovered `skill_name`
//! is part of the `ai_skill_events` uniqueness key and is re-derived from the
//! file on each run, editing a transcript line in place between runs can yield
//! a second, differently-named event for the same `log_id` (the `INSERT OR
//! IGNORE` sees a new key, not a conflict). Transcript files are append-only
//! in practice, so this is an edge case, but the "always safe to re-run" claim
//! is conditional on that. See the follow-up bead for optional content-hash
//! verification if this ever needs a hard guarantee.
//!
//! **Memory bound**: each recovered line is capped at `MAX_RECORD_SIZE_BYTES`
//! by the shared reader (oversized lines are skipped, not buffered), so no
//! single line can blow up memory. The per-chunk working set (`resolved`) is
//! *not* separately budgeted, so the theoretical transient ceiling is
//! `CHUNK_SIZE` recovered lines held at once — pathological only if a whole
//! chunk of rows each point at a distinct near-`MAX_RECORD_SIZE_BYTES` line.
//! Real transcript records are far smaller (KB-scale JSON), and `resolved` is
//! rebuilt-and-dropped per chunk (never accumulated across the run), so this
//! is bounded and self-freeing rather than a leak. A hard per-chunk byte
//! budget was considered and rejected: skipping over-budget rows would advance
//! `last_id` past them and drop them permanently (they are not truly
//! unavailable), so a correct cap would require dynamic chunk resizing — not
//! worth the complexity for an offline, single-flight, operator-triggered job.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use tokio::sync::Semaphore;

use crate::db::{DbPool, SkillEventInsert, insert_skill_events};
use crate::scanner::read_transcript_lines;
use crate::scanner::skill_events::{
    extract_claude_skill_events, extract_codex_skill_events_with_kind,
};

use super::super::models::{SkillBackfillRequest, SkillBackfillResult};
use super::super::time::parse_optional_timestamp;
use super::{CortexService, ServiceError, ServiceResult};

const CHUNK_SIZE: i64 = 2_000;

/// Eng review Fix 7: hard upper bound on `SkillBackfillRequest.limit`. Chosen
/// generously above any realistic single-host `logs` table size (millions of
/// rows would already be well past `CORTEX_MAX_DB_SIZE_MB`'s default 1024 MB
/// guard in practice) while still being a real, enforced ceiling rather than
/// "whatever the caller asks for" — closes the unbounded-scan DoS surface
/// now that this is a `pub` service method reachable from CLI/MCP/REST.
const MAX_BACKFILL_LIMIT: u64 = 1_000_000;

/// Eng review Fix 7: process-wide single-flight gate for
/// `backfill_skill_events`, mirroring the `SHARED_MAINTENANCE_PERMIT`
/// pattern in `src/api.rs` (`OnceLock<Arc<Semaphore>>` + `try_acquire_owned`)
/// but scoped to the service layer so CLI-local and MCP callers are covered
/// too, not just REST. A held permit means a backfill is in flight; a second
/// concurrent call observes `NoPermits` and returns `ServiceError::Busy`
/// immediately rather than queuing behind the first scan.
fn backfill_guard() -> Arc<Semaphore> {
    static GUARD: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(GUARD.get_or_init(|| Arc::new(Semaphore::new(1))))
}

struct CandidateRow {
    id: i64,
    ai_tool: String,
    ai_project: Option<String>,
    ai_session_id: Option<String>,
    hostname: String,
    timestamp: String,
    message: String,
    ai_transcript_path: Option<String>,
    metadata_json: Option<String>,
}

impl CortexService {
    pub async fn backfill_skill_events(
        &self,
        req: SkillBackfillRequest,
    ) -> ServiceResult<SkillBackfillResult> {
        let since = parse_optional_timestamp(req.since.as_deref(), "since")?;
        // Eng review Fix 7: hard clamp, not just a floor.
        let limit = req.limit.unwrap_or(10_000).clamp(1, MAX_BACKFILL_LIMIT);
        let dry_run = req.dry_run;

        // Eng review Fix 7: single-flight guard acquired BEFORE the run_db
        // call so a second concurrent caller never even queues for a DB
        // permit — it fails fast here instead.
        let _permit = backfill_guard()
            .try_acquire_owned()
            .map_err(|_| ServiceError::Busy("skill event backfill already running".into()))?;

        self.run_db("backfill_skill_events", move |pool| {
            run_backfill(pool, since.as_deref(), limit, dry_run)
        })
        .await
    }
}

fn run_backfill(
    pool: &DbPool,
    since: Option<&str>,
    limit: u64,
    dry_run: bool,
) -> Result<SkillBackfillResult> {
    let mut result = SkillBackfillResult {
        dry_run,
        ..Default::default()
    };
    let mut last_id = 0i64;
    let mut remaining = limit;

    loop {
        if remaining == 0 {
            result.truncated = true;
            break;
        }
        let chunk_limit = CHUNK_SIZE.min(remaining as i64).max(1);
        // Eng review Fix 6: no write_lock() here — this is a pure SELECT and
        // WAL mode already gives it a consistent snapshot. Holding the write
        // lock around a read needlessly serializes the backfill against the
        // live syslog ingest writer for zero correctness benefit.
        let conn = pool.get()?;
        let rows = fetch_candidate_chunk(&conn, since, last_id, chunk_limit)?;
        drop(conn); // release back to pool before per-row parse work + next chunk

        if rows.is_empty() {
            break;
        }
        last_id = rows.last().map(|r| r.id).unwrap_or(last_id);
        result.scanned += rows.len() as u64;
        remaining = remaining.saturating_sub(rows.len() as u64);

        // Resolve every Claude row's source line up front, grouped by file so
        // rows sharing a transcript file open and scan it once per chunk. Two
        // borrowed maps over `rows` (no owned-String clones): `row_source` maps
        // each row id to its `(path, line_no)`, and `wanted_by_file` collects
        // the distinct line numbers to pull from each file. See the "Claude row
        // recovery" note at the top of this file for why `row.message` can't be
        // used directly.
        let mut row_source: HashMap<i64, (&str, usize)> = HashMap::new();
        let mut wanted_by_file: HashMap<&str, HashSet<usize>> = HashMap::new();
        for row in &rows {
            if row.ai_tool != "claude" {
                continue;
            }
            match (
                row.ai_transcript_path.as_deref(),
                row.metadata_json.as_deref().and_then(line_no_from_metadata),
            ) {
                (Some(path), Some(line_no)) => {
                    row_source.insert(row.id, (path, line_no));
                    wanted_by_file.entry(path).or_default().insert(line_no);
                }
                _ => {
                    result.source_unavailable += 1;
                    tracing::debug!(
                        log_id = row.id,
                        "skill backfill: claude row missing ai_transcript_path/line_no metadata; unrecoverable"
                    );
                }
            }
        }
        let mut resolved: HashMap<(&str, usize), String> = HashMap::new();
        for (path, wanted) in &wanted_by_file {
            match read_transcript_lines(Path::new(*path), wanted) {
                Ok(lines) => {
                    for (line_no, text) in lines {
                        resolved.insert((*path, line_no), text);
                    }
                }
                Err(err) => {
                    // File gone/unreadable — every row wanting this file falls
                    // through to source_unavailable in the loop below.
                    tracing::debug!(
                        path = *path,
                        error = %err,
                        "skill backfill: could not read transcript file for claude row recovery"
                    );
                }
            }
        }

        let mut inserts = Vec::new();
        for row in &rows {
            let extracted = match row.ai_tool.as_str() {
                "claude" => {
                    let Some(&(path, line_no)) = row_source.get(&row.id) else {
                        // Already counted in `source_unavailable` above.
                        continue;
                    };
                    let Some(line_text) = resolved.get(&(path, line_no)) else {
                        result.source_unavailable += 1;
                        tracing::debug!(
                            log_id = row.id,
                            path,
                            line_no,
                            "skill backfill: transcript line unavailable (missing file or line out of range)"
                        );
                        continue;
                    };
                    // Cheap short-circuit on the actual raw JSON line (not
                    // the scrubbed `row.message`) before parsing.
                    if !line_text.contains("attributionSkill") {
                        continue;
                    }
                    match serde_json::from_str::<serde_json::Value>(line_text) {
                        Ok(value) => extract_claude_skill_events(&value),
                        Err(_) => {
                            result.parse_errors += 1;
                            continue;
                        }
                    }
                }
                "codex" => {
                    let metadata = row
                        .metadata_json
                        .as_deref()
                        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok());
                    let kind = metadata
                        .as_ref()
                        .and_then(|metadata| metadata.get("event_kind"))
                        .and_then(serde_json::Value::as_str);
                    extract_codex_skill_events_with_kind(&row.message, kind)
                }
                _ => continue,
            };
            for event in extracted {
                inserts.push(SkillEventInsert {
                    log_id: row.id,
                    ai_tool: row.ai_tool.clone(),
                    ai_project: row.ai_project.clone(),
                    ai_session_id: row.ai_session_id.clone(),
                    hostname: row.hostname.clone(),
                    timestamp: row.timestamp.clone(),
                    event,
                });
            }
        }

        if !dry_run && !inserts.is_empty() {
            let attempted = inserts.len() as u64;
            let inserted = insert_skill_events(pool, &inserts)? as u64;
            result.inserted += inserted;
            result.skipped_duplicates += attempted - inserted;
        }
        // Dry-run does not report a "would insert N" count — scanned /
        // parse_errors / source_unavailable are the only meaningful dry-run
        // signal per the CLI contract (`--dry-run` reports scanned rows and
        // parse errors without touching the table). Callers that need a
        // precise "would insert N" count should drop --dry-run.

        if (rows.len() as i64) < chunk_limit {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    Ok(result)
}

fn fetch_candidate_chunk(
    conn: &rusqlite::Connection,
    since: Option<&str>,
    last_id: i64,
    chunk_limit: i64,
) -> Result<Vec<CandidateRow>> {
    let (sql, bindings): (&str, Vec<rusqlite::types::Value>) = match since {
        Some(since) => (
            "SELECT id, ai_tool, ai_project, ai_session_id, hostname, timestamp, message,
                    ai_transcript_path, metadata_json
             FROM logs
             WHERE ai_tool IN ('claude', 'codex')
               AND id > ?1
               AND timestamp >= ?2
             ORDER BY id ASC
             LIMIT ?3",
            vec![
                rusqlite::types::Value::Integer(last_id),
                rusqlite::types::Value::Text(since.to_string()),
                rusqlite::types::Value::Integer(chunk_limit),
            ],
        ),
        None => (
            "SELECT id, ai_tool, ai_project, ai_session_id, hostname, timestamp, message,
                    ai_transcript_path, metadata_json
             FROM logs
             WHERE ai_tool IN ('claude', 'codex')
               AND id > ?1
             ORDER BY id ASC
             LIMIT ?2",
            vec![
                rusqlite::types::Value::Integer(last_id),
                rusqlite::types::Value::Integer(chunk_limit),
            ],
        ),
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bindings.iter()), |row| {
            Ok(CandidateRow {
                id: row.get(0)?,
                ai_tool: row.get(1)?,
                ai_project: row.get(2)?,
                ai_session_id: row.get(3)?,
                hostname: row.get(4)?,
                timestamp: row.get(5)?,
                message: row.get(6)?,
                ai_transcript_path: row.get(7)?,
                metadata_json: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Extract the `line_no` scanner.rs's `flush_chunk` records in `metadata_json`
/// at ingest time (`{"line_no": N, ...}`). `line_no` is 0-based, matching the
/// scanner's own counter (recorded before incrementing, starting from 0 for
/// the first line of a file), so it feeds directly into
/// `scanner::read_transcript_lines`. Returns `None` for legacy rows ingested
/// before this field existed, malformed JSON, a metadata blob truncated by
/// `bounded_metadata_json`'s size guard, or a `line_no` that doesn't fit in
/// `usize` (corrupt/adversarial value — routed to `source_unavailable` rather
/// than silently truncated).
fn line_no_from_metadata(metadata_json: &str) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_str(metadata_json).ok()?;
    usize::try_from(value.get("line_no")?.as_u64()?).ok()
}

#[cfg(test)]
#[path = "skill_backfill_tests.rs"]
mod tests;
