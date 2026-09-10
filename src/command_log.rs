use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::LazyLock;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::db::{self, LogBatchEntry};
use crate::enrich::{SourceKind, stamp_source_kind};
use crate::ingest_metadata::bounded_metadata_json;
use crate::receiver::enrichment::scrub_ai_message;

static COMMAND_SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r#"(?i)\bAuthorization:\s*Bearer\s+['"]?[^'"\s]+"#,
        r#"(?i)(?:^|\s)(?:--?(?:api[-_]?key|token|secret|password|passwd|client[-_]?secret))=("[^"]*"|'[^']*'|[^\s]+)"#,
        r#"(?i)(?:^|\s)(?:--?(?:api[-_]?key|token|secret|password|passwd|client[-_]?secret))\s+("[^"]*"|'[^']*'|[^\s]+)"#,
        r#"(?i)\b(?:[A-Z_][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|PWD|AUTH)[A-Z0-9_]*)=("[^"]*"|'[^']*'|[^\s]+)"#,
        r#"(?i)\bcurl\s+-u\s+("[^"]*"|'[^']*'|[^\s]+)"#,
        r#"(?i)\bhttps?://[^/\s:@]+:[^/\s@]+@"#,
        r#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#,
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).expect("static command secret regex"))
    .collect()
});

/// Truncate a string to at most `max` bytes, respecting UTF-8 char boundaries.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandLogImportResult {
    pub scanned: usize,
    pub imported: usize,
    pub skipped: usize,
    pub skipped_duplicates: usize,
    pub errors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZshHistoryRecord {
    pub started_at: DateTime<Utc>,
    pub duration_secs: u64,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentCommandSpoolRecord {
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub exit_status: Option<i32>,
    pub command: String,
    pub cwd: Option<String>,
    pub agent: String,
    pub command_surface: Option<String>,
    pub hostname: String,
    pub user: Option<String>,
    pub pid: u32,
    pub session_id: Option<String>,
    #[serde(default = "schema_version_one")]
    pub schema_version: u32,
    #[serde(default)]
    pub content_scrubbed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct ShellHistoryImportState {
    path: String,
    shell: String,
    offset: u64,
    #[serde(default)]
    line_no: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct AtuinHistoryImportState {
    path: String,
    last_timestamp_ns: i64,
    #[serde(default)]
    last_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AtuinHistoryRecord {
    id: String,
    timestamp_ns: i64,
    duration_ns: i64,
    exit_status: i64,
    command: String,
    cwd: String,
    session: String,
    hostname: String,
    author: Option<String>,
    intent: Option<String>,
}

pub fn import_zsh_history(
    pool: &db::DbPool,
    path: &Path,
    shell: &str,
) -> Result<CommandLogImportResult> {
    let state_path = shell_history_state_path(path, shell)?;
    import_zsh_history_with_state(pool, path, shell, &state_path)
}

fn import_zsh_history_with_state(
    pool: &db::DbPool,
    path: &Path,
    shell: &str,
    state_path: &Path,
) -> Result<CommandLogImportResult> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open shell history {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("stat shell history {}", path.display()))?
        .len();
    let mut state = read_shell_history_state(state_path, path, shell)?.unwrap_or_default();
    if state.offset > file_len {
        state.offset = 0;
        state.line_no = 0;
    }
    file.seek(SeekFrom::Start(state.offset))
        .with_context(|| format!("seek shell history {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let hostname = hostname();
    let user = username();
    let mut result = CommandLogImportResult::default();
    let mut batch = Vec::new();
    let mut line = String::new();
    let mut line_no = state.line_no;

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .with_context(|| format!("read shell history {}", path.display()))?;
        if bytes == 0 {
            break;
        }
        result.scanned += 1;
        line_no += 1;
        let line = line.trim_end_matches(['\r', '\n']);
        let Some(record) = parse_zsh_extended_history_line(line) else {
            result.skipped += 1;
            continue;
        };
        let entry = zsh_record_to_entry(&record, path, line_no, shell, &hostname, user.as_deref());
        if entry_exists(pool, &entry)? {
            result.skipped_duplicates += 1;
        } else {
            batch.push(entry);
        }
    }

    let next_offset = reader
        .stream_position()
        .with_context(|| format!("tell shell history {}", path.display()))?;
    if !batch.is_empty() {
        result.imported = db::insert_logs_batch(pool, &batch)?;
    }
    write_shell_history_state(state_path, path, shell, next_offset, line_no)?;
    Ok(result)
}

pub fn import_atuin_history(pool: &db::DbPool, path: &Path) -> Result<CommandLogImportResult> {
    let state_path = atuin_history_state_path(path)?;
    import_atuin_history_with_state(pool, path, &state_path)
}

fn import_atuin_history_with_state(
    pool: &db::DbPool,
    path: &Path,
    state_path: &Path,
) -> Result<CommandLogImportResult> {
    let state = read_atuin_history_state(state_path, path)?.unwrap_or_default();
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("open atuin history {}", path.display()))?;
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, duration, exit, command, cwd, session, hostname, author, intent
             FROM history
             WHERE deleted_at IS NULL
               AND (timestamp > ?1 OR (timestamp = ?1 AND id > ?2))
             ORDER BY timestamp ASC, id ASC",
        )
        .with_context(|| format!("prepare atuin history query {}", path.display()))?;
    let records = stmt
        .query_map((&state.last_timestamp_ns, &state.last_id), |row| {
            Ok(AtuinHistoryRecord {
                id: row.get(0)?,
                timestamp_ns: row.get(1)?,
                duration_ns: row.get(2)?,
                exit_status: row.get(3)?,
                command: row.get(4)?,
                cwd: row.get(5)?,
                session: row.get(6)?,
                hostname: row.get(7)?,
                author: row.get(8)?,
                intent: row.get(9)?,
            })
        })
        .with_context(|| format!("read atuin history {}", path.display()))?;

    let user = username();
    let mut result = CommandLogImportResult::default();
    let mut batch = Vec::new();
    let mut last_timestamp_ns = state.last_timestamp_ns;
    let mut last_id = state.last_id;
    for record in records {
        let record = record.with_context(|| format!("decode atuin history {}", path.display()))?;
        result.scanned += 1;
        last_timestamp_ns = record.timestamp_ns;
        last_id = record.id.clone();
        let Some(entry) = atuin_record_to_entry(&record, path, user.as_deref()) else {
            tracing::warn!(
                record_id = %record.id,
                timestamp_ns = record.timestamp_ns,
                "atuin record has out-of-range timestamp; skipping"
            );
            result.errors += 1;
            continue;
        };
        if entry_exists(pool, &entry)? {
            result.skipped_duplicates += 1;
        } else {
            batch.push(entry);
        }
    }

    if !batch.is_empty() {
        result.imported = db::insert_logs_batch(pool, &batch)?;
    }
    write_atuin_history_state(state_path, path, last_timestamp_ns, &last_id)?;
    Ok(result)
}

struct ParsedAgentCommandSpool {
    records: Vec<AgentCommandSpoolRecord>,
    scanned: usize,
    skipped: usize,
    errors: usize,
}

fn parse_agent_command_spool_lines(reader: impl BufRead) -> ParsedAgentCommandSpool {
    let mut parsed = ParsedAgentCommandSpool {
        records: Vec::new(),
        scanned: 0,
        skipped: 0,
        errors: 0,
    };
    for line in reader.lines() {
        parsed.scanned += 1;
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                tracing::warn!(
                    line = parsed.scanned,
                    error_kind = "io",
                    error = %e,
                    "failed to read line from agent command spool"
                );
                parsed.errors += 1;
                continue;
            }
        };
        if line.trim().is_empty() {
            parsed.skipped += 1;
            continue;
        }
        match serde_json::from_str::<AgentCommandSpoolRecord>(&line) {
            Ok(record) => parsed.records.push(record),
            Err(e) => {
                tracing::warn!(
                    line = parsed.scanned,
                    error_kind = "json",
                    error = %e,
                    line_preview = %truncate_utf8(&line, 80),
                    "failed to parse agent command spool record"
                );
                parsed.errors += 1;
            }
        }
    }
    parsed
}

/// Dedupes `records` against existing rows and inserts the remainder.
/// Shared by the local file-based import below and the server-side handler
/// in `agent_command_ingest.rs` that receives a forwarded batch over HTTP.
///
/// `forwarded_from_peer`: **engineering-review addition.** When `Some`, every
/// inserted row's `metadata_json` gets a `forwarded_from_peer_ip` field set
/// to this value. The rest of each record (`hostname`, `agent`,
/// `session_id`, which feed `source_ip`/`app_name`/`ai_tool`) remains fully
/// client-claimed and unverified — same as the pre-existing local-only
/// behavior — but recording the actual verified TCP peer alongside it means
/// a forged `hostname`/`agent` claim can be cross-referenced against which
/// token/peer really sent it, which local-only ingest never needed but the
/// network-reachable forwarding path (Task 13) does. Local callers
/// (`import_agent_command_spool` below) pass `None` — there's no remote peer
/// to record for a locally-read spool file.
pub fn import_agent_command_records(
    pool: &db::DbPool,
    records: &[AgentCommandSpoolRecord],
    forwarded_from_peer: Option<&str>,
) -> Result<CommandLogImportResult> {
    let mut result = CommandLogImportResult::default();
    if records.is_empty() {
        return Ok(result);
    }

    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let mut entry = agent_record_to_entry(record);
        if let Some(peer_ip) = forwarded_from_peer {
            annotate_forwarded_peer(&mut entry, peer_ip);
        }
        entries.push(entry);
    }

    // Engineering-review fix: one dedupe query for the whole batch instead of
    // one `SELECT COUNT(*)` per record. The original per-record loop was a
    // check-then-insert race even within a single batch (two identical
    // records both check "not present" before either inserts) and, now that
    // `/v1/agent-commands` exposes this path over the network to repeatedly-
    // retrying satellite hosts, an O(n) query-per-record cost that scales
    // with untrusted batch size rather than a fixed per-request cost.
    let existing = existing_entry_keys(pool, &entries)?;
    let mut seen_in_batch = std::collections::HashSet::new();
    let mut batch = Vec::new();
    for entry in entries {
        let key = (
            entry.source_ip.clone(),
            entry.timestamp.clone(),
            entry.message.clone(),
        );
        if existing.contains(&key) || !seen_in_batch.insert(key) {
            result.skipped_duplicates += 1;
        } else {
            batch.push(entry);
        }
    }
    if !batch.is_empty() {
        result.imported = db::insert_logs_batch(pool, &batch)?;
    }
    Ok(result)
}

/// Returns the `(source_ip, timestamp, message)` dedupe keys already present
/// in `logs` for any row that could possibly collide with `entries` — one
/// query for the whole batch, narrowed by `source_ip IN (...)` plus the
/// batch's timestamp range so it uses the existing
/// `idx_logs_source_ip_timestamp` index rather than scanning full history
/// for each distinct `source_ip`. Exact three-column matching happens
/// in-process against the returned candidate set, since SQLite has no
/// convenient multi-column `IN` syntax for the exact-tuple check.
fn existing_entry_keys(
    pool: &db::DbPool,
    entries: &[LogBatchEntry],
) -> Result<std::collections::HashSet<(String, String, String)>> {
    let mut source_ips: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        if seen.insert(entry.source_ip.as_str()) {
            source_ips.push(entry.source_ip.as_str());
        }
    }
    let min_ts = entries
        .iter()
        .map(|e| e.timestamp.as_str())
        .min()
        .unwrap_or_default();
    let max_ts = entries
        .iter()
        .map(|e| e.timestamp.as_str())
        .max()
        .unwrap_or_default();

    let conn = pool.get()?;
    let placeholders = std::iter::repeat_n("?", source_ips.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT source_ip, timestamp, message FROM logs \
         WHERE source_ip IN ({placeholders}) AND timestamp >= ? AND timestamp <= ?"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<&dyn rusqlite::ToSql> = source_ips
        .iter()
        .map(|ip| ip as &dyn rusqlite::ToSql)
        .collect();
    params.push(&min_ts);
    params.push(&max_ts);
    let rows = stmt.query_map(params.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut keys = std::collections::HashSet::new();
    for row in rows {
        keys.insert(row?);
    }
    Ok(keys)
}

/// Merges a `forwarded_from_peer_ip` field into an already-built entry's
/// `metadata_json`, preserving whatever `agent_record_to_entry` already put
/// there. `metadata_json` is always `Some` coming out of
/// `agent_record_to_entry` (it always calls `bounded_metadata_json`), so the
/// `unwrap_or_default` here is defensive only.
fn annotate_forwarded_peer(entry: &mut LogBatchEntry, peer_ip: &str) {
    let mut value: serde_json::Value = entry
        .metadata_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "forwarded_from_peer_ip".to_string(),
            serde_json::Value::String(peer_ip.to_string()),
        );
    }
    entry.metadata_json = Some(bounded_metadata_json(value));
}

pub fn import_agent_command_spool(
    pool: &db::DbPool,
    path: &Path,
) -> Result<CommandLogImportResult> {
    validate_spool_path_for_read(path)?;
    let mut file = open_spool_for_update(path)?;
    lock_file_exclusive(&file, path)?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seek agent command spool {}", path.display()))?;
    let parsed = parse_agent_command_spool_lines(BufReader::new(&mut file));
    let mut result = import_agent_command_records(pool, &parsed.records, None)?;
    result.scanned = parsed.scanned;
    result.skipped += parsed.skipped;
    result.errors += parsed.errors;
    file.set_len(0)
        .with_context(|| format!("truncate agent command spool {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind agent command spool {}", path.display()))?;
    Ok(result)
}

/// Reads and truncates the on-disk agent-command spool the same way
/// [`import_agent_command_spool`] does, but POSTs the parsed records to a
/// remote Cortex's `/v1/agent-commands` endpoint instead of writing to a
/// local `DbPool`. Truncates only after the remote POST succeeds, so a
/// network failure leaves the spool intact for the next attempt — mirroring
/// the heartbeat agent's retry-safe POST-then-truncate pattern in
/// `heartbeat_agent.rs`.
///
/// **Engineering-review addition:** the client has an explicit 30s request
/// timeout (`heartbeat_agent.rs`'s client now carries the same timeout).
/// Without this, a remote Cortex that's *hung* rather than down would block
/// the CLI invocation indefinitely with no feedback.
///
/// **Engineering-review fix:** the exclusive spool lock is held only for the
/// two brief local file operations (initial read, final consume-or-splice),
/// NOT across the network POST. An earlier version held the lock via a
/// single open `File` spanning the whole `.await` chain, including the
/// timeout — since `ingest shell agent wrap` also takes this same lock to
/// append each new command record, a slow-but-not-dead remote (up to the 30s
/// timeout) would have stalled every concurrent wrapped shell command on the
/// host for the duration of one forward attempt. Releasing the lock before
/// the POST and re-acquiring it only to consume what was actually forwarded
/// (see [`consume_forwarded_spool_prefix`]) fixes that without losing
/// records appended to the spool while the POST was in flight.
/// Per-request cap on how much of the spool a single forward chunk reads,
/// safely under the server's `AGENT_COMMAND_BODY_LIMIT_BYTES` (1 MiB) once
/// JSON-serialized. A spool that's accumulated a large backlog (e.g. the
/// forwarder was never running, or the host was offline for a while) is
/// drained over several chunks/loop iterations instead of failing outright
/// with `413 Payload Too Large` on one oversized POST.
const FORWARD_CHUNK_MAX_BYTES: u64 = 512 * 1024;

pub async fn forward_agent_command_spool(
    path: &Path,
    target: &str,
    token: Option<&str>,
) -> Result<CommandLogImportResult> {
    validate_spool_path_for_read(path)?;

    let url = agent_command_forward_url(target)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build agent-command forwarding reqwest::Client")?;
    let mut total = CommandLogImportResult::default();
    loop {
        let (parsed, chunk_bytes, reached_eof) = {
            let mut file = open_spool_for_update(path)?;
            lock_file_exclusive(&file, path)?;
            file.seek(SeekFrom::Start(0))
                .with_context(|| format!("seek agent command spool {}", path.display()))?;
            read_spool_chunk(&mut file, FORWARD_CHUNK_MAX_BYTES)?
            // `file` drops here, releasing the exclusive lock before any network I/O.
        };
        if chunk_bytes == 0 {
            break;
        }
        total.scanned += parsed.scanned;
        total.skipped += parsed.skipped;
        total.errors += parsed.errors;

        if parsed.records.is_empty() {
            // The chunk contained only malformed/skipped lines — still
            // consume it so a persistently bad prefix doesn't wedge the loop.
            consume_forwarded_spool_prefix(path, chunk_bytes)?;
            continue;
        }

        let mut request = client.post(&url).json(&parsed.records);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .context("agent command forward POST failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Don't consume this chunk — leave it in the spool to retry next
            // time, same as any other mid-loop failure below.
            bail!("agent command forward POST returned {status}: {body}");
        }
        let remote: CommandLogImportResult = response
            .json()
            .await
            .context("agent command forward response was not valid JSON")?;
        total.imported += remote.imported;
        total.skipped_duplicates += remote.skipped_duplicates;
        total.errors += remote.errors;

        consume_forwarded_spool_prefix(path, chunk_bytes)?;

        if reached_eof {
            break;
        }
    }

    Ok(total)
}

/// Read up to `max_bytes` from the start of `file`, snapped back to the last
/// complete line so a chunk never splits a record mid-line, and parse those
/// lines. Returns the parsed records, the exact byte length consumed (`0` if
/// the spool is empty — the caller passes this to
/// [`consume_forwarded_spool_prefix`] after a successful forward), and
/// whether this read reached EOF (fewer than `max_bytes` were available,
/// meaning the *unsnapped* read exhausted the file — the snapped/consumed
/// length alone can't signal this, since snapping to the last newline makes
/// a full chunk read slightly shorter than `max_bytes` too).
fn read_spool_chunk(
    file: &mut fs::File,
    max_bytes: u64,
) -> Result<(ParsedAgentCommandSpool, u64, bool)> {
    let mut buf = Vec::with_capacity(max_bytes as usize);
    file.take(max_bytes)
        .read_to_end(&mut buf)
        .with_context(|| "read agent command spool chunk".to_string())?;
    let reached_eof = (buf.len() as u64) < max_bytes;
    if buf.is_empty() {
        return Ok((
            ParsedAgentCommandSpool {
                records: Vec::new(),
                scanned: 0,
                skipped: 0,
                errors: 0,
            },
            0,
            reached_eof,
        ));
    }
    // Snap to the last full line: if the read hit EOF before filling the
    // cap, the whole buffer is a complete set of lines (the spool is always
    // newline-terminated by the appender). Otherwise, trim back to the last
    // '\n' so a chunk boundary never bisects a record.
    let consumed = if reached_eof {
        buf.len()
    } else {
        match buf.iter().rposition(|&b| b == b'\n') {
            Some(idx) => idx + 1,
            // No newline anywhere in a full-size chunk: a single line
            // exceeds the chunk cap. Fall back to consuming the whole
            // buffer rather than looping forever on an unsplittable line.
            None => buf.len(),
        }
    };
    let parsed = parse_agent_command_spool_lines(BufReader::new(&buf[..consumed]));
    Ok((parsed, consumed as u64, reached_eof))
}

/// Poll `spool_path` forever, forwarding new agent-command records to
/// `target` every `interval` and logging what shipped. Runs as one more
/// supervised stream inside `cortex agent`, alongside AI-transcript
/// forwarding — the spool otherwise only drains via a manual
/// `cortex shell agent index --server` invocation, which nothing was
/// actually scheduling (see bead: agent-forwarded AI transcript ingestion).
///
/// Never returns except on error, matching the other agent streams'
/// contract with `run_agent_streams`'s outer restart-on-error wrapper.
pub async fn run_agent_command_forward_loop(
    spool_path: PathBuf,
    target: String,
    token: Option<String>,
    interval: std::time::Duration,
) -> Result<()> {
    loop {
        match forward_agent_command_spool(&spool_path, &target, token.as_deref()).await {
            Ok(result) if result.imported > 0 || result.errors > 0 => {
                tracing::info!(
                    imported = result.imported,
                    skipped_duplicates = result.skipped_duplicates,
                    errors = result.errors,
                    "agent command spool forward: batch sent"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "agent command spool forward failed"
                );
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// Removes the first `original_len` bytes (everything already forwarded)
/// from the spool, preserving any bytes appended after the original read —
/// e.g. by a concurrent `ingest shell agent wrap` invocation while the
/// network POST above was in flight. Re-acquires the exclusive lock only for
/// this brief local operation.
fn consume_forwarded_spool_prefix(path: &Path, original_len: u64) -> Result<()> {
    let mut file = open_spool_for_update(path)?;
    lock_file_exclusive(&file, path)?;
    let current_len = file
        .metadata()
        .with_context(|| format!("stat agent command spool {}", path.display()))?
        .len();
    if current_len <= original_len {
        // Nothing new was appended (or something else already drained it) —
        // safe to truncate fully.
        file.set_len(0)
            .with_context(|| format!("truncate agent command spool {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("rewind agent command spool {}", path.display()))?;
        return Ok(());
    }
    // New records were appended after we read `original_len` bytes — keep
    // only that tail.
    let mut tail = Vec::with_capacity((current_len - original_len) as usize);
    file.seek(SeekFrom::Start(original_len))
        .with_context(|| format!("seek agent command spool tail {}", path.display()))?;
    file.read_to_end(&mut tail)
        .with_context(|| format!("read agent command spool tail {}", path.display()))?;
    file.set_len(0)
        .with_context(|| format!("truncate agent command spool {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind agent command spool {}", path.display()))?;
    file.write_all(&tail)
        .with_context(|| format!("write agent command spool tail {}", path.display()))?;
    Ok(())
}

fn agent_command_forward_url(target: &str) -> Result<String> {
    let trimmed = target.trim_end_matches('/');
    if trimmed.ends_with("/v1/agent-commands") {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(format!("{trimmed}/v1/agent-commands"));
    }
    bail!("agent command forward target must start with http:// or https://");
}

pub fn run_agent_command_wrapper(spool_path: &Path, command_args: &[String]) -> Result<i32> {
    anyhow::ensure!(
        !command_args.is_empty(),
        "agent-command wrap requires COMMAND after --"
    );
    ensure_private_parent(spool_path)?;

    let command = command_args_to_shell_command(command_args);
    if should_run_agent_command_unwrapped(command_args) {
        return run_command_unwrapped(command_args, &command);
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    let started = Utc::now();
    let timer = Instant::now();
    let status = command_status(command_args, &command).context("run wrapped command")?;
    let finished = Utc::now();
    let duration_ms = timer.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let record = AgentCommandSpoolRecord {
        started_at: rfc3339(started),
        finished_at: rfc3339(finished),
        duration_ms,
        exit_status: status.code(),
        command: scrub_command(&command),
        cwd,
        agent: crate::env::var("CORTEX_AGENT_COMMAND_AGENT")
            .unwrap_or_else(|_| "claude-code".to_string()),
        command_surface: crate::env::var("CORTEX_AGENT_COMMAND_SURFACE").ok(),
        hostname: hostname(),
        user: username(),
        pid: std::process::id(),
        session_id: crate::env::var("CLAUDE_CODE_SESSION_ID")
            .ok()
            .or_else(|| crate::env::var("CLAUDE_SESSION_ID").ok())
            .or_else(|| crate::env::var("CORTEX_AGENT_COMMAND_SESSION").ok()),
        schema_version: 1,
        content_scrubbed: true,
    };
    if let Err(error) = append_spool_record(spool_path, &record) {
        eprintln!(
            "cortex agent-command: failed to append to {}: {error:#}",
            spool_path.display()
        );
    }
    Ok(status.code().unwrap_or(1))
}

pub fn scrub_command(command: &str) -> String {
    let mut out = scrub_ai_message(command, None);
    for pattern in COMMAND_SECRET_PATTERNS.iter() {
        out = pattern.replace_all(&out, "[REDACTED]").into_owned();
    }
    out
}

fn run_command_unwrapped(command_args: &[String], fallback_shell_command: &str) -> Result<i32> {
    Ok(command_status(command_args, fallback_shell_command)?
        .code()
        .unwrap_or(1))
}

fn command_args_to_shell_command(command_args: &[String]) -> String {
    if command_args.len() == 1 {
        command_args[0].clone()
    } else {
        command_args
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn should_run_agent_command_unwrapped(command_args: &[String]) -> bool {
    crate::env::var("CORTEX_AGENT_COMMAND_WRAPPER")
        .ok()
        .as_deref()
        == Some("1")
        || is_agent_command_ingest_spool_invocation(command_args)
}

/// True when `argv0`'s basename is `cortex`. Shared by the self-ingest guard
/// below and `setup/doctor.rs`'s stale-unit `ExecStart=` scan, so both agree
/// on what counts as "this is a cortex invocation" from one place.
pub(crate) fn cortex_argv_program_matches(argv0: &str) -> bool {
    Path::new(argv0)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(argv0)
        == "cortex"
}

/// True for the canonical grammar: `ingest shell agent index`.
pub(crate) fn is_current_shell_agent_index_argv(rest: &[&str]) -> bool {
    matches!(rest, ["ingest", "shell", "agent", "index", ..])
}

/// True for the grouped pre-restructure grammar: `ingest agent-command
/// ingest-spool` — the one immediately-prior grammar already deployed on
/// live hosts (e.g. devhost).
pub(crate) fn is_grouped_legacy_agent_command_argv(rest: &[&str]) -> bool {
    matches!(rest, ["ingest", "agent-command", "ingest-spool", ..])
}

/// True for the even-older bare grammar: `agent-command ingest-spool` (no
/// `ingest` prefix). This form is unreachable through the CLI's own
/// top-level parser (see `src/surfaces.rs`), so callers that only care about
/// what the live CLI can produce (the self-ingest guard below) deliberately
/// don't tolerate it. `setup/doctor.rs`'s stale-unit scan does tolerate it,
/// since it's scanning static, possibly very old `ExecStart=` text rather
/// than argv the current CLI could have produced.
pub(crate) fn is_bare_legacy_agent_command_argv(rest: &[&str]) -> bool {
    matches!(rest, ["agent-command", "ingest-spool", ..])
}

fn is_agent_command_ingest_spool_invocation(command_args: &[String]) -> bool {
    let Some(program) = command_args.first() else {
        return false;
    };
    if !cortex_argv_program_matches(program) {
        return false;
    }
    let rest: Vec<&str> = command_args[1..].iter().map(String::as_str).collect();
    is_current_shell_agent_index_argv(&rest) || is_grouped_legacy_agent_command_argv(&rest)
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b'=' | b',' | b'+')
    }) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn command_status(command_args: &[String], fallback_shell_command: &str) -> Result<ExitStatus> {
    if command_args.len() == 1 {
        return shell_command_status(fallback_shell_command);
    }
    let (program, args) = command_args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("internal error: command_status called with empty args"))?;
    crate::env::command(program)
        .args(args)
        .env("CORTEX_AGENT_COMMAND_WRAPPER", "1")
        .env_remove("CLAUDE_CODE_SHELL_PREFIX")
        .status()
        .with_context(|| format!("run command {}", shell_quote(program)))
}

fn shell_command_status(command: &str) -> Result<ExitStatus> {
    let shell = crate::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    crate::env::command(shell)
        // The wrapper must not load a login profile. Apart from making a
        // non-interactive command depend on unrelated user configuration,
        // login profiles on persistent CI runners can contain stale absolute
        // paths left by earlier jobs.
        .arg("-c")
        .arg(command)
        .env("CORTEX_AGENT_COMMAND_WRAPPER", "1")
        .env_remove("CLAUDE_CODE_SHELL_PREFIX")
        .status()
        .context("run command")
}

pub fn parse_zsh_extended_history_line(line: &str) -> Option<ZshHistoryRecord> {
    let rest = line.strip_prefix(": ")?;
    let (epoch, rest) = rest.split_once(':')?;
    let (duration, command) = rest.split_once(';')?;
    let epoch = epoch.trim().parse::<i64>().ok()?;
    let duration_secs = duration.trim().parse::<u64>().ok()?;
    let started_at = Utc.timestamp_opt(epoch, 0).single()?;
    Some(ZshHistoryRecord {
        started_at,
        duration_secs,
        command: command.to_string(),
    })
}

fn zsh_record_to_entry(
    record: &ZshHistoryRecord,
    path: &Path,
    line_no: usize,
    shell: &str,
    hostname: &str,
    user: Option<&str>,
) -> LogBatchEntry {
    let command = scrub_command(&record.command);
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "shell_history",
        "source_kind": SourceKind::ShellHistory.as_str(),
        "shell": {
            "name": shell,
            "user": user,
            "history_path": path.display().to_string(),
            "line_no": line_no,
            "duration_secs": record.duration_secs,
            "timestamp_quality": "zsh_extended_history"
        },
        "content_scrubbed": true,
    }));
    let mut entry = LogBatchEntry {
        timestamp: rfc3339(record.started_at),
        hostname: hostname.to_string(),
        facility: Some("shell".to_string()),
        severity: "info".to_string(),
        app_name: Some(shell.to_string()),
        process_id: None,
        message: command.clone(),
        raw: command,
        source_ip: format!(
            "shell-history://{}/{}/{}",
            sanitize_uri_segment(hostname),
            sanitize_uri_segment(user.unwrap_or("unknown")),
            sanitize_uri_segment(shell)
        ),
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::ShellHistory);
    entry
}

fn atuin_record_to_entry(
    record: &AtuinHistoryRecord,
    path: &Path,
    user: Option<&str>,
) -> Option<LogBatchEntry> {
    let secs = record.timestamp_ns.div_euclid(1_000_000_000);
    let nanos = record.timestamp_ns.rem_euclid(1_000_000_000) as u32;
    let started_at = DateTime::<Utc>::from_timestamp(secs, nanos)?;
    let command = scrub_command(&record.command);
    let exit_status = if record.exit_status >= 0 {
        Some(record.exit_status)
    } else {
        None
    };
    let severity = match exit_status {
        Some(0) => "info",
        Some(_) => "warning",
        None => "err",
    };
    let duration_ms = if record.duration_ns >= 0 {
        Some(record.duration_ns / 1_000_000)
    } else {
        None
    };
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "shell_history",
        "source_kind": SourceKind::ShellHistory.as_str(),
        "shell": {
            "name": "atuin",
            "user": user,
            "history_path": path.display().to_string(),
            "id": record.id,
            "cwd": record.cwd,
            "session": record.session,
            "exit_status": exit_status,
            "duration_ms": duration_ms,
            "author": record.author,
            "intent": record.intent,
            "timestamp_quality": "atuin_sqlite"
        },
        "content_scrubbed": true,
    }));
    let mut entry = LogBatchEntry {
        timestamp: rfc3339(started_at),
        hostname: record.hostname.clone(),
        facility: Some("shell".to_string()),
        severity: severity.to_string(),
        app_name: Some("atuin".to_string()),
        process_id: None,
        message: command.clone(),
        raw: command,
        source_ip: format!(
            "shell-history://{}/{}/atuin",
            sanitize_uri_segment(&record.hostname),
            sanitize_uri_segment(user.unwrap_or("unknown"))
        ),
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: Some(record.cwd.clone()),
        ai_session_id: Some(record.session.clone()),
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: Some("command".to_string()),
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::ShellHistory);
    Some(entry)
}

fn agent_record_to_entry(record: &AgentCommandSpoolRecord) -> LogBatchEntry {
    let command = scrub_command(&record.command);
    let exit_status = record.exit_status;
    let severity = match exit_status {
        Some(0) => "info",
        Some(_) => "warning",
        None => "err",
    };
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "agent_command",
        "source_kind": SourceKind::AgentCommand.as_str(),
        "agent_command": {
            "schema_version": record.schema_version,
            "agent": record.agent,
            "command_surface": record.command_surface,
            "cwd": record.cwd,
            "user": record.user,
            "pid": record.pid,
            "exit_status": exit_status,
            "duration_ms": record.duration_ms,
            "finished_at": record.finished_at,
            "session_id": record.session_id
        },
        "content_scrubbed": true,
    }));
    let mut entry = LogBatchEntry {
        timestamp: normalize_or_now(&record.started_at),
        hostname: record.hostname.clone(),
        facility: Some("agent".to_string()),
        severity: severity.to_string(),
        app_name: Some(record.agent.clone()),
        process_id: Some(record.pid.to_string()),
        message: command.clone(),
        raw: command,
        source_ip: format!(
            "agent-command://{}/{}/{}",
            sanitize_uri_segment(&record.hostname),
            sanitize_uri_segment(&record.agent),
            sanitize_uri_segment(record.session_id.as_deref().unwrap_or("unknown"))
        ),
        docker_checkpoint: None,
        ai_tool: Some(record.agent.clone()),
        ai_project: record.cwd.clone(),
        ai_session_id: record.session_id.clone(),
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: Some("command".to_string()),
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::AgentCommand);
    entry
}

fn append_spool_record(path: &Path, record: &AgentCommandSpoolRecord) -> Result<()> {
    validate_spool_path_for_write(path)?;
    let mut file = open_spool_for_append(path)?;
    lock_file_exclusive(&file, path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn open_spool_for_update(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("open agent command spool {}", path.display()))
}

fn open_spool_for_append(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open agent command spool {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod agent command spool {}", path.display()))?;
    }
    Ok(file)
}

fn lock_file_exclusive(file: &fs::File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        anyhow::ensure!(
            rc == 0,
            "lock file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
    }
    Ok(())
}

fn shell_history_state_path(path: &Path, shell: &str) -> Result<PathBuf> {
    let state_dir = command_log_state_dir(path)?;
    let identity = format!("{}\0{}", shell, path.display());
    Ok(state_dir.join(format!(
        "shell-history-{:016x}.json",
        stable_hash(&identity)
    )))
}

fn atuin_history_state_path(path: &Path) -> Result<PathBuf> {
    let state_dir = command_log_state_dir(path)?;
    let identity = format!("atuin\0{}", path.display());
    Ok(state_dir.join(format!(
        "atuin-history-{:016x}.json",
        stable_hash(&identity)
    )))
}

fn command_log_state_dir(path: &Path) -> Result<PathBuf> {
    if let Some(value) = crate::env::var_os("CORTEX_COMMAND_LOG_STATE_DIR") {
        let state_dir = PathBuf::from(value);
        ensure_private_parent(&state_dir.join(".keep"))?;
        return Ok(state_dir);
    }
    if let Some(value) = crate::env::var_os("XDG_STATE_HOME") {
        let state_dir = PathBuf::from(value).join("cortex");
        ensure_private_parent(&state_dir.join(".keep"))?;
        return Ok(state_dir);
    }
    if let Some(value) = crate::env::var_os("HOME") {
        let state_dir = PathBuf::from(value).join(".local/state/cortex");
        ensure_private_parent(&state_dir.join(".keep"))?;
        return Ok(state_dir);
    }
    let fallback = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cortex-state");
    ensure_private_parent(&fallback.join(".keep"))?;
    Ok(fallback)
}

fn read_shell_history_state(
    state_path: &Path,
    history_path: &Path,
    shell: &str,
) -> Result<Option<ShellHistoryImportState>> {
    let raw = match fs::read_to_string(state_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read shell history state {}", state_path.display()));
        }
    };
    let state: ShellHistoryImportState = serde_json::from_str(&raw)
        .with_context(|| format!("parse shell history state {}", state_path.display()))?;
    if state.path == history_path.display().to_string() && state.shell == shell {
        Ok(Some(state))
    } else {
        Ok(None)
    }
}

fn write_shell_history_state(
    state_path: &Path,
    history_path: &Path,
    shell: &str,
    offset: u64,
    line_no: usize,
) -> Result<()> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create shell history state dir {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod shell history state dir {}", parent.display()))?;
        }
    }
    let state = ShellHistoryImportState {
        path: history_path.display().to_string(),
        shell: shell.to_string(),
        offset,
        line_no,
    };
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(state_path)
        .with_context(|| format!("open shell history state {}", state_path.display()))?;
    serde_json::to_writer(&mut file, &state)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn read_atuin_history_state(
    state_path: &Path,
    history_path: &Path,
) -> Result<Option<AtuinHistoryImportState>> {
    let raw = match fs::read_to_string(state_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read atuin history state {}", state_path.display()));
        }
    };
    let state: AtuinHistoryImportState = serde_json::from_str(&raw)
        .with_context(|| format!("parse atuin history state {}", state_path.display()))?;
    if state.path == history_path.display().to_string() {
        Ok(Some(state))
    } else {
        Ok(None)
    }
}

fn write_atuin_history_state(
    state_path: &Path,
    history_path: &Path,
    last_timestamp_ns: i64,
    last_id: &str,
) -> Result<()> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create atuin history state dir {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod atuin history state dir {}", parent.display()))?;
        }
    }
    let state = AtuinHistoryImportState {
        path: history_path.display().to_string(),
        last_timestamp_ns,
        last_id: last_id.to_string(),
    };
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(state_path)
        .with_context(|| format!("open atuin history state {}", state_path.display()))?;
    serde_json::to_writer(&mut file, &state)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn entry_exists(pool: &db::DbPool, entry: &LogBatchEntry) -> Result<bool> {
    let conn = pool.get()?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM logs WHERE source_ip = ?1 AND timestamp = ?2 AND message = ?3",
        (&entry.source_ip, &entry.timestamp, &entry.message),
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn ensure_private_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let parent_existed = parent.exists();
    fs::create_dir_all(&parent)
        .with_context(|| format!("create spool parent {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !parent_existed {
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod spool parent {}", parent.display()))?;
        }
    }
    Ok(())
}

fn validate_spool_path_for_write(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    if let Some(parent) = path.parent() {
        reject_unsafe_parent(parent)?;
    }
    Ok(())
}

fn validate_spool_path_for_read(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    if let Some(parent) = path.parent() {
        reject_unsafe_parent(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("stat spool {}", path.display()))?
            .mode()
            & 0o777;
        anyhow::ensure!(
            mode & 0o077 == 0,
            "agent command spool must not be readable or writable by group/other: {}",
            path.display()
        );
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "agent command spool must not be a symlink: {}",
            path.display()
        );
    }
    Ok(())
}

fn reject_unsafe_parent(parent: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if parent.exists() {
            let mode = fs::metadata(parent)
                .with_context(|| format!("stat spool parent {}", parent.display()))?
                .mode()
                & 0o777;
            anyhow::ensure!(
                mode & 0o022 == 0,
                "agent command spool parent must not be group/world writable: {}",
                parent.display()
            );
        }
    }
    Ok(())
}

fn schema_version_one() -> u32 {
    1
}

fn normalize_or_now(value: &str) -> String {
    match DateTime::parse_from_rfc3339(value) {
        Ok(dt) => rfc3339(dt.with_timezone(&Utc)),
        Err(e) => {
            tracing::warn!(
                raw_timestamp = value,
                error = %e,
                "agent command spool record has unparseable started_at; substituting import time"
            );
            rfc3339(Utc::now())
        }
    }
}

fn rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn hostname() -> String {
    crate::hostname::local_hostname()
}

fn username() -> Option<String> {
    crate::env::var("USER")
        .ok()
        .or_else(|| crate::env::var("LOGNAME").ok())
        .filter(|value| !value.trim().is_empty())
}

fn sanitize_uri_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
#[path = "command_log_tests.rs"]
mod tests;
