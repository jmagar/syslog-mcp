//! Forwards local shell command history (zsh/bash extended history, and
//! atuin) to the central cortex server via `POST /v1/shell-history` — one
//! more supervised stream inside `cortex agent`.
//!
//! Local `cortex ingest shell user index`/`atuinindex` have zero
//! forward capability (they only ever write to whatever local SQLite file
//! the process itself has open) — this is a real gap for the same reason
//! AI-transcript and agent-command forwarding were: a host's shell activity
//! is only useful centrally if it actually reaches wherever the shared
//! server lives.
//!
//! zsh/bash history is a plain append-only text file, tailed by line offset
//! (mirrors `agent::ai_transcript`'s Claude/Codex path). Atuin history is a
//! real SQLite database (`~/.local/share/atuin/history.db`), so it's polled
//! with a `(timestamp, id)` cursor query instead of a byte offset, mirroring
//! the local `import_atuin_history_with_state` approach but read-only and
//! without any local DB write.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::command_log::{parse_zsh_extended_history_line, scrub_command};
use crate::shell_history_ingest::{ShellHistoryIngestRequest, ShellHistoryRecord};

/// Cap on the aggregate batch per scan cycle, across zsh and atuin combined —
/// stays comfortably under the server's `MAX_RECORDS_PER_BATCH` (2,000) and
/// any fronting proxy's request-size limit.
const MAX_BATCH_RECORDS: usize = 500;

#[derive(Debug, Clone)]
pub struct ShellHistoryForwardConfig {
    /// `~/.zsh_history` (extended history format), if present.
    pub zsh_history_path: Option<PathBuf>,
    /// `~/.local/share/atuin/history.db`, if present.
    pub atuin_db_path: Option<PathBuf>,
    pub target: String,
    pub token: Option<String>,
    pub hostname: String,
    pub checkpoint_path: PathBuf,
    pub poll_interval: Duration,
}

impl ShellHistoryForwardConfig {
    pub fn new(target: String, token: Option<String>, checkpoint_path: PathBuf) -> Self {
        let home = crate::env::var_os("HOME").map(PathBuf::from);
        let zsh_history_path = home.as_ref().map(|h| h.join(".zsh_history"));
        let atuin_db_path = home
            .as_ref()
            .map(|h| h.join(".local/share/atuin/history.db"));
        Self {
            zsh_history_path: zsh_history_path.filter(|p| p.exists()),
            atuin_db_path: atuin_db_path.filter(|p| p.exists()),
            target,
            token,
            hostname: crate::scanner::local_hostname(),
            checkpoint_path,
            poll_interval: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Checkpoint {
    /// Lines already forwarded from `zsh_history_path`.
    zsh_line: usize,
    /// Atuin cursor: `(timestamp_ns, id)` of the last forwarded row.
    atuin_timestamp_ns: i64,
    #[serde(default)]
    atuin_id: String,
}

fn load_checkpoint(path: &std::path::Path) -> Checkpoint {
    match std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => std::fs::read(path.with_extension("json.bak"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default(),
    }
}

fn save_checkpoint(path: &std::path::Path, checkpoint: &Checkpoint) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create checkpoint dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec(checkpoint)?;
    crate::setup::heartbeat_agent_env::atomic_checkpoint_write(path, &bytes)
        .with_context(|| format!("failed to write checkpoint file {}", path.display()))
}

/// Read up to `limit` new zsh extended-history lines starting at `from_line`
/// (0-indexed), plus the checkpoint value to resume from next time. Mirrors
/// `agent::ai_transcript::read_new_lines`'s contract: the returned line
/// count reflects how far the (possibly limit-truncated) read actually got,
/// never the file's true EOF when the limit cuts it short.
///
/// Reads raw bytes and lossily converts to UTF-8 per line instead of
/// `BufRead::lines()` (which hard-errors the whole read on the first
/// invalid-UTF-8 byte). Real `.zsh_history` files can and do contain
/// stray non-UTF-8 bytes (pasted binary output, odd terminal escapes) —
/// one bad line must not block every line after it from ever forwarding.
fn read_new_zsh_lines(
    path: &std::path::Path,
    from_line: usize,
    limit: usize,
) -> Result<(Vec<String>, usize)> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    let mut line_no = 0usize;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buf)
            .with_context(|| format!("read line from {}", path.display()))?;
        if bytes_read == 0 {
            break; // EOF
        }
        if line_no < from_line {
            line_no += 1;
            continue;
        }
        if out.len() >= limit {
            break;
        }
        let line = String::from_utf8_lossy(&buf)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        out.push(line);
        line_no += 1;
    }
    Ok((out, line_no))
}

fn scan_zsh(
    path: &std::path::Path,
    hostname: &str,
    from_line: usize,
    limit: usize,
) -> Result<(Vec<ShellHistoryRecord>, usize)> {
    let (lines, new_line) = read_new_zsh_lines(path, from_line, limit)?;
    let mut records = Vec::new();
    for line in &lines {
        let Some(parsed) = parse_zsh_extended_history_line(line) else {
            continue;
        };
        records.push(ShellHistoryRecord {
            source: "zsh".to_string(),
            hostname: hostname.to_string(),
            timestamp: parsed
                .started_at
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            duration_ms: Some(parsed.duration_secs * 1000),
            command: scrub_command(&parsed.command),
            cwd: None,
            exit_status: None,
            session_id: None,
        });
    }
    Ok((records, new_line))
}

fn scan_atuin(
    path: &std::path::Path,
    hostname: &str,
    from_timestamp_ns: i64,
    from_id: &str,
    limit: usize,
) -> Result<(Vec<ShellHistoryRecord>, i64, String)> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("open atuin history {}", path.display()))?;
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, duration, exit, command, cwd, session
             FROM history
             WHERE deleted_at IS NULL
               AND (timestamp > ?1 OR (timestamp = ?1 AND id > ?2))
             ORDER BY timestamp ASC, id ASC
             LIMIT ?3",
        )
        .context("prepare atuin history query")?;
    let mut last_timestamp_ns = from_timestamp_ns;
    let mut last_id = from_id.to_string();
    let mut records = Vec::new();
    let rows = stmt
        .query_map(
            rusqlite::params![from_timestamp_ns, from_id, limit as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .context("read atuin history")?;
    for row in rows {
        let (id, timestamp_ns, duration_ns, exit_status, command, cwd, session) =
            row.context("decode atuin history row")?;
        last_timestamp_ns = timestamp_ns;
        last_id = id;
        let secs = timestamp_ns.div_euclid(1_000_000_000);
        let nanos = timestamp_ns.rem_euclid(1_000_000_000) as u32;
        let Some(started_at) = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos) else {
            continue;
        };
        records.push(ShellHistoryRecord {
            source: "atuin".to_string(),
            hostname: hostname.to_string(),
            timestamp: started_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            duration_ms: if duration_ns >= 0 {
                Some((duration_ns / 1_000_000) as u64)
            } else {
                None
            },
            command: scrub_command(&command),
            cwd: Some(cwd).filter(|s| !s.is_empty()),
            exit_status: if exit_status >= 0 {
                Some(exit_status as i32)
            } else {
                None
            },
            session_id: Some(session).filter(|s| !s.is_empty()),
        });
    }
    Ok((records, last_timestamp_ns, last_id))
}

async fn scan_and_forward(
    config: &ShellHistoryForwardConfig,
    client: &reqwest::Client,
    checkpoint: &mut Checkpoint,
) -> Result<usize> {
    let mut records = Vec::new();
    let mut new_zsh_line = None;
    let mut new_atuin_cursor = None;

    if let Some(path) = &config.zsh_history_path {
        match scan_zsh(
            path,
            &config.hostname,
            checkpoint.zsh_line,
            MAX_BATCH_RECORDS,
        ) {
            Ok((mut zsh_records, new_line)) => {
                if new_line != checkpoint.zsh_line {
                    new_zsh_line = Some(new_line);
                }
                records.append(&mut zsh_records);
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), error = format!("{error:#}"), "shell history forwarder failed to read zsh history");
            }
        }
    }

    if records.len() < MAX_BATCH_RECORDS
        && let Some(path) = &config.atuin_db_path
    {
        let remaining = MAX_BATCH_RECORDS - records.len();
        match scan_atuin(
            path,
            &config.hostname,
            checkpoint.atuin_timestamp_ns,
            &checkpoint.atuin_id,
            remaining,
        ) {
            Ok((mut atuin_records, last_ts, last_id)) => {
                if last_ts != checkpoint.atuin_timestamp_ns || last_id != checkpoint.atuin_id {
                    new_atuin_cursor = Some((last_ts, last_id));
                }
                records.append(&mut atuin_records);
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), error = format!("{error:#}"), "shell history forwarder failed to read atuin history");
            }
        }
    }

    if records.is_empty() {
        return Ok(0);
    }

    let sent = records.len();
    let mut url = config.target.trim_end_matches('/').to_string();
    url.push_str("/v1/shell-history");
    let mut request = client
        .post(&url)
        .json(&ShellHistoryIngestRequest { records });
    if let Some(token) = &config.token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("shell history POST failed")?;
    if !response.status().is_success() {
        anyhow::bail!(
            "shell history forward rejected: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    // Only advance checkpoints after a successful forward, so a failed
    // request retries the same records next cycle instead of losing them.
    if let Some(new_line) = new_zsh_line {
        checkpoint.zsh_line = new_line;
    }
    if let Some((ts, id)) = new_atuin_cursor {
        checkpoint.atuin_timestamp_ns = ts;
        checkpoint.atuin_id = id;
    }
    save_checkpoint(&config.checkpoint_path, checkpoint)?;
    Ok(sent)
}

/// Run the shell-history forward loop forever, polling every
/// `config.poll_interval`. Errors from a single scan are logged and do not
/// stop the loop.
pub async fn run(config: ShellHistoryForwardConfig) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build shell history forwarder http client")?;
    let mut checkpoint = load_checkpoint(&config.checkpoint_path);
    loop {
        match scan_and_forward(&config, &client, &mut checkpoint).await {
            Ok(0) => {}
            Ok(sent) => tracing::info!(sent, "shell history forwarder: batch sent"),
            Err(error) => tracing::warn!(
                error = format!("{error:#}"),
                "shell history forward scan failed"
            ),
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

#[cfg(test)]
#[path = "shell_history_tests.rs"]
mod tests;
