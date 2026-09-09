use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::time::sleep;

use super::syslog_sender::{PRI_LOCAL0_INFO, SyslogSender, format_rfc5424};

const EOF_SLEEP_MS: u64 = 500;

/// One file the agent tails and forwards to the cortex syslog receiver.
///
/// When `tag` is `Some`, lines are forwarded **raw** under that fixed
/// `app_name` (the message is the verbatim line) — this is how arbitrary app
/// log files (AdGuard's JSON `querylog.json`, SWAG `access.log`, fail2ban,
/// Plex) reach the right cortex parser without any host-side rsyslog drop-in.
/// When `tag` is `None`, each line is parsed as an RFC 3164 syslog record
/// (back-compat with `CORTEX_AGENT_SYSLOG_FILE` tailing `/var/log/syslog`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTailSource {
    pub path: PathBuf,
    pub tag: Option<String>,
}

/// Parse `CORTEX_AGENT_FILE_TAILS` — a comma-separated list of `PATH:TAG`
/// entries (e.g. `/data/querylog.json:adguard-query,/log/access.log:swag-access`).
/// The tag is the segment after the final colon, so absolute Linux paths (no
/// colon) round-trip cleanly. Entries without a usable `:TAG` suffix are
/// skipped with a `warn` — a silent drop would leave an operator's typo'd
/// source tailing nothing with no diagnostic.
pub fn parse_file_tails(spec: &str) -> Vec<FileTailSource> {
    let mut sources = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let parsed = entry.rsplit_once(':').and_then(|(path, tag)| {
            let (path, tag) = (path.trim(), tag.trim());
            (!path.is_empty() && !tag.is_empty()).then(|| FileTailSource {
                path: PathBuf::from(path),
                tag: Some(tag.to_string()),
            })
        });
        match parsed {
            Some(source) => sources.push(source),
            None => tracing::warn!(
                entry = %entry,
                "CORTEX_AGENT_FILE_TAILS: skipping malformed entry (expected non-empty PATH:TAG)"
            ),
        }
    }
    sources
}

struct ParsedSyslogLine<'a> {
    hostname: &'a str,
    app_name: &'a str,
    procid: &'a str,
    message: &'a str,
}

/// Tail a file from EOF and forward new lines to the cortex syslog receiver.
///
/// With `forced_app_name = Some(tag)` the line is forwarded verbatim as the
/// message under that `app_name` (raw mode, for arbitrary app log files). With
/// `None` the line is parsed as an RFC 3164 syslog record.
///
/// "Follow only": starting at EOF avoids replaying a large rotated backlog when
/// a heartbeat-agent container is redeployed.
pub async fn run_file_forwarder(
    path: &Path,
    fallback_hostname: &str,
    forced_app_name: Option<&str>,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    let mut reader = open_at_end(path).await?;
    let mut position = reader.stream_position().await?;
    tracing::info!(
        path = %path.display(),
        tag = forced_app_name.unwrap_or("<syslog>"),
        "file forwarder following"
    );

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            if file_was_truncated(path, position).await {
                tracing::info!(path = %path.display(), "file truncated; reopening");
                reader = open_at_end(path).await?;
                position = reader.stream_position().await?;
            }
            sleep(Duration::from_millis(EOF_SLEEP_MS)).await;
            continue;
        }

        position = position.saturating_add(read as u64);
        let raw = line.trim_end_matches(['\r', '\n']);
        if raw.is_empty() {
            continue;
        }

        let parsed = match forced_app_name {
            // Raw mode: verbatim line under the configured tag.
            Some(tag) => ParsedSyslogLine {
                hostname: fallback_hostname,
                app_name: tag,
                procid: "-",
                message: raw,
            },
            None => parse_syslog_line(raw, fallback_hostname),
        };
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let forwarded = format_rfc5424(
            PRI_LOCAL0_INFO,
            &timestamp,
            parsed.hostname,
            parsed.app_name,
            parsed.procid,
            parsed.message,
        );
        sender
            .send_from(&format!("file:{}", path.display()), forwarded)
            .await?;
    }
}

/// Tail a host syslog file (RFC 3164 lines). Back-compat wrapper over
/// [`run_file_forwarder`] with no forced tag.
pub async fn run_syslog_file_forwarder(
    path: &Path,
    fallback_hostname: &str,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    run_file_forwarder(path, fallback_hostname, None, sender).await
}

async fn open_at_end(path: &Path) -> Result<BufReader<File>> {
    let mut file = File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::End(0)).await?;
    Ok(BufReader::new(file))
}

async fn file_was_truncated(path: &Path, position: u64) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|metadata| metadata.len() < position)
        .unwrap_or(false)
}

fn parse_syslog_line<'a>(line: &'a str, fallback_hostname: &'a str) -> ParsedSyslogLine<'a> {
    let Some(after_timestamp) = strip_rfc3164_timestamp(line) else {
        return ParsedSyslogLine {
            hostname: fallback_hostname,
            app_name: "syslog-file",
            procid: "-",
            message: line,
        };
    };
    let Some((hostname, rest)) = after_timestamp.split_once(' ') else {
        return ParsedSyslogLine {
            hostname: fallback_hostname,
            app_name: "syslog-file",
            procid: "-",
            message: line,
        };
    };
    let Some((tag, message)) = rest.split_once(':') else {
        return ParsedSyslogLine {
            hostname,
            app_name: "syslog-file",
            procid: "-",
            message: rest,
        };
    };

    let (app_name, procid) = parse_tag(tag);
    ParsedSyslogLine {
        hostname,
        app_name,
        procid,
        message: message.trim_start(),
    }
}

fn strip_rfc3164_timestamp(line: &str) -> Option<&str> {
    if line.len() < 16 {
        return None;
    }
    let bytes = line.as_bytes();
    if bytes.get(3) != Some(&b' ')
        || bytes.get(6) != Some(&b' ')
        || bytes.get(9) != Some(&b':')
        || bytes.get(12) != Some(&b':')
        || bytes.get(15) != Some(&b' ')
    {
        return None;
    }
    line.get(16..)
}

fn parse_tag(tag: &str) -> (&str, &str) {
    if let Some(open) = tag.rfind('[')
        && tag.ends_with(']')
        && open > 0
    {
        return (&tag[..open], &tag[open + 1..tag.len() - 1]);
    }
    (tag, "-")
}

#[cfg(test)]
#[path = "syslog_file_tests.rs"]
mod tests;
