use anyhow::Result;
use cortex::app::LogEntry;
use serde::Serialize;

use super::super::color::{cyan, muted, primary, severity, violet};

pub(crate) fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub(crate) fn local_ts(utc: &str) -> String {
    use chrono::{DateTime, Local};
    DateTime::parse_from_rfc3339(utc)
        .map(|dt| {
            dt.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|_| utc.to_string())
}

pub(crate) fn print_log(log: &LogEntry) {
    if is_transcript_log(log) {
        print_ai_log(log);
        return;
    }
    let app = log.app_name.as_deref().unwrap_or("-");
    println!(
        "{} {:<7} {:<20} {:<16} {}",
        muted(&local_ts(&log.timestamp)),
        severity(&log.severity),
        cyan(&log.hostname),
        primary(app),
        log.message
    );
}

fn print_ai_log(log: &LogEntry) {
    let tool = log
        .ai_tool
        .as_deref()
        .or_else(|| {
            log.app_name
                .as_deref()
                .and_then(|app| app.strip_suffix("-transcript"))
        })
        .unwrap_or("ai");
    let tool = terminal_safe_line(tool);
    let timestamp = terminal_safe_line(&local_ts(&log.timestamp));
    let severity_label = terminal_safe_line(&log.severity);
    let project = terminal_safe_line(log.ai_project.as_deref().unwrap_or("(unknown project)"));
    let session = terminal_safe_line(log.ai_session_id.as_deref().unwrap_or("(unknown session)"));
    println!(
        "{} {:<7} {:<8} {:<36} session={}",
        muted(&timestamp),
        severity(&severity_label),
        violet(&truncate(&tool, 8)),
        primary(&truncate(&project, 35)),
        muted(&truncate(&session, 24))
    );
    println!(
        "    {}",
        indent_multiline(&terminal_safe_multiline(&log.message))
    );
}

pub(crate) fn terminal_safe_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

pub(crate) fn terminal_safe_multiline(value: &str) -> String {
    value
        .chars()
        .filter_map(|ch| match ch {
            '\n' => Some('\n'),
            ch if ch.is_control() => None,
            ch => Some(ch),
        })
        .collect()
}

pub(crate) fn is_transcript_log(log: &LogEntry) -> bool {
    log.source_ip.starts_with("transcript://")
        || log
            .app_name
            .as_deref()
            .is_some_and(|app| app.ends_with("-transcript"))
}

pub(crate) fn indent_multiline(value: &str) -> String {
    value.replace('\n', "\n    ")
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.chars().count() > max {
        let prefix: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{prefix}…")
    } else {
        s.to_string()
    }
}

/// Truncate `s` to at most `max_bytes` UTF-8 bytes (cutting on a char boundary),
/// appending `…` when truncated. Use this for `--max-bytes`-style budgets where
/// the limit is bytes, not characters — [`truncate`] counts characters and can
/// blow a byte budget on multibyte input.
pub(crate) fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    const ELLIPSIS: &str = "…"; // 3 bytes

    // Budgets too small to fit the marker return a bare byte-bounded prefix.
    // Compute the cut from `max_bytes` directly (not the ellipsis-reserved
    // budget), so a 1–2 byte budget still yields its prefix, not an empty string.
    if max_bytes < ELLIPSIS.len() {
        let mut cut = max_bytes.min(s.len());
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        return s[..cut].to_string();
    }
    // Reserve room for the ellipsis so the result stays within `max_bytes`.
    let budget = max_bytes - ELLIPSIS.len();
    let mut cut = budget.min(s.len());
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{ELLIPSIS}", &s[..cut])
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
