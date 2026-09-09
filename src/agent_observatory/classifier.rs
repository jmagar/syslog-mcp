//! Classification of canonical log rows into Agent Observatory projections.

#[path = "classifier_commands.rs"]
mod commands;
pub use commands::{
    CommandLogClassification, CommandLogProjection, CommandLogSource, CommandSkipDiagnostic,
    CommandSkipReason, classify_command_log,
};

use crate::ai_project::normalize_ai_project_path;
use crate::assessment::redact_json_value_strings;
use crate::db::LogEntry;
use crate::receiver::enrichment::scrub_ai_message;
use serde_json::Value;

pub const MAX_TRANSCRIPT_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_TRANSCRIPT_METADATA_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptSkipReason {
    InvalidLogId,
    MissingHostname,
    MissingAiTool,
    UnsupportedTool,
    MissingSessionId,
    MissingTranscriptPath,
    InvalidTimestamp,
    InvalidReceivedAt,
    MetadataTooLarge,
    InvalidMetadataJson,
    MetadataNotObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptSkipDiagnostic {
    pub log_id: i64,
    pub reason: TranscriptSkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptLogProjection {
    pub log_id: i64,
    pub timestamp: String,
    pub received_at: String,
    pub hostname: String,
    pub tool: String,
    pub provider_tool: String,
    pub project: Option<String>,
    pub session_id: String,
    pub transcript_path: String,
    pub process_id: Option<String>,
    pub severity: String,
    pub app_name: Option<String>,
    pub source_ip: String,
    pub message: String,
    pub message_truncated: bool,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptLogClassification {
    Project(Box<TranscriptLogProjection>),
    Skip(TranscriptSkipDiagnostic),
}

fn skip(log_id: i64, reason: TranscriptSkipReason) -> TranscriptLogClassification {
    TranscriptLogClassification::Skip(TranscriptSkipDiagnostic { log_id, reason })
}

fn required(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn canonical_known_tool(value: &str) -> Option<String> {
    crate::scanner::providers::canonical_transcript_provider(value).map(str::to_string)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

pub fn classify_transcript_log(row: &LogEntry) -> TranscriptLogClassification {
    if row.id <= 0 {
        return skip(row.id, TranscriptSkipReason::InvalidLogId);
    }
    let hostname = row.hostname.trim();
    if hostname.is_empty() {
        return skip(row.id, TranscriptSkipReason::MissingHostname);
    }
    let Some(provider_tool) = required(row.ai_tool.as_deref()) else {
        return skip(row.id, TranscriptSkipReason::MissingAiTool);
    };
    let Some(tool) = canonical_known_tool(provider_tool) else {
        return skip(row.id, TranscriptSkipReason::UnsupportedTool);
    };
    let Some(session_id) = required(row.ai_session_id.as_deref()) else {
        return skip(row.id, TranscriptSkipReason::MissingSessionId);
    };
    let Some(transcript_path) = required(row.ai_transcript_path.as_deref()) else {
        return skip(row.id, TranscriptSkipReason::MissingTranscriptPath);
    };
    if chrono::DateTime::parse_from_rfc3339(&row.timestamp).is_err() {
        return skip(row.id, TranscriptSkipReason::InvalidTimestamp);
    }
    if chrono::DateTime::parse_from_rfc3339(&row.received_at).is_err() {
        return skip(row.id, TranscriptSkipReason::InvalidReceivedAt);
    }

    let metadata_json = match row.metadata_json.as_deref() {
        None | Some("") => "{}".to_string(),
        Some(value) if value.len() > MAX_TRANSCRIPT_METADATA_BYTES => {
            return skip(row.id, TranscriptSkipReason::MetadataTooLarge);
        }
        Some(value) => match serde_json::from_str::<Value>(value) {
            Ok(mut value @ Value::Object(_)) => {
                redact_json_value_strings(&mut value);
                value.to_string()
            }
            Ok(_) => return skip(row.id, TranscriptSkipReason::MetadataNotObject),
            Err(_) => return skip(row.id, TranscriptSkipReason::InvalidMetadataJson),
        },
    };
    let project = required(row.ai_project.as_deref())
        .map(normalize_ai_project_path)
        .map(|value| scrub_ai_message(&value, None))
        .filter(|project| !project.is_empty());
    let scrubbed_message = scrub_ai_message(&row.message, None);
    let (message, message_truncated) =
        truncate_utf8(&scrubbed_message, MAX_TRANSCRIPT_MESSAGE_BYTES);

    TranscriptLogClassification::Project(Box::new(TranscriptLogProjection {
        log_id: row.id,
        timestamp: row.timestamp.clone(),
        received_at: row.received_at.clone(),
        hostname: scrub_ai_message(hostname, None),
        tool,
        provider_tool: scrub_ai_message(provider_tool, None),
        project,
        session_id: scrub_ai_message(session_id, None),
        transcript_path: scrub_ai_message(transcript_path, None),
        process_id: row
            .process_id
            .as_deref()
            .map(|value| scrub_ai_message(value, None)),
        severity: scrub_ai_message(row.severity.trim(), None),
        app_name: row
            .app_name
            .as_deref()
            .map(|value| scrub_ai_message(value, None)),
        source_ip: scrub_ai_message(&row.source_ip, None),
        message,
        message_truncated,
        metadata_json,
    }))
}

#[cfg(test)]
#[path = "classifier_tests.rs"]
mod tests;
