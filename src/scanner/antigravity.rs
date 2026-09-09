//! Parser for Antigravity's redacted JSONL transcript projection.
//!
//! Antigravity keeps its authoritative conversation database separately, but
//! emits a stable transcript projection at
//! `brain/<conversation-id>/.system_generated/logs/transcript.jsonl`.  This
//! adapter deliberately recognizes only that narrow path and never scans the
//! other user-authored or generated brain artifacts.

use std::path::{Component, Path};

use anyhow::{Context, Result};
use serde_json::Value;

use super::{ParsedTranscriptRecord, TranscriptSessionMetadata, hash_text};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AntigravityToolCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct AntigravityRecord {
    pub transcript: ParsedTranscriptRecord,
    pub step_index: Option<u64>,
    pub source: Option<String>,
    pub record_type: Option<String>,
    pub status: Option<String>,
    pub tool_calls: Vec<AntigravityToolCall>,
}

#[derive(Debug, Default)]
pub(crate) struct AntigravityParse {
    pub records: Vec<AntigravityRecord>,
    pub skipped_empty: usize,
}

pub(crate) fn is_transcript_file(path: &Path) -> bool {
    path.file_name().and_then(|part| part.to_str()) == Some("transcript.jsonl")
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|part| part.to_str())
            == Some("logs")
        && path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|part| part.to_str())
            == Some(".system_generated")
        && session_id_from_path(path).is_some()
}

/// Derive the conversation ID only from the bounded `brain/<id>` path segment.
/// Reject traversal-looking, hidden, oversized, or punctuation-heavy values.
pub(crate) fn session_id_from_path(path: &Path) -> Option<String> {
    let components: Vec<_> = path.components().collect();
    components.windows(4).rev().find_map(|parts| match parts {
        [
            Component::Normal(gemini),
            Component::Normal(provider),
            Component::Normal(parent),
            Component::Normal(id),
        ] if *gemini == ".gemini"
            && (*provider == "antigravity" || *provider == "antigravity-cli")
            && *parent == "brain" =>
        {
            let id = id.to_str()?;
            (!id.is_empty()
                && id.len() <= 128
                && !id.starts_with('.')
                && id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')))
            .then(|| id.to_string())
        }
        _ => None,
    })
}

pub(crate) fn parse_file(raw: &str, path: &Path) -> Result<AntigravityParse> {
    let session_id = session_id_from_path(path);
    let source_name = if path.to_string_lossy().contains("/.gemini/antigravity-cli/") {
        "antigravity-cli"
    } else {
        "antigravity"
    };
    // Antigravity's redacted projection does not expose a workspace path.
    // Retain that uncertainty while still giving session inventory a stable,
    // honest provider namespace (session queries intentionally exclude rows
    // with no project identity).
    let ai_project = if source_name == "antigravity-cli" {
        "antigravity://cli"
    } else {
        "antigravity://desktop"
    };
    let session_metadata = TranscriptSessionMetadata {
        agent_name: Some("antigravity".to_string()),
        model_provider: Some("google".to_string()),
        entrypoint: Some(source_name.to_string()),
        source: Some(source_name.to_string()),
        source_format: Some("antigravity-transcript-jsonl".to_string()),
        ..Default::default()
    };
    let mut parsed = AntigravityParse::default();

    for (line_no, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).with_context(|| {
            format!(
                "invalid Antigravity transcript record at line {}",
                line_no + 1
            )
        })?;
        let step_index = value.get("step_index").and_then(Value::as_u64);
        let source = string(&value, "source");
        let record_type = string(&value, "type");
        let status = string(&value, "status");
        let tool_calls = extract_tool_calls(&value);
        let Some(message) = extract_message(&value, &tool_calls) else {
            parsed.skipped_empty += 1;
            continue;
        };
        let serialized = serde_json::to_string(&value)?;
        let record_hash = hash_text(&serialized);
        let record_key = step_index
            .map(|index| format!("step:{index}:hash:{record_hash}"))
            .unwrap_or_else(|| format!("line:{line_no}:hash:{}", hash_text(&serialized)));
        let event_kind = event_kind(
            source.as_deref(),
            record_type.as_deref(),
            status.as_deref(),
            !tool_calls.is_empty(),
        );

        parsed.records.push(AntigravityRecord {
            transcript: ParsedTranscriptRecord {
                record_key,
                timestamp: string(&value, "created_at").or_else(|| string(&value, "timestamp")),
                message,
                session_id: session_id.clone(),
                ai_project: Some(ai_project.to_string()),
                event_kind,
                session_metadata: session_metadata.clone(),
                raw_value: Some(value),
            },
            step_index,
            source,
            record_type,
            status,
            tool_calls,
        });
    }
    Ok(parsed)
}

pub(crate) fn parse_line(
    line: &str,
    path: &Path,
    line_no: usize,
) -> Result<Option<ParsedTranscriptRecord>> {
    let mut record = parse_file(line, path)?.records.into_iter().next();
    if let Some(record) = &mut record
        && record.step_index.is_none()
    {
        let serialized = serde_json::to_string(
            record
                .transcript
                .raw_value
                .as_ref()
                .expect("Antigravity records retain their parsed value"),
        )?;
        record.transcript.record_key = format!("line:{line_no}:hash:{}", hash_text(&serialized));
    }
    Ok(record.map(|record| record.transcript))
}

fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn extract_tool_calls(value: &Value) -> Vec<AntigravityToolCall> {
    value
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|call| {
            let function = call.get("function").unwrap_or(call);
            let name = function.get("name").and_then(Value::as_str)?.trim();
            if name.is_empty() {
                return None;
            }
            Some(AntigravityToolCall {
                name: name.to_string(),
                arguments: function
                    .get("args")
                    .or_else(|| function.get("arguments"))
                    .cloned()
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn extract_message(value: &Value, tool_calls: &[AntigravityToolCall]) -> Option<String> {
    for key in ["content", "thinking"] {
        if let Some(text) = value.get(key).and_then(Value::as_str).map(str::trim)
            && !text.is_empty()
        {
            return Some(text.to_string());
        }
    }
    (!tool_calls.is_empty()).then(|| {
        format!(
            "tool call: {}",
            tool_calls
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn event_kind(
    source: Option<&str>,
    record_type: Option<&str>,
    status: Option<&str>,
    has_tool_calls: bool,
) -> String {
    if status.is_some_and(|status| {
        status.eq_ignore_ascii_case("error") || status.eq_ignore_ascii_case("failed")
    }) {
        "error"
    } else if has_tool_calls
        || record_type.is_some_and(|kind| kind.to_ascii_lowercase().contains("tool"))
    {
        "tool"
    } else if source.is_some_and(|source| source.eq_ignore_ascii_case("user")) {
        "user"
    } else if source.is_some_and(|source| source.eq_ignore_ascii_case("model")) {
        "assistant"
    } else {
        "status"
    }
    .to_string()
}

#[cfg(test)]
#[path = "antigravity_tests.rs"]
mod tests;
