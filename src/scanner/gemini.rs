//! Gemini CLI transcript parsing.
//!
//! Current Gemini CLI releases write a JSONL patch journal: a session metadata
//! snapshot followed by `$set` records containing newly persisted messages.
//! Older releases wrote one whole-file JSON object. [`parse_file`] accepts both
//! formats and normalizes them to one stable, duplicate-free message stream.

use std::path::Path;

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::{ParsedTranscriptRecord, TranscriptSessionMetadata, hash_text};

/// Outcome of parsing one Gemini session file.
///
/// Carries the observability signals the whole-file path would otherwise lose:
/// how many messages were skipped for lack of extractable text, and whether the
/// file is a chat file with no `messages` array at all (a likely upstream schema
/// change that must not be silently checkpointed as "fully indexed").
#[derive(Debug)]
pub struct GeminiParse {
    pub records: Vec<ParsedTranscriptRecord>,
    pub skipped_empty: usize,
    pub missing_messages: bool,
}

pub fn is_chat_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|name| name.to_str());
    let parent_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    matches!(parent_name, Some("chats"))
        && file_name.is_some_and(|name| {
            name.starts_with("session-") && (name.ends_with(".json") || name.ends_with(".jsonl"))
        })
}

pub fn parse_file(raw: &str, path: &Path) -> Result<GeminiParse> {
    if raw.trim().is_empty() {
        bail!("Gemini chat file is empty");
    }

    // A legacy session is exactly one JSON value. A current patch journal is
    // multiple independently valid JSON values separated by newlines.
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return parse_values(std::slice::from_ref(&value), path);
    }

    let mut values = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        values.push(
            serde_json::from_str::<Value>(line)
                .with_context(|| format!("invalid Gemini JSONL record at line {}", line_no + 1))?,
        );
    }
    if values.is_empty() {
        bail!("Gemini chat file has no JSON records");
    }
    parse_values(&values, path)
}

fn parse_values(values: &[Value], path: &Path) -> Result<GeminiParse> {
    let field = |names: &[&str]| {
        values.iter().rev().find_map(|value| {
            names.iter().find_map(|name| {
                value
                    .get(*name)
                    .or_else(|| value.get("$set").and_then(|set| set.get(*name)))
            })
        })
    };
    let session_id = field(&["sessionId", "session_id"])
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToString::to_string)
        });
    let ai_project = field(&["cwd", "projectPath", "project_path"])
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            field(&["projectHash", "project_hash"])
                .and_then(Value::as_str)
                .map(|hash| format!("gemini://project/{hash}"))
        });
    let default_timestamp = field(&["startTime", "started_at"])
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let string_field = |names: &[&str]| {
        field(names)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    };
    let title = string_field(&["title", "displayName", "display_name"]);
    let session_metadata = TranscriptSessionMetadata {
        title_provenance: title.as_ref().map(|_| "provider".to_string()),
        title,
        model: string_field(&["model", "modelName", "model_name"]),
        model_provider: Some("google".to_string()),
        client_version: string_field(&["version", "clientVersion", "client_version"]),
        entrypoint: Some("gemini-cli".to_string()),
        source: Some("gemini-cli".to_string()),
        source_format: Some(
            if values.len() == 1 && path.extension().is_some_and(|ext| ext == "json") {
                "gemini-legacy-json"
            } else {
                "gemini-patch-jsonl"
            }
            .to_string(),
        ),
        ..Default::default()
    };
    // `$set.messages` follows JSON patch replacement semantics. The last
    // message array is authoritative; replaying earlier snapshots duplicates
    // history and turns a growing journal into quadratic projection work.
    let messages = values.iter().rev().find_map(|value| {
        value
            .get("messages")
            .or_else(|| value.get("$set").and_then(|set| set.get("messages")))
            .and_then(Value::as_array)
    });
    let Some(messages) = messages else {
        return Ok(GeminiParse {
            records: Vec::new(),
            skipped_empty: 0,
            missing_messages: true,
        });
    };

    let mut records = Vec::new();
    let mut hash_occurrences = HashMap::<String, usize>::new();
    let mut skipped_empty = 0usize;
    for message in messages {
        let serialized = serde_json::to_string(message)?;
        let message_hash = hash_text(&serialized);
        let occurrence = hash_occurrences.entry(message_hash.clone()).or_default();
        let record_key = message
            .get("id")
            .or_else(|| message.get("uuid"))
            .and_then(Value::as_str)
            .map(|id| format!("id:{id}"))
            .unwrap_or_else(|| format!("hash:{message_hash}:occurrence:{occurrence}"));
        *occurrence += 1;
        let Some(content) = extract_message(message) else {
            skipped_empty += 1;
            continue;
        };
        let timestamp = message
            .get("timestamp")
            .or_else(|| message.get("created_at"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| default_timestamp.clone());
        records.push(ParsedTranscriptRecord {
            record_key,
            timestamp,
            message: content,
            session_id: session_id.clone(),
            ai_project: ai_project.clone(),
            event_kind: super::transcript_event_kind(message),
            session_metadata: session_metadata.clone(),
            raw_value: Some(message.clone()),
        });
    }
    Ok(GeminiParse {
        records,
        skipped_empty,
        missing_messages: false,
    })
}

/// Extract the textual content of one Gemini message.
///
/// Handles the shapes the Gemini CLI chat log emits: a scalar `content` or
/// `message` string, or a `content` array of strings / `{text}` / `{content}`
/// parts joined by spaces. Returns `None` when no non-empty text can be
/// extracted (an empty turn or an unrecognized shape) so the caller can count
/// the skip rather than silently swallowing it.
fn extract_message(value: &Value) -> Option<String> {
    let text = if let Some(content) = value.get("content").and_then(Value::as_str) {
        content.to_string()
    } else if let Some(message) = value.get("message").and_then(Value::as_str) {
        message.to_string()
    } else {
        let items = value.get("content").and_then(Value::as_array)?;
        items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("text").and_then(Value::as_str))
                    .or_else(|| item.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
#[path = "gemini_tests.rs"]
mod tests;
