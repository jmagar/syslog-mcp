//! MCP/tool-call event extraction from AI transcript records.
//!
//! Two independent extractors feed the same [`ExtractedMcpEvent`] shape:
//! - Claude: `message.content[]` items with `type = "tool_use"` (call) or
//!   `type = "tool_result"` (result, linked back to the call via
//!   `tool_use_id`).
//! - Codex: `response_item` rows with `payload.type = "function_call"` or
//!   `custom_tool_call` (call), paired with the corresponding `*_output`
//!   result through `payload.call_id`.
//!
//! Both extractors operate on the already-parsed raw JSON `Value` for a
//! single transcript line (never re-parse `line_text`), and return zero or
//! more events per line — unlike skill-event extraction, a single Claude
//! assistant turn can contain multiple `tool_use` blocks, so this is a
//! `Vec`, not an `Option`.
//!
//! `tool_name` classification: a name is classified as MCP
//! (`mcp_server`/`mcp_tool` populated) only when it matches the
//! `mcp__<server>__<tool>` naming convention emitted by both Claude and
//! Codex's MCP tool-call surface (GH #94's Lavra research: "Codex MCP/tool
//! names may be exposed as plain function names ... or namespaced tool
//! names ... Implement parser normalization by shape, not by one exact
//! prefix" — the `mcp__` double-underscore shape is the one safe prefix
//! both platforms actually emit). Builtin tool names (`Bash`, `Read`,
//! `shell`, `exec_command`, ...) are still recorded as general tool-call
//! rows with `mcp_server = NULL` per the schema note in GH #94's "MCP
//! assessment design" section — `cortex assess mcp` filters to
//! MCP-classified rows at query time.

use serde_json::Value;

use crate::assessment::{redact_json_value_strings, redact_secrets};

/// Bound on stored preview/argument fields — mirrors
/// `ingest_metadata::MAX_METADATA_STRING_CHARS` so a single oversized tool
/// payload cannot bloat `ai_mcp_events` rows or leak a full secret/log dump.
const MAX_PREVIEW_CHARS: usize = 2048;
const MAX_RAW_OUTPUT_CHARS: usize = MAX_PREVIEW_CHARS * 4;
const MAX_NAME_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpEventKind {
    Call,
    Result,
}

impl McpEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Result => "result",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedMcpEvent {
    pub call_id: String,
    pub tool_name: String,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub event_kind: McpEventKind,
    pub turn_id: Option<String>,
    pub status: Option<String>,
    pub is_error: Option<bool>,
    pub arguments_json: Option<String>,
    pub output_preview: Option<String>,
    pub error_text: Option<String>,
}

impl ExtractedMcpEvent {
    /// Reject the event if `tool_name`, `mcp_server`, or `mcp_tool` contain
    /// any `char::is_control()` character. Mirrors
    /// `ExtractedSkillEvent::normalized()` (eng review Fix 8 there): these
    /// fields are printed verbatim by the CLI's `println!`-based printer
    /// (`src/cli/output/logs/events.rs`), so an ANSI escape or embedded
    /// newline/CR here would otherwise be a terminal output spoofing
    /// vector. `tool_name` comes straight from the transcript's `name`
    /// field (an adversarial/malformed MCP server or transcript could set
    /// it to anything); `mcp_server`/`mcp_tool` are substrings of
    /// `tool_name` via `classify_tool_name`, so they inherit the same
    /// risk. Never panics — callers skip the event and keep parsing the
    /// rest of the transcript.
    fn normalized(self) -> Option<Self> {
        if self.tool_name.chars().any(char::is_control) {
            return None;
        }
        if self
            .mcp_server
            .as_deref()
            .is_some_and(|s| s.chars().any(char::is_control))
        {
            return None;
        }
        if self
            .mcp_tool
            .as_deref()
            .is_some_and(|s| s.chars().any(char::is_control))
        {
            return None;
        }
        Some(self)
    }
}

fn clamp_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

/// Classify `name` as MCP-style (`mcp__<server>__<tool>`) or leave it as a
/// general/builtin tool call. Only the double-underscore `mcp__` prefix is
/// treated as authoritative — anything else (bare builtins, single-underscore
/// wrapper-local names like `exec_command`) is left unclassified rather than
/// guessed at, per GH #94's "normalize by shape, not by one exact prefix"
/// guidance (shape here means: exactly the `mcp__` delimiter convention both
/// platforms are observed to emit for MCP-routed tools).
fn classify_tool_name(name: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = name.strip_prefix("mcp__") else {
        return (None, None);
    };
    match rest.split_once("__") {
        Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
            (Some(server.to_string()), Some(tool.to_string()))
        }
        _ => (None, None),
    }
}

/// Redact and length-clamp a preview string. `redact_secrets` tokenizes on
/// whitespace, so a secret carried as a JSON value (e.g.
/// `{"api_key":"sk-..."}`) serializes to a single whitespace-free token
/// that doesn't start with a known prefix and is never caught. When
/// `value` parses as a JSON object or array — the common shape for tool
/// arguments/output — redact each string leaf individually before
/// re-serializing instead, so secret boundaries are visible to
/// `looks_secretish`. Scalar JSON values (bare strings/numbers) and
/// non-JSON text fall back to whole-string redaction unchanged.
fn bounded_preview(value: &str) -> String {
    let redacted = match serde_json::from_str::<Value>(value) {
        Ok(mut parsed @ (Value::Object(_) | Value::Array(_))) => {
            redact_json_value_strings(&mut parsed);
            parsed.to_string()
        }
        // A bare JSON string (e.g. `value` is `"sk-realsecret"`, quotes
        // included) parses successfully but isn't an Object/Array, so it
        // fell through to `redact_secrets(value)` below on the STILL-
        // QUOTED text — the leading `"` breaks every `looks_secretish`
        // prefix check (`"sk-...` doesn't start with `sk-`), silently
        // letting the secret through. Redact the unquoted inner string
        // directly instead.
        Ok(Value::String(s)) => redact_secrets(&s),
        _ => redact_secrets(value),
    };
    clamp_chars(&redacted, MAX_PREVIEW_CHARS)
}

/// Extract Claude `tool_use`/`tool_result` events from one transcript line's
/// raw JSON value. Scans `message.content[]` (assistant `tool_use` rows) or
/// `message.content[]` (user `tool_result` rows) — both shapes live under
/// the same pointer, so a single scan covers both.
pub fn extract_claude_mcp_events(value: &Value) -> Vec<ExtractedMcpEvent> {
    let Some(items) = value.pointer("/message/content").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut events = Vec::new();
    for item in items {
        let Some(item_type) = item.get("type").and_then(Value::as_str) else {
            continue;
        };
        match item_type {
            "tool_use" => {
                let Some(call_id) = item.get("id").and_then(Value::as_str) else {
                    continue;
                };
                let Some(name) = item.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let (mcp_server, mcp_tool) = classify_tool_name(name);
                let arguments_json = item.get("input").map(|input| {
                    let encoded = input.to_string();
                    bounded_preview(&encoded)
                });
                if let Some(event) = (ExtractedMcpEvent {
                    call_id: clamp_chars(call_id, MAX_NAME_CHARS),
                    tool_name: clamp_chars(name, MAX_NAME_CHARS),
                    mcp_server,
                    mcp_tool,
                    event_kind: McpEventKind::Call,
                    turn_id: None,
                    status: None,
                    is_error: None,
                    arguments_json,
                    output_preview: None,
                    error_text: None,
                })
                .normalized()
                {
                    events.push(event);
                }
            }
            "tool_result" => {
                let Some(call_id) = item.get("tool_use_id").and_then(Value::as_str) else {
                    continue;
                };
                let is_error = item.get("is_error").and_then(Value::as_bool);
                let content_text = match item.get("content") {
                    Some(Value::String(text)) => Some(text.clone()),
                    Some(Value::Array(parts)) => {
                        let joined: Vec<&str> = parts
                            .iter()
                            .filter_map(|part| {
                                part.as_str()
                                    .or_else(|| part.get("text").and_then(Value::as_str))
                            })
                            .collect();
                        (!joined.is_empty()).then(|| joined.join(" "))
                    }
                    _ => None,
                };
                let (output_preview, error_text) = match (is_error, &content_text) {
                    (Some(true), Some(text)) => (None, Some(bounded_preview(text))),
                    (_, Some(text)) => (Some(bounded_preview(text)), None),
                    _ => (None, None),
                };
                if let Some(event) = (ExtractedMcpEvent {
                    call_id: clamp_chars(call_id, MAX_NAME_CHARS),
                    // Result rows don't carry the tool name in Claude's
                    // shape; the DB layer resolves it from the paired call
                    // row when persisting (see `db::mcp_events`). Kept empty
                    // here rather than guessed.
                    tool_name: String::new(),
                    mcp_server: None,
                    mcp_tool: None,
                    event_kind: McpEventKind::Result,
                    turn_id: None,
                    status: Some(
                        if is_error == Some(true) {
                            "error"
                        } else {
                            "ok"
                        }
                        .to_string(),
                    ),
                    is_error,
                    arguments_json: None,
                    output_preview,
                    error_text,
                })
                .normalized()
                {
                    events.push(event);
                }
            }
            _ => {}
        }
    }
    events
}

/// Extract Codex function/custom-tool call and output events from one
/// transcript line's raw JSON value (`{"type": "response_item", "payload":
/// {...}}`).
pub fn extract_codex_mcp_events(value: &Value) -> Vec<ExtractedMcpEvent> {
    if value.get("type").and_then(Value::as_str) != Some("response_item") {
        return Vec::new();
    }
    let Some(payload) = value.get("payload") else {
        return Vec::new();
    };
    let payload_type = payload.get("type").and_then(Value::as_str);
    let turn_id = payload
        .pointer("/metadata/turn_id")
        .and_then(Value::as_str)
        .map(|s| clamp_chars(s, MAX_NAME_CHARS));

    match payload_type {
        Some("function_call" | "custom_tool_call") => {
            let Some(call_id) = payload.get("call_id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let Some(name) = payload.get("name").and_then(Value::as_str) else {
                return Vec::new();
            };
            let (mcp_server, mcp_tool) = classify_tool_name(name);
            let arguments_json = payload
                .get("arguments")
                .or_else(|| payload.get("input"))
                .and_then(Value::as_str)
                .map(bounded_preview);
            (ExtractedMcpEvent {
                call_id: clamp_chars(call_id, MAX_NAME_CHARS),
                tool_name: clamp_chars(name, MAX_NAME_CHARS),
                mcp_server,
                mcp_tool,
                event_kind: McpEventKind::Call,
                turn_id,
                status: payload
                    .get("status")
                    .and_then(Value::as_str)
                    .map(|status| clamp_chars(status, MAX_NAME_CHARS)),
                is_error: None,
                arguments_json,
                output_preview: None,
                error_text: None,
            })
            .normalized()
            .into_iter()
            .collect()
        }
        Some("function_call_output" | "custom_tool_call_output") => {
            let Some(call_id) = payload.get("call_id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let raw_output = payload.get("output").and_then(output_text);
            // Codex wraps output as a JSON-encoded string:
            // `{"output": "...", "metadata": {"exit_code": N, ...}}"`.
            // Best-effort parse it to recover exit_code/is_error without
            // requiring it — plain string output is also accepted.
            let (output_text, is_error, status) = match raw_output
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
            {
                Some(parsed) => {
                    let text = parsed
                        .get("output")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| raw_output.clone());
                    let exit_code = parsed
                        .pointer("/metadata/exit_code")
                        .and_then(Value::as_i64);
                    let is_error = exit_code.map(|code| code != 0);
                    let status = exit_code.map(|code| code.to_string());
                    (text, is_error, status)
                }
                None => (raw_output, None, None),
            };
            let (output_preview, error_text) = match (is_error, &output_text) {
                (Some(true), Some(text)) => (None, Some(bounded_preview(text))),
                (_, Some(text)) => (Some(bounded_preview(text)), None),
                _ => (None, None),
            };
            (ExtractedMcpEvent {
                call_id: clamp_chars(call_id, MAX_NAME_CHARS),
                tool_name: String::new(),
                mcp_server: None,
                mcp_tool: None,
                event_kind: McpEventKind::Result,
                turn_id,
                status,
                is_error,
                arguments_json: None,
                output_preview,
                error_text,
            })
            .normalized()
            .into_iter()
            .collect()
        }
        _ => Vec::new(),
    }
}

/// Extract Antigravity tool calls from its redacted transcript projection.
/// These projections expose calls but not a stable paired-result shape, so
/// every item is recorded as a call and no result is invented.
pub fn extract_antigravity_mcp_events(value: &Value) -> Vec<ExtractedMcpEvent> {
    let Some(calls) = value.get("tool_calls").and_then(Value::as_array) else {
        return Vec::new();
    };
    let step = value.get("step_index").and_then(Value::as_u64);
    calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| {
            let function = call.get("function").unwrap_or(call);
            let name = function.get("name").and_then(Value::as_str)?.trim();
            if name.is_empty() {
                return None;
            }
            let call_id = call
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| {
                    format!("record:{}:{index}", super::hash_text(&value.to_string()))
                });
            let (mcp_server, mcp_tool) = classify_tool_name(name);
            let arguments_json = function
                .get("args")
                .or_else(|| function.get("arguments"))
                .map(|arguments| bounded_preview(&arguments.to_string()));
            ExtractedMcpEvent {
                call_id: clamp_chars(&call_id, MAX_NAME_CHARS),
                tool_name: clamp_chars(name, MAX_NAME_CHARS),
                mcp_server,
                mcp_tool,
                event_kind: McpEventKind::Call,
                turn_id: step.map(|value| value.to_string()),
                status: value
                    .get("status")
                    .and_then(Value::as_str)
                    .map(|status| clamp_chars(status, MAX_NAME_CHARS)),
                is_error: None,
                arguments_json,
                output_preview: None,
                error_text: None,
            }
            .normalized()
        })
        .collect()
}

/// Codex custom-tool results may be a scalar string or an array of typed text
/// blocks. Keep only text-bearing blocks: image/audio/resource payloads can be
/// very large and are not useful as a bounded event preview.
fn output_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.chars().take(MAX_RAW_OUTPUT_CHARS).collect()),
        Value::Array(items) => {
            let mut output = String::new();
            let mut output_chars = 0usize;
            for text in items.iter().filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("text").and_then(Value::as_str))
                    .or_else(|| item.get("content").and_then(Value::as_str))
            }) {
                if !output.is_empty() && output_chars < MAX_RAW_OUTPUT_CHARS {
                    output.push(' ');
                    output_chars += 1;
                }
                let remaining = MAX_RAW_OUTPUT_CHARS.saturating_sub(output_chars);
                let bounded: String = text.chars().take(remaining).collect();
                output_chars += bounded.chars().count();
                output.push_str(&bounded);
                if output_chars >= MAX_RAW_OUTPUT_CHARS {
                    break;
                }
            }
            (!output.is_empty()).then_some(output)
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "mcp_events_tests.rs"]
mod tests;
