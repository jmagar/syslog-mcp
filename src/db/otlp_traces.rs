//! OTLP trace persistence models and idempotent batch writes.

use anyhow::Result;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

use super::{DbPool, TRANSIENT_SQLITE_RETRY_DELAYS_MS, is_transient_sqlite_lock};

const MAX_METADATA_JSON_BYTES: usize = 256 * 1024;
const MAX_SPAN_NAME_CHARS: usize = 1024;
const MAX_TRACE_STATE_CHARS: usize = 512;
const MAX_STATUS_MESSAGE_CHARS: usize = 4096;
const MAX_HOSTNAME_CHARS: usize = 255;
const MAX_SERVICE_CHARS: usize = 512;
const MAX_SCOPE_CHARS: usize = 512;
const MAX_TOOL_BYTES: usize = 64;
const MAX_PROJECT_BYTES: usize = 512;
const MAX_SESSION_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelSpanInput {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub trace_state: Option<String>,
    pub flags: i64,
    pub span_name: String,
    pub span_kind: i64,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub duration_nano: i64,
    pub status_code: i64,
    pub status_message: Option<String>,
    pub hostname: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub scope_name: Option<String>,
    pub scope_version: Option<String>,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub run_id: Option<i64>,
    pub resource_json: String,
    pub attributes_json: String,
    pub events_json: String,
    pub links_json: String,
    pub received_at: String,
    pub content_scrubbed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelTraceBatchResult {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
}

impl OtelTraceBatchResult {
    #[cfg(test)]
    pub const fn total(self) -> usize {
        self.accepted + self.duplicates + self.rejected
    }
}

pub fn insert_otel_spans_batch(
    pool: &DbPool,
    entries: &[OtelSpanInput],
) -> Result<OtelTraceBatchResult> {
    let mut attempt = 0usize;
    loop {
        match insert_otel_spans_batch_once(pool, entries) {
            Ok(result) => return Ok(result),
            Err(error)
                if is_transient_sqlite_lock(&error)
                    && attempt < TRANSIENT_SQLITE_RETRY_DELAYS_MS.len() =>
            {
                let delay_ms = TRANSIENT_SQLITE_RETRY_DELAYS_MS[attempt];
                tracing::warn!(
                    error = %error,
                    attempt = attempt + 1,
                    retry_delay_ms = delay_ms,
                    entry_count = entries.len(),
                    "Transient SQLite lock during OTLP trace batch insert - retrying"
                );
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn insert_otel_spans_batch_once(
    pool: &DbPool,
    entries: &[OtelSpanInput],
) -> Result<OtelTraceBatchResult> {
    if entries.is_empty() {
        return Ok(OtelTraceBatchResult::default());
    }
    let mut conn = crate::db::write_conn(pool)?;
    let tx = conn.transaction()?;
    let result = insert_otel_spans_batch_in_tx(&tx, entries)?;
    tx.commit()?;
    if result.accepted > 0 {
        crate::db::agent_observatory::notify_projection_work();
    }
    tracing::debug!(
        accepted = result.accepted,
        duplicates = result.duplicates,
        rejected = result.rejected,
        "Committed OTLP trace batch transaction"
    );
    Ok(result)
}

fn insert_otel_spans_batch_in_tx(
    tx: &Transaction<'_>,
    entries: &[OtelSpanInput],
) -> Result<OtelTraceBatchResult> {
    let mut result = OtelTraceBatchResult::default();
    let mut stmt = tx.prepare_cached(
        "INSERT INTO otel_spans
            (trace_id, span_id, parent_span_id, trace_state, flags, span_name, span_kind,
             start_time_unix_nano, end_time_unix_nano, duration_nano, status_code,
             status_message, hostname, service_name, service_version, scope_name,
             scope_version, ai_tool, ai_project, ai_session_id, run_id, resource_json,
             attributes_json, events_json, links_json, received_at, content_scrubbed)
         VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
             ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)
         ON CONFLICT(trace_id, span_id) DO NOTHING",
    )?;

    for entry in entries {
        if !valid_span_input(tx, entry)? {
            result.rejected += 1;
            continue;
        }
        let changed = stmt.execute(params![
            entry.trace_id,
            entry.span_id,
            entry.parent_span_id,
            entry.trace_state,
            entry.flags,
            entry.span_name,
            entry.span_kind,
            entry.start_time_unix_nano,
            entry.end_time_unix_nano,
            entry.duration_nano,
            entry.status_code,
            entry.status_message,
            entry.hostname,
            entry.service_name,
            entry.service_version,
            entry.scope_name,
            entry.scope_version,
            entry.ai_tool,
            entry.ai_project,
            entry.ai_session_id,
            entry.run_id,
            entry.resource_json,
            entry.attributes_json,
            entry.events_json,
            entry.links_json,
            entry.received_at,
            entry.content_scrubbed,
        ])?;
        if changed == 1 {
            result.accepted += 1;
        } else {
            result.duplicates += 1;
        }
    }
    Ok(result)
}

fn valid_span_input(tx: &Transaction<'_>, entry: &OtelSpanInput) -> Result<bool> {
    if !valid_hex_id(&entry.trace_id, 32)
        || !valid_hex_id(&entry.span_id, 16)
        || entry
            .parent_span_id
            .as_deref()
            .is_some_and(|value| !valid_hex_id(value, 16))
        || entry.duration_nano < 0
        || entry.end_time_unix_nano < entry.start_time_unix_nano
        || entry
            .end_time_unix_nano
            .checked_sub(entry.start_time_unix_nano)
            != Some(entry.duration_nano)
        || chrono::DateTime::parse_from_rfc3339(&entry.received_at).is_err()
        || !within_chars(&entry.span_name, MAX_SPAN_NAME_CHARS)
        || !entry
            .trace_state
            .as_deref()
            .is_none_or(|value| within_chars(value, MAX_TRACE_STATE_CHARS))
        || !within_chars(&entry.hostname, MAX_HOSTNAME_CHARS)
        || !optional_chars(&entry.service_name, MAX_SERVICE_CHARS)
        || !optional_chars(&entry.service_version, MAX_SERVICE_CHARS)
        || !optional_chars(&entry.scope_name, MAX_SCOPE_CHARS)
        || !optional_chars(&entry.scope_version, MAX_SCOPE_CHARS)
        || !optional_chars(&entry.status_message, MAX_STATUS_MESSAGE_CHARS)
        || !optional_bytes(&entry.ai_tool, MAX_TOOL_BYTES)
        || !optional_bytes(&entry.ai_project, MAX_PROJECT_BYTES)
        || !optional_bytes(&entry.ai_session_id, MAX_SESSION_BYTES)
        || !json_shape(&entry.resource_json, JsonShape::Object)
        || !json_shape(&entry.attributes_json, JsonShape::Object)
        || !json_shape(&entry.events_json, JsonShape::Array)
        || !json_shape(&entry.links_json, JsonShape::Array)
    {
        return Ok(false);
    }
    if let Some(run_id) = entry.run_id {
        if run_id <= 0 {
            return Ok(false);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE id = ?1)",
            [run_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
    }
    Ok(true)
}

fn valid_hex_id(value: &str, expected_chars: usize) -> bool {
    value.len() == expected_chars
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn within_chars(value: &str, maximum: usize) -> bool {
    value.chars().count() <= maximum
}

fn optional_chars(value: &Option<String>, maximum: usize) -> bool {
    value
        .as_deref()
        .is_none_or(|value| within_chars(value, maximum))
}

fn optional_bytes(value: &Option<String>, maximum: usize) -> bool {
    value.as_ref().is_none_or(|value| value.len() <= maximum)
}

#[derive(Clone, Copy)]
enum JsonShape {
    Object,
    Array,
}

fn json_shape(raw: &str, shape: JsonShape) -> bool {
    if raw.len() > MAX_METADATA_JSON_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    matches!(
        (shape, value),
        (JsonShape::Object, serde_json::Value::Object(_))
            | (JsonShape::Array, serde_json::Value::Array(_))
    )
}

#[cfg(test)]
#[path = "otlp_traces_tests.rs"]
mod tests;
