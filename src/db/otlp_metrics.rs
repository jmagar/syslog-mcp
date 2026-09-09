//! OTLP metric-point persistence and idempotent batch writes.

use anyhow::Result;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

use super::{DbPool, TRANSIENT_SQLITE_RETRY_DELAYS_MS, is_transient_sqlite_lock};

const MAX_JSON_BYTES: usize = 256 * 1024;
const MAX_NAME_CHARS: usize = 512;
const MAX_DESCRIPTION_CHARS: usize = 4096;
const MAX_UNIT_CHARS: usize = 128;
const MAX_HOSTNAME_CHARS: usize = 255;
const MAX_IDENTITY_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelMetricPointInput {
    pub point_key: String,
    pub metric_name: String,
    pub description: String,
    pub unit: String,
    pub instrument_kind: String,
    pub aggregation_temporality: Option<i32>,
    pub monotonic: Option<bool>,
    pub start_time_unix_nano: Option<i64>,
    pub time_unix_nano: i64,
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
    pub value_json: String,
    pub exemplars_json: String,
    pub received_at: String,
    pub content_scrubbed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelMetricBatchResult {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
}

pub fn insert_otel_metric_points_batch(
    pool: &DbPool,
    entries: &[OtelMetricPointInput],
) -> Result<OtelMetricBatchResult> {
    let mut attempt = 0usize;
    loop {
        match insert_once(pool, entries) {
            Ok(result) => return Ok(result),
            Err(error)
                if is_transient_sqlite_lock(&error)
                    && attempt < TRANSIENT_SQLITE_RETRY_DELAYS_MS.len() =>
            {
                std::thread::sleep(std::time::Duration::from_millis(
                    TRANSIENT_SQLITE_RETRY_DELAYS_MS[attempt],
                ));
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn insert_once(pool: &DbPool, entries: &[OtelMetricPointInput]) -> Result<OtelMetricBatchResult> {
    if entries.is_empty() {
        return Ok(OtelMetricBatchResult::default());
    }
    let mut conn = crate::db::write_conn(pool)?;
    let tx = conn.transaction()?;
    let result = insert_in_tx(&tx, entries)?;
    tx.commit()?;
    if result.accepted > 0 {
        crate::db::agent_observatory::notify_projection_work();
    }
    Ok(result)
}

fn insert_in_tx(
    tx: &Transaction<'_>,
    entries: &[OtelMetricPointInput],
) -> Result<OtelMetricBatchResult> {
    let mut result = OtelMetricBatchResult::default();
    let mut stmt = tx.prepare_cached(
        "INSERT INTO otel_metric_points
            (point_key, metric_name, description, unit, instrument_kind,
             aggregation_temporality, monotonic, start_time_unix_nano, time_unix_nano,
             hostname, service_name, service_version, scope_name, scope_version,
             ai_tool, ai_project, ai_session_id, run_id, resource_json, attributes_json,
             value_json, exemplars_json, received_at, content_scrubbed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)
         ON CONFLICT(point_key) DO NOTHING",
    )?;
    for entry in entries {
        if !valid_input(tx, entry)? {
            result.rejected += 1;
            continue;
        }
        let changed = stmt.execute(params![
            entry.point_key,
            entry.metric_name,
            entry.description,
            entry.unit,
            entry.instrument_kind,
            entry.aggregation_temporality,
            entry.monotonic,
            entry.start_time_unix_nano,
            entry.time_unix_nano,
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
            entry.value_json,
            entry.exemplars_json,
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

fn valid_input(tx: &Transaction<'_>, entry: &OtelMetricPointInput) -> Result<bool> {
    let valid = entry.point_key.len() == 64
        && entry.point_key.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !entry.metric_name.is_empty()
        && within_chars(&entry.metric_name, MAX_NAME_CHARS)
        && within_chars(&entry.description, MAX_DESCRIPTION_CHARS)
        && within_chars(&entry.unit, MAX_UNIT_CHARS)
        && within_chars(&entry.hostname, MAX_HOSTNAME_CHARS)
        && matches!(
            entry.instrument_kind.as_str(),
            "gauge" | "sum" | "histogram" | "exponential_histogram" | "summary"
        )
        && valid_instrument_metadata(entry)
        && entry.time_unix_nano > 0
        && entry
            .start_time_unix_nano
            .is_none_or(|start| start >= 0 && start <= entry.time_unix_nano)
        && chrono::DateTime::parse_from_rfc3339(&entry.received_at).is_ok()
        && optional_bytes(&entry.service_name)
        && optional_bytes(&entry.service_version)
        && optional_bytes(&entry.scope_name)
        && optional_bytes(&entry.scope_version)
        && optional_bytes(&entry.ai_tool)
        && optional_bytes(&entry.ai_project)
        && optional_bytes(&entry.ai_session_id)
        && json_shape(&entry.resource_json, true)
        && json_shape(&entry.attributes_json, true)
        && json_shape(&entry.value_json, false)
        && json_array(&entry.exemplars_json);
    if !valid {
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

fn valid_instrument_metadata(entry: &OtelMetricPointInput) -> bool {
    match entry.instrument_kind.as_str() {
        "gauge" | "summary" => entry.aggregation_temporality.is_none() && entry.monotonic.is_none(),
        "sum" => matches!(entry.aggregation_temporality, Some(1 | 2)) && entry.monotonic.is_some(),
        "histogram" | "exponential_histogram" => {
            matches!(entry.aggregation_temporality, Some(1 | 2)) && entry.monotonic.is_none()
        }
        _ => false,
    }
}

fn within_chars(value: &str, maximum: usize) -> bool {
    value.chars().count() <= maximum
}

fn optional_bytes(value: &Option<String>) -> bool {
    value
        .as_ref()
        .is_none_or(|value| value.len() <= MAX_IDENTITY_BYTES)
}

fn parse_json(raw: &str) -> Option<serde_json::Value> {
    (raw.len() <= MAX_JSON_BYTES)
        .then(|| serde_json::from_str(raw).ok())
        .flatten()
}

fn json_shape(raw: &str, object: bool) -> bool {
    parse_json(raw).is_some_and(|value| !object || value.is_object())
}

fn json_array(raw: &str) -> bool {
    parse_json(raw).is_some_and(|value| value.is_array())
}

#[cfg(test)]
#[path = "otlp_metrics_tests.rs"]
mod tests;
