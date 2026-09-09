//! Shared OTLP attribute normalization for logs, spans, and metric points.
//!
//! Signal adapters keep ownership of signal-specific fields such as timestamps,
//! bodies, IDs, status, and values. This module owns provider identity and
//! bounded attribute rules that must stay identical across all OTLP signals.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::common::v1::{
    AnyValue, KeyValue, any_value::Value as AnyValueKind,
};

use crate::ingest_metadata::{MAX_METADATA_OBJECT_FIELDS, attrs_to_metadata_object_with_limit};

const MAX_SESSION_ID_BYTES: usize = 128;
const MAX_PROJECT_PATH_BYTES: usize = 512;
const MAX_TOOL_BYTES: usize = 64;
pub(crate) const MAX_RESOURCE_ATTRIBUTES: usize = 128;
pub(crate) const MAX_SIGNAL_ATTRIBUTES: usize = 256;
const STRING_TABLE_INDEX_WARNING_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NormalizedOtlpAttributes {
    pub host_name: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    /// Full provider normalization from contract section 9.4. Future trace
    /// and metric adapters consume this field directly.
    pub ai_tool: Option<String>,
    /// Compatibility value for the existing log converter. Before AO-041,
    /// logs only populated ai_tool from explicit ai.tool / ai_tool attributes;
    /// downstream enrichment handled service-name aliases.
    pub legacy_log_ai_tool: Option<String>,
    pub ai_session_id: Option<String>,
    pub ai_project: Option<String>,
    pub resource_attributes: serde_json::Value,
    pub signal_attributes: serde_json::Value,
    /// Existing /v1/logs metadata historically capped record attributes at
    /// the shared 128-field metadata limit. Keep that exact view while the
    /// shared signal view supports the Agent Observatory 256-attribute cap.
    pub legacy_log_signal_attributes: serde_json::Value,
}

impl NormalizedOtlpAttributes {
    pub(crate) fn log_ai_tool(&self) -> Option<String> {
        self.legacy_log_ai_tool.clone()
    }
}

pub(crate) fn normalize_attributes(
    resource_kvs: &[KeyValue],
    signal_kvs: &[KeyValue],
) -> NormalizedOtlpAttributes {
    let resource = collect_attrs(resource_kvs);
    let signal = collect_attrs(signal_kvs);
    let service_name = string_attr(&resource, "service.name");

    NormalizedOtlpAttributes {
        host_name: string_attr(&resource, "host.name").unwrap_or_default(),
        service_version: string_attr(&resource, "service.version"),
        ai_session_id: session_id(&signal, &resource),
        ai_project: project_path(&signal, &resource),
        legacy_log_ai_tool: legacy_log_ai_tool(&signal, &resource),
        ai_tool: normalized_tool(&signal, &resource, service_name.as_deref()),
        resource_attributes: attrs_to_json(&resource, MAX_RESOURCE_ATTRIBUTES),
        signal_attributes: attrs_to_json(&signal, MAX_SIGNAL_ATTRIBUTES),
        legacy_log_signal_attributes: attrs_to_json(&signal, MAX_METADATA_OBJECT_FIELDS),
        service_name,
    }
}

fn session_id(
    signal: &BTreeMap<&str, &AnyValue>,
    resource: &BTreeMap<&str, &AnyValue>,
) -> Option<String> {
    first_string(
        signal,
        &["session.id", "session_id", "gen_ai.conversation.id"],
    )
    .or_else(|| {
        first_string(
            resource,
            &["session.id", "session_id", "gen_ai.conversation.id"],
        )
    })
    .filter(|value| value.len() <= MAX_SESSION_ID_BYTES)
}

fn project_path(
    signal: &BTreeMap<&str, &AnyValue>,
    resource: &BTreeMap<&str, &AnyValue>,
) -> Option<String> {
    first_string(
        signal,
        &["project.path", "codebase.root_path", "session.cwd"],
    )
    .or_else(|| {
        first_string(
            resource,
            &["project.path", "codebase.root_path", "session.cwd"],
        )
    })
    .filter(|value| value.len() <= MAX_PROJECT_PATH_BYTES)
}

fn normalized_tool(
    signal: &BTreeMap<&str, &AnyValue>,
    resource: &BTreeMap<&str, &AnyValue>,
    service_name: Option<&str>,
) -> Option<String> {
    let explicit = first_string(signal, &["ai.tool", "ai_tool"])
        .or_else(|| first_string(resource, &["ai.tool", "ai_tool"]));
    let agent_name = string_attr(signal, "gen_ai.agent.name")
        .or_else(|| string_attr(resource, "gen_ai.agent.name"));
    explicit
        .or(agent_name)
        .or_else(|| service_name.map(str::to_string))
        .and_then(|value| canonical_tool(&value))
}

fn legacy_log_ai_tool(
    signal: &BTreeMap<&str, &AnyValue>,
    resource: &BTreeMap<&str, &AnyValue>,
) -> Option<String> {
    let raw = first_string(signal, &["ai.tool", "ai_tool"])
        .or_else(|| first_string(resource, &["ai.tool", "ai_tool"]))?;
    if raw.len() > MAX_TOOL_BYTES {
        return None;
    }
    crate::scanner::providers::canonical_transcript_provider(&raw).map(str::to_string)
}

fn canonical_tool(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(provider) = crate::scanner::providers::canonical_transcript_provider(&normalized) {
        return Some(provider.to_string());
    }
    let source = normalized
        .strip_prefix("unknown:")
        .map(str::trim)
        .unwrap_or(normalized.as_str());
    if source.is_empty() {
        return None;
    }
    let value = format!("unknown:{source}");
    (value.len() <= MAX_TOOL_BYTES).then_some(value)
}

fn first_string(attrs: &BTreeMap<&str, &AnyValue>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| string_attr(attrs, key))
}

fn string_attr(attrs: &BTreeMap<&str, &AnyValue>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|value| any_value_to_string(value))
}

fn collect_attrs(kvs: &[KeyValue]) -> BTreeMap<&str, &AnyValue> {
    kvs.iter()
        .filter_map(|kv| {
            let key = attr_key(kv)?;
            kv.value.as_ref().map(|value| (key, value))
        })
        .collect()
}

pub(super) fn attr_key(kv: &KeyValue) -> Option<&str> {
    if kv.key_strindex != 0 {
        warn_key_strindex_rate_limited(kv.key_strindex);
        return None;
    }
    Some(kv.key.as_str())
}

fn attrs_to_json(attrs: &BTreeMap<&str, &AnyValue>, max_fields: usize) -> serde_json::Value {
    attrs_to_metadata_object_with_limit(
        attrs
            .iter()
            .map(|(key, value)| (*key, any_value_to_json(value))),
        max_fields,
    )
}

pub(super) fn any_value_to_json(value: &AnyValue) -> serde_json::Value {
    match value.value.as_ref() {
        Some(AnyValueKind::StringValue(value)) => serde_json::Value::String(value.clone()),
        Some(AnyValueKind::BoolValue(value)) => serde_json::Value::Bool(*value),
        Some(AnyValueKind::IntValue(value)) => serde_json::Value::Number((*value).into()),
        Some(AnyValueKind::DoubleValue(value)) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(AnyValueKind::BytesValue(value)) => serde_json::json!({"bytes_len": value.len()}),
        Some(AnyValueKind::ArrayValue(value)) => {
            serde_json::json!({"array_len": value.values.len()})
        }
        Some(AnyValueKind::KvlistValue(value)) => {
            serde_json::json!({"kvlist_len": value.values.len()})
        }
        Some(AnyValueKind::StringValueStrindex(index)) => {
            warn_value_strindex_rate_limited(*index);
            serde_json::json!({"string_table_index": index})
        }
        None => serde_json::Value::Null,
    }
}

pub(super) fn any_value_to_string(value: &AnyValue) -> Option<String> {
    match value.value.as_ref()? {
        AnyValueKind::StringValue(value) => Some(value.clone()),
        AnyValueKind::BoolValue(value) => Some(value.to_string()),
        AnyValueKind::IntValue(value) => Some(value.to_string()),
        AnyValueKind::DoubleValue(value) => Some(value.to_string()),
        AnyValueKind::BytesValue(value) => Some(format!("[{} bytes]", value.len())),
        AnyValueKind::ArrayValue(value) => Some(format!("[array len={}]", value.values.len())),
        AnyValueKind::KvlistValue(value) => Some(format!("[kvlist len={}]", value.values.len())),
        AnyValueKind::StringValueStrindex(index) => {
            warn_value_strindex_rate_limited(*index);
            Some(format!("[string_table_index={index}]"))
        }
    }
}

static LAST_KEY_STRINDEX_WARNING: LazyLock<Mutex<Option<Instant>>> =
    LazyLock::new(|| Mutex::new(None));
static LAST_VALUE_STRINDEX_WARNING: LazyLock<Mutex<Option<Instant>>> =
    LazyLock::new(|| Mutex::new(None));

fn warn_key_strindex_rate_limited(key_strindex: i32) {
    let Ok(mut last) = LAST_KEY_STRINDEX_WARNING.lock() else {
        return;
    };
    if record_string_table_index_warning(
        &mut last,
        Instant::now(),
        STRING_TABLE_INDEX_WARNING_INTERVAL,
    ) {
        tracing::warn!(
            key_strindex,
            "OTLP KeyValue.key_strindex seen; attribute dropped because cortex cannot resolve the string-table index"
        );
    }
}

fn warn_value_strindex_rate_limited(string_table_index: i32) {
    let Ok(mut last) = LAST_VALUE_STRINDEX_WARNING.lock() else {
        return;
    };
    if record_string_table_index_warning(
        &mut last,
        Instant::now(),
        STRING_TABLE_INDEX_WARNING_INTERVAL,
    ) {
        tracing::warn!(
            string_table_index,
            "OTLP AnyValue::StringValueStrindex seen; preserving an opaque placeholder"
        );
    }
}

pub(super) fn record_string_table_index_warning(
    last: &mut Option<Instant>,
    now: Instant,
    interval: Duration,
) -> bool {
    match *last {
        Some(previous) if now.duration_since(previous) < interval => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

#[cfg(test)]
#[path = "normalization_tests.rs"]
mod tests;
