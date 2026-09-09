use serde_json::{Map, Value};

pub(crate) const MAX_METADATA_JSON_BYTES: usize = 64 * 1024;
pub(crate) const MAX_METADATA_STRING_CHARS: usize = 2048;
pub(crate) const MAX_METADATA_KEY_CHARS: usize = 128;
pub(crate) const MAX_METADATA_OBJECT_FIELDS: usize = 128;

const REDACTED: &str = "[REDACTED]";

pub(crate) fn bounded_metadata_json(value: Value) -> String {
    let value = sanitize_value(value, None);
    let encoded = value.to_string();
    if encoded.len() <= MAX_METADATA_JSON_BYTES {
        return encoded;
    }

    let source_type = value
        .get("source_type")
        .and_then(Value::as_str)
        .map(str::to_string);
    serde_json::json!({
        "source_type": source_type,
        "metadata_truncated": true,
        "metadata_original_bytes": encoded.len(),
    })
    .to_string()
}

/// Like [`bounded_metadata_json`], but refuses to truncate: returns `None`
/// when the sanitized encoding exceeds [`MAX_METADATA_JSON_BYTES`], so
/// callers whose metadata carries load-bearing keys (e.g. the extracted
/// `agent_docker` identity) can back out instead of losing them.
pub(crate) fn try_bounded_metadata_json(value: Value) -> Option<String> {
    let encoded = sanitize_value(value, None).to_string();
    (encoded.len() <= MAX_METADATA_JSON_BYTES).then_some(encoded)
}

#[cfg(test)]
pub(crate) fn attrs_to_metadata_object<'a, I>(attrs: I) -> Value
where
    I: IntoIterator<Item = (&'a str, Value)>,
{
    attrs_to_metadata_object_with_limit(attrs, MAX_METADATA_OBJECT_FIELDS)
}

pub(crate) fn attrs_to_metadata_object_with_limit<'a, I>(attrs: I, max_fields: usize) -> Value
where
    I: IntoIterator<Item = (&'a str, Value)>,
{
    let mut object = Map::new();
    let mut omitted = 0usize;
    for (key, value) in attrs {
        if object.len() >= max_fields {
            omitted += 1;
            continue;
        }
        let stored_key = truncate_chars(key, MAX_METADATA_KEY_CHARS);
        object.insert(stored_key, sanitize_value(value, Some(key)));
    }
    if omitted > 0 {
        // The omission marker is itself a field and must stay inside the
        // advertised object cap. Give it one slot rather than returning
        // `max_fields + 1` entries for over-cap input.
        if max_fields > 0
            && object.len() == max_fields
            && let Some(key) = object.keys().next_back().cloned()
        {
            object.remove(&key);
            omitted += 1;
        }
        if max_fields == 0 {
            return Value::Object(object);
        }
        object.insert("_omitted_fields".to_string(), Value::Number(omitted.into()));
    }
    Value::Object(object)
}

fn sanitize_value(value: Value, key: Option<&str>) -> Value {
    if key.is_some_and(is_sensitive_key) {
        return Value::String(REDACTED.to_string());
    }

    match value {
        Value::String(value) => Value::String(truncate_chars(&value, MAX_METADATA_STRING_CHARS)),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .take(MAX_METADATA_OBJECT_FIELDS)
                .map(|value| sanitize_value(value, key))
                .collect(),
        ),
        Value::Object(values) => sanitize_object(values),
        value => value,
    }
}

fn sanitize_object(values: Map<String, Value>) -> Value {
    let mut object = Map::new();
    let mut omitted = 0usize;
    for (key, value) in values {
        if object.len() >= MAX_METADATA_OBJECT_FIELDS {
            omitted += 1;
            continue;
        }
        let stored_key = truncate_chars(&key, MAX_METADATA_KEY_CHARS);
        object.insert(stored_key, sanitize_value(value, Some(&key)));
    }
    if omitted > 0 {
        object.insert("_omitted_fields".to_string(), Value::Number(omitted.into()));
    }
    Value::Object(object)
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "set-cookie",
        "token",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("access_key")
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max));
    for (idx, ch) in value.chars().enumerate() {
        if idx >= max {
            out.push_str("...[truncated]");
            return out;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[path = "ingest_metadata_tests.rs"]
mod tests;
