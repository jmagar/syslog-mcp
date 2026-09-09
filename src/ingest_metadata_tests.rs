use super::*;

#[test]
fn redacts_sensitive_keys_and_truncates_long_strings() {
    let value = attrs_to_metadata_object([
        ("Authorization", Value::String("Bearer secret".into())),
        (
            "normal",
            Value::String("x".repeat(MAX_METADATA_STRING_CHARS + 5)),
        ),
    ]);

    assert_eq!(value["Authorization"], REDACTED);
    assert!(
        value["normal"]
            .as_str()
            .unwrap()
            .ends_with("...[truncated]")
    );
}

#[test]
fn redacts_sensitive_keys_before_key_truncation() {
    let long_sensitive_key = format!("{}token", "x".repeat(MAX_METADATA_KEY_CHARS + 20));
    let stored_key = truncate_chars(&long_sensitive_key, MAX_METADATA_KEY_CHARS);
    let value =
        attrs_to_metadata_object([(long_sensitive_key.as_str(), Value::String("secret".into()))]);

    assert_eq!(value[stored_key], REDACTED);
}

#[test]
fn caps_object_field_count() {
    let attrs = (0..(MAX_METADATA_OBJECT_FIELDS + 2))
        .map(|idx| (format!("key-{idx}"), Value::String("value".into())))
        .collect::<Vec<_>>();
    let value = attrs_to_metadata_object(
        attrs
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone())),
    );

    assert_eq!(value["_omitted_fields"], 3);
    assert_eq!(value.as_object().unwrap().len(), MAX_METADATA_OBJECT_FIELDS);
}

#[test]
fn custom_object_field_limit_is_honored() {
    let attrs = (0..5)
        .map(|idx| (format!("key-{idx}"), Value::String("value".into())))
        .collect::<Vec<_>>();
    let value = attrs_to_metadata_object_with_limit(
        attrs
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone())),
        3,
    );

    assert_eq!(value["_omitted_fields"], 3);
    assert_eq!(value.as_object().unwrap().len(), 3);
}

#[test]
fn bounded_metadata_remains_valid_json_when_payload_is_too_large() {
    let value = serde_json::json!({
        "source_type": "otlp",
        "huge": vec!["x".repeat(MAX_METADATA_STRING_CHARS + 20); MAX_METADATA_OBJECT_FIELDS],
    });
    let encoded = bounded_metadata_json(value);
    let parsed: Value = serde_json::from_str(&encoded).unwrap();

    assert_eq!(parsed["source_type"], "otlp");
    assert!(parsed["metadata_truncated"].as_bool().unwrap());
}
