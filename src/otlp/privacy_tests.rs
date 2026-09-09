use super::*;

use opentelemetry_proto::tonic::common::v1::{
    ArrayValue, KeyValueList, any_value::Value as AnyValueKind,
};

fn av(value: &str) -> AnyValue {
    AnyValue {
        value: Some(AnyValueKind::StringValue(value.to_string())),
    }
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(av(value)),
        key_strindex: 0,
    }
}

#[test]
fn default_privacy_redacts_genai_content_identity_and_hashes_email() {
    let attrs = vec![
        kv("gen_ai.input.messages", "secret prompt"),
        kv("gen_ai.output.messages", "secret response"),
        kv("gen_ai.system_instructions", "secret system"),
        kv("gen_ai.tool.call.arguments", "secret args"),
        kv("gen_ai.tool.call.result", "secret result"),
        kv("user.id", "alice"),
        kv("user.email", "Alice@Example.Invalid"),
        kv("project.path", "/workspace/cortex"),
        kv("Authorization", "Bearer do-not-store"),
    ];
    let out = private_attributes(&attrs, 32, &AgentObservatoryPrivacyConfig::default());

    for key in [
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
        "user.id",
        "Authorization",
    ] {
        assert_eq!(out[key], REDACTED);
    }
    assert_eq!(out["project.path"], "/workspace/cortex");
    let expected = format!("sha256:{:x}", Sha256::digest(b"alice@example.invalid"));
    assert_eq!(out["user.email"], expected);
    let encoded = out.to_string();
    for secret in [
        "secret prompt",
        "secret response",
        "secret system",
        "secret args",
        "secret result",
        "alice@example.invalid",
        "do-not-store",
    ] {
        assert!(!encoded.to_ascii_lowercase().contains(secret));
    }
}

#[test]
fn explicit_privacy_opt_ins_preserve_content_but_generic_secrets_stay_redacted() {
    let privacy = AgentObservatoryPrivacyConfig {
        include_prompt_content: true,
        include_tool_content: true,
        include_command_content: true,
        include_paths: true,
        include_user_identity: true,
        hash_email: false,
    };
    let attrs = vec![
        kv("gen_ai.input.messages", "prompt"),
        kv("gen_ai.tool.call.arguments", "args"),
        kv("process.command_line", "echo hello"),
        kv("project.path", "/workspace/cortex"),
        kv("user.id", "alice"),
        kv("user.email", "alice@example.invalid"),
        kv("api_token", "top-secret"),
    ];
    let out = private_attributes(&attrs, 32, &privacy);

    assert_eq!(out["gen_ai.input.messages"], "prompt");
    assert_eq!(out["gen_ai.tool.call.arguments"], "args");
    assert_eq!(out["process.command_line"], "echo hello");
    assert_eq!(out["project.path"], "/workspace/cortex");
    assert_eq!(out["user.id"], "alice");
    assert_eq!(out["user.email"], "alice@example.invalid");
    assert_eq!(out["api_token"], REDACTED);
}

#[test]
fn disabled_paths_and_commands_are_redacted() {
    let privacy = AgentObservatoryPrivacyConfig {
        include_paths: false,
        include_command_content: false,
        ..AgentObservatoryPrivacyConfig::default()
    };
    let attrs = vec![
        kv("project.path", "/secret/project"),
        kv("session.cwd", "/secret/cwd"),
        kv("file.path", "/secret/file"),
        kv("process.command", "rm -rf nope"),
        kv("process.command_line", "echo nope"),
    ];
    let out = private_attributes(&attrs, 32, &privacy);
    for key in [
        "project.path",
        "session.cwd",
        "file.path",
        "process.command",
        "process.command_line",
    ] {
        assert_eq!(out[key], REDACTED);
    }
}

#[test]
fn nested_kvlists_and_arrays_cannot_bypass_privacy_or_secret_redaction() {
    let nested = AnyValue {
        value: Some(AnyValueKind::KvlistValue(KeyValueList {
            values: vec![
                kv("gen_ai.tool.call.result", "nested tool result"),
                kv("password", "nested password"),
                KeyValue {
                    key: "nested.array".to_string(),
                    value: Some(AnyValue {
                        value: Some(AnyValueKind::ArrayValue(ArrayValue {
                            values: vec![av("safe"), av("token=sk-secret-value")],
                        })),
                    }),
                    key_strindex: 0,
                },
            ],
        })),
    };
    let attrs = vec![KeyValue {
        key: "custom.nested".to_string(),
        value: Some(nested),
        key_strindex: 0,
    }];
    let out = private_attributes(&attrs, 32, &AgentObservatoryPrivacyConfig::default());
    let nested = &out["custom.nested"];
    assert_eq!(nested["gen_ai.tool.call.result"], REDACTED);
    assert_eq!(nested["password"], REDACTED);
    let encoded = out.to_string();
    assert!(!encoded.contains("nested tool result"));
    assert!(!encoded.contains("nested password"));
}

#[test]
fn field_limit_is_deterministic_and_reports_omitted_count() {
    let attrs = (0..8)
        .rev()
        .map(|index| kv(&format!("custom.{index}"), "value"))
        .collect::<Vec<_>>();
    let out = private_attributes(&attrs, 3, &AgentObservatoryPrivacyConfig::default());
    let object = out.as_object().unwrap();
    assert_eq!(object["_omitted_fields"], 6);
    assert!(object.contains_key("custom.0"));
    assert!(object.contains_key("custom.1"));
    assert!(!object.contains_key("custom.2"));
}

#[test]
fn nested_array_truncation_is_explicit() {
    let nested = AnyValue {
        value: Some(AnyValueKind::ArrayValue(ArrayValue {
            values: (0..140).map(|index| av(&format!("item-{index}"))).collect(),
        })),
    };
    let attrs = vec![KeyValue {
        key: "custom.array".to_string(),
        value: Some(nested),
        key_strindex: 0,
    }];
    let out = private_attributes(&attrs, 32, &AgentObservatoryPrivacyConfig::default());
    let array = out["custom.array"].as_array().unwrap();
    assert_eq!(array.len(), MAX_NESTED_FIELDS);
    assert_eq!(array[0], "item-0");
    let diagnostic = &array.last().unwrap()["_cortex_diagnostics"];
    assert_eq!(diagnostic["kind"], "array");
    assert_eq!(diagnostic["cortex_omitted"], 13);
    assert_eq!(diagnostic["reason"], "max_nested_items");
}
