use super::*;

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
fn session_id_precedence_is_signal_before_resource_and_contract_ordered() {
    let resource = vec![
        kv("session.id", "resource-dot"),
        kv("session_id", "resource-underscore"),
        kv("gen_ai.conversation.id", "resource-gen-ai"),
    ];

    let all_signal = vec![
        kv("session.id", "signal-dot"),
        kv("session_id", "signal-underscore"),
        kv("gen_ai.conversation.id", "signal-gen-ai"),
    ];
    assert_eq!(
        normalize_attributes(&resource, &all_signal)
            .ai_session_id
            .as_deref(),
        Some("signal-dot")
    );

    let signal_underscore = vec![
        kv("session_id", "signal-underscore"),
        kv("gen_ai.conversation.id", "signal-gen-ai"),
    ];
    assert_eq!(
        normalize_attributes(&resource, &signal_underscore)
            .ai_session_id
            .as_deref(),
        Some("signal-underscore")
    );

    let signal_gen_ai = vec![kv("gen_ai.conversation.id", "signal-gen-ai")];
    assert_eq!(
        normalize_attributes(&resource, &signal_gen_ai)
            .ai_session_id
            .as_deref(),
        Some("signal-gen-ai")
    );

    assert_eq!(
        normalize_attributes(&resource, &[])
            .ai_session_id
            .as_deref(),
        Some("resource-dot")
    );
    assert_eq!(
        normalize_attributes(&resource[1..], &[])
            .ai_session_id
            .as_deref(),
        Some("resource-underscore")
    );
    assert_eq!(
        normalize_attributes(&resource[2..], &[])
            .ai_session_id
            .as_deref(),
        Some("resource-gen-ai")
    );
}

#[test]
fn project_path_precedence_prefers_signal_then_contract_key_order() {
    let resource = vec![
        kv("project.path", "/resource/project"),
        kv("codebase.root_path", "/resource/root"),
        kv("session.cwd", "/resource/cwd"),
    ];
    let signal = vec![
        kv("codebase.root_path", "/signal/root"),
        kv("session.cwd", "/signal/cwd"),
    ];
    assert_eq!(
        normalize_attributes(&resource, &signal)
            .ai_project
            .as_deref(),
        Some("/signal/root")
    );
    assert_eq!(
        normalize_attributes(&resource, &[]).ai_project.as_deref(),
        Some("/resource/project")
    );
    assert_eq!(
        normalize_attributes(&resource[1..], &[])
            .ai_project
            .as_deref(),
        Some("/resource/root")
    );
}

#[test]
fn tool_precedence_covers_explicit_agent_service_and_unknown_service() {
    let resource = vec![
        kv("service.name", "gemini-transcript"),
        kv("gen_ai.agent.name", "claude-code"),
    ];
    let explicit = vec![kv("ai.tool", "codex")];
    assert_eq!(
        normalize_attributes(&resource, &explicit)
            .ai_tool
            .as_deref(),
        Some("codex")
    );
    assert_eq!(
        normalize_attributes(&resource, &[]).ai_tool.as_deref(),
        Some("claude")
    );

    let known_service = vec![kv("service.name", "claude-code")];
    assert_eq!(
        normalize_attributes(&known_service, &[]).ai_tool.as_deref(),
        Some("claude")
    );

    let unknown_service = vec![kv("service.name", "Acme-Agent")];
    assert_eq!(
        normalize_attributes(&unknown_service, &[])
            .ai_tool
            .as_deref(),
        Some("unknown:acme-agent")
    );
}

#[test]
fn log_tool_compatibility_remains_explicit_only() {
    let service_only = vec![kv("service.name", "claude-code")];
    let normalized = normalize_attributes(&service_only, &[]);
    assert_eq!(normalized.ai_tool.as_deref(), Some("claude"));
    assert_eq!(normalized.log_ai_tool(), None);

    let explicit = vec![kv("ai.tool", "CLAUDE")];
    let normalized = normalize_attributes(&service_only, &explicit);
    assert_eq!(normalized.ai_tool.as_deref(), Some("claude"));
    assert_eq!(normalized.log_ai_tool().as_deref(), Some("claude"));

    let unknown_explicit = vec![kv("ai.tool", "future-agent")];
    let normalized = normalize_attributes(&service_only, &unknown_explicit);
    assert_eq!(normalized.ai_tool.as_deref(), Some("unknown:future-agent"));
    assert_eq!(normalized.log_ai_tool(), None);
}

#[test]
fn otlp_provider_aliases_use_the_scanner_registry() {
    for (alias, expected) in [
        ("claude-transcript", "claude"),
        ("openai-codex", "codex"),
        ("gemini-cli", "gemini"),
    ] {
        let explicit = vec![kv("ai.tool", alias)];
        let normalized = normalize_attributes(&[], &explicit);
        assert_eq!(normalized.ai_tool.as_deref(), Some(expected));
        assert_eq!(normalized.log_ai_tool().as_deref(), Some(expected));
    }
}

#[test]
fn unknown_attributes_are_retained_and_sensitive_values_remain_redacted() {
    let resource = vec![
        kv("host.name", "devhost"),
        kv("custom.resource", "kept-resource"),
    ];
    let signal = vec![
        kv("custom.signal", "kept-signal"),
        kv("Authorization", "Bearer secret"),
    ];
    let normalized = normalize_attributes(&resource, &signal);

    assert_eq!(normalized.host_name, "devhost");
    assert_eq!(
        normalized.resource_attributes["custom.resource"],
        "kept-resource"
    );
    assert_eq!(normalized.signal_attributes["custom.signal"], "kept-signal");
    assert_eq!(normalized.signal_attributes["Authorization"], "[REDACTED]");
}

#[test]
fn provider_identity_bounds_match_existing_log_limits() {
    let resource = vec![
        kv("session.id", &"s".repeat(MAX_SESSION_ID_BYTES + 1)),
        kv("project.path", &"p".repeat(MAX_PROJECT_PATH_BYTES + 1)),
        kv("service.name", &"t".repeat(MAX_TOOL_BYTES + 1)),
    ];
    let normalized = normalize_attributes(&resource, &[]);
    assert_eq!(normalized.ai_session_id, None);
    assert_eq!(normalized.ai_project, None);
    assert_eq!(normalized.ai_tool, None);
}

#[test]
fn unknown_tool_normalization_is_unicode_safe_idempotent_and_total_length_bounded() {
    let unicode = vec![kv("service.name", "ÜBER-Agent")];
    assert_eq!(
        normalize_attributes(&unicode, &[]).ai_tool.as_deref(),
        Some("unknown:über-agent")
    );

    let already_unknown = vec![kv("service.name", "unknown:Future-Agent")];
    assert_eq!(
        normalize_attributes(&already_unknown, &[])
            .ai_tool
            .as_deref(),
        Some("unknown:future-agent")
    );

    let too_long_unknown = vec![kv(
        "service.name",
        &"x".repeat(MAX_TOOL_BYTES - "unknown:".len() + 1),
    )];
    assert_eq!(normalize_attributes(&too_long_unknown, &[]).ai_tool, None);
}

#[test]
fn shared_signal_attributes_support_256_fields_while_log_view_stays_128_compatible() {
    let signal = (0..200)
        .map(|index| kv(&format!("custom.{index:03}"), "value"))
        .collect::<Vec<_>>();
    let normalized = normalize_attributes(&[], &signal);
    let full = normalized.signal_attributes.as_object().unwrap();
    let legacy = normalized.legacy_log_signal_attributes.as_object().unwrap();

    assert_eq!(full.len(), 200);
    assert_eq!(legacy.len(), MAX_METADATA_OBJECT_FIELDS);
    assert_eq!(legacy["_omitted_fields"], 73);
}
