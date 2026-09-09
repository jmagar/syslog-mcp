use super::*;
use serde_json::json;

#[test]
fn extracts_top_level_hook_success_attachment() {
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookName": "format-on-save",
            "hookEvent": "PostToolUse",
            "command": "cargo fmt",
            "exitCode": 0,
            "durationMs": 123,
            "stdout": "formatted 3 files",
            "stderr": ""
        }
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.hook_event, "PostToolUse");
    assert_eq!(event.hook_name.as_deref(), Some("format-on-save"));
    assert_eq!(event.hook_command.as_deref(), Some("cargo fmt"));
    assert_eq!(event.status, HookStatus::Success);
    assert_eq!(event.exit_code, Some(0));
    assert_eq!(event.duration_ms, Some(123));
    assert_eq!(event.stdout_preview.as_deref(), Some("formatted 3 files"));
    assert_eq!(event.stderr_preview, None);
    assert_eq!(event.evidence_kind, HookEvidenceKind::RuntimeTranscript);
}

#[test]
fn extracts_nested_message_attachment() {
    let value = json!({
        "message": {
            "attachment": {
                "type": "hook_failure",
                "hookName": "lint",
                "hookEvent": "PreToolUse",
                "exitCode": 1,
                "stderr": "lint failed"
            }
        }
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].hook_event, "PreToolUse");
    assert_eq!(events[0].status, HookStatus::Failed);
    assert_eq!(events[0].exit_code, Some(1));
    assert_eq!(events[0].stderr_preview.as_deref(), Some("lint failed"));
}

#[test]
fn extracts_attachments_array_multiple_hooks() {
    let value = json!({
        "attachments": [
            {"type": "hook_success", "hookName": "a", "hookEvent": "SessionStart"},
            {"type": "not_a_hook", "hookName": "ignored"},
            {"type": "hook_blocked", "hookName": "b", "hookEvent": "PreToolUse"}
        ]
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].hook_name.as_deref(), Some("a"));
    assert_eq!(events[0].status, HookStatus::Success);
    assert_eq!(events[1].hook_name.as_deref(), Some("b"));
    assert_eq!(events[1].status, HookStatus::Blocked);
}

#[test]
fn emits_nothing_when_no_hook_attachment() {
    let value = json!({"attachment": {"type": "image", "path": "/tmp/x.png"}});
    assert!(extract_claude_hook_events(&value).is_empty());
    let no_attach = json!({"content": "just chatting"});
    assert!(extract_claude_hook_events(&no_attach).is_empty());
}

#[test]
fn unknown_hook_variant_maps_to_unknown_status_not_panic() {
    let value = json!({
        "attachment": {"type": "hook_weird_new_variant", "hookName": "x", "hookEvent": "Custom"}
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, HookStatus::Unknown);
}

#[test]
fn error_and_timeout_variants_map_to_error_status() {
    for t in [
        "hook_error",
        "hook_timeout",
        "hook_parse_error",
        "hook_non_blocking_error",
    ] {
        let value = json!({"attachment": {"type": t, "hookEvent": "PostToolUse"}});
        let events = extract_claude_hook_events(&value);
        assert_eq!(events.len(), 1, "variant {t}");
        assert_eq!(events[0].status, HookStatus::Error, "variant {t}");
    }
}

#[test]
fn extracts_async_hook_response_and_derives_status_from_exit_code() {
    let value = json!({
        "attachment": {
            "type": "async_hook_response",
            "hookName": "audit",
            "hookEvent": "PostToolUse",
            "exitCode": 2,
            "response": "async response",
            "stderr": "failed"
        }
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, HookStatus::Failed);
    assert_eq!(events[0].hook_name.as_deref(), Some("audit"));
    assert_eq!(events[0].stdout_preview.as_deref(), Some("async response"));
}

#[test]
fn falls_back_to_type_suffix_when_hook_event_missing() {
    let value = json!({"attachment": {"type": "hook_success", "hookName": "x"}});
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].hook_event, "success");
}

#[test]
fn content_field_used_as_stdout_fallback() {
    let value = json!({
        "attachment": {"type": "hook_success", "hookEvent": "Stop", "content": "hook output text"}
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(
        events[0].stdout_preview.as_deref(),
        Some("hook output text")
    );
}

#[test]
fn persisted_output_path_extracted() {
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "persistedOutputPath": "/data/hook-out/abc123.txt"
        }
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(
        events[0].persisted_output_path.as_deref(),
        Some("/data/hook-out/abc123.txt")
    );
}

#[test]
fn stdout_preview_is_redacted() {
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "stdout": "exporting TOKEN=FAKE_NOT_A_REAL_SECRET done"
        }
    });
    let events = extract_claude_hook_events(&value);
    let preview = events[0].stdout_preview.as_deref().unwrap();
    assert!(preview.contains("[REDACTED]"), "preview: {preview}");
    assert!(!preview.contains("NOT_A_REAL_SECRET"), "preview: {preview}");
}

#[test]
fn stdout_preview_secrets_shaped_as_json_are_redacted() {
    // Eng review fix: redact_secrets tokenizes on whitespace, so a secret
    // carried as a JSON value (e.g. {"api_key":"sk-..."}) serializes to a
    // single whitespace-free token that doesn't start with a known prefix
    // and was never caught. A hook script echoing a JSON config/API
    // response is a realistic real-world shape for stdout.
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "stdout": "{\"GITHUB_TOKEN\":\"ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000\"}"
        }
    });
    let events = extract_claude_hook_events(&value);
    let preview = events[0].stdout_preview.as_deref().unwrap();
    assert!(!preview.contains("ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000"));
    assert!(preview.contains("[REDACTED]"));
}

#[test]
fn stdout_preview_generic_credentials_are_redacted_by_key_recursively() {
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "stdout": "{\"outer\":{\"credential\":\"plain-value\"},\"private_key\":\"plain-key\",\"safe\":\"visible\"}"
        }
    });
    let preview = extract_claude_hook_events(&value)[0]
        .stdout_preview
        .as_deref()
        .unwrap()
        .to_string();
    assert!(!preview.contains("plain-value"));
    assert!(!preview.contains("plain-key"));
    assert!(preview.contains("visible"));
    assert_eq!(preview.matches("[REDACTED]").count(), 2);
}

#[test]
fn stdout_preview_bare_json_string_secret_is_redacted() {
    // Eng review fix (adversarial re-verify): stdout that is itself a bare
    // JSON string (quotes included, not wrapped in an object/array) parses
    // successfully but isn't Object/Array, so it previously fell through
    // to redact_secrets on the STILL-QUOTED text — the leading `"` broke
    // every looks_secretish prefix check, letting the secret through.
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "stdout": "\"ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000\""
        }
    });
    let events = extract_claude_hook_events(&value);
    let preview = events[0].stdout_preview.as_deref().unwrap();
    assert!(!preview.contains("ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000"));
    assert!(preview.contains("[REDACTED]"));
}

#[test]
fn hook_command_secrets_are_redacted() {
    // Eng review fix: hook_command previously went through normalize_field
    // (trim/control-char-reject/clamp only) with zero redaction, unlike
    // stdout/stderr — a configured hook command embedding a credential
    // (e.g. `curl -H "Authorization: Bearer sk-..."`) was stored and
    // surfaced verbatim.
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "command": "curl -H Authorization: sk-FAKE_TEST_TOKEN_DO_NOT_USE_000000000 https://api.example.com"
        }
    });
    let events = extract_claude_hook_events(&value);
    let command = events[0].hook_command.as_deref().unwrap();
    assert!(!command.contains("sk-FAKE_TEST_TOKEN_DO_NOT_USE_000000000"));
    assert!(command.contains("[REDACTED]"));
}

#[test]
fn control_chars_in_hook_command_reject_the_event_not_get_laundered() {
    // Eng review fix (adversarial re-verify): redacting hook_command
    // BEFORE the control-char check ran redact_secrets's
    // split_whitespace().join(" ") over the raw text first, which treats
    // tab (and other whitespace-class control chars) as a splitter and
    // re-emits a plain space — silently laundering the control character
    // out before normalize_field's char::is_control() check ever saw it,
    // so a command that should be rejected was instead accepted with the
    // control char quietly gone. The check must run on the RAW text.
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "command": "echo\tbad"
        }
    });
    assert!(extract_claude_hook_events(&value).is_empty());
}

#[test]
fn control_chars_in_hook_event_reject_the_event() {
    // Newline is a control char; hook_event with control chars is dropped.
    let value = json!({
        "attachment": {"type": "hook_success", "hookEvent": "Post\u{001b}[31mToolUse"}
    });
    // hookEvent has an ANSI escape → the whole event is rejected by normalized().
    assert!(extract_claude_hook_events(&value).is_empty());
}

#[test]
fn control_chars_in_stdout_are_sanitized_not_rejected() {
    let value = json!({
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PostToolUse",
            "stdout": "line1\nline2\ttabbed"
        }
    });
    let events = extract_claude_hook_events(&value);
    assert_eq!(events.len(), 1);
    let preview = events[0].stdout_preview.as_deref().unwrap();
    assert!(!preview.contains('\n'), "preview: {preview:?}");
    assert!(!preview.contains('\t'), "preview: {preview:?}");
    assert!(preview.contains("line1"));
    assert!(preview.contains("line2"));
}

#[test]
fn oversized_command_is_clamped() {
    let long_cmd = "x".repeat(5000);
    let value = json!({
        "attachment": {"type": "hook_success", "hookEvent": "PostToolUse", "command": long_cmd}
    });
    let events = extract_claude_hook_events(&value);
    let cmd = events[0].hook_command.as_deref().unwrap();
    assert_eq!(cmd.chars().count(), MAX_HOOK_COMMAND_CHARS);
}

#[test]
fn evidence_kind_as_str_round_trips() {
    assert_eq!(
        HookEvidenceKind::RuntimeTranscript.as_str(),
        "runtime_transcript"
    );
    assert_eq!(
        HookEvidenceKind::ConfigInventory.as_str(),
        "config_inventory"
    );
    assert_eq!(
        HookEvidenceKind::TrustedHashState.as_str(),
        "trusted_hash_state"
    );
    assert_eq!(HookEvidenceKind::LogCorrelation.as_str(), "log_correlation");
    assert_eq!(
        HookEvidenceKind::SideEffectInference.as_str(),
        "side_effect_inference"
    );
}

#[test]
fn status_as_str_round_trips() {
    assert_eq!(HookStatus::Success.as_str(), "success");
    assert_eq!(HookStatus::Failed.as_str(), "failed");
    assert_eq!(HookStatus::Blocked.as_str(), "blocked");
    assert_eq!(HookStatus::Error.as_str(), "error");
    assert_eq!(HookStatus::Unknown.as_str(), "unknown");
}
