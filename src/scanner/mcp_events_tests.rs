use super::*;

#[test]
fn antigravity_tool_calls_preserve_arguments_and_mcp_classification() {
    let value = serde_json::json!({
        "step_index": 7,
        "status": "completed",
        "tool_calls": [{
            "id": "call-7",
            "name": "mcp__cortex__search_sessions",
            "args": {"query": "timeout"}
        }]
    });
    let events = extract_antigravity_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].call_id, "call-7");
    assert_eq!(events[0].mcp_server.as_deref(), Some("cortex"));
    assert_eq!(events[0].mcp_tool.as_deref(), Some("search_sessions"));
    assert_eq!(
        events[0].arguments_json.as_deref(),
        Some("{\"query\":\"timeout\"}")
    );
    assert_eq!(events[0].status.as_deref(), Some("completed"));
}

#[test]
fn antigravity_fallback_call_ids_distinguish_records_without_steps() {
    let first = json!({"content":"first","tool_calls":[{"name":"run_command","args":{}}]});
    let second = json!({"content":"second","tool_calls":[{"name":"run_command","args":{}}]});
    let first_id = extract_antigravity_mcp_events(&first)[0].call_id.clone();
    let second_id = extract_antigravity_mcp_events(&second)[0].call_id.clone();
    assert_ne!(first_id, second_id);
    assert_eq!(
        first_id,
        extract_antigravity_mcp_events(&first)[0].call_id,
        "fallback identity must be replay-stable"
    );
}
use serde_json::json;

#[test]
fn rejects_tool_name_containing_control_characters() {
    // Mirrors ExtractedSkillEvent's control-character guard (eng review
    // Fix 8 there): tool_name/mcp_server/mcp_tool are printed verbatim by
    // the CLI's println!-based printer, so a crafted transcript embedding
    // an ANSI escape sequence in the tool name must be rejected, not
    // silently stored.
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "\u{1b}[2J\u{1b}[31mFAKE",
                    "input": {}
                }
            ]
        }
    });
    assert!(extract_claude_mcp_events(&value).is_empty());
}

#[test]
fn rejects_tool_name_containing_embedded_newline() {
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "Bash\nFAKE APPROVED LINE",
                    "input": {}
                }
            ]
        }
    });
    assert!(extract_claude_mcp_events(&value).is_empty());
}

#[test]
fn rejects_mcp_style_name_containing_control_characters() {
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "mcp__lumen__\u{1b}[31msearch",
                    "input": {}
                }
            ]
        }
    });
    assert!(extract_claude_mcp_events(&value).is_empty());
}

#[test]
fn codex_rejects_tool_name_containing_control_characters() {
    let value = json!({
        "timestamp": "2025-11-15T03:32:12.634Z",
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "name": "\u{1b}[2J\u{1b}[31mFAKE",
            "arguments": "{}",
            "call_id": "call_1"
        }
    });
    assert!(extract_codex_mcp_events(&value).is_empty());
}

#[test]
fn claude_tool_use_builtin_extracts_call_with_no_mcp_classification() {
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_01KeJaqayCJ1gCMx955pnF5u",
                    "name": "Bash",
                    "input": {"command": "ls"}
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.call_id, "toolu_01KeJaqayCJ1gCMx955pnF5u");
    assert_eq!(event.tool_name, "Bash");
    assert_eq!(event.mcp_server, None);
    assert_eq!(event.mcp_tool, None);
    assert_eq!(event.event_kind, McpEventKind::Call);
    assert!(event.arguments_json.is_some());
}

#[test]
fn claude_tool_use_mcp_style_name_classifies_server_and_tool() {
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_abc",
                    "name": "mcp__lumen__semantic_search",
                    "input": {"query": "foo"}
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].mcp_server.as_deref(), Some("lumen"));
    assert_eq!(events[0].mcp_tool.as_deref(), Some("semantic_search"));
}

#[test]
fn claude_tool_result_string_content_links_via_tool_use_id() {
    let value = json!({
        "message": {
            "content": [
                {
                    "tool_use_id": "toolu_01KeJaqayCJ1gCMx955pnF5u",
                    "type": "tool_result",
                    "content": "some output text",
                    "is_error": false
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.call_id, "toolu_01KeJaqayCJ1gCMx955pnF5u");
    assert_eq!(event.event_kind, McpEventKind::Result);
    assert_eq!(event.is_error, Some(false));
    assert_eq!(event.status.as_deref(), Some("ok"));
    assert_eq!(event.output_preview.as_deref(), Some("some output text"));
    assert!(event.error_text.is_none());
}

#[test]
fn claude_tool_result_error_populates_error_text_not_output_preview() {
    let value = json!({
        "message": {
            "content": [
                {
                    "tool_use_id": "toolu_xyz",
                    "type": "tool_result",
                    "content": "permission denied",
                    "is_error": true
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].is_error, Some(true));
    assert_eq!(events[0].status.as_deref(), Some("error"));
    assert_eq!(events[0].error_text.as_deref(), Some("permission denied"));
    assert!(events[0].output_preview.is_none());
}

#[test]
fn claude_tool_result_array_content_joins_text_items() {
    let value = json!({
        "message": {
            "content": [
                {
                    "tool_use_id": "toolu_arr",
                    "type": "tool_result",
                    "content": [
                        {"type": "text", "text": "line one"},
                        {"type": "text", "text": "line two"}
                    ],
                    "is_error": false
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].output_preview.as_deref(),
        Some("line one line two")
    );
}

#[test]
fn claude_multiple_tool_use_blocks_produce_multiple_events() {
    let value = json!({
        "message": {
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}},
                {"type": "tool_use", "id": "toolu_2", "name": "Bash", "input": {}}
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 2);
}

#[test]
fn claude_no_content_array_returns_empty() {
    let value = json!({"message": {"role": "user", "content": "hello"}});
    assert!(extract_claude_mcp_events(&value).is_empty());
}

#[test]
fn claude_secrets_in_arguments_are_redacted() {
    // redact_secrets splits on whitespace, so a token embedded in a
    // whitespace-separated value (e.g. a command string) is what actually
    // gets caught in practice — mirrors how `LlmRunner::sanitize_error` and
    // the skill-assessment prompt builder rely on the same helper.
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_secret",
                    "name": "mcp__gh__auth",
                    "input": {"command": "curl -H Authorization: ghp_FAKE_TEST_TOKEN_DO_NOT_USE_00000000 https://api.github.com"}
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let args = events[0].arguments_json.as_deref().unwrap();
    assert!(!args.contains("ghp_FAKE_TEST_TOKEN_DO_NOT_USE_00000000"));
    assert!(args.contains("[REDACTED]"));
}

#[test]
fn claude_secrets_shaped_as_json_values_are_redacted() {
    // Eng review fix (security-sentinel): a secret carried as a JSON
    // *value* (e.g. {"api_key":"sk-..."}) serializes to a single
    // whitespace-free token that doesn't start with a known prefix, so
    // whole-string redact_secrets misses it entirely. bounded_preview
    // must tree-walk JSON object/array inputs and redact each string
    // leaf individually.
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_secret",
                    "name": "mcp__gh__auth",
                    "input": {"api_key": "sk-FAKE_TEST_TOKEN_DO_NOT_USE_00000000000"}
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let args = events[0].arguments_json.as_deref().unwrap();
    assert!(!args.contains("sk-FAKE_TEST_TOKEN_DO_NOT_USE_00000000000"));
    assert!(args.contains("[REDACTED]"));
}

#[test]
fn claude_generic_credentials_are_redacted_by_key_recursively() {
    let value = json!({
        "message": {"content": [{
            "type": "tool_use",
            "id": "toolu_generic_secret",
            "name": "configure",
            "input": {
                "nested": {"access_token": "ordinary-looking-value"},
                "client-secret": "another-ordinary-value",
                "credentials": {"user": "alice"},
                "safe": "retained"
            }
        }]}
    });
    let args = extract_claude_mcp_events(&value)[0]
        .arguments_json
        .as_deref()
        .unwrap()
        .to_string();
    assert!(!args.contains("ordinary-looking-value"));
    assert!(!args.contains("another-ordinary-value"));
    assert!(!args.contains("alice"));
    assert!(args.contains("\"safe\":\"retained\""));
    assert_eq!(args.matches("[REDACTED]").count(), 3);
}

#[test]
fn authorization_credentials_are_redacted_by_key_recursively() {
    let value = json!({
        "message": {"content": [{
            "type": "tool_use",
            "id": "toolu_authorization_secret",
            "name": "request",
            "input": {
                "authorization": "Bearer opaque-secret",
                "Proxy-Authorization": "Basic another-secret",
                "auth_token": "ordinary-auth-value",
                "bearerToken": "ordinary-bearer-value",
                "safe": "retained"
            }
        }]}
    });
    let events = extract_claude_mcp_events(&value);
    let args = events[0].arguments_json.as_deref().unwrap();

    for secret in [
        "opaque-secret",
        "another-secret",
        "ordinary-auth-value",
        "ordinary-bearer-value",
    ] {
        assert!(!args.contains(secret));
    }
    assert!(args.contains("\"safe\":\"retained\""));
    assert_eq!(args.matches("[REDACTED]").count(), 4);
}

#[test]
fn claude_bare_json_string_secret_in_arguments_is_redacted() {
    // Eng review fix (adversarial re-verify): a scalar `input` value that
    // is itself a bare JSON string (not wrapped in an object/array) parses
    // successfully but isn't Object/Array, so it previously fell through
    // to redact_secrets on the STILL-QUOTED text — the leading `"` broke
    // every looks_secretish prefix check, letting the secret through.
    let value = json!({
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_secret",
                    "name": "mcp__gh__auth",
                    "input": "sk-FAKE_TEST_TOKEN_DO_NOT_USE_00000000000"
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let args = events[0].arguments_json.as_deref().unwrap();
    assert!(!args.contains("sk-FAKE_TEST_TOKEN_DO_NOT_USE_00000000000"));
    assert!(args.contains("[REDACTED]"));
}

#[test]
fn claude_tool_result_secrets_shaped_as_json_are_redacted() {
    // Output/error text is just as likely to carry a JSON-shaped secret
    // as call arguments (e.g. a tool echoing back an API response).
    let value = json!({
        "message": {
            "content": [
                {
                    "tool_use_id": "toolu_secret",
                    "type": "tool_result",
                    "content": "{\"GITHUB_TOKEN\":\"ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000\"}",
                    "is_error": false
                }
            ]
        }
    });
    let events = extract_claude_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let preview = events[0].output_preview.as_deref().unwrap();
    assert!(!preview.contains("ghp_FAKE_TEST_TOKEN_DO_NOT_USE_0000000000"));
    assert!(preview.contains("[REDACTED]"));
}

#[test]
fn codex_function_call_extracts_call_event() {
    let value = json!({
        "timestamp": "2025-11-15T03:32:12.634Z",
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "name": "shell",
            "arguments": "{\"command\":[\"pwd\"]}",
            "call_id": "call_uQHXzobqXG53qZ0hpqMTGMmj"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.call_id, "call_uQHXzobqXG53qZ0hpqMTGMmj");
    assert_eq!(event.tool_name, "shell");
    assert_eq!(event.mcp_server, None);
    assert_eq!(event.event_kind, McpEventKind::Call);
    assert!(event.arguments_json.is_some());
}

#[test]
fn codex_custom_tool_call_extracts_generic_call_event() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "custom_tool_call",
            "name": "exec",
            "input": "{\"cmd\":\"pwd\"}",
            "call_id": "call_custom",
            "status": "completed"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.call_id, "call_custom");
    assert_eq!(event.tool_name, "exec");
    assert_eq!(event.mcp_server, None);
    assert_eq!(event.status.as_deref(), Some("completed"));
    assert!(event.arguments_json.is_some());
}

#[test]
fn codex_function_call_mcp_style_name_classifies() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "name": "mcp__happy__change_title",
            "arguments": "{\"title\":\"x\"}",
            "call_id": "call_w1nH5eCmzI3GAg4HpGnSzQwp"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].mcp_server.as_deref(), Some("happy"));
    assert_eq!(events[0].mcp_tool.as_deref(), Some("change_title"));
}

#[test]
fn codex_function_call_output_success_links_via_call_id() {
    let value = json!({
        "timestamp": "2025-11-15T03:32:12.635Z",
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "call_uQHXzobqXG53qZ0hpqMTGMmj",
            "output": "{\"output\":\"/compose/pulse\\n\",\"metadata\":{\"exit_code\":0,\"duration_seconds\":0.0}}"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.call_id, "call_uQHXzobqXG53qZ0hpqMTGMmj");
    assert_eq!(event.event_kind, McpEventKind::Result);
    assert_eq!(event.is_error, Some(false));
    assert_eq!(event.status.as_deref(), Some("0"));
    assert!(event.output_preview.is_some());
    assert!(event.error_text.is_none());
}

#[test]
fn codex_function_call_output_nonzero_exit_is_error() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "call_fail",
            "output": "{\"output\":\"permission denied\\n\",\"metadata\":{\"exit_code\":1}}"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].is_error, Some(true));
    assert!(events[0].error_text.is_some());
    assert!(events[0].output_preview.is_none());
}

#[test]
fn codex_function_call_output_plain_string_without_metadata() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "call_plain",
            "output": "plain text output, not json"
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].is_error, None);
    assert_eq!(
        events[0].output_preview.as_deref(),
        Some("plain text output, not json")
    );
}

#[test]
fn codex_custom_tool_call_output_extracts_only_text_blocks() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "custom_tool_call_output",
            "call_id": "call_custom",
            "output": [
                {"type": "text", "text": "first"},
                {"type": "image", "data": "large-unwanted-payload"},
                {"type": "text", "text": "second"}
            ]
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_kind, McpEventKind::Result);
    assert_eq!(events[0].output_preview.as_deref(), Some("first second"));
    assert!(
        !events[0]
            .output_preview
            .as_deref()
            .unwrap()
            .contains("large-unwanted-payload")
    );
}

#[test]
fn codex_custom_tool_output_is_bounded_before_projection() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "custom_tool_call_output",
            "call_id": "call_large",
            "output": [{"type":"text", "text":"x".repeat(MAX_RAW_OUTPUT_CHARS * 4)}]
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].output_preview.as_deref().unwrap().chars().count(),
        MAX_PREVIEW_CHARS
    );
}

#[test]
fn codex_turn_id_is_captured_when_present() {
    let value = json!({
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "name": "shell",
            "arguments": "{}",
            "call_id": "call_turn",
            "metadata": {"turn_id": "turn-42"}
        }
    });
    let events = extract_codex_mcp_events(&value);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-42"));
}

#[test]
fn codex_non_response_item_returns_empty() {
    let value = json!({"type": "session_meta", "payload": {}});
    assert!(extract_codex_mcp_events(&value).is_empty());
}

#[test]
fn codex_other_payload_types_return_empty() {
    let value = json!({
        "type": "response_item",
        "payload": {"type": "message", "content": "hi"}
    });
    assert!(extract_codex_mcp_events(&value).is_empty());
}

#[test]
fn classify_tool_name_rejects_malformed_mcp_prefix() {
    assert_eq!(classify_tool_name("mcp__onlyserver"), (None, None));
    assert_eq!(classify_tool_name("mcp____"), (None, None));
    assert_eq!(classify_tool_name("exec_command"), (None, None));
    assert_eq!(classify_tool_name("Bash"), (None, None));
}

#[test]
fn classify_tool_name_accepts_extra_double_underscore_segments() {
    // mcp__server__tool__extra -> split_once keeps tool as "tool__extra"
    let (server, tool) = classify_tool_name("mcp__labby__search__v2");
    assert_eq!(server.as_deref(), Some("labby"));
    assert_eq!(tool.as_deref(), Some("search__v2"));
}
