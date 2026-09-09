use std::path::Path;

use super::*;

#[test]
fn parse_line_extracts_top_level_content_and_session_id() {
    let line = r#"{"sessionId":"claude-1","timestamp":"2026-05-11T00:00:00Z","content":"hello"}"#;

    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 0)
        .unwrap()
        .expect("content should produce a transcript record");

    assert_eq!(parsed.message, "hello");
    assert_eq!(parsed.session_id.as_deref(), Some("claude-1"));
    assert_eq!(parsed.timestamp.as_deref(), Some("2026-05-11T00:00:00Z"));
    assert!(parsed.record_key.starts_with("line:0:hash:"));
    assert!(parsed.ai_project.is_none());
}

#[test]
fn parse_line_extracts_nested_message_content() {
    let line = r#"{"session":{"id":"nested-1"},"message":{"content":"nested text"}}"#;

    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 0)
        .unwrap()
        .expect("nested message content should produce a transcript record");

    assert_eq!(parsed.message, "nested text");
    assert_eq!(parsed.session_id.as_deref(), Some("nested-1"));
}

#[test]
fn parse_line_joins_string_content_arrays() {
    let line = r#"{"session_id":"claude-array","content":["first","second",{"ignored":true}]}"#;

    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 0)
        .unwrap()
        .expect("string array content should produce a transcript record");

    assert_eq!(parsed.message, "first second");
    assert_eq!(parsed.session_id.as_deref(), Some("claude-array"));
}

#[test]
fn parse_line_extracts_project_and_object_array_content() {
    let line = r#"{"session_id":"claude-array","cwd":"/work/project","content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]}"#;

    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 0)
        .unwrap()
        .expect("object array content should produce a transcript record");

    assert_eq!(parsed.message, "first second");
    assert_eq!(parsed.ai_project.as_deref(), Some("/work/project"));
}

#[test]
fn parse_line_falls_back_to_path_as_session_id() {
    let path = Path::new("/tmp/no-session.jsonl");
    let line = r#"{"content":"hello without session"}"#;

    let parsed = parse_line(line, path, 0)
        .unwrap()
        .expect("content should produce a transcript record");

    assert_eq!(parsed.session_id.as_deref(), Some("/tmp/no-session.jsonl"));
}

#[test]
fn parse_line_ignores_records_without_message_content() {
    let line = r#"{"sessionId":"claude-1","timestamp":"2026-05-11T00:00:00Z"}"#;

    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 0).unwrap();

    assert!(parsed.is_none());
}

#[test]
fn parse_line_preserves_custom_title_as_metadata_without_treating_it_as_content() {
    let line = r#"{"type":"custom-title","sessionId":"claude-1","customTitle":"Parser fidelity"}"#;
    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 4)
        .unwrap()
        .expect("custom title is a session metadata observation");

    assert!(parsed.message.is_empty());
    assert_eq!(
        parsed.session_metadata.title.as_deref(),
        Some("Parser fidelity")
    );
    assert_eq!(
        parsed.session_metadata.title_provenance.as_deref(),
        Some("claude.custom-title")
    );
    assert_eq!(
        parsed.session_metadata.source_format.as_deref(),
        Some("claude_project_jsonl")
    );
}

#[test]
fn parse_line_keeps_agent_name_distinct_from_title() {
    let line = r#"{"type":"agent-name","sessionId":"claude-1","agentName":"Curie"}"#;
    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 5)
        .unwrap()
        .unwrap();

    assert_eq!(parsed.session_metadata.agent_name.as_deref(), Some("Curie"));
    assert!(parsed.session_metadata.title.is_none());
}

#[test]
fn parse_line_extracts_bounded_stable_claude_metadata() {
    let line = r#"{"type":"assistant","sessionId":"claude-1","cwd":"/work","gitBranch":"feature/x","entrypoint":"cli","effort":"high","version":"2.1.0","message":{"role":"assistant","model":"claude-opus","content":"done"}}"#;
    let parsed = parse_line(line, Path::new("/tmp/session.jsonl"), 6)
        .unwrap()
        .unwrap();

    assert_eq!(
        parsed.session_metadata.model.as_deref(),
        Some("claude-opus")
    );
    assert_eq!(
        parsed.session_metadata.git_branch.as_deref(),
        Some("feature/x")
    );
    assert_eq!(parsed.session_metadata.entrypoint.as_deref(), Some("cli"));
    assert_eq!(parsed.session_metadata.effort.as_deref(), Some("high"));
    assert_eq!(
        parsed.session_metadata.client_version.as_deref(),
        Some("2.1.0")
    );
}

#[test]
fn session_metadata_rejects_control_characters_and_clamps_length() {
    let long_title = "x".repeat(MAX_SESSION_METADATA_CHARS + 20);
    let value = serde_json::json!({
        "type": "custom-title",
        "sessionId": "claude-1",
        "customTitle": long_title,
        "gitBranch": "bad\nbranch"
    });
    let parsed = parse_line(&value.to_string(), Path::new("/tmp/session.jsonl"), 7)
        .unwrap()
        .unwrap();

    assert_eq!(
        parsed.session_metadata.title.unwrap().chars().count(),
        MAX_SESSION_METADATA_CHARS
    );
    assert!(parsed.session_metadata.git_branch.is_none());
}

#[test]
fn parse_line_carries_the_raw_parsed_value() {
    let line = r#"{"sessionId":"sess-1","content":"hi","attributionSkill":"cortex-troubleshoot"}"#;
    let parsed = parse_line(line, Path::new("/tmp/x.jsonl"), 0)
        .unwrap()
        .unwrap();
    let raw = parsed
        .raw_value
        .expect("claude parse_line must carry raw_value");
    assert_eq!(
        raw.get("attributionSkill").and_then(|v| v.as_str()),
        Some("cortex-troubleshoot")
    );
}
