use std::path::Path;

use serde_json::json;

use super::*;

const DESKTOP_PATH: &str = "/home/dev/.gemini/antigravity/brain/0a34e49d-fa05-40ca-90f7-df9f9265bf8c/.system_generated/logs/transcript.jsonl";

#[test]
fn recognizes_only_bounded_system_generated_transcript_path() {
    assert!(is_transcript_file(Path::new(DESKTOP_PATH)));
    assert!(!is_transcript_file(Path::new(
        "/home/dev/.gemini/antigravity/brain/id/transcript.jsonl"
    )));
    assert!(!is_transcript_file(Path::new(
        "/home/dev/.gemini/antigravity/brain/.hidden/.system_generated/logs/transcript.jsonl"
    )));
    assert!(!is_transcript_file(Path::new(
        "/tmp/brain/session/.system_generated/logs/transcript.jsonl"
    )));
}

#[test]
fn derives_only_safe_brain_session_ids() {
    assert_eq!(
        session_id_from_path(Path::new(DESKTOP_PATH)).as_deref(),
        Some("0a34e49d-fa05-40ca-90f7-df9f9265bf8c")
    );
    assert!(
        session_id_from_path(Path::new(
            "/home/dev/.gemini/antigravity/brain/bad.id/.system_generated/logs/transcript.jsonl"
        ))
        .is_none()
    );
}

#[test]
fn parses_typed_records_and_tool_calls_without_flattening_arguments() {
    let raw = concat!(
        r#"{"step_index":0,"source":"USER","type":"USER_INPUT","status":"DONE","created_at":"2026-08-29T14:32:00Z","content":"inspect this"}"#,
        "\n",
        r#"{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-08-29T14:32:01Z","thinking":"checking","tool_calls":[{"name":"run_command","args":{"Cwd":"/workspace"}}]}"#,
        "\n",
    );
    let parsed = parse_file(raw, Path::new(DESKTOP_PATH)).unwrap();

    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.records[0].transcript.event_kind, "user");
    assert_eq!(
        parsed.records[0].transcript.ai_project.as_deref(),
        Some("antigravity://desktop")
    );
    assert_eq!(parsed.records[1].transcript.event_kind, "tool");
    assert_eq!(parsed.records[1].tool_calls[0].name, "run_command");
    assert_eq!(
        parsed.records[1].tool_calls[0].arguments,
        json!({"Cwd":"/workspace"})
    );
    assert_eq!(
        parsed.records[1]
            .transcript
            .session_metadata
            .source_format
            .as_deref(),
        Some("antigravity-transcript-jsonl")
    );
    assert!(parsed.records[1].transcript.raw_value.is_some());
}

#[test]
fn retains_tool_only_rows_and_counts_empty_rows() {
    let raw = concat!(
        r#"{"step_index":2,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"name":"read_file","args":{}}]}"#,
        "\n",
        r#"{"step_index":3,"source":"SYSTEM","type":"CHECKPOINT","status":"DONE"}"#,
    );
    let parsed = parse_file(raw, Path::new(DESKTOP_PATH)).unwrap();

    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].transcript.message, "tool call: read_file");
    assert_eq!(parsed.skipped_empty, 1);
}

#[test]
fn identifies_cli_source_and_reports_malformed_line_number() {
    let cli = Path::new(
        "/home/dev/.gemini/antigravity-cli/brain/session_1/.system_generated/logs/transcript.jsonl",
    );
    let parsed = parse_file(r#"{"step_index":0,"source":"USER","content":"hello"}"#, cli).unwrap();
    assert_eq!(
        parsed.records[0]
            .transcript
            .session_metadata
            .source
            .as_deref(),
        Some("antigravity-cli")
    );
    assert_eq!(
        parsed.records[0].transcript.ai_project.as_deref(),
        Some("antigravity://cli")
    );

    let error = parse_file("{}\n{broken}\n", cli).unwrap_err();
    assert!(error.to_string().contains("line 2"));
}

#[test]
fn same_step_records_have_distinct_stable_keys() {
    let raw = concat!(
        r#"{"step_index":4,"source":"MODEL","content":"first"}"#,
        "\n",
        r#"{"step_index":4,"source":"MODEL","content":"second"}"#,
    );

    let parsed = parse_file(raw, Path::new(DESKTOP_PATH)).unwrap();
    assert_eq!(parsed.records.len(), 2);
    assert!(
        parsed.records[0]
            .transcript
            .record_key
            .starts_with("step:4:hash:")
    );
    assert!(
        parsed.records[1]
            .transcript
            .record_key
            .starts_with("step:4:hash:")
    );
    assert_ne!(
        parsed.records[0].transcript.record_key,
        parsed.records[1].transcript.record_key
    );
}

#[test]
fn single_line_parser_preserves_caller_line_number_for_identical_records() {
    let line = r#"{"source":"MODEL","content":"same status"}"#;
    let first = parse_line(line, Path::new(DESKTOP_PATH), 7)
        .unwrap()
        .unwrap();
    let second = parse_line(line, Path::new(DESKTOP_PATH), 8)
        .unwrap()
        .unwrap();

    assert!(first.record_key.starts_with("line:7:hash:"));
    assert!(second.record_key.starts_with("line:8:hash:"));
    assert_ne!(first.record_key, second.record_key);
}
