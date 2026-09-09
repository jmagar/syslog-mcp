use std::path::Path;

use super::*;
use rusqlite::Connection;

#[test]
fn parse_line_extracts_payload_content_items_and_project_from_arguments() {
    let line = r#"{"type":"response_item","payload":{"id":"item-1","content":[{"type":"output_text","text":"fixed parser"},{"content":"added test"}],"arguments":"{\"workdir\":\"/home/jmagar/workspace/cortex\"}","timestamp":"2026-05-11T00:00:00Z"}}"#;

    let parsed = parse_line(line, Path::new("/tmp/rollout-test.jsonl"), 0)
        .unwrap()
        .expect("content should produce a transcript record");

    assert_eq!(parsed.message, "fixed parser added test");
    assert_eq!(parsed.session_id.as_deref(), None);
    assert_eq!(parsed.timestamp.as_deref(), Some("2026-05-11T00:00:00Z"));
    assert_eq!(
        parsed.ai_project.as_deref(),
        Some("/home/jmagar/workspace/cortex")
    );
    assert_eq!(parsed.record_key, "id:item-1");
}

#[test]
fn parse_line_leaves_session_empty_when_session_metadata_is_missing() {
    let line = r#"{"timestamp":"2026-05-11T00:00:00Z","payload":{"text":"standalone text"}}"#;

    let parsed = parse_line(line, Path::new("/tmp/rollout-codex-123.jsonl"), 0)
        .unwrap()
        .expect("payload text should produce a transcript record");

    assert_eq!(parsed.message, "standalone text");
    assert_eq!(parsed.session_id.as_deref(), None);
    assert!(parsed.record_key.starts_with("line:0:hash:"));
}

#[test]
fn session_id_from_line_reads_session_meta_payload_id() {
    let line = r#"{"type":"session_meta","payload":{"id":"codex-1","cwd":"/tmp/project"}}"#;

    assert_eq!(session_id_from_line(line).as_deref(), Some("codex-1"));
}

#[test]
fn parse_line_preserves_session_meta_without_treating_it_as_content() {
    let line = r#"{"type":"session_meta","payload":{"id":"codex-1","cwd":"/tmp/project","originator":"codex_app","cli_version":"1.2.3","source":"vscode","thread_source":"user","model_provider":"openai","git":{"branch":"feature/x"}}}"#;

    let parsed = parse_line(line, Path::new("/tmp/rollout.jsonl"), 0)
        .unwrap()
        .expect("session_meta is a session metadata observation");

    assert!(parsed.message.is_empty());
    assert_eq!(
        parsed.session_metadata.model_provider.as_deref(),
        Some("openai")
    );
    assert_eq!(
        parsed.session_metadata.client_version.as_deref(),
        Some("1.2.3")
    );
    assert_eq!(
        parsed.session_metadata.git_branch.as_deref(),
        Some("feature/x")
    );
    assert_eq!(
        parsed.session_metadata.entrypoint.as_deref(),
        Some("codex_app")
    );
    assert_eq!(parsed.session_metadata.source.as_deref(), Some("vscode"));
    assert_eq!(
        parsed.session_metadata.thread_source.as_deref(),
        Some("user")
    );
    assert!(parsed.session_metadata.title.is_none());
}

#[test]
fn parse_line_preserves_turn_context_model_and_effort() {
    let line = r#"{"type":"turn_context","payload":{"turn_id":"turn-1","cwd":"/tmp/project","model":"gpt-5.6","effort":"high"}}"#;
    let parsed = parse_line(line, Path::new("/tmp/rollout.jsonl"), 1)
        .unwrap()
        .unwrap();

    assert!(parsed.message.is_empty());
    assert_eq!(parsed.session_metadata.model.as_deref(), Some("gpt-5.6"));
    assert_eq!(parsed.session_metadata.effort.as_deref(), Some("high"));
    assert_eq!(parsed.ai_project.as_deref(), Some("/tmp/project"));
}

#[test]
fn codex_parser_does_not_invent_a_title_from_transcript_content() {
    let line = r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"private prompt"}}"#;
    let parsed = parse_line(line, Path::new("/tmp/rollout.jsonl"), 2)
        .unwrap()
        .unwrap();
    assert!(parsed.session_metadata.title.is_none());
    assert!(parsed.session_metadata.title_provenance.is_none());
}

#[test]
fn parse_line_keeps_custom_tool_records_for_structured_extraction() {
    let call = r#"{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call-1","input":"{}"}}"#;
    let result = r#"{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-1","output":[{"type":"text","text":"ok"}]}}"#;

    assert_eq!(
        parse_line(call, Path::new("/tmp/rollout.jsonl"), 3)
            .unwrap()
            .unwrap()
            .message,
        "[custom_tool_call exec]"
    );
    assert_eq!(
        parse_line(result, Path::new("/tmp/rollout.jsonl"), 4)
            .unwrap()
            .unwrap()
            .message,
        "[custom_tool_call_output call-1]"
    );
}

#[test]
fn project_from_line_reads_turn_context_cwd() {
    let line = r#"{"turn_context":{"cwd":"/tmp/from-turn-context"},"content":"hello"}"#;

    assert_eq!(
        project_from_line(line).as_deref(),
        Some("/tmp/from-turn-context")
    );
}

#[test]
fn supplemental_title_prefers_user_name_over_generated_title() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state_5.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, name TEXT);
         INSERT INTO threads VALUES ('session-1', 'Generated title', 'My chosen title');",
    )
    .unwrap();
    drop(conn);

    assert_eq!(
        lookup_supplemental_session_title(dir.path(), "session-1"),
        Some(SupplementalSessionTitle {
            title: "My chosen title".to_string(),
            provenance: "codex.user-assigned".to_string(),
        })
    );
}

#[test]
fn supplemental_title_falls_back_across_schema_versions_and_bounds_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state_4.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT)", [])
        .unwrap();
    let long_title = "x".repeat(MAX_SESSION_METADATA_CHARS + 20);
    conn.execute(
        "INSERT INTO threads (id, title) VALUES (?1, ?2)",
        ("session-2", &long_title),
    )
    .unwrap();
    drop(conn);

    let title = lookup_supplemental_session_title(dir.path(), "session-2").unwrap();
    assert_eq!(title.title.chars().count(), MAX_SESSION_METADATA_CHARS);
    assert_eq!(title.provenance, "codex.generated");
}

#[test]
fn supplemental_title_rejects_control_characters_and_handles_unavailable_schema() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state_5.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, name TEXT);
         INSERT INTO threads VALUES ('unsafe', 'also\nunsafe', 'spoof\rname');",
    )
    .unwrap();
    drop(conn);

    assert!(lookup_supplemental_session_title(dir.path(), "unsafe").is_none());
    assert!(lookup_supplemental_session_title(dir.path(), "missing").is_none());

    let drifted = tempfile::tempdir().unwrap();
    Connection::open(drifted.path().join("state_99.sqlite"))
        .unwrap()
        .execute("CREATE TABLE conversations (identifier TEXT)", [])
        .unwrap();
    assert!(lookup_supplemental_session_title(drifted.path(), "unsafe").is_none());
    assert!(lookup_supplemental_session_title(Path::new("/missing/codex"), "unsafe").is_none());
}
