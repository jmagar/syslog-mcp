use super::{
    MAX_TRANSCRIPT_MESSAGE_BYTES, TranscriptLogClassification, TranscriptSkipReason,
    classify_transcript_log,
};
use crate::db::LogEntry;

fn log(tool: Option<&str>, session: Option<&str>, metadata: Option<String>) -> LogEntry {
    LogEntry {
        id: 101,
        timestamp: "2026-08-05T12:00:00.000Z".to_string(),
        hostname: "devhost".to_string(),
        facility: None,
        severity: "info".to_string(),
        app_name: Some("transcript".to_string()),
        process_id: Some("4242".to_string()),
        message: "hello".to_string(),
        received_at: "2026-08-05T12:00:01.000Z".to_string(),
        source_ip: "agent-ai-transcript://devhost".to_string(),
        ai_tool: tool.map(str::to_string),
        ai_project: Some("/workspace/cortex/.worktrees/task-one".to_string()),
        ai_session_id: session.map(str::to_string),
        ai_transcript_path: Some("/home/user/.claude/projects/cortex/session.jsonl".to_string()),
        metadata_json: metadata,
    }
}

#[test]
fn known_provider_uses_existing_fields_normalizes_project_and_bounds_message() {
    let mut row = log(
        Some("Claude"),
        Some("session-one"),
        Some(r#"{"role":"assistant"}"#.to_string()),
    );
    row.message = "🧠".repeat(MAX_TRANSCRIPT_MESSAGE_BYTES);
    let TranscriptLogClassification::Project(projected) = classify_transcript_log(&row) else {
        panic!("valid transcript row should project");
    };
    assert_eq!(projected.tool, "claude");
    assert_eq!(projected.provider_tool, "Claude");
    assert_eq!(projected.project.as_deref(), Some("/workspace/cortex"));
    assert_eq!(projected.session_id, "session-one");
    assert_eq!(projected.transcript_path, row.ai_transcript_path.unwrap());
    assert!(projected.message.len() <= MAX_TRANSCRIPT_MESSAGE_BYTES);
    assert!(projected.message_truncated);
    assert_eq!(projected.metadata_json, r#"{"role":"assistant"}"#);
}

#[test]
fn transcript_provider_aliases_use_the_shared_registry() {
    for (alias, expected) in [
        ("claude-code", "claude"),
        ("openai-codex", "codex"),
        ("gemini-transcript", "gemini"),
    ] {
        let row = log(Some(alias), Some("session-one"), None);
        let TranscriptLogClassification::Project(projected) = classify_transcript_log(&row) else {
            panic!("registry alias {alias} should project");
        };
        assert_eq!(projected.tool, expected);
        assert_eq!(projected.provider_tool, alias);
    }
}

#[test]
fn missing_session_unsupported_tool_and_invalid_metadata_are_diagnostics() {
    let missing = log(Some("claude"), None, None);
    let TranscriptLogClassification::Skip(diagnostic) = classify_transcript_log(&missing) else {
        panic!("missing session must be skipped");
    };
    assert_eq!(diagnostic.log_id, 101);
    assert_eq!(diagnostic.reason, TranscriptSkipReason::MissingSessionId);

    let unsupported = log(Some("copilot"), Some("session-one"), None);
    let TranscriptLogClassification::Skip(diagnostic) = classify_transcript_log(&unsupported)
    else {
        panic!("unsupported provider must be skipped");
    };
    assert_eq!(diagnostic.reason, TranscriptSkipReason::UnsupportedTool);

    let malformed = log(Some("gemini"), Some("session-one"), Some("{".to_string()));
    let TranscriptLogClassification::Skip(diagnostic) = classify_transcript_log(&malformed) else {
        panic!("invalid metadata must be skipped");
    };
    assert_eq!(diagnostic.reason, TranscriptSkipReason::InvalidMetadataJson);
}

#[test]
fn transcript_projection_scrubs_secrets_from_message_metadata_and_provenance() {
    let secret = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut row = log(
        Some("claude"),
        Some(secret),
        Some(format!(r#"{{"nested":{{"authorization":"{secret}"}}}}"#)),
    );
    row.message = format!("credential {secret}");
    row.hostname = format!("host-{secret}");
    row.ai_project = Some(format!("/workspace/{secret}"));
    row.ai_transcript_path = Some(format!("/tmp/{secret}.jsonl"));
    row.process_id = Some(secret.to_string());
    row.app_name = Some(secret.to_string());
    row.source_ip = secret.to_string();
    let TranscriptLogClassification::Project(projected) = classify_transcript_log(&row) else {
        panic!("valid transcript row should project");
    };
    let persisted = format!(
        "{} {} {} {} {} {} {} {} {} {}",
        projected.message,
        projected.metadata_json,
        projected.session_id,
        projected.project.unwrap_or_default(),
        projected.transcript_path,
        projected.hostname,
        projected.process_id.unwrap_or_default(),
        projected.app_name.unwrap_or_default(),
        projected.source_ip,
        projected.provider_tool,
    );
    assert!(!persisted.contains(secret));
    assert!(persisted.contains("[REDACTED]"));
}
