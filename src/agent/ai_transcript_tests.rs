use super::*;
use std::io::Write;

fn write_file(path: &Path, content: &str) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn accepted_receipt_response(request: &wiremock::Request) -> wiremock::ResponseTemplate {
    let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    let receipts: Vec<_> = value["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            serde_json::json!({
                "source_record_id": record["envelope"]["source_record_id"],
                "disposition": "accepted",
            })
        })
        .collect();
    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "accepted": receipts.len(),
        "receipts": receipts,
    }))
}

#[test]
fn collect_files_finds_supported_and_skips_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    write_file(&claude_dir.join("session.jsonl"), "{}\n");
    write_file(&claude_dir.join("readme.txt"), "not a transcript\n");

    let mut out = Vec::new();
    collect_files(dir.path(), &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("session.jsonl"));
}

#[test]
fn bounded_discovery_cursor_reaches_later_transcripts() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let first = claude_dir.join("001.jsonl");
    let second = claude_dir.join("002.jsonl");
    write_file(&first, "{}\n");
    write_file(&second, "{}\n");

    let mut after_first = Vec::new();
    collect_files_after(dir.path(), &mut after_first, Some(&first)).unwrap();
    assert_eq!(after_first, vec![second.clone()]);

    let mut after_last = Vec::new();
    collect_files_after(dir.path(), &mut after_last, Some(&second)).unwrap();
    assert!(
        after_last.is_empty(),
        "the caller can wrap after the final file"
    );
}

#[test]
fn collect_files_skips_build_artifact_directories() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".codex/worktrees/session-id/lab");
    let target = project.join("target/debug/.fingerprint/package");
    let node_modules = project.join("node_modules/package");
    let cache = project.join(".cache/cargo/release/deps/rustc123");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&node_modules).unwrap();
    fs::create_dir_all(&cache).unwrap();
    write_file(&project.join("rollout-session.jsonl"), "{}\n");
    write_file(&target.join("not-a-transcript.jsonl"), "{}\n");
    write_file(&node_modules.join("also-not-a-transcript.jsonl"), "{}\n");
    write_file(&cache.join("transient-not-a-transcript.jsonl"), "{}\n");

    let mut out = Vec::new();
    collect_files(dir.path(), &mut out).unwrap();

    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("rollout-session.jsonl"));
}

#[test]
fn configured_mounted_roots_keep_provider_layout_classification() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        forward_source_kind(&root.path().join(".claude/projects/project/session.jsonl")),
        scanner::SourceKind::ClaudeProject
    );
    assert_eq!(
        forward_source_kind(&root.path().join(".codex/sessions/2026/09/session.jsonl")),
        scanner::SourceKind::CodexSession
    );
    assert_eq!(
        forward_source_kind(&root.path().join(".gemini/tmp/session/chats/session-1.json")),
        scanner::SourceKind::GeminiSession
    );
}

#[test]
fn forwarded_evidence_capabilities_follow_the_provider_registry() {
    let claude = capability_coverage(scanner::SourceKind::ClaudeProject);
    assert_eq!(claude.transcript, EvidenceCoverage::Observed);
    assert_eq!(claude.mcp_events, EvidenceCoverage::Partial);
    assert_eq!(claude.skill_events, EvidenceCoverage::Partial);
    assert_eq!(claude.hook_events, EvidenceCoverage::Partial);

    let codex = capability_coverage(scanner::SourceKind::CodexSession);
    assert_eq!(codex.transcript, EvidenceCoverage::Observed);
    assert_eq!(codex.mcp_events, EvidenceCoverage::Partial);
    assert_eq!(codex.skill_events, EvidenceCoverage::Partial);
    assert_eq!(codex.hook_events, EvidenceCoverage::NotObserved);

    let gemini = capability_coverage(scanner::SourceKind::GeminiSession);
    assert_eq!(gemini.transcript, EvidenceCoverage::Observed);
    assert_eq!(gemini.mcp_events, EvidenceCoverage::NotObserved);
    assert_eq!(gemini.skill_events, EvidenceCoverage::NotObserved);
    assert_eq!(gemini.hook_events, EvidenceCoverage::NotObserved);

    // Explicit files remain useful, bounded transcript inputs, but have no
    // provider descriptor and therefore cannot claim extracted event lanes.
    let explicit = capability_coverage(scanner::SourceKind::ExplicitFile);
    assert_eq!(explicit.transcript, EvidenceCoverage::Partial);
    assert_eq!(explicit.mcp_events, EvidenceCoverage::NotObserved);
    assert_eq!(explicit.skill_events, EvidenceCoverage::NotObserved);
    assert_eq!(explicit.hook_events, EvidenceCoverage::NotObserved);
}

#[cfg(unix)]
#[test]
fn collect_files_never_follows_symlinked_transcript() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let transcript = outside.path().join("session.jsonl");
    write_file(&transcript, "{}\n");
    symlink(&transcript, root.path().join("session.jsonl")).unwrap();

    let mut files = Vec::new();
    collect_files(root.path(), &mut files).unwrap();
    assert!(files.is_empty());
}

#[test]
fn read_new_lines_returns_only_lines_past_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    write_file(&path, "line0\nline1\nline2\n");

    let (lines, total) = read_new_lines(&path, 1, 500).unwrap();
    assert_eq!(total, 3);
    assert_eq!(
        lines,
        vec![(1, "line1".to_string()), (2, "line2".to_string())]
    );
}

#[test]
fn read_new_lines_respects_limit_and_reports_checkpoint_at_cutoff_not_eof() {
    // Regression: the checkpoint returned must reflect how far the limited
    // read actually got, not the file's true EOF — otherwise lines past the
    // limit are silently skipped forever on the next call.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    write_file(&path, "line0\nline1\nline2\nline3\nline4\n");

    let (lines, checkpoint) = read_new_lines(&path, 0, 2).unwrap();
    assert_eq!(
        lines,
        vec![(0, "line0".to_string()), (1, "line1".to_string())]
    );
    assert_eq!(
        checkpoint, 2,
        "checkpoint must stop at the limit, not report EOF (5)"
    );

    let (lines, checkpoint) = read_new_lines(&path, checkpoint, 2).unwrap();
    assert_eq!(
        lines,
        vec![(2, "line2".to_string()), (3, "line3".to_string())]
    );
    assert_eq!(checkpoint, 4);
}

#[test]
fn read_new_lines_defers_an_incomplete_jsonl_tail_without_advancing_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    fs::write(&path, "{\"complete\":true}\n{\"partial\":").unwrap();

    let (lines, checkpoint) = read_new_lines(&path, 0, 10).unwrap();
    assert_eq!(lines, vec![(0, "{\"complete\":true}".into())]);
    assert_eq!(checkpoint, 1);

    fs::write(&path, "{\"complete\":true}\n{\"partial\":false}\n").unwrap();
    let (lines, checkpoint) = read_new_lines(&path, checkpoint, 10).unwrap();
    assert_eq!(lines, vec![(1, "{\"partial\":false}".into())]);
    assert_eq!(checkpoint, 2);
}

#[test]
fn read_new_lines_accepts_provider_records_larger_than_64_kib() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let record = format!(
        r#"{{"type":"tool_result","content":"{}"}}"#,
        "x".repeat(128 * 1024)
    );
    write_file(&path, &format!("{record}\n"));

    let (lines, checkpoint) = read_new_lines(&path, 0, 10).unwrap();

    assert_eq!(lines, vec![(0, record)]);
    assert_eq!(checkpoint, 1);
}

#[test]
fn read_new_lines_emits_a_gap_and_advances_past_an_oversized_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    write_file(
        &path,
        &format!(
            "{}\n{{\"type\":\"user\",\"message\":\"after gap\"}}\n",
            "x".repeat(MAX_JSONL_LINE_BYTES + 1)
        ),
    );

    let (lines, checkpoint) = read_new_lines(&path, 0, 10).unwrap();

    assert_eq!(checkpoint, 2);
    assert_eq!(lines[0], (0, OVERSIZED_JSONL_GAP_RECORD.to_string()));
    assert_eq!(
        lines[1],
        (1, r#"{"type":"user","message":"after gap"}"#.to_string())
    );
}

#[test]
fn seekable_jsonl_position_reads_only_the_appended_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let historical = format!("{}\n", "x".repeat(MAX_JSONL_LINE_BYTES + 1));
    write_file(&path, &historical);
    let offset = historical.len() as u64;
    let position = JsonlPosition {
        line: 1,
        byte_offset: offset,
        source_epoch: source_epoch(&path),
        prefix_guard: jsonl_prefix_guard(&path, offset).unwrap(),
        prefix_digest: Some(jsonl_prefix_digest(&path, offset).unwrap()),
        observed_len: offset,
        modified_ns: path.metadata().ok().and_then(|m| file_modified_ns(&m)),
    };
    assert!(jsonl_position_is_current(&path, &position));

    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"tail\n").unwrap();
    drop(file);

    let (lines, line, next_offset) =
        read_new_lines_from_offset(&path, position.line, position.byte_offset, 10).unwrap();
    assert_eq!(lines, vec![(1, "tail".to_string())]);
    assert_eq!(line, 2);
    assert_eq!(next_offset, offset + 5);
}

#[test]
fn seekable_jsonl_position_rejects_replacement_truncation_and_prefix_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    write_file(&path, "first\nsecond\n");
    let offset = fs::metadata(&path).unwrap().len();
    let position = JsonlPosition {
        line: 2,
        byte_offset: offset,
        source_epoch: source_epoch(&path),
        prefix_guard: jsonl_prefix_guard(&path, offset).unwrap(),
        prefix_digest: Some(jsonl_prefix_digest(&path, offset).unwrap()),
        observed_len: offset,
        modified_ns: path.metadata().ok().and_then(|m| file_modified_ns(&m)),
    };

    write_file(&path, "short\n");
    assert!(!jsonl_position_is_current(&path, &position));

    write_file(&path, "other\nsecond\n");
    assert!(!jsonl_position_is_current(&path, &position));
}

#[test]
fn seekable_jsonl_position_rejects_a_middle_only_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let original = format!(
        "{}{}{}",
        "a".repeat(5 * 1024),
        "b".repeat(4 * 1024),
        "c".repeat(5 * 1024)
    );
    write_file(&path, &original);
    let metadata = path.metadata().unwrap();
    let offset = metadata.len();
    let position = JsonlPosition {
        line: 1,
        byte_offset: offset,
        source_epoch: source_epoch(&path),
        prefix_guard: jsonl_prefix_guard(&path, offset).unwrap(),
        prefix_digest: Some(jsonl_prefix_digest(&path, offset).unwrap()),
        observed_len: offset,
        modified_ns: file_modified_ns(&metadata),
    };

    let rewritten = format!(
        "{}{}{}",
        "a".repeat(5 * 1024),
        "x".repeat(4 * 1024),
        "c".repeat(5 * 1024)
    );
    write_file(&path, &rewritten);
    let changed_time = filetime::FileTime::from_unix_time(
        metadata
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 1,
        0,
    );
    filetime::set_file_mtime(&path, changed_time).unwrap();

    assert_eq!(path.metadata().unwrap().len(), offset);
    assert_eq!(
        jsonl_prefix_guard(&path, offset).unwrap(),
        position.prefix_guard,
        "the rewrite must remain outside both sampled guard windows"
    );
    assert!(!jsonl_position_is_current(&path, &position));
}

#[test]
fn seekable_jsonl_position_rejects_a_middle_rewrite_followed_by_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let original = format!(
        "{}{}{}",
        "a".repeat(5 * 1024),
        "b".repeat(4 * 1024),
        "c".repeat(5 * 1024)
    );
    write_file(&path, &original);
    let metadata = path.metadata().unwrap();
    let offset = metadata.len();
    let position = JsonlPosition {
        line: 1,
        byte_offset: offset,
        source_epoch: source_epoch(&path),
        prefix_guard: jsonl_prefix_guard(&path, offset).unwrap(),
        prefix_digest: Some(jsonl_prefix_digest(&path, offset).unwrap()),
        observed_len: offset,
        modified_ns: file_modified_ns(&metadata),
    };

    let rewritten_and_appended = format!(
        "{}{}{}tail\n",
        "a".repeat(5 * 1024),
        "x".repeat(4 * 1024),
        "c".repeat(5 * 1024)
    );
    write_file(&path, &rewritten_and_appended);

    assert!(path.metadata().unwrap().len() > position.observed_len);
    assert_eq!(
        jsonl_prefix_guard(&path, offset).unwrap(),
        position.prefix_guard,
        "the rewrite must remain outside both sampled guard windows"
    );
    let rewritten_digest = jsonl_prefix_digest(&path, offset).unwrap();
    assert_ne!(
        Some(rewritten_digest.as_str()),
        position.prefix_digest.as_deref(),
        "the exact digest must cover the unsampled middle"
    );
    assert!(!jsonl_position_is_current(&path, &position));
}

#[test]
fn seekable_jsonl_position_invalidates_a_legacy_position_without_exact_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    write_file(&path, "record\n");
    let metadata = path.metadata().unwrap();
    let offset = metadata.len();
    let legacy = serde_json::json!({
        "line": 1,
        "byte_offset": offset,
        "source_epoch": source_epoch(&path),
        "prefix_guard": jsonl_prefix_guard(&path, offset).unwrap(),
        "observed_len": offset,
        "modified_ns": file_modified_ns(&metadata)
    });
    let position: JsonlPosition = serde_json::from_value(legacy).unwrap();

    assert_eq!(position.prefix_digest, None);
    assert!(!jsonl_position_is_current(&path, &position));
}

#[test]
fn checkpoint_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint_path = dir.path().join("checkpoint.json");
    let mut checkpoint = Checkpoint::default();
    checkpoint.files.insert("/tmp/foo.jsonl".to_string(), 42);
    checkpoint
        .fingerprints
        .insert("/tmp/foo.jsonl".to_string(), "sha256:prefix".to_string());
    checkpoint.jsonl_positions.insert(
        "/tmp/foo.jsonl".to_string(),
        JsonlPosition {
            line: 42,
            byte_offset: 1234,
            source_epoch: "sha256:epoch".to_string(),
            prefix_guard: "sha256:guard".to_string(),
            prefix_digest: Some("sha256:digest".to_string()),
            observed_len: 1234,
            modified_ns: Some(123),
        },
    );
    checkpoint
        .discovery_cursors
        .insert("/tmp/root".to_string(), "/tmp/root/later.jsonl".to_string());
    checkpoint.gemini_parse_failures.insert(
        "/tmp/bad-gemini.json".to_string(),
        GeminiParseFailure {
            fingerprint: 99,
            last_warned: Instant::now(),
        },
    );
    save_checkpoint(&checkpoint_path, &checkpoint).unwrap();

    let loaded = load_checkpoint(&checkpoint_path).unwrap();
    assert_eq!(loaded.files.get("/tmp/foo.jsonl"), Some(&42));
    assert_eq!(
        loaded
            .fingerprints
            .get("/tmp/foo.jsonl")
            .map(String::as_str),
        Some("sha256:prefix")
    );
    assert_eq!(
        loaded.jsonl_positions.get("/tmp/foo.jsonl"),
        checkpoint.jsonl_positions.get("/tmp/foo.jsonl")
    );
    assert_eq!(
        loaded
            .discovery_cursors
            .get("/tmp/root")
            .map(String::as_str),
        Some("/tmp/root/later.jsonl")
    );
    assert!(
        loaded.gemini_parse_failures.is_empty(),
        "parse-warning suppression is process-local and must not be persisted"
    );
}

#[test]
fn failed_checkpoint_replacement_removes_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint_path = dir.path().join("checkpoint.json");
    fs::create_dir(&checkpoint_path).unwrap();

    let error = save_checkpoint(&checkpoint_path, &Checkpoint::default()).unwrap_err();
    assert!(error.to_string().contains("atomically replace checkpoint"));

    let temporary_files = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("checkpoint.tmp-"))
        })
        .collect::<Vec<_>>();
    assert!(
        temporary_files.is_empty(),
        "left behind: {temporary_files:?}"
    );
}

#[test]
fn codex_prefix_recovery_reports_file_open_failure() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.jsonl");
    let mut project = None;
    let mut session_id = None;

    let error = seed_codex_prefix_fallbacks(
        &missing,
        scanner::SourceKind::CodexSession,
        1,
        &mut project,
        &mut session_id,
    )
    .unwrap_err();

    assert!(error.to_string().contains("open Codex prefix metadata"));
}

#[test]
fn codex_prefix_recovery_skips_an_oversized_line_without_unbounded_reading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized-prefix.jsonl");
    write_file(
        &path,
        &format!("{}\n", "x".repeat(MAX_JSONL_LINE_BYTES + 1)),
    );
    let mut project = None;
    let mut session_id = None;

    seed_codex_prefix_fallbacks(
        &path,
        scanner::SourceKind::CodexSession,
        1,
        &mut project,
        &mut session_id,
    )
    .unwrap();

    assert_eq!(project, None);
    assert_eq!(session_id, None);
}

#[test]
fn missing_checkpoint_starts_empty_but_corrupt_checkpoint_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint_path = dir.path().join("checkpoint.json");

    assert!(load_checkpoint(&checkpoint_path).unwrap().files.is_empty());
    write_file(&checkpoint_path, "{not-json");

    let error = load_checkpoint(&checkpoint_path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to decode checkpoint file"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn envelope_identity_survives_an_archive_move_when_native_session_is_available() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join(".claude/projects/project/session.jsonl");
    fs::create_dir_all(active.parent().unwrap()).unwrap();
    write_file(&active, "same record\n");
    let config = AiTranscriptForwardConfig {
        roots: vec![root.path().to_path_buf()],
        target: "http://unused".to_string(),
        token: None,
        hostname: "host-a".to_string(),
        checkpoint_path: root.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(1),
    };
    let before = transcript_record(
        &config,
        &active,
        scanner::SourceKind::ClaudeProject,
        TranscriptRecordDetails {
            revision: "line:0:same record".to_string(),
            timestamp: None,
            ai_project: None,
            ai_session_id: Some("native-session".to_string()),
            event_kind: Some("user".to_string()),
            message: "same record".to_string(),
            title: None,
            title_provenance: None,
            diagnostics: Vec::new(),
        },
    );
    let archived = root
        .path()
        .join(".claude/projects/project/archive/session.jsonl");
    fs::create_dir_all(archived.parent().unwrap()).unwrap();
    fs::rename(&active, &archived).unwrap();
    let after = transcript_record(
        &config,
        &archived,
        scanner::SourceKind::ClaudeProject,
        TranscriptRecordDetails {
            revision: "line:0:same record".to_string(),
            timestamp: None,
            ai_project: None,
            ai_session_id: Some("native-session".to_string()),
            event_kind: Some("user".to_string()),
            message: "same record".to_string(),
            title: None,
            title_provenance: None,
            diagnostics: Vec::new(),
        },
    );
    assert_eq!(
        before.envelope.source_record_id, after.envelope.source_record_id,
        "archive moves must replay to the same receipt identity"
    );
    assert_ne!(
        before.envelope.source.locator, after.envelope.source.locator,
        "safe locator records that the mutable location changed"
    );
}

#[test]
fn transcript_record_bounds_every_variable_wire_field() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.jsonl");
    write_file(&path, "{}\n");
    let config = AiTranscriptForwardConfig {
        roots: vec![root.path().to_path_buf()],
        target: "http://unused".to_string(),
        token: None,
        hostname: "h".repeat(MAX_FORWARDED_IDENTIFIER_BYTES + 1),
        checkpoint_path: root.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(1),
    };
    let record = transcript_record(
        &config,
        &path,
        scanner::SourceKind::ClaudeProject,
        TranscriptRecordDetails {
            revision: "revision".to_string(),
            timestamp: Some("t".repeat(MAX_FORWARDED_TIMESTAMP_BYTES + 1)),
            ai_project: None,
            ai_session_id: None,
            event_kind: Some("e".repeat(MAX_FORWARDED_IDENTIFIER_BYTES + 1)),
            message: "m".repeat(MAX_FORWARDED_MESSAGE_BYTES + 1),
            title: None,
            title_provenance: None,
            diagnostics: Vec::new(),
        },
    );
    assert!(record.envelope.hostname.len() <= MAX_FORWARDED_IDENTIFIER_BYTES + 3);
    assert!(record.envelope.timestamp.unwrap().len() <= MAX_FORWARDED_TIMESTAMP_BYTES + 3);
    assert!(record.envelope.event_kind.unwrap().len() <= MAX_FORWARDED_IDENTIFIER_BYTES + 3);
    assert!(record.envelope.message.len() <= MAX_FORWARDED_MESSAGE_BYTES + 3);
}

#[test]
fn gemini_parse_failure_warns_once_per_content_revision() {
    let mut checkpoint = Checkpoint::default();
    let key = "/tmp/bad-gemini.json";
    let now = Instant::now();

    assert!(should_warn_gemini_parse_failure(
        &mut checkpoint,
        key,
        "{not-json",
        now
    ));
    assert!(
        !should_warn_gemini_parse_failure(&mut checkpoint, key, "{not-json", now),
        "unchanged malformed content must not warn every poll"
    );
    assert!(
        should_warn_gemini_parse_failure(&mut checkpoint, key, "{still-not-json", now),
        "a changed malformed revision should warn once again"
    );
}

/// The failure mode content-only suppression creates: a transcript that goes
/// malformed and then stops changing would otherwise warn once and go silent
/// for the process lifetime while its data is never forwarded.
#[test]
fn gemini_parse_failure_rewarns_after_the_interval_even_when_content_is_unchanged() {
    let mut checkpoint = Checkpoint::default();
    let key = "/tmp/stuck-gemini.json";
    let start = Instant::now();

    assert!(should_warn_gemini_parse_failure(
        &mut checkpoint,
        key,
        "{not-json",
        start
    ));

    let just_before = start + GEMINI_REWARN_INTERVAL - Duration::from_secs(1);
    assert!(
        !should_warn_gemini_parse_failure(&mut checkpoint, key, "{not-json", just_before),
        "must stay quiet until the re-warn interval elapses"
    );

    let after = start + GEMINI_REWARN_INTERVAL;
    assert!(
        should_warn_gemini_parse_failure(&mut checkpoint, key, "{not-json", after),
        "a persistently malformed transcript must not go dark forever"
    );
    assert!(
        !should_warn_gemini_parse_failure(&mut checkpoint, key, "{not-json", after),
        "the re-warn must reset the clock, not latch on"
    );
}

#[test]
fn gemini_parse_failures_are_evicted_for_files_that_no_longer_exist() {
    let mut checkpoint = Checkpoint::default();
    let now = Instant::now();
    should_warn_gemini_parse_failure(&mut checkpoint, "/tmp/gone.json", "{bad", now);
    should_warn_gemini_parse_failure(&mut checkpoint, "/tmp/still-here.json", "{bad", now);

    let present: HashSet<String> = ["/tmp/still-here.json".to_string()].into_iter().collect();
    evict_missing_gemini_failures(&mut checkpoint, &present);

    assert!(
        !checkpoint
            .gemini_parse_failures
            .contains_key("/tmp/gone.json")
    );
    assert!(
        checkpoint
            .gemini_parse_failures
            .contains_key("/tmp/still-here.json")
    );
}

#[tokio::test]
async fn scan_and_forward_sends_new_lines_and_advances_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-1",
                "message": {"role": "user", "content": "hello world"}
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: Some("test-token".to_string()),
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    let sent = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent, 1);
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );

    // Second scan with no new lines should send nothing.
    let sent_again = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent_again, 0);
}

#[tokio::test]
async fn scan_and_forward_replaces_parse_failures_with_receipt_backed_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    let valid = |content: &str| {
        serde_json::json!({
            "type": "user",
            "timestamp": "2026-07-09T00:00:00Z",
            "sessionId": "sess-1",
            "message": {"role": "user", "content": content}
        })
        .to_string()
    };
    write_file(
        &transcript_path,
        &format!("{}\n{{not-json\n{}\n", valid("before"), valid("after")),
    );

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&3)
    );
    let requests = server.received_requests().await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let diagnostic = &payload["records"][1]["envelope"];
    assert_eq!(diagnostic["event_kind"], "parse_gap");
    assert_eq!(
        diagnostic["message"],
        "[Cortex skipped an unparseable transcript record]"
    );
    assert_eq!(
        diagnostic["diagnostics"][0]["code"],
        "malformed_transcript_record"
    );
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn scan_and_forward_checkpoints_an_all_invalid_file_only_after_gap_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    write_file(&transcript_path, "{not-json\n");

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn scan_and_forward_prioritizes_active_session_over_historical_backlog() {
    let dir = tempfile::tempdir().unwrap();
    let transcript_dir = dir.path().join(".codex/sessions");
    fs::create_dir_all(&transcript_dir).unwrap();
    let historical_path = transcript_dir.join("a-historical.jsonl");
    let active_path = transcript_dir.join("z-active.jsonl");
    let historical = (0..MAX_BATCH_RECORDS)
        .map(|index| {
            serde_json::json!({
                "type": "response_item",
                "timestamp": "2026-07-09T00:00:00Z",
                "payload": {"type": "message", "role": "user", "content": format!("old-{index}")}
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    write_file(&historical_path, &format!("{historical}\n"));
    std::thread::sleep(Duration::from_millis(20));
    write_file(
        &active_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "response_item",
                "timestamp": "2026-09-04T20:00:00Z",
                "payload": {"type": "message", "role": "user", "content": "active-now"}
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        MAX_BATCH_RECORDS
    );
    assert_eq!(
        checkpoint
            .files
            .get(&active_path.to_string_lossy().to_string()),
        Some(&1),
        "the newest session must enter the first saturated batch"
    );
    assert_eq!(
        checkpoint
            .files
            .get(&historical_path.to_string_lossy().to_string()),
        Some(&(MAX_BATCH_RECORDS - 1)),
        "the historical backlog must remain eligible to drain"
    );
}

#[tokio::test]
async fn scan_and_forward_retries_after_lost_or_incomplete_receipt_response() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-1",
                "message": {"role": "user", "content": "retry me"}
            })
        ),
    );
    let server = wiremock::MockServer::start().await;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_clone = calls.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |request: &wiremock::Request| {
            if calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                // Model the canonical commit succeeding but its receipt being
                // lost/truncated on the return path. The sender must not move
                // its cursor without exact receipt IDs.
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"accepted": 1, "receipts": []}))
            } else {
                accepted_receipt_response(request)
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    assert!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .is_err()
    );
    assert!(
        checkpoint.files.is_empty(),
        "no receipt means no checkpoint"
    );
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );
}

#[tokio::test]
async fn scan_and_forward_retries_oversized_gap_until_receipt_then_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let transcript_dir = dir.path().join(".codex/sessions");
    fs::create_dir_all(&transcript_dir).unwrap();
    let transcript_path = transcript_dir.join("oversized.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n{}\n",
            "x".repeat(MAX_JSONL_LINE_BYTES + 1),
            serde_json::json!({
                "type": "response_item",
                "timestamp": "2026-09-04T20:00:00Z",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": "after oversized record"
                }
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_clone = calls.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |request: &wiremock::Request| {
            if calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"accepted": 2, "receipts": []}))
            } else {
                accepted_receipt_response(request)
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .is_err()
    );
    assert!(
        checkpoint.files.is_empty(),
        "no receipt means no checkpoint"
    );
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&2)
    );
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        0
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["envelope"]["message"],
            "[Cortex skipped an oversized transcript record]"
        );
        assert_eq!(records[1]["envelope"]["message"], "after oversized record");
    }
}

#[tokio::test]
async fn scan_and_forward_retries_after_rate_limit_and_server_error_without_checkpointing() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-retry-status",
                "message": {"role": "user", "content": "retry after status"}
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_clone = calls.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |request: &wiremock::Request| {
            match calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => wiremock::ResponseTemplate::new(429).set_body_string("rate limited"),
                1 => wiremock::ResponseTemplate::new(503).set_body_string("unavailable"),
                _ => accepted_receipt_response(request),
            }
        })
        .expect(3)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    for expected_status in ["429", "503"] {
        let error = scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected_status), "{error:#}");
        assert!(checkpoint.files.is_empty());
        assert!(checkpoint.fingerprints.is_empty());
        assert!(checkpoint.discovery_cursors.is_empty());
        assert!(!config.checkpoint_path.exists());
    }

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );
}

#[tokio::test]
async fn scan_and_forward_retries_when_checkpoint_parent_was_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "sessionId": "sess-blocked-checkpoint",
                "message": {"role": "user", "content": "retry durable checkpoint"}
            })
        ),
    );
    let checkpoint_parent = dir.path().join("checkpoint-parent");
    write_file(&checkpoint_parent, "blocks directory creation");
    let checkpoint_path = checkpoint_parent.join("checkpoint.json");

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(2)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: checkpoint_path.clone(),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    let error = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to create checkpoint dir"),
        "{error:#}"
    );
    assert!(
        checkpoint.files.is_empty(),
        "a non-durable checkpoint must remain eligible for retry"
    );

    fs::remove_file(&checkpoint_parent).unwrap();
    fs::create_dir(&checkpoint_parent).unwrap();
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );
    assert!(checkpoint_path.exists());
}

#[tokio::test]
async fn malformed_source_does_not_prevent_valid_source_from_forwarding() {
    let dir = tempfile::tempdir().unwrap();
    let gemini_dir = dir.path().join(".gemini/tmp/broken/chats");
    let claude_dir = dir.path().join(".claude/projects/valid");
    fs::create_dir_all(&gemini_dir).unwrap();
    fs::create_dir_all(&claude_dir).unwrap();
    let broken_path = gemini_dir.join("session-broken.json");
    let valid_path = claude_dir.join("session.jsonl");
    write_file(&broken_path, "{not-json");
    write_file(
        &valid_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "sessionId": "sess-valid",
                "message": {"role": "user", "content": "still forward me"}
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&valid_path.to_string_lossy().to_string()),
        Some(&1)
    );
    assert!(
        !checkpoint
            .files
            .contains_key(&broken_path.to_string_lossy().to_string())
    );
    assert!(
        checkpoint
            .gemini_parse_failures
            .contains_key(&broken_path.to_string_lossy().to_string())
    );
}

#[tokio::test]
async fn scan_and_forward_replays_a_rewritten_jsonl_source_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    let transcript_path = claude_dir.join("session.jsonl");
    let line = |content: &str| {
        format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-1",
                "message": {"role": "user", "content": content}
            })
        )
    };
    write_file(&transcript_path, &line("before rewrite"));

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(2)
        .mount(&server)
        .await;
    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );

    // Same line count but a different prefix: never treat this as an append.
    write_file(&transcript_path, &line("after rewrite"));
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&transcript_path.to_string_lossy().to_string()),
        Some(&1)
    );
}

#[tokio::test]
async fn scan_and_forward_preserves_codex_prefix_metadata_after_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let codex_dir = dir.path().join(".codex/sessions/2026/07/12");
    fs::create_dir_all(&codex_dir).unwrap();
    let state = rusqlite::Connection::open(dir.path().join(".codex/state_5.sqlite")).unwrap();
    state
        .execute_batch(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, name TEXT);
             INSERT INTO threads VALUES ('codex-sess-1', 'Generated title', 'Operator title');",
        )
        .unwrap();
    drop(state);
    let transcript_path = codex_dir.join("rollout-2026-07-12T22-31-12-codex-sess-1.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n{}\n",
            serde_json::json!({
                "timestamp": "2026-07-09T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": "codex-sess-1",
                    "cwd": "/home/jmagar/workspace/cortex"
                }
            }),
            serde_json::json!({
                "timestamp": "2026-07-09T00:00:01Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "content": "hello from codex"
                }
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    let received = std::sync::Arc::new(std::sync::Mutex::new(None));
    let received_clone = received.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |req: &wiremock::Request| {
            *received_clone.lock().unwrap() = Some(req.body.clone());
            accepted_receipt_response(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    checkpoint
        .files
        .insert(transcript_path.to_string_lossy().to_string(), 1);

    let sent = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent, 1);

    let body = received.lock().unwrap().take().unwrap();
    let request: AiTranscriptIngestRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(request.records.len(), 1);
    let envelope = &request.records[0].envelope;
    assert_eq!(envelope.source.provider, "codex");
    assert_eq!(envelope.source.title.as_deref(), Some("Operator title"));
    assert_eq!(
        envelope.source.title_provenance.as_deref(),
        Some("codex.user-assigned")
    );
    assert!(
        envelope
            .ai_project
            .as_deref()
            .is_some_and(|value| value.starts_with("project:sha256:"))
    );
    assert!(
        envelope
            .ai_session_id
            .as_deref()
            .is_some_and(|value| value.starts_with("session:sha256:"))
    );
}

#[tokio::test]
async fn scan_and_forward_scrubs_credentials_before_sending() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    write_file(
        &claude_dir.join("session.jsonl"),
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-1",
                "message": {"role": "user", "content": "export OPENAI_API_KEY=sk-proj-super-secret-value-long-enough-to-match"}
            })
        ),
    );

    let server = wiremock::MockServer::start().await;
    let received = std::sync::Arc::new(std::sync::Mutex::new(None));
    let received_clone = received.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |req: &wiremock::Request| {
            *received_clone.lock().unwrap() = Some(req.body.clone());
            accepted_receipt_response(req)
        })
        .expect(1)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();

    let body = received.lock().unwrap().take().unwrap();
    let body_str = String::from_utf8(body).unwrap();
    assert!(
        !body_str.contains("sk-proj-super-secret-value-long-enough-to-match"),
        "raw API key must not reach the network: {body_str}"
    );
    assert!(body_str.contains("REDACTED"), "got: {body_str}");
}

#[tokio::test]
async fn scan_and_forward_clears_gemini_parse_failure_after_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let gemini_dir = dir.path().join(".gemini/tmp/abc123/chats");
    fs::create_dir_all(&gemini_dir).unwrap();
    let session_path = gemini_dir.join("session-1.json");
    write_file(&session_path, "{not-json");

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .expect(1)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();
    let key = session_path.to_string_lossy().to_string();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        0
    );
    assert!(checkpoint.gemini_parse_failures.contains_key(&key));

    write_file(
        &session_path,
        &serde_json::json!({
            "sessionId": "gemini-sess-1",
            "cwd": "/home/jmagar/workspace/cortex",
            "messages": [
                {"id": "m1", "timestamp": "2026-07-09T00:00:00Z", "content": "recovered"},
            ]
        })
        .to_string(),
    );

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert!(!checkpoint.gemini_parse_failures.contains_key(&key));
}

#[tokio::test]
async fn scan_and_forward_handles_gemini_whole_file_session_with_record_index_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let gemini_dir = dir.path().join(".gemini/tmp/abc123/chats");
    fs::create_dir_all(&gemini_dir).unwrap();
    let session_path = gemini_dir.join("session-1.json");
    write_file(
        &session_path,
        &serde_json::json!({
            "sessionId": "gemini-sess-1",
            "cwd": "/home/jmagar/workspace/cortex",
            "messages": [
                {"id": "m1", "timestamp": "2026-07-09T00:00:00Z", "content": "first message"},
            ]
        })
        .to_string(),
    );

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(accepted_receipt_response)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    let sent = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent, 1);
    assert_eq!(
        checkpoint
            .files
            .get(&session_path.to_string_lossy().to_string()),
        Some(&1),
        "gemini checkpoint tracks a record index, not a byte offset"
    );

    // No new messages yet: re-scanning must send nothing.
    let sent_again = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent_again, 0);

    // Gemini rewrites the whole file with the new message appended —
    // only the new one (past the checkpoint) should forward next cycle.
    write_file(
        &session_path,
        &serde_json::json!({
            "sessionId": "gemini-sess-1",
            "cwd": "/home/jmagar/workspace/cortex",
            "messages": [
                {"id": "m1", "timestamp": "2026-07-09T00:00:00Z", "content": "first message"},
                {"id": "m2", "timestamp": "2026-07-09T00:01:00Z", "content": "second message"},
            ]
        })
        .to_string(),
    );
    let sent_third = scan_and_forward(&config, &client, &mut checkpoint)
        .await
        .unwrap();
    assert_eq!(sent_third, 1);
    assert_eq!(
        checkpoint
            .files
            .get(&session_path.to_string_lossy().to_string()),
        Some(&2)
    );
}

#[tokio::test]
async fn scan_and_forward_replays_a_rewritten_gemini_acknowledged_prefix() {
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let gemini_dir = dir.path().join(".gemini/tmp/abc123/chats");
    fs::create_dir_all(&gemini_dir).unwrap();
    let session_path = gemini_dir.join("session-1.json");
    let session = |first: &str, include_second: bool| {
        let mut messages = vec![serde_json::json!({
            "id": "m1",
            "timestamp": "2026-07-09T00:00:00Z",
            "content": first,
        })];
        if include_second {
            messages.push(serde_json::json!({
                "id": "m2",
                "timestamp": "2026-07-09T00:01:00Z",
                "content": "second message",
            }));
        }
        serde_json::json!({
            "sessionId": "gemini-sess-1",
            "cwd": "/home/jmagar/workspace/cortex",
            "messages": messages,
        })
        .to_string()
    };
    write_file(&session_path, &session("first message", false));

    let server = wiremock::MockServer::start().await;
    let seen_ids = Arc::new(Mutex::new(HashSet::<String>::new()));
    let batches = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let response_seen_ids = seen_ids.clone();
    let response_batches = batches.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |request: &wiremock::Request| {
            let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let ids: Vec<String> = value["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["envelope"]["source_record_id"].as_str().unwrap().to_owned())
                .collect();
            response_batches.lock().unwrap().push(ids.clone());
            let mut seen = response_seen_ids.lock().unwrap();
            let receipts: Vec<_> = ids
                .into_iter()
                .map(|source_record_id| {
                    let disposition = if seen.insert(source_record_id.clone()) {
                        "accepted"
                    } else {
                        "duplicate"
                    };
                    serde_json::json!({"source_record_id": source_record_id, "disposition": disposition})
                })
                .collect();
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accepted": receipts.len(),
                "receipts": receipts,
            }))
        })
        .expect(3)
        .mount(&server)
        .await;

    let config = AiTranscriptForwardConfig {
        roots: vec![dir.path().to_path_buf()],
        target: server.uri(),
        token: None,
        hostname: "test-host".to_string(),
        checkpoint_path: dir.path().join("checkpoint.json"),
        poll_interval: Duration::from_secs(15),
    };
    let client = reqwest::Client::new();
    let mut checkpoint = Checkpoint::default();

    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );

    // A normal whole-file append keeps the acknowledged semantic prefix and
    // forwards only the newly added record.
    write_file(&session_path, &session("first message", true));
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpoint
            .files
            .get(&session_path.to_string_lossy().to_string()),
        Some(&2)
    );

    // Rewriting an already acknowledged record resets to zero. The unchanged
    // second record receives a duplicate receipt while the changed first
    // record is accepted; both exact IDs must let the checkpoint advance.
    write_file(&session_path, &session("rewritten first message", true));
    assert_eq!(
        scan_and_forward(&config, &client, &mut checkpoint)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        checkpoint
            .files
            .get(&session_path.to_string_lossy().to_string()),
        Some(&2)
    );

    let batches = batches.lock().unwrap();
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![1, 1, 2]
    );
    assert_ne!(
        batches[0][0], batches[2][0],
        "rewritten first record has a new identity"
    );
    assert_eq!(
        batches[1][0], batches[2][1],
        "unchanged second record is replayed idempotently"
    );
}
