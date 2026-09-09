use super::*;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn write_file(path: &Path, content: &str) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

#[test]
fn collect_files_finds_supported_and_skips_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude/projects/foo");
    fs::create_dir_all(&claude_dir).unwrap();
    write_file(&claude_dir.join("session.jsonl"), "{}\n");
    write_file(&claude_dir.join("readme.txt"), "not a transcript\n");

    let mut out = Vec::new();
    collect_files(dir.path(), &mut out);
    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("session.jsonl"));
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
    collect_files(dir.path(), &mut out);

    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("rollout-session.jsonl"));
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
fn checkpoint_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint_path = dir.path().join("checkpoint.json");
    let mut checkpoint = Checkpoint::default();
    checkpoint.files.insert("/tmp/foo.jsonl".to_string(), 42);
    checkpoint.gemini_parse_failures.insert(
        "/tmp/bad-gemini.json".to_string(),
        GeminiParseFailure {
            fingerprint: 99,
            last_warned: Instant::now(),
        },
    );
    save_checkpoint(&checkpoint_path, &checkpoint).unwrap();

    let loaded = load_checkpoint(&checkpoint_path);
    assert_eq!(loaded.files.get("/tmp/foo.jsonl"), Some(&42));
    assert!(
        loaded.gemini_parse_failures.is_empty(),
        "parse-warning suppression is process-local and must not be persisted"
    );
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
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1})),
        )
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
async fn scan_and_forward_retries_without_event_kind_for_legacy_server() {
    let dir = tempfile::tempdir().unwrap();
    let transcript_path = dir.path().join("session.jsonl");
    write_file(
        &transcript_path,
        &format!(
            "{}\n",
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-07-09T00:00:00Z",
                "sessionId": "sess-legacy",
                "message": {"role": "user", "content": "compatibility proof"}
            })
        ),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/ai-transcripts"))
        .respond_with(move |request: &wiremock::Request| {
            let call = observed.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            if call == 0 {
                assert!(body["records"][0].get("event_kind").is_some());
                wiremock::ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_payload",
                    "message": "unknown field `event_kind`"
                }))
            } else {
                assert!(body["records"][0].get("event_kind").is_none());
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"accepted": 1}))
            }
        })
        .expect(2)
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
    let mut checkpoint = Checkpoint::default();
    assert_eq!(
        scan_and_forward(&config, &reqwest::Client::new(), &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        checkpoint.files[&transcript_path.to_string_lossy().to_string()],
        1
    );
}

#[tokio::test]
async fn scan_and_forward_preserves_codex_prefix_metadata_after_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let codex_dir = dir.path().join(".codex/sessions/2026/07/12");
    fs::create_dir_all(&codex_dir).unwrap();
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
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1}))
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
    let record = &request.records[0];
    assert_eq!(record.ai_tool, "codex");
    assert_eq!(
        record.ai_project.as_deref(),
        Some("/home/jmagar/workspace/cortex")
    );
    assert_eq!(record.ai_session_id.as_deref(), Some("codex-sess-1"));
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
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1}))
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
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1})),
        )
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
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1})),
        )
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
