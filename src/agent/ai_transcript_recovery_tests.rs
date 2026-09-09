use super::*;

#[tokio::test]
async fn recovery_replays_live_reads_after_title_changes_against_real_receiver() {
    verify_recovery_replays(false).await;
}

#[tokio::test]
async fn recovery_upgrades_unknown_kind_read_receipt_without_identity_conflict() {
    verify_recovery_replays(true).await;
}

async fn verify_recovery_replays(seed_legacy: bool) {
    let dir = tempfile::tempdir().unwrap();
    let codex = dir.path().join(".codex");
    let root = codex.join("sessions");
    fs::create_dir_all(&root).unwrap();
    let state_path = codex.join("state_5.sqlite");
    let state_db = rusqlite::Connection::open(&state_path).unwrap();
    state_db.execute_batch("CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, name TEXT); INSERT INTO threads VALUES ('replay-session', 'Before', NULL);").unwrap();
    let path = root.join("rollout-2026-09-08T12-00-00-replay-session.jsonl");
    let record = serde_json::json!({
        "type":"event_msg", "timestamp":"2026-09-08T12:00:00Z", "session_id":"replay-session",
        "payload":{"type":"item_completed","item":{
            "type":"CommandExecution","status":"completed","exit_code":0,"aggregated_output":"skill content",
            "parsed_cmd":[{"type":"read","path":"/skills/limetech-ai-review/SKILL.md"}]
        }}
    });
    write_file(&path, &format!("{record}\n"));
    let mut storage = crate::config::StorageConfig::for_test(dir.path().join("receiver.db"));
    storage.pool_size = 4;
    let pool = std::sync::Arc::new(crate::db::init_pool(&storage).unwrap());
    let receiver = crate::ai_transcript_ingest::AiTranscriptIngestState::new(
        pool.clone(),
        None,
        Default::default(),
        crate::mcp::AuthPolicy::LoopbackDev,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            crate::ai_transcript_ingest::router(receiver)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let checkpoint_path = dir.path().join("checkpoint.json");
    let mut config =
        AiTranscriptForwardConfig::new(format!("http://{address}"), None, checkpoint_path.clone());
    config.roots = vec![root];
    if seed_legacy {
        let legacy = transcript_record(
            &config,
            &path,
            scanner::SourceKind::CodexSession,
            TranscriptRecordDetails {
                revision: format!("line:0:{record}"),
                timestamp: Some("2026-09-08T12:00:00Z".into()),
                ai_project: None,
                ai_session_id: Some("replay-session".into()),
                event_kind: Some("unknown".into()),
                message: "{\"cortex_skill_read\":\"limetech-ai-review\"}".into(),
                title: Some("Before".into()),
                title_provenance: Some("codex.generated".into()),
                diagnostics: Vec::new(),
            },
        );
        assert_eq!(
            send_records(&config, &reqwest::Client::new(), vec![legacy])
                .await
                .unwrap(),
            1
        );
    }
    let mut checkpoint = Checkpoint::default();
    assert_eq!(
        scan_and_forward(&config, &reqwest::Client::new(), &mut checkpoint)
            .await
            .unwrap(),
        1
    );
    let checkpoint_before = fs::read(&checkpoint_path).unwrap();
    let conn = pool.get().unwrap();
    let source: String = conn
        .query_row(
            "SELECT json_extract(metadata_json, '$.source.title') FROM logs",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        source, "Before",
        "fixture must exercise supplemental title lookup"
    );
    drop(conn);
    state_db
        .execute("UPDATE threads SET title='After'", [])
        .unwrap();
    assert_eq!(backfill_codex_skill_reads(config.clone()).await.unwrap(), 1);
    drop(state_db);
    fs::remove_file(state_path).unwrap();
    assert_eq!(backfill_codex_skill_reads(config).await.unwrap(), 1);
    let conn = pool.get().unwrap();
    let counts: (i64, i64, i64) = conn.query_row("SELECT (SELECT count(*) FROM logs), (SELECT count(*) FROM ai_skill_events WHERE event_kind='codex_skill_read'), (SELECT count(*) FROM ai_transcript_forward_receipts)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
    assert_eq!(
        counts,
        (1 + i64::from(seed_legacy), 1, 1 + i64::from(seed_legacy)),
        "real duplicate receipts must not insert evidence again"
    );
    assert_eq!(fs::read(checkpoint_path).unwrap(), checkpoint_before);
    server.abort();
    let _ = server.await;
}

#[test]
fn derived_skill_read_identity_is_versioned_but_source_revision_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollout-test.jsonl");
    write_file(&path, "original native completion\n");
    let config = AiTranscriptForwardConfig::new(
        "http://localhost".into(),
        None,
        dir.path().join("checkpoint"),
    );
    let make_record = |event_kind: &str| {
        transcript_record(
            &config,
            &path,
            scanner::SourceKind::CodexSession,
            TranscriptRecordDetails {
                revision: "line:0:original native completion".into(),
                timestamp: None,
                ai_project: None,
                ai_session_id: Some("session".into()),
                event_kind: Some(event_kind.into()),
                message: "{\"cortex_skill_read\":\"limetech-ai-review\"}".into(),
                title: None,
                title_provenance: None,
                diagnostics: Vec::new(),
            },
        )
    };
    let old = make_record("unknown").envelope;
    let new = make_record("codex_skill_read").envelope;
    let replay = make_record("codex_skill_read").envelope;
    assert_ne!(old.source_record_id, new.source_record_id);
    assert_eq!(old.source.source_revision, new.source.source_revision);
    assert_eq!(old.source.source_identity, new.source.source_identity);
    assert_eq!(new, replay);
}
