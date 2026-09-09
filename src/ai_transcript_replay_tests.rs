use super::*;

#[tokio::test]
async fn title_changes_and_missing_metadata_are_duplicate_replays() {
    let (app, dir) = test_app(Some("secret"));
    for title in [Some("Before"), Some("After"), None] {
        let mut record = sample_record();
        record["envelope"]["source"]["title"] = json!(title);
        record["envelope"]["source"]["title_provenance"] = json!(title.map(|_| "codex_state"));
        let response = app
            .clone()
            .oneshot(transcript_request(json!({"records": [record]}).to_string()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if title != Some("Before") {
            assert_eq!(body["receipts"][0]["disposition"], "duplicate");
        }
    }
    let conn = rusqlite::Connection::open(dir.path().join("ai-transcript-ingest-test.db")).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn old_full_envelope_receipt_accepts_title_only_changes_but_not_evidence_changes() {
    check_old_receipt_replay(false).await;
    check_old_receipt_replay(true).await;
}

async fn check_old_receipt_replay(timestamp_absent: bool) {
    use sha2::{Digest, Sha256};
    let (app, dir) = test_app(Some("secret"));
    let mut original = sample_record();
    if timestamp_absent {
        original["envelope"]["timestamp"] = serde_json::Value::Null;
    }
    let envelope: EvidenceEnvelope = serde_json::from_value(original["envelope"].clone()).unwrap();
    let scrubbed = scrub_envelope(envelope).unwrap();
    let old_hash = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&scrubbed).unwrap())
    );
    let first = app
        .clone()
        .oneshot(transcript_request(
            json!({"records": [original]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let conn = rusqlite::Connection::open(dir.path().join("ai-transcript-ingest-test.db")).unwrap();
    conn.execute(
        "UPDATE ai_transcript_forward_receipts SET request_fingerprint = ?1",
        [&old_hash],
    )
    .unwrap();
    // Bounded canonical metadata may be unavailable; an exact old request
    // must still be a duplicate, using its stored fingerprint as proof.
    let metadata: String = conn
        .query_row("SELECT metadata_json FROM logs", [], |r| r.get(0))
        .unwrap();
    conn.execute(
        "UPDATE logs SET metadata_json = '{\"metadata_truncated\":true}'",
        [],
    )
    .unwrap();
    let exact = app
        .clone()
        .oneshot(transcript_request(
            json!({"records": [original.clone()]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(exact.status(), StatusCode::OK);
    conn.execute("UPDATE logs SET metadata_json = ?1", [metadata])
        .unwrap();
    // Restore the old receipt to independently qualify title-change upgrade.
    conn.execute(
        "UPDATE ai_transcript_forward_receipts SET request_fingerprint = ?1",
        [&old_hash],
    )
    .unwrap();
    let mut replay = sample_record();
    if timestamp_absent {
        replay["envelope"]["timestamp"] = serde_json::Value::Null;
    }
    replay["envelope"]["source"]["title"] = json!("Renamed");
    let renamed = app
        .clone()
        .oneshot(transcript_request(
            json!({"records": [replay.clone()]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(renamed.status(), StatusCode::OK);
    replay["envelope"]["message"] = json!("different evidence");
    let changed = app
        .oneshot(transcript_request(json!({"records": [replay]}).to_string()))
        .await
        .unwrap();
    assert_eq!(changed.status(), StatusCode::CONFLICT);
}
