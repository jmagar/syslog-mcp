use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::*;
use crate::config::StorageConfig;
use crate::mcp::AuthPolicy;

fn test_app(token: Option<&str>) -> (Router, tempfile::TempDir) {
    test_app_with(
        token,
        AuthPolicy::Mounted { auth_state: None },
        SocketAddr::from(([10, 0, 0, 7], 41000)),
    )
}

fn test_app_with(
    token: Option<&str>,
    auth_policy: AuthPolicy,
    peer: SocketAddr,
) -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("ai-transcript-ingest-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let state = AiTranscriptIngestState::new(pool, token.map(str::to_string), auth_policy);
    let app = router(state).layer(MockConnectInfo(peer));
    (app, dir)
}

fn sample_record() -> serde_json::Value {
    serde_json::json!({
        "timestamp": "2026-07-09T00:00:00Z",
        "hostname": "devhost",
        "ai_tool": "claude",
        "ai_project": "/home/jmagar/workspace/cortex",
        "ai_session_id": "sess-1",
        "ai_transcript_path": "/home/jmagar/.claude/projects/-home-jmagar-workspace-cortex/sess-1.jsonl",
        "message": "test transcript line",
    })
}

#[tokio::test]
async fn forwarded_codex_skill_is_available_to_reflection_queries() {
    let (app, dir) = test_app(Some("secret"));
    let mut record = sample_record();
    record["ai_tool"] = json!("codex");
    record["message"] = json!("<skill><name>cortex:skill-improvement-assessment</name></skill>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(json!({"records": [record]}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let conn = rusqlite::Connection::open(dir.path().join("ai-transcript-ingest-test.db")).unwrap();
    let events: i64 = conn
        .query_row(
            "SELECT count(*) FROM ai_skill_events s JOIN logs l ON l.id = s.log_id
         WHERE s.skill_name = 'cortex:skill-improvement-assessment'
           AND s.ai_tool = 'codex' AND s.ai_session_id = 'sess-1'
           AND s.hostname = 'devhost' AND s.timestamp = l.timestamp",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        events, 1,
        "remote skill evidence must retain its source log and session"
    );
}

#[tokio::test]
async fn rejects_missing_bearer_token() {
    let (app, _dir) = test_app(Some("secret"));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"records":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn skill_projection_failure_rolls_back_the_forwarded_log() {
    let (app, dir) = test_app(Some("secret"));
    let conn = rusqlite::Connection::open(dir.path().join("ai-transcript-ingest-test.db")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_skill BEFORE INSERT ON ai_skill_events
         BEGIN SELECT RAISE(ABORT, 'test projection failure'); END;",
    )
    .unwrap();
    let mut record = sample_record();
    record["ai_tool"] = json!("codex");
    record["message"] = json!("<skill><name>test-skill</name></skill>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(json!({"records": [record]}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let count: i64 = conn
        .query_row("SELECT count(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 0,
        "agents must be able to retry without a partial write"
    );
}

#[tokio::test]
async fn ordinary_mentions_and_other_provider_text_do_not_become_codex_skill_events() {
    let (app, dir) = test_app(Some("secret"));
    let mut mention = sample_record();
    mention["ai_tool"] = json!("codex");
    mention["message"] = json!("Please use the test-skill skill from SKILL.md");
    let mut claude = sample_record();
    claude["message"] = json!("<skill><name>test-skill</name></skill>");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(
                    json!({"records": [mention, claude]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let conn = rusqlite::Connection::open(dir.path().join("ai-transcript-ingest-test.db")).unwrap();
    let counts: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM logs), (SELECT count(*) FROM ai_skill_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (2, 0));
}

#[tokio::test]
async fn loopback_dev_allows_unauthenticated_local_peer() {
    let (app, _dir) = test_app_with(
        None,
        AuthPolicy::LoopbackDev,
        SocketAddr::from(([127, 0, 0, 1], 41000)),
    );
    let body = serde_json::to_string(&serde_json::json!({"records": [sample_record()]})).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn accepts_batch_with_valid_bearer_token_and_inserts_rows() {
    let (app, _dir) = test_app(Some("secret"));
    let body = serde_json::to_string(&serde_json::json!({"records": [sample_record()]})).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(value["accepted"], 1);
}

#[tokio::test]
async fn rejects_batch_over_record_limit() {
    let (app, _dir) = test_app(Some("secret"));
    let records: Vec<_> = (0..MAX_RECORDS_PER_BATCH + 1)
        .map(|_| sample_record())
        .collect();
    let body = serde_json::to_string(&serde_json::json!({"records": records})).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn rejects_unknown_fields_in_record() {
    let (app, _dir) = test_app(Some("secret"));
    let mut record = sample_record();
    record
        .as_object_mut()
        .unwrap()
        .insert("bogus".to_string(), serde_json::json!(true));
    let body = serde_json::to_string(&serde_json::json!({"records": [record]})).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ai-transcripts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
