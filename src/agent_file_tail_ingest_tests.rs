use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::*;
use crate::config::StorageConfig;

fn app() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&StorageConfig::for_test(dir.path().join("tails.db"))).unwrap(),
    );
    let state = AgentFileTailIngestState::new(
        pool,
        Some("secret".into()),
        AuthPolicy::Mounted { auth_state: None },
    );
    (
        router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000)))),
        dir,
    )
}

fn record() -> serde_json::Value {
    serde_json::json!({
        "hostname": "devhost",
        "source_id": "app-log",
        "tag": "my-app",
        "path_basename": "app.log",
        "timestamp": "2026-09-02T12:00:00Z",
        "message": "request complete"
    })
}

async fn post(app: Router, value: serde_json::Value, authorized: bool) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/file-tails")
        .header(header::CONTENT_TYPE, "application/json");
    if authorized {
        builder = builder.header(header::AUTHORIZATION, "Bearer secret");
    }
    app.oneshot(builder.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn requires_bearer_authentication() {
    let (app, _dir) = app();
    assert_eq!(
        post(app, serde_json::json!({"records": []}), false)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn accepts_a_bounded_device_tail_record() {
    let (app, _dir) = app();
    let response = post(app, serde_json::json!({"records": [record()]}), true).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_forgeable_or_ambiguous_identity() {
    let (app, _dir) = app();
    let mut bad = record();
    bad["hostname"] = serde_json::json!("devhost/other");
    assert_eq!(
        post(app, serde_json::json!({"records": [bad]}), true)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn rejects_unknown_fields() {
    let (app, _dir) = app();
    let mut bad = record();
    bad["credential"] = serde_json::json!("must-not-be-accepted");
    assert_eq!(
        post(app, serde_json::json!({"records": [bad]}), true)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn rejects_batches_over_the_record_limit() {
    let (app, _dir) = app();
    let records = std::iter::repeat_with(record)
        .take(MAX_RECORDS_PER_BATCH + 1)
        .collect::<Vec<_>>();
    assert_eq!(
        post(app, serde_json::json!({"records": records}), true)
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[test]
fn maps_to_distinct_agent_file_tail_envelope() {
    let parsed: AgentFileTailRecord = serde_json::from_value(record()).unwrap();
    let entry = to_log_batch_entry(parsed).unwrap();
    assert_eq!(entry.source_ip, "agent-file-tail://devhost/app-log");
    assert_eq!(entry.hostname, "devhost");
    assert_eq!(entry.app_name.as_deref(), Some("my-app"));
    let metadata: serde_json::Value =
        serde_json::from_str(entry.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_kind"], "agent-file-tail");
    assert_eq!(metadata["path_basename"], "app.log");
}
