use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::Request;
use tower::util::ServiceExt;

use crate::config::{ApiConfig, StorageConfig};
use crate::db::{self, DbPool, LogBatchEntry};

use super::*;

fn test_state(token: Option<String>) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("api-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        ApiState {
            service: crate::app::LogService::new(Arc::clone(&pool), storage),
            config: ApiConfig {
                enabled: true,
                api_token: token,
            },
        },
        pool,
        dir,
    )
}

fn entry(ts: &str, host: &str, severity: &str, msg: &str, source_ip: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: None,
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: source_ip.to_string(),
    }
}

async fn get_json(
    app: axum::Router,
    uri: &str,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(builder.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[test]
fn router_requires_token_when_enabled() {
    let (mut state, _pool, _dir) = test_state(None);
    state.config.enabled = true;
    assert!(router(state).is_err());
}

#[test]
fn router_rejects_disabled_config_when_called_directly() {
    let (mut state, _pool, _dir) = test_state(Some("secret".into()));
    state.config.enabled = false;
    let err = match router(state) {
        Ok(_) => panic!("disabled API config should be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("disabled"));
}

#[tokio::test]
async fn stats_route_requires_bearer_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();

    let (status, _) = get_json(app.clone(), "/api/stats", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    let (status, value) = get_json(app, "/api/stats", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("total_logs").is_some());
}

#[tokio::test]
async fn correlate_route_returns_plain_api_json() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/correlate?reference_time=2026-01-01T00:00:00Z",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("content").is_none(),
        "API must not return MCP envelope"
    );
    assert_eq!(value["window_minutes"], 5);
}

#[tokio::test]
async fn search_route_returns_plain_api_json() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "err",
            "api search needle",
            "10.0.0.1:514",
        )],
    )
    .unwrap();

    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/search?query=needle", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("content").is_none(),
        "API must not return MCP envelope"
    );
    assert_eq!(value["count"], 1);
}

#[tokio::test]
async fn tail_route_returns_plain_api_json() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "info",
                "from one",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "host-b",
                "info",
                "from two",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let app = router(state).unwrap();
    let (status, value) =
        get_json(app, "/api/tail?source_ip=10.0.0.2:514&n=5", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("content").is_none(),
        "API must not return MCP envelope"
    );
    assert_eq!(value["count"], 1);
    assert_eq!(value["logs"][0]["message"], "from two");
}
