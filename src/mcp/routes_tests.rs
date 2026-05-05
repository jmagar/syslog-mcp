use super::*;
use crate::app::LogService;
use crate::config::{McpConfig, StorageConfig};
use crate::db;
use crate::mcp::AppState;
use axum::body::to_bytes;
use axum::http::Request;
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_state_with_token(token: Option<String>) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        AppState {
            service: LogService::new(pool, storage.clone()),
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "syslog-mcp".into(),
                api_token: token,
            },
        },
        dir,
    )
}

struct TestHarness {
    state: AppState,
    _dir: tempfile::TempDir,
}

impl TestHarness {
    fn new() -> Self {
        let (state, dir) = test_state_with_token(None);
        TestHarness { state, _dir: dir }
    }

    fn with_token(token: String) -> Self {
        let (state, dir) = test_state_with_token(Some(token));
        TestHarness { state, _dir: dir }
    }
}

fn jsonrpc_request(id: u64, method: &str, params: Option<serde_json::Value>) -> serde_json::Value {
    let mut req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });
    if let Some(p) = params {
        req.as_object_mut().unwrap().insert("params".into(), p);
    }
    req
}

async fn mcp_post(
    app: Router,
    body: serde_json::Value,
    auth: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Content-Type", "application/json");
    if let Some(token) = auth {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn integration_health_returns_200() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn integration_initialize() {
    let h = TestHarness::new();
    let body = jsonrpc_request(1, "initialize", None);
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value["result"]["protocolVersion"].is_string());
    assert!(value["result"]["serverInfo"]["name"].is_string());
}

#[tokio::test]
async fn integration_tools_list() {
    let h = TestHarness::new();
    let body = jsonrpc_request(2, "tools/list", None);
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let tools = value["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "search_logs",
        "tail_logs",
        "get_errors",
        "list_hosts",
        "correlate_events",
        "get_stats",
    ] {
        assert!(names.contains(&expected), "missing tool: {expected}");
    }
}

#[tokio::test]
async fn integration_get_stats() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        3,
        "tools/call",
        Some(serde_json::json!({"name": "get_stats", "arguments": {}})),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let content = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        content.contains("total_logs"),
        "expected total_logs in: {content}"
    );
}

#[tokio::test]
async fn integration_tail_logs_empty_db() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        4,
        "tools/call",
        Some(serde_json::json!({"name": "tail_logs", "arguments": {"n": 10}})),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value["error"].is_null(), "unexpected error: {value}");
}

#[tokio::test]
async fn integration_search_logs_empty_db() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        5,
        "tools/call",
        Some(
            serde_json::json!({"name": "search_logs", "arguments": {"query": "error", "limit": 5}}),
        ),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value["error"].is_null(), "unexpected error: {value}");
}

#[tokio::test]
async fn integration_auth_missing_token_returns_401() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(7, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn integration_auth_correct_token_succeeds() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(8, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("secret-token")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn mcp_rejects_wrong_token() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(9, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("wrong-token")).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sse_requires_token_when_auth_enabled() {
    let h = TestHarness::with_token("secret-token".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/sse")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

    let request = Request::builder()
        .method("GET")
        .uri("/sse")
        .header("Authorization", "Bearer secret-token")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn health_stays_unauthenticated_when_auth_enabled() {
    let h = TestHarness::with_token("secret-token".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn oversized_mcp_request_is_rejected_by_body_limit() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from("x".repeat(70_000)))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
}
