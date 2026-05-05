use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::util::ServiceExt;

use crate::{
    app::LogService,
    config::{McpConfig, StorageConfig},
    db::{self, DbPool, LogBatchEntry},
    mcp::{streamable_http_config, streamable_http_service, AppState},
};

fn test_state() -> (AppState, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("rmcp-server-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let state = AppState {
        service: LogService::new(Arc::clone(&pool), storage.clone()),
        config: McpConfig {
            host: "127.0.0.1".into(),
            port: 3100,
            server_name: "syslog-mcp".into(),
            api_token: None,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
        },
    };
    (state, pool, dir)
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

fn rmcp_router(state: AppState) -> Router {
    let config = streamable_http_config(&state.config);
    Router::new().nest_service("/mcp", streamable_http_service(state, config))
}

fn jsonrpc_request(id: u64, method: &str, params: Option<Value>) -> Value {
    let mut req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });
    if let Some(params) = params {
        req.as_object_mut()
            .unwrap()
            .insert("params".to_string(), params);
    }
    req
}

async fn post_rmcp(router: Router, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn content_json(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn rmcp_tools_list_exposes_all_seven_tools() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(1, "tools/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tools = response["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    for expected in [
        "search_logs",
        "tail_logs",
        "get_errors",
        "list_hosts",
        "correlate_events",
        "get_stats",
        "syslog_help",
    ] {
        assert!(names.contains(&expected), "missing tool: {expected}");
    }
}

#[tokio::test]
async fn rmcp_get_stats_works_against_temp_db() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            2,
            "tools/call",
            Some(json!({"name": "get_stats", "arguments": {}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stats = content_json(&response);
    assert_eq!(stats["total_logs"], 0);
    assert!(stats.get("logical_db_size_mb").is_some());
}

#[tokio::test]
async fn rmcp_search_logs_works_against_seeded_data() {
    let (state, pool, _dir) = test_state();
    db::insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "err",
            "disk full",
            "10.0.0.1:514",
        )],
    )
    .unwrap();

    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            3,
            "tools/call",
            Some(json!({"name": "search_logs", "arguments": {"query": "disk", "limit": 5}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result = content_json(&response);
    assert_eq!(result["count"], 1);
    assert_eq!(result["logs"][0]["hostname"], "host-a");
}

#[tokio::test]
async fn rmcp_correlate_events_rejects_bad_reference_time_as_invalid_params() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            4,
            "tools/call",
            Some(json!({"name": "correlate_events", "arguments": {"reference_time": "bad"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["error"]["code"], -32602);
}

#[tokio::test]
async fn rmcp_correlate_events_rejects_bad_severity_as_invalid_params() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            5,
            "tools/call",
            Some(json!({
                "name": "correlate_events",
                "arguments": {
                    "reference_time": "2026-01-01T00:00:00Z",
                    "severity_min": "loud"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["error"]["code"], -32602);
}

#[tokio::test]
async fn rmcp_correlate_events_preserves_truncation_and_host_grouping() {
    let (state, pool, _dir) = test_state();
    db::insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "err",
                "disk full",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:01:00Z",
                "host-b",
                "warning",
                "service slow",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            6,
            "tools/call",
            Some(json!({
                "name": "correlate_events",
                "arguments": {
                    "reference_time": "2026-01-01T00:00:00Z",
                    "window_minutes": 5,
                    "severity_min": "warning",
                    "limit": 1
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result = content_json(&response);
    assert_eq!(result["total_events"], 1);
    assert_eq!(result["hosts_count"], 1);
    assert_eq!(result["truncated"], true);
}
