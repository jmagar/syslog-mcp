use super::*;
use axum::body::to_bytes;

fn test_state_with_token(token: Option<String>) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        AppState {
            pool,
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "syslog-mcp".into(),
                api_token: token,
            },
            storage,
        },
        dir,
    )
}

/// Owns both `AppState` and the `TempDir` backing the SQLite DB so the
/// directory cannot be accidentally dropped (e.g. via `let (state, _) = …`)
/// while the connection pool still holds the path.
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

#[tokio::test]
async fn tool_get_stats_returns_storage_guard_fields() {
    let h = TestHarness::new();
    let state = h.state;
    let value = tool_get_stats(&state, json!({})).await.unwrap();
    assert!(value.get("logical_db_size_mb").is_some());
    assert!(value.get("physical_db_size_mb").is_some());
    assert!(value.get("write_blocked").is_some());
    assert!(value.get("phantom_fts_rows").is_some());
}

#[tokio::test]
async fn initialized_notification_returns_no_jsonrpc_body() {
    let h = TestHarness::new();
    let state = h.state;
    let response = handle_mcp_post(
        State(state),
        Json(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/initialized".into(),
            params: Some(json!({})),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(body.is_empty());
}

#[test]
fn summarize_json_value_truncates_long_values() {
    let value = json!({"query": "x".repeat(80)});
    let summary = summarize_json_value(&value, 24);
    assert!(summary.len() <= 27);
    assert!(summary.ends_with('…'));
}

#[test]
fn summarize_json_value_handles_multibyte_utf8() {
    // Each Greek letter is 2 bytes; limit=5 falls inside the 3rd letter
    let value = json!("αβγδεζ");
    let summary = summarize_json_value(&value, 5);
    // Should not panic, should be valid UTF-8
    assert!(summary.is_char_boundary(summary.len()));
    assert!(summary.ends_with('…'));
}

// ---- Integration tests: HTTP-level through the axum router ----

mod integration_tests {
    use super::*;
    use axum::http::Request;
    use tower::util::ServiceExt;

    /// Build a JSON-RPC request body
    fn jsonrpc_request(
        id: u64,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> serde_json::Value {
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

    /// Send a POST /mcp request through the router and return (status, parsed body).
    /// Pass `auth` to include an `Authorization: Bearer <token>` header.
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
        for expected in &[
            "search_logs",
            "tail_logs",
            "get_errors",
            "list_hosts",
            "correlate_events",
            "get_stats",
        ] {
            assert!(names.contains(expected), "missing tool: {}", expected);
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
            "expected total_logs in: {}",
            content
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
        assert!(value["error"].is_null(), "unexpected error: {}", value);
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
        assert!(value["error"].is_null(), "unexpected error: {}", value);
    }

    #[tokio::test]
    async fn integration_unknown_method_returns_error() {
        let h = TestHarness::new();
        let body = jsonrpc_request(6, "nonexistent/method", None);
        let (status, value) = mcp_post(router(h.state), body, None).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(value["error"]["code"].as_i64().unwrap(), -32601);
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
}
