use super::*;
use crate::app::SyslogService;
use crate::config::{McpConfig, StorageConfig};
use crate::db;
use crate::mcp::AppState;
use serde_json::json;
use std::sync::Arc;

fn test_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        AppState {
            service: SyslogService::new(pool, storage.clone()),
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "syslog-mcp".into(),
                api_token: None,
            },
        },
        dir,
    )
}

#[tokio::test]
async fn initialized_notification_dispatches_without_response() {
    let (state, _dir) = test_state();
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: None,
        method: "notifications/initialized".into(),
        params: Some(json!({})),
    };

    assert!(matches!(
        dispatch(&state, &req).await,
        DispatchResult::Notification
    ));
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

#[tokio::test]
async fn unknown_method_returns_json_rpc_error() {
    let (state, _dir) = test_state();
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(6)),
        method: "nonexistent/method".into(),
        params: None,
    };

    let response = match dispatch(&state, &req).await {
        DispatchResult::Response(response) => response,
        DispatchResult::Notification => panic!("unknown method must return response"),
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["error"]["code"].as_i64().unwrap(), -32601);
}
