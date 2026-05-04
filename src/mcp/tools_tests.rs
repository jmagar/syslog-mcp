use super::*;
use crate::config::{McpConfig, StorageConfig};
use crate::db;
use crate::mcp::AppState;
use serde_json::json;
use std::sync::Arc;

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

struct TestHarness {
    state: AppState,
    _dir: tempfile::TempDir,
}

impl TestHarness {
    fn new() -> Self {
        let (state, dir) = test_state_with_token(None);
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

#[test]
fn parse_optional_timestamp_normalizes_offsets_to_utc() {
    let parsed = parse_optional_timestamp(Some("2026-01-01T01:00:00+01:00"), "from")
        .unwrap()
        .unwrap();
    assert_eq!(parsed, "2026-01-01T00:00:00+00:00");
}

#[test]
fn parse_optional_timestamp_rejects_invalid_values() {
    let err = parse_optional_timestamp(Some("not-a-date"), "from").unwrap_err();
    assert!(err.to_string().contains("Invalid from"));
}
