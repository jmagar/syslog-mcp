use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, header};
use tower::util::ServiceExt;

use crate::config::{ApiConfig, StorageConfig};
use crate::db::{self, DbPool, LogBatchEntry, insert_logs_batch};
use crate::mcp::AuthPolicy;

use super::*;

#[test]
fn documented_rest_route_count_matches_router_registrations() {
    let binding_count = crate::surfaces::api_bindings().count();
    assert_eq!(binding_count, 93, "update the documented API denominator");
    assert!(include_str!("../docs/api.md").contains("93 method/path bindings total"));
    assert!(include_str!("../docs/architecture.md").contains("(93 method/path bindings)"));
}

/// Build the router for a test, layering a `MockConnectInfo` so handlers
/// extracting `ConnectInfo<SocketAddr>` (e.g. `ai_prune_checkpoints`) work
/// under `tower::ServiceExt::oneshot`. Production wires `ConnectInfo` via
/// `into_make_service_with_connect_info` at `src/main.rs:565`.
fn test_router(state: ApiState) -> axum::Router {
    router(state)
        .unwrap()
        .layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 99], 65000))))
}

/// Build an ApiState. The /api/* router forces bearer enforcement regardless
/// of the supplied AuthPolicy (see `router()`), so tests can use whichever
/// variant most closely matches the production wiring they care about.
fn test_state(token: Option<String>) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    test_state_with_policy(token, AuthPolicy::Mounted { auth_state: None })
}

#[tokio::test]
async fn every_contract_api_method_path_is_actually_mounted() {
    use crate::surfaces::{HttpMethod, api_bindings};
    for binding in api_bindings() {
        let (state, _, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
        let app = test_router(state);
        let path = binding
            .path
            .replace("{id}", "1")
            .replace("{repository_id}", "1")
            .replace("{run_key}", "contract-probe");
        let method = match binding.method {
            HttpMethod::Get => axum::http::Method::GET,
            HttpMethod::Post => axum::http::Method::POST,
        };
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Dynamic resource routes may legitimately return a JSON 404 for this
        // synthetic probe when the temporary database lacks that resource.
        // Axum's unmatched-route fallback has no JSON content type, so keep
        // the construction audit without requiring seeded state for every
        // contracted dynamic path.
        assert!(
            response.status() != axum::http::StatusCode::NOT_FOUND
                || response.headers().contains_key(header::CONTENT_TYPE),
            "{:?} {} is contracted but not mounted",
            binding.method,
            binding.path
        );
        assert_ne!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            "{:?} {} has wrong mounted method",
            binding.method,
            binding.path
        );
    }
}

fn test_state_with_policy(
    token: Option<String>,
    auth_policy: AuthPolicy,
) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    test_state_full(token, auth_policy, Vec::new())
}

fn test_state_with_origins(
    token: Option<String>,
    allowed_origins: Vec<String>,
) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    test_state_full(
        token,
        AuthPolicy::Mounted { auth_state: None },
        allowed_origins,
    )
}

fn test_state_with_admin(
    token: Option<String>,
    admin_token: impl Into<String>,
) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    let (mut state, pool, dir) = test_state(token);
    state.config.admin_token = crate::config::Secret(Some(admin_token.into()));
    (state, pool, dir)
}

fn test_state_full(
    token: Option<String>,
    auth_policy: AuthPolicy,
    allowed_origins: Vec<String>,
) -> (ApiState, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("api-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let file_tail_registry = Arc::new(crate::filetail::FileTailRegistry::new(
        dir.path().join("file-tails.json"),
    ));
    let service = crate::app::CortexService::new(Arc::clone(&pool), storage)
        .with_file_tail_control(file_tail_registry, Arc::new(|| Ok(())), Arc::new(Vec::new));
    // Every test gets a fresh per-state maintenance permit so parallel tests
    // never contend on the process-wide `SHARED_MAINTENANCE_PERMIT` — see
    // `ApiState::with_isolated_maintenance_permit` docs.
    let state = ApiState::new(
        service,
        ApiConfig {
            api_token: crate::config::Secret(token),
            admin_token: crate::config::Secret(None),
        },
        3100,
        true,
        allowed_origins,
        auth_policy,
        false, // static_token_is_admin: read-only in tests
        crate::config::NotificationsConfig::default(),
        crate::stream::CursorKeys::resolved(Some("api-test-key"), &[], true).unwrap(),
        crate::api::resolved_integration_profile(&crate::config::Config::default()).unwrap(),
    )
    .expect("ApiState::new should succeed against a fresh pool")
    .with_isolated_maintenance_permit();
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
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: None,
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

fn refresh_graph_projection_for_test(pool: &DbPool) {
    let _guard = crate::db::graph::GRAPH_TEST_LOCK.lock();
    crate::db::graph::refresh_graph_projection(pool).unwrap();
}

async fn get_json(
    app: axum::Router,
    uri: &str,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let response = get_response(app, uri, token).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn get_response(
    app: axum::Router,
    uri: &str,
    token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    app.oneshot(builder.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn agent_observatory_routes_are_bearer_protected_and_return_bounded_pages() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    pool.get()
        .unwrap()
        .execute(
            "INSERT INTO repositories
                (repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at)
             VALUES ('repo-one','host','/workspace/repo/.git','/workspace/repo','repo',?1,?1)",
            ["2026-09-02T12:00:00.000Z"],
        )
        .unwrap();
    let app = test_router(state);
    let (status, _) = get_json(app.clone(), "/api/repositories", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let (status, body) = get_json(app.clone(), "/api/repositories?limit=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["repositories"][0]["key"], "repo-one");
    assert_eq!(body["repositories"][0]["id"], "1");
    assert!(body.get("items").is_none());
    assert_eq!(body["pagination"]["limit"], 1);
    let (status, body) = get_json(
        app.clone(),
        "/api/repositories?limit=999999",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["pagination"]["limit"], 200);
    let (status, _) = get_json(
        app.clone(),
        "/api/repositories?unexpected=yes",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    let (status, body) = get_json(
        app,
        "/api/agent-runs?status=active&status=idle",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["pagination"]["limit"], 50);
    assert!(body["runs"].is_array());
    assert!(body.get("items").is_none());
}

#[test]
fn router_requires_token() {
    let (state, _pool, _dir) = test_state(None);
    let err = router(state).expect_err("missing token must abort router construction");
    let msg = err.to_string();
    assert!(
        msg.contains("CORTEX_API_TOKEN"),
        "error must mention the missing env var: {msg}"
    );
    assert!(
        msg.contains("cortex setup repair"),
        "error must include recovery hint: {msg}"
    );
}

#[tokio::test]
async fn stats_route_requires_bearer_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    let (status, _) = get_json(app.clone(), "/api/stats", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    let (status, value) = get_json(app, "/api/stats", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("total_logs").is_some());
}

fn artifact_evidence_body(event_id: &str, artifact_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "dinglebear.cortex-artifact-evidence/v1",
        "eventId": event_id,
        "eventKind": "runtime_call",
        "sourceSystem": "labby",
        "sourceIssuer": "gateway:personal/jake",
        "observedAt": "2026-08-19T12:00:00-04:00",
        "artifactId": artifact_id,
        "revisionId": "revision-rest-1",
        "contentDigest": format!("sha256:{}", "a".repeat(64)),
        "requestId": "req-rest-1",
        "correlationId": "corr-rest-1",
        "targetId": "target-node-a",
        "operationRef": "mcp:tools/call",
        "outcome": "success",
        "metadata": {
            "durationMs": 21,
            "resultBytes": 84,
            "message": "result sk-super-secret"
        }
    })
}

#[tokio::test]
async fn artifact_evidence_rest_admin_write_and_read_query_share_service_contract() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let body = artifact_evidence_body("evt-rest-1", "artifact-rest-1");

    // Admin authorization is checked before artifact-envelope parsing. Even a
    // body that cannot deserialize as ArtifactEvidenceInput must return the
    // admin denial rather than a parser error when the admin token is absent.
    let (status, value) = post_json(
        app.clone(),
        "/api/artifact-evidence",
        serde_json::json!({"requestBody": "not an evidence envelope"}),
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "X-Cortex-Admin-Token required for admin API actions"
    );

    let (status, value) = post_json(
        app.clone(),
        "/api/artifact-evidence",
        body.clone(),
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "X-Cortex-Admin-Token required for admin API actions"
    );

    let (status, recorded) = post_json_with_admin(
        app.clone(),
        "/api/artifact-evidence",
        body,
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "response: {recorded}");
    assert_eq!(recorded["inserted"], true);
    assert!(recorded["cortexLogId"].as_i64().unwrap() > 0);
    assert_eq!(recorded["event"]["observedAt"], "2026-08-19T16:00:00.000Z");
    assert_eq!(
        recorded["event"]["metadata"]["message"],
        "result [REDACTED]"
    );

    let (status, queried) = get_json(
        app,
        "/api/artifact-evidence?artifactId=artifact-rest-1&correlationId=corr-rest-1",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "response: {queried}");
    assert_eq!(queried["events"].as_array().unwrap().len(), 1);
    assert_eq!(queried["events"][0]["eventId"], "evt-rest-1");
    assert_eq!(queried["events"][0]["artifactId"], "artifact-rest-1");
    assert_eq!(queried["truncated"], false);

    let oversized = serde_json::json!({
        "padding": "x".repeat(crate::artifact_evidence::MAX_EVIDENCE_WIRE_BYTES + 1)
    });
    let (status, oversized_response) = post_json_with_admin(
        test_router(test_state_with_admin(Some("secret".into()), "admin-secret").0),
        "/api/artifact-evidence",
        oversized,
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        oversized_response["error"],
        "artifact_evidence_body_too_large"
    );
}

#[tokio::test]
async fn artifact_evidence_rest_requires_json_content_type_after_admin_auth() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/artifact-evidence")
        .header("Authorization", "Bearer secret")
        .header("X-Cortex-Admin-Token", "admin-secret")
        .body(axum::body::Body::from(
            artifact_evidence_body("evt-rest-content-type", "artifact-rest-ct").to_string(),
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"], "artifact_evidence_requires_json");
}

#[tokio::test]
async fn artifact_evidence_rest_replay_conflict_and_malformed_metadata_fail_closed() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let body = artifact_evidence_body("evt-rest-replay", "artifact-rest-1");

    let (status, first) = post_json_with_admin(
        app.clone(),
        "/api/artifact-evidence",
        body.clone(),
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "response: {first}");
    let first_id = first["cortexLogId"].as_i64().unwrap();

    let (status, replay) = post_json_with_admin(
        app.clone(),
        "/api/artifact-evidence",
        body.clone(),
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "response: {replay}");
    assert_eq!(replay["inserted"], false);
    assert_eq!(replay["cortexLogId"], first_id);

    let mut conflict = body.clone();
    conflict["targetId"] = serde_json::json!("target-node-b");
    let (status, conflict_response) = post_json_with_admin(
        app.clone(),
        "/api/artifact-evidence",
        conflict,
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    assert_eq!(conflict_response["error"], "constraint_violation");
    assert_eq!(
        conflict_response["detail"],
        "artifact_evidence_event_id_conflict"
    );

    let mut malformed = artifact_evidence_body("evt-rest-bad", "artifact-rest-2");
    malformed["metadata"] = serde_json::json!({"requestBody": "raw tool payload"});
    let (status, malformed_response) = post_json_with_admin(
        app,
        "/api/artifact-evidence",
        malformed,
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert!(
        malformed_response["error"]
            .as_str()
            .is_some_and(|error| error.contains("forbidden")),
        "response: {malformed_response}"
    );
}

#[tokio::test]
async fn file_tails_route_adds_and_lists_sources() {
    let (mut state, _pool, dir) = test_state(Some("secret".into()));
    state.config.admin_token = crate::config::Secret(Some("admin-secret".into()));
    let app = test_router(state);
    let log_path = dir.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let body = serde_json::json!({
        "op": "add",
        "id": "swag-access",
        "path": log_path,
        "tag": "swag-access",
        "host": "edgehost",
        "facility": "local4",
        "severity": "info",
        "start_at_end": true
    });

    let (status, _value) =
        post_json(app.clone(), "/api/file-tails", body.clone(), Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    let (status, value) = post_json_with_admin(
        app.clone(),
        "/api/file-tails",
        body,
        Some("secret"),
        Some("admin-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "response: {value}");
    assert_eq!(value["sources"].as_array().unwrap().len(), 1);
    assert_eq!(value["sources"][0]["id"], "swag-access");

    let (status, value) = post_json_with_admin(
        app,
        "/api/file-tails",
        serde_json::json!({ "op": "list" }),
        Some("secret"),
        Some("admin-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "response: {value}");
    assert_eq!(value["sources"].as_array().unwrap().len(), 1);
    assert_eq!(value["sources"][0]["tag"], "swag-access");
}

#[tokio::test]
async fn file_tails_route_rejects_when_server_admin_token_unconfigured() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    let (status, value) = post_json_with_admin(
        app,
        "/api/file-tails",
        serde_json::json!({ "op": "status" }),
        Some("secret"),
        Some("admin-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "CORTEX_API_ADMIN_TOKEN required for admin API actions"
    );
}

#[tokio::test]
async fn file_tails_route_rejects_blank_server_admin_token() {
    let (mut state, _pool, _dir) = test_state(Some("secret".into()));
    state.config.admin_token = crate::config::Secret(Some("   ".into()));
    let app = test_router(state);

    let (status, value) = post_json_with_admin(
        app,
        "/api/file-tails",
        serde_json::json!({ "op": "status" }),
        Some("secret"),
        Some(""),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "CORTEX_API_ADMIN_TOKEN required for admin API actions"
    );
}

#[tokio::test]
async fn file_tails_route_rejects_wrong_admin_token() {
    let (mut state, _pool, _dir) = test_state(Some("secret".into()));
    state.config.admin_token = crate::config::Secret(Some("admin-secret".into()));
    let app = test_router(state);

    let (status, value) = post_json_with_admin(
        app,
        "/api/file-tails",
        serde_json::json!({ "op": "status" }),
        Some("secret"),
        Some("wrong-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "X-Cortex-Admin-Token required for admin API actions"
    );
}

#[tokio::test]
async fn notifications_test_rest_route_uses_service_instead_of_501_stub() {
    let (mut state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    state.notifications_config = crate::config::NotificationsConfig {
        apprise_url: "http://127.0.0.1:1".to_string(),
        apprise_urls: vec!["gotify://token@example.test".to_string()],
        ..crate::config::NotificationsConfig::default()
    };
    let app = test_router(state);

    let (status, value) = post_json_admin(
        app,
        "/api/notifications/test",
        serde_json::json!({ "body": "live-cli-sweep" }),
    )
    .await;

    assert_ne!(status, axum::http::StatusCode::NOT_IMPLEMENTED);
    assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(value["error"], "internal_error");
}

#[tokio::test]
async fn error_ack_routes_reject_normal_bearer_without_admin_token() {
    let (mut state, _pool, _dir) = test_state(Some("secret".into()));
    state.config.admin_token = crate::config::Secret(Some("admin-secret".into()));
    let app = test_router(state);
    let hash = "0".repeat(64);

    for (path, body) in [
        (
            "/api/errors/ack",
            serde_json::json!({ "signature_hash": hash, "notes": "handled" }),
        ),
        (
            "/api/errors/unack",
            serde_json::json!({ "signature_hash": hash, "reason": "regressed" }),
        ),
    ] {
        let (status, value) = post_json(app.clone(), path, body, Some("secret")).await;

        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{path}: {value}");
        assert_eq!(
            value["error"],
            "X-Cortex-Admin-Token required for admin API actions"
        );
    }
}

#[tokio::test]
async fn stats_route_accepts_case_insensitive_bearer_scheme() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/stats")
        .header("Authorization", "bearer secret")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn api_routes_emit_cors_for_configured_port() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/stats")
        .header("Authorization", "Bearer secret")
        .header("Origin", "http://localhost:3100")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:3100"
    );
}

#[tokio::test]
async fn api_cors_preflight_allows_only_required_request_headers() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/stats")
        .header("Origin", "http://localhost:3100")
        .header("Access-Control-Request-Method", "GET")
        .header(
            "Access-Control-Request-Headers",
            "authorization,accept,x-cortex-admin-token,x-unexpected-header",
        )
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let allowed = response
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allowed.contains("authorization"));
    assert!(allowed.contains("accept"));
    assert!(allowed.contains("x-cortex-admin-token"));
    assert!(
        !allowed.contains("x-unexpected-header"),
        "CORS allow-headers must not reflect arbitrary request headers: {allowed}"
    );
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
async fn filter_route_rejects_query_param() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();

    let (status, _value) = get_json(app, "/api/filter?query=needle", Some("secret")).await;

    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn filter_route_transcript_source_kind_excludes_agent_commands() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    let mut transcript = entry(
        "2026-01-01T00:00:00Z",
        "host-a",
        "info",
        "api transcript row",
        "transcript://codex",
    );
    transcript.app_name = Some("codex-transcript".into());
    transcript.facility = Some("transcript".into());
    transcript.ai_tool = Some("codex".into());
    transcript.ai_project = Some("/tmp/project".into());
    transcript.ai_session_id = Some("sess-1".into());
    transcript.ai_transcript_path = Some("/tmp/project/sess-1.jsonl".into());

    let mut agent_command = entry(
        "2026-01-01T00:00:01Z",
        "host-a",
        "info",
        "api agent command row",
        "agent-command://host-a/codex/sess-1",
    );
    agent_command.ai_tool = Some("codex".into());
    agent_command.ai_project = Some("/tmp/project".into());
    agent_command.ai_session_id = Some("sess-1".into());

    db::insert_logs_batch(&pool, &[transcript, agent_command]).unwrap();

    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/filter?source_kind=transcript&tool=codex&project=%2Ftmp%2Fproject&session_id=sess-1",
        Some("secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(value["count"], 1);
    assert_eq!(value["logs"][0]["message"], "api transcript row");
    assert_eq!(value["logs"][0]["source_ip"], "transcript://codex");
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
    let (status, value) = get_json(app, "/api/tail?source=10.0.0.2:514&n=5", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("content").is_none(),
        "API must not return MCP envelope"
    );
    assert_eq!(value["count"], 1);
    assert_eq!(value["logs"][0]["message"], "from two");
}

#[tokio::test]
async fn feed_route_is_cursor_based_host_filtered_and_includes_raw() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "info",
                "first",
                "source-a",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "host-b",
                "info",
                "other",
                "source-b",
            ),
            entry(
                "2026-01-01T00:00:02Z",
                "host-a",
                "warning",
                "third",
                "source-a",
            ),
            entry(
                "2026-01-01T00:00:03Z",
                "host-b",
                "info",
                "fourth",
                "source-b",
            ),
        ],
    )
    .unwrap();

    let app = router(state).unwrap();
    let (status, first) = get_json(
        app.clone(),
        "/api/feed?after_id=0&host=host-a&limit=1",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{first}");
    assert_eq!(first["logs"][0]["message"], "first");
    assert_eq!(first["logs"][0]["raw"], "first");
    assert_eq!(first["has_more"], true);

    let cursor = first["next_after_id"].as_i64().unwrap();
    let (status, second) = get_json(
        app.clone(),
        &format!("/api/feed?after_id={cursor}&host=host-a&limit=10"),
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{second}");
    assert_eq!(second["logs"].as_array().unwrap().len(), 1);
    assert_eq!(second["logs"][0]["message"], "third");
    assert_eq!(second["has_more"], false);
    assert!(second["next_after_id"].as_i64().unwrap() > second["logs"][0]["id"].as_i64().unwrap());

    let (status, current) = get_json(app, "/api/feed?host=host-a", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{current}");
    assert!(current["logs"].as_array().unwrap().is_empty());
    assert_eq!(current["next_after_id"], second["next_after_id"]);
}

// ── AuthPolicy coverage on /api/* ────────────────────────────────────────────

/// Mounted static-bearer: wrong token → 401 (no fall-through to permit).
#[tokio::test]
async fn api_wrong_token_returns_401_no_fallthrough() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/stats", Some("wrong")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "AuthLayer must not fall through on bad token"
    );
}

/// Mounted static-bearer: no credentials → 401 (fail-closed).
#[tokio::test]
async fn api_missing_credentials_returns_401_fail_closed() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/stats", None).await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "missing credentials must be rejected, not permitted"
    );
}

/// Mounted: session cookie without Authorization header is rejected (bearer-only).
#[tokio::test]
async fn api_cookie_without_bearer_is_rejected() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/stats")
        .header("Cookie", "session=some-session-id")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "session cookie must not bypass bearer-only AuthLayer on /api/*"
    );
}

// ── /api/version + force-bearer-on-loopback + schema_version cache ────────────

#[test]
fn version_info_serializes_optional_fleet_identity() {
    let value = serde_json::to_value(VersionInfo {
        version: "1.2.3",
        git_sha: None,
        schema_version: 48,
        instance_id: Some("instance".into()),
        deployment_id: Some("sha256:image".into()),
        database_fingerprint: Some("db-fingerprint".into()),
        compose_project: Some("project".into()),
        compose_service: Some("candidate".into()),
        compose_container: Some("project-candidate-1".into()),
        fleet_allowlist: vec!["instance".into()],
        capabilities: vec!["read".into(), "admin".into()],
    })
    .unwrap();
    assert_eq!(value["instance_id"], "instance");
    assert_eq!(value["compose_service"], "candidate");
    assert_eq!(value["capabilities"], serde_json::json!(["read", "admin"]));
}

/// `/api/version` returns 200 with a well-formed payload when authenticated.
/// Verifies the cached `version_info` is rendered, not re-queried.
#[tokio::test]
async fn version_route_returns_payload_with_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/version", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        value.get("schema_version").is_some(),
        "schema_version must be present"
    );
    assert!(
        value["schema_version"].as_i64().unwrap() >= 0,
        "schema_version must be a non-negative integer"
    );
}

#[tokio::test]
async fn capabilities_advertise_bounded_polling_and_native_streams() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let (status, value) = get_json(test_router(state), "/api/capabilities", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["contract_version"], "1.0.0");
    assert_eq!(value["generation"], 1);
    assert_eq!(value["sessions"]["rendered_pages"], true);
    assert_eq!(value["sessions"]["native_stream"], true);
    assert_eq!(value["logs"]["native_stream"], true);
    assert_eq!(value["sessions"]["stream"]["max_batch_items"], 100);
    assert_eq!(value["logs"]["stream"]["max_batch_bytes"], 131_072);
    assert_eq!(value["sessions"]["polling"]["max_page_items"], 200);
    assert_eq!(value["sessions"]["polling"]["max_page_bytes"], 262_144);
}

#[tokio::test]
async fn runtime_integration_identity_matches_contract_and_mounted_routes() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let (status, value) = get_json(
        test_router(state),
        "/api/integration-profile",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["contract_version"], "1.0.0");
    assert_eq!(value["product"], "cortex");
    assert!(value["server_id"].as_str().unwrap().starts_with("cortex_"));
    assert_eq!(value["api_version"]["major"], 1);
    assert_eq!(value["streams"]["transport"], "sse");
    assert_eq!(value["streams"]["resume"], "opaque_cursor");
    assert_eq!(
        value["route_support"],
        serde_json::json!(["logs", "sessions", "fleet", "graph", "correlation"])
    );
    assert!(
        value["auth"]["modes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mode| mode == "static_bearer")
    );
    assert_ne!(value["auth"]["credential_generation"], "secret");
}

#[tokio::test]
async fn palette_integration_identity_alias_matches_canonical_profile() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (canonical_status, canonical) =
        get_json(app.clone(), "/api/integration-profile", Some("secret")).await;
    let (alias_status, alias) = get_json(app, "/v1/integration/identity", Some("secret")).await;

    assert_eq!(canonical_status, axum::http::StatusCode::OK);
    assert_eq!(alias_status, axum::http::StatusCode::OK);
    assert_eq!(alias, canonical);
}

#[tokio::test]
async fn palette_integration_identity_alias_requires_bearer_auth() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let (status, _) = get_json(test_router(state), "/v1/integration/identity", None).await;

    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[test]
fn integration_identity_is_stable_and_unique_for_resolved_instances() {
    let first = crate::config::Config {
        server_id: Some("instance-one".into()),
        ..Default::default()
    };
    let first_id = crate::api::resolved_integration_profile(&first).unwrap()["server_id"].clone();
    assert_eq!(
        first_id,
        crate::api::resolved_integration_profile(&first).unwrap()["server_id"]
    );
    let mut second = first;
    second.server_id = Some("instance-two".into());
    assert_ne!(
        first_id,
        crate::api::resolved_integration_profile(&second).unwrap()["server_id"]
    );
}

#[test]
fn external_integration_identity_fails_closed_without_unique_resolved_seed() {
    let mut config = crate::config::Config::default();
    config.mcp.host = "0.0.0.0".into();
    assert!(crate::api::resolved_integration_profile(&config).is_err());
    config.mcp.auth.public_url = Some("https://cortex.example.test".into());
    assert!(crate::api::resolved_integration_profile(&config).is_ok());
}

#[tokio::test]
async fn durable_stream_routes_require_auth_and_negotiate_sse() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let response = get_response(app.clone(), "/api/streams/logs", None).await;
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

    let response = get_response(app, "/api/streams/logs?host=devhost", Some("secret")).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
}

#[tokio::test]
async fn durable_stream_route_enforces_sixty_four_clients_and_recovers_after_disconnect() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state.with_stream_client_limit(64));
    let mut responses = Vec::with_capacity(64);

    for _ in 0..64 {
        let response = get_response(app.clone(), "/api/streams/logs", Some("secret")).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        responses.push(response);
    }

    let rejected = get_response(app.clone(), "/api/streams/logs", Some("secret")).await;
    assert_eq!(rejected.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

    drop(responses.pop());
    let recovered = get_response(app, "/api/streams/logs", Some("secret")).await;
    assert_eq!(recovered.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn rendered_session_pages_are_ordered_bounded_and_resumable() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    let mut newest_timestamp_first = entry(
        "2026-08-28T00:00:02Z",
        "devhost",
        "info",
        "assistant",
        "transcript://codex",
    );
    newest_timestamp_first.ai_tool = Some("codex".into());
    newest_timestamp_first.ai_project = Some("/repo".into());
    newest_timestamp_first.ai_session_id = Some("session-1".into());
    newest_timestamp_first.metadata_json =
        Some(r#"{"event_kind":"assistant","content_scrubbed":true}"#.into());
    let mut older_timestamp_second = newest_timestamp_first.clone();
    older_timestamp_second.timestamp = "2026-08-28T00:00:01Z".into();
    older_timestamp_second.message = "tool output [REDACTED]".into();
    older_timestamp_second.metadata_json =
        Some(r#"{"event_kind":"tool","content_scrubbed":true}"#.into());
    older_timestamp_second.parse_error = Some("partial write recovered".into());
    insert_logs_batch(&pool, &[newest_timestamp_first, older_timestamp_second]).unwrap();
    let app = test_router(state);
    let base = "/api/sessions/rendered?project=%2Frepo&tool=codex&session_id=session-1&host=devhost&limit=1";
    let (status, first) = get_json(app.clone(), base, Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(first["delivery"], "polling");
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    assert_eq!(first["events"][0]["kind"], "assistant");
    assert_eq!(first["has_more"], true);
    let first_position = first["events"][0]["position"].as_i64().unwrap();
    let cursor = first["next_cursor"].as_str().unwrap();
    let uri = format!("{base}&cursor={cursor}");
    let (status, second) = get_json(app, &uri, Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(second["events"].as_array().unwrap().len(), 1);
    assert!(second["events"][0]["position"].as_i64().unwrap() > first_position);
    assert_eq!(second["events"][0]["kind"], "tool");
    assert_eq!(second["events"][0]["redacted"], true);
    assert_eq!(
        second["events"][0]["parse_warning"],
        "partial write recovered"
    );
    assert_eq!(second["has_more"], false);
}

#[tokio::test]
async fn rendered_session_rejects_invalid_cursor_and_clamps_limit() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let base =
        "/api/sessions/rendered?project=%2Frepo&tool=codex&session_id=session-1&host=devhost";
    let (status, _) = get_json(
        app.clone(),
        &format!("{base}&cursor=not-a-cursor"),
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    let (status, value) = get_json(app, &format!("{base}&limit=9999"), Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["limit_clamped_to"], 200);
}

/// CRITICAL (eng-review C1): even when the listener is bound to loopback and
/// callers therefore *could* be unauthenticated under the MCP policy, the
/// `/api/*` router MUST force `AuthPolicy::Mounted` and reject unauthenticated
/// requests. Without this, the "single shared token" model documented for
/// /api + /mcp breaks open on dev/loopback deployments.
#[tokio::test]
async fn version_route_requires_bearer_even_on_loopback_policy() {
    let (state, _pool, _dir) =
        test_state_with_policy(Some("secret".into()), AuthPolicy::LoopbackDev);
    let app = router(state).unwrap();

    let (status, _) = get_json(app.clone(), "/api/version", None).await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "loopback bind must not bypass bearer on /api/*"
    );

    let (status, value) = get_json(app, "/api/version", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

/// Repeated calls return identical schema_version values, proving the value
/// was captured once at startup rather than queried per request.
#[tokio::test]
async fn version_schema_version_is_cached_across_requests() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();

    let (s1, v1) = get_json(app.clone(), "/api/version", Some("secret")).await;
    let (s2, v2) = get_json(app, "/api/version", Some("secret")).await;
    assert_eq!(s1, axum::http::StatusCode::OK);
    assert_eq!(s2, axum::http::StatusCode::OK);
    assert_eq!(v1["schema_version"], v2["schema_version"]);
}

/// When GIT_SHA is not set at build time, the JSON response omits the field
/// rather than rendering `null`. This test is conditional: if a downstream
/// build *does* set GIT_SHA, the field will be present and the assertion
/// (`is_string()`) still holds.
#[tokio::test]
async fn version_git_sha_is_omitted_when_unset_or_string_when_set() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/version", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    match value.get("git_sha") {
        None => {}
        Some(v) => assert!(
            v.is_string(),
            "git_sha when present must be a string, got: {v}"
        ),
    }
    assert!(
        !value.get("git_sha").map(|v| v.is_null()).unwrap_or(false),
        "git_sha must never be JSON null — omit the field instead"
    );
}

// ── /api/sessions + /api/sessions/* happy-paths and contract checks ───────────────

fn ai_entry(
    ts: &str,
    host: &str,
    severity: &str,
    msg: &str,
    project: &str,
    tool: &str,
    session: &str,
) -> LogBatchEntry {
    let mut e = entry(ts, host, severity, msg, "10.0.0.1:514");
    e.ai_project = Some(project.into());
    e.ai_tool = Some(tool.into());
    e.ai_session_id = Some(session.into());
    e
}

#[tokio::test]
async fn sessions_route_returns_empty_when_db_empty() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["count"], 0);
    assert!(value["sessions"].is_array());
}

#[tokio::test]
async fn sessions_route_lists_ingested_session() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "info",
            "claude session start",
            "cortex",
            "claude",
            "sess-1",
        )],
    )
    .unwrap();
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["count"], 1);
    assert_eq!(value["sessions"][0]["project"], "cortex");
    assert_eq!(value["sessions"][0]["tool"], "claude");
}

#[tokio::test]
async fn ai_search_requires_query_param() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/sessions/search", Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "missing required `query` must yield 400"
    );
}

#[tokio::test]
async fn ai_search_clamps_limit_and_marks_truncated() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/sessions/search?query=anything&limit=10000",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        value["limit_clamped_to"], 500,
        "clamp marker must report the cap value"
    );
    assert_eq!(
        value["truncated"], true,
        "limit clamp must force truncated:true"
    );
}

#[tokio::test]
async fn ai_search_without_limit_omits_clamp_marker() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) =
        get_json(app, "/api/sessions/search?query=anything", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("limit_clamped_to").is_none(),
        "clamp marker must be omitted when limit not supplied"
    );
}

#[tokio::test]
async fn ai_abuse_accepts_terms_singular_query_param() {
    // Bead 0p8r.15: server-side `QsQuery<AbuseSearchRequest>` accepts
    // `terms=<x>` and surfaces it as a single-element Vec<String>.
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/abuse?terms=ignore", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("matches").is_some());
}

#[tokio::test]
async fn ai_abuse_accepts_multiple_terms_via_repeated_keys() {
    // Bead 0p8r.15 round-trip: `terms=a&terms=b` (the wire shape
    // `serde_qs::to_string` produces from `Vec<String>`) is accepted, and
    // every term reaches the service.
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/sessions/abuse?terms=alpha&terms=beta&terms=gamma",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let terms = value["terms"].as_array().expect("terms must be array");
    let collected: Vec<&str> = terms.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        collected,
        vec!["alpha", "beta", "gamma"],
        "all three repeated terms must reach the service: {value}"
    );
}

#[tokio::test]
async fn ai_abuse_clamps_limit_and_marks_truncated() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/abuse?limit=10000", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["limit_clamped_to"], 500);
    assert_eq!(value["truncated"], true);
}

#[tokio::test]
async fn ai_correlate_clamps_events_per_anchor_and_marks_clamp() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/sessions/correlate?events_per_anchor=200",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        value["events_per_anchor_clamped_to"], 50,
        "events_per_anchor clamp marker must be present when caller asked for > 50"
    );
    // related_limit_per_anchor reflects the clamped value (service computes
    // from the value we pass after clamping).
    assert_eq!(value["related_limit_per_anchor"], 50);
}

#[tokio::test]
async fn ai_correlate_without_clamp_has_no_marker() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(
        app,
        "/api/sessions/correlate?events_per_anchor=10",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("events_per_anchor_clamped_to").is_none(),
        "clamp marker must be omitted when caller stays under the cap"
    );
}

#[tokio::test]
async fn ai_blocks_returns_payload() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/blocks", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("blocks").is_some());
}

#[tokio::test]
async fn ai_context_rejects_missing_project() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/sessions/context", Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "missing required `project` must yield 400"
    );
}

#[tokio::test]
async fn ai_context_rejects_empty_project() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/context?project=", Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "empty `project` must yield 400 (eng-review #A7)"
    );
    assert!(
        value["error"].as_str().unwrap_or("").contains("project"),
        "error body must mention `project`: {value}"
    );
}

#[tokio::test]
async fn ai_context_accepts_non_empty_project() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/context?project=foo", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["project"], "foo");
}

#[tokio::test]
async fn ai_tools_returns_payload() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/tools", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("tools").is_some());
}

#[tokio::test]
async fn ai_projects_returns_payload() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, value) = get_json(app, "/api/sessions/projects", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("projects").is_some());
}

// ── deny_unknown_fields enforcement ─────────────────────────────────────────

#[tokio::test]
async fn unknown_query_param_returns_400_on_ai_blocks() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/sessions/blocks?bogus=1", Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "unknown query field must be rejected when deny_unknown_fields is in effect"
    );
}

#[tokio::test]
async fn unknown_query_param_returns_400_on_legacy_search() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/search?bogus=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

// ── all new routes require bearer ───────────────────────────────────────────

#[tokio::test]
async fn ai_routes_require_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    for path in [
        "/api/sessions",
        "/api/sessions/search?query=x",
        "/api/sessions/abuse",
        "/api/sessions/correlate",
        "/api/sessions/blocks",
        "/api/sessions/context?project=foo",
        "/api/sessions/tools",
        "/api/sessions/projects",
    ] {
        let (status, _) = get_json(app.clone(), path, None).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "{path} must require a bearer token",
        );
    }
}

// ── CORS plumbing from CORTEX_ALLOWED_ORIGINS ───────────────────────────

#[tokio::test]
async fn allowed_origins_grants_cors_for_env_supplied_host() {
    let (state, _pool, _dir) =
        test_state_with_origins(Some("secret".into()), vec!["https://ui.example.com".into()]);
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/stats")
        .header("Authorization", "Bearer secret")
        .header("Origin", "https://ui.example.com")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default(),
        "https://ui.example.com",
        "env-supplied origin must be reflected by the CORS layer"
    );
}

/// Bead 0p8r.21: on a non-loopback bind, the default `localhost:port` /
/// `127.0.0.1:port` CORS allowlist must NOT fire. Only `CORTEX_ALLOWED_ORIGINS`
/// is authoritative.
#[tokio::test]
async fn cors_localhost_defaults_suppressed_on_external_bind() {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("api-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let service = crate::app::CortexService::new(Arc::clone(&pool), storage);
    let state = ApiState::new(
        service,
        ApiConfig {
            api_token: crate::config::Secret(Some("secret".into())),
            admin_token: crate::config::Secret(None),
        },
        3100,
        // External bind — defaults must be dropped.
        false,
        vec![],
        AuthPolicy::Mounted { auth_state: None },
        false, // static_token_is_admin: read-only in tests
        crate::config::NotificationsConfig::default(),
        crate::stream::CursorKeys::resolved(Some("api-test-key"), &[], false).unwrap(),
        crate::api::resolved_integration_profile(&crate::config::Config::default()).unwrap(),
    )
    .unwrap()
    .with_isolated_maintenance_permit();
    let app = router(state).unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/api/stats")
        .header("Authorization", "Bearer secret")
        .header("Origin", "http://localhost:3100")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "localhost origin must NOT be allowed on external bind without an explicit allowlist"
    );
}

/// Grep guard: there must be no `CORTEX_API_ENABLED` reference left in the
/// source tree. The env var was retired when /api/* became always-on, and a
/// stray reference would be a silent foot-gun (operators expecting it to
/// control mounting).
#[test]
fn no_syslog_api_enabled_references_remain_in_source_tree() {
    use std::path::{Path, PathBuf};

    fn walk(dir: &Path, hits: &mut Vec<(PathBuf, usize, String)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, hits);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            // Skip the grep test itself (it legitimately mentions the
            // string as a literal we're searching for).
            if path.file_name().and_then(|s| s.to_str()) == Some("api_tests.rs") {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (idx, line) in contents.lines().enumerate() {
                if line.contains("CORTEX_API_ENABLED") {
                    hits.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
    }

    // CARGO_MANIFEST_DIR is the crate root regardless of where `cargo test`
    // is invoked from (worktree, CI runner, etc.).
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk(&src_root, &mut hits);
    assert!(
        hits.is_empty(),
        "found leftover CORTEX_API_ENABLED references in src/: {hits:#?}"
    );
}

// ── bead 0p8r.3: AI diagnostic + prune-checkpoints endpoints ─────────────────

async fn post_json(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    post_json_with_admin(app, uri, body, token, None).await
}

async fn post_json_with_admin(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
    admin_token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(admin_token) = admin_token {
        builder = builder.header("X-Cortex-Admin-Token", admin_token);
    }
    let response = app
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn post_json_admin(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    post_json_with_admin(app, uri, body, Some("secret"), Some("admin-secret")).await
}

async fn post_json_response(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    app.oneshot(
        builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn investigation_v1_ask_requires_auth_and_returns_no_store_safe_envelope() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let mut app_log = entry(
        "2026-01-01T00:00:00.000Z",
        "host-a",
        "err",
        "nginx emitted password=secret token=abc",
        "10.0.0.1:514",
    );
    app_log.app_name = Some("nginx".into());
    insert_logs_batch(&pool, &[app_log]).unwrap();
    refresh_graph_projection_for_test(&pool);

    let response = post_json_response(
        app.clone(),
        "/api/v1/investigations/ask",
        serde_json::json!({"prompt": "Why did host-a fail?", "host": "host-a"}),
        None,
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

    let response = post_json_response(
        app.clone(),
        "/api/v1/investigations/ask",
        serde_json::json!({"prompt": "Why did host-a fail?", "host": "host-a"}),
        Some("secret"),
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("\"metadata\""));
    assert!(text.contains("\"result\""));
    assert!(text.contains("supported_correlation"));
    assert!(!text.contains("password="));
    assert!(!text.contains("token="));
    assert!(!text.contains("metadata_json"));
    assert!(!text.contains("source_signature_hash"));

    let entity_response = get_response(
        app.clone(),
        "/api/v1/graph/entity?entity_type=host&key=host-a",
        Some("secret"),
    )
    .await;
    assert_eq!(entity_response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        entity_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let bytes = to_bytes(entity_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("resolved_entity"));
    assert!(!text.contains("source_id"));

    let around_response = get_response(
        app.clone(),
        "/api/v1/graph/around?entity_type=host&key=host-a&limit=10&evidence_sample_limit=2",
        Some("secret"),
    )
    .await;
    assert_eq!(around_response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        around_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let bytes = to_bytes(around_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let around: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let around_text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !around["result"]["relationships"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let evidence_id = around["result"]["evidence"][0]["id"].as_i64().unwrap();
    assert!(!around_text.contains("source_signature_hash"));
    assert!(!around_text.contains("source_id"));

    let explain_response = get_response(
        app.clone(),
        "/api/v1/graph/explain?entity_type=host&key=host-a&depth=1&beam_width=10&evidence_sample_limit=2",
        Some("secret"),
    )
    .await;
    assert_eq!(explain_response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        explain_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let bytes = to_bytes(explain_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let explain_text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(explain_text.contains("\"relationships\""));
    assert!(!explain_text.contains("source_signature_hash"));
    assert!(!explain_text.contains("source_id"));

    let evidence_response = get_response(
        app,
        &format!("/api/v1/graph/evidence?evidence_id={evidence_id}"),
        Some("secret"),
    )
    .await;
    assert_eq!(evidence_response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        evidence_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let bytes = to_bytes(evidence_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let evidence_text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(evidence_text.contains("source_log_summary"));
    assert!(!evidence_text.contains("password="));
    assert!(!evidence_text.contains("token="));
    assert!(!evidence_text.contains("source_signature_hash"));
    assert!(!evidence_text.contains("source_id"));
}

#[tokio::test]
async fn ai_checkpoints_route_returns_empty_when_db_empty() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/sessions/checkpoints", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.is_array(), "expected JSON array, got {value}");
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn ai_checkpoints_route_accepts_filter_flags() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(
        app,
        "/api/sessions/checkpoints?errors_only=true&missing_only=false&limit=10",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn ai_checkpoints_rejects_unknown_query_param() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(app, "/api/sessions/checkpoints?bogus=1", Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "deny_unknown_fields must reject unknown query params"
    );
}

#[tokio::test]
async fn ai_parse_errors_route_returns_empty_when_db_empty() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/sessions/errors", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.is_array(), "expected JSON array, got {value}");
}

#[tokio::test]
async fn ai_parse_errors_honors_limit() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(app, "/api/sessions/errors?limit=5", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn ai_prune_checkpoints_with_dry_run_true_returns_ok() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let body = json!({"dry_run": true, "missing_only": true});

    let (status, value) = post_json(
        app.clone(),
        "/api/sessions/prune-checkpoints",
        body.clone(),
        Some("secret"),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "response: {value}"
    );

    let (status, value) = post_json_admin(
        app,
        "/api/sessions/prune-checkpoints",
        // `missing_only` is required by the service (it refuses to prune
        // arbitrary checkpoints — see scanner::checkpoint::prune_checkpoints).
        body,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["matched"], 0);
    assert_eq!(value["pruned"], 0);
}

#[tokio::test]
async fn ai_prune_checkpoints_with_dry_run_false_returns_ok_and_prunes() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) = post_json_admin(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"dry_run": false, "missing_only": true}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["dry_run"], false);
    // Empty DB → nothing matched/pruned, but the shape is correct.
    assert_eq!(value["matched"], 0);
    assert_eq!(value["pruned"], 0);
}

/// CRITICAL (eng-review C3): `POST {}` MUST return 400, not silently
/// default `dry_run` to `false` and mass-delete checkpoints.
#[tokio::test]
async fn ai_prune_checkpoints_missing_dry_run_returns_400() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) = post_json_admin(app, "/api/sessions/prune-checkpoints", json!({})).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "POST {{}} must return 400 to defend against mass-delete (eng-review C3)"
    );
    let msg = value["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("dry_run is required"),
        "error must mention dry_run is required, got: {msg}"
    );
}

#[tokio::test]
async fn ai_prune_checkpoints_with_only_missing_only_returns_400() {
    // missing_only present but dry_run absent → still 400.
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"missing_only": true}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_prune_checkpoints_rejects_unknown_field() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"dry_run": true, "unknown": 1}),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "deny_unknown_fields must reject unknown body fields"
    );
}

#[tokio::test]
async fn ai_prune_checkpoints_rejects_non_object_body() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, _) =
        post_json_admin(app, "/api/sessions/prune-checkpoints", json!([1, 2, 3])).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_prune_checkpoints_rejects_malformed_json() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/sessions/prune-checkpoints")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer secret")
        .header("X-Cortex-Admin-Token", "admin-secret")
        .body(axum::body::Body::from("{not json"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_prune_checkpoints_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = post_json(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"dry_run": true}),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ai_checkpoints_routes_require_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    for path in ["/api/sessions/checkpoints", "/api/sessions/errors"] {
        let (status, _) = get_json(app.clone(), path, None).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "{path} must require a bearer token"
        );
    }
}

// ── CORS preflight for POST endpoint ────────────────────────────────────────

/// Browser preflight: OPTIONS + Origin + Access-Control-Request-Method must
/// return 2xx (axum's CORS layer returns 200 OK) with `Allow-Methods`
/// listing POST. Without the CORS update in this bead, the preflight
/// silently fails and the browser never issues the actual POST.
#[tokio::test]
async fn cors_preflight_for_post_includes_post_in_allow_methods() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/sessions/prune-checkpoints")
        .header("Origin", "http://localhost:3100")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,content-type,x-cortex-admin-token",
        )
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    // tower-http CorsLayer returns 200 OK for preflights.
    assert!(
        response.status().is_success() || response.status().as_u16() == 204,
        "CORS preflight must succeed, got {}",
        response.status()
    );
    let allow_methods = response
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_uppercase();
    assert!(
        allow_methods.contains("POST"),
        "Access-Control-Allow-Methods must include POST, got: {allow_methods}"
    );
    assert!(
        allow_methods.contains("OPTIONS"),
        "Access-Control-Allow-Methods must include OPTIONS, got: {allow_methods}"
    );

    // Bead 0p8r.14: allowed-headers must be an explicit allowlist, NOT `*`.
    // authorization / content-type / accept are required; arbitrary
    // headers (cookie, x-custom-token, etc.) must NOT be reflected.
    let allow_headers = response
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        allow_headers.contains("authorization"),
        "Access-Control-Allow-Headers must include authorization, got: {allow_headers}"
    );
    assert!(
        allow_headers.contains("content-type"),
        "Access-Control-Allow-Headers must include content-type, got: {allow_headers}"
    );
    assert!(
        allow_headers.contains("x-cortex-admin-token"),
        "Access-Control-Allow-Headers must include x-cortex-admin-token for /api/file-tails, got: {allow_headers}"
    );
    assert!(
        !allow_headers.contains('*'),
        "Access-Control-Allow-Headers must NOT be the wildcard; got: {allow_headers}"
    );
}

/// Bead 0p8r.14: a preflight that asks for a non-allowlisted header (cookie,
/// x-custom-token) must NOT have that header echoed in
/// access-control-allow-headers. The browser then refuses the actual request.
#[tokio::test]
async fn cors_preflight_rejects_non_allowlisted_header() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/sessions/prune-checkpoints")
        .header("Origin", "http://localhost:3100")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,cookie,x-custom-token",
        )
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let allow_headers = response
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        !allow_headers.contains("cookie"),
        "cookie header must not be reflected by CORS preflight: {allow_headers}"
    );
    assert!(
        !allow_headers.contains("x-custom-token"),
        "x-custom-token must not be reflected by CORS preflight: {allow_headers}"
    );
}

/// All new bead-0p8r.3 routes must require a bearer (consolidated check).
#[tokio::test]
async fn bead_0p8r_3_routes_require_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    for path in ["/api/sessions/checkpoints", "/api/sessions/errors"] {
        let (status, _) = get_json(app.clone(), path, None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{path}");
    }
    let (status, _) = post_json(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"dry_run": true}),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

// ── Audit-log-before-service-call ordering ──────────────────────────────────

/// Eng-review #A13 / security finding #35: `tracing::warn!` audit line must
/// fire BEFORE the service call, so a process crash mid-prune still leaves
/// an audit trail.
///
/// Test strategy (per bead 0p8r.3 MUST-CHECK fallback when `tracing-test`
/// isn't a dependency): assert ordering via source-grep on the handler in
/// `src/api.rs`. Specifically, inside the `async fn ai_prune_checkpoints`
/// body the `tracing::warn!` macro invocation must appear LEXICALLY before
/// the `.prune_ai_checkpoints(` service call. Because Rust executes
/// expressions in source order within an async block, lexical ordering is
/// emission ordering.
///
/// We also assert the audit fields (`caller_ip`, `action`, `dry_run`,
/// `missing_only`) are present in the warn! invocation source so the
/// observability surface is right.
#[test]
fn ai_prune_checkpoints_audit_log_precedes_service_call_in_source() {
    let api_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"),
    )
    .expect("src/api.rs must be readable");

    // Locate the handler body.
    let handler_start = api_src
        .find("async fn ai_prune_checkpoints(")
        .expect("ai_prune_checkpoints handler must exist in src/api.rs");
    let handler_tail = &api_src[handler_start..];
    // Stop at the next top-level `async fn` or `fn ` after the handler so we
    // don't drag audit-log strings from later handlers into the search.
    let handler_end = handler_tail[1..]
        .find("\nasync fn ")
        .map(|i| i + 1)
        .or_else(|| handler_tail[1..].find("\nfn ").map(|i| i + 1))
        .unwrap_or(handler_tail.len());
    let handler = &handler_tail[..handler_end];

    let warn_pos = handler
        .find("tracing::warn!(")
        .expect("handler must contain tracing::warn!( audit invocation");
    let service_call_pos = handler
        .find(".prune_ai_checkpoints_checked(")
        .expect("handler must call .prune_ai_checkpoints_checked( on the service");
    assert!(
        warn_pos < service_call_pos,
        "audit tracing::warn! must appear in source BEFORE the \
         .prune_ai_checkpoints_checked service call (eng-review #A13). \
         warn_pos={warn_pos}, service_call_pos={service_call_pos}"
    );

    // The warn! invocation must include the required audit fields.
    let warn_slice_end = handler[warn_pos..]
        .find(')')
        .map(|i| warn_pos + i + 1)
        .unwrap_or(handler.len());
    let warn_slice = &handler[warn_pos..warn_slice_end];
    for required in ["caller_ip", "action", "dry_run", "missing_only"] {
        assert!(
            warn_slice.contains(required),
            "audit warn! must include `{required}` field, got: {warn_slice}"
        );
    }
}

// ── bead 0p8r.4: DB ops endpoints (status/integrity/checkpoint/vacuum) ───────

#[tokio::test]
async fn db_status_returns_pragma_snapshot() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/db/status", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("page_count").is_some(),
        "missing page_count: {value}"
    );
    assert!(
        value.get("page_size").is_some(),
        "missing page_size: {value}"
    );
    assert!(value.get("journal_mode").is_some());
    assert_eq!(value["sqlite_page_cache_mb"], 128);
    assert_eq!(value["sqlite_page_cache_kib_per_connection"], -131_072);
    assert_eq!(value["sqlite_mmap_mb"], 256);
    assert_eq!(value["sqlite_mmap_bytes"], 256 * 1024 * 1024);
    assert_eq!(value["heavy_read_concurrency"], 1);
    assert_eq!(value["wal_checkpoint_mb"], 256);
    assert_eq!(value["wal_checkpoint_threshold_bytes"], 256 * 1024 * 1024);
    assert!(matches!(
        value["cgroup_memory_status"].as_str(),
        Some("ok" | "unlimited" | "unavailable" | "error")
    ));
    for key in [
        "cgroup_memory_max_bytes",
        "cgroup_memory_current_bytes",
        "cgroup_memory_peak_bytes",
    ] {
        assert!(
            value
                .get(key)
                .is_some_and(|field| field.is_null() || field.is_number()),
            "{key} should be null or numeric: {value}"
        );
    }
    let rendered = value.to_string();
    assert!(
        !rendered.contains("/sys/fs/cgroup"),
        "cgroup diagnostics must not expose host paths: {rendered}"
    );
}

#[tokio::test]
async fn db_status_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(app, "/api/db/status", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn db_integrity_quick_returns_ok() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/db/integrity?quick=true", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["ok"], true, "fresh DB should pass integrity: {value}");
}

#[tokio::test]
async fn db_integrity_full_returns_ok() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/db/integrity", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["ok"], true);
}

#[tokio::test]
async fn db_integrity_rejects_unknown_query_param() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(app, "/api/db/integrity?bogus=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn db_integrity_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = get_json(app, "/api/db/integrity", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_maintenance_routes_reject_plain_api_bearer() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);

    for (uri, body) in [
        (
            "/api/sessions/prune-checkpoints",
            json!({"dry_run": true, "missing_only": true}),
        ),
        (
            "/api/db/integrity/background?quick=true",
            serde_json::Value::Null,
        ),
        ("/api/db/checkpoint", json!({"mode": "passive"})),
        (
            "/api/db/vacuum",
            json!({"full": false, "incremental_pages": 16}),
        ),
        ("/api/db/backup", json!({})),
    ] {
        let (status, _) = post_json(app.clone(), uri, body, Some("secret")).await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "{uri} must require X-Cortex-Admin-Token in addition to bearer auth"
        );
    }
}

#[tokio::test]
async fn admin_maintenance_background_and_backup_accept_admin_token() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);

    let (status, value) = post_json_admin(
        app.clone(),
        "/api/db/integrity/background?quick=true",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");

    let (status, value) = post_json_admin(app, "/api/db/backup", json!({})).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");
}

#[tokio::test]
async fn db_checkpoint_passive_returns_ok() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) =
        post_json_admin(app, "/api/db/checkpoint", json!({"mode": "passive"})).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");
    assert_eq!(value["mode"], "passive");
}

#[tokio::test]
async fn db_checkpoint_accepts_uppercase_mode() {
    // Validation is case-insensitive; the service receives the lowercase form.
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) =
        post_json_admin(app, "/api/db/checkpoint", json!({"mode": "PASSIVE"})).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["mode"], "passive");
}

/// Bead 0p8r.4 #A17: unknown `mode` returns 400 with allowed list.
#[tokio::test]
async fn db_checkpoint_rejects_invalid_mode() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) =
        post_json_admin(app, "/api/db/checkpoint", json!({"mode": "INVALID"})).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    let msg = value["error"].as_str().unwrap_or_default();
    for required in ["passive", "full", "restart", "truncate"] {
        assert!(
            msg.contains(required),
            "error must list allowed mode `{required}`, got: {msg}"
        );
    }
}

#[tokio::test]
async fn db_checkpoint_rejects_unknown_field() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/db/checkpoint",
        json!({"mode": "passive", "bogus": 1}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn db_checkpoint_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = post_json(app, "/api/db/checkpoint", json!({"mode": "passive"}), None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn db_vacuum_incremental_returns_ok() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");
    assert_eq!(value["full"], false);
    assert_eq!(value["incremental_pages"], 16);
}

#[tokio::test]
async fn db_vacuum_full_on_small_db_returns_ok() {
    // Fresh DB is well under 2 GB, no force needed.
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, value) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": true, "incremental_pages": 0}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");
    assert_eq!(value["full"], true);
}

/// Bead 0p8r.4 / eng-review C3 + bead 0p8r.17: `force` MUST be explicit when
/// the LIVE DB size exceeds the guard. We lower the threshold to 1 byte (via
/// test-only `with_full_vacuum_size_guard_bytes`) so even a freshly-opened
/// SQLite (page_count >= 1, page_size = 4096) trips the guard. This proves
/// the handler is reading the live `page_count * page_size` at request time
/// rather than a stale snapshot from `ApiState` construction.
#[tokio::test]
async fn db_vacuum_full_on_large_db_without_force_returns_409() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let state = state.with_full_vacuum_size_guard_bytes(1);
    let app = test_router(state);
    let (status, value) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": true, "incremental_pages": 0}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    let msg = value["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("force") && msg.contains("GB"),
        "error must mention force + GB hint, got: {msg}"
    );
}

#[tokio::test]
async fn db_vacuum_full_with_force_bypasses_size_guard() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let state = state.with_full_vacuum_size_guard_bytes(1);
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": true, "incremental_pages": 0, "force": true}),
    )
    .await;
    // force=true bypasses the live size pre-flight.
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn db_vacuum_force_false_does_not_bypass_size_guard() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let state = state.with_full_vacuum_size_guard_bytes(1);
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": true, "incremental_pages": 0, "force": false}),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "force:false must NOT bypass — only Some(true) does"
    );
}

/// Bead 0p8r.17: pre-flight reads LIVE size; a DB that grows past the guard
/// AFTER `ApiState` construction must trip the gate. Seed the DB with rows
/// post-construction, then assert 409. Pre-bead-.17 this would have used the
/// stale startup cache (0 bytes on empty DB) and incorrectly returned 200.
#[tokio::test]
async fn db_vacuum_full_size_guard_reads_live_size_post_construction() {
    let (state, pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let state = state.with_full_vacuum_size_guard_bytes(1);
    // Insert real rows AFTER ApiState was built so the live page_count grows
    // beyond the 1-byte threshold. A pre-bead-.17 implementation that
    // snapshotted at construction would not see this growth and would
    // incorrectly return 200.
    let batch: Vec<_> = (0..32)
        .map(|i| {
            entry(
                "2026-01-01T00:00:00Z",
                "h",
                "info",
                &format!("seed-{i}"),
                "10.0.0.1",
            )
        })
        .collect();
    db::insert_logs_batch(&pool, &batch).expect("seed insert");
    let app = test_router(state);
    let (status, value) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": true, "incremental_pages": 0}),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "live size must drive the pre-flight, not a stale snapshot: {value}"
    );
}

#[tokio::test]
async fn db_vacuum_size_guard_does_not_apply_to_incremental() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let state = state.with_full_vacuum_size_guard_bytes(1);
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn db_vacuum_rejects_unknown_field() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);
    let (status, _) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16, "bogus": 1}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn db_vacuum_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _) = post_json(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

/// Single-flight (eng-review C2): when MAINTENANCE_PERMIT is held, a
/// concurrent vacuum POST returns 409 immediately.
///
/// We acquire the permit directly via `maintenance_permit()` to avoid racing
/// two real vacuums on a fresh DB (which might both finish before the second
/// request arrives).
#[tokio::test]
async fn db_vacuum_single_flight_returns_409_when_locked() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    // Grab the permit from THIS state (each test has its own per
    // `with_isolated_maintenance_permit`).
    let permit = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    let (status, value) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    assert_eq!(
        value["error"].as_str().unwrap_or_default(),
        "db maintenance already in progress"
    );

    drop(permit);
}

/// Bead 0p8r.16: prune_ai_checkpoints must compete for MAINTENANCE_PERMIT
/// alongside vacuum/checkpoint, so concurrent maintenance surfaces as a
/// clean 409 rather than SQLITE_BUSY/timeout.
#[tokio::test]
async fn ai_prune_checkpoints_single_flight_returns_409_when_locked() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let permit = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    let (status, value) = post_json_admin(
        app,
        "/api/sessions/prune-checkpoints",
        json!({"dry_run": true}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    assert_eq!(
        value["error"].as_str().unwrap_or_default(),
        "db maintenance already in progress"
    );

    drop(permit);
}

#[tokio::test]
async fn db_checkpoint_single_flight_returns_409_when_locked() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let permit = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    let (status, value) =
        post_json_admin(app, "/api/db/checkpoint", json!({"mode": "passive"})).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    assert_eq!(
        value["error"].as_str().unwrap_or_default(),
        "db maintenance already in progress"
    );

    drop(permit);
}

/// Vacuum and checkpoint share the SAME permit (single-flight applies across
/// both). With one held, the other returns 409.
#[tokio::test]
async fn db_vacuum_blocks_db_checkpoint_via_shared_permit() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let permit = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    // Hold the permit, fire a checkpoint POST — should 409.
    let (status, _) = post_json_admin(app, "/api/db/checkpoint", json!({"mode": "passive"})).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);

    drop(permit);
}

/// Single-flight (deterministic): while the MAINTENANCE_PERMIT is held,
/// a vacuum request must return 409 immediately. Holding the permit
/// explicitly removes the race window so the assertion is strict.
#[tokio::test]
async fn db_vacuum_request_returns_409_when_permit_held() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let _held = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    let (status, _) = post_json_admin(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "vacuum must 409 while MAINTENANCE_PERMIT is held"
    );
}

/// Concurrent vacuum requests against the same ApiState: at least one
/// must succeed (200) and the other is either 200 (raced wide) or 409
/// (raced narrow). Neither may 5xx or block. Lossy by design — the
/// permit-held variant above carries the strict contention check.
#[tokio::test]
async fn db_vacuum_concurrent_requests_no_5xx_at_least_one_success() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);

    let app2 = app.clone();
    let h1 = tokio::spawn(async move {
        post_json_admin(
            app2,
            "/api/db/vacuum",
            json!({"full": false, "incremental_pages": 16}),
        )
        .await
    });
    let h2 = tokio::spawn(async move {
        post_json_admin(
            app,
            "/api/db/vacuum",
            json!({"full": false, "incremental_pages": 16}),
        )
        .await
    });
    let (r1, r2) = tokio::join!(h1, h2);
    let (s1, _) = r1.unwrap();
    let (s2, _) = r2.unwrap();
    for code in [s1, s2] {
        assert!(
            code == axum::http::StatusCode::OK || code == axum::http::StatusCode::CONFLICT,
            "expected 200 or 409, got {code}"
        );
    }
    assert!(
        s1 == axum::http::StatusCode::OK || s2 == axum::http::StatusCode::OK,
        "at least one vacuum should complete"
    );
}

/// Eng-review C2: while the maintenance permit is held, reads (which use
/// the independent `db_permits` pool inside `CortexService::run_db`) must
/// continue to succeed.
#[tokio::test]
async fn reads_continue_while_maintenance_permit_held() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let permit = Arc::clone(&state.maintenance_permit)
        .try_acquire_owned()
        .expect("permit must be free at test start");
    let app = test_router(state);

    // GET /api/hosts goes through the service's db_permits pool — totally
    // independent of the maintenance permit.
    let (status, _) = get_json(app.clone(), "/api/hosts", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // GET /api/db/status is also a read — bypasses the maintenance permit.
    let (status, _) = get_json(app, "/api/db/status", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    drop(permit);
}

/// All bead 0p8r.4 routes require a bearer (consolidated check).
#[tokio::test]
async fn bead_0p8r_4_routes_require_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    for path in ["/api/db/status", "/api/db/integrity"] {
        let (status, _) = get_json(app.clone(), path, None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{path}");
    }
    let (status, _) = post_json(
        app.clone(),
        "/api/db/checkpoint",
        json!({"mode": "passive"}),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let (status, _) = post_json(
        app,
        "/api/db/vacuum",
        json!({"full": false, "incremental_pages": 16}),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

/// Audit-log ordering for `db_vacuum` and `db_checkpoint` — mirrors the
/// bead 0p8r.3 source-grep approach for `ai_prune_checkpoints`. The
/// `tracing::warn!` must appear lexically before the service call AND before
/// the permit acquisition so even a queued-but-rejected attempt leaves a
/// trace.
#[test]
fn db_admin_audit_logs_precede_service_calls_in_source() {
    let api_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"),
    )
    .expect("src/api.rs must be readable");

    for (handler_name, service_call, required_fields) in [
        (
            "async fn db_vacuum(",
            ".db_vacuum_checked(",
            &["caller_ip", "action", "full", "force"][..],
        ),
        (
            "async fn db_checkpoint(",
            ".db_checkpoint_checked(",
            &["caller_ip", "action", "mode"][..],
        ),
    ] {
        let handler_start = api_src
            .find(handler_name)
            .unwrap_or_else(|| panic!("{handler_name} handler must exist in src/api.rs"));
        let handler_tail = &api_src[handler_start..];
        let handler_end = handler_tail[1..]
            .find("\nasync fn ")
            .map(|i| i + 1)
            .or_else(|| handler_tail[1..].find("\nfn ").map(|i| i + 1))
            .unwrap_or(handler_tail.len());
        let handler = &handler_tail[..handler_end];

        let warn_pos = handler.find("tracing::warn!(").unwrap_or_else(|| {
            panic!("{handler_name} must contain tracing::warn!( audit invocation")
        });
        let service_call_pos = handler
            .find(service_call)
            .unwrap_or_else(|| panic!("{handler_name} must call {service_call}"));
        assert!(
            warn_pos < service_call_pos,
            "audit tracing::warn! must appear in source BEFORE the service call \
             ({handler_name}). warn_pos={warn_pos}, service_call_pos={service_call_pos}"
        );

        let warn_slice_end = handler[warn_pos..]
            .find(')')
            .map(|i| warn_pos + i + 1)
            .unwrap_or(handler.len());
        let warn_slice = &handler[warn_pos..warn_slice_end];
        for required in required_fields {
            assert!(
                warn_slice.contains(*required),
                "{handler_name} audit warn! must include `{required}`, got: {warn_slice}"
            );
        }
    }

    // Bead 0p8r.22 + cortex-yab3.5: db_checkpoint's audit warn! must also
    // precede the checked service operation, because the mode allowlist now
    // lives in the service request model. A rejected `mode=evil` 400 still
    // leaves an audit row.
    let handler_start = api_src
        .find("async fn db_checkpoint(")
        .expect("db_checkpoint handler must exist");
    let handler_tail = &api_src[handler_start..];
    let handler_end = handler_tail[1..]
        .find("\nasync fn ")
        .map(|i| i + 1)
        .or_else(|| handler_tail[1..].find("\nfn ").map(|i| i + 1))
        .unwrap_or(handler_tail.len());
    let handler = &handler_tail[..handler_end];
    let warn_pos = handler.find("tracing::warn!(").expect("warn must exist");
    let mode_check_pos = handler
        .find(".db_checkpoint_checked(")
        .expect("checked service mode validation call must exist");
    assert!(
        warn_pos < mode_check_pos,
        "db_checkpoint audit warn! must precede the checked service validation call (bead 0p8r.22). \
         warn_pos={warn_pos}, mode_check_pos={mode_check_pos}"
    );
}

/// Bead 0p8r.4 / eng-review C2: the new admin handlers must NOT touch the
/// `db_permits` pool directly — they only call into the service (which
/// acquires from `db_permits` internally). Source-grep for any direct
/// reference to `db_permits` in the new handlers, IGNORING comment lines
/// (the dual-permit pattern is documented inline, which is intentional).
#[test]
fn db_admin_handlers_do_not_touch_db_permits_pool_directly() {
    let api_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"),
    )
    .expect("src/api.rs must be readable");

    for handler_name in ["async fn db_vacuum(", "async fn db_checkpoint("] {
        let handler_start = api_src
            .find(handler_name)
            .unwrap_or_else(|| panic!("{handler_name} must exist"));
        let handler_tail = &api_src[handler_start..];
        let handler_end = handler_tail[1..]
            .find("\nasync fn ")
            .map(|i| i + 1)
            .or_else(|| handler_tail[1..].find("\nfn ").map(|i| i + 1))
            .unwrap_or(handler_tail.len());
        let handler = &handler_tail[..handler_end];
        // Strip comment lines (//-leading) before checking; the rationale
        // comments are allowed to mention `db_permits`, but actual code must
        // not.
        let non_comment_lines: String = handler
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !non_comment_lines.contains("db_permits"),
            "{handler_name} must not reference db_permits in code — the \
             maintenance permit is the outer gate; the service's db_permits \
             pool is acquired internally by run_db. Found in:\n{non_comment_lines}"
        );
    }
}

// ── Surface parity gap closure: 12 new REST routes (2026-05-22) ──────────────
//
// One smoke test per new endpoint. Each test asserts the route is mounted,
// the bearer token is enforced, and a happy-path call against an empty DB
// returns 200 with a JSON object (not 404, not 401, not 500 on parse error).

#[tokio::test]
async fn silent_hosts_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) =
        get_json(app, "/api/silent-hosts?silent_minutes=60", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.get("silent_minutes").is_some(),
        "missing silent_minutes: {value}"
    );
    assert!(value.get("hosts").is_some(), "missing hosts: {value}");
}

#[tokio::test]
async fn clock_skew_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/clock-skew", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("hosts").is_some(), "missing hosts: {value}");
}

#[tokio::test]
async fn anomalies_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(
        app,
        "/api/anomalies?recent_minutes=15&baseline_minutes=360",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("hosts").is_some(), "missing hosts: {value}");
}

#[tokio::test]
async fn compare_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(
        app,
        "/api/compare?a_from=2026-05-20T00:00:00Z&a_to=2026-05-20T23:59:59Z&b_from=2026-05-21T00:00:00Z&b_to=2026-05-21T23:59:59Z",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("a").is_some(), "missing a: {value}");
    assert!(value.get("b").is_some(), "missing b: {value}");
}

#[tokio::test]
async fn mcp_session_routes_and_incident_narrowing_have_rest_parity() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    for path in [
        "/api/sessions/skill-investigate?incident_id=skill-inc-1",
        "/api/sessions/mcp-events?limit=1",
        "/api/sessions/mcp-incidents?limit=1",
        "/api/sessions/mcp-investigate?mcp_server=labby&limit=1",
        "/api/sessions/hook-investigate?incident_id=hook-inc-1",
    ] {
        let (status, value) = get_json(app.clone(), path, Some("secret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{path}: {value}");
    }
}

#[tokio::test]
async fn apps_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/apps?limit=50", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("apps").is_some(), "missing apps: {value}");
}

#[tokio::test]
async fn similar_incidents_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/similar-incidents?query=disk%20full&window_minutes=30",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn recurring_error_comparison_requires_token_and_returns_bounded_shape() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let path = "/api/recurring-error-comparison?until=2026-05-21T13:00:00Z&window_minutes=60";
    let (unauthorized, _) = get_json(app.clone(), path, None).await;
    assert_eq!(unauthorized, axum::http::StatusCode::UNAUTHORIZED);
    let (status, value) = get_json(app, path, Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(value["candidate_cap"], 512);
    assert!(
        value.get("comparisons").is_some(),
        "missing comparisons: {value}"
    );
    assert_eq!(value["privacy_policy"], "irreversible_redaction/v1");
}

#[tokio::test]
async fn incident_context_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/incident-context?since=2026-05-21T11:00:00Z&until=2026-05-21T13:00:00Z",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn ai_api_namespace_is_removed() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    for route in [
        "/api/ai",
        "/api/ai/search?query=ssh%20key%20rotation",
        "/api/ai/abuse",
        "/api/ai/correlate",
        "/api/ai/blocks",
        "/api/ai/context?project=foo",
        "/api/ai/tools",
        "/api/ai/projects",
        "/api/ai/ask-history?query=test",
        "/api/ai/incidents",
        "/api/ai/investigate",
        "/api/ai/checkpoints",
        "/api/ai/errors",
        "/api/ai/prune-checkpoints",
    ] {
        let (status, _value) = get_json(app.clone(), route, Some("secret")).await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "{route} must stay unmounted as a clean protocol break"
        );
    }
}

#[tokio::test]
async fn ai_incidents_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(app, "/api/sessions/incidents?limit=10", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn ai_incidents_accepts_supported_terms_encodings() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[
            ai_entry(
                "2026-05-24T12:00:00Z",
                "host-a",
                "info",
                "tooling transcript row",
                "/tmp/project",
                "codex",
                "sess-1",
            ),
            ai_entry(
                "2026-05-24T12:01:00Z",
                "host-a",
                "info",
                "plain transcript row",
                "/tmp/project",
                "codex",
                "sess-1",
            ),
        ],
    )
    .unwrap();
    let app = test_router(state);

    for uri in [
        "/api/sessions/incidents?terms=tooling&limit=1",
        "/api/sessions/incidents?terms[]=tooling&limit=1",
    ] {
        let (status, value) = get_json(app.clone(), uri, Some("secret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{uri}: {value}");
        assert_eq!(
            value["incidents"][0]["terms"],
            serde_json::json!(["tooling"]),
            "{uri}: {value}"
        );
    }
}

#[tokio::test]
async fn ai_incidents_rejects_unsupported_indexed_terms_query() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/sessions/incidents?terms%5B0%5D=tooling&limit=1",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_investigate_returns_200_with_token() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/sessions/investigate?window_minutes=60&correlation_window_minutes=30",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn ai_investigate_accepts_supported_terms_encodings() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[ai_entry(
            "2026-05-24T12:00:00Z",
            "host-a",
            "info",
            "tooling transcript row",
            "/tmp/project",
            "codex",
            "sess-1",
        )],
    )
    .unwrap();
    let app = test_router(state);

    for uri in [
        "/api/sessions/investigate?terms=tooling&limit=1",
        "/api/sessions/investigate?terms[]=tooling&limit=1",
    ] {
        let (status, value) = get_json(app.clone(), uri, Some("secret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{uri}: {value}");
        assert_eq!(
            value["evidence"][0]["incident"]["terms"],
            serde_json::json!(["tooling"]),
            "{uri}: {value}"
        );
    }
}

#[tokio::test]
async fn ai_investigate_rejects_unsupported_indexed_terms_query() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/sessions/investigate?terms%5B0%5D=tooling&limit=1",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

/// Regression for cortex-fzj7: the CLI HTTP client serializes
/// `AiInvestigateRequest` with `serde_qs::to_string` and sends it as the raw
/// query string. The investigate CLI path always sets `incident_id: None`, and
/// the server-side `AiInvestigateQuery` uses `deny_unknown_fields` without an
/// `incident_id` field. Before the fix, serde_qs emitted a bare `incident_id`
/// key for the `None` option, so the server rejected the request with 400
/// ("unknown field `incident_id`"). This test pins both halves: the query the
/// client produces must not contain `incident_id`, and the server must accept
/// the exact client-produced query string.
#[tokio::test]
async fn ai_investigate_cli_query_omits_incident_id_and_server_accepts() {
    // `AiInvestigateRequest` is in scope via `use super::*` (api.rs re-export).
    // Mirror the CLI investigate path: incident_id is always None.
    let req = AiInvestigateRequest {
        incident_id: None,
        window_minutes: Some(60),
        correlation_window_minutes: Some(30),
        ..Default::default()
    };
    let qs = serde_qs::to_string(&req).expect("serialize investigate request");
    assert!(
        !qs.contains("incident_id"),
        "serialized query must not contain incident_id, got: {qs}"
    );

    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let uri = format!("/api/sessions/investigate?{qs}");
    let (status, value) = get_json(app, &uri, Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "server must accept CLI-produced query {uri}: {value}"
    );
}

/// Discriminating test for cortex-fzj7: a *non-empty* `terms` Vec must
/// also survive the CLI client serializer → server extractor round-trip.
/// `serde_qs::to_string` emits indexed `terms[0]=..&terms[1]=..`; the server
/// extractor must accept that exact encoding.
#[tokio::test]
async fn ai_investigate_cli_query_with_terms_server_accepts() {
    let req = AiInvestigateRequest {
        incident_id: None,
        terms: vec!["foo".into(), "bar".into()],
        ..Default::default()
    };
    let qs = serde_qs::to_string(&req).expect("serialize investigate request");
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let uri = format!("/api/sessions/investigate?{qs}");
    let (status, value) = get_json(app, &uri, Some("secret")).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "server must accept CLI-produced terms query {uri}: {value}"
    );
}

#[tokio::test]
async fn compose_status_route_exists() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(app, "/api/compose/status", Some("secret")).await;
    // In test env Docker is likely absent; we only assert the route is mounted.
    assert_ne!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn compose_doctor_route_exists() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(app, "/api/compose/doctor", Some("secret")).await;
    assert_ne!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn compose_doctor_unready_returns_structured_projection() {
    let status = crate::compose::ComposeStatus {
        container_name: "cortex".into(),
        container_id: None,
        status: None,
        health: None,
        image: None,
        image_id: None,
        compose_project: None,
        compose_working_dir: None,
        compose_files: Vec::new(),
        service: None,
        data_mounts: Vec::new(),
        ports: Vec::new(),
        systemd: None,
        diagnostics: vec![crate::compose::ComposeDiagnostic {
            severity: crate::compose::DiagnosticSeverity::Error,
            code: "docker_unavailable".into(),
            message: "docker inspect failed".into(),
        }],
    };

    let response = compose_doctor_unready_response(&status, anyhow::anyhow!("not ready"));
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["container_name"], "cortex");
    assert_eq!(value["ownership"], "unknown");
    assert_eq!(value["runtime_state"], "docker_unavailable");
    assert_eq!(value["diagnostics"][0]["code"], "docker_unavailable");
}

// ─── /api/host-state ────────────────────────────────────────────────────────

#[tokio::test]
async fn host_state_defaults_to_freshest_host_and_returns_null_when_empty() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/host-state", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        value.is_null(),
        "expected an empty host-state response: {value}"
    );
}

#[tokio::test]
async fn host_state_returns_400_for_invalid_since_timestamp() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(
        app,
        "/api/host-state?host=foo&since=not-a-timestamp",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert!(value.get("error").is_some(), "missing error: {value}");
}

#[tokio::test]
async fn host_state_returns_404_for_unknown_host() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(app, "/api/host-state?host=nonexistent", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// ─── /api/context ───────────────────────────────────────────────────────────

#[tokio::test]
async fn context_returns_400_without_pivot() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/context", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert!(value.get("error").is_some(), "missing error: {value}");
}

#[tokio::test]
async fn context_returns_404_for_unknown_log_id() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(app, "/api/context?log_id=999999", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// ─── /api/fleet-state ───────────────────────────────────────────────────────

#[tokio::test]
async fn fleet_state_returns_200_with_token_on_empty_db() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(app, "/api/fleet-state", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("hosts").is_some(), "missing hosts: {value}");
    assert!(value.get("summary").is_some(), "missing summary: {value}");
}

#[tokio::test]
async fn fleet_state_accepts_include_ok_and_sort_params() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, _value) = get_json(
        app,
        "/api/fleet-state?include_ok=false&sort=freshness",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

// ─── /api/graph ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn graph_routes_return_shared_service_payloads() {
    let (state, pool, _dir) = test_state(Some("secret".into()));
    db::insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "graph-api-host",
            "info",
            "graph api seed",
            "10.0.0.8:514",
        )],
    )
    .unwrap();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&pool).unwrap();
    }
    let app = test_router(state);

    let (status, value) = get_json(
        app.clone(),
        "/api/graph/entity?entity_type=host&key=graph-api-host",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["resolved_entity"]["canonical_key"], "graph-api-host");
    assert_eq!(value["metadata"]["projection_status"], "ready");

    let (status, value) = get_json(
        app.clone(),
        "/api/graph/around?entity_type=host&key=graph-api-host&depth=1&limit=5",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["resolved_entity"]["canonical_key"], "graph-api-host");
    assert!(!value["relationships"].as_array().unwrap().is_empty());
    assert_eq!(value["metadata"]["depth"], 1);
    let evidence = value["evidence"].as_array().unwrap();
    assert!(
        !evidence.is_empty(),
        "expected graph evidence from around route"
    );
    let evidence_id = evidence[0]["id"].as_i64().unwrap();

    let (status, value) = get_json(
        app.clone(),
        "/api/graph/explain?entity_type=host&key=graph-api-host&depth=2&beam_width=5&max_chains=10",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["resolved_entity"]["canonical_key"], "graph-api-host");
    assert!(!value["chains"].as_array().unwrap().is_empty());
    assert_eq!(value["metadata"]["depth"], 2);

    let (status, value) = get_json(
        app,
        &format!("/api/graph/evidence?evidence_id={evidence_id}"),
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["evidence"]["id"], evidence_id);
    assert!(value["source_log_summary"].is_object());
    assert!(value["src_entity"].is_object());
    assert!(value["dst_entity"].is_object());
    assert!(value["relationship"]["src_entity"].is_object());
    assert!(value["relationship"]["dst_entity"].is_object());
    let serialized = value.to_string();
    assert!(!serialized.contains("metadata_json"));
    assert!(!serialized.contains("\"raw\""));
}

// ── bearer enforcement on new RAG-adjacent / heartbeat routes ───────────────

#[tokio::test]
async fn host_state_route_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/host-state?host=foo", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn context_route_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/context?log_id=1", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fleet_state_route_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/fleet-state", None).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn graph_routes_require_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    for path in [
        "/api/graph/entity?entity_type=host&key=foo",
        "/api/graph/around?entity_type=host&key=foo",
        "/api/graph/explain?entity_type=host&key=foo",
        "/api/graph/evidence?evidence_id=1",
    ] {
        let (status, _) = get_json(app.clone(), path, None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }
}

// ── deny_unknown_fields enforcement on new routes ───────────────────────────

#[tokio::test]
async fn unknown_query_param_returns_400_on_host_state() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/host-state?host=foo&bogus=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_query_param_returns_400_on_context() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/context?bogus=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_query_param_returns_400_on_fleet_state() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(app, "/api/fleet-state?bogus=1", Some("secret")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_query_param_returns_400_on_graph_routes() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    for path in [
        "/api/graph/entity?entity_type=host&key=foo&bogus=1",
        "/api/graph/around?entity_type=host&key=foo&bogus=1",
        "/api/graph/explain?entity_type=host&key=foo&bogus=1",
        "/api/graph/evidence?evidence_id=1&bogus=1",
    ] {
        let (status, _) = get_json(app.clone(), path, Some("secret")).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }
}

// ─── /api/correlate-state (cxih.4) ──────────────────────────────────────────

#[tokio::test]
async fn correlate_state_returns_200_with_token_on_empty_db() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);
    let (status, value) = get_json(
        app,
        "/api/correlate-state?reference_time=2026-05-25T00:00:00Z",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(value.get("window").is_some(), "missing window: {value}");
    assert!(value.get("hosts").is_some(), "missing hosts: {value}");
    assert_eq!(value["truncated"], false, "expected not truncated: {value}");
}

#[tokio::test]
async fn correlate_state_route_requires_bearer() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(
        app,
        "/api/correlate-state?reference_time=2026-05-25T00:00:00Z",
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_query_param_returns_400_on_correlate_state() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = router(state).unwrap();
    let (status, _) = get_json(
        app,
        "/api/correlate-state?reference_time=2026-05-25T00:00:00Z&bogus=1",
        Some("secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

// ── PR #106 reconciliation: GET /api/sessions/llm-invocations admin gating ──
//
// `ai_llm_invocations` is admin-gated like `file_tails`/`ack_error`/
// `unack_error` (see the doc comment on the handler in `src/api.rs`), but
// unlike those it's a GET route with no body, so it needs its own request
// builder rather than reusing `post_json_with_admin`.

async fn get_json_with_admin(
    app: axum::Router,
    uri: &str,
    token: Option<&str>,
    admin_token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(admin_token) = admin_token {
        builder = builder.header("X-Cortex-Admin-Token", admin_token);
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

#[tokio::test]
async fn llm_invocations_route_rejects_when_server_admin_token_unconfigured() {
    let (state, _pool, _dir) = test_state(Some("secret".into()));
    let app = test_router(state);

    let (status, value) = get_json_with_admin(
        app,
        "/api/sessions/llm-invocations",
        Some("secret"),
        Some("admin-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "CORTEX_API_ADMIN_TOKEN required for admin API actions"
    );
}

#[tokio::test]
async fn llm_invocations_route_rejects_wrong_admin_token() {
    let (mut state, _pool, _dir) = test_state(Some("secret".into()));
    state.config.admin_token = crate::config::Secret(Some("admin-secret".into()));
    let app = test_router(state);

    let (status, value) = get_json_with_admin(
        app,
        "/api/sessions/llm-invocations",
        Some("secret"),
        Some("wrong-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        value["error"],
        "X-Cortex-Admin-Token required for admin API actions"
    );
}

#[tokio::test]
async fn llm_invocations_route_rejects_plain_bearer_without_admin_token() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);

    let (status, value) = get_json(app, "/api/sessions/llm-invocations", Some("secret")).await;

    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "body: {value}");
    assert_eq!(
        value["error"],
        "X-Cortex-Admin-Token required for admin API actions"
    );
}

#[tokio::test]
async fn llm_invocations_route_accepts_correct_admin_token() {
    let (state, _pool, _dir) = test_state_with_admin(Some("secret".into()), "admin-secret");
    let app = test_router(state);

    let (status, value) = get_json_with_admin(
        app,
        "/api/sessions/llm-invocations",
        Some("secret"),
        Some("admin-secret"),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "body: {value}");
    assert!(
        value.is_array(),
        "expected a JSON array of invocation rows, got: {value}"
    );
}
