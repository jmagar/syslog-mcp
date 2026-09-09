use super::*;
use crate::app::CortexService;
use crate::config::{McpConfig, StorageConfig};
use crate::db;
use crate::mcp::{AppState, AuthPolicy};
use axum::body::to_bytes;
use axum::http::{Method, Request, StatusCode, header};
use std::sync::Arc;
use tower::util::ServiceExt;

/// Build an AppState with LoopbackDev policy (no auth applied).
fn test_state_no_auth() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        AppState {
            service: CortexService::new(pool, storage.clone()),
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "cortex".into(),
                no_auth: false,
                trusted_gateway_no_auth: false,
                api_token: crate::config::Secret(None),
                allowed_hosts: Vec::new(),
                allowed_origins: Vec::new(),
                auth: Default::default(),
                forwarding_agents: Default::default(),
                static_token_is_admin: false,
            },
            notifications_config: crate::config::NotificationsConfig::default(),
            otlp_counters: Arc::new(crate::otlp::OtlpCounters::default()),
            auth_policy: AuthPolicy::LoopbackDev,
            observability: Arc::new(crate::observability::RuntimeObservability::default()),
        },
        dir,
    )
}

/// Build an AppState with Mounted { auth_state: None } policy (static-bearer auth via AuthLayer).
fn test_state_with_token(token: String) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    (
        AppState {
            service: CortexService::new(pool, storage.clone()),
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "cortex".into(),
                no_auth: false,
                trusted_gateway_no_auth: false,
                api_token: crate::config::Secret(Some(token)),
                allowed_hosts: Vec::new(),
                allowed_origins: Vec::new(),
                auth: Default::default(),
                forwarding_agents: Default::default(),
                static_token_is_admin: false,
            },
            notifications_config: crate::config::NotificationsConfig::default(),
            otlp_counters: Arc::new(crate::otlp::OtlpCounters::default()),
            // Mounted { auth_state: None } = static-bearer only; AuthLayer IS applied.
            auth_policy: AuthPolicy::Mounted { auth_state: None },
            observability: Arc::new(crate::observability::RuntimeObservability::default()),
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
        let (state, dir) = test_state_no_auth();
        TestHarness { state, _dir: dir }
    }

    fn with_token(token: String) -> Self {
        let (state, dir) = test_state_with_token(token);
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
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
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
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // /health is the minimal liveness probe — no ingest counters.
    assert_eq!(value["status"], "ok");
    assert!(value.get("ingest").is_none());
}

/// A started-then-dead syslog listener must fail /health so the Docker
/// healthcheck turns unhealthy and the restart policy can recover ingestion
/// (bead syslog-mcp-7f0y).
#[tokio::test]
async fn integration_health_returns_503_when_listener_down() {
    let h = TestHarness::new();
    h.state
        .observability
        .set_udp_listener_state(crate::observability::ListenerState::Down);
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["reason"], "syslog listener down");
}

/// TCP-only down (UDP stays NotStarted) must still fail /health with 503.
#[tokio::test]
async fn integration_health_returns_503_when_tcp_listener_down() {
    let h = TestHarness::new();
    h.state
        .observability
        .set_tcp_listener_state(crate::observability::ListenerState::Down);
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["reason"], "syslog listener down");
}

/// Alive listeners (the normal serve-mode state) keep /health at 200.
#[tokio::test]
async fn integration_health_returns_200_with_alive_listeners() {
    let h = TestHarness::new();
    h.state
        .observability
        .set_udp_listener_state(crate::observability::ListenerState::Alive);
    h.state
        .observability
        .set_tcp_listener_state(crate::observability::ListenerState::Alive);
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn integration_initialize() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        1,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "route-test", "version": "1.0"}
        })),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["result"]["protocolVersion"].is_string());
    assert!(value["result"]["serverInfo"]["name"].is_string());
}

#[tokio::test]
async fn integration_get_stats() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        3,
        "tools/call",
        Some(serde_json::json!({"name": "cortex", "arguments": {"action": "stats"}})),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, StatusCode::OK);
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
        Some(serde_json::json!({"name": "cortex", "arguments": {"action": "tail", "n": 10}})),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["error"].is_null(), "unexpected error: {value}");
}

#[tokio::test]
async fn integration_search_logs_empty_db() {
    let h = TestHarness::new();
    let body = jsonrpc_request(
        5,
        "tools/call",
        Some(
            serde_json::json!({"name": "cortex", "arguments": {"action": "search", "query": "error", "limit": 5}}),
        ),
    );
    let (status, value) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["error"].is_null(), "unexpected error: {value}");
}

#[tokio::test]
async fn integration_auth_missing_token_returns_401() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(7, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn integration_auth_correct_token_succeeds() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(8, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("secret-token")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn mcp_accepts_case_insensitive_bearer_scheme() {
    let h = TestHarness::with_token("secret-token".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Authorization", "bearer secret-token")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(10, "tools/list", None)).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_cors_uses_configured_port() {
    let (mut state, _dir) = test_state_no_auth();
    state.config.port = 3201;
    let app = router(state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("Origin", "http://localhost:3201")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:3201"
    );
}

#[tokio::test]
async fn mcp_cors_allows_configured_origins() {
    let (mut state, _dir) = test_state_no_auth();
    state.config.allowed_origins = vec!["https://syslog.example.com".into()];
    let app = router(state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("Origin", "https://syslog.example.com")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://syslog.example.com"
    );
}

#[tokio::test]
async fn mcp_cors_preflight_allows_only_required_request_headers() {
    let (mut state, _dir) = test_state_no_auth();
    state.config.allowed_origins = vec!["https://syslog.example.com".into()];
    let app = router(state);
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/mcp")
        .header("Origin", "https://syslog.example.com")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,content-type,accept,mcp-protocol-version,mcp-session-id",
        )
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let allowed = response
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    let allowed_tokens: Vec<&str> = allowed.split(',').map(str::trim).collect();
    for header in [
        "authorization",
        "content-type",
        "accept",
        "mcp-protocol-version",
        "mcp-session-id",
    ] {
        assert!(
            allowed_tokens.contains(&header),
            "missing {header} from allow-headers: {allowed}"
        );
    }
    assert!(
        !allowed_tokens.contains(&"x-unexpected-header"),
        "CORS allow-headers must not reflect arbitrary request headers: {allowed}"
    );
}

#[tokio::test]
async fn mcp_rejects_wrong_token() {
    let h = TestHarness::with_token("secret-token".into());
    let body = jsonrpc_request(9, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("wrong-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_sse_endpoint_is_removed() {
    let h = TestHarness::with_token("secret-token".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/sse")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = Request::builder()
        .method("GET")
        .uri("/sse")
        .header("Authorization", "Bearer secret-token")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_mcp_request_is_rejected_by_body_limit() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::CONTENT_LENGTH, "70000")
        .body(axum::body::Body::from("x".repeat(70_000)))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn mcp_rejects_missing_accept_header() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(11, "tools/list", None)).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn mcp_rejects_missing_content_type_header() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(12, "tools/list", None)).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn mcp_rejects_unsupported_protocol_version() {
    let h = TestHarness::new();
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "1900-01-01")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(13, "tools/list", None)).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stateless_mcp_rejects_get_and_delete() {
    let h = TestHarness::new();
    let app = router(h.state);
    for method in [Method::GET, Method::DELETE] {
        let request = Request::builder()
            .method(method.clone())
            .uri("/mcp")
            .header(header::HOST, "localhost:3100")
            .header(header::ACCEPT, "text/event-stream")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

// ── AuthPolicy coverage ──────────────────────────────────────────────────────

/// LoopbackDev: AuthLayer is NOT applied; requests reach /mcp without any token.
#[tokio::test]
async fn loopback_dev_policy_skips_auth_layer() {
    let h = TestHarness::new(); // LoopbackDev, no token
    let body = jsonrpc_request(20, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "LoopbackDev must not require bearer token"
    );
}

/// Mounted { auth_state: None }: valid static token → 200.
#[tokio::test]
async fn mounted_static_bearer_valid_token_succeeds() {
    let h = TestHarness::with_token("static-secret".into());
    let body = jsonrpc_request(21, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("static-secret")).await;
    assert_eq!(status, StatusCode::OK);
}

/// Mounted { auth_state: None }: wrong static token → 401 (no fall-through to permit).
#[tokio::test]
async fn mounted_static_bearer_wrong_token_returns_401_no_fallthrough() {
    let h = TestHarness::with_token("static-secret".into());
    let body = jsonrpc_request(22, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, Some("wrong-token")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "AuthLayer must not fall through on bad token"
    );
}

/// Mounted { auth_state: None }: no credentials at all → 401 (fail-closed; no permit fallthrough).
#[tokio::test]
async fn mounted_missing_credentials_returns_401_fail_closed() {
    let h = TestHarness::with_token("static-secret".into());
    let body = jsonrpc_request(23, "tools/list", None);
    let (status, _) = mcp_post(router(h.state), body, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing credentials must be rejected, not permitted"
    );
}

/// Mounted: cookie header without Authorization is ignored — bearer-only mode.
#[tokio::test]
async fn mounted_cookie_without_bearer_is_rejected() {
    let h = TestHarness::with_token("static-secret".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::COOKIE, "session=some-session-id")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(24, "tools/list", None)).unwrap(),
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "session cookie must not bypass bearer-only AuthLayer"
    );
}

/// Bearer-only mode: valid static token + scope-gated action (stats) → 200.
///
/// Regression test for the bug where `build_auth_layer` built an `AuthLayer`
/// with `static_token_scopes: Vec::new()` in bearer-only mode because
/// `AuthLayer::with_auth_state(None)` does not populate scopes.
/// After the S-03 fix, `build_auth_layer` explicitly calls `.with_static_token_scopes`
/// so the `AuthContext` injected by the layer carries `["cortex:read"]` by default
/// (or `["cortex:read", "cortex:admin"]` when `static_token_is_admin=true`).
/// `stats` requires only `cortex:read`, so it succeeds with the default token.
#[tokio::test]
async fn mounted_static_bearer_valid_token_can_call_scope_gated_action() {
    let h = TestHarness::with_token("static-secret".into());
    // `stats` requires cortex:read — it is scope-gated at the rmcp layer.
    let body = jsonrpc_request(
        25,
        "tools/call",
        Some(serde_json::json!({"name": "cortex", "arguments": {"action": "stats"}})),
    );
    let (status, response) = mcp_post(router(h.state), body, Some("static-secret")).await;
    assert_eq!(status, StatusCode::OK, "response: {response}");
    // Must be a successful result, not a JSON-RPC scope-denial error.
    assert!(
        response.get("error").is_none() || response["error"].is_null(),
        "static bearer token must pass scope check for stats; response: {response}"
    );
    assert!(
        response["result"].is_object(),
        "stats result expected; response: {response}"
    );
}

/// S-03: Static bearer token without CORTEX_STATIC_TOKEN_ADMIN=true
/// must NOT be able to call admin actions (ack_error, unack_error, notifications_test).
#[tokio::test]
async fn static_bearer_token_cannot_call_admin_actions_by_default() {
    // `static_token_is_admin: false` (the default in test_state_with_token)
    let h = TestHarness::with_token("static-secret".into());
    let app = router(h.state);
    // `ack_error` requires cortex:admin — must be denied for read-only static token
    let body = jsonrpc_request(
        30,
        "tools/call",
        Some(serde_json::json!({
            "name": "cortex",
            "arguments": {"action": "ack_error", "signature_hash": "0000000000000000000000000000000000000000000000000000000000000000"}
        })),
    );
    let (status, response) = mcp_post(app.clone(), body, Some("static-secret")).await;
    assert_eq!(status, StatusCode::OK, "response: {response}");
    // Must be denied with a scope error (-32600 / forbidden).
    assert_eq!(
        response["error"]["code"], -32600,
        "static bearer without admin opt-in must be denied for ack_error; response: {response}"
    );
    let msg = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("requires scope: cortex:admin"),
        "denial message should name cortex:admin; got: {msg}"
    );
}

/// /health stays unauthenticated even when Mounted policy is active.
#[tokio::test]
async fn health_unauthenticated_under_mounted_policy() {
    let h = TestHarness::with_token("static-secret".into());
    let app = router(h.state);
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ── OAuth router mount tests ─────────────────────────────────────────────────

/// Helper: build an AppState with `AuthPolicy::Mounted { auth_state: Some(...) }`.
///
/// Uses tempfiles for the SQLite store and JWT key so no real filesystem paths
/// are required. Calls `lab_auth::state::AuthState::new` with a minimal OAuth
/// config (mode=oauth, public_url, fake Google credentials).
async fn test_state_with_oauth() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    // Auth files live in the same tempdir as the syslog DB.
    let auth_db = dir.path().join("auth.db");
    let auth_key = dir.path().join("auth.pem");

    // Key names match lab-auth's AuthConfigBuilder env_key() function:
    // env_key(prefix, suffix) → "{PREFIX}_{SUFFIX}" (uppercased).
    // e.g. env_key("CORTEX", "AUTH_MODE") → "CORTEX_AUTH_MODE"
    //      env_key("CORTEX", "GOOGLE_CLIENT_ID") → "CORTEX_GOOGLE_CLIENT_ID"
    let vars: Vec<(String, String)> = vec![
        ("CORTEX_AUTH_MODE".into(), "oauth".into()),
        (
            "CORTEX_PUBLIC_URL".into(),
            "https://syslog.example.com".into(),
        ),
        // Google credential keys do NOT have "AUTH_" prefix in lab-auth's schema.
        ("CORTEX_GOOGLE_CLIENT_ID".into(), "test-client-id".into()),
        (
            "CORTEX_GOOGLE_CLIENT_SECRET".into(),
            "test-client-secret".into(),
        ),
        ("CORTEX_AUTH_ADMIN_EMAIL".into(), "admin@example.com".into()),
        (
            "CORTEX_AUTH_SQLITE_PATH".into(),
            auth_db.to_str().unwrap().into(),
        ),
        (
            "CORTEX_AUTH_KEY_PATH".into(),
            auth_key.to_str().unwrap().into(),
        ),
    ];

    let auth_config = lab_auth::config::AuthConfigBuilder::new()
        .env_prefix("CORTEX")
        .session_cookie_name("cortex_session")
        .scopes_supported(vec!["cortex:read".into(), "cortex:admin".into()])
        .default_scope("cortex:read")
        .resource_path("/mcp")
        .enable_dynamic_registration(true)
        .build_from_sources(vars)
        .expect("test auth config should build");

    let auth_state = lab_auth::state::AuthState::new(auth_config)
        .await
        .expect("test auth state should init");

    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());

    let state = AppState {
        service: CortexService::new(pool, storage.clone()),
        config: McpConfig {
            host: "127.0.0.1".into(),
            port: 3100,
            server_name: "cortex".into(),
            no_auth: false,
            trusted_gateway_no_auth: false,
            api_token: crate::config::Secret(None),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            auth: crate::config::AuthConfig {
                public_url: Some("https://syslog.example.com".into()),
                ..Default::default()
            },
            forwarding_agents: Default::default(),
            static_token_is_admin: false,
        },
        notifications_config: crate::config::NotificationsConfig::default(),
        otlp_counters: Arc::new(crate::otlp::OtlpCounters::default()),
        auth_policy: AuthPolicy::Mounted {
            auth_state: Some(Arc::new(auth_state)),
        },
        observability: Arc::new(crate::observability::RuntimeObservability::default()),
    };

    (state, dir)
}

/// OAuth router IS mounted when auth_state: Some(_).
/// GET /.well-known/oauth-authorization-server returns 200.
#[tokio::test]
async fn oauth_router_mounted_when_auth_state_is_some() {
    let (state, _dir) = test_state_with_oauth().await;
    let app = router(state);
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "OAuth well-known endpoint must be reachable when auth_state is Some"
    );
}

/// The external lab-auth router is upgraded independently, so its complete
/// contracted method/path surface must remain mounted. This prevents the
/// declaration passed to `contracted_external_router` from becoming a
/// post-hoc list that stays green after an upstream route is removed.
#[tokio::test]
async fn every_contracted_external_oauth_route_is_mounted_with_its_method() {
    let (state, _dir) = test_state_with_oauth().await;
    let app = router(state);

    for binding in crate::surfaces::OAUTH_ROUTE_BINDINGS {
        let (method, path) = binding.split_once(' ').expect("METHOD /path binding");
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "contracted external OAuth route {binding} is not mounted"
        );
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "contracted external OAuth route {binding} is mounted with the wrong method"
        );
    }
}

/// Codex derives OAuth discovery URLs from the configured MCP URL
/// (`https://host/mcp`) unless `oauth_resource` is set, so support the same
/// metadata under `/mcp/.well-known/*` when OAuth is active.
#[tokio::test]
async fn oauth_router_mounts_path_based_discovery_for_codex() {
    let (state, _dir) = test_state_with_oauth().await;
    let app = router(state);

    for path in [
        "/mcp/.well-known/oauth-authorization-server",
        "/mcp/.well-known/openid-configuration",
        "/mcp/.well-known/oauth-protected-resource",
    ] {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "OAuth discovery endpoint {path} must be reachable for Codex"
        );
    }
}

/// OAuth router NOT mounted when auth_state: None (bearer-only).
/// GET /.well-known/oauth-authorization-server returns 404.
#[tokio::test]
async fn oauth_router_not_mounted_when_bearer_only() {
    // Mounted { auth_state: None } = bearer-only; no OAuth router.
    let (state, _dir) = test_state_with_token("some-token".into());
    let app = router(state);
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "OAuth well-known endpoint must NOT be mounted in bearer-only mode"
    );
}

/// OAuth router NOT mounted when LoopbackDev.
#[tokio::test]
async fn oauth_router_not_mounted_when_loopback_dev() {
    let (state, _dir) = test_state_no_auth();
    let app = router(state);
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "OAuth well-known endpoint must NOT be mounted in LoopbackDev mode"
    );
}

/// POST /register is 404 in LoopbackDev and bearer-only (no OAuth router), but
/// mounted in OAuth mode so MCP clients can self-register (RFC-7591).
#[tokio::test]
async fn register_mounted_only_in_oauth_mode() {
    let (loopback_state, _dir1) = test_state_no_auth();
    let (bearer_state, _dir2) = test_state_with_token("tok".into());
    let (oauth_state, _dir3) = test_state_with_oauth().await;

    for (label, state, mounted) in [
        ("LoopbackDev", loopback_state, false),
        ("bearer-only", bearer_state, false),
        ("OAuth", oauth_state, true),
    ] {
        let app = router(state);
        let request = Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"redirect_uris":[]}"#))
            .unwrap();
        let status = app.oneshot(request).await.unwrap().status();
        if mounted {
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "POST /register must be mounted in {label} mode"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "POST /register must not be mounted in {label} mode"
            );
        }
    }
}

/// GET /auth/login is 404 in LoopbackDev and bearer-only (no OAuth router), but
/// mounted in OAuth mode (full browser router → 302 redirect).
#[tokio::test]
async fn auth_login_mounted_only_in_oauth_mode() {
    let (loopback_state, _dir1) = test_state_no_auth();
    let (bearer_state, _dir2) = test_state_with_token("tok".into());
    let (oauth_state, _dir3) = test_state_with_oauth().await;

    for (label, state, mounted) in [
        ("LoopbackDev", loopback_state, false),
        ("bearer-only", bearer_state, false),
        ("OAuth", oauth_state, true),
    ] {
        let app = router(state);
        let request = Request::builder()
            .method("GET")
            .uri("/auth/login")
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(request).await.unwrap().status();
        if mounted {
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "GET /auth/login must be mounted in {label} mode"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "GET /auth/login must not be mounted in {label} mode"
            );
        }
    }
}

/// null-Origin is rejected (403 Forbidden) by rmcp's internal origin validator
/// on the /mcp endpoint.
///
/// rmcp's StreamableHttpService validates the Origin header before routing and
/// parses "null" as NormalizedOrigin::Null. Since "null" is never in our
/// allowed_origins list, the request is rejected with 403 Forbidden. This
/// makes the implicit rejection of spoofed sandboxed-iframe origins explicit
/// and verifiable.
///
/// Note: tower-http CorsLayer (applied to /health and other non-rmcp routes)
/// does NOT actively reject null-Origin — it simply omits the ACAO header and
/// relies on the browser to block the cross-origin read. The active 403 comes
/// from rmcp's DNS-rebinding guard on /mcp.
#[tokio::test]
async fn null_origin_rejected_by_rmcp_validator_on_mcp_endpoint() {
    let h = TestHarness::new(); // LoopbackDev — no auth so we reach the origin check
    let app = router(h.state);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost:3100")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Origin", "null")
        .body(axum::body::Body::from(
            serde_json::to_vec(&jsonrpc_request(99, "tools/list", None)).unwrap(),
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Origin: null must be rejected by rmcp's origin validator (NormalizedOrigin::Null \
         is never in the allowed_origins list)"
    );
}

// NOTE: Tests for allowed_hosts() / allowed_origins() public_url extension
// live in rmcp_server_tests.rs (same module as the functions, via `use super::*`).
