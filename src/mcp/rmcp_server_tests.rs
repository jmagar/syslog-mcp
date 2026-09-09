use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request as AxumRequest,
    http::{Request, StatusCode, header},
    middleware::{self, Next},
};
use lab_auth::AuthContext;
use serde_json::{Value, json};
use tower::util::ServiceExt;

use crate::{
    app::CortexService,
    config::{McpConfig, StorageConfig},
    db::{self, DbPool, LogBatchEntry},
    mcp::{AppState, AuthPolicy, streamable_http_config, streamable_http_service},
};

use super::{
    ToolErrorClass, actions, allowed_hosts, allowed_origins, classify_tool_error,
    required_scope_for,
};

/// Build an AppState with the given auth policy. The two production-relevant
/// policies in these tests (`LoopbackDev`, `Mounted`) share an otherwise
/// identical config, so they differ only in the policy passed here.
fn make_state(auth_policy: AuthPolicy) -> (AppState, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("rmcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let state = AppState {
        service: CortexService::new(Arc::clone(&pool), storage.clone()),
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
        auth_policy,
        observability: Arc::new(crate::observability::RuntimeObservability::default()),
    };
    (state, pool, dir)
}

fn test_state() -> (AppState, Arc<DbPool>, tempfile::TempDir) {
    make_state(AuthPolicy::LoopbackDev)
}

/// Build a Mounted-policy AppState (no OAuth; static-bearer only path).
fn mounted_state() -> (AppState, Arc<DbPool>, tempfile::TempDir) {
    make_state(AuthPolicy::Mounted { auth_state: None })
}

/// Build a test router with an axum middleware that injects `auth_ctx` into
/// request extensions before the request reaches the rmcp service.
fn rmcp_router_with_auth(state: AppState, auth_ctx: AuthContext) -> Router {
    let config = streamable_http_config(&state.config);
    let service = streamable_http_service(state, config);
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(
            move |mut req: AxumRequest, next: Next| {
                let ctx = auth_ctx.clone();
                async move {
                    req.extensions_mut().insert(ctx);
                    next.run(req).await
                }
            },
        ))
}

fn auth_ctx(subject: &str, scopes: Vec<&str>, email: Option<&str>) -> AuthContext {
    AuthContext {
        sub: subject.to_string(),
        actor_key: None,
        scopes: scopes.into_iter().map(String::from).collect(),
        issuer: "local".to_string(),
        via_session: false,
        csrf_token: None,
        email: email.map(String::from),
    }
}

fn auth_ctx_with_scopes(scopes: Vec<&str>) -> AuthContext {
    auth_ctx("test-user@example.com", scopes, None)
}

fn seed_error_signature(pool: &DbPool, hash: &str) {
    let conn = pool.get().unwrap();
    crate::db::error_signatures::upsert_signature(
        &conn,
        crate::db::error_signatures::UpsertSignatureParams {
            hash,
            normalizer_version: crate::app::error_detection::NORMALIZER_VERSION,
            template: "mounted auth coverage",
            sample_message: "mounted auth coverage",
            sample_hostname: "auth-test-host",
            sample_app_name: Some("schema-test"),
            severity: "err",
            first_seen_at: "2026-01-01T00:00:00.000Z",
            last_seen_at: "2026-01-01T00:00:00.000Z",
            delta: 1,
        },
    )
    .unwrap();
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

fn seed_auth_action_log(pool: &DbPool) {
    db::insert_logs_batch(
        pool,
        &[entry(
            "2026-01-01T00:00:00Z",
            "auth-test-host",
            "err",
            "mounted auth coverage",
            "127.0.0.1:514",
        )],
    )
    .unwrap();
}

fn minimal_args_for_action(action: &str) -> Value {
    match action {
        "correlate" => json!({"action": action, "reference_time": "2026-01-01T00:00:00Z"}),
        "search_sessions" => json!({"action": action, "query": "mounted"}),
        "ai_correlate" => json!({"action": action, "project": "/tmp/project"}),
        "project_context" => json!({"action": action, "project": "/tmp/project"}),
        "context" => json!({"action": action, "log_id": 1}),
        "get" => json!({"action": action, "id": 1}),
        "compare" => json!({
            "action": action,
            "a_from": "2026-01-01T00:00:00Z",
            "a_to": "2026-01-01T00:01:00Z",
            "b_from": "2026-01-01T00:01:00Z",
            "b_to": "2026-01-01T00:02:00Z",
        }),
        _ => json!({"action": action}),
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

fn structured_json(response: &Value) -> &Value {
    &response["result"]["structuredContent"]
}

fn assert_invalid_tool_error(response: &Value, action: &str, message_fragment: &str) {
    assert!(
        response.get("error").is_none(),
        "tool validation must use an isError result, not a JSON-RPC error: {response}"
    );
    assert_eq!(response["result"]["isError"], json!(true));

    let structured = structured_json(response);
    assert_eq!(structured["kind"], "invalid_param");
    assert_eq!(structured["action"], action);
    assert_eq!(structured["retryable"], json!(false));
    assert!(
        structured["message"]
            .as_str()
            .is_some_and(|message| message.contains(message_fragment)),
        "expected validation message containing {message_fragment:?}: {structured}"
    );
    assert_eq!(content_json(response), structured.clone());
}

#[test]
fn allowed_hosts_include_bracketed_ipv6_authority_variants() {
    let mut config = McpConfig {
        host: "::1".into(),
        port: 3100,
        server_name: "cortex".into(),
        no_auth: false,
        trusted_gateway_no_auth: false,
        api_token: crate::config::Secret(None),
        allowed_hosts: vec!["[fd00::1]".into(), "syslog.example.com:443".into()],
        allowed_origins: Vec::new(),
        auth: Default::default(),
        forwarding_agents: Default::default(),
        static_token_is_admin: false,
    };

    let hosts = allowed_hosts(&config);
    assert!(hosts.contains(&"::1".to_string()));
    assert!(hosts.contains(&"[::1]".to_string()));
    assert!(hosts.contains(&"[::1]:3100".to_string()));
    assert!(!hosts.contains(&"::1:3100".to_string()));

    config.host = "0.0.0.0".into();
    let hosts = allowed_hosts(&config);
    assert!(hosts.contains(&"[fd00::1]:3100".to_string()));
    assert!(hosts.contains(&"syslog.example.com:443".to_string()));
    assert!(!hosts.contains(&"[syslog.example.com:443]".to_string()));
}

/// Table-driven pin of the typed error classifier (full-review AH1/TM1):
/// every ServiceError variant maps to its distinct class, and untyped anyhow
/// errors — including ones whose MESSAGE looks like a validation error, which
/// fooled the old string-matching classifier — are Internal.
#[test]
fn classify_tool_error_pins_every_variant() {
    use crate::app::ServiceError as E;

    let cases: Vec<(anyhow::Error, ToolErrorClass)> = vec![
        (
            anyhow::Error::new(E::InvalidInput("limit must be <= 1000".into())),
            ToolErrorClass::InvalidParams,
        ),
        (
            anyhow::Error::new(E::Busy("database worker limit reached".into())),
            ToolErrorClass::Retryable,
        ),
        (
            anyhow::Error::new(E::DatabaseTimeout {
                source: anyhow::anyhow!("timed out waiting for connection"),
            }),
            ToolErrorClass::Retryable,
        ),
        (
            anyhow::Error::new(E::NotFound("log id 42 not found".into())),
            ToolErrorClass::NotFound,
        ),
        (anyhow::Error::new(E::RowNotFound), ToolErrorClass::NotFound),
        (
            anyhow::Error::new(E::ConstraintViolation {
                message: "UNIQUE constraint failed".into(),
            }),
            ToolErrorClass::Conflict,
        ),
        (
            anyhow::Error::new(E::Internal(anyhow::anyhow!("disk I/O error"))),
            ToolErrorClass::Internal,
        ),
        // Untyped anyhow → Internal, even when the message resembles the old
        // string-matched validation patterns.
        (
            anyhow::anyhow!("field x is required"),
            ToolErrorClass::Internal,
        ),
        (
            anyhow::anyhow!("value must be <= 7"),
            ToolErrorClass::Internal,
        ),
        (anyhow::anyhow!("disk I/O error"), ToolErrorClass::Internal),
    ];

    for (error, expected) in cases {
        assert_eq!(
            classify_tool_error(&error),
            expected,
            "misclassified: {error}"
        );
    }
}

/// A typed ServiceError surviving an anyhow `?` chain (the tools.rs path)
/// still classifies correctly via downcast.
#[test]
fn classify_tool_error_downcasts_through_anyhow_chain() {
    fn service_call() -> Result<(), crate::app::ServiceError> {
        Err(crate::app::ServiceError::Busy("pool exhausted".into()))
    }
    fn tool_fn() -> anyhow::Result<()> {
        service_call()?;
        Ok(())
    }
    let error = tool_fn().unwrap_err();
    assert_eq!(classify_tool_error(&error), ToolErrorClass::Retryable);
}

#[tokio::test]
async fn rmcp_tools_list_exposes_one_action_tool() {
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
    assert_eq!(names, vec!["cortex"]);
    assert_eq!(tools[0]["inputSchema"]["required"], json!(["action"]));
    assert_eq!(
        tools[0]["_meta"]["ui"]["resourceUri"],
        super::QUERY_WIDGET_RESOURCE_URI
    );
    assert_eq!(
        tools[0]["_meta"]["ui"]["visibility"],
        json!(["model", "app"])
    );
    // Modern flat key (ext-apps RESOURCE_URI_META_KEY) must ride alongside
    // the nested object — host generations differ in which one they read.
    assert_eq!(
        tools[0]["_meta"]["ui/resourceUri"],
        super::QUERY_WIDGET_RESOURCE_URI
    );
}

#[tokio::test]
async fn rmcp_initialize_advertises_prompts_capability() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            13,
            "initialize",
            Some(json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "syslog-test", "version": "1.0"}
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["capabilities"]["prompts"].is_object(),
        "initialize should advertise prompts capability; response: {response}"
    );
}

#[tokio::test]
async fn rmcp_prompts_list_exposes_infra_debugging_prompts() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(14, "prompts/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let prompts = response["result"]["prompts"].as_array().unwrap();
    let names: Vec<&str> = prompts
        .iter()
        .filter_map(|prompt| prompt["name"].as_str())
        .collect();
    assert!(names.contains(&"infra.incident-triage"));
    assert!(names.contains(&"infra.host-health"));
    assert!(names.contains(&"infra.service-outage"));
    assert!(names.contains(&"infra.security-auth-review"));
    assert!(names.contains(&"infra.noise-reduction"));
    assert!(names.contains(&"infra.agent-change-correlation"));
    assert!(names.contains(&"infra.docker-container-regression"));
    assert!(names.contains(&"infra.network-dns-failure"));
    assert!(names.contains(&"infra.storage-pressure"));
    assert!(names.contains(&"infra.auth-bruteforce"));
    assert!(names.contains(&"infra.syslog-forwarding-gap"));
    assert!(names.contains(&"infra.after-deploy-check"));
    assert!(
        prompts.iter().any(|prompt| prompt["arguments"]
            .as_array()
            .is_some_and(|args| !args.is_empty())),
        "prompts should advertise arguments; response: {response}"
    );
}

#[tokio::test]
async fn rmcp_prompts_get_renders_argument_aware_prompt() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            15,
            "prompts/get",
            Some(json!({
                "name": "infra.service-outage",
                "arguments": {
                    "service": "plex",
                    "host": "nashost",
                    "window": "last 45 minutes"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["result"]["description"],
        "Debug a service, app, or container outage from logs and correlated host events."
    );
    let text = response["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("service `plex`"));
    assert!(text.contains("Host: nashost"));
    assert!(text.contains("Window: last 45 minutes"));
    assert!(text.contains("action=correlate"));
}

#[tokio::test]
async fn rmcp_prompts_get_rejects_unknown_prompt() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(16, "prompts/get", Some(json!({"name": "infra.not-real"}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["error"]["code"], -32602);
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("unknown prompt"))
    );
}

#[tokio::test]
async fn rmcp_get_stats_works_against_temp_db() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            2,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "stats"}})),
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
            Some(json!({"name": "cortex", "arguments": {"action": "search", "query": "disk", "limit": 5}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result = content_json(&response);
    assert_eq!(result["count"], 1);
    assert_eq!(result["logs"][0]["hostname"], "host-a");
    let structured = structured_json(&response);
    assert_eq!(structured["count"], 1);
    assert_eq!(structured["logs"][0]["message"], "disk full");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("\"message\": \"disk full\"")),
        "text content should remain readable JSON; response: {response}"
    );
}

#[tokio::test]
async fn rmcp_correlate_events_returns_structured_error_for_bad_reference_time() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            4,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "correlate", "reference_time": "bad"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_invalid_tool_error(&response, "correlate", "reference_time");
}

#[tokio::test]
async fn rmcp_correlate_events_returns_structured_error_for_bad_severity() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            5,
            "tools/call",
            Some(json!({
                "name": "cortex",
                "arguments": {
                    "action": "correlate",
                    "reference_time": "2026-01-01T00:00:00Z",
                    "severity_min": "loud"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_invalid_tool_error(&response, "correlate", "severity_min");
}

#[tokio::test]
async fn rmcp_search_returns_structured_error_for_bad_severity() {
    let (state, _pool, _dir) = test_state();
    let (status, response) = post_rmcp(
        rmcp_router(state),
        jsonrpc_request(
            6,
            "tools/call",
            Some(json!({
                "name": "cortex",
                "arguments": {
                    "action": "search",
                    "severity": "bogus"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_invalid_tool_error(&response, "search", "severity");
}

#[tokio::test]
async fn rmcp_numeric_args_return_structured_errors_for_wrong_types() {
    for (id, action, arguments) in [
        (7, "tail", json!({"action": "tail", "n": "10"})),
        (8, "search", json!({"action": "search", "limit": "5"})),
        (
            9,
            "correlate",
            json!({
                "action": "correlate",
                "reference_time": "2026-01-01T00:00:00Z",
                "window_minutes": "5"
            }),
        ),
        (
            10,
            "correlate",
            json!({
                "action": "correlate",
                "reference_time": "2026-01-01T00:00:00Z",
                "limit": "10"
            }),
        ),
    ] {
        let (state, _pool, _dir) = test_state();
        let (status, response) = post_rmcp(
            rmcp_router(state),
            jsonrpc_request(
                id,
                "tools/call",
                Some(json!({"name": "cortex", "arguments": arguments})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_invalid_tool_error(&response, action, "invalid");
    }
}

#[tokio::test]
async fn rmcp_action_specific_unknown_fields_return_structured_errors() {
    for (id, action, arguments, rejected_field) in [
        (
            101,
            "project_context",
            json!({
                "action": "project_context",
                "project": "/home/jmagar/workspace/cortex",
                "since": "2026-08-01T00:00:00Z"
            }),
            "since",
        ),
        (
            102,
            "list_ai_projects",
            json!({"action": "list_ai_projects", "limit": 20}),
            "limit",
        ),
    ] {
        let (state, _pool, _dir) = test_state();
        let (status, response) = post_rmcp(
            rmcp_router(state),
            jsonrpc_request(
                id,
                "tools/call",
                Some(json!({"name": "cortex", "arguments": arguments})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_invalid_tool_error(
            &response,
            action,
            &format!("unknown field `{rejected_field}`"),
        );
    }
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
            11,
            "tools/call",
            Some(json!({
                "name": "cortex",
                "arguments": {
                    "action": "correlate",
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

// ── PUBLIC_URL host/origin allowlist extension ───────────────────────────────

/// Build a default `McpConfig` (host `0.0.0.0`) whose only non-default field is
/// `auth.public_url`. Shared by the PUBLIC_URL allowlist tests below, which
/// differ only in the URL they assert against.
fn public_url_config(public_url: &str) -> McpConfig {
    McpConfig {
        host: "0.0.0.0".into(),
        port: 3100,
        server_name: "cortex".into(),
        no_auth: false,
        trusted_gateway_no_auth: false,
        api_token: crate::config::Secret(None),
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        auth: crate::config::AuthConfig {
            public_url: Some(public_url.into()),
            ..Default::default()
        },
        forwarding_agents: Default::default(),
        static_token_is_admin: false,
    }
}

/// `CORTEX_PUBLIC_URL` bare host is added to `allowed_hosts`.
#[test]
fn public_url_host_added_to_allowed_hosts() {
    let config = public_url_config("https://syslog.example.com");

    let hosts = allowed_hosts(&config);
    assert!(
        hosts.contains(&"syslog.example.com".to_string()),
        "public_url bare host must be in allowed_hosts; got: {hosts:?}"
    );
}

/// `CORTEX_PUBLIC_URL` standard-port https origin is added to `allowed_origins`
/// without the port (browsers omit default ports from the Origin header).
#[test]
fn public_url_origin_added_to_allowed_origins() {
    let config = public_url_config("https://syslog.example.com");

    let origins = allowed_origins(&config);
    // https on port 443 (default) — browser omits port from Origin header.
    assert!(
        origins.contains(&"https://syslog.example.com".to_string()),
        "public_url origin must be in allowed_origins; got: {origins:?}"
    );
}

/// Non-standard port: host and origin variants both include the explicit port.
#[test]
fn public_url_non_standard_port_included_in_host_and_origin() {
    let config = public_url_config("https://syslog.example.com:8443");

    let hosts = allowed_hosts(&config);
    // Non-standard port: both bare host and host:port must be present.
    // Browsers include the port in the Host header for non-standard ports.
    assert!(
        hosts.contains(&"syslog.example.com".to_string()),
        "expected bare host in allowed_hosts for non-standard port; got: {hosts:?}"
    );
    assert!(
        hosts.contains(&"syslog.example.com:8443".to_string()),
        "expected host:port in allowed_hosts for non-standard port; got: {hosts:?}"
    );

    let origins = allowed_origins(&config);
    // Non-standard port is included in the Origin header by browsers.
    assert!(
        origins.contains(&"https://syslog.example.com:8443".to_string()),
        "expected https://syslog.example.com:8443 in allowed_origins; got: {origins:?}"
    );
}

/// Standard port (https:443): bare host AND host:443 must be in allowed_hosts.
/// Browsers omit the default port from the Host header, so bare host is required.
/// host:443 is also added so rmcp's port-aware comparison passes.
#[test]
fn public_url_standard_https_port_host_variants() {
    let config = public_url_config("https://syslog.example.com");

    let hosts = allowed_hosts(&config);
    // Bare host: what browsers send when using the default port.
    assert!(
        hosts.contains(&"syslog.example.com".to_string()),
        "expected bare host in allowed_hosts for standard port; got: {hosts:?}"
    );
    // host:443: for rmcp's port-aware comparison when the URL port is explicit.
    assert!(
        hosts.contains(&"syslog.example.com:443".to_string()),
        "expected host:443 in allowed_hosts for standard-https URL; got: {hosts:?}"
    );
}

// ── Scope-based authorization tests ──────────────────────────────────────────
//
// These tests verify the fail-closed scope check added in cortex-brt0.8.
// Pattern: middleware injects AuthContext into request extensions; rmcp
// propagates it into RequestContext.extensions via http::request::Parts.

/// `AuthPolicy::LoopbackDev` bypasses all auth checks — any action succeeds
/// regardless of whether AuthContext is present.
#[tokio::test]
async fn loopback_dev_policy_permits_all_actions_without_auth_context() {
    let (state, _pool, _dir) = test_state();
    // No auth middleware — AuthContext is NOT in extensions.
    let router = rmcp_router(state);

    // tools/list should succeed without AuthContext under LoopbackDev.
    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(10, "tools/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["tools"].is_array(),
        "response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(12, "resources/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["resources"].is_array(),
        "resources/list should succeed under LoopbackDev; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(13, "prompts/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["prompts"].is_array(),
        "prompts/list should succeed under LoopbackDev; response: {response}"
    );

    // tools/call should succeed without AuthContext under LoopbackDev.
    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            11,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "stats"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(response["result"].is_object(), "response: {response}");
}

/// `AuthPolicy::Mounted` + valid AuthContext with `cortex:read` → read
/// actions permitted, but admin actions (ack_error, unack_error, notifications_test)
/// are denied.
#[tokio::test]
async fn mounted_policy_with_read_scope_permits_read_actions() {
    let (state, pool, _dir) = mounted_state();
    seed_auth_action_log(&pool);
    let auth = auth_ctx_with_scopes(vec!["cortex:read"]);
    let router = rmcp_router_with_auth(state, auth);

    for action in actions::ACTION_SPECS
        .iter()
        .map(|s| s.name)
        .filter(|action| {
            *action != "help" && actions::required_scope_for(action) != Some("cortex:admin")
        })
    {
        let (status, response) = post_rmcp(
            router.clone(),
            jsonrpc_request(
                20,
                "tools/call",
                Some(json!({"name": "cortex", "arguments": minimal_args_for_action(action)})),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "action={action} should succeed; response: {response}"
        );
        // Must not be a forbidden error (-32600).
        assert_ne!(
            response["error"]["code"], -32600,
            "action={action} got forbidden; response: {response}"
        );
    }

    // Admin actions must be denied for cortex:read-only callers.
    for action in actions::ACTION_SPECS
        .iter()
        .map(|s| s.name)
        .filter(|a| actions::required_scope_for(a) == Some("cortex:admin"))
    {
        let (status, response) = post_rmcp(
            router.clone(),
            jsonrpc_request(
                21,
                "tools/call",
                Some(json!({"name": "cortex", "arguments": minimal_args_for_action(action)})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response["error"]["code"], -32600,
            "admin action={action} should be denied with read-only scope; response: {response}"
        );
        let msg = response["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("requires scope: cortex:admin"),
            "denial message should reference admin scope; got: {msg}"
        );
    }
}

#[test]
fn public_read_actions_require_cortex_read_scope() {
    for action in actions::ACTION_SPECS
        .iter()
        .map(|s| s.name)
        .filter(|action| {
            *action != "help" && actions::required_scope_for(action) != Some("cortex:admin")
        })
    {
        assert_eq!(
            required_scope_for(action),
            Some("cortex:read"),
            "action={action} must require cortex:read"
        );
    }
    // Admin actions require cortex:admin, not cortex:read
    for action in actions::ACTION_SPECS
        .iter()
        .map(|s| s.name)
        .filter(|a| actions::required_scope_for(a) == Some("cortex:admin"))
    {
        assert_eq!(
            required_scope_for(action),
            Some("cortex:admin"),
            "admin action={action} must require cortex:admin"
        );
    }
    assert_eq!(required_scope_for("help"), None);
    assert_eq!(
        required_scope_for("not_a_real_action"),
        Some("cortex:__deny__")
    );
}

#[test]
fn sessions_action_requires_read_scope() {
    assert_eq!(required_scope_for("sessions"), Some("cortex:read"));
}

#[test]
fn compose_actions_require_read_scope() {
    assert_eq!(required_scope_for("compose_status"), Some("cortex:read"));
    assert_eq!(required_scope_for("compose_doctor"), Some("cortex:read"));
}

/// `AuthPolicy::Mounted` + AuthContext with `cortex:admin` (superset) → read
/// actions permitted because `cortex:admin` implies `cortex:read`.
#[tokio::test]
async fn mounted_policy_with_admin_scope_permits_read_actions() {
    let (state, _pool, _dir) = mounted_state();
    // cortex:admin is a superset of cortex:read — check_scope treats it as
    // satisfying any cortex:read requirement (admin ⊃ read superset semantics).
    let auth = auth_ctx_with_scopes(vec!["cortex:admin"]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            30,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "stats"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // cortex:admin implies cortex:read — must be permitted.
    assert_ne!(
        response["error"]["code"], -32600,
        "cortex:admin should satisfy cortex:read requirement; response: {response}"
    );
    assert!(
        response["result"].is_object(),
        "stats should return result; response: {response}"
    );
}

/// `AuthPolicy::Mounted` + AuthContext with BOTH scopes → all actions permitted.
#[tokio::test]
async fn mounted_policy_with_both_scopes_permits_all_actions() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec!["cortex:read", "cortex:admin"]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            40,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "stats"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(response["result"].is_object(), "response: {response}");
}

#[tokio::test]
async fn mounted_admin_actions_record_per_request_subject_actor() {
    let (state, pool, _dir) = mounted_state();
    let signature_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    seed_error_signature(&pool, signature_hash);

    let alice_router = rmcp_router_with_auth(
        state.clone(),
        auth_ctx("alice-subject", vec!["cortex:admin"], None),
    );
    let (status, response) = post_rmcp(
        alice_router,
        jsonrpc_request(
            41,
            "tools/call",
            Some(json!({
                "name": "cortex",
                "arguments": {
                    "action": "ack_error",
                    "signature_hash": signature_hash,
                    "notes": "alice ack"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ack = content_json(&response);
    assert_eq!(ack["actor"], "alice-subject", "response: {response}");

    let bob_router = rmcp_router_with_auth(
        state,
        auth_ctx("bob-subject", vec!["cortex:admin"], Some("bob@example.com")),
    );
    let (status, response) = post_rmcp(
        bob_router,
        jsonrpc_request(
            42,
            "tools/call",
            Some(json!({
                "name": "cortex",
                "arguments": {
                    "action": "unack_error",
                    "signature_hash": signature_hash,
                    "reason": "bob unack"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let unack = content_json(&response);
    assert_eq!(unack["actor"], "bob@example.com", "response: {response}");

    let conn = pool.get().unwrap();
    let events = conn
        .prepare(
            "SELECT event_type, actor FROM error_signature_ack_events
             WHERE signature_hash = ?1
             ORDER BY id",
        )
        .unwrap()
        .query_map([signature_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        events,
        vec![
            ("ack".to_string(), "alice-subject".to_string()),
            ("unack".to_string(), "bob@example.com".to_string()),
        ]
    );
}

/// `AuthPolicy::Mounted` + AuthContext with EMPTY scopes + any action → denied.
#[tokio::test]
async fn mounted_policy_with_empty_scopes_denies_read_actions() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    for action in actions::ACTION_SPECS
        .iter()
        .map(|s| s.name)
        .filter(|action| *action != "help")
    {
        let (status, response) = post_rmcp(
            router.clone(),
            jsonrpc_request(
                50,
                "tools/call",
                Some(json!({"name": "cortex", "arguments": minimal_args_for_action(action)})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response["error"]["code"], -32600,
            "action={action} with empty scopes should be denied; response: {response}"
        );
        let msg = response["error"]["message"].as_str().unwrap_or("");
        // Read actions require cortex:read; admin actions require cortex:admin.
        let expected_scope = if actions::required_scope_for(action) == Some("cortex:admin") {
            "cortex:admin"
        } else {
            "cortex:read"
        };
        assert!(
            msg.contains(&format!("requires scope: {expected_scope}")),
            "error message should name the required scope '{expected_scope}' for action={action}; got: {msg}"
        );
    }
}

/// `AuthPolicy::Mounted` + AuthContext with empty scopes + `help` action →
/// permitted (help requires AuthContext but no scope).
#[tokio::test]
async fn mounted_policy_with_empty_scopes_permits_help_action() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            60,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "help"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // help should succeed (no scope gate) and return tool content.
    assert!(
        response["result"]["content"].is_array(),
        "help should return content; response: {response}"
    );
}

/// Fail-closed: `AuthPolicy::Mounted` + **missing** AuthContext (simulating
/// broken middleware ordering) → ALL actions denied, including `help` and
/// `tools/list`.
#[tokio::test]
async fn mounted_policy_missing_auth_context_denies_all_including_help_and_tools_list() {
    let (state, _pool, _dir) = mounted_state();
    // No auth middleware — AuthContext absent from extensions.
    let router = rmcp_router(state);

    // tools/list must be denied when AuthContext absent under Mounted policy.
    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(70, "tools/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "tools/list with missing AuthContext should be forbidden; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(73, "resources/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "resources/list with missing AuthContext should be forbidden; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(
            74,
            "resources/read",
            Some(json!({"uri": super::SCHEMA_RESOURCE_URI})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "resources/read with missing AuthContext should be forbidden; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(75, "prompts/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "prompts/list with missing AuthContext should be forbidden; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(
            76,
            "prompts/get",
            Some(json!({"name": "infra.incident-triage"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "prompts/get with missing AuthContext should be forbidden; response: {response}"
    );

    // help must also be denied.
    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(
            71,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "help"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "help with missing AuthContext should be forbidden; response: {response}"
    );

    // A read action must also be denied.
    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            72,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "stats"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "stats with missing AuthContext should be forbidden; response: {response}"
    );
}

/// `AuthPolicy::Mounted` + valid AuthContext with `cortex:read` + `tools/list`
/// → capability discovery succeeds (AuthContext present, no scope required).
#[tokio::test]
async fn mounted_policy_with_auth_context_permits_tools_list() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) =
        post_rmcp(router, jsonrpc_request(80, "tools/list", Some(json!({})))).await;
    assert_eq!(status, StatusCode::OK);
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(
        tools[0]["name"], "cortex",
        "tools/list should return cortex tool; response: {response}"
    );
}

#[tokio::test]
async fn mounted_policy_with_auth_context_permits_schema_resources() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(81, "resources/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resources = response["result"]["resources"].as_array().unwrap();
    let uris: Vec<&str> = resources
        .iter()
        .filter_map(|resource| resource["uri"].as_str())
        .collect();
    assert!(
        uris.contains(&super::SCHEMA_RESOURCE_URI),
        "resources/list should expose schema resource; response: {response}"
    );
    assert!(
        uris.contains(&super::PROMPT_OUTPUT_SCHEMA_RESOURCE_URI),
        "resources/list should expose prompt output schema resource; response: {response}"
    );
    assert!(
        uris.contains(&super::QUERY_WIDGET_RESOURCE_URI),
        "resources/list should expose query widget resource; response: {response}"
    );

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(
            82,
            "resources/read",
            Some(json!({"uri": super::SCHEMA_RESOURCE_URI})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["contents"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("\"name\": \"cortex\"")
                && text.contains("x-cortex-action-metadata")),
        "resources/read should return schema JSON; response: {response}"
    );

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            821,
            "resources/read",
            Some(json!({"uri": super::PROMPT_OUTPUT_SCHEMA_RESOURCE_URI})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("prompt output schema text");
    let schema: serde_json::Value =
        serde_json::from_str(text).expect("prompt output resource is valid JSON schema");
    assert_eq!(
        schema["required"],
        json!([
            "verdict",
            "confidence",
            "evidence",
            "likely_cause",
            "not_supported",
            "next_actions",
            "telemetry_gaps"
        ])
    );
    assert_eq!(
        schema["properties"]["evidence"]["items"]["required"],
        json!([
            "source",
            "summary",
            "timestamp",
            "host",
            "app",
            "severity",
            "log_id"
        ])
    );
    assert_eq!(
        schema["properties"]["evidence"]["items"]["properties"]["app"]["type"],
        json!(["string", "null"])
    );
}

#[tokio::test]
async fn mounted_policy_with_auth_context_permits_prompts() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router.clone(),
        jsonrpc_request(83, "prompts/list", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["prompts"]
            .as_array()
            .is_some_and(|prompts| {
                prompts
                    .iter()
                    .any(|prompt| prompt["name"] == "infra.incident-triage")
            }),
        "prompts/list should expose infra prompts; response: {response}"
    );

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            84,
            "prompts/get",
            Some(json!({"name": "infra.incident-triage"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["result"]["messages"][0]["content"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Return exactly these sections:")
                && text.contains("- Verdict:")
                && text.contains("bucket=minute")
                && text.contains("limit=10")),
        "prompts/get should render tightened prompt text; response: {response}"
    );
}

#[tokio::test]
async fn mounted_policy_with_auth_context_permits_query_widget_resource() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            83,
            "resources/read",
            Some(json!({"uri": super::QUERY_WIDGET_RESOURCE_URI})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["result"]["contents"][0]["uri"],
        super::QUERY_WIDGET_RESOURCE_URI
    );
    assert_eq!(
        response["result"]["contents"][0]["mimeType"],
        super::MCP_APP_HTML_MIME_TYPE
    );
    let widget_html = response["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        widget_html.contains("data-syslog-query-widget"),
        "resources/read should return query widget HTML; response: {response}"
    );
    // Stable anchors the widget UI depends on. These guard the wire format
    // (per yi66 risk note: verify format, do not assume a host renderer).
    for anchor in [
        "value=\"search\"",        // hidden action input -> action=search
        "name=\"query\"",          // FTS5 query field
        "name=\"hostname\"",       // hostname filter
        "name=\"severity\"",       // severity filter
        "name=\"limit\"",          // limit control
        "data-rows",               // results table body
        "Host bridge unavailable", // graceful bridge-unavailable state
        "ui-message-response",     // mcp-ui postMessage bridge protocol
        "event.source",            // origin-bound message guard (anti-spoof)
    ] {
        assert!(
            widget_html.contains(anchor),
            "query widget HTML missing stable anchor {anchor:?}; response: {response}"
        );
    }
}

/// Scope check fires BEFORE execute_tool — a read denied by scope must not
/// trigger any DB query. Verified by asserting the error comes back without
/// any `content` field (DB results would appear in content).
#[tokio::test]
async fn scope_check_fires_before_db_execution() {
    let (state, _pool, _dir) = mounted_state();
    let auth = auth_ctx_with_scopes(vec![]); // no scopes → denied before DB
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            90,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "search", "query": "error"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Must be a JSON-RPC error (scope denied), not a successful result.
    assert_eq!(
        response["error"]["code"], -32600,
        "scope check must fire before DB; response: {response}"
    );
    assert!(
        response.get("result").is_none() || response["result"].is_null(),
        "no result should be present when scope check fails; response: {response}"
    );
}

/// Unknown action → denied by `syslog:__deny__` sentinel, not passed through.
///
/// The catch-all arm of `required_scope_for` returns `Some("cortex:__deny__")`
/// — a scope that is never granted — so unknown actions are rejected at the
/// auth layer rather than falling through to `execute_tool`.
/// This prevents future actions added to dispatch but not to the scope map
/// from being silently accessible with only `cortex:read`.
#[tokio::test]
async fn unknown_action_is_denied_by_sentinel_scope() {
    let (state, _pool, _dir) = mounted_state();
    // cortex:read + cortex:admin — both real scopes, but neither matches __deny__
    let auth = auth_ctx_with_scopes(vec!["cortex:read", "cortex:admin"]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            100,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "not_a_real_action"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Must be a JSON-RPC error — the sentinel scope is never granted.
    assert_eq!(
        response["error"]["code"], -32600,
        "unknown action must be denied by sentinel scope; response: {response}"
    );
    let msg = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("requires scope"),
        "denial message should reference scope requirement; got: {msg}"
    );
}

// llm_invocations exposes circuit-breaker/kill-switch operational state
// (status/error/metadata_json) — it must be admin-scoped, not cortex:read.
// See eng review Fix 4 (security reviewer, MP2) in the LLM invocation
// guard plan. This is additive alongside the generic admin-denial loop in
// mounted_policy_with_read_scope_permits_read_actions, mirroring how this
// repo already has an explicit sessions_action_requires_read_scope test
// alongside its own generic loop.
#[test]
fn llm_invocations_action_requires_admin_scope() {
    assert_eq!(
        required_scope_for("llm_invocations"),
        Some("cortex:admin"),
        "llm_invocations exposes circuit-breaker/kill-switch operational \
         state and must be admin-scoped, not cortex:read (eng review Fix 4)"
    );
}

#[tokio::test]
async fn llm_invocations_action_is_denied_for_read_only_scope() {
    let (state, pool, _dir) = mounted_state();
    seed_auth_action_log(&pool);
    let auth = auth_ctx_with_scopes(vec!["cortex:read"]);
    let router = rmcp_router_with_auth(state, auth);

    let (status, response) = post_rmcp(
        router,
        jsonrpc_request(
            30,
            "tools/call",
            Some(json!({"name": "cortex", "arguments": {"action": "llm_invocations"}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32600,
        "llm_invocations must be denied for a cortex:read-only caller; response: {response}"
    );
    let msg = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("requires scope: cortex:admin"),
        "denial message should reference admin scope; got: {msg}"
    );
}

#[test]
fn widget_embed_opt_in_defaults_off() {
    use super::parse_widget_embed;
    assert!(!parse_widget_embed(None));
    assert!(!parse_widget_embed(Some("")));
    assert!(!parse_widget_embed(Some("0")));
    assert!(!parse_widget_embed(Some("false")));
    assert!(!parse_widget_embed(Some("nonsense")));
    assert!(parse_widget_embed(Some("1")));
    assert!(parse_widget_embed(Some("true")));
    assert!(parse_widget_embed(Some(" TRUE ")));
    assert!(parse_widget_embed(Some("yes")));
    assert!(parse_widget_embed(Some("on")));
}

#[test]
fn widget_embeds_only_for_query_actions_and_only_when_enabled() {
    use super::should_embed_widget;
    for action in ["search", "filter", "tail", "errors"] {
        assert!(
            should_embed_widget(action, true),
            "{action} should embed when enabled"
        );
        assert!(
            !should_embed_widget(action, false),
            "{action} must not embed when disabled"
        );
    }
    for action in ["help", "stats", "get", "ack_error", "hosts", ""] {
        assert!(
            !should_embed_widget(action, true),
            "{action} must never embed"
        );
    }
}

#[test]
fn embedded_widget_content_matches_resource_declaration() {
    use rmcp::model::{ResourceContents, Role};

    let content = super::embedded_widget_content();
    assert_eq!(
        content
            .as_resource()
            .and_then(|embedded| embedded.annotations.as_ref())
            .and_then(|annotations| annotations.audience.as_ref()),
        Some(&vec![Role::User]),
        "widget block must be user-audience so audience-aware hosts keep it out of model context"
    );
    let embedded = content
        .as_resource()
        .expect("widget block must be an embedded resource");
    let ResourceContents::TextResourceContents {
        uri,
        mime_type,
        text,
        ..
    } = &embedded.resource
    else {
        panic!("widget resource must be text contents");
    };
    assert_eq!(uri, super::QUERY_WIDGET_RESOURCE_URI);
    assert_eq!(mime_type.as_deref(), Some(super::MCP_APP_HTML_MIME_TYPE));
    assert!(
        text.contains("data-syslog-query-widget"),
        "embedded HTML should be the query widget"
    );
}
