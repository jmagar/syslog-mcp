use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::{
    RuntimeCore, background_interval, build_auth_policy, mcp_static_token_active,
    reject_unsafe_otlp_oauth_only_exposure, resolve_auth_path, retention_initial_delay_from,
};
use crate::config::{AuthConfig, AuthMode, Config, McpConfig, StorageConfig};
use crate::mcp::AuthPolicy;

#[tokio::test]
async fn background_interval_waits_full_period_before_first_tick() {
    let delay = tokio::time::Duration::from_millis(25);
    let mut interval = background_interval(delay);
    let started = std::time::Instant::now();
    interval.tick().await;
    assert!(
        started.elapsed() >= tokio::time::Duration::from_millis(20),
        "first tick should wait roughly one full period before firing"
    );
}

#[test]
fn retention_initial_delay_is_test_gated_and_bounded() {
    assert_eq!(
        retention_initial_delay_from(None, Some("1")).as_secs(),
        3600
    );
    assert_eq!(
        retention_initial_delay_from(Some("0"), Some("1")).as_secs(),
        3600
    );
    assert_eq!(
        retention_initial_delay_from(Some("1"), Some("1")).as_secs(),
        1
    );
    assert_eq!(
        retention_initial_delay_from(Some("1"), Some("60")).as_secs(),
        60
    );
    assert_eq!(
        retention_initial_delay_from(Some("1"), Some("0")).as_secs(),
        3600
    );
    assert_eq!(
        retention_initial_delay_from(Some("1"), Some("61")).as_secs(),
        3600
    );
    assert_eq!(
        retention_initial_delay_from(Some("1"), Some("invalid")).as_secs(),
        3600
    );
}

/// Build a minimal `Config` rooted at `tmp` with the supplied overrides.
fn test_config(tmp: &std::path::Path, mcp: McpConfig) -> Config {
    let storage = StorageConfig::for_test(tmp.join("cortex.db"));
    Config {
        receiver: Default::default(),
        storage,
        mcp,
        api: Default::default(),
        docker_ingest: Default::default(),
        enrichment: Default::default(),
        error_detection: Default::default(),
        notifications: Default::default(),
        llm: Default::default(),
        agent_observatory: Default::default(),
        server_id: None,
        cursor_signing_key: crate::config::Secret(None),
        cursor_previous_keys: Vec::new(),
    }
}

fn loopback_mcp() -> McpConfig {
    McpConfig {
        host: "127.0.0.1".into(),
        port: 3100,
        server_name: "cortex".into(),
        no_auth: false,
        trusted_gateway_no_auth: false,
        api_token: crate::config::Secret(None),
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        auth: AuthConfig::default(),
        forwarding_agents: Default::default(),
        static_token_is_admin: false,
    }
}

#[tokio::test]
async fn build_auth_policy_rejects_no_auth_non_loopback_without_trusted_gateway() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = loopback_mcp();
    mcp.host = "0.0.0.0".into();
    mcp.no_auth = true;
    let config = test_config(tmp.path(), mcp);
    let err = build_auth_policy(&config, false)
        .await
        .expect_err("non-loopback no_auth must require trusted gateway flag");
    assert!(err.to_string().contains("CORTEX_TRUSTED_GATEWAY_NO_AUTH"));
}

#[tokio::test]
async fn build_auth_policy_returns_trusted_gateway_when_explicitly_asserted() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = loopback_mcp();
    mcp.host = "0.0.0.0".into();
    mcp.no_auth = true;
    mcp.trusted_gateway_no_auth = true;
    let config = test_config(tmp.path(), mcp);
    let policy = build_auth_policy(&config, false)
        .await
        .expect("build policy");
    assert!(matches!(policy, AuthPolicy::TrustedGatewayUnscoped));
}

#[tokio::test]
async fn runtime_no_auth_ignores_stale_oauth_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = loopback_mcp();
    mcp.no_auth = true;
    mcp.auth.mode = AuthMode::OAuth;
    mcp.auth.allowed_emails = vec!["stale@example.com".into()];
    let config = test_config(tmp.path(), mcp);

    let runtime = RuntimeCore::for_server(config)
        .await
        .expect("no_auth should bypass ignored OAuth config");
    assert!(matches!(runtime.auth_policy, AuthPolicy::LoopbackDev));
}

fn oauth_mcp(tmp: &std::path::Path) -> McpConfig {
    let mut mcp = loopback_mcp();
    mcp.auth = AuthConfig {
        mode: AuthMode::OAuth,
        public_url: Some("https://syslog.example.com".into()),
        google_client_id: Some("client-id".into()),
        google_client_secret: Some("client-secret".into()).into(),
        admin_email: "admin@example.com".into(),
        allowed_emails: Vec::new(),
        sqlite_path: tmp.join("auth.db"),
        key_path: tmp.join("auth-jwt.pem"),
        access_token_ttl_secs: 3_600,
        refresh_token_ttl_secs: 28_800,
        auth_code_ttl_secs: 300,
        register_rpm: 20,
        authorize_rpm: 60,
        disable_static_token_with_oauth: true,
        allowed_client_redirect_uris: Vec::new(),
    };
    mcp
}

#[test]
fn resolve_auth_path_keeps_absolute_and_roots_relative_paths_in_storage_dir() {
    let base = std::path::Path::new("/var/lib/cortex");

    assert_eq!(
        resolve_auth_path(base, std::path::Path::new("auth.db")),
        std::path::PathBuf::from("/var/lib/cortex/auth.db")
    );
    assert_eq!(
        resolve_auth_path(base, std::path::Path::new("/run/cortex/auth.db")),
        std::path::PathBuf::from("/run/cortex/auth.db")
    );
}

#[test]
fn mcp_static_token_active_requires_nonblank_token() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = loopback_mcp();
    let mut config = test_config(tmp.path(), mcp.clone());
    assert!(!mcp_static_token_active(&config));

    mcp.api_token = Some("   ".into()).into();
    config = test_config(tmp.path(), mcp.clone());
    assert!(!mcp_static_token_active(&config));

    mcp.api_token = Some("secret".into()).into();
    config = test_config(tmp.path(), mcp);
    assert!(mcp_static_token_active(&config));
}

#[test]
fn unsafe_otlp_oauth_exposure_guard_allows_stdio_loopback_token_and_trusted_gateway() {
    let tmp = tempfile::tempdir().unwrap();

    let mut stdio_mcp = oauth_mcp(tmp.path());
    stdio_mcp.host = "0.0.0.0".into();
    stdio_mcp.api_token = None.into();
    let stdio_config = test_config(tmp.path(), stdio_mcp);
    assert!(reject_unsafe_otlp_oauth_only_exposure(&stdio_config, true).is_ok());

    let loopback_config = test_config(tmp.path(), oauth_mcp(tmp.path()));
    assert!(reject_unsafe_otlp_oauth_only_exposure(&loopback_config, false).is_ok());

    let mut token_mcp = oauth_mcp(tmp.path());
    token_mcp.host = "0.0.0.0".into();
    token_mcp.api_token = Some("token".into()).into();
    let token_config = test_config(tmp.path(), token_mcp);
    assert!(reject_unsafe_otlp_oauth_only_exposure(&token_config, false).is_ok());

    let mut gateway_mcp = oauth_mcp(tmp.path());
    gateway_mcp.host = "0.0.0.0".into();
    gateway_mcp.no_auth = true;
    gateway_mcp.trusted_gateway_no_auth = true;
    gateway_mcp.api_token = None.into();
    let gateway_config = test_config(tmp.path(), gateway_mcp);
    assert!(reject_unsafe_otlp_oauth_only_exposure(&gateway_config, false).is_ok());
}

#[test]
fn unsafe_otlp_oauth_exposure_guard_rejects_nonloopback_without_static_token_or_gateway() {
    let tmp = tempfile::tempdir().unwrap();

    let mut oauth_only = oauth_mcp(tmp.path());
    oauth_only.host = "0.0.0.0".into();
    oauth_only.api_token = None.into();
    let oauth_only_config = test_config(tmp.path(), oauth_only);
    let err = reject_unsafe_otlp_oauth_only_exposure(&oauth_only_config, false).unwrap_err();
    assert!(err.to_string().contains("OTLP /v1/logs"));

    let mut no_auth = oauth_mcp(tmp.path());
    no_auth.host = "0.0.0.0".into();
    no_auth.no_auth = true;
    no_auth.trusted_gateway_no_auth = false;
    let no_auth_config = test_config(tmp.path(), no_auth);
    let err = reject_unsafe_otlp_oauth_only_exposure(&no_auth_config, false).unwrap_err();
    assert!(err.to_string().contains("CORTEX_TRUSTED_GATEWAY_NO_AUTH"));
}

#[tokio::test]
async fn build_auth_policy_returns_loopback_dev_when_no_auth_and_loopback_bind() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path(), loopback_mcp());
    let policy = build_auth_policy(&config, false)
        .await
        .expect("build policy");
    assert!(matches!(policy, AuthPolicy::LoopbackDev));
}

#[tokio::test]
async fn query_only_forces_loopback_dev_for_nonloopback_oauth_config() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = oauth_mcp(tmp.path());
    mcp.host = "0.0.0.0".into();
    mcp.api_token = None.into();
    let config = test_config(tmp.path(), mcp);

    let runtime = RuntimeCore::query_only(config)
        .await
        .expect("stdio runtime should ignore HTTP OAuth exposure constraints");

    assert!(matches!(runtime.auth_policy, AuthPolicy::LoopbackDev));
}

#[tokio::test]
async fn runtime_accessors_build_shared_state_and_ingest_routers() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .expect("runtime");

    let _service = runtime.service();
    let _pool = runtime.pool();
    let _otlp = runtime.otlp_router();
    let _heartbeat = runtime.heartbeat_router();
    let _agent_command = runtime.agent_command_router();
    let state = runtime.mcp_state();

    assert_eq!(state.config.server_name, "cortex");
    assert!(matches!(runtime.auth_policy(), AuthPolicy::LoopbackDev));

    runtime.shutdown(std::time::Duration::from_secs(1)).await;
}

/// **Engineering-review addition.** `axum::Router::merge` panics at
/// *runtime*, not compile time, on duplicate route registration. This proves
/// `heartbeat_router()` and `agent_command_router()` can be merged into one
/// app (mirroring the merge chain in `main.rs`'s `serve_mcp()`) without a
/// route collision, and that both paths resolve to something other than 404.
#[tokio::test]
async fn merged_app_serves_both_heartbeat_and_agent_command_routers_without_panicking() {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .expect("runtime");

    let app = axum::Router::new()
        .merge(runtime.heartbeat_router())
        .merge(runtime.agent_command_router())
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9000))));

    let heartbeat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/heartbeats")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(heartbeat_response.status(), StatusCode::NOT_FOUND);

    let agent_command_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agent-commands")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(agent_command_response.status(), StatusCode::NOT_FOUND);

    runtime.shutdown(std::time::Duration::from_secs(1)).await;
}

/// **Backlog-review addition (syslog-mcp-uail9).** The prior merge test above
/// only covered `heartbeat_router()` + `agent_command_router()`. `serve_mcp()`
/// in `main.rs` merges the full chain — `mcp::router`, `api::router`,
/// `otlp_router()`, `heartbeat_router()`, `agent_command_router()`, and
/// `web_app::router()` — so a route collision between any two of those (which
/// only panics at runtime, not compile time) would only surface in
/// production. This test builds and merges the same chain and probes one
/// route per router.
#[tokio::test]
async fn full_serve_mcp_router_chain_merges_without_panicking() {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let tmp = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp.path(), loopback_mcp());
    config.api.api_token = crate::config::Secret(Some("test-api-token".to_string()));
    let runtime = RuntimeCore::for_server(config).await.expect("runtime");

    let api_state = crate::api::ApiState::new(
        runtime.service(),
        runtime.config.api.clone(),
        runtime.config.mcp.port,
        crate::config::mcp_bind_is_loopback(&runtime.config),
        runtime.config.mcp.allowed_origins.clone(),
        runtime.auth_policy().clone(),
        runtime.config.mcp.static_token_is_admin,
        runtime.config.notifications.clone(),
        crate::stream::CursorKeys::resolved(
            runtime
                .config
                .cursor_signing_key
                .as_deref()
                .or(Some("runtime-test-key")),
            &runtime.config.cursor_previous_keys,
            true,
        )
        .unwrap(),
        crate::api::resolved_integration_profile(&runtime.config).unwrap(),
    )
    .expect("ApiState::new should succeed against a fresh pool");
    assert!(Arc::ptr_eq(
        &api_state.maintenance_permit,
        &runtime.maintenance_permit()
    ));

    let app = crate::mcp::router(runtime.mcp_state())
        .merge(crate::api::router(api_state).expect("api::router requires CORTEX_API_TOKEN"))
        .merge(runtime.otlp_router())
        .merge(runtime.heartbeat_router())
        .merge(runtime.agent_command_router())
        .merge(crate::web_app::router())
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9000))));

    let get = |uri: &'static str| {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };

    let api_response = app.clone().oneshot(get("/api/hosts")).await.unwrap();
    assert_ne!(api_response.status(), StatusCode::NOT_FOUND);

    let web_app_response = app.clone().oneshot(get("/app")).await.unwrap();
    assert_ne!(web_app_response.status(), StatusCode::NOT_FOUND);

    let otlp_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(otlp_response.status(), StatusCode::NOT_FOUND);

    let heartbeat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/heartbeats")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(heartbeat_response.status(), StatusCode::NOT_FOUND);

    let agent_command_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agent-commands")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(agent_command_response.status(), StatusCode::NOT_FOUND);

    runtime.shutdown(std::time::Duration::from_secs(1)).await;
}

#[tokio::test]
async fn spawn_maintenance_tasks_constructs_expected_handles_and_shutdowns_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .expect("runtime");

    let handles = runtime.spawn_maintenance_tasks();

    assert!(handles.purge.is_some());
    assert!(handles.storage.is_some());
    assert!(handles.file_tail.is_some());
    assert!(handles.inventory_refresh.is_some());
    assert!(handles.inventory_backfill.is_some());
    assert!(handles.session_rollup.is_some());
    assert!(handles.timeline_rollup.is_some());
    assert!(handles.optimize.is_some());
    assert!(handles.syslog_monitor.is_none());
    assert!(handles.docker_ingest.is_empty());

    handles.shutdown(std::time::Duration::from_secs(1)).await;
    runtime.shutdown(std::time::Duration::from_secs(1)).await;
}

#[tokio::test]
async fn maintenance_shutdown_stops_syslog_monitor_and_listeners_cooperatively() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp.path(), loopback_mcp());
    // TCP and UDP can each bind their own ephemeral port; the exact port is
    // irrelevant to this lifecycle assertion and avoids test-host collisions.
    config.receiver.host = "127.0.0.1".into();
    config.receiver.port = 0;
    let runtime = RuntimeCore::for_server(config).await.expect("runtime");
    let mut handles = runtime.spawn_maintenance_tasks();
    runtime
        .start_syslog(&mut handles)
        .await
        .expect("syslog supervisors start");

    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.observability.udp_listener_state()
            != crate::observability::ListenerState::Alive
            || runtime.observability.tcp_listener_state()
                != crate::observability::ListenerState::Alive
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both listener supervisors report alive");

    assert!(
        handles.shutdown(Duration::from_millis(250)).await,
        "graceful shutdown must not spend its timeout aborting syslog tasks"
    );
    assert_eq!(
        runtime.observability.udp_listener_state(),
        crate::observability::ListenerState::Down
    );
    assert_eq!(
        runtime.observability.tcp_listener_state(),
        crate::observability::ListenerState::Down
    );
    runtime.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn shutdown_timeout_aborts_and_joins_non_cooperative_tasks() {
    let progress = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task_progress = Arc::clone(&progress);
    let handle = tokio::spawn(async move {
        loop {
            task_progress.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(!super::await_or_abort_tasks(vec![handle], Duration::from_millis(1)).await);
    let after_shutdown = progress.load(std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        progress.load(std::sync::atomic::Ordering::SeqCst),
        after_shutdown,
        "task continued after shutdown returned"
    );
}

#[tokio::test]
async fn syslog_monitor_stops_listener_supervisors_when_maintenance_stops() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp.path(), loopback_mcp());
    config.receiver.port = 0;
    let runtime = RuntimeCore::for_server(config).await.expect("runtime");
    let mut handles = runtime.spawn_maintenance_tasks();

    runtime
        .start_syslog(&mut handles)
        .await
        .expect("start supervised listeners");

    assert!(handles.syslog_monitor.is_some());
    assert!(handles.shutdown(Duration::from_secs(1)).await);
    assert!(runtime.shutdown(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn maintenance_shutdown_reports_panicked_and_cancelled_tasks_as_unclean() {
    let panicked = tokio::spawn(async { panic!("injected maintenance panic") });
    assert!(!super::await_or_abort_tasks(vec![panicked], Duration::from_secs(1)).await);

    let cancelled = tokio::spawn(async { std::future::pending::<()>().await });
    cancelled.abort();
    assert!(!super::await_or_abort_tasks(vec![cancelled], Duration::from_secs(1)).await);

    let clean = tokio::spawn(async {});
    assert!(super::await_or_abort_tasks(vec![clean], Duration::from_secs(1)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_shutdown_is_unclean_when_file_tail_checkpoint_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path(), loopback_mcp());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        crate::filetail::FileTailRegistry::path_from_storage_db(&config.storage.db_path),
    ));
    let log_path = tmp.path().join("runtime-tail.log");
    tokio::fs::write(&log_path, b"runtime line\n")
        .await
        .unwrap();
    registry
        .upsert(crate::filetail::FileTailSource {
            id: "runtime-tail".into(),
            path: log_path.to_string_lossy().into_owned(),
            tag: "runtime-tail".into(),
            hostname: Some("runtime-test".into()),
            facility: Some("local4".into()),
            severity: "info".into(),
            start_at_end: false,
            enabled: true,
            checkpoint_dev: None,
            checkpoint_ino: None,
            checkpoint_offset: None,
            created_at: "2026-08-29T00:00:00Z".into(),
            updated_at: "2026-08-29T00:00:00Z".into(),
        })
        .unwrap();
    let runtime = RuntimeCore::for_server(config).await.unwrap();
    let handles = runtime.spawn_maintenance_tasks();
    // The all-features suite runs thousands of CPU- and SQLite-heavy tests in
    // parallel. Allow scheduler headroom while still bounding readiness; this
    // assertion is about the checkpoint-failure shutdown result below.
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if runtime
                .file_tail_supervisor
                .statuses()
                .first()
                .and_then(|status| status.last_line_at.as_ref())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    runtime
        .file_tail_supervisor
        .fail_checkpoint_writes_for_test(true);

    assert!(!handles.shutdown(Duration::from_secs(3)).await);
    runtime.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn notification_wrapper_propagates_unexpected_exit_and_panic_but_cancels_cleanly() {
    let token = tokio_util::sync::CancellationToken::new();
    let wrapper = super::spawn_notification_wrapper("test-exit", token, tokio::spawn(async {}));
    assert!(wrapper.await.unwrap_err().is_panic());

    let token = tokio_util::sync::CancellationToken::new();
    let wrapper = super::spawn_notification_wrapper(
        "test-panic",
        token,
        tokio::spawn(async { panic!("inner panic") }),
    );
    assert!(wrapper.await.unwrap_err().is_panic());

    let token = tokio_util::sync::CancellationToken::new();
    let inner_token = token.clone();
    let wrapper = super::spawn_notification_wrapper(
        "test-abort",
        token.clone(),
        tokio::spawn(async move { inner_token.cancelled().await }),
    );
    token.cancel();
    wrapper.await.unwrap();
}

#[tokio::test]
async fn enabled_notification_maintenance_tasks_shutdown_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp.path(), loopback_mcp());
    config.notifications.enabled = true;
    let runtime = RuntimeCore::for_server(config).await.unwrap();
    let handles = runtime.spawn_maintenance_tasks();

    assert!(handles.shutdown(Duration::from_secs(3)).await);
    runtime.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn runtime_shutdown_skips_checkpoint_when_ingest_writer_does_not_drain() {
    let tmp = tempfile::tempdir().unwrap();
    let mut runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    runtime.ingest = crate::ingest::IngestTx::from_envelope_sender_for_test(tx)
        .with_writer_handle_for_test(tokio::spawn(std::future::pending()));

    assert!(!runtime.shutdown(Duration::ZERO).await);
}

#[tokio::test]
async fn runtime_shutdown_skips_checkpoint_when_integrity_drain_times_out() {
    let tmp = tempfile::tempdir().unwrap();
    let mut runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .unwrap();
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = Arc::clone(&gate);
    runtime.service = runtime
        .service
        .clone()
        .with_integrity_test_hook(Arc::new(move || {
            worker_gate.wait();
            Ok(vec!["ok".to_string()])
        }));
    let pool = Arc::clone(&runtime.pool);
    let started = runtime
        .service()
        .db_integrity_start_background(true)
        .await
        .unwrap();

    assert!(!runtime.shutdown(Duration::from_millis(5)).await);
    gate.wait();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let job = crate::db::get_maintenance_job(&pool, started.job_id)
                .unwrap()
                .unwrap();
            if job.status != "running" {
                assert_eq!(job.status, "done");
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn background_intervals_skip_missed_ticks() {
    let interval = super::background_interval(tokio::time::Duration::from_secs(60));
    assert_eq!(
        interval.missed_tick_behavior(),
        tokio::time::MissedTickBehavior::Skip
    );
}

#[tokio::test]
async fn runtime_and_service_share_integrity_maintenance_admission() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimeCore::for_server(test_config(tmp.path(), loopback_mcp()))
        .await
        .unwrap();
    let gate = runtime.maintenance_permit();
    let _held = Arc::clone(&gate).acquire_owned().await.unwrap();
    let error = runtime.service().db_integrity(true).await.unwrap_err();
    assert!(matches!(error, crate::app::ServiceError::Busy(_)));
}

#[tokio::test]
async fn build_auth_policy_returns_mounted_bearer_only_when_static_token_only() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = loopback_mcp();
    mcp.api_token = Some("supersecret".into()).into();
    mcp.host = "0.0.0.0".into();
    let config = test_config(tmp.path(), mcp);
    // Bearer-only: AuthLayer is mounted (auth is enforced), but no OAuth state.
    // Scope checks in S5 must still run — Mounted { auth_state: None } is correct.
    let policy = build_auth_policy(&config, false)
        .await
        .expect("build policy");
    assert!(matches!(policy, AuthPolicy::Mounted { auth_state: None }));
}

#[tokio::test]
async fn build_auth_policy_returns_mounted_when_oauth_configured() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path(), oauth_mcp(tmp.path()));
    let policy = build_auth_policy(&config, false)
        .await
        .expect("oauth init should succeed");
    assert!(matches!(
        policy,
        AuthPolicy::Mounted {
            auth_state: Some(_)
        }
    ));

    // The lab-auth files must exist after init.
    assert!(tmp.path().join("auth.db").exists(), "auth.db missing");
    assert!(
        tmp.path().join("auth-jwt.pem").exists(),
        "auth-jwt.pem missing"
    );
}

#[tokio::test]
async fn runtime_rejects_non_loopback_oauth_without_static_token_before_otlp_mount() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = oauth_mcp(tmp.path());
    mcp.host = "0.0.0.0".into();
    mcp.api_token = None.into();
    let config = test_config(tmp.path(), mcp);

    let err = match RuntimeCore::for_server(config).await {
        Ok(_) => panic!("oauth-only non-loopback OTLP exposure must be rejected"),
        Err(err) => err,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("OTLP /v1/logs") && msg.contains("CORTEX_TOKEN"),
        "wrong error: {msg}"
    );
    assert!(
        !tmp.path().join("cortex.db").exists(),
        "rejection must occur before db::init_pool runs"
    );
}

#[tokio::test]
async fn runtime_rejects_oauth_allowed_emails_before_db_init() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = oauth_mcp(tmp.path());
    mcp.auth.allowed_emails = vec!["ops@example.com".into()];
    let config = test_config(tmp.path(), mcp);

    let err = match RuntimeCore::for_server(config).await {
        Ok(_) => panic!("runtime must reject unsupported allowed_emails"),
        Err(err) => err,
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("allowed_emails"), "wrong error: {msg}");
    assert!(
        !tmp.path().join("cortex.db").exists(),
        "rejection must occur before db::init_pool runs"
    );
}

#[tokio::test]
async fn build_auth_policy_propagates_lab_auth_errors() {
    // OAuth mode with an invalid public_url (not a URL) → AuthState::new fails.
    let tmp = tempfile::tempdir().unwrap();
    let mut mcp = oauth_mcp(tmp.path());
    mcp.auth.public_url = Some("not a url".into());
    let config = test_config(tmp.path(), mcp);
    let err = build_auth_policy(&config, false)
        .await
        .expect_err("invalid public_url should fail");
    let msg = format!("{err:#}");
    assert!(
        msg.to_ascii_lowercase().contains("public_url") || msg.to_ascii_lowercase().contains("url"),
        "error should mention url; got: {msg}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn build_auth_policy_enforces_restrictive_permissions_on_auth_db() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path(), oauth_mcp(tmp.path()));
    let _policy = build_auth_policy(&config, false).await.expect("oauth init");

    let db_path: PathBuf = tmp.path().join("auth.db");
    let mode = std::fs::metadata(&db_path)
        .expect("stat auth.db")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "auth.db must be 0600 (group/other bits clear); got mode={:o}",
        mode
    );

    let key_path: PathBuf = tmp.path().join("auth-jwt.pem");
    let key_mode = std::fs::metadata(&key_path)
        .expect("stat auth-jwt.pem")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        key_mode & 0o077,
        0,
        "auth-jwt.pem must be 0600 (group/other bits clear); got mode={:o}",
        key_mode
    );
}
