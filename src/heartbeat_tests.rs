use super::*;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::util::ServiceExt;

use crate::config::StorageConfig;

fn test_app(token: Option<&str>) -> (Router, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("heartbeat-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let state = HeartbeatState::new(
        Arc::clone(&pool),
        token.map(str::to_string),
        AuthPolicy::Mounted { auth_state: None },
    );
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    (app, pool, dir)
}

fn heartbeat_payload() -> Value {
    json!({
        "host": {
            "host_id": "host-1",
            "hostname": "nashost",
            "os": "linux",
            "kernel": "6.8.0",
            "architecture": "x86_64",
            "boot_id": "boot-1",
            "timezone": "America/New_York"
        },
        "sample": {
            "sequence": 42,
            "sampled_at": "2026-05-25T01:02:03Z",
            "uptime_secs": 86400,
            "monotonic_ms": 86400000,
            "collection_ms": 37,
            "partial": false,
            "probe_errors": [],
            "skipped_probes": []
        },
        "agent": {
            "version": "0.32.6",
            "mode": "always_on",
            "interval_secs": 30,
            "push_latency_ms": 12,
            "retry_backlog": 0
        },
        "cpu": {
            "load1": 0.1,
            "load5": 0.2,
            "load15": 0.3,
            "usage_pct": 4.5,
            "iowait_pct": 0.1,
            "steal_pct": 0.0,
            "core_count": 8
        },
        "memory": {
            "mem_total_bytes": 1000,
            "mem_available_bytes": 250,
            "swap_total_bytes": 100,
            "swap_used_bytes": 10
        },
        "disks": [{
            "kind": "mount",
            "name": "/",
            "fs_type": "ext4",
            "bytes_total": 1000,
            "bytes_free": 400,
            "bytes_used": 600
        }],
        "network": [{
            "interface": "eth0",
            "rx_bytes_per_sec": 100.0,
            "tx_bytes_per_sec": 200.0,
            "rx_errors_per_sec": 0.0,
            "tx_errors_per_sec": 1.0
        }],
        "processes": {
            "total": 10,
            "running": 1,
            "sleeping": 9,
            "zombies": 0,
            "top": []
        },
        "containers": {
            "runtime": "docker",
            "reachable": true,
            "running": 3,
            "exited": 1,
            "restarting": 0,
            "unhealthy": 1,
            "details": []
        }
    })
}

fn heartbeat_payload_v1() -> Value {
    let mut payload = heartbeat_payload();
    payload["schema_version"] = json!(1);
    payload["networks"] = payload["network"].take();
    payload.as_object_mut().unwrap().remove("network");
    payload
}

async fn post_json(
    app: Router,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let (status, _headers, value) = post_json_with_headers(app, uri, token, body).await;
    (status, value)
}

/// As [`post_json`], but keeps the response headers — needed wherever the
/// contract is a header rather than a body field (`Retry-After`).
async fn post_json_with_headers(
    app: Router,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, headers, value)
}

#[tokio::test]
async fn valid_heartbeat_is_accepted_and_persisted() {
    let (app, pool, _dir) = test_app(Some("secret"));
    let (status, value) =
        post_json(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(value["accepted"], 1);
    assert!(value["heartbeat_id"].as_i64().unwrap() > 0);

    let conn = pool.get().unwrap();
    let row: (String, String, i64) = conn
        .query_row(
            "SELECT host_id, source_ip, sequence FROM host_heartbeats",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(row.0, "host-1");
    assert_eq!(row.1, "10.0.0.7:41000");
    assert_eq!(row.2, 42);

    for table in [
        "heartbeat_cpu",
        "heartbeat_memory",
        "heartbeat_disks",
        "heartbeat_network",
        "heartbeat_processes",
        "heartbeat_containers",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "expected one row in {table}");
    }
}

#[tokio::test]
async fn valid_v1_heartbeat_with_networks_is_accepted() {
    let (app, pool, _dir) = test_app(Some("secret"));
    let (status, value) = post_json(
        app,
        "/v1/heartbeats",
        Some("secret"),
        heartbeat_payload_v1(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(value["accepted"], 1);

    let conn = pool.get().unwrap();
    let network_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM heartbeat_network", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(network_count, 1);
}

#[tokio::test]
async fn duplicate_heartbeat_is_idempotent() {
    let (app, pool, _dir) = test_app(Some("secret"));
    let payload = heartbeat_payload();
    let first = post_json(
        app.clone(),
        "/v1/heartbeats",
        Some("secret"),
        payload.clone(),
    )
    .await;
    let second = post_json(app, "/v1/heartbeats", Some("secret"), payload).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    assert_eq!(second.0, StatusCode::ACCEPTED);
    assert_eq!(second.1["accepted"], 0);
    assert_eq!(first.1["heartbeat_id"], second.1["heartbeat_id"]);

    let conn = pool.get().unwrap();
    let parent_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM host_heartbeats", [], |row| row.get(0))
        .unwrap();
    let cpu_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM heartbeat_cpu", [], |row| row.get(0))
        .unwrap();
    assert_eq!(parent_count, 1);
    assert_eq!(cpu_count, 1);
}

#[tokio::test]
async fn bearer_auth_is_required_and_query_tokens_are_ignored() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    for (uri, token) in [
        ("/v1/heartbeats", None),
        ("/v1/heartbeats", Some("wrong")),
        ("/v1/heartbeats?token=secret", None),
    ] {
        let (status, value) = post_json(app.clone(), uri, token, heartbeat_payload()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(value["error"], "unauthorized");
    }

    let (status, _) = post_json(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn invalid_payloads_return_invalid_payload() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let mut payload = heartbeat_payload();
    payload["unexpected"] = json!(true);
    let (status, value) = post_json(app, "/v1/heartbeats", Some("secret"), payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "invalid_payload");
}

#[tokio::test]
async fn heartbeat_body_limit_is_route_local_256k() {
    let (app, _pool, _dir) = test_app(Some("secret"));

    let mut accepted = heartbeat_payload();
    accepted["gpu"] = json!({"padding": "x".repeat(70 * 1024)});
    let (status, _) = post_json(app.clone(), "/v1/heartbeats", Some("secret"), accepted).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let mut oversized = heartbeat_payload();
    oversized["gpu"] = json!({"padding": "x".repeat(300 * 1024)});
    let (status, value) = post_json(app, "/v1/heartbeats", Some("secret"), oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"], "payload_too_large");
}

#[tokio::test]
async fn different_boot_id_same_sequence_is_accepted_as_new_heartbeat() {
    let (app, pool, _dir) = test_app(Some("secret"));

    let mut first = heartbeat_payload();
    first["host"]["boot_id"] = serde_json::json!("boot-A");
    first["sample"]["sequence"] = serde_json::json!(1);

    let mut second = heartbeat_payload();
    second["host"]["boot_id"] = serde_json::json!("boot-B");
    second["sample"]["sequence"] = serde_json::json!(1); // same sequence, different boot

    let (s1, v1) = post_json(app.clone(), "/v1/heartbeats", Some("secret"), first).await;
    let (s2, v2) = post_json(app, "/v1/heartbeats", Some("secret"), second).await;

    assert_eq!(s1, StatusCode::ACCEPTED);
    assert_eq!(s2, StatusCode::ACCEPTED);
    assert_eq!(v1["accepted"], 1);
    assert_eq!(v2["accepted"], 1);
    // Both should be distinct heartbeat_ids
    assert_ne!(v1["heartbeat_id"], v2["heartbeat_id"]);

    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM host_heartbeats", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn loopback_dev_auth_accepts_loopback_peer() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let state = HeartbeatState::new(Arc::clone(&pool), None, AuthPolicy::LoopbackDev);
    // Use loopback address (127.0.0.1)
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9000))));

    // No auth header, loopback peer — should be accepted
    let (status, value) = post_json(app, "/v1/heartbeats", None, heartbeat_payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(value["accepted"], 1);
}

#[tokio::test]
async fn loopback_dev_auth_rejects_non_loopback_peer() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let state = HeartbeatState::new(Arc::clone(&pool), None, AuthPolicy::LoopbackDev);
    // Non-loopback address
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));

    let (status, value) = post_json(app, "/v1/heartbeats", None, heartbeat_payload()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value["error"], "unauthorized");
}

#[tokio::test]
async fn mounted_auth_with_no_token_rejects_all_requests() {
    let (app, _pool, _dir) = test_app(None);
    // Even with a token in the header, no api_token configured so everything rejects
    let (status, value) =
        post_json(app, "/v1/heartbeats", Some("anything"), heartbeat_payload()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value["error"], "unauthorized");
}

#[tokio::test]
async fn zero_memory_total_stores_null_used_percent() {
    let (app, pool, _dir) = test_app(Some("secret"));
    let mut payload = heartbeat_payload();
    payload["memory"]["mem_total_bytes"] = serde_json::json!(0);
    payload["memory"]["mem_available_bytes"] = serde_json::json!(0);

    let (status, _) = post_json(app, "/v1/heartbeats", Some("secret"), payload).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let conn = pool.get().unwrap();
    let used_percent: Option<f64> = conn
        .query_row("SELECT used_percent FROM heartbeat_memory", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        used_percent.is_none(),
        "used_percent should be NULL when mem_total_bytes is 0"
    );
}

// --- Agent auto-update (server side) ---

async fn get_request(app: Router, uri: &str, token: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    app.oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[test]
fn platform_release_available_for_fleet_platforms() {
    assert!(platform_release_available("linux", "x86_64"));
    assert!(platform_release_available("linux", "amd64"));
    assert!(platform_release_available("Linux", "x86_64"));
    assert!(platform_release_available("windows", "x86_64"));
    assert!(platform_release_available("windows", "amd64"));
    assert!(platform_release_available("macos", "aarch64"));
    assert!(platform_release_available("macos", "arm64"));
    assert!(!platform_release_available("macos", "x86_64"));
    assert!(!platform_release_available("linux", "riscv64"));
    assert!(platform_self_servable("linux", "x86_64"));
    assert!(!platform_self_servable("windows", "x86_64"));
    assert_eq!(
        release_asset("macos", "aarch64", "binary").map(|asset| asset.0),
        Some("cortex-macos-arm64")
    );
    assert_eq!(
        release_asset("macos", "arm64", "checksum").map(|asset| asset.0),
        Some("cortex-macos-arm64.sha256")
    );
    assert!(release_asset("macos", "x86_64", "binary").is_none());
}

#[test]
fn directive_for_decisions() {
    let release = AgentReleaseInfo {
        version: SERVER_VERSION,
        sha256: Some("abc123".to_string()),
        exe_path: None,
    };
    // Stale linux agent → directive toward the server version.
    let d = release
        .directive_for("linux", "x86_64", "0.0.0")
        .expect("stale linux agent gets a directive");
    assert_eq!(d.version, SERVER_VERSION);
    assert_eq!(d.sha256.as_deref(), Some("abc123"));
    assert!(d.path.contains("os=linux"));
    assert!(d.path.contains("arch=x86_64"));
    // Matching version → no directive.
    assert!(
        release
            .directive_for("linux", "x86_64", SERVER_VERSION)
            .is_none()
    );
    // Stale Windows agent → a server-mediated release directive.
    let windows = release
        .directive_for("windows", "x86_64", "0.0.0")
        .expect("stale Windows agent gets a directive");
    assert_eq!(windows.version, SERVER_VERSION);
    assert!(windows.path.contains("os=windows"));
    assert!(windows.path.contains("arch=x86_64"));
    assert_eq!(windows.os, "windows");
    assert_eq!(windows.arch, "x86_64");

    let macos = release
        .directive_for("macos", "arm64", "0.0.0")
        .expect("stale macOS arm64 agent gets an exact release directive");
    assert_eq!(macos.os, "macos");
    assert_eq!(macos.arch, "aarch64");
    assert!(macos.path.contains("os=macos"));
    assert!(macos.path.contains("arch=aarch64"));

    // No sha (binary unreadable) → never advertise.
    let no_sha = AgentReleaseInfo {
        version: SERVER_VERSION,
        sha256: None,
        exe_path: None,
    };
    assert!(no_sha.directive_for("linux", "x86_64", "0.0.0").is_none());
}

#[tokio::test]
async fn heartbeat_ack_advertises_update_for_stale_linux_agent() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let (status, body) =
        post_json(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["server_version"], json!(SERVER_VERSION));
    assert_eq!(
        body["agent_update_status"],
        json!("available_checksum_integrity_only")
    );
    let update = &body["agent_update"];
    assert_eq!(update["version"], json!(SERVER_VERSION));
    assert!(update["path"].as_str().unwrap().contains("os=linux"));
    assert!(!update["sha256"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn heartbeat_ack_advertises_server_mediated_release_for_stale_windows_agent() {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("heartbeat-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let state = HeartbeatState::new(
        pool,
        Some("secret".to_string()),
        AuthPolicy::Mounted { auth_state: None },
    );
    state.release_availability.lock().await.insert(
        format!("windows:x86_64:{SERVER_VERSION}"),
        ReleaseAvailability {
            available: true,
            expires: Instant::now() + Duration::from_secs(60),
        },
    );
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let mut payload = heartbeat_payload();
    payload["host"]["os"] = json!("windows");
    let (status, body) = post_json(app, "/v1/heartbeats", Some("secret"), payload).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let update = &body["agent_update"];
    assert_eq!(update["version"], json!(SERVER_VERSION));
    assert_eq!(update["format"], json!("binary"));
    assert_eq!(
        body["agent_update_status"],
        json!("available_checksum_integrity_only")
    );
    assert_eq!(
        update["path"],
        json!(format!(
            "/v1/agent/release?os=windows&arch=x86_64&version={SERVER_VERSION}&kind=binary"
        ))
    );
    assert_eq!(
        update["checksum_path"],
        json!(format!(
            "/v1/agent/release?os=windows&arch=x86_64&version={SERVER_VERSION}&kind=checksum"
        ))
    );
}

#[tokio::test]
async fn heartbeat_ack_omits_update_for_matching_version() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let mut payload = heartbeat_payload();
    payload["agent"]["version"] = json!(SERVER_VERSION);
    let (status, body) = post_json(app, "/v1/heartbeats", Some("secret"), payload).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["server_version"], json!(SERVER_VERSION));
    assert_eq!(body["agent_update_status"], json!("current"));
    assert!(body.get("agent_update").is_none() || body["agent_update"].is_null());
}

#[tokio::test]
async fn agent_binary_endpoint_requires_auth() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let status = get_request(app, "/v1/agent/binary?os=linux&arch=x86_64", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_binary_endpoint_rejects_unsupported_platform() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let status = get_request(
        app,
        "/v1/agent/binary?os=windows&arch=x86_64",
        Some("secret"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn agent_release_endpoint_rejects_versions_other_than_running_server() {
    let (app, _pool, _dir) = test_app(Some("secret"));
    let status = get_request(
        app,
        "/v1/agent/release?os=windows&arch=x86_64&version=0.0.0&kind=binary",
        Some("secret"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_release_endpoint_proxies_authenticated_release_asset() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v{SERVER_VERSION}/cortex-windows-x86_64.exe.sha256"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string("a".repeat(64)))
        .expect(1)
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("heartbeat-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let mut state = HeartbeatState::new(
        pool,
        Some("secret".to_string()),
        AuthPolicy::Mounted { auth_state: None },
    );
    state.release_base_url = upstream.uri();
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let request = Request::builder()
        .uri(format!(
            "/v1/agent/release?os=windows&arch=x86_64&version={SERVER_VERSION}&kind=checksum"
        ))
        .header("authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 4096).await.unwrap(),
        "a".repeat(64)
    );
}

#[tokio::test]
async fn macos_release_availability_requires_exact_binary_and_checksum_assets() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path(format!("/v{SERVER_VERSION}/cortex-macos-arm64")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("HEAD"))
        .and(path(format!(
            "/v{SERVER_VERSION}/cortex-macos-arm64.sha256"
        )))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("heartbeat-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let mut state = HeartbeatState::new(
        pool,
        Some("secret".to_string()),
        AuthPolicy::Mounted { auth_state: None },
    );
    state.release_base_url = upstream.uri();
    assert!(state.release_assets_available("macos", "arm64").await);
    // A second lookup is served by the bounded success cache.
    assert!(state.release_assets_available("macos", "arm64").await);
}

#[tokio::test]
async fn macos_release_availability_negative_caches_missing_checksum() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path(format!("/v{SERVER_VERSION}/cortex-macos-arm64")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("HEAD"))
        .and(path(format!(
            "/v{SERVER_VERSION}/cortex-macos-arm64.sha256"
        )))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("heartbeat-test.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let mut state = HeartbeatState::new(
        pool,
        Some("secret".to_string()),
        AuthPolicy::Mounted { auth_state: None },
    );
    state.release_base_url = upstream.uri();
    assert!(!state.release_assets_available("macos", "aarch64").await);
    assert!(!state.release_assets_available("macos", "aarch64").await);
}

// --- Connection-pool contention (bead syslog-mcp-2yhfy) ---
//
// Production `db::init_pool` hardcodes a 6s r2d2 `connection_timeout`, and
// that value is out of scope here (see `db/pool.rs`). Waiting it out would
// make every case below multi-second, so they point a *second* pool with a
// short `connection_timeout` at the same already-migrated database file.
// `heartbeat.rs` derives its per-attempt acquisition budget from
// `DbPool::connection_timeout`, so the short-timeout pool drives the exact
// production retry logic on a compressed clock.
//
// Deliberately not compressed further: `cargo test` runs these alongside the
// rest of the suite, and the holder threads below release on a wall clock. The
// margins are sized so ordinary scheduling jitter under a saturated test
// machine cannot flip an outcome.
const TEST_POOL_TIMEOUT: Duration = Duration::from_millis(400);

fn short_timeout_pool(db_path: &std::path::Path, timeout: Duration) -> Arc<DbPool> {
    let manager = r2d2_sqlite::SqliteConnectionManager::file(db_path);
    Arc::new(
        r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(timeout)
            .build(manager)
            .expect("short-timeout test pool builds"),
    )
}

/// Router backed by a single-connection, short-timeout pool over a freshly
/// migrated database. Returns the pool so the caller can starve it.
fn contention_app(dir: &tempfile::TempDir) -> (Router, Arc<DbPool>) {
    let db_path = dir.path().join("contention.db");
    let storage = StorageConfig::for_test(db_path.clone());
    // Migrate through the normal constructor, then drop that pool so it holds
    // nothing against the short-timeout pool the handler actually uses.
    drop(crate::db::init_pool(&storage).unwrap());

    let pool = short_timeout_pool(&db_path, TEST_POOL_TIMEOUT);
    let state = HeartbeatState::new(
        Arc::clone(&pool),
        Some("secret".to_string()),
        AuthPolicy::Mounted { auth_state: None },
    );
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    (app, pool)
}

/// Holds the process write lock plus the pool's only connection on a
/// background thread, standing in for another ingest-side writer (the hourly
/// retention purge, the syslog batch writer) occupying the single reserved
/// writer slot. Blocks until the hold is established so the caller's request
/// is guaranteed to race it. Releases after `hold_for`, or earlier when the
/// returned sender fires.
fn hold_only_connection(
    pool: Arc<DbPool>,
    hold_for: Duration,
) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        // Lock then connection, through the same helper every real writer uses:
        // `WriteConn` returns the connection to the pool before it releases the
        // lock, exactly as a real writer unwinds, so a waiting heartbeat can
        // never deadlock behind it.
        let _held = crate::db::write_conn(&pool)
            .expect("single-connection pool yields its connection to the holder");
        let _ = ready_tx.send(());
        let _ = release_rx.recv_timeout(hold_for);
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("holder thread established its hold");
    (holder, release_tx)
}

/// Sustained contention must answer honestly: 503 `busy` ("try again"), not
/// 500 `internal_error` ("the server is broken"). Pre-fix this was a single
/// unretried `pool.get()` whose r2d2 timeout fell through to the handler's
/// generic error arm.
#[tokio::test]
async fn heartbeat_returns_busy_when_pool_contention_outlasts_the_retry_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (app, pool) = contention_app(&dir);

    // Far longer than the whole acquisition budget; released below.
    let (holder, release_tx) = hold_only_connection(Arc::clone(&pool), Duration::from_secs(30));

    let (status, headers, value) =
        post_json_with_headers(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;

    let _ = release_tx.send(());
    holder.join().unwrap();

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "exhausted pool contention must surface as retryable, got body {value}"
    );
    // The literal the heartbeat contract specifies for a backpressured write
    // path (docs/contracts/heartbeat-telemetry.md), not a generic "busy".
    assert_eq!(value["error"], "storage_unavailable");
    // A 503 with no `Retry-After` leaves the agent to invent a delay. Every
    // other transient-write-path 503 cortex emits names the same one-second
    // floor; this one must too. See docs/contracts/heartbeat-telemetry.md §10.
    assert_eq!(
        headers.get(axum::http::header::RETRY_AFTER),
        Some(&axum::http::HeaderValue::from_static("1")),
        "storage_unavailable must tell the agent when to come back"
    );
}

/// Contention shorter than the retry budget but longer than one attempt must
/// still be accepted. Pre-fix the single attempt expired at the pool's
/// `connection_timeout` and the heartbeat was lost to a 500.
#[tokio::test]
async fn heartbeat_recovers_from_contention_shorter_than_the_retry_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (app, pool) = contention_app(&dir);

    // Outlasts a single attempt (one `TEST_POOL_TIMEOUT`) but sits well inside
    // the three-attempt budget, leaving the last attempt as slack for jitter.
    let hold = TEST_POOL_TIMEOUT + TEST_POOL_TIMEOUT / 2;
    let (holder, release_tx) = hold_only_connection(Arc::clone(&pool), hold);

    let (status, value) =
        post_json(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;

    let _ = release_tx.send(());
    holder.join().unwrap();

    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "bounded retry must ride out contention shorter than its budget, got body {value}"
    );
    assert_eq!(value["accepted"], 1);
}

/// The busy path must not swallow real failures: a genuine SQL error still
/// reports 500 `internal_error`, unchanged.
#[tokio::test]
async fn genuine_insert_failure_still_returns_internal_error() {
    let (app, pool, _dir) = test_app(Some("secret"));
    {
        let conn = pool.get().unwrap();
        conn.execute_batch("DROP TABLE heartbeat_cpu").unwrap();
    }

    let (status, value) =
        post_json(app, "/v1/heartbeats", Some("secret"), heartbeat_payload()).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(value["error"], "internal_error");
}
