//! Heartbeat telemetry ingest (`POST /v1/heartbeats`) — server side of the
//! fleet inventory/graph sub-product's host-state pipeline.
//!
//! Receives bounded JSON snapshots (load, memory, disk, top processes) from
//! the host-local agent in `heartbeat_agent.rs`, mounted on the shared HTTP
//! listener (port 3100) next to MCP and OTLP. Rows back the `host_state`,
//! `fleet_state`, and `correlate_state` actions and are retained 14 days.
//!
//! Invariants: request bodies are capped at 256 KiB; auth mirrors MCP — the
//! static `CORTEX_TOKEN` bearer when configured, with non-loopback
//! unauthenticated exposure rejected at startup by config validation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::surfaces::{get, post};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{Next, from_fn},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use lab_auth::middleware::{parse_bearer_token, tokens_equal};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use tower_http::limit::RequestBodyLimitLayer;

use crate::db::DbPool;
use crate::mcp::AuthPolicy;

/// Server version compiled into this binary; advertised to agents so they can
/// converge to it via [`AgentReleaseInfo`].
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const HEARTBEAT_BODY_LIMIT_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct HeartbeatState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    auth_policy: AuthPolicy,
    release: Arc<AgentReleaseInfo>,
    release_client: reqwest::Client,
    release_base_url: String,
    release_downloads: Arc<Semaphore>,
    release_availability: Arc<Mutex<HashMap<String, ReleaseAvailability>>>,
}

impl HeartbeatState {
    pub fn new(pool: Arc<DbPool>, api_token: Option<String>, auth_policy: AuthPolicy) -> Self {
        Self {
            pool,
            api_token,
            auth_policy,
            release: Arc::new(AgentReleaseInfo::from_current_exe()),
            release_client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(120))
                .user_agent(format!("cortex/{SERVER_VERSION}"))
                .build()
                .expect("static release proxy client configuration is valid"),
            release_base_url: "https://github.com/dinglebear-ai/cortex/releases/download"
                .to_string(),
            release_downloads: Arc::new(Semaphore::new(2)),
            release_availability: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Identity of the agent binary this server can hand out (its own running
/// binary). Computed once at construction; the SHA-256 lets agents verify the
/// download over the authenticated heartbeat channel.
struct AgentReleaseInfo {
    version: &'static str,
    /// Lowercase hex SHA-256 of the server binary, or `None` if it could not be
    /// read (e.g. in unit tests) — in which case no update is ever advertised.
    sha256: Option<String>,
    exe_path: Option<PathBuf>,
}

impl AgentReleaseInfo {
    fn from_current_exe() -> Self {
        let (sha256, exe_path) = match std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::read(&path).ok().map(|bytes| (path, bytes)))
        {
            Some((path, bytes)) => {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hexed: String = hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                (Some(hexed), Some(path))
            }
            None => (None, None),
        };
        Self {
            version: SERVER_VERSION,
            sha256,
            exe_path,
        }
    }

    /// Build an update directive when the reporting agent is on a different
    /// version and a matching release is available. Linux receives the
    /// server's own binary; Windows receives authenticated proxy paths for the
    /// raw executable and checksum published by release CI.
    fn directive_for(
        &self,
        os: &str,
        arch: &str,
        agent_version: &str,
    ) -> Option<AgentUpdateDirective> {
        if agent_version == self.version {
            return None;
        }
        if !platform_release_available(os, arch) {
            return None;
        }
        if !platform_self_servable(os, arch) {
            let canonical_os = canonical_os(os)?;
            let canonical_arch = canonical_arch(os, arch)?;
            let base = format!(
                "/v1/agent/release?os={canonical_os}&arch={canonical_arch}&version={}&kind=",
                self.version
            );
            return Some(AgentUpdateDirective {
                version: self.version.to_string(),
                os: canonical_os.to_string(),
                arch: canonical_arch.to_string(),
                path: format!("{base}binary"),
                sha256: None,
                checksum_path: Some(format!("{base}checksum")),
                format: "binary".to_string(),
            });
        }
        let sha256 = self.sha256.as_ref()?;
        Some(AgentUpdateDirective {
            version: self.version.to_string(),
            os: canonical_os(os)?.to_string(),
            arch: canonical_arch(os, arch)?.to_string(),
            path: format!("/v1/agent/binary?os={os}&arch={arch}"),
            sha256: Some(sha256.clone()),
            checksum_path: None,
            format: "binary".to_string(),
        })
    }
}

fn canonical_os(os: &str) -> Option<&'static str> {
    if os.eq_ignore_ascii_case("linux") {
        Some("linux")
    } else if os.eq_ignore_ascii_case("windows") {
        Some("windows")
    } else if os.eq_ignore_ascii_case("macos") {
        Some("macos")
    } else {
        None
    }
}

fn canonical_arch(os: &str, arch: &str) -> Option<&'static str> {
    if os.eq_ignore_ascii_case("macos") && matches!(arch, "aarch64" | "arm64") {
        Some("aarch64")
    } else if matches!(arch, "x86_64" | "amd64") {
        Some("x86_64")
    } else {
        None
    }
}

/// True for the platform whose binary the server can hand out from its own
/// running image (linux on a 64-bit x86 host).
fn platform_release_available(os: &str, arch: &str) -> bool {
    (matches!(arch, "x86_64" | "amd64")
        && (os.eq_ignore_ascii_case("linux") || os.eq_ignore_ascii_case("windows")))
        || (os.eq_ignore_ascii_case("macos") && matches!(arch, "aarch64" | "arm64"))
}

fn platform_self_servable(os: &str, arch: &str) -> bool {
    os.eq_ignore_ascii_case("linux") && matches!(arch, "x86_64" | "amd64")
}

/// Auto-update directive serialized into the heartbeat `202` ack. The agent
/// resolves `path` against its own heartbeat target base URL.
#[derive(Debug, Clone, Serialize)]
pub struct AgentUpdateDirective {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_path: Option<String>,
    pub format: String,
}

pub fn router(state: HeartbeatState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("POST /v1/heartbeats", post(heartbeat_handler))
        .layer(RequestBodyLimitLayer::new(HEARTBEAT_BODY_LIMIT_BYTES))
        .layer(from_fn(json_payload_too_large))
        .contract_route("GET /v1/agent/binary", get(agent_binary_handler))
        .contract_route("GET /v1/agent/release", get(agent_release_handler))
        .with_state(state)
}

const MAX_RELEASE_BINARY_BYTES: usize = 128 * 1024 * 1024;
const MAX_RELEASE_CHECKSUM_BYTES: usize = 4096;
const RELEASE_AVAILABLE_TTL: Duration = Duration::from_secs(300);
const RELEASE_MISSING_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct ReleaseAvailability {
    available: bool,
    expires: Instant,
}

fn release_asset(os: &str, arch: &str, kind: &str) -> Option<(&'static str, usize, &'static str)> {
    let stem = if os.eq_ignore_ascii_case("windows") && matches!(arch, "x86_64" | "amd64") {
        "cortex-windows-x86_64.exe"
    } else if os.eq_ignore_ascii_case("macos") && matches!(arch, "aarch64" | "arm64") {
        "cortex-macos-arm64"
    } else {
        return None;
    };
    match kind {
        "binary" => Some((stem, MAX_RELEASE_BINARY_BYTES, "application/octet-stream")),
        "checksum" => Some((
            if stem == "cortex-windows-x86_64.exe" {
                "cortex-windows-x86_64.exe.sha256"
            } else {
                "cortex-macos-arm64.sha256"
            },
            MAX_RELEASE_CHECKSUM_BYTES,
            "text/plain; charset=utf-8",
        )),
        _ => None,
    }
}

impl HeartbeatState {
    async fn release_assets_available(&self, os: &str, arch: &str) -> bool {
        if platform_self_servable(os, arch) {
            return self.release.sha256.is_some() && self.release.exe_path.is_some();
        }
        if release_asset(os, arch, "binary").is_none() {
            return false;
        }
        let key = format!(
            "{}:{}:{}",
            os.to_ascii_lowercase(),
            arch.to_ascii_lowercase(),
            self.release.version
        );
        let now = Instant::now();
        if let Some(cached) = self.release_availability.lock().await.get(&key).copied()
            && cached.expires > now
        {
            return cached.available;
        }
        let mut available = true;
        for kind in ["binary", "checksum"] {
            let Some((asset, _, _)) = release_asset(os, arch, kind) else {
                available = false;
                break;
            };
            let url = format!(
                "{}/v{}/{asset}",
                self.release_base_url.trim_end_matches('/'),
                self.release.version
            );
            match self.release_client.head(&url).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::info!(%url, status = %response.status(), "release asset not currently available");
                    available = false;
                    break;
                }
                Err(error) => {
                    tracing::warn!(%url, %error, "release asset availability check failed");
                    available = false;
                    break;
                }
            }
        }
        let ttl = if available {
            RELEASE_AVAILABLE_TTL
        } else {
            RELEASE_MISSING_TTL
        };
        self.release_availability.lock().await.insert(
            key,
            ReleaseAvailability {
                available,
                expires: now + ttl,
            },
        );
        available
    }
}

/// Proxy a platform release artifact through the authenticated Cortex server.
/// This keeps the server as the fleet's update coordinator while allowing the
/// Linux server to distribute the native Windows binary built by release CI.
async fn agent_release_handler(
    State(state): State<HeartbeatState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_authorized(&state, &peer, &headers) {
        return unauthorized();
    }
    let os = params.get("os").map(String::as_str).unwrap_or("");
    let arch = params.get("arch").map(String::as_str).unwrap_or("");
    let version = params.get("version").map(String::as_str).unwrap_or("");
    let kind = params.get("kind").map(String::as_str).unwrap_or("");
    if version != state.release.version {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "version_mismatch", "server_version": state.release.version})),
        )
            .into_response();
    }
    if release_asset(os, arch, "binary").is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unsupported_platform", "os": os, "arch": arch})),
        )
            .into_response();
    }
    let (asset, max_bytes, content_type) = match release_asset(os, arch, kind) {
        Some(descriptor) => descriptor,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_release_kind"})),
            )
                .into_response();
        }
    };
    let url = format!(
        "{}/v{version}/{asset}",
        state.release_base_url.trim_end_matches('/')
    );
    let permit = match Arc::clone(&state.release_downloads).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::RETRY_AFTER, "30")
                .body(Body::from("release proxy busy"))
                .unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
    };
    let response = match state.release_client.get(&url).send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            let status = response.status();
            let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
            let mut builder = Response::builder().status(if status == StatusCode::NOT_FOUND {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            });
            if let Some(value) = retry_after {
                builder = builder.header(header::RETRY_AFTER, value);
            }
            return builder
                .body(Body::from("release artifact unavailable"))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
        }
        Err(error) => {
            tracing::warn!(error = %error, %url, "agent release artifact unavailable");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "release_artifact_unavailable"})),
            )
                .into_response();
        }
    };
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let stream = futures_util::StreamExt::scan(
        response.bytes_stream(),
        (0usize, false, permit),
        move |state, item| {
            let result = if state.1 {
                return std::future::ready(None);
            } else {
                match item {
                    Ok(chunk) => match state.0.checked_add(chunk.len()) {
                        Some(new_len) if new_len <= max_bytes => {
                            state.0 = new_len;
                            Ok(chunk)
                        }
                        _ => {
                            state.1 = true;
                            Err(std::io::Error::other("release artifact exceeds size limit"))
                        }
                    },
                    Err(error) => {
                        state.1 = true;
                        Err(std::io::Error::other(error))
                    }
                }
            };
            std::future::ready(Some(result))
        },
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header("x-cortex-version", version)
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /v1/agent/binary?os=&arch=` — streams the server's own binary so agents
/// can self-update to match. Shares the heartbeat auth model (bearer token, or
/// loopback under `LoopbackDev`). Only serves the platform the server runs on.
async fn agent_binary_handler(
    State(state): State<HeartbeatState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_authorized(&state, &peer, &headers) {
        return unauthorized();
    }
    let os = params.get("os").map(String::as_str).unwrap_or("");
    let arch = params.get("arch").map(String::as_str).unwrap_or("");
    if !platform_self_servable(os, arch) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unsupported_platform", "os": os, "arch": arch})),
        )
            .into_response();
    }
    let Some(exe_path) = state.release.exe_path.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "binary_unavailable"})),
        )
            .into_response();
    };
    let sha256 = state.release.sha256.clone().unwrap_or_default();
    match tokio::fs::read(&exe_path).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("x-cortex-version", state.release.version)
            .header("x-cortex-sha256", sha256)
            .body(Body::from(bytes))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
            }),
        Err(error) => {
            tracing::error!(error = %error, "failed to read agent binary for download");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "binary_read_failed"})),
            )
                .into_response()
        }
    }
}

async fn json_payload_too_large(
    req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let response = next.run(req).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "payload_too_large"})),
        )
            .into_response();
    }
    response
}

async fn heartbeat_handler(
    State(state): State<HeartbeatState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !is_authorized(&state, &peer, &headers) {
        return unauthorized();
    }

    let request: HeartbeatRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_payload", "message": error.to_string()})),
            )
                .into_response();
        }
    };

    // Capture identity for the auto-update directive before `request` is moved
    // into the blocking insert task.
    let agent_os = request.host.os.clone();
    let agent_arch = request.host.architecture.clone();
    let agent_version = request.agent.version.clone();

    let pool = Arc::clone(&state.pool);
    let source_ip = peer.to_string();
    let exec_start = Instant::now();
    let join_result =
        tokio::task::spawn_blocking(move || insert_heartbeat(&pool, request, &source_ip)).await;
    let exec_ms = exec_start.elapsed().as_millis();
    let result = join_result
        .map_err(|error| {
            HeartbeatIngestError::Internal(anyhow::anyhow!("heartbeat insert task failed: {error}"))
        })
        .and_then(|result| result);
    // Two-tier: heartbeat INSERTs target <5ms; warn only above 500ms to avoid noise.
    if exec_ms > 500 {
        match &result {
            Ok(_) => tracing::warn!(op = "heartbeat.insert", exec_ms, "db op ok"),
            Err(e) => tracing::warn!(op = "heartbeat.insert", exec_ms, error = %e, "db op err"),
        }
    } else {
        match &result {
            Ok(_) => tracing::debug!(op = "heartbeat.insert", exec_ms, "db op ok"),
            Err(e) => tracing::debug!(op = "heartbeat.insert", exec_ms, error = %e, "db op err"),
        }
    }

    match result {
        Ok(mut response) => {
            response.server_version = Some(state.release.version.to_string());
            if agent_version == state.release.version {
                response.agent_update_status = Some("current".to_string());
                response.agent_update = None;
            } else if !platform_release_available(&agent_os, &agent_arch) {
                response.agent_update_status = Some("unsupported_platform".to_string());
                response.agent_update = None;
            } else if state.release_assets_available(&agent_os, &agent_arch).await {
                response.agent_update_status =
                    Some("available_checksum_integrity_only".to_string());
                response.agent_update =
                    state
                        .release
                        .directive_for(&agent_os, &agent_arch, &agent_version);
            } else {
                response.agent_update_status = Some("release_assets_unavailable".to_string());
                response.agent_update = None;
            }
            (StatusCode::ACCEPTED, Json(response)).into_response()
        }
        // Losing the race for the write lock or a reserved writer connection is
        // a "try again", not a server fault. 503 keeps the agent's own retry
        // path in charge instead of recording a hard error against a healthy
        // server. `acquire_write_conn` already logged the exhaustion.
        //
        // `storage_unavailable` is the literal specified by
        // docs/contracts/heartbeat-telemetry.md section 10 ("503 |
        // storage_unavailable | DB write path unavailable or backpressured").
        // It was documented but never emitted by any code path until now.
        //
        // `Retry-After` matches the OTLP backpressure 503s
        // (`otlp::error::OtlpError::retry_after`): every 503 cortex emits for
        // transient write-path contention names the same one-second floor, so
        // an agent does not have to know which endpoint it hit to know how
        // long to wait. One second is a floor, not a schedule — the agent's
        // own backoff applies on top.
        Err(HeartbeatIngestError::PoolBusy { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, HEARTBEAT_BUSY_RETRY_AFTER_SECONDS)],
            Json(json!({"error": "storage_unavailable"})),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "heartbeat ingest failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
    }
}

fn is_authorized(state: &HeartbeatState, peer: &SocketAddr, headers: &HeaderMap) -> bool {
    if matches!(state.auth_policy, AuthPolicy::LoopbackDev) {
        return peer.ip().is_loopback();
    }
    let Some(expected) = state.api_token.as_deref() else {
        return false;
    };
    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    parse_bearer_token(auth).is_some_and(|token| tokens_equal(&token, expected))
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

/// `Retry-After` sent with the `storage_unavailable` 503.
const HEARTBEAT_BUSY_RETRY_AFTER_SECONDS: &str = "1";

/// Backoff between heartbeat write-connection attempts; its length fixes the
/// attempt count at [`HEARTBEAT_ACQUIRE_ATTEMPTS`].
const HEARTBEAT_ACQUIRE_BACKOFF: [Duration; 2] =
    [Duration::from_millis(50), Duration::from_millis(150)];

const HEARTBEAT_ACQUIRE_ATTEMPTS: usize = HEARTBEAT_ACQUIRE_BACKOFF.len() + 1;

/// Ceiling on any single acquisition attempt.
///
/// The pool's own `connection_timeout` (6s in production) is the total budget
/// a heartbeat used to spend on one attempt. Capping each attempt at a third
/// of that keeps three attempts plus backoff at roughly the same wall clock,
/// so the retry buys extra chances rather than extra latency. Pools configured
/// with a shorter timeout than the cap keep their own, tighter per-attempt
/// budget (their total still spans three attempts plus backoff).
const HEARTBEAT_ACQUIRE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Split so write-path contention can be answered honestly instead of being
/// flattened into a generic 500.
#[derive(Debug, thiserror::Error)]
enum HeartbeatIngestError {
    /// Neither the write lock nor a pooled connection came free within the
    /// bounded retry budget.
    #[error("heartbeat write path unavailable after {attempts} attempts: {detail}")]
    PoolBusy { attempts: usize, detail: String },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Acquire the write lock and then a connection for a heartbeat write, retrying
/// a bounded number of times with backoff.
///
/// Lock first, connection second — `db::write_conn`'s ordering, and for its
/// reason: a heartbeat queued on the write lock must not be sitting on a pooled
/// connection while it waits. Both waits are bounded here, because a heartbeat
/// is a request-scoped writer that has to answer 503 rather than queue behind an
/// arbitrarily long write (the 2026-08-24 orphan sweep held the lock 15m25s).
/// `db::try_write_conn_for` drops the guard before returning, so the backoff
/// sleep below never happens while holding the lock.
///
/// Every ingest-side writer shares the connections reserved outside the service
/// layer's read semaphore (see `app::services::read_permits_for_pool`), and
/// contention on either resource is usually transient — the hourly retention
/// purge releases lock and connection between chunks, so both free repeatedly
/// within a single request's budget. One un-retried attempt turns that
/// transient loss into a dropped heartbeat; three attempts ride it out.
///
/// Only the acquisition retries. Once the pair is in hand the transaction runs
/// exactly once, so constraint and serialization failures still fail fast.
fn acquire_write_conn(pool: &DbPool) -> Result<crate::db::WriteConn, HeartbeatIngestError> {
    let attempt_timeout = pool
        .connection_timeout()
        .min(HEARTBEAT_ACQUIRE_ATTEMPT_TIMEOUT);
    let mut attempt = 0usize;
    loop {
        let detail = match crate::db::try_write_conn_for(pool, attempt_timeout) {
            Ok(conn) => {
                if attempt > 0 {
                    tracing::warn!(
                        attempt = attempt + 1,
                        "heartbeat write path acquired after retry"
                    );
                }
                return Ok(conn);
            }
            Err(crate::db::WriteConnBusy::Admission) => {
                format!("writer admission still held after {attempt_timeout:?}")
            }
            Err(crate::db::WriteConnBusy::Lock) => {
                format!("write lock still held after {attempt_timeout:?}")
            }
            Err(crate::db::WriteConnBusy::Pool(error)) => error.to_string(),
        };
        let Some(backoff) = HEARTBEAT_ACQUIRE_BACKOFF.get(attempt) else {
            tracing::error!(
                detail = %detail,
                attempts = HEARTBEAT_ACQUIRE_ATTEMPTS,
                "heartbeat write path unavailable; reporting busy"
            );
            return Err(HeartbeatIngestError::PoolBusy {
                attempts: HEARTBEAT_ACQUIRE_ATTEMPTS,
                detail,
            });
        };
        tracing::warn!(
            detail = %detail,
            attempt = attempt + 1,
            retry_delay_ms = backoff.as_millis(),
            "heartbeat write path unavailable; retrying"
        );
        std::thread::sleep(*backoff);
        attempt += 1;
    }
}

fn insert_heartbeat(
    pool: &DbPool,
    request: HeartbeatRequest,
    source_ip: &str,
) -> Result<HeartbeatIngestResponse, HeartbeatIngestError> {
    // Stamped before the (possibly retried) acquisition so `received_at`
    // stays the arrival time, not the time the writer slot came free.
    let received_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut conn = acquire_write_conn(pool)?;
    Ok(write_heartbeat(&mut conn, request, source_ip, received_at)?)
}

fn write_heartbeat(
    conn: &mut crate::db::WriteConn,
    request: HeartbeatRequest,
    source_ip: &str,
    received_at: String,
) -> anyhow::Result<HeartbeatIngestResponse> {
    // The write lock is already held: `acquire_write_conn` took it before this
    // connection was borrowed.
    let tx = conn.transaction()?;
    let metadata_json = heartbeat_metadata_json(&request)?;

    tx.execute(
        "INSERT OR IGNORE INTO host_heartbeats (
             host_id, hostname, source_ip, sampled_at, received_at, boot_id,
             uptime_secs, sequence, collection_ms, push_latency_ms, partial,
             agent_version, os, kernel, architecture, metadata_json
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
         )",
        params![
            request.host.host_id,
            request.host.hostname,
            source_ip,
            request.sample.sampled_at,
            received_at,
            request.host.boot_id,
            request.sample.uptime_secs,
            request.sample.sequence,
            request.sample.collection_ms,
            request.agent.push_latency_ms,
            request.sample.partial as i64,
            request.agent.version,
            request.host.os,
            request.host.kernel,
            request.host.architecture,
            metadata_json,
        ],
    )?;

    let heartbeat_id = if tx.changes() == 0 {
        let id: i64 = tx.query_row(
            "SELECT id FROM host_heartbeats
             WHERE host_id = ?1 AND boot_id = ?2 AND sequence = ?3",
            params![
                request.host.host_id,
                request.host.boot_id,
                request.sample.sequence
            ],
            |row| row.get(0),
        )?;
        tx.commit()?;
        return Ok(HeartbeatIngestResponse {
            accepted: 0,
            heartbeat_id: id,
            received_at,
            server_version: None,
            agent_update: None,
            agent_update_status: None,
        });
    } else {
        tx.last_insert_rowid()
    };

    insert_metric_rows(&tx, heartbeat_id, &request)?;

    // Keep the fleet-state cache in sync. Only runs for accepted (non-duplicate)
    // heartbeats. The WHERE guard on sampled_at ensures out-of-order retries
    // never overwrite a newer entry with an older one.
    tx.execute(
        "INSERT INTO host_heartbeats_latest
             (host_id, heartbeat_id, hostname, sampled_at, received_at,
              partial, agent_version, os, architecture, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(host_id) DO UPDATE SET
             heartbeat_id  = excluded.heartbeat_id,
             hostname      = excluded.hostname,
             sampled_at    = excluded.sampled_at,
             received_at   = excluded.received_at,
             partial       = excluded.partial,
             agent_version = excluded.agent_version,
             os            = excluded.os,
             architecture  = excluded.architecture,
             metadata_json = excluded.metadata_json
         WHERE excluded.sampled_at >= host_heartbeats_latest.sampled_at",
        params![
            request.host.host_id,
            heartbeat_id,
            request.host.hostname,
            request.sample.sampled_at,
            received_at,
            request.sample.partial as i64,
            request.agent.version,
            request.host.os,
            request.host.architecture,
            metadata_json,
        ],
    )?;

    tx.commit()?;

    Ok(HeartbeatIngestResponse {
        accepted: 1,
        heartbeat_id,
        received_at,
        server_version: None,
        agent_update: None,
        agent_update_status: None,
    })
}

fn heartbeat_metadata_json(request: &HeartbeatRequest) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&json!({
        "schema_version": request.schema_version,
        "host": {
            "timezone": request.host.timezone,
        },
        "sample": {
            "monotonic_ms": request.sample.monotonic_ms,
            "probe_errors": request.sample.probe_errors,
            "skipped_probes": request.sample.skipped_probes,
        },
        "agent": {
            "mode": request.agent.mode,
            "interval_secs": request.agent.interval_secs,
            "retry_backlog": request.agent.retry_backlog,
        },
        "gpu": request.gpu,
        "cpu": request.cpu,
        "memory": request.memory,
        "disks": request.disks,
        "networks": request.networks,
        "processes": request.processes,
        "containers": request.containers,
    }))?)
}

fn insert_metric_rows(
    tx: &rusqlite::Transaction<'_>,
    heartbeat_id: i64,
    request: &HeartbeatRequest,
) -> rusqlite::Result<()> {
    if let Some(cpu) = &request.cpu {
        tx.execute(
            "INSERT INTO heartbeat_cpu (
                 heartbeat_id, load1, load5, load15, usage_percent, steal_percent, io_wait_percent
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                heartbeat_id,
                cpu.load1,
                cpu.load5,
                cpu.load15,
                cpu.usage_pct,
                cpu.steal_pct,
                cpu.iowait_pct,
            ],
        )?;
    }

    if let Some(memory) = &request.memory {
        let used_percent = if memory.mem_total_bytes > 0 {
            let used = memory
                .mem_total_bytes
                .saturating_sub(memory.mem_available_bytes);
            Some((used as f64 / memory.mem_total_bytes as f64) * 100.0)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO heartbeat_memory (
                 heartbeat_id, total_bytes, available_bytes, used_percent,
                 swap_total_bytes, swap_used_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                heartbeat_id,
                memory.mem_total_bytes,
                memory.mem_available_bytes,
                used_percent,
                memory.swap_total_bytes,
                memory.swap_used_bytes,
            ],
        )?;
    }

    for disk in &request.disks {
        tx.execute(
            "INSERT INTO heartbeat_disks (
                 heartbeat_id, mountpoint, filesystem, total_bytes, available_bytes,
                 used_percent, read_bytes_per_sec, write_bytes_per_sec
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                heartbeat_id,
                disk.name,
                disk.fs_type,
                disk.bytes_total,
                disk.bytes_free,
                disk.used_percent(),
                disk.read_bytes_per_sec,
                disk.write_bytes_per_sec,
            ],
        )?;
    }

    for net in &request.networks {
        tx.execute(
            "INSERT INTO heartbeat_network (
                 heartbeat_id, interface, rx_bytes_per_sec, tx_bytes_per_sec, rx_errors, tx_errors
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                heartbeat_id,
                net.interface,
                net.rx_bytes_per_sec,
                net.tx_bytes_per_sec,
                net.rx_errors_per_sec.map(|value| value.round() as i64),
                net.tx_errors_per_sec.map(|value| value.round() as i64),
            ],
        )?;
    }

    if let Some(processes) = &request.processes {
        tx.execute(
            "INSERT INTO heartbeat_processes (
                 heartbeat_id, total, running, sleeping, zombie, top_cpu_json, top_memory_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                heartbeat_id,
                processes.total,
                processes.running,
                processes.sleeping,
                processes.zombies,
                Some(
                    serde_json::to_string(&processes.top)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                ),
            ],
        )?;
    }

    if let Some(containers) = &request.containers {
        tx.execute(
            "INSERT INTO heartbeat_containers (
                 heartbeat_id, runtime, running, stopped, restarting, unhealthy, summary_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                heartbeat_id,
                containers.runtime.as_deref().unwrap_or("docker"),
                containers.running,
                containers.exited,
                containers.restarting,
                containers.unhealthy,
                Some(
                    serde_json::to_string(&containers.details)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                ),
            ],
        )?;
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct HeartbeatIngestResponse {
    accepted: u32,
    heartbeat_id: i64,
    received_at: String,
    /// Server version, so agents can detect drift even without a directive.
    #[serde(skip_serializing_if = "Option::is_none")]
    server_version: Option<String>,
    /// Present only when the agent should self-update to match the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_update: Option<AgentUpdateDirective>,
    /// Evidence state for update routing. The checksum-only state deliberately
    /// does not claim signed provenance or attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_update_status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatRequest {
    #[serde(default = "default_schema_version")]
    schema_version: u8,
    host: HeartbeatHost,
    sample: HeartbeatSample,
    agent: HeartbeatAgent,
    #[serde(default)]
    cpu: Option<HeartbeatCpu>,
    #[serde(default)]
    memory: Option<HeartbeatMemory>,
    #[serde(default)]
    disks: Vec<HeartbeatDisk>,
    #[serde(default, alias = "network")]
    networks: Vec<HeartbeatNetwork>,
    #[serde(default)]
    processes: Option<HeartbeatProcesses>,
    #[serde(default)]
    containers: Option<HeartbeatContainers>,
    #[serde(default)]
    gpu: Option<serde_json::Value>,
}

fn default_schema_version() -> u8 {
    1
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatHost {
    host_id: String,
    hostname: String,
    os: String,
    #[serde(default)]
    kernel: Option<String>,
    architecture: String,
    boot_id: String,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatSample {
    sequence: i64,
    sampled_at: String,
    uptime_secs: i64,
    #[serde(default)]
    monotonic_ms: Option<i64>,
    collection_ms: i64,
    partial: bool,
    #[serde(default)]
    probe_errors: Vec<String>,
    #[serde(default)]
    skipped_probes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatAgent {
    version: String,
    mode: String,
    interval_secs: i64,
    #[serde(default)]
    push_latency_ms: Option<i64>,
    #[serde(default)]
    retry_backlog: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatCpu {
    load1: f64,
    load5: f64,
    load15: f64,
    #[serde(default)]
    usage_pct: Option<f64>,
    #[serde(default)]
    user_pct: Option<f64>,
    #[serde(default)]
    system_pct: Option<f64>,
    #[serde(default)]
    iowait_pct: Option<f64>,
    #[serde(default)]
    steal_pct: Option<f64>,
    core_count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatMemory {
    mem_total_bytes: i64,
    mem_available_bytes: i64,
    #[serde(default)]
    mem_used_bytes: Option<i64>,
    swap_total_bytes: i64,
    swap_used_bytes: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatDisk {
    kind: String,
    name: String,
    #[serde(default)]
    fs_type: Option<String>,
    #[serde(default)]
    bytes_total: Option<i64>,
    #[serde(default)]
    bytes_free: Option<i64>,
    #[serde(default)]
    bytes_used: Option<i64>,
    #[serde(default)]
    read_bytes_per_sec: Option<f64>,
    #[serde(default)]
    write_bytes_per_sec: Option<f64>,
}

impl HeartbeatDisk {
    fn used_percent(&self) -> Option<f64> {
        let total = self.bytes_total?;
        if total <= 0 {
            return None;
        }
        let used = self
            .bytes_used
            .or_else(|| self.bytes_free.map(|free| total.saturating_sub(free)))?;
        Some((used as f64 / total as f64) * 100.0)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatNetwork {
    interface: String,
    #[serde(default)]
    rx_bytes_per_sec: Option<f64>,
    #[serde(default)]
    tx_bytes_per_sec: Option<f64>,
    #[serde(default)]
    rx_errors_per_sec: Option<f64>,
    #[serde(default)]
    tx_errors_per_sec: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatProcesses {
    total: i64,
    #[serde(default)]
    running: Option<i64>,
    #[serde(default)]
    sleeping: Option<i64>,
    zombies: i64,
    #[serde(default)]
    top: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatContainers {
    #[serde(default)]
    runtime: Option<String>,
    reachable: bool,
    running: i64,
    exited: i64,
    restarting: i64,
    unhealthy: i64,
    #[serde(default)]
    details: Vec<serde_json::Value>,
}

#[cfg(test)]
#[path = "heartbeat_tests.rs"]
mod tests;
