//! Always-on non-MCP REST API (`/api/*`) for the log intelligence core —
//! the default transport for the CLI since v0.26 (`CORTEX_USE_HTTP=true`).
//!
//! REST routes mirroring the MCP action surface one-for-one (see
//! `docs/api.md` for the endpoint matrix). Every route requires the
//! `CORTEX_API_TOKEN` bearer; route mounting fails at startup when the token
//! is absent, so the surface is never silently open.
//!
//! Invariants: read routes acquire service `db_permits`; admin POST routes
//! (vacuum, checkpoint, prune-checkpoints) single-flight on
//! `MAINTENANCE_PERMIT` and audit-log the caller IP before the service call.
//! Handlers clamp caller-supplied limits (REST response-size caps) as a
//! second line of defence behind the service-layer clamps.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json},
};
use lab_auth::AuthContext;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Semaphore;
use tower_http::cors::CorsLayer;

use crate::app::{
    AbuseSearchRequest, AckErrorRequest, AiCheckpointsRequest, AiCorrelateLimitPolicy,
    AiCorrelateRequest, AiHookIncidentRequest, AiHookInvestigateRequest, AiIncidentRequest,
    AiInvestigateRequest, AiLimitPolicy, AiMcpIncidentRequest, AiMcpInvestigateRequest,
    AiParseErrorsRequest, AiPruneCheckpointsRequest, AiSkillIncidentRequest,
    AiSkillInvestigateRequest, AnomaliesRequest, ClockSkewRequest, CompareRequest, ContextRequest,
    CorrelateEventsRequest, CorrelateStateRequest, CortexService, DbBackupRequest,
    DbCheckpointRequest, DbIntegrityRequest, DbVacuumRequest, FeedLogsRequest, FileTailRequest,
    FilterLogsRequest, FleetStateRequest, GetErrorsRequest, GetLogRequest, GraphAroundRequest,
    GraphEntityLookupRequest, GraphEvidenceLookupRequest, GraphExplainRequest, HostStateRequest,
    IncidentContextRequest, IngestRateRequest, ListAiProjectsRequest, ListAiToolsRequest,
    ListAppsRequest, ListArtifactEvidenceRequest, ListHookEventsRequest, ListMcpEventsRequest,
    ListSessionsRequest, ListSkillEventsRequest, ListSourceIpsRequest, LlmInvocationsRequest,
    NotificationsRecentRequest, PatternsRequest, ProjectContextRequest,
    RecurringErrorComparisonRequest, RenderedSessionPageRequest, RequestActor, SearchLogsRequest,
    SearchSessionsRequest, ServiceError, SilentHostsRequest, SimilarIncidentsRequest,
    TailLogsRequest, TimelineRequest, TopicCorrelateRequest, UnackErrorRequest,
    UnaddressedErrorsRequest, UsageBlocksRequest,
};
use crate::artifact_evidence::{ArtifactEvidenceInput, MAX_EVIDENCE_WIRE_BYTES};
use crate::config::{ApiConfig, NotificationsConfig};
use crate::db::agent_observatory as observatory;
use crate::mcp::{AuthPolicy, build_auth_layer};
use crate::surfaces::{get, post};

mod investigation;

/// Crate version cached at compile time (CARGO_PKG_VERSION).
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Optional git SHA injected at build time via the `GIT_SHA` env var. When
/// absent we emit `None` so the `/api/version` JSON response omits the field
/// rather than rendering `null`.
const GIT_SHA: Option<&str> = option_env!("GIT_SHA");

/// Size threshold for the `POST /api/db/vacuum` full-vacuum pre-flight.
/// When the cached physical size exceeds this AND the request does NOT carry
/// `"force": true`, the handler returns 409 instead of starting a multi-minute
/// VACUUM that would block ingest. See `db_vacuum` for the dual-permit
/// design (eng-review C2/C3).
pub const FULL_VACUUM_SIZE_GUARD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Process-wide single-flight gate for the maintenance routes.
/// (`POST /api/db/vacuum`, `POST /api/db/checkpoint`,
/// `POST /api/sessions/prune-checkpoints`). Held via `ApiState::maintenance_permit`,
/// The gate is created by `RuntimeCore`, stored by `CortexService`, and cloned
/// into `ApiState`, so REST and background maintenance share one coordinator.
///
/// **Dual-permit pattern (eng-review C2)**: this gate is SEPARATE from
/// `CortexService::db_permits` (the read-worker pool). Handlers
/// `try_acquire_owned` this permit BEFORE calling the service; on `NoPermits`
/// they return 409 with `{"error": "db maintenance already in progress"}`.
/// Holding the gate outside the read pool means VACUUM can't starve
/// concurrent reads (`GET /api/hosts`, etc.). The permit is held for the
/// whole handler call including response IO — see `ApiState::maintenance_permit`
/// for the intentional "whole-op gate" rationale (bead 0p8r.19).
///
/// Static snapshot of the server identity returned by `GET /api/version`.
/// Built once at `ApiState` construction; `/api/version` is a hot read path
/// for CLI health checks and must not touch SQLite per request (eng-review #A3).
#[derive(Clone, Debug, Serialize)]
pub struct VersionInfo {
    pub version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    pub schema_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_container: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fleet_allowlist: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

fn csv_env(name: &str) -> Vec<String> {
    crate::env::var(name)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Shared mutable state for the /api/* router.
///
/// **One-pool-per-process invariant (bead 0p8r.18)**: `ApiState::new` clones
/// `maintenance_permit` from its `CortexService`, which production wires to
/// the same gate used by runtime maintenance tasks.
///
/// **Maintenance-permit lifetime (bead 0p8r.19)**: `db_vacuum`,
/// `db_checkpoint`, and `prune_ai_checkpoints` hold the permit across the
/// awaited service call AND the JSON response serialization. This is the
/// intentional "whole-op gate" — on loopback the response IO is microseconds;
/// on a remote bind (SWAG) it's tens of ms. We accept this to keep the
/// 409 contract simple: while the route reports work, the gate is held.
#[derive(Clone)]
pub struct ApiState {
    pub service: CortexService,
    pub config: ApiConfig,
    pub cors_port: u16,
    /// `true` when the MCP HTTP listener binds to a loopback address (e.g.
    /// `127.0.0.1` / `::1`). The CORS layer only emits the `localhost:{port}`
    /// and `127.0.0.1:{port}` allowlist entries when this is set; on external
    /// binds (homelab IP, Tailscale, etc.) those defaults are skipped because
    /// they'd let a malicious page on the operator's *workstation* speak to
    /// the remote API (bead 0p8r.21). `CORTEX_ALLOWED_ORIGINS` is
    /// authoritative on external binds.
    pub loopback_bind: bool,
    /// Origins to allow via CORS (in addition to the default `cors_port`
    /// loopback variants when `loopback_bind` is true). Sourced from
    /// `CORTEX_ALLOWED_ORIGINS` — single env shared with the /mcp
    /// surface. Mirrors `src/mcp/routes.rs:cors_layer`.
    pub allowed_origins: Vec<String>,
    /// Authentication policy. The `/api/*` router forces bearer enforcement
    /// regardless of this variant (see `router()`), so callers may pass any
    /// policy — the field is still carried so future per-route OAuth scope
    /// checks can read the shared `auth_state`.
    pub auth_policy: AuthPolicy,
    /// Cached server identity for `GET /api/version`.
    pub version_info: Arc<VersionInfo>,
    /// Test-overridable threshold for the `POST /api/db/vacuum` full-vacuum
    /// pre-flight (bytes). Defaults to [`FULL_VACUUM_SIZE_GUARD_BYTES`] in
    /// production via `ApiState::new`. Tests use
    /// `ApiState::with_full_vacuum_size_guard_bytes` to set a small value so
    /// they can drive the guard without seeding a multi-GB DB.
    pub full_vacuum_size_guard_bytes: u64,
    /// Single-flight gate for `POST /api/db/vacuum` and
    /// `POST /api/db/checkpoint`. In production this is a clone of the
    /// process-wide `SHARED_MAINTENANCE_PERMIT` so every router/listener in
    /// the process serializes against the same gate. See
    /// `SHARED_MAINTENANCE_PERMIT` docs for the dual-permit rationale
    /// (eng-review C2) and the test-isolation rationale.
    pub maintenance_permit: Arc<Semaphore>,
    /// When `true`, the static bearer token (`CORTEX_TOKEN`) is granted
    /// `cortex:admin` scope in addition to `cortex:read`. Mirrors
    /// [`crate::config::McpConfig::static_token_is_admin`]. Default: `false`.
    pub static_token_is_admin: bool,
    /// Server-side notification destinations used by `/api/notifications/test`.
    /// This mirrors MCP state so the REST admin endpoint has the same behavior
    /// as the `notifications_test` MCP action.
    pub notifications_config: NotificationsConfig,
    pub cursor_keys: crate::stream::CursorKeys,
    pub stream_client_permits: Arc<Semaphore>,
    pub integration_profile: Arc<serde_json::Value>,
}

impl ApiState {
    /// Build an `ApiState`, querying the SQLite schema version once at
    /// startup. Caching avoids per-request DB hits on `/api/version`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: CortexService,
        config: ApiConfig,
        cors_port: u16,
        loopback_bind: bool,
        allowed_origins: Vec<String>,
        auth_policy: AuthPolicy,
        static_token_is_admin: bool,
        notifications_config: NotificationsConfig,
        cursor_keys: crate::stream::CursorKeys,
        integration_profile: serde_json::Value,
    ) -> anyhow::Result<Self> {
        let schema_version = service.schema_version()?;
        let version_info = Arc::new(VersionInfo {
            version: CRATE_VERSION,
            git_sha: GIT_SHA.map(str::to_string),
            schema_version,
            instance_id: crate::env::var("CORTEX_INSTANCE_ID").ok(),
            deployment_id: crate::env::var("CORTEX_DEPLOYMENT_ID").ok(),
            database_fingerprint: crate::env::var("CORTEX_DATABASE_FINGERPRINT").ok(),
            compose_project: crate::env::var("CORTEX_COMPOSE_PROJECT").ok(),
            compose_service: crate::env::var("CORTEX_COMPOSE_SERVICE").ok(),
            compose_container: crate::env::var("CORTEX_COMPOSE_CONTAINER").ok(),
            fleet_allowlist: csv_env("CORTEX_FLEET_ALLOWLIST"),
            capabilities: csv_env("CORTEX_CAPABILITIES"),
        });
        let maintenance_permit = service.maintenance_permit();
        Ok(Self {
            service,
            config,
            cors_port,
            loopback_bind,
            allowed_origins,
            auth_policy,
            version_info,
            full_vacuum_size_guard_bytes: FULL_VACUUM_SIZE_GUARD_BYTES,
            maintenance_permit,
            static_token_is_admin,
            notifications_config,
            cursor_keys,
            stream_client_permits: crate::stream::shared_client_permits(),
            integration_profile: Arc::new(integration_profile),
        })
    }

    /// Test-only constructor that replaces `maintenance_permit` with a fresh
    /// per-state `Arc<Semaphore>` so parallel tests don't contend on the
    /// process-wide `SHARED_MAINTENANCE_PERMIT`. Production code MUST use
    /// `ApiState::new` so vacuum/checkpoint serialize across the whole
    /// process.
    #[cfg(test)]
    pub fn with_isolated_maintenance_permit(mut self) -> Self {
        self.maintenance_permit = Arc::new(Semaphore::new(1));
        self
    }

    #[cfg(test)]
    pub fn with_stream_client_limit(mut self, limit: usize) -> Self {
        self.stream_client_permits = Arc::new(Semaphore::new(limit));
        self
    }

    /// Test-only knob: lowers the full-vacuum pre-flight threshold so tests
    /// can drive the 409 path without seeding a multi-GB DB. Production code
    /// MUST NOT call this — the constant guards against multi-minute VACUUMs
    /// that block ingest.
    #[cfg(test)]
    pub fn with_full_vacuum_size_guard_bytes(mut self, bytes: u64) -> Self {
        self.full_vacuum_size_guard_bytes = bytes;
        self
    }
}

pub fn router(state: ApiState) -> anyhow::Result<Router> {
    use crate::surfaces::ContractRouterExt as _;
    if state.config.api_token.is_none() {
        anyhow::bail!(
            "CORTEX_API_TOKEN required for the REST API — run 'cortex setup repair' to generate one"
        );
    }

    let routes = Router::new()
        // --- syslog queries ---
        .contract_route("GET /api/search", get(search))
        .contract_route("GET /api/filter", get(filter))
        .contract_route("GET /api/feed", get(feed))
        .contract_route("GET /api/tail", get(tail))
        .contract_route("GET /api/errors", get(errors))
        .contract_route("GET /api/hosts", get(hosts))
        .contract_route("GET /api/correlate", get(correlate))
        .contract_route("GET /api/stats", get(stats))
        .contract_route("GET /api/version", get(version))
        .contract_route("GET /api/integration-profile", get(integration_profile))
        .contract_route("GET /v1/integration/identity", get(integration_profile))
        .contract_route("GET /api/capabilities", get(capabilities))
        // --- Agent Observatory (authenticated, read-only) ---
        .contract_route(
            "GET /api/agent-observatory/repositories",
            get(observatory_repositories),
        )
        .contract_route("GET /api/repositories", get(observatory_repositories))
        .contract_route(
            "GET /api/agent-observatory/worktrees",
            get(observatory_worktrees),
        )
        .contract_route(
            "GET /api/repositories/{repository_id}/worktrees",
            get(observatory_repository_worktrees),
        )
        .contract_route("GET /api/agent-observatory/runs", get(observatory_runs))
        .contract_route("GET /api/agent-runs", get(observatory_runs))
        .contract_route(
            "GET /api/agent-observatory/runs/{run_key}/events",
            get(observatory_events),
        )
        .contract_route(
            "GET /api/agent-runs/{run_key}/events",
            get(observatory_events),
        )
        .contract_route(
            "GET /api/agent-observatory/runs/{run_key}/telemetry",
            get(observatory_telemetry),
        )
        .contract_route(
            "GET /api/agent-runs/{run_key}/telemetry",
            get(observatory_telemetry),
        )
        .contract_route("GET /api/streams/logs", get(log_stream))
        .contract_route("GET /api/streams/sessions", get(session_stream))
        .merge(investigation::routes())
        // --- surface parity routes ---
        .contract_route("GET /api/source-ips", get(source_ips))
        .contract_route("GET /api/timeline", get(timeline))
        .contract_route("GET /api/patterns", get(patterns))
        .contract_route("GET /api/ingest-rate", get(ingest_rate))
        .contract_route("GET /api/get", get(get_log))
        .contract_route("GET /api/host-state", get(host_state))
        .contract_route("GET /api/context", get(context))
        .contract_route("GET /api/fleet-state", get(fleet_state))
        .contract_route("GET /api/correlate-state", get(correlate_state))
        .contract_route("POST /api/topic-correlate", post(topic_correlate))
        .contract_route("GET /api/errors/unaddressed", get(unaddressed_errors))
        .contract_route("POST /api/errors/ack", post(ack_error))
        .contract_route("POST /api/errors/unack", post(unack_error))
        .contract_route("GET /api/notifications/recent", get(notifications_recent))
        .contract_route("POST /api/notifications/test", post(notifications_test))
        .contract_route("POST /api/file-tails", post(file_tails))
        // --- surface parity routes ---
        .contract_route("GET /api/silent-hosts", get(silent_hosts))
        .contract_route("GET /api/clock-skew", get(clock_skew))
        .contract_route("GET /api/anomalies", get(anomalies))
        .contract_route("GET /api/compare", get(compare))
        .contract_route("GET /api/apps", get(apps))
        .contract_route("GET /api/similar-incidents", get(similar_incidents))
        .contract_route(
            "GET /api/recurring-error-comparison",
            get(recurring_error_comparison),
        )
        .contract_route("GET /api/incident-context", get(incident_context))
        .contract_route("GET /api/graph/entity", get(graph_entity))
        .contract_route("GET /api/graph/around", get(graph_around))
        .contract_route("GET /api/graph/explain", get(graph_explain))
        .contract_route("GET /api/graph/evidence", get(graph_evidence))
        .contract_routes(
            &["GET /api/artifact-evidence", "POST /api/artifact-evidence"],
            get(artifact_evidence).post(record_artifact_evidence),
        )
        .contract_route("GET /api/sessions/incidents", get(ai_incidents))
        .contract_route("GET /api/sessions/investigate", get(ai_investigate))
        .contract_route("GET /api/sessions/llm-invocations", get(ai_llm_invocations))
        .contract_route("GET /api/sessions/skills", get(ai_skills))
        .contract_route("GET /api/sessions/skill-incidents", get(ai_skill_incidents))
        .contract_route(
            "GET /api/sessions/skill-investigate",
            get(ai_skill_investigate),
        )
        .contract_route("GET /api/sessions/mcp-events", get(ai_mcp_events))
        .contract_route("GET /api/sessions/mcp-incidents", get(ai_mcp_incidents))
        .contract_route("GET /api/sessions/mcp-investigate", get(ai_mcp_investigate))
        .contract_route("GET /api/sessions/hooks", get(ai_hooks))
        .contract_route("GET /api/sessions/hook-incidents", get(ai_hook_incidents))
        .contract_route(
            "GET /api/sessions/hook-investigate",
            get(ai_hook_investigate),
        )
        .contract_route("GET /api/compose/status", get(compose_status))
        .contract_route("GET /api/compose/doctor", get(compose_doctor))
        // --- ai session queries ---
        .contract_route("GET /api/sessions", get(sessions))
        .contract_route("GET /api/sessions/rendered", get(rendered_session_page))
        .contract_route("GET /api/sessions/search", get(ai_search))
        .contract_route("GET /api/sessions/abuse", get(ai_abuse))
        .contract_route("GET /api/sessions/correlate", get(ai_correlate))
        .contract_route("GET /api/sessions/blocks", get(ai_blocks))
        .contract_route("GET /api/sessions/context", get(ai_context))
        .contract_route("GET /api/sessions/tools", get(ai_tools))
        .contract_route("GET /api/sessions/projects", get(ai_projects))
        // --- ai diagnostic + admin (bead 0p8r.3) ---
        .contract_route("GET /api/sessions/checkpoints", get(ai_checkpoints))
        .contract_route("GET /api/sessions/errors", get(ai_parse_errors))
        .contract_route(
            "POST /api/sessions/prune-checkpoints",
            post(ai_prune_checkpoints),
        )
        // --- db ops (bead 0p8r.4) ---
        .contract_route("GET /api/db/status", get(db_status))
        .contract_route("GET /api/db/integrity", get(db_integrity))
        .contract_route(
            "POST /api/db/integrity/background",
            post(db_integrity_background),
        )
        .contract_route("GET /api/db/integrity/jobs/{id}", get(db_integrity_job))
        .contract_route("POST /api/db/checkpoint", post(db_checkpoint))
        .contract_route("POST /api/db/vacuum", post(db_vacuum))
        .contract_route("POST /api/db/backup", post(db_backup));

    // Force `AuthPolicy::Mounted` on /api/* regardless of the listener bind.
    // Loopback callers (CLI on the same host) MUST still present a bearer
    // token — the single-token model documented for /api/* and /mcp depends
    // on this invariant (eng-review C1).
    let forced_policy = match &state.auth_policy {
        AuthPolicy::LoopbackDev | AuthPolicy::TrustedGatewayUnscoped => {
            AuthPolicy::Mounted { auth_state: None }
        }
        AuthPolicy::Mounted { auth_state } => AuthPolicy::Mounted {
            auth_state: auth_state.clone(),
        },
    };
    let routes = match build_auth_layer(
        &forced_policy,
        state.config.api_token.as_deref().map(Arc::<str>::from),
        None,
        state.static_token_is_admin,
    ) {
        Some(layer) => routes.layer(layer),
        _ => {
            // `forced_policy` is always `Mounted`, so `build_auth_layer` returns
            // `Some(_)`. Reach here only if `build_auth_layer` ever changes its
            // contract — fail loud rather than mount routes without auth.
            anyhow::bail!(
                "internal: auth layer construction returned None for /api/* (forced Mounted)"
            )
        }
    };

    let cors = cors_layer(state.cors_port, state.loopback_bind, &state.allowed_origins);
    let routes = routes.layer(cors).with_state(state);
    Ok(routes)
}

pub fn resolved_integration_profile(
    config: &crate::config::Config,
) -> anyhow::Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    let configured_seed = config
        .server_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.mcp.auth.public_url.clone());
    if configured_seed.is_none() && !crate::config::mcp_bind_is_loopback(config) {
        anyhow::bail!("non-loopback integrations require CORTEX_SERVER_ID or CORTEX_PUBLIC_URL");
    }
    let seed = configured_seed.unwrap_or_else(|| {
        format!(
            "{}\0{}\0{}",
            config.mcp.server_name,
            config.mcp.bind_addr(),
            config.storage.db_path.display()
        )
    });
    let server_id = if seed.starts_with("cortex_") && seed.len() >= 23 {
        seed
    } else {
        format!("cortex_{:x}", Sha256::digest(seed.as_bytes()))
    };
    let public_url = config.mcp.auth.public_url.clone();
    let token_generation = config.api.api_token.as_deref().map_or_else(
        || "none".to_string(),
        |token| format!("{:x}", Sha256::digest(token.as_bytes()))[..16].to_string(),
    );
    let modes = if config.mcp.auth.mode == crate::config::AuthMode::OAuth {
        serde_json::json!(["static_bearer", "oauth2"])
    } else {
        serde_json::json!(["static_bearer"])
    };
    Ok(serde_json::json!({
        "contract_version":"1.0.0", "product":"cortex", "server_id":server_id,
        "product_version":CRATE_VERSION, "api_version":{"major":1,"minor":0},
        "route_support":["logs","sessions","fleet","graph","correlation"],
        "auth":{"modes":modes,"issuer":public_url,"audience":public_url,
            "token_endpoint_origin":public_url,"principal_cache_scope":"issuer+subject",
            "credential_generation":token_generation},
        "streams":{"transport":"sse","resume":"opaque_cursor"}
    }))
}

async fn file_tails(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<FileTailRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    tracing::warn!(caller_ip = %peer.ip(), action = ?req.op, "admin: file_tails invoked");
    respond(state.service.ingest().file_tails(req).await)
}

fn require_api_admin_token(
    state: &ApiState,
    headers: &HeaderMap,
) -> Option<axum::response::Response> {
    let Some(expected) = state
        .config
        .admin_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    else {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "CORTEX_API_ADMIN_TOKEN required for admin API actions"})),
            )
                .into_response(),
        );
    };
    let presented = headers
        .get("x-cortex-admin-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if presented == Some(expected) {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "X-Cortex-Admin-Token required for admin API actions"})),
            )
                .into_response(),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryRepositoriesQuery {
    host: Option<String>,
    query: Option<String>,
    active_runs_only: Option<bool>,
    include_removed: Option<bool>,
    since: Option<String>,
    until: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ObservatoryPage<T> {
    #[serde(flatten)]
    resources: T,
    pagination: crate::app::agent_observatory::Pagination,
    as_of: String,
    stream_cursor: String,
}

#[derive(Serialize)]
struct RepositoryResources<T> {
    repositories: Vec<T>,
}
#[derive(Serialize)]
struct WorktreeResources<T> {
    worktrees: Vec<T>,
}
#[derive(Serialize)]
struct RunResources<T> {
    runs: Vec<T>,
}
#[derive(Serialize)]
struct EventResources<T> {
    run_key: String,
    events: Vec<T>,
}

fn observatory_page<T, R>(
    page: crate::app::agent_observatory::Page<T>,
    resources: impl FnOnce(Vec<T>) -> R,
) -> ObservatoryPage<R> {
    let crate::app::agent_observatory::Page {
        items,
        pagination,
        as_of,
        stream_cursor,
    } = page;

    ObservatoryPage {
        resources: resources(items),
        pagination,
        as_of,
        stream_cursor,
    }
}

async fn observatory_repositories(
    State(state): State<ApiState>,
    Query(query): Query<ObservatoryRepositoriesQuery>,
) -> impl IntoResponse {
    match state
        .service
        .observatory_repositories(
            observatory::RepositoryQuery {
                host: query.host,
                query: query.query,
                active_runs_only: query.active_runs_only.unwrap_or(false),
                include_removed: query.include_removed.unwrap_or(false),
                since: query.since,
                until: query.until,
            },
            query.cursor,
            query.limit.unwrap_or(50),
        )
        .await
    {
        Ok(page) => Json(observatory_page(page, |repositories| RepositoryResources {
            repositories,
        }))
        .into_response(),
        Err(error) => respond::<()>(Err(error)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryWorktreesQuery {
    repository_id: i64,
    branch: Option<String>,
    dirty: Option<bool>,
    include_removed: Option<bool>,
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryRepositoryWorktreesQuery {
    branch: Option<String>,
    dirty: Option<bool>,
    include_removed: Option<bool>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn observatory_worktrees(
    State(state): State<ApiState>,
    Query(query): Query<ObservatoryWorktreesQuery>,
) -> impl IntoResponse {
    match state
        .service
        .observatory_worktrees(
            query.repository_id,
            query.branch,
            query.dirty,
            query.include_removed.unwrap_or(false),
            query.cursor,
            query.limit.unwrap_or(50),
        )
        .await
    {
        Ok(page) => Json(observatory_page(page, |worktrees| WorktreeResources {
            worktrees,
        }))
        .into_response(),
        Err(error) => respond::<()>(Err(error)),
    }
}

async fn observatory_repository_worktrees(
    State(state): State<ApiState>,
    Path(repository_id): Path<i64>,
    serde_qs::axum::QsQuery(query): serde_qs::axum::QsQuery<ObservatoryRepositoryWorktreesQuery>,
) -> impl IntoResponse {
    match state
        .service
        .observatory_worktrees(
            repository_id,
            query.branch,
            query.dirty,
            query.include_removed.unwrap_or(false),
            query.cursor,
            query.limit.unwrap_or(50),
        )
        .await
    {
        Ok(page) => Json(observatory_page(page, |worktrees| WorktreeResources {
            worktrees,
        }))
        .into_response(),
        Err(error) => respond::<()>(Err(error)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryRunsQuery {
    repository_id: Option<i64>,
    worktree_id: Option<i64>,
    branch: Option<String>,
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    tool: Vec<String>,
    host: Option<String>,
    query: Option<String>,
    since: Option<String>,
    until: Option<String>,
    active_only: Option<bool>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn observatory_runs(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(query): serde_qs::axum::QsQuery<ObservatoryRunsQuery>,
) -> impl IntoResponse {
    match state
        .service
        .observatory_runs(
            observatory::AgentRunQuery {
                repository_id: query.repository_id,
                worktree_id: query.worktree_id,
                branch: query.branch,
                statuses: query.status,
                tools: query.tool,
                host: query.host,
                query: query.query,
                since: query.since,
                until: query.until,
                active_only: query.active_only.unwrap_or(false),
            },
            query.cursor,
            query.limit.unwrap_or(50),
        )
        .await
    {
        Ok(page) => Json(observatory_page(page, |runs| RunResources { runs })).into_response(),
        Err(error) => respond::<()>(Err(error)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryEventsQuery {
    #[serde(default)]
    kind: Vec<String>,
    severity_min: Option<i64>,
    actor_key: Option<String>,
    trace_id: Option<String>,
    query: Option<String>,
    since: Option<String>,
    until: Option<String>,
    include: Option<String>,
    order: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn observatory_events(
    State(state): State<ApiState>,
    Path(run_key): Path<String>,
    serde_qs::axum::QsQuery(query): serde_qs::axum::QsQuery<ObservatoryEventsQuery>,
) -> impl IntoResponse {
    let asc = query.order.as_deref().is_some_and(|order| order == "asc");
    if query
        .order
        .as_deref()
        .is_some_and(|order| order != "asc" && order != "desc")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_order"})),
        )
            .into_response();
    }
    let include_payload = match query.include.as_deref() {
        None => false,
        Some("payload") => true,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_include"})),
            )
                .into_response();
        }
    };
    let response_run_key = run_key.clone();
    match state
        .service
        .observatory_events(
            run_key,
            observatory::AgentEventQuery {
                kinds: query.kind,
                severity_min: query.severity_min,
                actor_key: query.actor_key,
                trace_id: query.trace_id,
                query: query.query,
                since: query.since,
                until: query.until,
                include_payload,
            },
            query.cursor,
            query.limit.unwrap_or(100),
            asc,
        )
        .await
    {
        Ok(page) => Json(observatory_page(page, |events| EventResources {
            run_key: response_run_key,
            events,
        }))
        .into_response(),
        Err(error) => respond::<()>(Err(error)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservatoryTelemetryQuery {
    trace_id: Option<String>,
    metric_name: Option<String>,
    since_nano: Option<i64>,
    until_nano: Option<i64>,
    span_cursor: Option<String>,
    metric_cursor: Option<String>,
    span_limit: Option<usize>,
    metric_limit: Option<usize>,
}

async fn observatory_telemetry(
    State(state): State<ApiState>,
    Path(run_key): Path<String>,
    Query(query): Query<ObservatoryTelemetryQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .observatory_telemetry(
                run_key,
                observatory::TelemetryQuery {
                    trace_id: query.trace_id,
                    metric_name: query.metric_name,
                    since_nano: query.since_nano,
                    until_nano: query.until_nano,
                },
                query.span_cursor,
                query.metric_cursor,
                query.span_limit.unwrap_or(100),
                query.metric_limit.unwrap_or(100),
            )
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchQuery {
    query: Option<String>,
    host: Option<String>,
    source: Option<String>,
    severity: Option<String>,
    app: Option<String>,
    facility: Option<String>,
    exclude_facility: Option<String>,
    process_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    received_since: Option<String>,
    received_until: Option<String>,
    limit: Option<u32>,
    source_kind: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    session_id: Option<String>,
    container: Option<String>,
    docker_host: Option<String>,
    stream: Option<String>,
    event_action: Option<String>,
}

async fn search(
    State(state): State<ApiState>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .search_logs(SearchLogsRequest {
                query: query.query,
                host: query.host,
                source: query.source,
                severity: query.severity,
                app: query.app,
                facility: query.facility,
                exclude_facility: query.exclude_facility,
                process_id: query.process_id,
                since: query.since,
                until: query.until,
                received_since: query.received_since,
                received_until: query.received_until,
                limit: query.limit,
                source_kind: query.source_kind,
                tool: query.tool,
                project: query.project,
                session_id: query.session_id,
                container: query.container,
                docker_host: query.docker_host,
                stream: query.stream,
                event_action: query.event_action,
            })
            .await,
    )
}

async fn filter(
    State(state): State<ApiState>,
    Query(query): Query<FilterLogsRequest>,
) -> impl IntoResponse {
    respond(state.service.filter_logs(query).await)
}

async fn feed(
    State(state): State<ApiState>,
    Query(query): Query<FeedLogsRequest>,
) -> impl IntoResponse {
    respond(state.service.feed_logs(query).await)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TailQuery {
    host: Option<String>,
    source: Option<String>,
    app: Option<String>,
    severity_min: Option<String>,
    n: Option<u32>,
}

async fn tail(State(state): State<ApiState>, Query(query): Query<TailQuery>) -> impl IntoResponse {
    respond(
        state
            .service
            .tail_logs(TailLogsRequest {
                host: query.host,
                source: query.source,
                app: query.app,
                severity_min: query.severity_min,
                n: query.n,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorQuery {
    since: Option<String>,
    until: Option<String>,
    group_by: Option<String>,
    limit: Option<u32>,
}

async fn errors(
    State(state): State<ApiState>,
    Query(query): Query<ErrorQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .analysis()
            .errors(GetErrorsRequest {
                since: query.since,
                until: query.until,
                group_by: query.group_by,
                limit: query.limit,
            })
            .await,
    )
}

async fn hosts(State(state): State<ApiState>) -> impl IntoResponse {
    respond(state.service.hosts().list().await)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelateQuery {
    reference_time: Option<String>,
    window_minutes: Option<u32>,
    severity_min: Option<String>,
    host: Option<String>,
    source: Option<String>,
    query: Option<String>,
    limit: Option<u32>,
}

async fn correlate(
    State(state): State<ApiState>,
    Query(query): Query<CorrelateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .correlate()
            .events(CorrelateEventsRequest {
                reference_time: query.reference_time,
                window_minutes: query.window_minutes,
                severity_min: query.severity_min,
                host: query.host,
                source: query.source,
                query: query.query,
                limit: query.limit,
            })
            .await,
    )
}

async fn stats(State(state): State<ApiState>) -> impl IntoResponse {
    respond(state.service.stats().summary().await)
}

/// `GET /api/version` — returns the cached server identity. SQLite is NOT
/// queried per request; `schema_version` is captured once at startup.
async fn version(State(state): State<ApiState>) -> impl IntoResponse {
    Json((*state.version_info).clone()).into_response()
}

/// Runtime identity used by typed clients.  Every field is derived from the
/// same mounted routes/auth configuration advertised by this process.
async fn integration_profile(State(state): State<ApiState>) -> impl IntoResponse {
    Json((*state.integration_profile).clone()).into_response()
}

/// `GET /api/capabilities` — explicit transport support for typed clients.
/// Native streams remain false until the durable SSE slice lands.
async fn capabilities() -> impl IntoResponse {
    Json(crate::app::capabilities()).into_response()
}

async fn log_stream(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Query(mut request): Query<crate::stream::LogStreamRequest>,
) -> impl IntoResponse {
    if request.cursor.is_none() {
        request.cursor = last_event_id(&headers);
    }
    crate::stream::log_stream_with_clients(
        state.service,
        auth,
        request,
        state.cursor_keys,
        state.stream_client_permits,
    )
    .await
    .into_response()
}

async fn session_stream(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Query(mut request): Query<crate::stream::SessionStreamRequest>,
) -> impl IntoResponse {
    if request.cursor.is_none() {
        request.cursor = last_event_id(&headers);
    }
    crate::stream::session_stream(state.service, auth, request, state.cursor_keys)
        .await
        .into_response()
}

fn last_event_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

// ─── Surface parity routes ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SourceIpsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn source_ips(
    State(state): State<ApiState>,
    Query(query): Query<SourceIpsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .hosts()
            .source_ips(ListSourceIpsRequest {
                limit: query.limit,
                offset: query.offset,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimelineQuery {
    bucket: Option<String>,
    group_by: Option<String>,
    since: Option<String>,
    until: Option<String>,
    host: Option<String>,
    app: Option<String>,
    severity_min: Option<String>,
}

async fn timeline(
    State(state): State<ApiState>,
    Query(query): Query<TimelineQuery>,
) -> impl IntoResponse {
    // Default lookback is centralized in `CortexService::timeline` (bead dyqw):
    // it applies a bucket-sized window only when neither `since` nor `until` is set,
    // preventing full table scans without recreating the logic per transport.
    respond(
        state
            .service
            .stats()
            .timeline(TimelineRequest {
                bucket: query.bucket,
                group_by: query.group_by,
                since: query.since,
                until: query.until,
                host: query.host,
                app: query.app,
                severity_min: query.severity_min,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternsQuery {
    since: Option<String>,
    until: Option<String>,
    host: Option<String>,
    app: Option<String>,
    severity_min: Option<String>,
    scan_limit: Option<u32>,
    top_n: Option<u32>,
}

async fn patterns(
    State(state): State<ApiState>,
    Query(query): Query<PatternsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .analysis()
            .patterns(PatternsRequest {
                since: query.since,
                until: query.until,
                host: query.host,
                app: query.app,
                severity_min: query.severity_min,
                scan_limit: query.scan_limit,
                top_n: query.top_n,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct IngestRateQuery {
    by_host: Option<bool>,
}

async fn ingest_rate(
    State(state): State<ApiState>,
    Query(query): Query<IngestRateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .stats()
            .ingest_rate(IngestRateRequest {
                by_host: query.by_host,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct GetLogQuery {
    id: i64,
}

async fn get_log(
    State(state): State<ApiState>,
    Query(query): Query<GetLogQuery>,
) -> impl IntoResponse {
    respond(state.service.get_log(GetLogRequest { id: query.id }).await)
}

async fn host_state(
    State(state): State<ApiState>,
    Query(req): Query<HostStateRequest>,
) -> impl IntoResponse {
    respond(state.service.state().host(req).await)
}

async fn context(
    State(state): State<ApiState>,
    Query(req): Query<ContextRequest>,
) -> impl IntoResponse {
    respond(state.service.context(req).await)
}

async fn fleet_state(
    State(state): State<ApiState>,
    Query(req): Query<FleetStateRequest>,
) -> impl IntoResponse {
    respond(state.service.state().fleet(req).await)
}

async fn correlate_state(
    State(state): State<ApiState>,
    Query(req): Query<CorrelateStateRequest>,
) -> impl IntoResponse {
    respond(state.service.correlate().state(req).await)
}

async fn topic_correlate(
    State(state): State<ApiState>,
    Json(req): Json<TopicCorrelateRequest>,
) -> impl IntoResponse {
    respond(state.service.correlate().topic(req).await)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnaddressedErrorsQuery {
    limit: Option<u32>,
    include_acknowledged: Option<bool>,
}

async fn unaddressed_errors(
    State(state): State<ApiState>,
    Query(query): Query<UnaddressedErrorsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .alerts()
            .signatures(UnaddressedErrorsRequest {
                limit: query.limit,
                include_acknowledged: query.include_acknowledged,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct AckErrorBody {
    signature_hash: String,
    notes: Option<String>,
}

async fn ack_error(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<AckErrorBody>,
) -> impl IntoResponse {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    tracing::warn!(caller_ip = %peer.ip(), signature_hash = %body.signature_hash, "admin: ack_error invoked");
    respond(
        state
            .service
            .alerts()
            .ack_signature(
                AckErrorRequest {
                    signature_hash: body.signature_hash,
                    notes: body.notes,
                },
                RequestActor::api(),
            )
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct UnackErrorBody {
    signature_hash: String,
    reason: Option<String>,
}

async fn unack_error(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<UnackErrorBody>,
) -> impl IntoResponse {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    tracing::warn!(caller_ip = %peer.ip(), signature_hash = %body.signature_hash, "admin: unack_error invoked");
    respond(
        state
            .service
            .alerts()
            .unack_signature(
                UnackErrorRequest {
                    signature_hash: body.signature_hash,
                    reason: body.reason,
                },
                RequestActor::api(),
            )
            .await,
    )
}

async fn notifications_recent(
    State(state): State<ApiState>,
    Query(req): Query<NotificationsRecentRequest>,
) -> impl IntoResponse {
    respond(state.service.alerts().notifications(req).await)
}

/// `GET /api/sessions/llm-invocations` — admin-gated, unlike the plain
/// `notifications_recent` handler above: `llm_invocations` exposes
/// circuit-breaker/kill-switch/rate-limit operational state (see eng review
/// Fix 4 in the LLM invocation guard plan), so it requires
/// `CORTEX_API_ADMIN_TOKEN` / `X-Cortex-Admin-Token`, matching the existing
/// `ack_error`/`unack_error` admin handlers.
async fn ai_llm_invocations(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(req): Query<LlmInvocationsRequest>,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    tracing::warn!(caller_ip = %peer.ip(), "admin: llm_invocations invoked");
    respond(state.service.llm_invocations_checked(req).await)
}

/// `GET /api/sessions/skills` — `cortex:read`-scoped per GH #94's explicit
/// decision (not admin, unlike `ai_llm_invocations` above). Note: the
/// original plan drafted this as `GET /api/ai/skills`, but the live repo
/// permanently removed the `/api/ai/*` prefix as a "clean break" migration
/// to `/api/sessions/*` (see `src/surfaces/api.rs`'s `RemovedCleanBreak`
/// entries + `surfaces_tests::api_ai_routes_are_intentional_clean_breaks`,
/// which asserts `/api/ai/*` stays gone with no compatibility shim) — so
/// this route lives under `/api/sessions/` alongside its siblings
/// (`/api/sessions/tools`, `/api/sessions/llm-invocations`, etc.) instead.
/// As cheap defense-in-depth this handler logs the caller IP and query
/// filters at `tracing::info!` before serving the response — matching the
/// logging LEVEL convention of `Read`-scoped AI-transcript routes in this
/// file (the admin-scoped `ai_llm_invocations` uses `tracing::warn!`
/// because it exposes kill-switch/circuit-breaker operational state; a
/// plain `Read`-scoped route like this one uses `info!` instead, so
/// there's at least a trace record of who queried skill-usage history
/// without the noise level of a `warn!` on every normal read).
async fn ai_skills(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(req): Query<ListSkillEventsRequest>,
) -> impl IntoResponse {
    tracing::info!(
        caller_ip = %peer.ip(),
        skill = ?req.skill,
        plugin = ?req.plugin,
        tool = ?req.tool,
        project = ?req.project,
        session_id = ?req.session_id,
        hostname = ?req.hostname,
        "read: skill_events queried"
    );
    respond(state.service.list_skill_events(req).await)
}

/// `GET /api/sessions/hooks` — `cortex:read`-scoped, mirrors `ai_skills`
/// above one-for-one (GH #105).
async fn ai_hooks(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(req): Query<ListHookEventsRequest>,
) -> impl IntoResponse {
    tracing::info!(
        caller_ip = %peer.ip(),
        hook_event = ?req.hook_event,
        hook_name = ?req.hook_name,
        hook_source = ?req.hook_source,
        evidence_kind = ?req.evidence_kind,
        tool = ?req.tool,
        project = ?req.project,
        session_id = ?req.session_id,
        hostname = ?req.hostname,
        "read: hook_events queried"
    );
    respond(state.service.list_hook_events(req).await)
}

async fn artifact_evidence(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(req): Query<ListArtifactEvidenceRequest>,
) -> impl IntoResponse {
    tracing::info!(
        caller_ip = %peer.ip(),
        event_kind = ?req.event_kind,
        artifact_id_filter = req.artifact_id.is_some(),
        revision_id_filter = req.revision_id.is_some(),
        content_digest_filter = req.content_digest.is_some(),
        correlation_id_filter = req.correlation_id.is_some(),
        request_id_filter = req.request_id.is_some(),
        target_id_filter = req.target_id.is_some(),
        source_system_filter = req.source_system.is_some(),
        "read: artifact_evidence queried"
    );
    respond(state.service.list_artifact_evidence(req).await)
}

async fn record_artifact_evidence(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> axum::response::Response {
    // Authorize the admin mutation before reading or parsing caller-controlled
    // evidence bytes. This keeps malformed bodies from becoming an admin-token
    // oracle and avoids buffering an unbounded request before the admin check.
    if let Some(resp) = require_api_admin_token(&state, request.headers()) {
        return resp;
    }
    let content_type_ok = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|media_type| {
            media_type == "application/json"
                || (media_type.starts_with("application/") && media_type.ends_with("+json"))
        });
    if !content_type_ok {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({"error": "artifact_evidence_requires_json"})),
        )
            .into_response();
    }
    let body = match axum::body::to_bytes(request.into_body(), MAX_EVIDENCE_WIRE_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "artifact_evidence_body_too_large"})),
            )
                .into_response();
        }
    };
    let input: ArtifactEvidenceInput = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_artifact_evidence_body"})),
            )
                .into_response();
        }
    };
    tracing::warn!(
        caller_ip = %peer.ip(),
        event_kind = input.event_kind.as_str(),
        "admin: artifact_evidence record invoked"
    );
    respond(state.service.record_artifact_evidence(input).await)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationsTestBody {
    body: Option<String>,
}

async fn notifications_test(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    let req: NotificationsTestBody = if body.is_empty() {
        NotificationsTestBody { body: None }
    } else {
        match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid request body: {err}")})),
                )
                    .into_response();
            }
        }
    };
    tracing::warn!(caller_ip = %peer.ip(), "admin: notifications_test invoked");
    let message = req
        .body
        .unwrap_or_else(|| "Test notification from cortex".to_string());
    respond(
        state
            .service
            .alerts()
            .test_notification(message, RequestActor::api(), &state.notifications_config)
            .await
            .map(|result| json!({ "result": result })),
    )
}

// ─── Surface parity gap closure (12 new handlers) ───────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SilentHostsQuery {
    silent_minutes: Option<u32>,
}

async fn silent_hosts(
    State(state): State<ApiState>,
    Query(query): Query<SilentHostsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .hosts()
            .silent(SilentHostsRequest {
                silent_minutes: query.silent_minutes,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockSkewQuery {
    since: Option<String>,
    limit: Option<u32>,
}

async fn clock_skew(
    State(state): State<ApiState>,
    Query(query): Query<ClockSkewQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .state()
            .clock_skew(ClockSkewRequest {
                since: query.since,
                limit: query.limit,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnomaliesQuery {
    recent_minutes: Option<u32>,
    baseline_minutes: Option<u32>,
}

async fn anomalies(
    State(state): State<ApiState>,
    Query(query): Query<AnomaliesQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .analysis()
            .anomalies(AnomaliesRequest {
                recent_minutes: query.recent_minutes,
                baseline_minutes: query.baseline_minutes,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompareQuery {
    a_from: Option<String>,
    a_to: Option<String>,
    b_from: Option<String>,
    b_to: Option<String>,
}

async fn compare(
    State(state): State<ApiState>,
    Query(query): Query<CompareQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .analysis()
            .compare(CompareRequest {
                a_from: query.a_from,
                a_to: query.a_to,
                b_from: query.b_from,
                b_to: query.b_to,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppsQuery {
    host: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn apps(State(state): State<ApiState>, Query(query): Query<AppsQuery>) -> impl IntoResponse {
    respond(
        state
            .service
            .list_apps(ListAppsRequest {
                host: query.host,
                since: query.since,
                until: query.until,
                limit: query.limit,
                offset: query.offset,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimilarIncidentsQuery {
    query: String,
    host: Option<String>,
    app: Option<String>,
    severity_min: Option<String>,
    since: Option<String>,
    until: Option<String>,
    window_minutes: Option<u32>,
    limit: Option<u32>,
}

async fn similar_incidents(
    State(state): State<ApiState>,
    Query(q): Query<SimilarIncidentsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .similar_incidents(SimilarIncidentsRequest {
                query: q.query,
                host: q.host,
                app: q.app,
                severity_min: q.severity_min,
                since: q.since,
                until: q.until,
                window_minutes: q.window_minutes,
                limit: q.limit,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecurringErrorComparisonQuery {
    signature_hash: Option<String>,
    since: Option<String>,
    until: Option<String>,
    window_minutes: Option<u32>,
    limit: Option<u32>,
    include_acknowledged: Option<bool>,
}

async fn recurring_error_comparison(
    State(state): State<ApiState>,
    Query(q): Query<RecurringErrorComparisonQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .compare_recurring_errors(RecurringErrorComparisonRequest {
                signature_hash: q.signature_hash,
                since: q.since,
                until: q.until,
                window_minutes: q.window_minutes,
                limit: q.limit,
                include_acknowledged: q.include_acknowledged,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IncidentContextQuery {
    since: Option<String>,
    until: Option<String>,
    host: Option<String>,
    app: Option<String>,
    query: Option<String>,
    severity_min: Option<String>,
    limit: Option<u32>,
}

async fn incident_context(
    State(state): State<ApiState>,
    Query(q): Query<IncidentContextQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .incident_context(IncidentContextRequest {
                since: q.since,
                until: q.until,
                host: q.host,
                app: q.app,
                query: q.query,
                severity_min: q.severity_min,
                limit: q.limit,
            })
            .await,
    )
}

async fn graph_entity(
    State(state): State<ApiState>,
    Query(q): Query<GraphEntityLookupRequest>,
) -> impl IntoResponse {
    respond(state.service.graph_entity_lookup(q).await)
}

async fn graph_around(
    State(state): State<ApiState>,
    Query(q): Query<GraphAroundRequest>,
) -> impl IntoResponse {
    respond(state.service.graph_around(q).await)
}

async fn graph_explain(
    State(state): State<ApiState>,
    Query(q): Query<GraphExplainRequest>,
) -> impl IntoResponse {
    respond(state.service.graph_explain(q).await)
}

async fn graph_evidence(
    State(state): State<ApiState>,
    Query(q): Query<GraphEvidenceLookupRequest>,
) -> impl IntoResponse {
    respond(state.service.graph_evidence_lookup(q).await)
}

/// AI incidents — uses `QsQuery` because `terms: Vec<String>` cannot be
/// deserialized from a URL query string via `axum::extract::Query`
/// (which uses `serde_urlencoded`). Mirrors `ai_abuse` above.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiIncidentsQuery {
    project: Option<String>,
    tool: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    #[serde(default)]
    terms: Vec<String>,
}

async fn ai_incidents(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiIncidentsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .list_ai_incidents(AiIncidentRequest {
                project: q.project,
                tool: q.tool,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                terms: q.terms,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiInvestigateQuery {
    project: Option<String>,
    tool: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    correlation_window_minutes: Option<u32>,
    #[serde(default)]
    terms: Vec<String>,
}

async fn ai_investigate(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiInvestigateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .investigate_ai_incidents(AiInvestigateRequest {
                incident_id: None,
                project: q.project,
                tool: q.tool,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                correlation_window_minutes: q.correlation_window_minutes,
                terms: q.terms,
            })
            .await,
    )
}

/// Skill incidents — uses `QsQuery` because `signals: Vec<String>` cannot be
/// deserialized from a URL query string via `axum::extract::Query`. Mirrors
/// `ai_incidents` above.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiSkillIncidentsQuery {
    skill: Option<String>,
    plugin: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    session_id: Option<String>,
    hostname: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    #[serde(default)]
    signals: Vec<String>,
    min_score: Option<f64>,
}

async fn ai_skill_incidents(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiSkillIncidentsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .list_ai_skill_incidents(AiSkillIncidentRequest {
                skill: q.skill,
                plugin: q.plugin,
                tool: q.tool,
                project: q.project,
                session_id: q.session_id,
                hostname: q.hostname,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                signals: q.signals,
                min_score: q.min_score,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiSkillInvestigateQuery {
    incident_id: Option<String>,
    skill: Option<String>,
    plugin: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    correlation_window_minutes: Option<u32>,
}

async fn ai_skill_investigate(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiSkillInvestigateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .investigate_ai_skill_incidents(AiSkillInvestigateRequest {
                incident_id: q.incident_id,
                skill: q.skill,
                plugin: q.plugin,
                tool: q.tool,
                project: q.project,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                correlation_window_minutes: q.correlation_window_minutes,
            })
            .await,
    )
}

async fn ai_mcp_events(
    State(state): State<ApiState>,
    Query(q): Query<ListMcpEventsRequest>,
) -> impl IntoResponse {
    respond(state.service.list_mcp_events(q).await)
}

async fn ai_mcp_incidents(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiMcpIncidentRequest>,
) -> impl IntoResponse {
    respond(state.service.list_ai_mcp_incidents(q).await)
}

async fn ai_mcp_investigate(
    State(state): State<ApiState>,
    Query(q): Query<AiMcpInvestigateRequest>,
) -> impl IntoResponse {
    respond(state.service.investigate_ai_mcp_incidents(q).await)
}

/// Hook incidents — mirrors `AiSkillIncidentsQuery`/`ai_skill_incidents`
/// one-for-one (GH #105).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiHookIncidentsQuery {
    hook_event: Option<String>,
    hook_name: Option<String>,
    hook_source: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    session_id: Option<String>,
    hostname: Option<String>,
    evidence_kind: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    #[serde(default)]
    signals: Vec<String>,
    min_score: Option<f64>,
}

async fn ai_hook_incidents(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiHookIncidentsQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .list_ai_hook_incidents(AiHookIncidentRequest {
                hook_event: q.hook_event,
                hook_name: q.hook_name,
                hook_source: q.hook_source,
                tool: q.tool,
                project: q.project,
                session_id: q.session_id,
                hostname: q.hostname,
                evidence_kind: q.evidence_kind,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                signals: q.signals,
                min_score: q.min_score,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiHookInvestigateQuery {
    incident_id: Option<String>,
    hook_event: Option<String>,
    hook_name: Option<String>,
    hook_source: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<u32>,
    window_minutes: Option<u32>,
    correlation_window_minutes: Option<u32>,
}

async fn ai_hook_investigate(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(q): serde_qs::axum::QsQuery<AiHookInvestigateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .investigate_ai_hook_incidents(AiHookInvestigateRequest {
                incident_id: q.incident_id,
                hook_event: q.hook_event,
                hook_name: q.hook_name,
                hook_source: q.hook_source,
                tool: q.tool,
                project: q.project,
                since: q.since,
                until: q.until,
                limit: q.limit,
                window_minutes: q.window_minutes,
                correlation_window_minutes: q.correlation_window_minutes,
            })
            .await,
    )
}

async fn compose_status() -> impl IntoResponse {
    match crate::app::run_compose_status().await {
        Ok(status) => respond::<_>(Ok(crate::compose::mcp_projection(&status))),
        Err(e) => respond::<crate::compose::ComposeMcpStatus>(Err(e)),
    }
}

async fn compose_doctor() -> impl IntoResponse {
    let status = match crate::app::run_compose_status().await {
        Ok(s) => s,
        Err(e) => {
            return respond::<crate::compose::ComposeMcpStatus>(Err(e));
        }
    };
    if let Err(e) = crate::compose::ensure_doctor_ready(&status) {
        return compose_doctor_unready_response(&status, e);
    }
    respond::<_>(Ok(crate::compose::mcp_projection(&status)))
}

fn compose_doctor_unready_response(
    status: &crate::compose::ComposeStatus,
    error: anyhow::Error,
) -> axum::response::Response {
    tracing::warn!(error = %error, "Compose doctor readiness check failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(crate::compose::mcp_projection(status)),
    )
        .into_response()
}

// ─── AI session queries ─────────────────────────────────────────────────────

async fn sessions(
    State(state): State<ApiState>,
    Query(req): Query<ListSessionsRequest>,
) -> impl IntoResponse {
    respond(state.service.list_sessions(req).await)
}

async fn rendered_session_page(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Query(mut req): Query<RenderedSessionPageRequest>,
) -> impl IntoResponse {
    if req.cursor.is_none() {
        req.cursor = last_event_id(&headers);
    }
    let filters = match crate::stream::session_filter_fingerprint(
        &req.project,
        &req.tool,
        &req.session_id,
        &req.host,
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let position = match req.cursor.as_deref() {
        Some(value) => match crate::stream::decode_session_handoff(
            value,
            &auth,
            &req.project,
            &req.tool,
            &req.session_id,
            &req.host,
            &state.cursor_keys,
        ) {
            Ok(position) => position,
            Err(error) => return error.into_response(),
        },
        None => 0,
    };
    req.cursor = Some(format!("cortex-session-v1:{position}"));
    match state.service.rendered_session_page(req).await {
        Ok(mut page) => {
            page.next_cursor = crate::stream::encode_cursor_with_keys(
                page.high_watermark,
                &crate::stream::principal(&auth),
                &filters,
                chrono::Utc::now().timestamp(),
                &state.cursor_keys,
            );
            while serde_json::to_vec(&page)
                .is_ok_and(|bytes| bytes.len() > crate::app::RENDERED_SESSION_PAGE_MAX_BYTES)
            {
                if page.events.pop().is_none() {
                    break;
                }
                page.has_more = true;
                page.truncated_by_bytes = true;
                page.high_watermark = page.events.last().map_or(position, |event| event.position);
                page.next_cursor = crate::stream::encode_cursor_with_keys(
                    page.high_watermark,
                    &crate::stream::principal(&auth),
                    &filters,
                    chrono::Utc::now().timestamp(),
                    &state.cursor_keys,
                );
            }
            Json(page).into_response()
        }
        Err(error) => respond::<()>(Err(error)),
    }
}

async fn ai_search(
    State(state): State<ApiState>,
    Query(req): Query<SearchSessionsRequest>,
) -> impl IntoResponse {
    let response = match state
        .service
        .search_sessions_with_limit_policy(req, Some(AiLimitPolicy::REST))
        .await
    {
        Ok(v) => v,
        Err(err) => return respond::<()>(Err(err)),
    };
    Json(response).into_response()
}

/// `/api/sessions/abuse` deserializes directly into [`AbuseSearchRequest`] via
/// `serde_qs::axum::QsQuery`, which handles `Vec<String>` from repeated
/// `?terms=a&terms=b` (and `?terms[]=a&terms[]=b`) query params — something
/// the default `serde_urlencoded` backing of `axum::extract::Query` cannot do
/// (bead 0p8r.15: closes the wire-shape duplication seam).
async fn ai_abuse(
    State(state): State<ApiState>,
    serde_qs::axum::QsQuery(req): serde_qs::axum::QsQuery<AbuseSearchRequest>,
) -> impl IntoResponse {
    let response = match state
        .service
        .search_abuse_with_limit_policy(req, Some(AiLimitPolicy::REST))
        .await
    {
        Ok(v) => v,
        Err(err) => return respond::<()>(Err(err)),
    };
    Json(response).into_response()
}

async fn ai_correlate(
    State(state): State<ApiState>,
    Query(req): Query<AiCorrelateRequest>,
) -> impl IntoResponse {
    let response = match state
        .service
        .correlate_ai_logs_with_limit_policy(req, AiCorrelateLimitPolicy::REST)
        .await
    {
        Ok(v) => v,
        Err(err) => return respond::<()>(Err(err)),
    };
    Json(response).into_response()
}

async fn ai_blocks(
    State(state): State<ApiState>,
    Query(req): Query<UsageBlocksRequest>,
) -> impl IntoResponse {
    respond(state.service.usage_blocks(req).await)
}

async fn ai_context(
    State(state): State<ApiState>,
    Query(req): Query<ProjectContextRequest>,
) -> impl IntoResponse {
    // `project` is required by the service, but axum/serde happily accepts
    // empty strings. Eng-review #A7: reject empty up-front with a 400 so
    // callers don't get an empty-result 200 instead of a clear error.
    if req.project.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "project query parameter is required and must be non-empty"})),
        )
            .into_response();
    }
    respond(state.service.project_context(req).await)
}

async fn ai_tools(
    State(state): State<ApiState>,
    Query(req): Query<ListAiToolsRequest>,
) -> impl IntoResponse {
    respond(state.service.list_ai_tools(req).await)
}

async fn ai_projects(
    State(state): State<ApiState>,
    Query(req): Query<ListAiProjectsRequest>,
) -> impl IntoResponse {
    respond(state.service.list_ai_projects(req).await)
}

// ─── AI diagnostic + admin (bead 0p8r.3) ─────────────────────────────────────
//
// `list_ai_checkpoints`, `list_ai_parse_errors`, `prune_ai_checkpoints` keep
// their loose primitive signatures on `CortexService` (eng-review #S3 — the
// service refactor was cut). Handlers build the typed Request struct from
// query/body, then unpack into positional args.

/// `GET /api/sessions/checkpoints` — inventory of AI transcript checkpoints (read).
async fn ai_checkpoints(
    State(state): State<ApiState>,
    Query(req): Query<AiCheckpointsRequest>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .list_ai_checkpoints(req.errors_only, req.missing_only, req.limit)
            .await,
    )
}

/// `GET /api/sessions/errors` — recent transcript parse errors (read).
async fn ai_parse_errors(
    State(state): State<ApiState>,
    Query(req): Query<AiParseErrorsRequest>,
) -> impl IntoResponse {
    respond(state.service.list_ai_parse_errors(req.limit).await)
}

/// `POST /api/sessions/prune-checkpoints` — admin/destructive: delete checkpoints
/// from the AI transcript inventory.
///
/// Validation flow (eng-review C3 — defense against `POST {}` mass-delete):
/// 1. Deserialize the body as `serde_json::Value` first.
/// 2. If the `dry_run` key is absent → 400 `"dry_run is required and must be
///    specified explicitly"`. Do NOT default to `false`.
/// 3. Then deserialize the value into `AiPruneCheckpointsRequest`
///    (`deny_unknown_fields` catches typos).
///
/// Audit log (eng-review #A13 / security #35): fires `tracing::warn!` BEFORE
/// the service call so a crash mid-prune still leaves an audit row.
///
/// `caller_ip` is sourced from `ConnectInfo<SocketAddr>`. Production wires it
/// via `into_make_service_with_connect_info` (see `src/main.rs:565`); tests
/// drive the router through a `MockConnectInfo` layer because
/// `tower::ServiceExt::oneshot` does not populate `ConnectInfo` on its own.
async fn ai_prune_checkpoints(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }

    // Step 1+2: parse as Value, require `dry_run` key explicitly.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid JSON body: {err}")})),
            )
                .into_response();
        }
    };
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "request body must be a JSON object"})),
            )
                .into_response();
        }
    };
    if !obj.contains_key("dry_run") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "dry_run is required and must be specified explicitly"
            })),
        )
            .into_response();
    }

    // Step 3: typed deserialize — `deny_unknown_fields` rejects typos.
    let req: AiPruneCheckpointsRequest = match serde_json::from_value(value) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid request body: {err}")})),
            )
                .into_response();
        }
    };

    // Audit BEFORE the service call so a process crash mid-prune still
    // leaves a trace of who asked for what.
    tracing::warn!(
        caller_ip = %peer,
        action = "prune_ai_checkpoints",
        dry_run = req.dry_run,
        missing_only = req.missing_only,
        limit = ?req.limit,
        "admin: prune_ai_checkpoints invoked"
    );

    // Single-flight gate — prune competes with vacuum/checkpoint for the
    // SQLite writer lock, so it joins the same MAINTENANCE_PERMIT cohort to
    // give callers a uniform 409 contract during concurrent maintenance
    // (bead 0p8r.16). Without the gate, concurrent prune+vacuum surfaces as
    // SQLITE_BUSY/timeout to clients instead of a clean 409.
    let _permit = match Arc::clone(&state.maintenance_permit).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "db maintenance already in progress"})),
            )
                .into_response();
        }
    };

    respond(state.service.prune_ai_checkpoints_checked(req).await)
}

fn respond<T: serde::Serialize>(result: crate::app::ServiceResult<T>) -> axum::response::Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(crate::app::ServiceError::InvalidInput(msg)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Err(crate::app::ServiceError::Busy(msg)) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": msg}))).into_response()
        }
        Err(crate::app::ServiceError::NotFound(msg)) => {
            (StatusCode::NOT_FOUND, Json(json!({"error": msg}))).into_response()
        }
        // Logged, not silent. This 503 fired repeatedly during the
        // 2026-08-24 pool-contention incident and left no trace of its own:
        // the only evidence was a caller-side 503 with no matching server
        // line, so the exhaustion had to be inferred from unrelated `db op
        // err` warnings. `pool_source` carries the chain the variant now
        // preserves, which is where a connection-establishment failure (a
        // permanent fault wearing a timeout's clothes) shows up.
        Err(err @ crate::app::ServiceError::DatabaseTimeout { .. }) => {
            tracing::error!(
                error = %err,
                pool_source = ?std::error::Error::source(&err),
                "API request failed: connection pool did not yield a connection"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "database_timeout"})),
            )
                .into_response()
        }
        Err(crate::app::ServiceError::ConstraintViolation { message }) => {
            tracing::warn!(error = %message, "Constraint violation in API request");
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "constraint_violation", "detail": message})),
            )
                .into_response()
        }
        Err(crate::app::ServiceError::RowNotFound) => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response()
        }
        Err(crate::app::ServiceError::Internal(err)) => {
            tracing::error!(error = %err, "API request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
    }
}

fn cors_layer(port: u16, loopback_bind: bool, allowed_origins: &[String]) -> CorsLayer {
    // Default loopback origins are only useful when the API actually listens
    // on a loopback address — otherwise they grant CORS access from the
    // operator's *workstation* (where `localhost:port` points at unrelated
    // services) to a remote API (bead 0p8r.21). On external binds,
    // `CORTEX_ALLOWED_ORIGINS` is the only authority.
    let mut origins: Vec<HeaderValue> = if loopback_bind {
        vec![
            format!("http://localhost:{port}")
                .parse::<HeaderValue>()
                .expect("valid localhost origin"),
            format!("http://127.0.0.1:{port}")
                .parse::<HeaderValue>()
                .expect("valid 127.0.0.1 origin"),
            // IPv6 loopback — when the listener binds [::1] or :: the
            // browser sends an Origin like http://[::1]:port and would
            // otherwise be blocked by CORS.
            format!("http://[::1]:{port}")
                .parse::<HeaderValue>()
                .expect("valid ::1 origin"),
        ]
    } else {
        Vec::new()
    };
    for origin in allowed_origins {
        match origin.parse::<HeaderValue>() {
            Ok(value) => origins.push(value),
            Err(error) => {
                tracing::warn!(
                    origin = %origin,
                    error = %error,
                    "Ignoring invalid CORS origin from CORTEX_ALLOWED_ORIGINS"
                );
            }
        }
    }
    // GET for reads, POST for mutating endpoints (added with bead 0p8r.3 —
    // first POST route is /api/sessions/prune-checkpoints), OPTIONS so browser
    // preflights for the POST endpoint succeed.
    //
    // `allow_headers` is an explicit allowlist (bead 0p8r.14): bearer auth
    // still defends every request, but pinning the preflight surface to the
    // headers the API actually reads keeps a compromised allowed-origin page
    // from echoing arbitrary headers (cookies from other origins, custom auth
    // tokens) through the browser into POST /api/sessions/prune-checkpoints,
    // /api/db/vacuum, /api/db/checkpoint.
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::HeaderName::from_static("x-cortex-admin-token"),
        ])
}

// ─── DB ops (bead 0p8r.4) ────────────────────────────────────────────────────
//
// Maintenance routes use the dual-permit pattern described on
// `MAINTENANCE_PERMIT` above: vacuum/checkpoint hold MAINTENANCE_PERMIT for the
// duration of the awaited service call, while reads continue to acquire from
// `CortexService::db_permits` independently. `db_status` and `db_integrity` are
// read-side and bypass MAINTENANCE_PERMIT entirely.

/// `GET /api/db/status` — cached PRAGMA snapshot (read).
async fn db_status(State(state): State<ApiState>) -> impl IntoResponse {
    respond(state.service.db_status().await)
}

/// `GET /api/db/integrity` — full or `?quick=true` integrity check (read).
async fn db_integrity(
    State(state): State<ApiState>,
    Query(req): Query<DbIntegrityRequest>,
) -> impl IntoResponse {
    respond(state.service.db_integrity(req.quick).await)
}

/// `POST /api/db/integrity/background` — start a non-blocking integrity check.
///
/// The full check is ~147s on a multi-GB DB (it reads every page — unfixable),
/// so this records a `running` job, spawns the check server-side, and returns
/// the job id immediately. Poll `GET /api/db/integrity/jobs/{id}` for the
/// outcome. Reuses the `quick` query param of the sync endpoint.
async fn db_integrity_background(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(req): Query<DbIntegrityRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }
    respond(state.service.db_integrity_start_background(req.quick).await)
}

/// `GET /api/db/integrity/jobs/{id}` — poll a background integrity job.
async fn db_integrity_job(State(state): State<ApiState>, Path(id): Path<i64>) -> impl IntoResponse {
    respond(state.service.db_integrity_job_status(id).await)
}

/// `POST /api/db/checkpoint` — admin: `PRAGMA wal_checkpoint(<mode>)`.
///
/// Uses MAINTENANCE_PERMIT (dual-permit pattern — see `MAINTENANCE_PERMIT`
/// docs). On contention returns 409 immediately rather than queuing.
async fn db_checkpoint(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }

    let req: DbCheckpointRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid request body: {err}")})),
            )
                .into_response();
        }
    };

    // Audit BEFORE mode validation (bead 0p8r.22) so rejected 400s are also
    // recorded; otherwise an attacker can probe `mode=evil` indefinitely
    // without leaving a trace. Audit BEFORE the service call so a process
    // crash mid-checkpoint also leaves a row of who asked for what.
    let mode_lower = req.mode.to_ascii_lowercase();
    tracing::warn!(
        caller_ip = %peer,
        action = "db_checkpoint",
        mode = %mode_lower,
        "admin: db_checkpoint invoked"
    );

    // Single-flight gate — separate from the read-worker pool (eng-review C2).
    // See `maintenance_permit` field docs on ApiState.
    let _permit = match Arc::clone(&state.maintenance_permit).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "db maintenance already in progress"})),
            )
                .into_response();
        }
    };

    respond(state.service.db_checkpoint_checked(req).await)
}

/// `POST /api/db/vacuum` — admin: full or incremental VACUUM.
///
/// Flow:
/// 1. Deserialize the body. `force` is `Option<bool>` so the size pre-flight
///    only relaxes when the body explicitly carries `"force": true`.
/// 2. Audit log (`tracing::warn!`) BEFORE any other work.
/// 3. Acquire MAINTENANCE_PERMIT (single-flight, dual-permit pattern —
///    see `MAINTENANCE_PERMIT` docs). On contention return 409.
/// 4. Size pre-flight when `full == true && force != Some(true)`: read
///    a FRESH `page_count * page_size` via the service (bead 0p8r.17 —
///    cached snapshots cannot defend a gate after weeks of ingest growth)
///    and 409 if `> full_vacuum_size_guard_bytes`.
/// 5. Call the service.
async fn db_vacuum(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }

    let req: DbVacuumRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid request body: {err}")})),
            )
                .into_response();
        }
    };

    // Audit BEFORE service call so a process crash mid-vacuum leaves a trace.
    tracing::warn!(
        caller_ip = %peer,
        action = "db_vacuum",
        full = req.full,
        force = ?req.force,
        incremental_pages = req.incremental_pages,
        "admin: db_vacuum invoked"
    );

    // Single-flight gate FIRST so two concurrent callers can't both pass the
    // size pre-flight and then both queue inside run_db. Acquired from
    // `state.maintenance_permit` (NOT the read-worker pool — eng-review C2).
    let _permit = match Arc::clone(&state.maintenance_permit).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "db maintenance already in progress"})),
            )
                .into_response();
        }
    };

    match state
        .service
        .db_vacuum_checked(req, state.full_vacuum_size_guard_bytes)
        .await
    {
        Err(ServiceError::Busy(msg)) if msg.contains("full VACUUM would block ingest") => {
            (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response()
        }
        other => respond(other),
    }
}

/// `POST /api/db/backup` — admin: online backup via rusqlite backup API.
///
/// The backup runs inside the server process using the pool connection, so it
/// cooperates with WAL writers and never hits SQLITE_BUSY. The caller supplies
/// an **optional server-side** `output_path`; the server resolves it to a path
/// it can write (e.g. `/data/backups/...` via the Docker bind-mount).
///
/// Uses MAINTENANCE_PERMIT (single-flight, dual-permit pattern — see
/// `MAINTENANCE_PERMIT` docs). On contention returns 409 immediately.
async fn db_backup(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Some(resp) = require_api_admin_token(&state, &headers) {
        return resp;
    }

    let req: DbBackupRequest = if body.is_empty() {
        DbBackupRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid request body: {err}")})),
                )
                    .into_response();
            }
        }
    };

    // Sanitize before logging (bead xknb.4): `output_path` is attacker-influenced
    // input; strip CR/LF/ESC so it can't inject newlines or ANSI escapes into log
    // aggregators or terminals tailing the audit stream.
    let logged_output_path = req
        .output_path
        .as_deref()
        .map(|p| p.replace(['\n', '\r', '\x1b'], "?"));
    tracing::warn!(
        caller_ip = %peer,
        action = "db_backup",
        output_path = ?logged_output_path,
        "admin: db_backup invoked"
    );

    let _permit = match Arc::clone(&state.maintenance_permit).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "db maintenance already in progress"})),
            )
                .into_response();
        }
    };

    let output = req.output_path.map(std::path::PathBuf::from);
    respond(state.service.db_backup(output).await)
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
