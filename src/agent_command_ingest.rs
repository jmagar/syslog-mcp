//! Remote agent-command ingest (`POST /v1/agent-commands`) — receives a
//! batch of `AgentCommandSpoolRecord`s forwarded from a satellite host's
//! local spool (see `command_log::forward_agent_command_spool`) and inserts
//! them into this server's own log store, deduping the same way local
//! `cortex ingest shell agent index` does via
//! `command_log::import_agent_command_records`.
//!
//! Mounted on the shared HTTP listener (port 3100) next to MCP, OTLP, and
//! heartbeats. Auth mirrors heartbeats (`src/heartbeat.rs`): static
//! `CORTEX_TOKEN` bearer when configured, loopback-only otherwise.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::surfaces::post;
use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use lab_auth::middleware::{parse_bearer_token, tokens_equal};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;

use crate::command_log::{self, AgentCommandSpoolRecord};
use crate::db::DbPool;
use crate::mcp::AuthPolicy;

pub const AGENT_COMMAND_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Caps record *count*, independent of the byte-size limit above. A dense
/// batch of small `AgentCommandSpoolRecord`s (each roughly 150-400 bytes of
/// JSON) could still pack several thousand records into 1 MiB, and each
/// record triggers one synchronous dedupe query in
/// `command_log::import_agent_command_records` — engineering review flagged
/// this as the actual scaling risk, not the byte cap. 5,000 records is a
/// generous multiple of what a single drain cycle of one host's local spool
/// should ever accumulate between runs.
pub const MAX_RECORDS_PER_BATCH: usize = 5_000;

#[derive(Clone)]
pub struct AgentCommandIngestState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    auth_policy: AuthPolicy,
}

impl AgentCommandIngestState {
    pub fn new(pool: Arc<DbPool>, api_token: Option<String>, auth_policy: AuthPolicy) -> Self {
        Self {
            pool,
            api_token,
            auth_policy,
        }
    }
}

pub fn router(state: AgentCommandIngestState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("POST /v1/agent-commands", post(ingest_handler))
        .layer(RequestBodyLimitLayer::new(AGENT_COMMAND_BODY_LIMIT_BYTES))
        .with_state(state)
}

async fn ingest_handler(
    State(state): State<AgentCommandIngestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_authorized(&state, &peer, &headers) {
        return unauthorized();
    }

    let records: Vec<AgentCommandSpoolRecord> = match serde_json::from_slice(&body) {
        Ok(records) => records,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_payload", "message": error.to_string()})),
            )
                .into_response();
        }
    };

    if records.len() > MAX_RECORDS_PER_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "batch_too_large",
                "message": format!(
                    "batch has {} records, exceeds the {MAX_RECORDS_PER_BATCH}-record limit per request",
                    records.len()
                ),
            })),
        )
            .into_response();
    }

    let pool = Arc::clone(&state.pool);
    let peer_ip = peer.ip().to_string();
    let join_result = tokio::task::spawn_blocking(move || {
        command_log::import_agent_command_records(&pool, &records, Some(&peer_ip))
    })
    .await;

    match join_result {
        Ok(Ok(result)) => (StatusCode::OK, Json(result)).into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "agent command forward ingest failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
        Err(join_error) => {
            // Distinguish "the blocking task panicked/was cancelled" from an
            // ordinary DB error — engineering review flagged the prior
            // version collapsing both into the same generic `internal_error`
            // with no way for a forwarding client to tell them apart.
            tracing::error!(error = %join_error, "agent command ingest task panicked or was cancelled");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ingest_task_failed", "message": join_error.to_string()})),
            )
                .into_response()
        }
    }
}

fn is_authorized(state: &AgentCommandIngestState, peer: &SocketAddr, headers: &HeaderMap) -> bool {
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

#[cfg(test)]
#[path = "agent_command_ingest_tests.rs"]
mod tests;
