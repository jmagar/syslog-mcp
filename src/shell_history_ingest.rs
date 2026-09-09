//! Remote shell-history ingest (`POST /v1/shell-history`) — receives a batch
//! of pre-parsed zsh/bash extended-history or atuin records forwarded by a
//! satellite host's `cortex agent` (see `agent::shell_history`) and inserts
//! them into this server's own log store via `db::insert_logs_batch`, the
//! same path `cortex ingest shell user index`/`atuinindex` use locally.
//!
//! Local `cortex ingest shell user index`/`atuinindex` have no forward
//! mode at all — this endpoint exists so a host's own interactive command
//! history reaches wherever the shared cortex server actually lives, the
//! same way syslog/Docker/heartbeat/AI-transcript/agent-command data does.
//!
//! Mounted on the shared HTTP listener (port 3100) next to MCP, OTLP,
//! heartbeats, agent-commands, and AI-transcripts. Auth mirrors those:
//! static `CORTEX_TOKEN` bearer when configured, loopback-only otherwise.

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
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;

use crate::db::{self, DbPool, LogBatchEntry};
use crate::mcp::AuthPolicy;

pub const SHELL_HISTORY_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Caps record *count* per request, matching the reasoning used by the
/// agent-command and AI-transcript ingest endpoints.
pub const MAX_RECORDS_PER_BATCH: usize = 2_000;

/// One shell-history entry, forwarded by an agent's shell-history watcher.
/// Already scrubbed of common credential patterns agent-side (see
/// `command_log::scrub_command`) before it ever reaches the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellHistoryRecord {
    /// `"zsh"`, `"bash"`, or `"atuin"`.
    pub source: String,
    pub hostname: String,
    /// RFC3339 timestamp the command started.
    pub timestamp: String,
    pub duration_ms: Option<u64>,
    /// Already-scrubbed command text.
    pub command: String,
    pub cwd: Option<String>,
    pub exit_status: Option<i32>,
    /// Atuin session id, when the source is atuin.
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellHistoryIngestRequest {
    pub records: Vec<ShellHistoryRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellHistoryIngestResponse {
    pub accepted: usize,
}

#[derive(Clone)]
pub struct ShellHistoryIngestState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    auth_policy: AuthPolicy,
}

impl ShellHistoryIngestState {
    pub fn new(pool: Arc<DbPool>, api_token: Option<String>, auth_policy: AuthPolicy) -> Self {
        Self {
            pool,
            api_token,
            auth_policy,
        }
    }
}

pub fn router(state: ShellHistoryIngestState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("POST /v1/shell-history", post(ingest_handler))
        .layer(RequestBodyLimitLayer::new(SHELL_HISTORY_BODY_LIMIT_BYTES))
        .with_state(state)
}

fn to_log_batch_entry(record: ShellHistoryRecord) -> LogBatchEntry {
    let source_ip = format!("agent-shell-history://{}", record.hostname);
    let severity = match record.exit_status {
        Some(0) => "info",
        Some(_) => "warning",
        None => "info",
    };
    let metadata_json = crate::ingest_metadata::bounded_metadata_json(serde_json::json!({
        "source_type": "shell_history",
        "shell": record.source,
        "cwd": record.cwd,
        "exit_status": record.exit_status,
        "duration_ms": record.duration_ms,
        "content_scrubbed": true,
    }));
    LogBatchEntry {
        timestamp: record.timestamp,
        hostname: record.hostname,
        facility: Some("shell".to_string()),
        severity: severity.to_string(),
        app_name: Some(record.source),
        process_id: None,
        message: record.command.clone(),
        raw: record.command,
        source_ip,
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: record.session_id,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

async fn ingest_handler(
    State(state): State<ShellHistoryIngestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_authorized(&state, &peer, &headers) {
        return unauthorized();
    }

    let request: ShellHistoryIngestRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_payload", "message": error.to_string()})),
            )
                .into_response();
        }
    };

    if request.records.len() > MAX_RECORDS_PER_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "batch_too_large",
                "message": format!(
                    "batch has {} records, exceeds the {MAX_RECORDS_PER_BATCH}-record limit per request",
                    request.records.len()
                ),
            })),
        )
            .into_response();
    }

    let pool = Arc::clone(&state.pool);
    let entries: Vec<LogBatchEntry> = request
        .records
        .into_iter()
        .map(to_log_batch_entry)
        .collect();
    let join_result =
        tokio::task::spawn_blocking(move || db::insert_logs_batch(&pool, &entries)).await;

    match join_result {
        Ok(Ok(accepted)) => (
            StatusCode::OK,
            Json(ShellHistoryIngestResponse { accepted }),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "shell history forward ingest failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
        Err(join_error) => {
            tracing::error!(error = %join_error, "shell history ingest task panicked or was cancelled");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ingest_task_failed", "message": join_error.to_string()})),
            )
                .into_response()
        }
    }
}

fn is_authorized(state: &ShellHistoryIngestState, peer: &SocketAddr, headers: &HeaderMap) -> bool {
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
#[path = "shell_history_ingest_tests.rs"]
mod tests;
