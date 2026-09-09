//! Authenticated ingest for configured file tails forwarded by fleet agents.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
};
use bytes::Bytes;
use lab_auth::middleware::{parse_bearer_token, tokens_equal};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;

use crate::db::{self, DbPool, LogBatchEntry};
use crate::enrich::{SourceKind, stamp_source_kind};
use crate::mcp::AuthPolicy;

pub const BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RECORDS_PER_BATCH: usize = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFileTailRecord {
    pub hostname: String,
    pub source_id: String,
    pub tag: String,
    pub path_basename: String,
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFileTailIngestRequest {
    pub records: Vec<AgentFileTailRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentFileTailIngestResponse {
    pub accepted: usize,
}

#[derive(Clone)]
pub struct AgentFileTailIngestState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    auth_policy: AuthPolicy,
}

impl AgentFileTailIngestState {
    pub fn new(pool: Arc<DbPool>, api_token: Option<String>, auth_policy: AuthPolicy) -> Self {
        Self {
            pool,
            api_token,
            auth_policy,
        }
    }
}

pub fn router(state: AgentFileTailIngestState) -> Router {
    Router::new()
        .route("/v1/file-tails", post(ingest_handler))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        .with_state(state)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn to_log_batch_entry(record: AgentFileTailRecord) -> Result<LogBatchEntry, &'static str> {
    if !valid_identity(&record.hostname)
        || !valid_identity(&record.source_id)
        || record.tag.trim().is_empty()
        || record.tag.len() > 255
        || record.path_basename.trim().is_empty()
        || record.path_basename.len() > 255
    {
        return Err("invalid file-tail identity");
    }
    let metadata_json = crate::ingest_metadata::bounded_metadata_json(json!({
        "source_type": "agent_file_tail",
        "source_kind": SourceKind::AgentFileTail.as_str(),
        "file_tail_id": record.source_id,
        "tag": record.tag,
        "path_basename": record.path_basename,
    }));
    let mut entry = LogBatchEntry {
        timestamp: record.timestamp,
        hostname: record.hostname.clone(),
        facility: Some("local0".to_string()),
        severity: "info".to_string(),
        app_name: Some(record.tag),
        process_id: None,
        message: record.message.clone(),
        raw: record.message,
        source_ip: format!("agent-file-tail://{}/{}", record.hostname, record.source_id),
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::AgentFileTail);
    Ok(entry)
}

async fn ingest_handler(
    State(state): State<AgentFileTailIngestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_authorized(&state, &peer, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let request: AgentFileTailIngestRequest = match serde_json::from_slice(&body) {
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
            Json(json!({"error": "batch_too_large"})),
        )
            .into_response();
    }
    let entries: Vec<_> = match request
        .records
        .into_iter()
        .map(to_log_batch_entry)
        .collect()
    {
        Ok(entries) => entries,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_payload", "message": message})),
            )
                .into_response();
        }
    };
    let pool = Arc::clone(&state.pool);
    match tokio::task::spawn_blocking(move || db::insert_logs_batch(&pool, &entries)).await {
        Ok(Ok(accepted)) => (
            StatusCode::OK,
            Json(AgentFileTailIngestResponse { accepted }),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "agent file-tail ingest failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "agent file-tail ingest task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ingest_task_failed"})),
            )
                .into_response()
        }
    }
}

fn is_authorized(state: &AgentFileTailIngestState, peer: &SocketAddr, headers: &HeaderMap) -> bool {
    if matches!(state.auth_policy, AuthPolicy::LoopbackDev) {
        return peer.ip().is_loopback();
    }
    let (Some(expected), Some(auth)) = (
        state.api_token.as_deref(),
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
    ) else {
        return false;
    };
    parse_bearer_token(auth).is_some_and(|token| tokens_equal(&token, expected))
}

#[cfg(test)]
#[path = "agent_file_tail_ingest_tests.rs"]
mod tests;
