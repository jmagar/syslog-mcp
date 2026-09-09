//! Receipt-backed syslog forwarding endpoint.
//!
//! The TCP syslog listener intentionally remains standards-compatible and
//! best-effort.  Agents that need replay send the same RFC5424 frame through
//! this authenticated endpoint, with a source-local sequence and stable
//! idempotency key.  The receiver commits the canonical log row and receipt in
//! one SQLite transaction, so a lost HTTP response is safe to retry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

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

use crate::db::DbPool;
use crate::mcp::AuthPolicy;
use crate::surfaces::post;

pub const SYSLOG_FORWARD_BODY_LIMIT_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS_PER_BATCH: usize = 200;
pub const MAX_GAPS_PER_BATCH: usize = 50;

/// Server-derived authentication identity. Keeping the credential class in
/// the type prevents a user-controlled principal label from becoming an
/// internal system identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ForwardingPrincipal {
    Loopback,
    SharedBearer,
    Named(String),
}

impl ForwardingPrincipal {
    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Loopback => "loopback",
            Self::SharedBearer => "shared_bearer",
            Self::Named(label) => label,
        }
    }

    pub(crate) fn receipt_namespace(&self) -> String {
        match self {
            // Preserve the legacy namespaces for system credentials so
            // receipts written before named principals existed still replay.
            Self::Loopback => "loopback".to_owned(),
            Self::SharedBearer => "shared_bearer".to_owned(),
            Self::Named(label) => format!("named:{}:{label}", label.len()),
        }
    }

    pub(crate) fn is_shared(&self) -> bool {
        matches!(self, Self::SharedBearer)
    }
}

#[derive(Debug)]
struct IdempotencyConflict;

impl std::fmt::Display for IdempotencyConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("idempotency_conflict")
    }
}

impl std::error::Error for IdempotencyConflict {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyslogForwardRecord {
    pub source_instance: String,
    pub source_epoch: u64,
    pub sequence: u64,
    pub idempotency_key: String,
    pub observed_at: String,
    /// An RFC5424 frame. Never include this in diagnostics or status output.
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyslogForwardGap {
    pub source_instance: String,
    pub source_epoch: u64,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub idempotency_key: String,
    pub observed_at: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SyslogForwardRequest {
    #[serde(default)]
    pub records: Vec<SyslogForwardRecord>,
    #[serde(default)]
    pub gaps: Vec<SyslogForwardGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SyslogForwardResponse {
    pub receipts: Vec<String>,
}

#[derive(Clone)]
pub struct SyslogForwardIngestState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    forwarding_agent_tokens: Arc<HashMap<String, String>>,
    auth_policy: AuthPolicy,
}

impl SyslogForwardIngestState {
    pub fn new(
        pool: Arc<DbPool>,
        api_token: Option<String>,
        forwarding_agent_tokens: HashMap<String, String>,
        auth_policy: AuthPolicy,
    ) -> Self {
        Self {
            pool,
            api_token,
            forwarding_agent_tokens: Arc::new(forwarding_agent_tokens),
            auth_policy,
        }
    }
}

pub fn router(state: SyslogForwardIngestState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("POST /v1/syslog-forward", post(ingest_handler))
        .layer(RequestBodyLimitLayer::new(SYSLOG_FORWARD_BODY_LIMIT_BYTES))
        .with_state(state)
}

async fn ingest_handler(
    State(state): State<SyslogForwardIngestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(forwarder_identity) = authenticated_forwarder(&state, &peer, &headers) else {
        return unauthorized();
    };
    let request: SyslogForwardRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_payload"})),
            )
                .into_response();
        }
    };
    if request.records.len() > MAX_RECORDS_PER_BATCH || request.gaps.len() > MAX_GAPS_PER_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "batch_too_large"})),
        )
            .into_response();
    }
    if request.records.iter().any(invalid_record) || request.gaps.iter().any(invalid_gap) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_record"})),
        )
            .into_response();
    }
    let pool = Arc::clone(&state.pool);
    let peer_ip = peer.ip().to_string();
    let record_count = request.records.len();
    let gap_count = request.gaps.len();
    let diagnostic_identity = forwarder_identity.label().to_owned();
    match tokio::task::spawn_blocking(move || {
        persist_authenticated_request(&pool, request, &peer_ip, &forwarder_identity)
    })
    .await
    {
        Ok(Ok(receipts)) => {
            (StatusCode::OK, Json(SyslogForwardResponse { receipts })).into_response()
        }
        Ok(Err(error)) if error.downcast_ref::<IdempotencyConflict>().is_some() => (
            StatusCode::CONFLICT,
            Json(json!({"error": "idempotency_conflict"})),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::error!(
                reason_code = "syslog_forward_ingest_failed",
                error = %error,
                forwarder = %diagnostic_identity,
                peer = %peer,
                record_count,
                gap_count,
                "syslog forwarding ingest failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
        Err(join_error) => {
            tracing::error!(
                reason_code = "syslog_forward_ingest_task_failed",
                error = %join_error,
                forwarder = %diagnostic_identity,
                peer = %peer,
                record_count,
                gap_count,
                "syslog forwarding ingest task failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ingest_task_failed"})),
            )
                .into_response()
        }
    }
}

fn invalid_record(record: &SyslogForwardRecord) -> bool {
    record.source_instance.is_empty()
        || record.source_instance.len() > 128
        || record.idempotency_key.is_empty()
        || record.idempotency_key.len() > 256
        || record.source_epoch > i64::MAX as u64
        || record.sequence > i64::MAX as u64
        || !valid_observed_at(&record.observed_at)
        || record.line.is_empty()
        || record.line.len() > 64 * 1024
}

fn invalid_gap(gap: &SyslogForwardGap) -> bool {
    gap.source_instance.is_empty()
        || gap.source_instance.len() > 128
        || gap.idempotency_key.is_empty()
        || gap.idempotency_key.len() > 256
        || gap.source_epoch > i64::MAX as u64
        || gap.to_sequence > i64::MAX as u64
        || !valid_observed_at(&gap.observed_at)
        || !matches!(
            gap.reason_code.as_str(),
            "local_retention_quota" | "aggregate_retention_quota" | "record_too_large"
        )
        || gap.from_sequence > gap.to_sequence
}

fn valid_observed_at(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

#[path = "syslog_forward_ingest/persistence.rs"]
mod persistence;
use persistence::persist_authenticated_request;
#[cfg(test)]
use persistence::{forwarded_metadata, persist_request};

fn authenticated_forwarder(
    state: &SyslogForwardIngestState,
    peer: &SocketAddr,
    headers: &HeaderMap,
) -> Option<ForwardingPrincipal> {
    if matches!(state.auth_policy, AuthPolicy::LoopbackDev) {
        return peer
            .ip()
            .is_loopback()
            .then_some(ForwardingPrincipal::Loopback);
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer_token)?;
    if let Some(identity) = state
        .forwarding_agent_tokens
        .iter()
        .find_map(|(expected, identity)| tokens_equal(&token, expected).then(|| identity.clone()))
    {
        return Some(ForwardingPrincipal::Named(identity));
    }
    state
        .api_token
        .as_deref()
        .filter(|expected| tokens_equal(&token, expected))
        .map(|_| ForwardingPrincipal::SharedBearer)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

#[cfg(test)]
#[path = "syslog_forward_ingest_tests.rs"]
mod tests;
