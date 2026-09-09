//! OTLP/HTTP receiver for OpenTelemetry logs, traces, and metrics. Logs feed the
//! existing Cortex ingest pipeline; traces and metrics normalize into the Agent
//! Observatory stores.
//!
//! Mounted on the same axum server as MCP. Logs retain a 4 MiB body limit;
//! traces and metrics use 8 MiB. Bearer auth uses the same
//! static MCP token as `/mcp` — `config.mcp.api_token`, set via
//! `CORTEX_TOKEN`. It is NOT `CORTEX_API_TOKEN` (that is `config.api.api_token`,
//! the separate REST `/api/*` token) and NOT `CORTEX_API_ADMIN_TOKEN`.
//! Loopback / trusted-gateway policies skip the check; OAuth-only deployments
//! with no static token deny OTLP outright (no OAuth flow for exporters).
//!
//! Log request wiring lives here; trace HTTP handling is in [`trace_http`],
//! `AnyValue`/`LogBatchEntry` conversion is in [`entries`], and the bearer-token
//! gate is in [`auth`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::mcp::AuthPolicy;
use crate::surfaces::post;
use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER},
    middleware::{Next, from_fn},
    response::IntoResponse,
};
use bytes::Bytes;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use parking_lot::Mutex;
use prost::Message;

use crate::config::AgentObservatoryPrivacyConfig;
use crate::db::{DbPool, StorageBudgetState};
use crate::ingest::IngestTx;

mod auth;
mod entries;
mod error;
mod metric_http;
mod metrics;
mod metrics_payload;
mod normalization;
mod privacy;
mod trace_http;
mod traces;

#[cfg(test)]
#[path = "otlp/provider_fixtures_tests.rs"]
mod provider_fixtures_tests;

use auth::{
    is_authorized, otlp_auth_policy_label, should_warn_unauthorized, unauthorized,
    unauthorized_diagnostics,
};
use entries::build_entries;
use error::OtlpError;
#[cfg(test)]
use metric_http::MAX_METRIC_POINTS_PER_REQUEST;
use metric_http::{MetricIngestState, metrics_handler};
#[cfg(test)]
use trace_http::MAX_SPANS_PER_REQUEST;
use trace_http::{TraceIngestState, traces_handler};

/// Existing `/v1/logs` body cap. Larger payloads receive 413 + `Retry-After: 86400`.
pub const OTLP_BODY_LIMIT_BYTES: usize = 4 * 1024 * 1024;
/// Agent Observatory trace and metric body cap.
pub const OTLP_SIGNAL_BODY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// Atomic counters for the OTLP receiver, surfaced via `/health`.
#[derive(Debug, Default)]
pub struct OtlpCounters {
    pub logs_received: AtomicU64,
    pub decode_errors: AtomicU64,
    pub metrics_accepted: AtomicU64,
    pub metrics_duplicates: AtomicU64,
    pub metrics_rejected: AtomicU64,
    pub metrics_backpressure: AtomicU64,
    pub metrics_auth_failures: AtomicU64,
    pub metrics_decode_errors: AtomicU64,
    pub metrics_persistence_errors: AtomicU64,
}

/// Shared state for every OTLP route.
#[derive(Clone)]
pub struct OtlpState {
    pub(crate) ingest: IngestTx,
    pub api_token: Option<String>,
    pub counters: Arc<OtlpCounters>,
    pub auth_policy: AuthPolicy,
    metric_ingest: Option<MetricIngestState>,
    trace_ingest: Option<TraceIngestState>,
}

impl OtlpState {
    pub(crate) fn new(
        ingest: IngestTx,
        api_token: Option<String>,
        counters: Arc<OtlpCounters>,
        auth_policy: AuthPolicy,
    ) -> Self {
        Self {
            ingest,
            api_token,
            counters,
            auth_policy,
            metric_ingest: None,
            trace_ingest: None,
        }
    }

    pub(crate) fn with_trace_ingest(
        mut self,
        pool: Arc<DbPool>,
        storage_state: Arc<Mutex<Option<StorageBudgetState>>>,
        privacy: AgentObservatoryPrivacyConfig,
    ) -> Self {
        self.metric_ingest = Some(MetricIngestState::new(
            Arc::clone(&pool),
            Arc::clone(&storage_state),
            privacy.clone(),
        ));
        self.trace_ingest = Some(TraceIngestState::new(pool, storage_state, privacy));
        self
    }
}

/// Build the OTLP router. Logs retain their existing 4 MiB body cap while
/// traces and metrics use the Agent Observatory 8 MiB cap.
pub fn router(state: OtlpState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route(
            "POST /v1/logs",
            post(logs_handler).request_body_limit(OTLP_BODY_LIMIT_BYTES),
        )
        .contract_route(
            "POST /v1/metrics",
            post(metrics_handler).request_body_limit(OTLP_SIGNAL_BODY_LIMIT_BYTES),
        )
        .contract_route(
            "POST /v1/traces",
            post(traces_handler).request_body_limit(OTLP_SIGNAL_BODY_LIMIT_BYTES),
        )
        .layer(from_fn(add_retry_after_on_413))
        .with_state(state)
}

/// Tower middleware: attach `Retry-After: 86400` to any 413 response so OTLP
/// exporters back off instead of hammering the endpoint on retry.
async fn add_retry_after_on_413(
    req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("86400"));
    }
    response
}

async fn logs_handler(
    State(state): State<OtlpState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !is_authorized(&state, &headers) {
        let diagnostics = unauthorized_diagnostics(&headers);
        if should_warn_unauthorized(&peer, &diagnostics) {
            tracing::warn!(
                source_ip = %peer,
                has_auth = diagnostics.has_auth,
                auth_scheme = %diagnostics.auth_scheme,
                bearer_sha256_12 = %diagnostics.bearer_sha256_12,
                user_agent = %diagnostics.user_agent,
                token_configured = state.api_token.is_some(),
                auth_policy = %otlp_auth_policy_label(&state.auth_policy),
                "OTLP /v1/logs unauthorized"
            );
        } else {
            tracing::debug!(
                source_ip = %peer,
                has_auth = diagnostics.has_auth,
                auth_scheme = %diagnostics.auth_scheme,
                bearer_sha256_12 = %diagnostics.bearer_sha256_12,
                user_agent = %diagnostics.user_agent,
                token_configured = state.api_token.is_some(),
                auth_policy = %otlp_auth_policy_label(&state.auth_policy),
                "OTLP /v1/logs unauthorized suppressed by rate limit"
            );
        }
        return unauthorized();
    }

    // prost decode is CPU-bound; isolate from the runtime via spawn_blocking.
    let body_for_decode = body.clone();
    let decoded =
        tokio::task::spawn_blocking(move || ExportLogsServiceRequest::decode(body_for_decode))
            .await;

    let req = match decoded {
        Ok(Ok(req)) => req,
        Ok(Err(err)) => {
            state.counters.decode_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %err, source_ip = %peer, "OTLP /v1/logs decode failed");
            return OtlpError::DecodeFailed.into_response_with_message(err.to_string());
        }
        Err(err) => {
            state.counters.decode_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %err, "OTLP decode task panicked");
            return OtlpError::Internal.into_response();
        }
    };

    let entries = build_entries(&req, peer);
    let count = entries.len();

    // Pre-flight capacity check: reject the WHOLE request with 503 if the
    // channel can't fit it. Without this, partial accept (entries 0..N
    // queued, N+1 hits Full, return 503) leads to OTel exporter retry of
    // the full batch — duplicating the rows already accepted. See review
    // threads PRRT_*ALWfA / *ALb_p / *ALYDZ.
    if state.ingest.capacity() < count {
        tracing::warn!(
            source_ip = %peer,
            requested = count,
            available = state.ingest.capacity(),
            "OTLP write channel insufficient capacity — returning 503 (no partial accept)"
        );
        return OtlpError::ChannelFull.into_response();
    }

    // Capacity reservation is best-effort (concurrent senders may consume
    // slots between check and send). On Full mid-loop we still 503, which
    // can in the worst case duplicate a few records on retry, but the
    // pre-flight makes the common case clean.
    for entry in entries {
        match state.ingest.try_send(entry) {
            Ok(()) => {}
            Err(crate::ingest::TrySendErr::Full) => {
                tracing::warn!(
                    source_ip = %peer,
                    "OTLP write channel filled mid-batch — returning 503"
                );
                return OtlpError::ChannelFull.into_response();
            }
            Err(crate::ingest::TrySendErr::Closed) => {
                tracing::error!(
                    source_ip = %peer,
                    "OTLP write channel CLOSED — batch writer task is dead"
                );
                return OtlpError::WriterUnavailable.into_response();
            }
        }
    }

    state
        .counters
        .logs_received
        .fetch_add(count as u64, Ordering::Relaxed);
    tracing::info!(records = count, source_ip = %peer, "OTLP logs ingested");
    StatusCode::OK.into_response()
}

#[cfg(test)]
#[path = "otlp_tests.rs"]
mod tests;
