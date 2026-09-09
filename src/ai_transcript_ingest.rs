//! Remote AI-transcript ingest (`POST /v1/ai-transcripts`) — receives a batch
//! of already-parsed AI transcript records forwarded by a satellite host's
//! `cortex agent` (see `agent::ai_transcript`) and inserts them into this
//! server's own log store via the same `db::insert_logs_batch` path used by
//! local `cortex sessions add`/`sessions watch`.
//!
//! This exists because AI transcript ingestion historically wrote directly to
//! a local SQLite file co-located with the server (`cortex::scanner` +
//! `cortex::ai_watch`), which only works when the watcher and the server run
//! on the same host. Once the server moves to a different host than the one
//! running Claude/Codex/Gemini/Antigravity, that local-write path silently
//! orphans all new transcript data. This endpoint gives every fleet host a way
//! to forward its transcripts to wherever the server actually lives, the same
//! way syslog/Docker/heartbeat data already does.
//!
//! Mounted on the shared HTTP listener (port 3100) next to MCP, OTLP,
//! heartbeats, and agent-commands. Auth mirrors heartbeats/agent-commands
//! (`src/heartbeat.rs`): static `CORTEX_TOKEN` bearer when configured,
//! loopback-only otherwise.

use std::collections::HashMap;
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
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;

use crate::db::{self, DbPool, LogBatchEntry};
use crate::mcp::AuthPolicy;
use crate::syslog_forward_ingest::ForwardingPrincipal;

pub const AI_TRANSCRIPT_BODY_LIMIT_BYTES: usize = 4 * 1024 * 1024;

/// Caps record *count* per request, independent of the byte-size limit above,
/// following the same reasoning as `agent_command_ingest::MAX_RECORDS_PER_BATCH`:
/// bounds per-request DB work regardless of how small individual records are.
pub const MAX_RECORDS_PER_BATCH: usize = 2_000;
pub const EVIDENCE_ENVELOPE_VERSION: u16 = 1;
const MAX_TEXT_CHARS: usize = 16 * 1024;
const MAX_TIMESTAMP_CHARS: usize = 128;
const MAX_IDENTIFIER_CHARS: usize = 512;
const MAX_DIAGNOSTICS: usize = 16;
const MAX_DIAGNOSTIC_CHARS: usize = 1_024;

/// The only provider capabilities a transcript forwarder may claim.  Values
/// are receipt-oriented: an adapter that cannot observe a lane must say so
/// explicitly instead of silently serializing an empty lane as healthy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    Observed,
    Partial,
    NotObserved,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCapabilityCoverage {
    pub transcript: EvidenceCoverage,
    pub mcp_events: EvidenceCoverage,
    pub skill_events: EvidenceCoverage,
    pub hook_events: EvidenceCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDiagnostic {
    /// A short, stable classifier such as `malformed_json` or
    /// `metadata_missing`. Never carries raw parser text.
    pub code: String,
    /// Scrubbed and bounded detail. It is operator-facing evidence, not an
    /// arbitrary error payload from an untrusted forwarder.
    pub detail: Option<String>,
}

/// Safe provenance for a transcript source. Both identities are SHA-256
/// digests created by the agent; raw local paths, sqlite locations, and home
/// directory names are intentionally absent from this protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub provider: String,
    pub adapter_version: String,
    pub source_identity: String,
    pub source_epoch: String,
    pub source_revision: String,
    pub locator: String,
    #[serde(default)]
    pub native_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub title_provenance: Option<String>,
}

/// Versioned, redacted data-plane record. A stable `source_record_id` is the
/// idempotency key for one source revision/event; it is the only identifier a
/// forwarder may use to advance a local cursor after a response is lost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub version: u16,
    pub source_record_id: String,
    pub source: EvidenceSource,
    pub timestamp: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub ai_project: Option<String>,
    #[serde(default)]
    pub ai_session_id: Option<String>,
    #[serde(default)]
    pub event_kind: Option<String>,
    pub message: String,
    pub capabilities: EvidenceCapabilityCoverage,
    #[serde(default)]
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

/// One versioned AI evidence envelope forwarded by an agent. The nesting is
/// intentional: adding evidence fields cannot accidentally look like a new
/// top-level transport option.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiTranscriptRecord {
    pub envelope: EvidenceEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiTranscriptIngestRequest {
    pub records: Vec<AiTranscriptRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTranscriptIngestResponse {
    pub accepted: usize,
    pub receipts: Vec<AiTranscriptReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiTranscriptReceipt {
    pub source_record_id: String,
    /// `accepted` means the canonical log and receipt committed in this
    /// request. `duplicate` means a previous committed receipt was returned
    /// exactly, which is also safe for the sender to checkpoint.
    pub disposition: ReceiptDisposition,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDisposition {
    Accepted,
    Duplicate,
}

#[derive(Clone)]
pub struct AiTranscriptIngestState {
    pool: Arc<DbPool>,
    api_token: Option<String>,
    forwarding_agent_tokens: Arc<HashMap<String, String>>,
    auth_policy: AuthPolicy,
}

impl AiTranscriptIngestState {
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

pub fn router(state: AiTranscriptIngestState) -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("POST /v1/ai-transcripts", post(ingest_handler))
        .layer(RequestBodyLimitLayer::new(AI_TRANSCRIPT_BODY_LIMIT_BYTES))
        .with_state(state)
}

fn to_log_batch_entry(
    envelope: EvidenceEnvelope,
    forwarder_identity: &str,
    peer: &SocketAddr,
) -> LogBatchEntry {
    let timestamp = envelope
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let source_ip = format!("agent-ai-transcript://{}", peer.ip());
    let metadata_json = crate::ingest_metadata::bounded_metadata_json(serde_json::json!({
        "source_type": "transcript",
        "evidence_envelope_version": envelope.version,
        "source_record_id": envelope.source_record_id,
        "source": envelope.source,
        "capabilities": envelope.capabilities,
        "diagnostics": envelope.diagnostics,
        "event_kind": envelope.event_kind.as_deref().unwrap_or("unknown"),
        "provenance": {
            "authenticated_forwarder": forwarder_identity,
            "transport_peer": peer.ip().to_string(),
            "hostname_claim": envelope.hostname,
            "trust": if forwarder_identity == "shared_bearer" { "claimed" } else { "verified_forwarder_claimed_host" },
        },
        "content_scrubbed": true,
    }));
    LogBatchEntry {
        timestamp,
        hostname: format!("agent-{forwarder_identity}"),
        facility: None,
        severity: "info".to_string(),
        app_name: Some(format!("{}-transcript", envelope.source.provider)),
        process_id: None,
        message: envelope.message,
        raw: String::new(),
        source_ip,
        docker_checkpoint: None,
        ai_tool: Some(envelope.source.provider),
        ai_project: envelope.ai_project,
        ai_session_id: envelope.ai_session_id,
        ai_transcript_path: Some(envelope.source.locator),
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

fn clamp_chars(value: &str, limit: usize) -> String {
    let mut out = String::with_capacity(value.len().min(limit));
    for (idx, ch) in value.chars().enumerate() {
        if idx == limit {
            out.push_str("...[truncated]");
            break;
        }
        out.push(ch);
    }
    out
}

fn scrub_text(value: &str, limit: usize) -> String {
    let scrubbed = crate::receiver::enrichment::scrub_ai_message(value, None);
    let scrubbed = crate::assessment::redact_secrets(&scrubbed);
    clamp_chars(&scrubbed, limit)
}

fn safe_identifier(value: &str) -> String {
    // Identifiers can be sent by a hostile authenticated peer. Do not accept
    // controls or an arbitrary unbounded value into a receipt primary key.
    let text: String = value.chars().filter(|ch| !ch.is_control()).collect();
    scrub_text(&text, MAX_IDENTIFIER_CHARS)
}

fn safe_session_label(value: &str) -> Option<String> {
    let scrubbed = scrub_text(value, MAX_IDENTIFIER_CHARS);
    let terminal_safe = scrubbed
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let terminal_safe = terminal_safe.trim();
    (!terminal_safe.is_empty()).then(|| terminal_safe.to_string())
}

fn is_sha256_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scrub_envelope(mut envelope: EvidenceEnvelope) -> Result<EvidenceEnvelope, &'static str> {
    if envelope.version != EVIDENCE_ENVELOPE_VERSION {
        return Err("unsupported_evidence_envelope_version");
    }
    if !is_sha256_id(&envelope.source_record_id)
        || !is_sha256_id(&envelope.source.source_identity)
        || !is_sha256_id(&envelope.source.source_epoch)
        || !is_sha256_id(&envelope.source.source_revision)
        || !is_sha256_id(&envelope.source.locator)
    {
        return Err("invalid_evidence_identity");
    }
    if envelope.source.provider.is_empty() || envelope.hostname.is_empty() {
        return Err("missing_evidence_identity");
    }

    envelope.hostname = safe_identifier(&envelope.hostname);
    envelope.source.provider = safe_identifier(&envelope.source.provider);
    envelope.source.adapter_version = safe_identifier(&envelope.source.adapter_version);
    envelope.source.native_session_id = envelope
        .source
        .native_session_id
        .as_deref()
        .map(|value| scrub_text(value, MAX_IDENTIFIER_CHARS));
    envelope.source.title = envelope
        .source
        .title
        .as_deref()
        .and_then(safe_session_label);
    envelope.source.title_provenance = envelope
        .source
        .title_provenance
        .as_deref()
        .and_then(safe_session_label);
    envelope.ai_project = envelope
        .ai_project
        .as_deref()
        .map(|value| scrub_text(value, MAX_IDENTIFIER_CHARS));
    envelope.ai_session_id = envelope
        .ai_session_id
        .as_deref()
        .map(|value| scrub_text(value, MAX_IDENTIFIER_CHARS));
    envelope.event_kind = envelope.event_kind.as_deref().map(safe_identifier);
    envelope.timestamp = envelope
        .timestamp
        .as_deref()
        .map(safe_timestamp)
        .transpose()?
        .flatten();
    envelope.message = scrub_text(&envelope.message, MAX_TEXT_CHARS);
    envelope.diagnostics.truncate(MAX_DIAGNOSTICS);
    for diagnostic in &mut envelope.diagnostics {
        diagnostic.code = safe_identifier(&diagnostic.code);
        diagnostic.detail = diagnostic
            .detail
            .as_deref()
            .map(|value| scrub_text(value, MAX_DIAGNOSTIC_CHARS));
    }
    Ok(envelope)
}

/// Timestamps arrive from an authenticated but untrusted forwarding client.
/// Treat them like every other evidence scalar: scrub/bound before attempting
/// to parse, then retain only a canonical RFC3339 representation. Reject a
/// malformed supplied value explicitly so the sender cannot mistake receipt
/// time for the event time it attempted to provide.
fn safe_timestamp(value: &str) -> Result<Option<String>, &'static str> {
    let scrubbed = scrub_text(value, MAX_TIMESTAMP_CHARS);
    chrono::DateTime::parse_from_rfc3339(&scrubbed)
        .map(|timestamp| Some(timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)))
        .map_err(|_| "invalid_evidence_timestamp")
}

#[path = "ai_transcript_ingest/legacy_receipt.rs"]
mod legacy_receipt;
use legacy_receipt::*;

async fn ingest_handler(
    State(state): State<AiTranscriptIngestState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(forwarder_identity) = authenticated_forwarder(&state, &peer, &headers) else {
        return unauthorized();
    };

    let request: AiTranscriptIngestRequest = match serde_json::from_slice(&body) {
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

    // Reject unsupported/ill-formed envelopes before admitting a writer. The
    // transactional path scrubs a second time immediately before persistence
    // so this preflight never becomes a trust boundary.
    let records: std::result::Result<Vec<_>, _> = request
        .records
        .into_iter()
        .map(|record| {
            scrub_envelope(record.envelope).map(|envelope| AiTranscriptRecord { envelope })
        })
        .collect();
    let records = match records {
        Ok(records) => records,
        Err(reason) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": reason}))).into_response();
        }
    };
    let pool = Arc::clone(&state.pool);
    let join_result = tokio::task::spawn_blocking(move || {
        insert_envelopes_with_principal(&pool, records, forwarder_identity, peer)
    })
    .await;

    match join_result {
        Ok(Ok(receipts)) => (
            StatusCode::OK,
            Json(AiTranscriptIngestResponse {
                accepted: receipts.len(),
                receipts,
            }),
        )
            .into_response(),
        Ok(Err(error)) if error.downcast_ref::<IdempotencyConflict>().is_some() => (
            StatusCode::CONFLICT,
            Json(json!({"error": "idempotency_conflict"})),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "ai transcript forward ingest failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response()
        }
        Err(join_error) => {
            tracing::error!(error = %join_error, "ai transcript ingest task panicked or was cancelled");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ingest_task_failed", "message": join_error.to_string()})),
            )
                .into_response()
        }
    }
}

fn authenticated_forwarder(
    state: &AiTranscriptIngestState,
    peer: &SocketAddr,
    headers: &HeaderMap,
) -> Option<ForwardingPrincipal> {
    if matches!(state.auth_policy, AuthPolicy::LoopbackDev) {
        return peer
            .ip()
            .is_loopback()
            .then_some(ForwardingPrincipal::Loopback);
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let token = parse_bearer_token(auth)?;
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
#[path = "ai_transcript_ingest_tests.rs"]
mod tests;
