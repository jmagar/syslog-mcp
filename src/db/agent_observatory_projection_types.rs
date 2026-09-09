//! Public inputs and materialized rows for atomic Agent Observatory projection writes.

use super::super::{
    AgentEventKind, AgentRunEventRow, AgentRunRow, AgentRunWorktreeEvidenceRow, EvidenceTrustLevel,
    RunStatus, StreamEventName,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentRunUpsert {
    pub native_session_id: String,
    pub tool: String,
    pub provider_tool: Option<String>,
    pub hostname: String,
    pub parent_run_key: Option<String>,
    pub previous_run_key: Option<String>,
    pub primary_worktree_key: Option<String>,
    pub transcript_path: Option<String>,
    pub process_id: Option<String>,
    pub status: RunStatus,
    pub status_reason: String,
    pub status_observed_at: String,
    pub started_at: String,
    pub last_activity_at: String,
    pub ended_at: Option<String>,
    pub primary_branch: Option<String>,
    pub start_head_sha: Option<String>,
    pub current_head_sha: Option<String>,
    pub projection_version: i64,
    pub freshness_json: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentActorUpsert {
    pub native_actor_id: String,
    pub actor_type: Option<String>,
    pub display_name: Option<String>,
    pub started_at: Option<String>,
    pub last_activity_at: Option<String>,
    pub ended_at: Option<String>,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentWorktreeEvidenceUpsert {
    pub worktree_key: String,
    pub evidence_kind: String,
    pub evidence_source: String,
    pub trust_level: EvidenceTrustLevel,
    pub confidence: f64,
    pub is_primary: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub metadata_json: String,
}

/// A versioned, explicit relationship from an OTLP span to the run that the
/// projector could identify.  This deliberately carries the evidence rather
/// than making read paths rediscover a relationship from host/session fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentTraceRelationUpsert {
    pub trace_id: String,
    pub span_id: String,
    pub identifier_namespace: String,
    pub provider: Option<String>,
    pub evidence_kind: String,
    pub confidence: f64,
    pub reason: String,
    pub projection_version: i64,
    pub candidate_count: i64,
    pub observed_at: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentTraceRelationRow {
    pub id: i64,
    pub relation_key: String,
    pub trace_id: String,
    pub span_id: String,
    pub run_id: Option<i64>,
    pub identifier_namespace: String,
    pub provider: Option<String>,
    pub evidence_kind: String,
    pub confidence: f64,
    pub reason: String,
    pub projection_version: i64,
    pub candidate_count: i64,
    pub observed_at: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentRunEventUpsert {
    pub source_kind: String,
    pub source_id: String,
    pub projection_variant: String,
    pub worktree_key: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub event_kind: AgentEventKind,
    pub source_log_id: Option<i64>,
    pub provider_sequence: Option<i64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub payload_json: String,
    pub content_scrubbed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentProjectionOutboxInput {
    pub event_name: StreamEventName,
    pub expires_at: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentProjectionWriteInput {
    pub run: AgentRunUpsert,
    pub actor: Option<AgentActorUpsert>,
    pub worktree_evidence: Option<AgentWorktreeEvidenceUpsert>,
    pub trace_relation: Option<AgentTraceRelationUpsert>,
    pub event: AgentRunEventUpsert,
    pub outbox: AgentProjectionOutboxInput,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentActorRow {
    pub id: i64,
    pub actor_key: String,
    pub run_id: i64,
    pub native_actor_id: String,
    pub actor_type: Option<String>,
    pub display_name: Option<String>,
    pub started_at: Option<String>,
    pub last_activity_at: Option<String>,
    pub ended_at: Option<String>,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProjectionOutboxRow {
    pub id: i64,
    pub outbox_key: String,
    pub run_id: i64,
    pub event_name: StreamEventName,
    pub expires_at: String,
    pub payload_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentProjectionWriteResult {
    pub run: AgentRunRow,
    pub actor: Option<AgentActorRow>,
    pub worktree_evidence: Option<AgentRunWorktreeEvidenceRow>,
    pub trace_relation: Option<AgentTraceRelationRow>,
    pub event: AgentRunEventRow,
    pub event_inserted: bool,
    pub materialized_state_changed: bool,
    pub outbox: Option<AgentProjectionOutboxRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentProjectionWriteFault {
    EventInsert,
    CursorAdvance,
    Commit,
}
