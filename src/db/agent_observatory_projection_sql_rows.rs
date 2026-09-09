//! Row decoding helpers for Agent Observatory projection SQL.

use super::super::super::{AgentRunEventRow, AgentRunRow, AgentRunWorktreeEvidenceRow};
use super::super::types::{AgentActorRow, AgentProjectionOutboxRow, AgentTraceRelationRow};
use rusqlite::{Row, types::Type};
use std::str::FromStr;

fn enum_value<T>(row: &Row<'_>, index: usize) -> rusqlite::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value: String = row.get(index)?;
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error))
    })
}

pub(super) fn run_row(row: &Row<'_>) -> rusqlite::Result<AgentRunRow> {
    Ok(AgentRunRow {
        id: row.get(0)?,
        run_key: row.get(1)?,
        native_session_id: row.get(2)?,
        tool: row.get(3)?,
        provider_tool: row.get(4)?,
        hostname: row.get(5)?,
        parent_run_id: row.get(6)?,
        previous_run_id: row.get(7)?,
        primary_worktree_id: row.get(8)?,
        transcript_path: row.get(9)?,
        process_id: row.get(10)?,
        status: enum_value(row, 11)?,
        status_reason: row.get(12)?,
        status_observed_at: row.get(13)?,
        started_at: row.get(14)?,
        last_activity_at: row.get(15)?,
        ended_at: row.get(16)?,
        first_source_log_id: row.get(17)?,
        last_source_log_id: row.get(18)?,
        last_event_id: row.get(19)?,
        event_count: row.get(20)?,
        error_count: row.get(21)?,
        primary_branch: row.get(22)?,
        start_head_sha: row.get(23)?,
        current_head_sha: row.get(24)?,
        projection_version: row.get(25)?,
        freshness_json: row.get(26)?,
        metadata_json: row.get(27)?,
        created_at: row.get(28)?,
        updated_at: row.get(29)?,
    })
}
pub(super) fn actor_row(row: &Row<'_>) -> rusqlite::Result<AgentActorRow> {
    Ok(AgentActorRow {
        id: row.get(0)?,
        actor_key: row.get(1)?,
        run_id: row.get(2)?,
        native_actor_id: row.get(3)?,
        actor_type: row.get(4)?,
        display_name: row.get(5)?,
        started_at: row.get(6)?,
        last_activity_at: row.get(7)?,
        ended_at: row.get(8)?,
        metadata_json: row.get(9)?,
    })
}
pub(super) fn evidence_row(row: &Row<'_>) -> rusqlite::Result<AgentRunWorktreeEvidenceRow> {
    Ok(AgentRunWorktreeEvidenceRow {
        id: row.get(0)?,
        relation_key: row.get(1)?,
        run_id: row.get(2)?,
        worktree_id: row.get(3)?,
        evidence_kind: row.get(4)?,
        evidence_source: row.get(5)?,
        trust_level: enum_value(row, 6)?,
        confidence: row.get(7)?,
        is_primary: row.get(8)?,
        first_seen_at: row.get(9)?,
        last_seen_at: row.get(10)?,
        metadata_json: row.get(11)?,
    })
}
pub(super) fn event_row(row: &Row<'_>) -> rusqlite::Result<AgentRunEventRow> {
    Ok(AgentRunEventRow {
        id: row.get(0)?,
        event_key: row.get(1)?,
        run_id: row.get(2)?,
        actor_id: row.get(3)?,
        worktree_id: row.get(4)?,
        commit_id: row.get(5)?,
        observed_at: row.get(6)?,
        ingested_at: row.get(7)?,
        event_kind: enum_value(row, 8)?,
        source_kind: row.get(9)?,
        source_id: row.get(10)?,
        source_log_id: row.get(11)?,
        provider_sequence: row.get(12)?,
        trace_id: row.get(13)?,
        span_id: row.get(14)?,
        severity: row.get(15)?,
        title: row.get(16)?,
        summary: row.get(17)?,
        payload_json: row.get(18)?,
        content_scrubbed: row.get(19)?,
        created_at: row.get(20)?,
    })
}
pub(super) fn outbox_row(row: &Row<'_>) -> rusqlite::Result<AgentProjectionOutboxRow> {
    Ok(AgentProjectionOutboxRow {
        id: row.get(0)?,
        outbox_key: row.get(1)?,
        run_id: row.get(2)?,
        event_name: enum_value(row, 3)?,
        expires_at: row.get(4)?,
        payload_json: row.get(5)?,
        created_at: row.get(6)?,
    })
}
pub(super) fn trace_relation_row(row: &Row<'_>) -> rusqlite::Result<AgentTraceRelationRow> {
    Ok(AgentTraceRelationRow {
        id: row.get(0)?,
        relation_key: row.get(1)?,
        trace_id: row.get(2)?,
        span_id: row.get(3)?,
        run_id: row.get(4)?,
        identifier_namespace: row.get(5)?,
        provider: row.get(6)?,
        evidence_kind: row.get(7)?,
        confidence: row.get(8)?,
        reason: row.get(9)?,
        projection_version: row.get(10)?,
        candidate_count: row.get(11)?,
        observed_at: row.get(12)?,
        metadata_json: row.get(13)?,
    })
}
