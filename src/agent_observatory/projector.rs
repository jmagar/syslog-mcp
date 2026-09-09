//! Projection of classified source rows into Agent Observatory materialized state.

#[path = "projector_sources.rs"]
mod sources;
pub(crate) use sources::project_agent_source_with_cursor;
pub use sources::{
    SourceProjectionDiagnostic, SourceProjectionOutcome, SourceProjectionSkipReason,
    project_agent_source,
};
#[path = "projector_commands.rs"]
mod commands;
pub(crate) use commands::project_command_log_with_cursor;
pub use commands::{
    CommandProjectionDiagnostic, CommandProjectionOutcome, CommandProjectionSkipReason,
    project_command_log,
};

use super::AGENT_OBSERVATORY_PROJECTION_VERSION;
use super::classifier::{
    CommandLogClassification, TranscriptLogClassification, TranscriptLogProjection,
    TranscriptSkipDiagnostic, classify_command_log, classify_transcript_log,
};
use crate::db::agent_observatory::{
    AgentEventKind, AgentProjectionOutboxInput, AgentProjectionWriteInput,
    AgentProjectionWriteResult, AgentRunEventUpsert, AgentRunUpsert, RunStatus, StreamEventName,
    advance_projection_cursor, write_agent_projection, write_agent_projection_with_cursor,
};
use crate::db::{DbPool, LogEntry};
use anyhow::{Context, Result};
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

const MAX_TRANSCRIPT_SUMMARY_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum TranscriptProjectionOutcome {
    Projected(Box<AgentProjectionWriteResult>),
    Skipped(TranscriptSkipDiagnostic),
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn expires_at(received_at: &str) -> Result<String> {
    let received = chrono::DateTime::parse_from_rfc3339(received_at)
        .with_context(|| format!("invalid transcript received_at: {received_at}"))?;
    Ok((received.with_timezone(&Utc) + Duration::hours(24))
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn projection_input(source: &TranscriptLogProjection) -> Result<AgentProjectionWriteInput> {
    let metadata: Value = serde_json::from_str(&source.metadata_json)
        .context("classified transcript metadata must remain valid JSON")?;
    let severity = if source.severity.is_empty() {
        "info"
    } else {
        source.severity.as_str()
    };
    let run_metadata = json!({
        "app_name": source.app_name,
        "project": source.project,
        "provider_tool": source.provider_tool,
        "source_ip": source.source_ip,
    });
    let freshness = json!({
        "last_transcript_at": source.timestamp,
        "source_log_id": source.log_id,
    });
    let payload = json!({
        "message": source.message,
        "message_truncated": source.message_truncated,
        "metadata": metadata,
        "project": source.project,
        "transcript_path": source.transcript_path,
    });
    let outbox_payload = json!({
        "event_kind": "transcript",
        "source_log_id": source.log_id,
        "tool": source.tool,
    });

    Ok(AgentProjectionWriteInput {
        run: AgentRunUpsert {
            native_session_id: source.session_id.clone(),
            tool: source.tool.clone(),
            provider_tool: Some(source.provider_tool.clone()),
            hostname: source.hostname.clone(),
            parent_run_key: None,
            previous_run_key: None,
            primary_worktree_key: None,
            transcript_path: Some(source.transcript_path.clone()),
            process_id: source.process_id.clone(),
            status: RunStatus::Active,
            status_reason: "transcript activity".to_string(),
            status_observed_at: source.timestamp.clone(),
            started_at: source.timestamp.clone(),
            last_activity_at: source.timestamp.clone(),
            ended_at: None,
            primary_branch: None,
            start_head_sha: None,
            current_head_sha: None,
            projection_version: i64::from(AGENT_OBSERVATORY_PROJECTION_VERSION),
            freshness_json: freshness.to_string(),
            metadata_json: run_metadata.to_string(),
        },
        actor: None,
        worktree_evidence: None,
        trace_relation: None,
        event: AgentRunEventUpsert {
            source_kind: "logs".to_string(),
            source_id: source.log_id.to_string(),
            projection_variant: "transcript".to_string(),
            worktree_key: None,
            observed_at: source.timestamp.clone(),
            ingested_at: source.received_at.clone(),
            event_kind: AgentEventKind::Transcript,
            source_log_id: Some(source.log_id),
            provider_sequence: None,
            trace_id: None,
            span_id: None,
            severity: severity.to_string(),
            title: format!("{} transcript", source.tool),
            summary: truncate_utf8(&source.message, MAX_TRANSCRIPT_SUMMARY_BYTES),
            payload_json: payload.to_string(),
            content_scrubbed: true,
        },
        outbox: AgentProjectionOutboxInput {
            event_name: StreamEventName::RunEvent,
            expires_at: expires_at(&source.received_at)?,
            payload_json: outbox_payload.to_string(),
        },
    })
}

fn project_transcript_log_inner(
    pool: &DbPool,
    row: &LogEntry,
    cursor: Option<(&str, &str)>,
) -> Result<TranscriptProjectionOutcome> {
    match classify_transcript_log(row) {
        TranscriptLogClassification::Skip(diagnostic) => {
            Ok(TranscriptProjectionOutcome::Skipped(diagnostic))
        }
        TranscriptLogClassification::Project(source) => {
            let input = projection_input(&source)?;
            let written = match cursor {
                Some((source_name, cursor)) => {
                    write_agent_projection_with_cursor(pool, &input, source_name, cursor)?
                }
                None => write_agent_projection(pool, &input)?,
            };
            Ok(TranscriptProjectionOutcome::Projected(Box::new(written)))
        }
    }
}

pub fn project_transcript_log(
    pool: &DbPool,
    row: &LogEntry,
) -> Result<TranscriptProjectionOutcome> {
    project_transcript_log_inner(pool, row, None)
}

pub(crate) fn project_log_row(pool: &DbPool, row: &LogEntry) -> Result<bool> {
    let transcript_projects = matches!(
        classify_transcript_log(row),
        TranscriptLogClassification::Project(_)
    );
    let command_projects = matches!(
        classify_command_log(row),
        CommandLogClassification::Project(_)
    );
    match (transcript_projects, command_projects) {
        (true, true) => anyhow::bail!(
            "log row {} matches both transcript and command projection contracts",
            row.id
        ),
        (true, false) => {
            project_transcript_log(pool, row)?;
            Ok(true)
        }
        (false, true) => {
            project_command_log(pool, row)?;
            Ok(true)
        }
        (false, false) => Ok(false),
    }
}

pub(crate) fn project_log_row_with_cursor(pool: &DbPool, row: &LogEntry) -> Result<()> {
    let transcript_projects = matches!(
        classify_transcript_log(row),
        TranscriptLogClassification::Project(_)
    );
    let command_projects = matches!(
        classify_command_log(row),
        CommandLogClassification::Project(_)
    );
    let cursor = row.id.to_string();

    match (transcript_projects, command_projects) {
        (true, true) => anyhow::bail!(
            "log row {} matches both transcript and command projection contracts",
            row.id
        ),
        (true, false) => {
            project_transcript_log_inner(pool, row, Some(("logs", &cursor)))?;
        }
        (false, true) => {
            project_command_log_with_cursor(pool, row, "logs", &cursor)?;
        }
        (false, false) => advance_projection_cursor(pool, "logs", &cursor)?,
    }
    Ok(())
}

#[cfg(test)]
#[path = "projector_tests.rs"]
mod tests;
