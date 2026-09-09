//! Agent-command and shell-history projection.

use super::super::AGENT_OBSERVATORY_PROJECTION_VERSION;
use crate::agent_observatory::classifier::{
    CommandLogClassification, CommandLogProjection, CommandLogSource, CommandSkipDiagnostic,
    CommandSkipReason, classify_command_log,
};
use crate::db::agent_observatory::{
    AgentEventKind, AgentProjectionOutboxInput, AgentProjectionRunMatch, AgentProjectionWriteInput,
    AgentProjectionWriteResult, AgentRunEventUpsert, AgentRunRow, AgentRunUpsert,
    AgentWorktreeEvidenceUpsert, EvidenceTrustLevel, RunStatus, StreamEventName,
    advance_projection_cursor, find_active_projection_worktree,
    find_unique_overlapping_projection_run, write_agent_projection,
    write_agent_projection_with_cursor,
};
use crate::db::{DbPool, LogEntry};
use anyhow::{Context, Result};
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

const MAX_COMMAND_SUMMARY_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandProjectionSkipReason {
    Classification(CommandSkipReason),
    NoMatchingWorktree,
    NoOverlappingRun,
    AmbiguousOverlappingRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProjectionDiagnostic {
    pub log_id: i64,
    pub reason: CommandProjectionSkipReason,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandProjectionOutcome {
    Projected(Box<AgentProjectionWriteResult>),
    Skipped(CommandProjectionDiagnostic),
}

fn skip(log_id: i64, reason: CommandProjectionSkipReason) -> CommandProjectionOutcome {
    CommandProjectionOutcome::Skipped(CommandProjectionDiagnostic { log_id, reason })
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
        .with_context(|| format!("invalid command received_at: {received_at}"))?;
    Ok((received.with_timezone(&Utc) + Duration::hours(24))
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn existing_run_input(row: &AgentRunRow) -> AgentRunUpsert {
    AgentRunUpsert {
        native_session_id: row.native_session_id.clone(),
        tool: row.tool.clone(),
        provider_tool: row.provider_tool.clone(),
        hostname: row.hostname.clone(),
        parent_run_key: None,
        previous_run_key: None,
        primary_worktree_key: None,
        transcript_path: row.transcript_path.clone(),
        process_id: row.process_id.clone(),
        status: row.status,
        status_reason: row.status_reason.clone(),
        status_observed_at: row.status_observed_at.clone(),
        started_at: row.started_at.clone(),
        last_activity_at: row.last_activity_at.clone(),
        ended_at: row.ended_at.clone(),
        primary_branch: row.primary_branch.clone(),
        start_head_sha: row.start_head_sha.clone(),
        current_head_sha: row.current_head_sha.clone(),
        projection_version: row.projection_version,
        freshness_json: row.freshness_json.clone(),
        metadata_json: row.metadata_json.clone(),
    }
}

fn payload(source: &CommandLogProjection) -> Result<String> {
    let metadata: Value = serde_json::from_str(&source.metadata_json)
        .context("classified command metadata must remain valid JSON")?;
    Ok(json!({
        "command": source.command,
        "command_surface": source.command_surface,
        "command_truncated": source.command_truncated,
        "content_scrubbed": source.content_scrubbed,
        "cwd": source.cwd,
        "duration_ms": source.duration_ms,
        "exit_status": source.exit_status,
        "finished_at": source.finished_at,
        "metadata": metadata,
        "provider_session_id": source.provider_session_id,
        "shell_session_id": source.shell_session_id,
    })
    .to_string())
}

fn event_input(source: &CommandLogProjection, worktree_key: &str) -> Result<AgentRunEventUpsert> {
    let (variant, title, event_kind) = match source.source {
        CommandLogSource::AgentCommand => {
            ("agent_command", "agent command", AgentEventKind::Command)
        }
        CommandLogSource::Atuin => (
            "shell_history",
            "Atuin shell command",
            AgentEventKind::ShellHistory,
        ),
    };
    Ok(AgentRunEventUpsert {
        source_kind: "logs".to_string(),
        source_id: source.log_id.to_string(),
        projection_variant: variant.to_string(),
        worktree_key: Some(worktree_key.to_string()),
        observed_at: source.timestamp.clone(),
        ingested_at: source.received_at.clone(),
        event_kind,
        source_log_id: Some(source.log_id),
        provider_sequence: None,
        trace_id: None,
        span_id: None,
        severity: if source.severity.is_empty() {
            "info".to_string()
        } else {
            source.severity.clone()
        },
        title: title.to_string(),
        summary: truncate_utf8(&source.command, MAX_COMMAND_SUMMARY_BYTES),
        payload_json: payload(source)?,
        content_scrubbed: source.content_scrubbed,
    })
}

fn outbox_input(source: &CommandLogProjection) -> Result<AgentProjectionOutboxInput> {
    let (event_kind, source_name) = match source.source {
        CommandLogSource::AgentCommand => ("command", "agent_command"),
        CommandLogSource::Atuin => ("shell_history", "shell_history"),
    };
    Ok(AgentProjectionOutboxInput {
        event_name: StreamEventName::RunEvent,
        expires_at: expires_at(&source.received_at)?,
        payload_json: json!({
            "event_kind": event_kind,
            "source_log_id": source.log_id,
            "source": source_name,
        })
        .to_string(),
    })
}

fn agent_input(
    source: &CommandLogProjection,
    worktree_key: &str,
) -> Result<AgentProjectionWriteInput> {
    let tool = source
        .tool
        .as_deref()
        .context("agent command tool missing after classification")?;
    let session = source
        .provider_session_id
        .as_deref()
        .context("agent command session missing after classification")?;
    let last_activity_at = source.finished_at.as_deref().unwrap_or(&source.timestamp);
    Ok(AgentProjectionWriteInput {
        run: AgentRunUpsert {
            native_session_id: session.to_string(),
            tool: tool.to_string(),
            provider_tool: source.provider_tool.clone(),
            hostname: source.hostname.clone(),
            parent_run_key: None,
            previous_run_key: None,
            primary_worktree_key: Some(worktree_key.to_string()),
            transcript_path: None,
            process_id: source.process_id.clone(),
            status: RunStatus::Active,
            status_reason: "agent command activity".to_string(),
            status_observed_at: source.timestamp.clone(),
            started_at: source.timestamp.clone(),
            last_activity_at: last_activity_at.to_string(),
            ended_at: None,
            primary_branch: None,
            start_head_sha: None,
            current_head_sha: None,
            projection_version: i64::from(AGENT_OBSERVATORY_PROJECTION_VERSION),
            freshness_json: json!({
                "last_command_at": source.timestamp,
                "source_log_id": source.log_id,
            })
            .to_string(),
            metadata_json: json!({
                "command_surface": source.command_surface,
                "provider_tool": source.provider_tool,
            })
            .to_string(),
        },
        actor: None,
        worktree_evidence: Some(AgentWorktreeEvidenceUpsert {
            worktree_key: worktree_key.to_string(),
            evidence_kind: "agent_command_cwd".to_string(),
            evidence_source: format!("logs:{}", source.log_id),
            trust_level: EvidenceTrustLevel::Verified,
            confidence: 0.98,
            is_primary: true,
            first_seen_at: source.timestamp.clone(),
            last_seen_at: source.timestamp.clone(),
            metadata_json: json!({ "cwd": source.cwd }).to_string(),
        }),
        trace_relation: None,
        event: event_input(source, worktree_key)?,
        outbox: outbox_input(source)?,
    })
}

fn atuin_input(
    source: &CommandLogProjection,
    run: &AgentRunRow,
    worktree_key: &str,
) -> Result<AgentProjectionWriteInput> {
    Ok(AgentProjectionWriteInput {
        run: existing_run_input(run),
        actor: None,
        worktree_evidence: Some(AgentWorktreeEvidenceUpsert {
            worktree_key: worktree_key.to_string(),
            evidence_kind: "atuin_cwd_window".to_string(),
            evidence_source: format!("logs:{}", source.log_id),
            trust_level: EvidenceTrustLevel::Claimed,
            confidence: 0.85,
            is_primary: false,
            first_seen_at: source.timestamp.clone(),
            last_seen_at: source.timestamp.clone(),
            metadata_json: json!({
                "cwd": source.cwd,
                "shell_session_id": source.shell_session_id,
            })
            .to_string(),
        }),
        trace_relation: None,
        event: event_input(source, worktree_key)?,
        outbox: outbox_input(source)?,
    })
}

fn skipped_with_cursor(
    pool: &DbPool,
    cursor: Option<(&str, &str)>,
    log_id: i64,
    reason: CommandProjectionSkipReason,
) -> Result<CommandProjectionOutcome> {
    if let Some((source_name, cursor)) = cursor {
        advance_projection_cursor(pool, source_name, cursor)?;
    }
    Ok(skip(log_id, reason))
}

fn project_command_log_inner(
    pool: &DbPool,
    row: &LogEntry,
    cursor: Option<(&str, &str)>,
) -> Result<CommandProjectionOutcome> {
    let source = match classify_command_log(row) {
        CommandLogClassification::Skip(CommandSkipDiagnostic { log_id, reason }) => {
            return skipped_with_cursor(
                pool,
                cursor,
                log_id,
                CommandProjectionSkipReason::Classification(reason),
            );
        }
        CommandLogClassification::Project(source) => source,
    };
    let Some(worktree) = find_active_projection_worktree(pool, &source.hostname, &source.cwd)?
    else {
        return skipped_with_cursor(
            pool,
            cursor,
            source.log_id,
            CommandProjectionSkipReason::NoMatchingWorktree,
        );
    };
    let input = match source.source {
        CommandLogSource::AgentCommand => agent_input(&source, &worktree.worktree_key)?,
        CommandLogSource::Atuin => {
            let run = match find_unique_overlapping_projection_run(
                pool,
                &source.hostname,
                &source.timestamp,
            )? {
                AgentProjectionRunMatch::None => {
                    return skipped_with_cursor(
                        pool,
                        cursor,
                        source.log_id,
                        CommandProjectionSkipReason::NoOverlappingRun,
                    );
                }
                AgentProjectionRunMatch::Ambiguous => {
                    return skipped_with_cursor(
                        pool,
                        cursor,
                        source.log_id,
                        CommandProjectionSkipReason::AmbiguousOverlappingRun,
                    );
                }
                AgentProjectionRunMatch::Unique(run) => run,
            };
            atuin_input(&source, &run, &worktree.worktree_key)?
        }
    };
    let written = match cursor {
        Some((source_name, cursor)) => {
            write_agent_projection_with_cursor(pool, &input, source_name, cursor)?
        }
        None => write_agent_projection(pool, &input)?,
    };
    Ok(CommandProjectionOutcome::Projected(Box::new(written)))
}

pub fn project_command_log(pool: &DbPool, row: &LogEntry) -> Result<CommandProjectionOutcome> {
    project_command_log_inner(pool, row, None)
}

pub(crate) fn project_command_log_with_cursor(
    pool: &DbPool,
    row: &LogEntry,
    source_name: &str,
    cursor: &str,
) -> Result<CommandProjectionOutcome> {
    project_command_log_inner(pool, row, Some((source_name, cursor)))
}

#[cfg(test)]
#[path = "projector_commands_tests.rs"]
mod tests;
