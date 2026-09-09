//! Projection adapters for MCP, hook, skill, and LLM source rows.

#[path = "projector_sources_types.rs"]
mod types;
use types::{MAX_SUMMARY_BYTES, ProjectionParts, bounded_payload, projection_parts, truncate_utf8};
#[path = "projector_sources/repository.rs"]
mod repository;
use repository::project_repository_observation;

use super::super::AGENT_OBSERVATORY_PROJECTION_VERSION;
use crate::agent_observatory::identity::canonical_tool;
use crate::db::DbPool;
use crate::db::agent_observatory::{
    AgentActorUpsert, AgentProjectionOutboxInput, AgentProjectionRunMatch,
    AgentProjectionWriteInput, AgentProjectionWriteResult, AgentRunEventUpsert, AgentRunRow,
    AgentRunUpsert, AgentSourceKind, AgentSourceRecord, AgentTraceRelationUpsert,
    AgentWorktreeEvidenceUpsert, EvidenceTrustLevel, RunStatus, StreamEventName,
    advance_projection_cursor, find_active_projection_worktree,
    find_unique_projection_run_by_session, projection_event_has_summary,
    reconcile_unmatched_trace_relations, write_agent_projection,
    write_agent_projection_with_cursor, write_agent_trace_relation_without_run,
};
use anyhow::{Context, Result};
use chrono::{Duration, SecondsFormat, Utc};
use rusqlite::params;
use serde_json::json;

const OTEL_GENAI_SEMCONV_VERSION: &str = "opentelemetry-genai-v1.26.0";
const TRACE_RELATION_CANDIDATE_CAP: i64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpanAssociation {
    Exact(i64),
    NoMatch,
    Ambiguous(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceProjectionSkipReason {
    MissingTool,
    MissingSession,
    MissingHostname,
    MissingWorktree,
    AlreadyProjected,
    NoMatchingRun,
    AmbiguousMatchingRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProjectionDiagnostic {
    pub source_kind: AgentSourceKind,
    pub source_id: String,
    pub reason: SourceProjectionSkipReason,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SourceProjectionOutcome {
    Projected(Box<AgentProjectionWriteResult>),
    Skipped(SourceProjectionDiagnostic),
}

pub(super) fn skip(
    source: &ProjectionParts,
    reason: SourceProjectionSkipReason,
) -> SourceProjectionOutcome {
    SourceProjectionOutcome::Skipped(SourceProjectionDiagnostic {
        source_kind: source.kind,
        source_id: source.source_id.clone(),
        reason,
    })
}

pub(super) fn expires_at(observed_at: &str) -> Result<String> {
    let observed = chrono::DateTime::parse_from_rfc3339(observed_at)
        .with_context(|| format!("invalid source observed_at: {observed_at}"))?;
    Ok((observed.with_timezone(&Utc) + Duration::hours(24))
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn existing_run_input(row: &AgentRunRow, last_activity_at: &str) -> AgentRunUpsert {
    let last_activity_at = chrono::DateTime::parse_from_rfc3339(last_activity_at)
        .ok()
        .zip(chrono::DateTime::parse_from_rfc3339(&row.last_activity_at).ok())
        .map_or_else(
            || last_activity_at.to_string(),
            |(new, old)| {
                if new > old {
                    last_activity_at.to_string()
                } else {
                    row.last_activity_at.clone()
                }
            },
        );
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
        last_activity_at,
        ended_at: row.ended_at.clone(),
        primary_branch: row.primary_branch.clone(),
        start_head_sha: row.start_head_sha.clone(),
        current_head_sha: row.current_head_sha.clone(),
        projection_version: row.projection_version,
        freshness_json: row.freshness_json.clone(),
        metadata_json: row.metadata_json.clone(),
    }
}

fn new_run(
    source: &ProjectionParts,
    tool: &str,
    session: &str,
    hostname: &str,
    worktree_key: Option<&str>,
) -> AgentRunUpsert {
    AgentRunUpsert {
        native_session_id: session.to_string(),
        tool: tool.to_string(),
        provider_tool: source.provider_tool.clone(),
        hostname: hostname.to_string(),
        parent_run_key: None,
        previous_run_key: None,
        primary_worktree_key: worktree_key.map(str::to_string),
        transcript_path: None,
        process_id: None,
        status: RunStatus::Active,
        status_reason: format!("{} activity", source.projection_variant),
        status_observed_at: source.observed_at.clone(),
        started_at: source.observed_at.clone(),
        last_activity_at: source.last_activity_at.clone(),
        ended_at: None,
        primary_branch: None,
        start_head_sha: None,
        current_head_sha: None,
        projection_version: i64::from(AGENT_OBSERVATORY_PROJECTION_VERSION),
        freshness_json: json!({
            "last_source_at": source.observed_at,
            "source_cursor": source.source_cursor,
            "source_kind": source.source_kind,
        })
        .to_string(),
        metadata_json: json!({
            "project": source.project,
            "provider_tool": source.provider_tool,
        })
        .to_string(),
    }
}

fn projection_input(
    pool: &DbPool,
    source: &ProjectionParts,
    trace_relation: Option<AgentTraceRelationUpsert>,
) -> Result<Result<AgentProjectionWriteInput, SourceProjectionSkipReason>> {
    let Some(raw_tool) = source
        .tool
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(Err(SourceProjectionSkipReason::MissingTool));
    };
    let tool = canonical_tool(raw_tool).context("canonicalize source tool")?;
    let Some(session) = source
        .session_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(Err(SourceProjectionSkipReason::MissingSession));
    };

    let (run, worktree_key, worktree_evidence) = if let Some(hostname) = source.hostname.as_deref()
    {
        if hostname.trim().is_empty() {
            return Ok(Err(SourceProjectionSkipReason::MissingHostname));
        }
        let worktree = match source.project.as_deref() {
            Some(project) if project.starts_with('/') => {
                find_active_projection_worktree(pool, hostname, project)?
            }
            _ => None,
        };
        let worktree_key = worktree.as_ref().map(|row| row.worktree_key.clone());
        let evidence = worktree_key
            .as_ref()
            .map(|key| AgentWorktreeEvidenceUpsert {
                worktree_key: key.clone(),
                evidence_kind: "transcript_project_path".to_string(),
                evidence_source: format!("{}:{}", source.source_kind, source.source_id),
                trust_level: EvidenceTrustLevel::Verified,
                confidence: 0.95,
                is_primary: true,
                first_seen_at: source.observed_at.clone(),
                last_seen_at: source.observed_at.clone(),
                metadata_json: json!({ "project": source.project }).to_string(),
            });
        (
            new_run(source, &tool, session, hostname, worktree_key.as_deref()),
            worktree_key,
            evidence,
        )
    } else {
        match find_unique_projection_run_by_session(pool, &tool, session)? {
            AgentProjectionRunMatch::None => {
                return Ok(Err(SourceProjectionSkipReason::NoMatchingRun));
            }
            AgentProjectionRunMatch::Ambiguous => {
                return Ok(Err(SourceProjectionSkipReason::AmbiguousMatchingRun));
            }
            AgentProjectionRunMatch::Unique(row) => (
                existing_run_input(&row, &source.last_activity_at),
                None,
                None,
            ),
        }
    };

    let payload = bounded_payload(source.payload.clone(), &source.title, &source.source_cursor);
    Ok(Ok(AgentProjectionWriteInput {
        run,
        actor: Some(AgentActorUpsert {
            native_actor_id: source.actor_id.clone(),
            actor_type: Some(source.actor_type.to_string()),
            display_name: Some(truncate_utf8(&source.actor_name, MAX_SUMMARY_BYTES)),
            started_at: Some(source.observed_at.clone()),
            last_activity_at: Some(source.last_activity_at.clone()),
            ended_at: None,
            metadata_json: json!({ "source_kind": source.source_kind }).to_string(),
        }),
        worktree_evidence,
        trace_relation,
        event: AgentRunEventUpsert {
            source_kind: source.source_kind.to_string(),
            source_id: source.source_id.clone(),
            projection_variant: source.projection_variant.to_string(),
            worktree_key,
            observed_at: source.observed_at.clone(),
            ingested_at: source.ingested_at.clone(),
            event_kind: source.event_kind,
            source_log_id: source.source_log_id,
            provider_sequence: source.provider_sequence,
            trace_id: source.trace_id.clone(),
            span_id: source.span_id.clone(),
            severity: source.severity.clone(),
            title: truncate_utf8(&source.title, MAX_SUMMARY_BYTES),
            summary: source.summary.clone(),
            payload_json: payload,
            content_scrubbed: true,
        },
        outbox: AgentProjectionOutboxInput {
            event_name: StreamEventName::RunEvent,
            expires_at: expires_at(&source.observed_at)?,
            payload_json: json!({
                "event_kind": source.projection_variant,
                "source_cursor": source.source_cursor,
                "source_id": source.source_id,
                "source_kind": source.source_kind,
            })
            .to_string(),
        },
    }))
}

fn bounded_identity(value: Option<&str>, maximum: usize) -> Option<String> {
    value
        .filter(|value| value.len() <= maximum && !value.trim().is_empty())
        .map(str::to_string)
}

fn safe_attribute_identity(source: &ProjectionParts, keys: &[&str]) -> Option<String> {
    let attributes = source.payload.get("attributes")?.as_object()?;
    keys.iter().find_map(|key| {
        attributes
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .and_then(|value| bounded_identity(Some(value), 128))
    })
}

fn trace_relation(
    source: &ProjectionParts,
    association: SpanAssociation,
) -> Option<AgentTraceRelationUpsert> {
    if source.kind != AgentSourceKind::OtelSpan {
        return None;
    }
    let (Some(trace_id), Some(span_id)) = (source.trace_id.as_deref(), source.span_id.as_deref())
    else {
        return None;
    };
    let (evidence_kind, confidence, reason, candidate_count) = match association {
        SpanAssociation::Exact(count) => (
            "exact_provider_id",
            0.98,
            "same host, canonical provider, and provider conversation identity",
            count,
        ),
        SpanAssociation::NoMatch => (
            "no_match",
            1.0,
            "no existing run has the asserted provider identity",
            0,
        ),
        SpanAssociation::Ambiguous(count) => (
            "ambiguous",
            0.0,
            "provider session identity collides across candidate runs",
            count,
        ),
    };
    Some(AgentTraceRelationUpsert {
        trace_id: trace_id.to_string(),
        span_id: span_id.to_string(),
        identifier_namespace: "otel.gen_ai.conversation.id".to_string(),
        provider: bounded_identity(source.provider_tool.as_deref(), 64)
            .or_else(|| bounded_identity(source.tool.as_deref(), 64)),
        evidence_kind: evidence_kind.to_string(),
        confidence,
        reason: reason.to_string(),
        projection_version: i64::from(AGENT_OBSERVATORY_PROJECTION_VERSION),
        candidate_count,
        observed_at: source.observed_at.clone(),
        // Only values in this pinned field matrix acquire association meaning.
        // Unknown future OTLP conventions remain bounded source evidence only.
        metadata_json: json!({
            "semantic_convention": OTEL_GENAI_SEMCONV_VERSION,
            "model": safe_attribute_identity(source, &["gen_ai.request.model", "gen_ai.response.model"]),
            "mcp_server": safe_attribute_identity(source, &["mcp.server.name", "gen_ai.mcp.server.name"]),
            "mcp_tool": safe_attribute_identity(source, &["mcp.tool.name", "gen_ai.tool.name"]),
            "status": source.severity,
        })
        .to_string(),
    })
}

fn classify_telemetry_association(
    pool: &DbPool,
    source: &ProjectionParts,
) -> Result<SpanAssociation> {
    if !matches!(
        source.kind,
        AgentSourceKind::OtelSpan | AgentSourceKind::OtelMetric
    ) {
        return Ok(SpanAssociation::Exact(1));
    }
    let (Some(hostname), Some(tool), Some(session)) = (
        source
            .hostname
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
        source
            .tool
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
        source
            .session_id
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) else {
        return Ok(SpanAssociation::NoMatch);
    };
    let canonical = canonical_tool(tool)?;
    let conn = pool.get()?;
    let candidates = conn
        .prepare(
            "SELECT tool FROM agent_runs
              WHERE hostname = ?1 AND native_session_id = ?2
              ORDER BY id LIMIT ?3",
        )?
        .query_map(
            params![hostname, session, TRACE_RELATION_CANDIDATE_CAP + 1],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let count = i64::try_from(candidates.len().min(TRACE_RELATION_CANDIDATE_CAP as usize))
        .expect("bounded candidate count fits i64");
    if candidates.iter().any(|candidate| candidate == &canonical) {
        Ok(SpanAssociation::Exact(count))
    } else if candidates.is_empty() {
        Ok(SpanAssociation::NoMatch)
    } else {
        Ok(SpanAssociation::Ambiguous(count))
    }
}

fn project_agent_source_inner(
    pool: &DbPool,
    record: &AgentSourceRecord,
    cursor: Option<(&str, &str)>,
) -> Result<SourceProjectionOutcome> {
    let source = projection_parts(record);
    if matches!(record, AgentSourceRecord::RepositoryObservation(_)) {
        return project_repository_observation(pool, &source, cursor);
    }
    let association = classify_telemetry_association(pool, &source)?;
    let relation = trace_relation(&source, association);
    if matches!(
        source.kind,
        AgentSourceKind::OtelSpan | AgentSourceKind::OtelMetric
    ) && !matches!(association, SpanAssociation::Exact(_))
    {
        if let Some(relation) = relation.as_ref() {
            write_agent_trace_relation_without_run(pool, relation)?;
        }
        if let Some((source_name, cursor)) = cursor {
            advance_projection_cursor(pool, source_name, cursor)?;
        }
        return Ok(skip(
            &source,
            if matches!(association, SpanAssociation::Ambiguous(_)) {
                SourceProjectionSkipReason::AmbiguousMatchingRun
            } else {
                SourceProjectionSkipReason::NoMatchingRun
            },
        ));
    }
    let terminal_llm_replay = matches!(
        record,
        AgentSourceRecord::Llm(row)
            if row.finished_at.is_some() && !row.status.eq_ignore_ascii_case("running")
    );
    if terminal_llm_replay
        && let Some((source_name, cursor)) = cursor
        && projection_event_has_summary(
            pool,
            source.source_kind,
            &source.source_id,
            source.projection_variant,
            "running",
        )?
    {
        advance_projection_cursor(pool, source_name, cursor)?;
        return Ok(skip(&source, SourceProjectionSkipReason::AlreadyProjected));
    }
    let input = match projection_input(pool, &source, relation)? {
        Ok(input) => input,
        Err(reason) => {
            if let Some((source_name, cursor)) = cursor {
                advance_projection_cursor(pool, source_name, cursor)?;
            }
            return Ok(skip(&source, reason));
        }
    };
    let written = match cursor {
        Some((source_name, cursor)) => {
            write_agent_projection_with_cursor(pool, &input, source_name, cursor)?
        }
        None => write_agent_projection(pool, &input)?,
    };
    // A later transcript/source may resolve an older no-match span, but only
    // through the exact host/tool/provider-session identity; never by time.
    let _ = reconcile_unmatched_trace_relations(pool)?;
    Ok(SourceProjectionOutcome::Projected(Box::new(written)))
}

pub fn project_agent_source(
    pool: &DbPool,
    record: &AgentSourceRecord,
) -> Result<SourceProjectionOutcome> {
    project_agent_source_inner(pool, record, None)
}

pub(crate) fn project_agent_source_with_cursor(
    pool: &DbPool,
    record: &AgentSourceRecord,
    source_name: &str,
    cursor: &str,
) -> Result<SourceProjectionOutcome> {
    project_agent_source_inner(pool, record, Some((source_name, cursor)))
}

#[cfg(test)]
#[path = "projector_sources_tests.rs"]
mod tests;
