//! Projection of repository observations onto verified active runs.

use anyhow::Result;
use serde_json::json;

use super::types::bounded_payload;
use super::{
    DbPool, ProjectionParts, SourceProjectionOutcome, SourceProjectionSkipReason, expires_at, skip,
};
use crate::db::agent_observatory::{
    AgentProjectionOutboxInput, AgentRepositoryObservationRunMatch, AgentRunEventUpsert,
    StreamEventName, advance_projection_cursor,
    find_unique_projection_run_for_repository_observation, write_agent_existing_run_event,
    write_agent_existing_run_event_with_cursor,
};

pub(super) fn project_repository_observation(
    pool: &DbPool,
    source: &ProjectionParts,
    cursor: Option<(&str, &str)>,
) -> Result<SourceProjectionOutcome> {
    let Some(worktree_key) = source
        .payload
        .pointer("/observation/worktree_key")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        if let Some((source_name, cursor)) = cursor {
            advance_projection_cursor(pool, source_name, cursor)?;
        }
        return Ok(skip(source, SourceProjectionSkipReason::MissingWorktree));
    };
    let association = match find_unique_projection_run_for_repository_observation(
        pool,
        worktree_key,
        &source.observed_at,
    )? {
        AgentRepositoryObservationRunMatch::None => {
            if let Some((source_name, cursor)) = cursor {
                advance_projection_cursor(pool, source_name, cursor)?;
            }
            return Ok(skip(source, SourceProjectionSkipReason::NoMatchingRun));
        }
        AgentRepositoryObservationRunMatch::Ambiguous => {
            if let Some((source_name, cursor)) = cursor {
                advance_projection_cursor(pool, source_name, cursor)?;
            }
            return Ok(skip(
                source,
                SourceProjectionSkipReason::AmbiguousMatchingRun,
            ));
        }
        AgentRepositoryObservationRunMatch::Unique(association) => association,
    };
    let payload = bounded_payload(
        json!({
            "association": {"confidence": association.evidence_confidence.min(0.75), "evidence_kind": association.evidence_kind, "evidence_source": association.evidence_source, "evidence_trust": association.evidence_trust.as_str(), "method": "active_worktree_evidence", "trust": "correlated"},
            "source": source.payload,
        }),
        &source.title,
        &source.source_cursor,
    );
    let event = AgentRunEventUpsert {
        source_kind: source.source_kind.to_string(),
        source_id: source.source_id.clone(),
        projection_variant: source.projection_variant.to_string(),
        worktree_key: Some(worktree_key.to_string()),
        observed_at: source.observed_at.clone(),
        ingested_at: source.ingested_at.clone(),
        event_kind: source.event_kind,
        source_log_id: None,
        provider_sequence: source.provider_sequence,
        trace_id: None,
        span_id: None,
        severity: source.severity.clone(),
        title: source.title.clone(),
        summary: source.summary.clone(),
        payload_json: payload,
        content_scrubbed: true,
    };
    let outbox = AgentProjectionOutboxInput { event_name: StreamEventName::RunEvent, expires_at: expires_at(&source.observed_at)?, payload_json: json!({"event_kind": "repository_observation", "source_cursor": source.source_cursor, "source_id": source.source_id, "source_kind": source.source_kind}).to_string() };
    let written = match cursor {
        Some((source_name, cursor)) => write_agent_existing_run_event_with_cursor(
            pool,
            &association.run,
            &event,
            &outbox,
            source_name,
            cursor,
        )?,
        None => write_agent_existing_run_event(pool, &association.run, &event, &outbox)?,
    };
    Ok(SourceProjectionOutcome::Projected(Box::new(written)))
}
