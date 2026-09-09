//! Atomic Agent Observatory projector persistence.

#[path = "agent_observatory_projection_types.rs"]
mod types;
pub(super) use types::AgentProjectionWriteFault;
pub use types::{
    AgentActorRow, AgentActorUpsert, AgentProjectionOutboxInput, AgentProjectionWriteInput,
    AgentProjectionWriteResult, AgentRunEventUpsert, AgentRunUpsert, AgentTraceRelationRow,
    AgentTraceRelationUpsert, AgentWorktreeEvidenceUpsert,
};

#[path = "agent_observatory_projection_counters.rs"]
mod counters;
#[path = "agent_observatory_projection_lookup.rs"]
mod lookup;
pub use lookup::{
    AgentProjectionRunMatch, find_active_projection_worktree,
    find_unique_overlapping_projection_run, find_unique_projection_run_by_session,
};
pub(crate) use lookup::{
    AgentRepositoryObservationRunMatch, find_unique_projection_run_for_repository_observation,
};
#[path = "agent_observatory_projection_refs.rs"]
mod refs;
#[path = "agent_observatory_projection_sql.rs"]
mod sql;
#[path = "agent_observatory_projection/summary.rs"]
mod summary;
#[path = "agent_observatory_projection_tie_break.rs"]
mod tie_break;
pub(crate) use summary::projection_event_has_summary;

use super::AgentRunRow;
use crate::agent_observatory::identity::{actor_key, canonical_tool, event_key, run_key};
use crate::db::pool::DbPool;
use anyhow::{Context, Result, bail};
use rusqlite::TransactionBehavior;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn required(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must be non-empty");
    }
    Ok(())
}

fn timestamp(value: &str, field: &str) -> Result<()> {
    chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid {field}: {value}"))?;
    Ok(())
}

fn optional_timestamp(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value {
        timestamp(value, field)?;
    }
    Ok(())
}

fn json_object(value: &str, field: &str) -> Result<()> {
    let parsed: Value =
        serde_json::from_str(value).with_context(|| format!("{field} must be valid JSON"))?;
    if !parsed.is_object() {
        bail!("{field} must be a JSON object");
    }
    Ok(())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn optional_object_id(value: Option<&str>, field: &str) -> Result<()> {
    if value.is_some_and(|value| !valid_object_id(value)) {
        bail!("{field} must be a 40- or 64-byte hex object ID");
    }
    Ok(())
}

fn validate_run(input: &AgentRunUpsert) -> Result<()> {
    run_key(&input.hostname, &input.tool, &input.native_session_id)?;
    required(&input.status_reason, "status_reason")?;
    timestamp(&input.status_observed_at, "status_observed_at")?;
    timestamp(&input.started_at, "started_at")?;
    timestamp(&input.last_activity_at, "last_activity_at")?;
    optional_timestamp(input.ended_at.as_deref(), "ended_at")?;
    if input.projection_version <= 0 {
        bail!("projection_version must be positive");
    }
    optional_object_id(input.start_head_sha.as_deref(), "start_head_sha")?;
    optional_object_id(input.current_head_sha.as_deref(), "current_head_sha")?;
    json_object(&input.freshness_json, "freshness_json")?;
    json_object(&input.metadata_json, "run metadata_json")?;
    for (field, value) in [
        ("parent_run_key", input.parent_run_key.as_deref()),
        ("previous_run_key", input.previous_run_key.as_deref()),
        (
            "primary_worktree_key",
            input.primary_worktree_key.as_deref(),
        ),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            bail!("{field} must be non-empty when present");
        }
    }
    Ok(())
}

fn validate_actor(input: &AgentActorUpsert) -> Result<()> {
    required(&input.native_actor_id, "native_actor_id")?;
    optional_timestamp(input.started_at.as_deref(), "actor started_at")?;
    optional_timestamp(input.last_activity_at.as_deref(), "actor last_activity_at")?;
    optional_timestamp(input.ended_at.as_deref(), "actor ended_at")?;
    json_object(&input.metadata_json, "actor metadata_json")
}

fn validate_evidence(input: &AgentWorktreeEvidenceUpsert) -> Result<()> {
    required(&input.worktree_key, "evidence worktree_key")?;
    required(&input.evidence_kind, "evidence_kind")?;
    required(&input.evidence_source, "evidence_source")?;
    if !input.confidence.is_finite() || !(0.0..=1.0).contains(&input.confidence) {
        bail!("confidence must be between 0.0 and 1.0");
    }
    timestamp(&input.first_seen_at, "evidence first_seen_at")?;
    timestamp(&input.last_seen_at, "evidence last_seen_at")?;
    json_object(&input.metadata_json, "evidence metadata_json")
}

fn validate_trace_relation(input: &AgentTraceRelationUpsert) -> Result<()> {
    if !valid_hex_id(&input.trace_id, 32) || !valid_hex_id(&input.span_id, 16) {
        bail!("trace relation requires valid trace and span identifiers");
    }
    required(&input.identifier_namespace, "trace identifier_namespace")?;
    required(&input.evidence_kind, "trace evidence_kind")?;
    required(&input.reason, "trace relation reason")?;
    if !input.confidence.is_finite() || !(0.0..=1.0).contains(&input.confidence) {
        bail!("trace relation confidence must be between 0.0 and 1.0");
    }
    if input.projection_version <= 0 || !(0..=8).contains(&input.candidate_count) {
        bail!("trace relation version or candidate count is invalid");
    }
    timestamp(&input.observed_at, "trace relation observed_at")?;
    json_object(&input.metadata_json, "trace relation metadata_json")
}

fn valid_hex_id(value: &str, expected: usize) -> bool {
    value.len() == expected
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn validate_event(input: &AgentRunEventUpsert) -> Result<()> {
    event_key(
        &input.source_kind,
        &input.source_id,
        &input.projection_variant,
    )?;
    if input
        .worktree_key
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("event worktree_key must be non-empty when present");
    }
    timestamp(&input.observed_at, "event observed_at")?;
    timestamp(&input.ingested_at, "event ingested_at")?;
    if input.source_log_id.is_some_and(|value| value <= 0) {
        bail!("source_log_id must be positive when present");
    }
    if input.provider_sequence.is_some_and(|value| value < 0) {
        bail!("provider_sequence must be non-negative when present");
    }
    required(&input.severity, "severity")?;
    json_object(&input.payload_json, "event payload_json")
}

fn validate_outbox(input: &AgentProjectionOutboxInput) -> Result<()> {
    timestamp(&input.expires_at, "outbox expires_at")?;
    json_object(&input.payload_json, "outbox payload_json")
}

fn validate_input(input: &AgentProjectionWriteInput) -> Result<()> {
    validate_run(&input.run)?;
    if let Some(actor) = &input.actor {
        validate_actor(actor)?;
    }
    if let Some(evidence) = &input.worktree_evidence {
        validate_evidence(evidence)?;
    }
    if let Some(relation) = &input.trace_relation {
        validate_trace_relation(relation)?;
    }
    validate_event(&input.event)?;
    validate_outbox(&input.outbox)
}

fn digest_key(namespace: &str, values: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("v1:{namespace}:{:x}", hasher.finalize())
}

fn evidence_key(run_key: &str, input: &AgentWorktreeEvidenceUpsert) -> String {
    digest_key(
        "run_worktree_evidence",
        &[
            run_key,
            &input.worktree_key,
            &input.evidence_kind,
            &input.evidence_source,
        ],
    )
}

fn trace_relation_key(input: &AgentTraceRelationUpsert) -> String {
    digest_key(
        "trace_run_relation",
        &[&input.trace_id, &input.span_id, &input.identifier_namespace],
    )
}

fn outbox_key(input: &AgentProjectionWriteInput) -> Result<String> {
    let bytes = serde_json::to_vec(input).context("serialize projection input fingerprint")?;
    Ok(format!("v1:projection_outbox:{:x}", Sha256::digest(bytes)))
}

fn existing_run_event_outbox_key(event_key: &str) -> String {
    digest_key("repository_observation_outbox", &[event_key])
}

fn write_inner(
    pool: &DbPool,
    input: &AgentProjectionWriteInput,
    cursor: Option<(&str, &str)>,
    fault: Option<AgentProjectionWriteFault>,
) -> Result<AgentProjectionWriteResult> {
    validate_input(input)?;
    let canonical_tool = canonical_tool(&input.run.tool)?;
    let durable_run_key = run_key(
        &input.run.hostname,
        &canonical_tool,
        &input.run.native_session_id,
    )?;
    let durable_actor_key = input
        .actor
        .as_ref()
        .map(|actor| actor_key(&durable_run_key, &actor.native_actor_id))
        .transpose()?;
    let durable_event_key = event_key(
        &input.event.source_kind,
        &input.event.source_id,
        &input.event.projection_variant,
    )?;
    let durable_evidence_key = input
        .worktree_evidence
        .as_ref()
        .map(|evidence| evidence_key(&durable_run_key, evidence));
    let durable_trace_relation_key = input.trace_relation.as_ref().map(trace_relation_key);

    let mut connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let refs = sql::resolve_run_refs(&tx, &input.run)?;
    let (mut run, run_changed) =
        sql::upsert_run(&tx, &durable_run_key, &canonical_tool, &input.run, &refs)?;

    let (actor, actor_changed) = match (&input.actor, durable_actor_key.as_deref()) {
        (Some(actor), Some(key)) => {
            let (row, changed) = sql::upsert_actor(&tx, key, run.id, actor)?;
            (Some(row), changed)
        }
        (None, None) => (None, false),
        _ => unreachable!("actor input and key are constructed together"),
    };

    let (worktree_evidence, evidence_changed) =
        match (&input.worktree_evidence, durable_evidence_key.as_deref()) {
            (Some(evidence), Some(key)) => {
                let worktree_id = sql::worktree_id(&tx, &evidence.worktree_key)?;
                let (row, changed) = sql::upsert_evidence(&tx, key, run.id, worktree_id, evidence)?;
                (Some(row), changed)
            }
            (None, None) => (None, false),
            _ => unreachable!("evidence input and key are constructed together"),
        };

    let (trace_relation, trace_relation_changed) =
        match (&input.trace_relation, durable_trace_relation_key.as_deref()) {
            (Some(relation), Some(key)) => {
                let (row, changed) = sql::upsert_trace_relation(&tx, key, Some(run.id), relation)?;
                (Some(row), changed)
            }
            (None, None) => (None, false),
            _ => unreachable!("trace relation input and key are constructed together"),
        };

    let event_worktree_id = input
        .event
        .worktree_key
        .as_deref()
        .map(|key| sql::worktree_id(&tx, key))
        .transpose()?;
    let (event, event_inserted) = sql::insert_event(
        &tx,
        &durable_event_key,
        run.id,
        actor.as_ref().map(|row| row.id),
        event_worktree_id,
        &input.event,
    )?;

    if fault == Some(AgentProjectionWriteFault::EventInsert) {
        bail!("injected failure after event insert");
    }

    if event_inserted {
        run = counters::apply_event_counters(&tx, run.id, &event)?;
    }
    let materialized_state_changed = run_changed
        || actor_changed
        || evidence_changed
        || trace_relation_changed
        || event_inserted;
    let outbox = if materialized_state_changed {
        Some(sql::insert_outbox(
            &tx,
            &outbox_key(input)?,
            run.id,
            &input.outbox,
        )?)
    } else {
        None
    };
    if let Some((source_name, cursor)) = cursor {
        super::advance_projection_cursor_in_tx(&tx, source_name, cursor)?;
    }
    if fault == Some(AgentProjectionWriteFault::CursorAdvance) {
        bail!("injected failure after cursor advance");
    }
    tx.commit()?;
    if fault == Some(AgentProjectionWriteFault::Commit) {
        bail!("injected failure after commit");
    }

    Ok(AgentProjectionWriteResult {
        run,
        actor,
        worktree_evidence,
        trace_relation,
        event,
        event_inserted,
        materialized_state_changed,
        outbox,
    })
}

pub fn write_agent_projection(
    pool: &DbPool,
    input: &AgentProjectionWriteInput,
) -> Result<AgentProjectionWriteResult> {
    write_inner(pool, input, None, None)
}

pub(crate) fn write_agent_projection_with_cursor(
    pool: &DbPool,
    input: &AgentProjectionWriteInput,
    source_name: &str,
    cursor: &str,
) -> Result<AgentProjectionWriteResult> {
    write_inner(pool, input, Some((source_name, cursor)), None)
}

/// Atomically attach source evidence to a pre-existing run.  Unlike
/// [`write_agent_projection_with_cursor`], this does not upsert or refresh the
/// run: callers use it for sources (notably Git observations) that have no
/// native agent/session identity and therefore must not manufacture activity.
fn write_agent_existing_run_event_inner(
    pool: &DbPool,
    expected_run: &AgentRunRow,
    event: &AgentRunEventUpsert,
    outbox: &AgentProjectionOutboxInput,
    cursor: Option<(&str, &str)>,
) -> Result<AgentProjectionWriteResult> {
    required(&expected_run.run_key, "existing run_key")?;
    validate_event(event)?;
    validate_outbox(outbox)?;
    let durable_event_key = event_key(
        &event.source_kind,
        &event.source_id,
        &event.projection_variant,
    )?;
    let mut connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current_run = sql::run_by_id(&tx, expected_run.id)?;
    if current_run.run_key != expected_run.run_key {
        bail!("existing run identity changed before repository observation projection");
    }
    let event_worktree_id = event
        .worktree_key
        .as_deref()
        .map(|key| sql::worktree_id(&tx, key))
        .transpose()?;
    let (event_row, event_inserted) = sql::insert_event(
        &tx,
        &durable_event_key,
        current_run.id,
        None,
        event_worktree_id,
        event,
    )?;
    let run = if event_inserted {
        counters::apply_evidence_event_counters(&tx, current_run.id, &event_row)?
    } else {
        current_run
    };
    let outbox = if event_inserted {
        Some(sql::insert_outbox(
            &tx,
            &existing_run_event_outbox_key(&durable_event_key),
            run.id,
            outbox,
        )?)
    } else {
        None
    };
    if let Some((source_name, cursor)) = cursor {
        super::advance_projection_cursor_in_tx(&tx, source_name, cursor)?;
    }
    tx.commit()?;
    Ok(AgentProjectionWriteResult {
        run,
        actor: None,
        worktree_evidence: None,
        trace_relation: None,
        event: event_row,
        event_inserted,
        materialized_state_changed: event_inserted,
        outbox,
    })
}

pub(crate) fn write_agent_existing_run_event_with_cursor(
    pool: &DbPool,
    expected_run: &AgentRunRow,
    event: &AgentRunEventUpsert,
    outbox: &AgentProjectionOutboxInput,
    source_name: &str,
    cursor: &str,
) -> Result<AgentProjectionWriteResult> {
    write_agent_existing_run_event_inner(
        pool,
        expected_run,
        event,
        outbox,
        Some((source_name, cursor)),
    )
}

pub(crate) fn write_agent_existing_run_event(
    pool: &DbPool,
    expected_run: &AgentRunRow,
    event: &AgentRunEventUpsert,
    outbox: &AgentProjectionOutboxInput,
) -> Result<AgentProjectionWriteResult> {
    write_agent_existing_run_event_inner(pool, expected_run, event, outbox, None)
}

/// Record an explicit non-match or ambiguous trace conclusion when no run can
/// safely be projected.  It is intentionally durable instead of leaving a
/// read path to rediscover the same weak host/session coincidence.
pub(crate) fn write_agent_trace_relation_without_run(
    pool: &DbPool,
    input: &AgentTraceRelationUpsert,
) -> Result<AgentTraceRelationRow> {
    validate_trace_relation(input)?;
    let key = trace_relation_key(input);
    let mut connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (row, _) = sql::upsert_trace_relation(&tx, &key, None, input)?;
    tx.commit()?;
    Ok(row)
}

/// A later transcript/source projection may make a previously unmatchable
/// span exact. Reconcile a fixed page only; this is evidence repair, never a
/// timestamp-based association upgrade.
pub(crate) fn reconcile_unmatched_trace_relations(pool: &DbPool) -> Result<usize> {
    let connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let changed = connection.execute(
        "UPDATE agent_run_trace_relations
            SET run_id = (
                    SELECT ar.id FROM otel_spans os
                    JOIN agent_runs ar
                      ON ar.hostname = os.hostname
                     AND ar.tool = os.ai_tool
                     AND ar.native_session_id = os.ai_session_id
                   WHERE os.trace_id = agent_run_trace_relations.trace_id
                     AND os.span_id = agent_run_trace_relations.span_id
                 ),
                evidence_kind = 'exact_provider_id',
                confidence = 0.98,
                reason = 'late exact provider identity became available',
                candidate_count = 1
          WHERE id IN (
                SELECT relation.id
                  FROM agent_run_trace_relations relation
                  JOIN otel_spans os
                    ON os.trace_id = relation.trace_id AND os.span_id = relation.span_id
                  JOIN agent_runs ar
                    ON ar.hostname = os.hostname
                   AND ar.tool = os.ai_tool
                   AND ar.native_session_id = os.ai_session_id
                 WHERE relation.run_id IS NULL
                 ORDER BY relation.id
                 LIMIT 64
          )",
        [],
    )?;
    Ok(changed)
}

#[cfg(test)]
pub(super) fn write_agent_projection_with_fault(
    pool: &DbPool,
    input: &AgentProjectionWriteInput,
    fault: AgentProjectionWriteFault,
) -> Result<AgentProjectionWriteResult> {
    write_inner(pool, input, None, Some(fault))
}

#[cfg(test)]
pub(super) fn write_agent_projection_with_cursor_and_fault(
    pool: &DbPool,
    input: &AgentProjectionWriteInput,
    source_name: &str,
    cursor: &str,
    fault: AgentProjectionWriteFault,
) -> Result<AgentProjectionWriteResult> {
    write_inner(pool, input, Some((source_name, cursor)), Some(fault))
}

#[cfg(test)]
#[path = "agent_observatory_projection_tests.rs"]
mod tests;
