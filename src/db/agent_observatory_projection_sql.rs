//! SQL primitives for one atomic Agent Observatory projection write.

use super::super::{AgentRunEventRow, AgentRunRow, AgentRunWorktreeEvidenceRow};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(super) use super::refs::{RunRefs, resolve_run_refs, worktree_id};
use super::types::{
    AgentActorRow, AgentActorUpsert, AgentProjectionOutboxInput, AgentProjectionOutboxRow,
    AgentRunEventUpsert, AgentRunUpsert, AgentTraceRelationRow, AgentTraceRelationUpsert,
    AgentWorktreeEvidenceUpsert,
};

const RUN_COLUMNS: &str = "id, run_key, native_session_id, tool, provider_tool, hostname,
 parent_run_id, previous_run_id, primary_worktree_id, transcript_path, process_id, status,
 status_reason, status_observed_at, started_at, last_activity_at, ended_at,
 first_source_log_id, last_source_log_id, last_event_id, event_count, error_count,
 primary_branch, start_head_sha, current_head_sha, projection_version, freshness_json,
 metadata_json, created_at, updated_at";
const ACTOR_COLUMNS: &str = "id, actor_key, run_id, native_actor_id, actor_type, display_name,
 started_at, last_activity_at, ended_at, metadata_json";
const EVIDENCE_COLUMNS: &str = "id, relation_key, run_id, worktree_id, evidence_kind,
 evidence_source, trust_level, confidence, is_primary, first_seen_at, last_seen_at,
 metadata_json";
const EVENT_COLUMNS: &str = "id, event_key, run_id, actor_id, worktree_id, commit_id,
 observed_at, ingested_at, event_kind, source_kind, source_id, source_log_id,
 provider_sequence, trace_id, span_id, severity, title, summary, payload_json,
 content_scrubbed, created_at";
const OUTBOX_COLUMNS: &str = "id, outbox_key, run_id, stream_event_type, expires_at,
 payload_json, created_at";
const TRACE_RELATION_COLUMNS: &str = "id, relation_key, trace_id, span_id, run_id,
 identifier_namespace, provider, evidence_kind, confidence, reason, projection_version,
 candidate_count, observed_at, metadata_json";

#[path = "agent_observatory_projection_sql_rows.rs"]
mod rows;
use rows::{actor_row, event_row, evidence_row, outbox_row, run_row, trace_relation_row};

pub(super) fn run_id(tx: &Transaction<'_>, key: &str) -> Result<Option<i64>> {
    tx.query_row(
        "SELECT id FROM agent_runs WHERE run_key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .context("query run ID")
}

pub(super) fn upsert_run(
    tx: &Transaction<'_>,
    key: &str,
    canonical_tool: &str,
    input: &AgentRunUpsert,
    refs: &RunRefs,
) -> Result<(AgentRunRow, bool)> {
    let select_sql = format!("SELECT {RUN_COLUMNS} FROM agent_runs WHERE run_key = ?1");
    let existing = tx.query_row(&select_sql, [key], run_row).optional()?;
    let activity_wins = existing.as_ref().is_none_or(|row| {
        super::tie_break::run_activity_wins(input, refs.primary_worktree_id, row)
    });
    let status_wins = existing
        .as_ref()
        .is_none_or(|row| super::tie_break::run_status_wins(input, row));
    tx.execute(
        "INSERT INTO agent_runs
            (run_key, native_session_id, tool, provider_tool, hostname, parent_run_id,
             previous_run_id, primary_worktree_id, transcript_path, process_id, status,
             status_reason, status_observed_at, started_at, last_activity_at, ended_at,
             primary_branch, start_head_sha, current_head_sha, projection_version,
             freshness_json, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)
         ON CONFLICT(run_key) DO UPDATE SET
             provider_tool=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.provider_tool, agent_runs.provider_tool)
                 ELSE agent_runs.provider_tool END,
             parent_run_id=COALESCE(agent_runs.parent_run_id, excluded.parent_run_id),
             previous_run_id=COALESCE(agent_runs.previous_run_id, excluded.previous_run_id),
             primary_worktree_id=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.primary_worktree_id, agent_runs.primary_worktree_id)
                 ELSE agent_runs.primary_worktree_id END,
             transcript_path=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.transcript_path, agent_runs.transcript_path)
                 ELSE agent_runs.transcript_path END,
             process_id=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.process_id, agent_runs.process_id)
                 ELSE agent_runs.process_id END,
             status=CASE
                 WHEN ?24
                 THEN excluded.status ELSE agent_runs.status END,
             status_reason=CASE
                 WHEN ?24
                 THEN excluded.status_reason ELSE agent_runs.status_reason END,
             status_observed_at=MAX(agent_runs.status_observed_at, excluded.status_observed_at),
             started_at=MIN(agent_runs.started_at, excluded.started_at),
             last_activity_at=MAX(agent_runs.last_activity_at, excluded.last_activity_at),
             ended_at=CASE
                 WHEN excluded.ended_at IS NULL THEN agent_runs.ended_at
                 WHEN agent_runs.ended_at IS NULL THEN excluded.ended_at
                 ELSE MAX(agent_runs.ended_at, excluded.ended_at) END,
             primary_branch=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.primary_branch, agent_runs.primary_branch)
                 ELSE agent_runs.primary_branch END,
             start_head_sha=COALESCE(agent_runs.start_head_sha, excluded.start_head_sha),
             current_head_sha=CASE
                 WHEN ?23
                 THEN COALESCE(excluded.current_head_sha, agent_runs.current_head_sha)
                 ELSE agent_runs.current_head_sha END,
             projection_version=MAX(agent_runs.projection_version, excluded.projection_version),
             freshness_json=CASE
                 WHEN ?23
                 THEN excluded.freshness_json ELSE agent_runs.freshness_json END,
             metadata_json=CASE
                 WHEN ?23
                 THEN excluded.metadata_json ELSE agent_runs.metadata_json END,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE (?23 AND (
                 agent_runs.provider_tool IS NOT
                     COALESCE(excluded.provider_tool, agent_runs.provider_tool)
              OR agent_runs.primary_worktree_id IS NOT
                     COALESCE(excluded.primary_worktree_id, agent_runs.primary_worktree_id)
              OR agent_runs.transcript_path IS NOT
                     COALESCE(excluded.transcript_path, agent_runs.transcript_path)
              OR agent_runs.process_id IS NOT
                     COALESCE(excluded.process_id, agent_runs.process_id)
              OR agent_runs.primary_branch IS NOT
                     COALESCE(excluded.primary_branch, agent_runs.primary_branch)
              OR agent_runs.current_head_sha IS NOT
                     COALESCE(excluded.current_head_sha, agent_runs.current_head_sha)
              OR agent_runs.freshness_json IS NOT excluded.freshness_json
              OR agent_runs.metadata_json IS NOT excluded.metadata_json))
            OR (?24 AND (
                 agent_runs.status IS NOT excluded.status
              OR agent_runs.status_reason IS NOT excluded.status_reason
              OR agent_runs.status_observed_at IS NOT excluded.status_observed_at))
            OR (agent_runs.parent_run_id IS NULL AND excluded.parent_run_id IS NOT NULL)
            OR (agent_runs.previous_run_id IS NULL AND excluded.previous_run_id IS NOT NULL)
            OR agent_runs.started_at > excluded.started_at
            OR agent_runs.last_activity_at < excluded.last_activity_at
            OR (excluded.ended_at IS NOT NULL AND (
                agent_runs.ended_at IS NULL OR agent_runs.ended_at < excluded.ended_at))
            OR (agent_runs.start_head_sha IS NULL AND excluded.start_head_sha IS NOT NULL)
            OR agent_runs.projection_version < excluded.projection_version",
        params![
            key,
            input.native_session_id,
            canonical_tool,
            input.provider_tool,
            input.hostname,
            refs.parent_run_id,
            refs.previous_run_id,
            refs.primary_worktree_id,
            input.transcript_path,
            input.process_id,
            input.status.as_str(),
            input.status_reason,
            input.status_observed_at,
            input.started_at,
            input.last_activity_at,
            input.ended_at,
            input.primary_branch,
            input.start_head_sha,
            input.current_head_sha,
            input.projection_version,
            input.freshness_json,
            input.metadata_json,
            activity_wins,
            status_wins
        ],
    )?;
    let changed = tx.changes() > 0;
    let row = tx.query_row(&select_sql, [key], run_row)?;
    if row.hostname != input.hostname
        || row.tool != canonical_tool
        || row.native_session_id != input.native_session_id
    {
        bail!("run identity conflict for key {key}");
    }
    Ok((row, changed))
}

pub(super) fn upsert_actor(
    tx: &Transaction<'_>,
    key: &str,
    run_id: i64,
    input: &AgentActorUpsert,
) -> Result<(AgentActorRow, bool)> {
    let select_sql = format!("SELECT {ACTOR_COLUMNS} FROM agent_run_actors WHERE actor_key = ?1");
    let existing = tx.query_row(&select_sql, [key], actor_row).optional()?;
    let actor_wins = existing
        .as_ref()
        .is_none_or(|row| super::tie_break::actor_wins(input, row));
    tx.execute(
        "INSERT INTO agent_run_actors
            (actor_key, run_id, native_actor_id, actor_type, display_name, started_at,
             last_activity_at, ended_at, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(actor_key) DO UPDATE SET
             actor_type=CASE WHEN ?10 THEN excluded.actor_type ELSE agent_run_actors.actor_type END,
             display_name=CASE WHEN ?10 THEN excluded.display_name ELSE agent_run_actors.display_name END,
             started_at=CASE WHEN agent_run_actors.started_at IS NULL THEN excluded.started_at WHEN excluded.started_at IS NULL THEN agent_run_actors.started_at ELSE MIN(agent_run_actors.started_at, excluded.started_at) END,
             last_activity_at=CASE WHEN agent_run_actors.last_activity_at IS NULL THEN excluded.last_activity_at WHEN excluded.last_activity_at IS NULL THEN agent_run_actors.last_activity_at ELSE MAX(agent_run_actors.last_activity_at, excluded.last_activity_at) END,
             ended_at=CASE WHEN agent_run_actors.ended_at IS NULL THEN excluded.ended_at WHEN excluded.ended_at IS NULL THEN agent_run_actors.ended_at ELSE MAX(agent_run_actors.ended_at, excluded.ended_at) END,
             metadata_json=CASE WHEN ?10 THEN excluded.metadata_json ELSE agent_run_actors.metadata_json END
         WHERE (?10 AND (
                agent_run_actors.actor_type IS NOT excluded.actor_type
             OR agent_run_actors.display_name IS NOT excluded.display_name
             OR agent_run_actors.metadata_json IS NOT excluded.metadata_json))
            OR (excluded.started_at IS NOT NULL AND (
                agent_run_actors.started_at IS NULL OR agent_run_actors.started_at > excluded.started_at))
            OR (excluded.last_activity_at IS NOT NULL AND (
                agent_run_actors.last_activity_at IS NULL OR agent_run_actors.last_activity_at < excluded.last_activity_at))
            OR (excluded.ended_at IS NOT NULL AND (
                agent_run_actors.ended_at IS NULL OR agent_run_actors.ended_at < excluded.ended_at))",
        params![
            key,
            run_id,
            input.native_actor_id,
            input.actor_type,
            input.display_name,
            input.started_at,
            input.last_activity_at,
            input.ended_at,
            input.metadata_json,
            actor_wins
        ],
    )?;
    let changed = tx.changes() > 0;
    let row = tx.query_row(&select_sql, [key], actor_row)?;
    if row.run_id != run_id || row.native_actor_id != input.native_actor_id {
        bail!("actor identity conflict for key {key}");
    }
    Ok((row, changed))
}

pub(super) fn upsert_evidence(
    tx: &Transaction<'_>,
    key: &str,
    run_id: i64,
    worktree_id: i64,
    input: &AgentWorktreeEvidenceUpsert,
) -> Result<(AgentRunWorktreeEvidenceRow, bool)> {
    let select_sql =
        format!("SELECT {EVIDENCE_COLUMNS} FROM agent_run_worktrees WHERE relation_key = ?1");
    let existing = tx.query_row(&select_sql, [key], evidence_row).optional()?;
    let evidence_wins = existing
        .as_ref()
        .is_none_or(|row| super::tie_break::evidence_wins(input, row));
    tx.execute(
        "INSERT INTO agent_run_worktrees
            (relation_key, run_id, worktree_id, evidence_kind, evidence_source, trust_level,
             confidence, is_primary, first_seen_at, last_seen_at, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(relation_key) DO UPDATE SET
             trust_level=CASE WHEN ?12 THEN excluded.trust_level ELSE agent_run_worktrees.trust_level END,
             confidence=CASE WHEN ?12 THEN excluded.confidence ELSE agent_run_worktrees.confidence END,
             is_primary=CASE WHEN ?12 THEN excluded.is_primary ELSE agent_run_worktrees.is_primary END,
             first_seen_at=MIN(agent_run_worktrees.first_seen_at, excluded.first_seen_at),
             last_seen_at=MAX(agent_run_worktrees.last_seen_at, excluded.last_seen_at),
             metadata_json=CASE WHEN ?12 THEN excluded.metadata_json ELSE agent_run_worktrees.metadata_json END
         WHERE (?12 AND (
                agent_run_worktrees.trust_level IS NOT excluded.trust_level
             OR agent_run_worktrees.confidence IS NOT excluded.confidence
             OR agent_run_worktrees.is_primary IS NOT excluded.is_primary
             OR agent_run_worktrees.metadata_json IS NOT excluded.metadata_json))
            OR agent_run_worktrees.first_seen_at > excluded.first_seen_at
            OR agent_run_worktrees.last_seen_at < excluded.last_seen_at",
        params![
            key,
            run_id,
            worktree_id,
            input.evidence_kind,
            input.evidence_source,
            input.trust_level.as_str(),
            input.confidence,
            input.is_primary,
            input.first_seen_at,
            input.last_seen_at,
            input.metadata_json,
            evidence_wins
        ],
    )?;
    let changed = tx.changes() > 0;
    let row = tx.query_row(&select_sql, [key], evidence_row)?;
    if row.run_id != run_id
        || row.worktree_id != worktree_id
        || row.evidence_kind != input.evidence_kind
        || row.evidence_source != input.evidence_source
    {
        bail!("worktree evidence identity conflict for key {key}");
    }
    Ok((row, changed))
}

pub(super) fn insert_event(
    tx: &Transaction<'_>,
    key: &str,
    run_id: i64,
    actor_id: Option<i64>,
    worktree_id: Option<i64>,
    input: &AgentRunEventUpsert,
) -> Result<(AgentRunEventRow, bool)> {
    tx.execute(
        "INSERT INTO agent_run_events
            (event_key, run_id, actor_id, worktree_id, observed_at, ingested_at, event_kind,
             source_kind, source_id, source_log_id, provider_sequence, trace_id, span_id,
             severity, title, summary, payload_json, content_scrubbed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18)
         ON CONFLICT(event_key) DO NOTHING",
        params![
            key,
            run_id,
            actor_id,
            worktree_id,
            input.observed_at,
            input.ingested_at,
            input.event_kind.as_str(),
            input.source_kind,
            input.source_id,
            input.source_log_id,
            input.provider_sequence,
            input.trace_id,
            input.span_id,
            input.severity,
            input.title,
            input.summary,
            input.payload_json,
            input.content_scrubbed
        ],
    )?;
    let inserted = tx.changes() > 0;
    let sql = format!("SELECT {EVENT_COLUMNS} FROM agent_run_events WHERE event_key = ?1");
    let row = tx.query_row(&sql, [key], event_row)?;
    if row.run_id != run_id
        || row.source_kind != input.source_kind
        || row.source_id != input.source_id
        || row.event_kind != input.event_kind
        || row.actor_id != actor_id
        || row.worktree_id != worktree_id
        || row.observed_at != input.observed_at
        || row.ingested_at != input.ingested_at
        || row.source_log_id != input.source_log_id
        || row.provider_sequence != input.provider_sequence
        || row.trace_id != input.trace_id
        || row.span_id != input.span_id
        || row.severity != input.severity
        || row.title != input.title
        || row.summary != input.summary
        || row.payload_json != input.payload_json
        || row.content_scrubbed != input.content_scrubbed
    {
        bail!("event identity conflict for key {key}");
    }
    Ok((row, inserted))
}

pub(super) fn upsert_trace_relation(
    tx: &Transaction<'_>,
    key: &str,
    run_id: Option<i64>,
    input: &AgentTraceRelationUpsert,
) -> Result<(AgentTraceRelationRow, bool)> {
    let select_sql = format!(
        "SELECT {TRACE_RELATION_COLUMNS} FROM agent_run_trace_relations WHERE relation_key = ?1"
    );
    tx.execute(
        "INSERT INTO agent_run_trace_relations
            (relation_key, trace_id, span_id, run_id, identifier_namespace, provider,
             evidence_kind, confidence, reason, projection_version, candidate_count,
             observed_at, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(relation_key) DO UPDATE SET
             run_id=excluded.run_id,
             provider=excluded.provider,
             evidence_kind=excluded.evidence_kind,
             confidence=excluded.confidence,
             reason=excluded.reason,
             projection_version=MAX(agent_run_trace_relations.projection_version, excluded.projection_version),
             candidate_count=excluded.candidate_count,
             observed_at=MAX(agent_run_trace_relations.observed_at, excluded.observed_at),
             metadata_json=excluded.metadata_json
         WHERE agent_run_trace_relations.run_id IS NOT excluded.run_id
            OR agent_run_trace_relations.provider IS NOT excluded.provider
            OR agent_run_trace_relations.evidence_kind IS NOT excluded.evidence_kind
            OR agent_run_trace_relations.confidence IS NOT excluded.confidence
            OR agent_run_trace_relations.reason IS NOT excluded.reason
            OR agent_run_trace_relations.projection_version < excluded.projection_version
            OR agent_run_trace_relations.candidate_count IS NOT excluded.candidate_count
            OR agent_run_trace_relations.observed_at < excluded.observed_at
            OR agent_run_trace_relations.metadata_json IS NOT excluded.metadata_json",
        params![
            key,
            input.trace_id,
            input.span_id,
            run_id,
            input.identifier_namespace,
            input.provider,
            input.evidence_kind,
            input.confidence,
            input.reason,
            input.projection_version,
            input.candidate_count,
            input.observed_at,
            input.metadata_json,
        ],
    )?;
    let changed = tx.changes() > 0;
    let row = tx.query_row(&select_sql, [key], trace_relation_row)?;
    if row.trace_id != input.trace_id || row.span_id != input.span_id {
        bail!("trace relation identity conflict for key {key}");
    }
    Ok((row, changed))
}

pub(super) fn run_by_id(connection: &Connection, run_id: i64) -> Result<AgentRunRow> {
    let sql = format!("SELECT {RUN_COLUMNS} FROM agent_runs WHERE id = ?1");
    connection
        .query_row(&sql, [run_id], run_row)
        .context("query run by ID")
}

pub(super) fn insert_outbox(
    tx: &Transaction<'_>,
    key: &str,
    run_id: i64,
    input: &AgentProjectionOutboxInput,
) -> Result<AgentProjectionOutboxRow> {
    tx.execute(
        "INSERT INTO agent_stream_outbox
            (outbox_key, run_id, stream_event_type, expires_at, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(outbox_key) DO NOTHING",
        params![
            key,
            run_id,
            input.event_name.as_str(),
            input.expires_at,
            input.payload_json
        ],
    )?;
    let sql = format!("SELECT {OUTBOX_COLUMNS} FROM agent_stream_outbox WHERE outbox_key = ?1");
    tx.query_row(&sql, [key], outbox_row)
        .context("query projection outbox row")
}
