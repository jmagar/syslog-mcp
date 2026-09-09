//! Resumable Agent Observatory source replay and Git-attribution repair.

use super::git_attribution::attribute_exact_commits;
use super::projector::{SourceProjectionOutcome, project_agent_source, project_log_row};
use crate::db::agent_observatory::{
    AgentSourceKind, GitCommitRow, list_git_commits, page_agent_sources,
};
use crate::db::{
    DbPool, get_maintenance_job, insert_maintenance_job_with_result, page_agent_projection_logs,
};
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[path = "backfill/persistence.rs"]
mod persistence;
use persistence::persist;

const JOB_KIND: &str = "agent_observatory_backfill";
const STATE_VERSION: u32 = 1;
const MAX_CHUNK_ROWS: usize = 500;
const SOURCE_COUNT: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentBackfillHighWater {
    pub logs: i64,
    pub mcp_events: i64,
    pub hook_events: i64,
    pub skill_events: i64,
    pub llm_invocations: String,
    #[serde(default)]
    pub otel_spans: i64,
    #[serde(default)]
    pub otel_metric_points: i64,
    pub repository_observations: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentBackfillCursors {
    pub logs: i64,
    pub mcp_events: String,
    pub hook_events: String,
    pub skill_events: String,
    pub llm_invocations: String,
    #[serde(default)]
    pub otel_spans: String,
    #[serde(default)]
    pub otel_metric_points: String,
    /// Separate from the Git-attribution repair cursor below.  Repository
    /// observations are a projected source as well as a HEAD-repair input.
    #[serde(default)]
    pub repository_observation_events: String,
    pub repository_observations: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBackfillProgress {
    pub version: u32,
    pub source_index: u8,
    pub high_water: AgentBackfillHighWater,
    pub cursors: AgentBackfillCursors,
    pub source_rows_scanned: u64,
    pub source_rows_projected: u64,
    pub observations_scanned: u64,
    pub commit_relations_written: u64,
    pub done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBackfillJob {
    pub job_id: i64,
    pub status: String,
    pub progress: AgentBackfillProgress,
}

#[derive(Debug, Deserialize)]
struct LlmCursor {
    #[serde(alias = "started_at")]
    ready_at: String,
    id: String,
}

#[derive(Debug)]
struct HeadObservation {
    id: i64,
    observation_key: String,
    repository_id: i64,
    worktree_id: Option<i64>,
    observed_at: String,
    old_head_sha: Option<String>,
    new_head_sha: Option<String>,
    payload_json: String,
}

fn max_id(connection: &rusqlite::Connection, table: &str) -> Result<i64> {
    let sql = format!("SELECT COALESCE(MAX(id), 0) FROM {table}");
    Ok(connection.query_row(&sql, [], |row| row.get(0))?)
}

fn llm_high_water(connection: &rusqlite::Connection) -> Result<String> {
    let row = connection
        .query_row(
            "SELECT finished_at, id FROM llm_invocations
              WHERE finished_at IS NOT NULL ORDER BY finished_at DESC, id DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    row.map_or_else(
        || Ok(String::new()),
        |(ready_at, id)| {
            serde_json::to_string(&serde_json::json!({ "ready_at": ready_at, "id": id }))
                .map_err(Into::into)
        },
    )
}

fn capture_high_water(pool: &DbPool) -> Result<AgentBackfillHighWater> {
    let mut connection = pool.get().context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let high_water = AgentBackfillHighWater {
        logs: max_id(&tx, "logs")?,
        mcp_events: max_id(&tx, "ai_mcp_events")?,
        hook_events: max_id(&tx, "ai_hook_events")?,
        skill_events: max_id(&tx, "ai_skill_events")?,
        llm_invocations: llm_high_water(&tx)?,
        otel_spans: max_id(&tx, "otel_spans")?,
        otel_metric_points: max_id(&tx, "otel_metric_points")?,
        repository_observations: max_id(&tx, "repository_observations")?,
    };
    tx.commit()?;
    Ok(high_water)
}

fn encode(progress: &AgentBackfillProgress) -> Result<String> {
    serde_json::to_string(progress).context("serialize Agent Observatory backfill progress")
}

fn decode(raw: &str) -> Result<AgentBackfillProgress> {
    let progress: AgentBackfillProgress =
        serde_json::from_str(raw).context("parse Agent Observatory backfill progress")?;
    if progress.version != STATE_VERSION {
        bail!(
            "unsupported Agent Observatory backfill state version {}",
            progress.version
        );
    }
    Ok(progress)
}

pub fn start_agent_backfill(pool: &DbPool) -> Result<AgentBackfillJob> {
    let progress = AgentBackfillProgress {
        version: STATE_VERSION,
        source_index: 0,
        high_water: capture_high_water(pool)?,
        cursors: AgentBackfillCursors::default(),
        source_rows_scanned: 0,
        source_rows_projected: 0,
        observations_scanned: 0,
        commit_relations_written: 0,
        done: false,
    };
    let job_id = insert_maintenance_job_with_result(pool, JOB_KIND, &encode(&progress)?)?;
    Ok(AgentBackfillJob {
        job_id,
        status: "running".to_string(),
        progress,
    })
}

pub fn get_agent_backfill(pool: &DbPool, job_id: i64) -> Result<AgentBackfillJob> {
    let job = get_maintenance_job(pool, job_id)?
        .with_context(|| format!("Agent Observatory backfill job {job_id} not found"))?;
    if job.kind != JOB_KIND {
        bail!("maintenance job {job_id} is not an Agent Observatory backfill");
    }
    let raw = job
        .result_json
        .as_deref()
        .context("Agent Observatory backfill is missing progress")?;
    Ok(AgentBackfillJob {
        job_id,
        status: job.status,
        progress: decode(raw)?,
    })
}

fn numeric_at_or_before(cursor: &str, high_water: i64) -> Result<bool> {
    let value = cursor
        .parse::<i64>()
        .with_context(|| format!("invalid numeric backfill cursor {cursor}"))?;
    Ok(value <= high_water)
}

fn llm_at_or_before(cursor: &str, high_water: &str) -> Result<bool> {
    if high_water.is_empty() {
        return Ok(false);
    }
    let cursor: LlmCursor = serde_json::from_str(cursor).context("invalid LLM backfill cursor")?;
    let high: LlmCursor =
        serde_json::from_str(high_water).context("invalid LLM high-water cursor")?;
    Ok(
        (cursor.ready_at.as_str(), cursor.id.as_str())
            <= (high.ready_at.as_str(), high.id.as_str()),
    )
}

fn process_logs(
    pool: &DbPool,
    progress: &mut AgentBackfillProgress,
    budget: usize,
) -> Result<(usize, bool)> {
    if progress.cursors.logs >= progress.high_water.logs {
        return Ok((0, true));
    }
    let page = page_agent_projection_logs(pool, progress.cursors.logs, budget.min(MAX_CHUNK_ROWS))?;
    if page.is_empty() {
        return Ok((0, true));
    }
    let mut consumed = 0usize;
    for row in page {
        if row.id > progress.high_water.logs {
            return Ok((consumed, true));
        }
        progress.source_rows_scanned += 1;
        progress.source_rows_projected += u64::from(project_log_row(pool, &row)?);
        progress.cursors.logs = row.id;
        consumed += 1;
        if row.id == progress.high_water.logs {
            return Ok((consumed, true));
        }
    }
    Ok((consumed, false))
}

fn source_cursor_mut(progress: &mut AgentBackfillProgress, kind: AgentSourceKind) -> &mut String {
    match kind {
        AgentSourceKind::Mcp => &mut progress.cursors.mcp_events,
        AgentSourceKind::Hook => &mut progress.cursors.hook_events,
        AgentSourceKind::Skill => &mut progress.cursors.skill_events,
        AgentSourceKind::Llm => &mut progress.cursors.llm_invocations,
        AgentSourceKind::OtelSpan => &mut progress.cursors.otel_spans,
        AgentSourceKind::OtelMetric => &mut progress.cursors.otel_metric_points,
        AgentSourceKind::RepositoryObservation => {
            &mut progress.cursors.repository_observation_events
        }
    }
}

fn source_high_water(progress: &AgentBackfillProgress, kind: AgentSourceKind) -> String {
    match kind {
        AgentSourceKind::Mcp => progress.high_water.mcp_events.to_string(),
        AgentSourceKind::Hook => progress.high_water.hook_events.to_string(),
        AgentSourceKind::Skill => progress.high_water.skill_events.to_string(),
        AgentSourceKind::Llm => progress.high_water.llm_invocations.clone(),
        AgentSourceKind::OtelSpan => progress.high_water.otel_spans.to_string(),
        AgentSourceKind::OtelMetric => progress.high_water.otel_metric_points.to_string(),
        AgentSourceKind::RepositoryObservation => {
            progress.high_water.repository_observations.to_string()
        }
    }
}

fn cursor_at_or_before(kind: AgentSourceKind, cursor: &str, high_water: &str) -> Result<bool> {
    match kind {
        AgentSourceKind::Llm => llm_at_or_before(cursor, high_water),
        _ => numeric_at_or_before(cursor, high_water.parse::<i64>()?),
    }
}

fn process_source(
    pool: &DbPool,
    progress: &mut AgentBackfillProgress,
    kind: AgentSourceKind,
    budget: usize,
) -> Result<(usize, bool)> {
    let high_water = source_high_water(progress, kind);
    if high_water.is_empty() || high_water == "0" {
        return Ok((0, true));
    }
    let after = source_cursor_mut(progress, kind).clone();
    if after == high_water {
        return Ok((0, true));
    }
    let page = page_agent_sources(pool, kind, &after, budget.min(MAX_CHUNK_ROWS))?;
    if page.records.is_empty() {
        return Ok((0, true));
    }
    let mut consumed = 0usize;
    for record in page.records {
        let next = record.next_cursor();
        if !cursor_at_or_before(kind, &next, &high_water)? {
            return Ok((consumed, true));
        }
        progress.source_rows_scanned += 1;
        if matches!(
            project_agent_source(pool, &record)?,
            SourceProjectionOutcome::Projected(_)
        ) {
            progress.source_rows_projected += 1;
        }
        *source_cursor_mut(progress, kind) = next.clone();
        consumed += 1;
        if next == high_water {
            return Ok((consumed, true));
        }
    }
    Ok((consumed, false))
}

fn head_observations(
    pool: &DbPool,
    after: i64,
    high_water: i64,
    limit: usize,
) -> Result<Vec<HeadObservation>> {
    let connection = pool.get().context("acquire database connection")?;
    let mut statement = connection.prepare(
        "SELECT id, observation_key, repository_id, worktree_id, observed_at, old_head_sha,
                new_head_sha, payload_json
           FROM repository_observations
          WHERE id > ?1 AND id <= ?2 AND observation_kind = 'head'
          ORDER BY id LIMIT ?3",
    )?;
    Ok(statement
        .query_map(params![after, high_water, i64::try_from(limit)?], |row| {
            Ok(HeadObservation {
                id: row.get(0)?,
                observation_key: row.get(1)?,
                repository_id: row.get(2)?,
                worktree_id: row.get(3)?,
                observed_at: row.get(4)?,
                old_head_sha: row.get(5)?,
                new_head_sha: row.get(6)?,
                payload_json: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn observation_commit_shas(observation: &HeadObservation) -> Result<Vec<String>> {
    let payload: Value = serde_json::from_str(&observation.payload_json)
        .context("parse HEAD observation payload")?;
    Ok(payload
        .get("new_commit_shas")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }))
}

fn reachable_shas(
    commits: &HashMap<String, GitCommitRow>,
    start_sha: &str,
) -> Result<HashSet<String>> {
    let mut reachable = HashSet::new();
    let mut pending = vec![start_sha.to_string()];
    while let Some(sha) = pending.pop() {
        if !reachable.insert(sha.clone()) {
            continue;
        }
        let Some(commit) = commits.get(&sha) else {
            continue;
        };
        let parents: Vec<String> = serde_json::from_str(&commit.parent_shas_json)
            .with_context(|| format!("invalid parent_shas_json for commit {sha}"))?;
        pending.extend(parents);
    }
    Ok(reachable)
}

fn legacy_transition_commits(
    pool: &DbPool,
    observation: &HeadObservation,
) -> Result<Vec<GitCommitRow>> {
    let Some(new_head) = observation.new_head_sha.as_deref() else {
        return Ok(Vec::new());
    };
    let commits = list_git_commits(pool, observation.repository_id)?;
    let by_sha = commits
        .iter()
        .cloned()
        .map(|commit| (commit.sha.clone(), commit))
        .collect::<HashMap<_, _>>();
    let new_reachable = reachable_shas(&by_sha, new_head)?;
    let old_reachable = observation
        .old_head_sha
        .as_deref()
        .map(|old_head| reachable_shas(&by_sha, old_head))
        .transpose()?
        .unwrap_or_default();
    Ok(commits
        .into_iter()
        .filter(|commit| {
            new_reachable.contains(&commit.sha) && !old_reachable.contains(&commit.sha)
        })
        .collect())
}

fn observation_commits(pool: &DbPool, observation: &HeadObservation) -> Result<Vec<GitCommitRow>> {
    let shas = observation_commit_shas(observation)?;
    if shas.is_empty() {
        return legacy_transition_commits(pool, observation);
    }
    let mut commits = Vec::with_capacity(shas.len());
    for sha in shas {
        if let Some(commit) = crate::db::agent_observatory::git_commit_by_repository_sha(
            pool,
            observation.repository_id,
            &sha,
        )? {
            commits.push(commit);
        }
    }
    Ok(commits)
}

fn process_observations(
    pool: &DbPool,
    progress: &mut AgentBackfillProgress,
    budget: usize,
) -> Result<(usize, bool)> {
    if progress.cursors.repository_observations >= progress.high_water.repository_observations {
        return Ok((0, true));
    }
    let rows = head_observations(
        pool,
        progress.cursors.repository_observations,
        progress.high_water.repository_observations,
        budget.min(MAX_CHUNK_ROWS),
    )?;
    if rows.is_empty() {
        progress.cursors.repository_observations = progress.high_water.repository_observations;
        return Ok((0, true));
    }
    let mut consumed = 0usize;
    for observation in rows {
        progress.observations_scanned += 1;
        if let (Some(worktree_id), Some(new_head_sha)) =
            (observation.worktree_id, observation.new_head_sha.as_deref())
        {
            let commits = observation_commits(pool, &observation)?;
            progress.commit_relations_written += u64::try_from(attribute_exact_commits(
                pool,
                worktree_id,
                &observation.observation_key,
                &observation.observed_at,
                observation.old_head_sha.as_deref(),
                new_head_sha,
                &commits,
            )?)?;
        }
        progress.cursors.repository_observations = observation.id;
        consumed += 1;
    }
    let done =
        progress.cursors.repository_observations >= progress.high_water.repository_observations;
    Ok((consumed, done))
}

/// Process at most `row_budget` durable source/HEAD rows and persist progress.
/// Calling this repeatedly resumes from the last durable job checkpoint.
pub fn run_agent_backfill_chunk(
    pool: &DbPool,
    job_id: i64,
    row_budget: usize,
) -> Result<AgentBackfillJob> {
    if row_budget == 0 || row_budget > MAX_CHUNK_ROWS {
        bail!("row_budget must be between 1 and {MAX_CHUNK_ROWS}");
    }
    let mut job = get_agent_backfill(pool, job_id)?;
    if job.progress.done {
        return Ok(job);
    }
    if job.status != "running" {
        bail!("Agent Observatory backfill job is not running");
    }
    let mut remaining = row_budget;
    while remaining > 0 && job.progress.source_index < SOURCE_COUNT {
        let (used, done) = match job.progress.source_index {
            0 => process_logs(pool, &mut job.progress, remaining)?,
            1 => process_source(pool, &mut job.progress, AgentSourceKind::Mcp, remaining)?,
            2 => process_source(pool, &mut job.progress, AgentSourceKind::Hook, remaining)?,
            3 => process_source(pool, &mut job.progress, AgentSourceKind::Skill, remaining)?,
            4 => process_source(pool, &mut job.progress, AgentSourceKind::Llm, remaining)?,
            5 => process_source(
                pool,
                &mut job.progress,
                AgentSourceKind::OtelSpan,
                remaining,
            )?,
            6 => process_source(
                pool,
                &mut job.progress,
                AgentSourceKind::OtelMetric,
                remaining,
            )?,
            _ => unreachable!(),
        };
        remaining = remaining.saturating_sub(used);
        if done {
            job.progress.source_index += 1;
        }
        if used == 0 && !done {
            break;
        }
    }
    while remaining > 0 && job.progress.source_index == SOURCE_COUNT {
        let (used, done) = process_observations(pool, &mut job.progress, remaining)?;
        remaining = remaining.saturating_sub(used);
        if done {
            job.progress.done = true;
            break;
        }
        if used == 0 {
            break;
        }
    }
    persist(pool, job_id, &job.progress)?;
    job.status = if job.progress.done {
        "done".to_string()
    } else {
        "running".to_string()
    };
    Ok(job)
}

#[cfg(test)]
#[path = "backfill_tests.rs"]
mod tests;
