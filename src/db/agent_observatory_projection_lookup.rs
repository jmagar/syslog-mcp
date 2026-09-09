//! Read-side lookups used by Agent Observatory source projectors.

use super::super::AgentRunRow;
use super::sql;
use crate::agent_observatory::identity::canonical_tool;
use crate::db::agent_observatory::EvidenceTrustLevel;
use crate::db::pool::DbPool;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rusqlite::params;
use std::path::{Component, Path};

const ACTIVE_REPOSITORY_OBSERVATION_WINDOW_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProjectionWorktreeRef {
    pub id: i64,
    pub worktree_key: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentProjectionRunMatch {
    None,
    Unique(Box<AgentRunRow>),
    Ambiguous,
}

/// The only admissible repository-observation attachment: an existing run
/// with persisted worktree evidence that was current at the observation time.
/// Repository data never supplies a tool/session identity of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRepositoryObservationRunAssociation {
    pub run: Box<AgentRunRow>,
    pub evidence_kind: String,
    pub evidence_source: String,
    pub evidence_trust: EvidenceTrustLevel,
    pub evidence_confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentRepositoryObservationRunMatch {
    None,
    Unique(Box<AgentRepositoryObservationRunAssociation>),
    Ambiguous,
}

fn parse_timestamp(value: &str, label: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid {label}: {value}"))?
        .with_timezone(&Utc))
}

fn association_is_current(
    observed_at: DateTime<Utc>,
    run: &AgentRunRow,
    evidence_first_seen_at: &str,
    evidence_last_seen_at: &str,
) -> Result<bool> {
    let started = parse_timestamp(&run.started_at, "run started_at")?;
    if started > observed_at {
        return Ok(false);
    }
    if let Some(ended_at) = run.ended_at.as_deref()
        && parse_timestamp(ended_at, "run ended_at")? < observed_at
    {
        return Ok(false);
    }
    let mut latest = started;
    for (value, label) in [
        (run.last_activity_at.as_str(), "run last_activity_at"),
        (evidence_first_seen_at, "worktree evidence first_seen_at"),
        (evidence_last_seen_at, "worktree evidence last_seen_at"),
    ] {
        let timestamp = parse_timestamp(value, label)?;
        if timestamp <= observed_at && timestamp > latest {
            latest = timestamp;
        }
    }
    Ok(observed_at.signed_duration_since(latest)
        <= Duration::seconds(ACTIVE_REPOSITORY_OBSERVATION_WINDOW_SECS))
}

/// Resolve one current run from durable worktree evidence.  The source is
/// intentionally rejected when two runs are plausible; choosing by timestamp
/// or recency would manufacture an agent identity from Git state.
pub fn find_unique_projection_run_for_repository_observation(
    pool: &DbPool,
    worktree_key: &str,
    observed_at: &str,
) -> Result<AgentRepositoryObservationRunMatch> {
    if worktree_key.trim().is_empty() {
        bail!("repository observation worktree_key must be non-empty");
    }
    let observed = parse_timestamp(observed_at, "repository observation observed_at")?;
    let connection = pool.get().context("acquire database connection")?;
    let mut statement = connection.prepare(
        "WITH ranked_candidates AS (
             SELECT r.id, e.evidence_kind, e.evidence_source, e.trust_level, e.confidence,
                    e.first_seen_at, e.last_seen_at,
                    ROW_NUMBER() OVER (
                      PARTITION BY r.id
                      ORDER BY e.confidence DESC, e.last_seen_at DESC, e.id
                    ) AS evidence_rank
               FROM agent_runs r
               JOIN agent_run_worktrees e ON e.run_id = r.id
               JOIN repository_worktrees w ON w.id = e.worktree_id
              WHERE w.worktree_key = ?1
                AND e.first_seen_at <= ?2
                AND r.started_at <= ?2
                AND (r.ended_at IS NULL OR r.ended_at >= ?2)
                AND e.trust_level != 'refuted'
           )
           SELECT id, evidence_kind, evidence_source, trust_level, confidence,
                  first_seen_at, last_seen_at
             FROM ranked_candidates
            WHERE evidence_rank = 1
            ORDER BY id
            LIMIT 2",
    )?;
    let candidates = statement
        .query_map(params![worktree_key, observed_at], |row| {
            let trust: String = row.get(3)?;
            let evidence_trust = trust.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                evidence_trust,
                row.get::<_, f64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut matches = Vec::new();
    for (
        run_id,
        evidence_kind,
        evidence_source,
        evidence_trust,
        evidence_confidence,
        first,
        last,
    ) in candidates
    {
        let run = sql::run_by_id(&connection, run_id)?;
        if association_is_current(observed, &run, &first, &last)? {
            matches.push(AgentRepositoryObservationRunAssociation {
                run: Box::new(run),
                evidence_kind,
                evidence_source,
                evidence_trust,
                evidence_confidence,
            });
        }
    }
    match matches.len() {
        0 => Ok(AgentRepositoryObservationRunMatch::None),
        1 => Ok(AgentRepositoryObservationRunMatch::Unique(Box::new(
            matches.pop().expect("length checked"),
        ))),
        _ => Ok(AgentRepositoryObservationRunMatch::Ambiguous),
    }
}

fn canonical_absolute(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

pub fn find_active_projection_worktree(
    pool: &DbPool,
    hostname: &str,
    path: &str,
) -> Result<Option<AgentProjectionWorktreeRef>> {
    if hostname.trim().is_empty() {
        bail!("hostname must be non-empty");
    }
    if !canonical_absolute(path) {
        bail!("worktree path must be canonical and absolute");
    }
    let connection = pool.get().context("acquire database connection")?;
    let mut statement = connection.prepare(
        "SELECT id, worktree_key, path FROM repository_worktrees
          WHERE hostname = ?1
            AND removed_at IS NULL
            AND (
              path = ?2
              OR path = '/'
              OR (
                length(?2) > length(path)
                AND substr(?2, 1, length(path)) = path
                AND substr(?2, length(path) + 1, 1) = '/'
              )
            )
          ORDER BY length(path) DESC, id
          LIMIT 1",
    )?;
    let rows = statement
        .query_map(params![hostname.trim(), path], |row| {
            Ok(AgentProjectionWorktreeRef {
                id: row.get(0)?,
                worktree_key: row.get(1)?,
                path: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows.into_iter().next())
}

pub fn find_unique_overlapping_projection_run(
    pool: &DbPool,
    hostname: &str,
    observed_at: &str,
) -> Result<AgentProjectionRunMatch> {
    if hostname.trim().is_empty() {
        bail!("hostname must be non-empty");
    }
    chrono::DateTime::parse_from_rfc3339(observed_at)
        .with_context(|| format!("invalid observed_at: {observed_at}"))?;
    let connection = pool.get().context("acquire database connection")?;
    let mut statement = connection.prepare(
        "SELECT id FROM agent_runs
          WHERE hostname = ?1
            AND started_at <= ?2
            AND last_activity_at >= ?2
            AND status IN ('starting','active','waiting','idle','stale')
          ORDER BY id LIMIT 2",
    )?;
    let ids = statement
        .query_map(params![hostname.trim(), observed_at], |row| {
            row.get::<_, i64>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match ids.as_slice() {
        [] => Ok(AgentProjectionRunMatch::None),
        [id] => Ok(AgentProjectionRunMatch::Unique(Box::new(sql::run_by_id(
            &connection,
            *id,
        )?))),
        _ => Ok(AgentProjectionRunMatch::Ambiguous),
    }
}

pub fn find_unique_projection_run_by_session(
    pool: &DbPool,
    tool: &str,
    session_id: &str,
) -> Result<AgentProjectionRunMatch> {
    if tool.trim().is_empty() {
        bail!("tool must be non-empty");
    }
    if session_id.trim().is_empty() {
        bail!("session_id must be non-empty");
    }
    let canonical_tool = canonical_tool(tool)?;
    let connection = pool.get().context("acquire database connection")?;
    let mut statement = connection.prepare(
        "SELECT id FROM agent_runs
          WHERE tool = ?1
            AND native_session_id = ?2
            AND status IN ('starting','active','waiting','idle','stale')
          ORDER BY id LIMIT 2",
    )?;
    let ids = statement
        .query_map(params![canonical_tool, session_id.trim()], |row| {
            row.get::<_, i64>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match ids.as_slice() {
        [] => Ok(AgentProjectionRunMatch::None),
        [id] => Ok(AgentProjectionRunMatch::Unique(Box::new(sql::run_by_id(
            &connection,
            *id,
        )?))),
        _ => Ok(AgentProjectionRunMatch::Ambiguous),
    }
}
