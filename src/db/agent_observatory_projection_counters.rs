//! Run counter updates for atomic Agent Observatory projection writes.

use super::super::{AgentRunEventRow, AgentRunRow};
use super::sql;
use anyhow::Result;
use rusqlite::{Transaction, params};

pub(super) fn apply_event_counters(
    tx: &Transaction<'_>,
    run_id: i64,
    event: &AgentRunEventRow,
) -> Result<AgentRunRow> {
    let error_increment = i64::from(event.severity == "err");
    tx.execute(
        "UPDATE agent_runs SET last_event_id=?1, event_count=event_count+1,
             error_count=error_count+?2,
             first_source_log_id=CASE
                 WHEN ?3 IS NULL THEN first_source_log_id
                 WHEN first_source_log_id IS NULL OR first_source_log_id > ?3 THEN ?3
                 ELSE first_source_log_id END,
             last_source_log_id=CASE
                 WHEN ?3 IS NULL THEN last_source_log_id
                 WHEN last_source_log_id IS NULL OR last_source_log_id < ?3 THEN ?3
                 ELSE last_source_log_id END,
             last_activity_at=MAX(last_activity_at, ?4),
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?5",
        params![
            event.id,
            error_increment,
            event.source_log_id,
            event.observed_at,
            run_id
        ],
    )?;
    sql::run_by_id(tx, run_id)
}

/// Repository observations are evidence *about* a run, not proof that the
/// agent did work at the Git-observer timestamp.  Keep their event counters
/// and replay cursor durable without extending the run's activity/lifecycle.
pub(super) fn apply_evidence_event_counters(
    tx: &Transaction<'_>,
    run_id: i64,
    event: &AgentRunEventRow,
) -> Result<AgentRunRow> {
    let error_increment = i64::from(event.severity == "err");
    tx.execute(
        "UPDATE agent_runs SET last_event_id=?1, event_count=event_count+1,
             error_count=error_count+?2,
             first_source_log_id=CASE
                 WHEN ?3 IS NULL THEN first_source_log_id
                 WHEN first_source_log_id IS NULL OR first_source_log_id > ?3 THEN ?3
                 ELSE first_source_log_id END,
             last_source_log_id=CASE
                 WHEN ?3 IS NULL THEN last_source_log_id
                 WHEN last_source_log_id IS NULL OR last_source_log_id < ?3 THEN ?3
                 ELSE last_source_log_id END,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?4",
        params![event.id, error_increment, event.source_log_id, run_id],
    )?;
    sql::run_by_id(tx, run_id)
}
