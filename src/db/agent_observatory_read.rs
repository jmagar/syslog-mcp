//! Bounded, cursor-oriented reads for Agent Observatory service surfaces.

use super::DbPool;
use anyhow::{Context, Result};
use rusqlite::{Row, params_from_iter, types::Value};
#[path = "agent_observatory_read_cursor.rs"]
mod cursor;
use cursor::{bounded_limit, int_cursor, push_filter, text_cursor};
#[path = "agent_observatory_read_models.rs"]
mod models;
pub use models::*;

pub fn list_observatory_repositories(
    pool: &DbPool,
    query: &RepositoryQuery,
    cursor: Option<(&str, i64)>,
    limit: usize,
    high_water: i64,
) -> Result<Vec<ObservatoryRepositoryRow>> {
    let conn = pool.get()?;
    let mut values = Vec::new();
    let mut sql = "SELECT r.id,r.repository_key,r.hostname,r.primary_path,r.display_name,r.first_seen_at,r.last_seen_at,r.removed_at,(SELECT COUNT(*) FROM repository_worktrees w WHERE w.repository_id=r.id),(SELECT COUNT(*) FROM agent_runs a JOIN agent_run_worktrees rw ON rw.run_id=a.id JOIN repository_worktrees w ON w.id=rw.worktree_id WHERE w.repository_id=r.id AND a.status IN ('starting','active','waiting','idle')) FROM repositories r WHERE 1=1".to_string();
    push_filter(&mut sql, &mut values, "r.id <= ?", high_water);
    if !query.include_removed {
        sql.push_str(" AND r.removed_at IS NULL");
    }
    if let Some(v) = &query.host {
        push_filter(&mut sql, &mut values, "r.hostname = ?", v.clone());
    }
    if let Some(v) = &query.query {
        push_filter(
            &mut sql,
            &mut values,
            "(r.display_name LIKE ? OR r.primary_path LIKE ?)",
            format!("%{v}%"),
        );
        values.push(format!("%{v}%").into());
    }
    if query.active_runs_only {
        sql.push_str(" AND EXISTS (SELECT 1 FROM agent_runs a JOIN agent_run_worktrees rw ON rw.run_id=a.id JOIN repository_worktrees w ON w.id=rw.worktree_id WHERE w.repository_id=r.id AND a.status IN ('starting','active','waiting','idle'))");
    }
    if let Some(v) = &query.since {
        push_filter(&mut sql, &mut values, "r.last_seen_at >= ?", v.clone());
    }
    if let Some(v) = &query.until {
        push_filter(&mut sql, &mut values, "r.last_seen_at <= ?", v.clone());
    }
    text_cursor(
        &mut sql,
        &mut values,
        ("r.last_seen_at", "r.id"),
        cursor,
        false,
    );
    sql.push_str(" ORDER BY r.last_seen_at DESC,r.id DESC LIMIT ?");
    values.push(((bounded_limit(limit, 200) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), |r| {
            Ok(ObservatoryRepositoryRow {
                id: r.get(0)?,
                key: r.get(1)?,
                hostname: r.get(2)?,
                primary_path: r.get(3)?,
                name: r.get(4)?,
                first_seen_at: r.get(5)?,
                last_seen_at: r.get(6)?,
                removed_at: r.get(7)?,
                worktree_count: r.get(8)?,
                active_run_count: r.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory repositories")
}

#[allow(clippy::too_many_arguments)]
pub fn list_observatory_worktrees(
    pool: &DbPool,
    repository_id: i64,
    branch: Option<&str>,
    dirty: Option<bool>,
    include_removed: bool,
    cursor: Option<(&str, i64)>,
    limit: usize,
    high_water: i64,
) -> Result<Vec<ObservatoryWorktreeRow>> {
    let conn = pool.get()?;
    let mut values = vec![repository_id.into()];
    let mut sql="SELECT id,worktree_key,repository_id,hostname,path,branch_ref,branch_name,head_sha,upstream_ref,detached,bare,locked,lock_reason,prunable,prune_reason,dirty,staged_count,unstaged_count,untracked_count,ahead,behind,first_seen_at,last_seen_at,removed_at FROM repository_worktrees WHERE repository_id=?".to_string();
    push_filter(&mut sql, &mut values, "id <= ?", high_water);
    if !include_removed {
        sql.push_str(" AND removed_at IS NULL");
    }
    if let Some(v) = branch {
        push_filter(&mut sql, &mut values, "branch_name = ?", v.to_owned());
    }
    if let Some(v) = dirty {
        push_filter(&mut sql, &mut values, "dirty = ?", v);
    }
    text_cursor(&mut sql, &mut values, ("last_seen_at", "id"), cursor, false);
    sql.push_str(" ORDER BY last_seen_at DESC,id DESC LIMIT ?");
    values.push(((bounded_limit(limit, 200) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), |r| {
            Ok(ObservatoryWorktreeRow {
                id: r.get(0)?,
                key: r.get(1)?,
                repository_id: r.get(2)?,
                hostname: r.get(3)?,
                path: r.get(4)?,
                branch_ref: r.get(5)?,
                branch: r.get(6)?,
                head_sha: r.get(7)?,
                upstream_ref: r.get(8)?,
                detached: r.get(9)?,
                bare: r.get(10)?,
                locked: r.get(11)?,
                lock_reason: r.get(12)?,
                prunable: r.get(13)?,
                prune_reason: r.get(14)?,
                dirty: r.get(15)?,
                staged: r.get(16)?,
                unstaged: r.get(17)?,
                untracked: r.get(18)?,
                ahead: r.get(19)?,
                behind: r.get(20)?,
                first_seen_at: r.get(21)?,
                last_seen_at: r.get(22)?,
                removed_at: r.get(23)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory worktrees")
}

pub fn list_observatory_runs(
    pool: &DbPool,
    q: &AgentRunQuery,
    cursor: Option<(&str, i64)>,
    limit: usize,
    high_water: i64,
) -> Result<Vec<ObservatoryRunRow>> {
    let conn = pool.get()?;
    let mut values = Vec::new();
    let mut sql="SELECT DISTINCT a.id,a.run_key,a.native_session_id,a.tool,a.provider_tool,a.hostname,a.status,a.status_reason,a.status_observed_at,a.started_at,a.last_activity_at,a.ended_at,a.transcript_path,a.primary_worktree_id,a.primary_branch,a.start_head_sha,a.current_head_sha,a.event_count,a.error_count,a.freshness_json FROM agent_runs a WHERE 1=1".to_string();
    push_filter(&mut sql, &mut values, "a.id <= ?", high_water);
    if let Some(id) = q.worktree_id {
        push_filter(
            &mut sql,
            &mut values,
            "EXISTS(SELECT 1 FROM agent_run_worktrees rw WHERE rw.run_id=a.id AND rw.worktree_id=?)",
            id,
        );
    }
    if let Some(id) = q.repository_id {
        push_filter(
            &mut sql,
            &mut values,
            "EXISTS(SELECT 1 FROM agent_run_worktrees rw JOIN repository_worktrees w ON w.id=rw.worktree_id WHERE rw.run_id=a.id AND w.repository_id=?)",
            id,
        );
    }
    if let Some(v) = &q.branch {
        push_filter(&mut sql, &mut values, "a.primary_branch = ?", v.clone());
    }
    if let Some(v) = &q.host {
        push_filter(&mut sql, &mut values, "a.hostname = ?", v.clone());
    }
    if !q.statuses.is_empty() {
        sql.push_str(&format!(
            " AND a.status IN ({})",
            vec!["?"; q.statuses.len()].join(",")
        ));
        values.extend(q.statuses.iter().cloned().map(Value::from));
    }
    if !q.tools.is_empty() {
        sql.push_str(&format!(
            " AND a.tool IN ({})",
            vec!["?"; q.tools.len()].join(",")
        ));
        values.extend(q.tools.iter().cloned().map(Value::from));
    }
    if q.active_only {
        sql.push_str(" AND a.status IN ('starting','active','waiting','idle')");
    }
    if let Some(v) = &q.query {
        push_filter(
            &mut sql,
            &mut values,
            "(a.run_key LIKE ? OR a.native_session_id LIKE ? OR a.metadata_json LIKE ?)",
            format!("%{v}%"),
        );
        values.push(format!("%{v}%").into());
        values.push(format!("%{v}%").into());
    }
    if let Some(v) = &q.since {
        push_filter(&mut sql, &mut values, "a.last_activity_at >= ?", v.clone());
    }
    if let Some(v) = &q.until {
        push_filter(&mut sql, &mut values, "a.last_activity_at <= ?", v.clone());
    }
    text_cursor(
        &mut sql,
        &mut values,
        ("a.last_activity_at", "a.id"),
        cursor,
        false,
    );
    sql.push_str(" ORDER BY a.last_activity_at DESC,a.id DESC LIMIT ?");
    values.push(((bounded_limit(limit, 200) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), run_row)?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory runs")
}
fn run_row(r: &Row<'_>) -> rusqlite::Result<ObservatoryRunRow> {
    Ok(ObservatoryRunRow {
        id: r.get(0)?,
        run_key: r.get(1)?,
        native_session_id: r.get(2)?,
        tool: r.get(3)?,
        provider_tool: r.get(4)?,
        hostname: r.get(5)?,
        status: r.get(6)?,
        status_reason: r.get(7)?,
        status_observed_at: r.get(8)?,
        started_at: r.get(9)?,
        last_activity_at: r.get(10)?,
        ended_at: r.get(11)?,
        transcript_path: r.get(12)?,
        primary_worktree_id: r.get(13)?,
        primary_branch: r.get(14)?,
        start_head_sha: r.get(15)?,
        current_head_sha: r.get(16)?,
        event_count: r.get(17)?,
        error_count: r.get(18)?,
        freshness_json: r.get(19)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn list_observatory_events(
    pool: &DbPool,
    run_key: &str,
    q: &AgentEventQuery,
    cursor: Option<(&str, i64)>,
    limit: usize,
    asc: bool,
    high_water: i64,
) -> Result<Vec<ObservatoryEventRow>> {
    let conn = pool.get()?;
    let mut values = vec![run_key.to_owned().into()];
    let payload = if q.include_payload {
        "e.payload_json"
    } else {
        "NULL"
    };
    let mut sql = format!(
        "SELECT e.id,e.event_key,a.run_key,aa.actor_key,e.worktree_id,g.sha,e.observed_at,e.ingested_at,e.event_kind,e.source_kind,e.source_id,e.source_log_id,e.provider_sequence,e.trace_id,e.span_id,e.severity,e.title,e.summary,{payload},e.content_scrubbed FROM agent_run_events e JOIN agent_runs a ON a.id=e.run_id LEFT JOIN agent_run_actors aa ON aa.id=e.actor_id LEFT JOIN git_commits g ON g.id=e.commit_id WHERE a.run_key=?"
    );
    push_filter(&mut sql, &mut values, "e.id <= ?", high_water);
    if !q.kinds.is_empty() {
        sql.push_str(&format!(
            " AND e.event_kind IN ({})",
            vec!["?"; q.kinds.len()].join(",")
        ));
        values.extend(q.kinds.iter().cloned().map(Value::from));
    }
    if let Some(v) = &q.actor_key {
        push_filter(&mut sql, &mut values, "aa.actor_key = ?", v.clone());
    }
    if let Some(v) = &q.trace_id {
        push_filter(&mut sql, &mut values, "e.trace_id = ?", v.clone());
    }
    if let Some(v) = &q.query {
        push_filter(
            &mut sql,
            &mut values,
            "(e.title LIKE ? OR e.summary LIKE ?)",
            format!("%{v}%"),
        );
        values.push(format!("%{v}%").into());
    }
    if let Some(v) = &q.since {
        push_filter(&mut sql, &mut values, "e.observed_at >= ?", v.clone());
    }
    if let Some(v) = &q.until {
        push_filter(&mut sql, &mut values, "e.observed_at <= ?", v.clone());
    }
    if let Some(v) = q.severity_min {
        push_filter(
            &mut sql,
            &mut values,
            "CASE e.severity WHEN 'emerg' THEN 7 WHEN 'alert' THEN 6 WHEN 'crit' THEN 5 WHEN 'err' THEN 4 WHEN 'warning' THEN 3 WHEN 'notice' THEN 2 WHEN 'info' THEN 1 ELSE 0 END >= ?",
            v,
        );
    }
    text_cursor(
        &mut sql,
        &mut values,
        ("e.observed_at", "e.id"),
        cursor,
        asc,
    );
    let order = if asc { "ASC" } else { "DESC" };
    sql.push_str(&format!(
        " ORDER BY e.observed_at {order},e.id {order} LIMIT ?"
    ));
    values.push(((bounded_limit(limit, 500) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), |r| {
            Ok(ObservatoryEventRow {
                id: r.get(0)?,
                event_key: r.get(1)?,
                run_key: r.get(2)?,
                actor_key: r.get(3)?,
                worktree_id: r.get(4)?,
                commit_sha: r.get(5)?,
                observed_at: r.get(6)?,
                ingested_at: r.get(7)?,
                kind: r.get(8)?,
                source_kind: r.get(9)?,
                source_id: r.get(10)?,
                source_log_id: r.get(11)?,
                provider_sequence: r.get(12)?,
                trace_id: r.get(13)?,
                span_id: r.get(14)?,
                severity: r.get(15)?,
                title: r.get(16)?,
                summary: r.get(17)?,
                payload_json: r.get(18)?,
                content_scrubbed: r.get(19)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory events")
}

pub fn list_observatory_spans(
    pool: &DbPool,
    run_id: i64,
    _identity: &RunTelemetryIdentity,
    q: &TelemetryQuery,
    cursor: Option<(i64, i64)>,
    limit: usize,
    high_water: i64,
) -> Result<Vec<ObservatorySpanRow>> {
    let conn = pool.get()?;
    let mut values = vec![run_id.into()];
    let mut sql="SELECT os.id,os.trace_id,os.span_id,os.parent_span_id,os.span_name,os.span_kind,os.start_time_unix_nano,os.end_time_unix_nano,os.duration_nano,os.status_code,os.status_message,os.service_name,os.attributes_json,r.identifier_namespace,r.evidence_kind,r.confidence,r.reason,r.candidate_count FROM agent_run_trace_relations r JOIN otel_spans os ON os.trace_id=r.trace_id AND os.span_id=r.span_id WHERE r.run_id=?".to_string();
    push_filter(&mut sql, &mut values, "os.id <= ?", high_water);
    if let Some(v) = &q.trace_id {
        push_filter(&mut sql, &mut values, "os.trace_id=?", v.clone());
    }
    if let Some(v) = q.since_nano {
        push_filter(&mut sql, &mut values, "os.start_time_unix_nano>=?", v);
    }
    if let Some(v) = q.until_nano {
        push_filter(&mut sql, &mut values, "os.start_time_unix_nano<=?", v);
    }
    int_cursor(
        &mut sql,
        &mut values,
        ("os.start_time_unix_nano", "os.id"),
        cursor,
        false,
    );
    sql.push_str(" ORDER BY os.start_time_unix_nano DESC,os.id DESC LIMIT ?");
    values.push(((bounded_limit(limit, 500) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), |r| {
            Ok(ObservatorySpanRow {
                id: r.get(0)?,
                trace_id: r.get(1)?,
                span_id: r.get(2)?,
                parent_span_id: r.get(3)?,
                name: r.get(4)?,
                kind: r.get(5)?,
                start_time_unix_nano: r.get(6)?,
                end_time_unix_nano: r.get(7)?,
                duration_nano: r.get(8)?,
                status_code: r.get(9)?,
                status_message: r.get(10)?,
                service_name: r.get(11)?,
                attributes_json: r.get(12)?,
                relation_namespace: r.get(13)?,
                relation_evidence_kind: r.get(14)?,
                relation_confidence: r.get(15)?,
                relation_reason: r.get(16)?,
                relation_candidate_count: r.get(17)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory spans")
}
pub fn list_observatory_metrics(
    pool: &DbPool,
    run_id: i64,
    identity: &RunTelemetryIdentity,
    q: &TelemetryQuery,
    cursor: Option<(i64, i64)>,
    limit: usize,
    high_water: i64,
) -> Result<Vec<ObservatoryMetricRow>> {
    let conn = pool.get()?;
    let mut values = vec![
        run_id.into(),
        identity.hostname.clone().into(),
        identity.native_session_id.clone().into(),
        identity.tool.clone().into(),
        identity.provider_tool.clone().unwrap_or_default().into(),
    ];
    let mut sql="SELECT id,point_key,metric_name,description,unit,instrument_kind,start_time_unix_nano,time_unix_nano,value_json,attributes_json,exemplars_json FROM otel_metric_points WHERE (run_id=? OR (run_id IS NULL AND hostname=? AND ai_session_id=? AND (ai_tool=? OR ai_tool=?) AND (SELECT COUNT(*) FROM agent_runs ar WHERE ar.hostname=otel_metric_points.hostname AND ar.native_session_id=otel_metric_points.ai_session_id AND (ar.tool=otel_metric_points.ai_tool OR ar.provider_tool=otel_metric_points.ai_tool))=1))".to_string();
    push_filter(&mut sql, &mut values, "id <= ?", high_water);
    if let Some(v) = &q.metric_name {
        push_filter(&mut sql, &mut values, "metric_name=?", v.clone());
    }
    if let Some(v) = q.since_nano {
        push_filter(&mut sql, &mut values, "time_unix_nano>=?", v);
    }
    if let Some(v) = q.until_nano {
        push_filter(&mut sql, &mut values, "time_unix_nano<=?", v);
    }
    int_cursor(
        &mut sql,
        &mut values,
        ("time_unix_nano", "id"),
        cursor,
        false,
    );
    sql.push_str(" ORDER BY time_unix_nano DESC,id DESC LIMIT ?");
    values.push(((bounded_limit(limit, 500) + 1) as i64).into());
    conn.prepare(&sql)?
        .query_map(params_from_iter(values), |r| {
            Ok(ObservatoryMetricRow {
                id: r.get(0)?,
                point_key: r.get(1)?,
                metric_name: r.get(2)?,
                description: r.get(3)?,
                unit: r.get(4)?,
                instrument_kind: r.get(5)?,
                start_time_unix_nano: r.get(6)?,
                time_unix_nano: r.get(7)?,
                value_json: r.get(8)?,
                attributes_json: r.get(9)?,
                exemplars_json: r.get(10)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("list observatory metrics")
}

#[cfg(test)]
#[path = "agent_observatory_read_tests.rs"]
mod tests;
