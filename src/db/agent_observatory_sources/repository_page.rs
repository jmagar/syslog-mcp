//! Repository-observation source paging.

use anyhow::Result;
use rusqlite::params;

use super::{AgentRepositoryObservationSourceRow, AgentSourceRecord};

pub(super) fn repository_observation_page(
    conn: &rusqlite::Connection,
    after: i64,
    limit: i64,
) -> Result<Vec<AgentSourceRecord>> {
    let mut stmt = conn.prepare(
        "SELECT o.id, o.observation_key, r.repository_key, r.display_name, r.hostname,
                w.worktree_key, w.path, o.observed_at, o.observation_kind,
                o.old_head_sha, o.new_head_sha, o.summary, o.payload_json
           FROM repository_observations o
           JOIN repositories r ON r.id = o.repository_id
      LEFT JOIN repository_worktrees w ON w.id = o.worktree_id
          WHERE o.id > ?1
          ORDER BY o.id
          LIMIT ?2",
    )?;
    Ok(stmt
        .query_map(params![after, limit], |row| {
            Ok(AgentSourceRecord::RepositoryObservation(
                AgentRepositoryObservationSourceRow {
                    cursor_id: row.get(0)?,
                    observation_key: row.get(1)?,
                    repository_key: row.get(2)?,
                    repository_name: row.get(3)?,
                    hostname: row.get(4)?,
                    worktree_key: row.get(5)?,
                    worktree_path: row.get(6)?,
                    observed_at: row.get(7)?,
                    observation_kind: row.get(8)?,
                    old_head_sha: row.get(9)?,
                    new_head_sha: row.get(10)?,
                    summary: row.get(11)?,
                    payload_json: row.get(12)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<_>>()?)
}
