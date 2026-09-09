//! Idempotency lookups for source projections with summary evidence.

use anyhow::{Context, Result};

use crate::agent_observatory::identity::event_key;
use crate::db::pool::DbPool;

pub(crate) fn projection_event_has_summary(
    pool: &DbPool,
    source_kind: &str,
    source_id: &str,
    projection_variant: &str,
    summary: &str,
) -> Result<bool> {
    let key = event_key(source_kind, source_id, projection_variant)?;
    let connection = pool.get().context("acquire database connection")?;
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM agent_run_events
              WHERE event_key = ?1 AND summary = ?2
         )",
        rusqlite::params![key, summary],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}
