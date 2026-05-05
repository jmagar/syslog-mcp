use std::sync::Arc;

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::db::DbPool;

pub(super) fn load_checkpoint(
    pool: &Arc<DbPool>,
    host_name: &str,
    container_id: &str,
) -> Result<Option<String>> {
    let conn = pool.get()?;
    let value = conn
        .query_row(
            "SELECT last_timestamp
             FROM docker_ingest_checkpoints
             WHERE host_name = ?1 AND container_id = ?2",
            params![host_name, container_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value)
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
