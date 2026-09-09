//! Durable checkpoint persistence for the resumable backfill job.

use anyhow::Result;

use super::{AgentBackfillProgress, DbPool, encode};
use crate::db::{finish_maintenance_job, update_maintenance_job_progress};

pub(super) fn persist(pool: &DbPool, job_id: i64, progress: &AgentBackfillProgress) -> Result<()> {
    let encoded = encode(progress)?;
    if progress.done {
        finish_maintenance_job(pool, job_id, "done", &encoded)
    } else {
        update_maintenance_job_progress(pool, job_id, &encoded)
    }
}
