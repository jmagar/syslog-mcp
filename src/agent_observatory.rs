//! Agent Observatory domain constants and coordination entry points.

pub mod attribution;
pub mod backfill;
pub mod classifier;
pub mod git_attribution;
pub mod identity;
pub mod lifecycle;
pub mod projector;

/// Schema version reached after all planned Agent Observatory migrations.
///
/// This is intentionally separate from `db::KNOWN_SCHEMA_VERSION` so the
/// Observatory contract keeps an explicit schema revision.
pub const AGENT_OBSERVATORY_SCHEMA_VERSION: i64 = 48;

/// Version of the durable Agent Observatory projection contract.
pub const AGENT_OBSERVATORY_PROJECTION_VERSION: u32 = 1;

/// Maximum number of canonical log rows fetched by one projector cycle.
/// Processing remains independently bounded by `projector_page_bytes`.
pub const AGENT_OBSERVATORY_LOG_PAGE_MAX: usize = 2_000;

#[cfg(test)]
#[path = "agent_observatory_tests.rs"]
mod tests;
