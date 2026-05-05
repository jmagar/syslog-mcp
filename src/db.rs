#![allow(unused_imports)]

mod ingest;
mod maintenance;
mod models;
mod pool;
mod queries;

pub use ingest::insert_logs_batch;
pub use maintenance::{
    enforce_storage_budget, get_storage_metrics, purge_old_logs, DiskSpaceProbe,
};
pub use models::{
    DbStats, DockerCheckpoint, ErrorSummaryEntry, HostEntry, LogBatchEntry, LogEntry, SearchParams,
};
pub use models::{StorageBudgetState, StorageEnforcementOutcome, StorageMetrics, StorageRecovery};
pub use pool::{init_pool, DbPool};
pub use queries::{
    get_error_summary, get_stats, list_hosts, search_logs, severity_to_num, tail_logs,
    validate_fts_query, SEVERITY_LEVELS,
};
