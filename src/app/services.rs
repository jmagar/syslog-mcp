use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::{TimeDelta, Utc};
use parking_lot::Mutex;
use tokio::sync::Semaphore;

const DB_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const SLOW_DB_MS: u128 = 500;

use super::correlate::{group_by_host, severity_at_or_above};
use super::models::{
    AbuseAssessRequest, AbuseAssessResponse, AbuseSearchRequest, AbuseSearchResponse,
    AiAssessEvidenceSummary, AiAssessRequest, AiAssessResponse, AiCorrelateLimitPolicy,
    AiCorrelateRequest, AiCorrelateResponse, AiCorrelationAnchor, AiHookIncidentRequest,
    AiHookIncidentResponse, AiHookInvestigateRequest, AiHookInvestigateResponse, AiIncidentRequest,
    AiIncidentResponse, AiInvestigateRequest, AiInvestigateResponse, AiLimitPolicy,
    AiMcpIncidentRequest, AiMcpIncidentResponse, AiMcpInvestigateRequest, AiMcpInvestigateResponse,
    AiSessionEntry, AiSkillIncidentRequest, AiSkillIncidentResponse, AiSkillInvestigateRequest,
    AiSkillInvestigateResponse, AnomaliesRequest, AnomaliesResponse, AppGraphResponse,
    AskInvestigationRequest, AskInvestigationResponse, ClockSkewRequest, ClockSkewResponse,
    CompareRequest, CompareResponse, ContextRequest, ContextResponse, CorrelateEventsRequest,
    CorrelateEventsResponse, CorrelateStateHostEntry, CorrelateStateRequest,
    CorrelateStateResponse, CorrelateStateWindow, CorrelatedLogRow, CortexOverlaySummary,
    DbBackupResult, DbCheckpointRequest, DbCheckpointResult, DbIntegrityJobStarted,
    DbIntegrityResult, DbMaintenanceStatus, DbStats, DbVacuumRequest, DbVacuumResult,
    FeedLogsRequest, FeedLogsResponse, FilterLogsRequest, FleetStateHostRow, FleetStateRequest,
    FleetStateResponse, FleetStateSummary, GetErrorsRequest, GetErrorsResponse, GetLogRequest,
    GetLogResponse, GraphAroundRequest, GraphAroundResponse, GraphEntity, GraphEntityCandidate,
    GraphEntityLookupRequest, GraphEntityLookupResponse, GraphEntitySummary, GraphEvidence,
    GraphEvidenceLookupRequest, GraphEvidenceLookupResponse, GraphExplainRequest,
    GraphExplainResponse, GraphIncidentNarrative, GraphNarrativeChain, GraphNextQuery,
    GraphProjectionStatusResponse, GraphRebuildResponse, GraphRebuildStatsResponse,
    GraphRelationship, GraphResponseMetadata, GraphSessionCorrelation, GraphSourceLogSummary,
    HomelabMapAnswerRow, HomelabMapAnswerTruncation, HomelabMapGraphAnswer, HomelabMapGraphTarget,
    HomelabMapNextQuery, HomelabMapNode, HomelabMapProofQuery, HomelabMapRequest,
    HomelabMapResponse, HomelabMapSummary, HookIncidentEvidence, HookIncidentSummary,
    INVESTIGATION_UI_VERSION, IncidentContextRequest, IncidentContextResponse, IncidentEvent,
    IncidentRequest, IncidentResponse, IngestRateRequest, IngestRateResponse, InvestigationBudget,
    InvestigationBudgetUsed, InvestigationClaim, InvestigationClaimType, InvestigationEnvelope,
    InvestigationMetadata, ListAiProjectsRequest, ListAiProjectsResponse, ListAiToolsRequest,
    ListAiToolsResponse, ListAppsRequest, ListAppsResponse, ListHostsResponse, ListSessionsRequest,
    ListSessionsResponse, ListSourceIpsRequest, ListSourceIpsResponse, LlmInvocationsRequest,
    LogEntry, MaintenanceJobStatus, McpIncidentEvidence, McpIncidentSummary,
    NotificationsRecentRequest, PatternsRequest, PatternsResponse, ProjectContextRequest,
    ProjectContextResponse, RecurringErrorComparisonEntry, RecurringErrorComparisonRequest,
    RecurringErrorComparisonResponse, RecurringErrorEvidenceBundle, RecurringErrorNextQuery,
    RequestActor, ResolvedTopicEntity, SearchLogsRequest, SearchLogsResponse,
    SearchSessionsRequest, SearchSessionsResponse, SearchedSessionEntry, ServiceJournalEntry,
    ServiceLogsRequest, ServiceLogsResponse, SilentHostsRequest, SilentHostsResponse,
    SimilarIncidentsRequest, SimilarIncidentsResponse, SkillIncidentEvidence, SkillIncidentSummary,
    TailLogsRequest, TimelineRequest, TimelineResponse, TopicCorrelateRequest,
    TopicCorrelateResponse, TopicExpansionEntity, TopicTimelineEntry, TopologyFinding,
    TopologyFindingEntity, TopologyFindingEvidence, UsageBlocksRequest, UsageBlocksResponse,
    app_entity_summary, app_graph_from_explain_response, app_log_summary, safe_passive_text,
};
use super::os_adapter::{OsAdapter, SystemOsAdapter};
use super::time::{parse_optional_timestamp, parse_required_timestamp, rfc3339_z};
use super::{ServiceError, ServiceResult};
use crate::app::{correlate, heartbeat_flags, models, os_adapter, time};
use crate::assessment::{GeminiAssessConfig, build_assessment_prompt, run_gemini_assessment};
use crate::command_log::{self, CommandLogImportResult};
use crate::config::{PoolBudget, StorageConfig};
use crate::db::{self, Bucket, ContextRef, DbPool, SearchParams, TimelineGroupBy};
use crate::filetail::{FileTailRegistry, FileTailStatus};
use crate::scanner;

async fn run_gemini_with_delta<F>(
    runner: &crate::app::llm_runner::LlmRunner,
    spec: crate::app::llm_runner::LlmInvocationSpec,
    gemini_config: &GeminiAssessConfig,
    on_delta: &mut F,
) -> ServiceResult<String>
where
    F: FnMut(&str) -> anyhow::Result<()> + Send,
{
    let gemini_config = gemini_config.clone();
    runner
        .run(spec, move |prompt| async move {
            run_gemini_assessment(&prompt, &gemini_config, |delta| on_delta(delta)).await
        })
        .await
        .map(|outcome| outcome.output)
        .map_err(|error| ServiceError::Internal(anyhow::anyhow!(error)))
}

mod ai;
mod ai_indexing;
mod analytics;
mod artifact_evidence;
mod assessment;
mod compose;
mod correlate_events;
mod domains;
mod error_detection;
mod file_tails;
mod filters;
mod graph;
mod graph_limits;
mod graph_safety;
mod graph_support;
mod hook_assessment;
mod hook_backfill;
mod hook_events;
mod hook_incidents;
mod imports;
mod incidents;
mod investigation;
mod journal;
mod logs;
mod maintenance;
mod map;
mod map_answers;
mod map_findings;
mod mcp_assessment;
mod mcp_backfill;
mod mcp_events;
mod mcp_incidents;
mod rag;
mod session_pages;
mod skill_assessment;
mod skill_backfill;
mod skill_events;
mod skill_incidents;
mod streams;
mod topic_correlate;

pub use compose::run_compose_status;
pub use journal::run_service_logs;
#[cfg(test)]
use journal::{normalize_syslog_owned_service, parse_journal_json_lines};

pub fn wal_checkpoint_complete(busy: i64, log_frames: i64, checkpointed_frames: i64) -> bool {
    db::wal_checkpoint_complete(busy, log_frames, checkpointed_frames)
}

/// Parse the `source_kind` recorded in a log row's `metadata_json`, if present.
/// Shared by the `ai_correlate` and `topic_correlate` lanes.
pub(crate) fn row_source_kind(entry: &db::LogEntry) -> Option<String> {
    let meta = entry.metadata_json.as_deref()?;
    let value: serde_json::Value = serde_json::from_str(meta).ok()?;
    value
        .get("source_kind")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Service-layer entry point bridging request structs to SQLite.
///
/// `Clone` is cheap because every field is either `Arc`-wrapped or a small
/// scalar. Public methods live in focused `services/*` modules; this file owns
/// construction and DB execution coordination.
#[derive(Clone)]
pub struct CortexService {
    pool: Arc<DbPool>,
    pub(super) storage: StorageConfig,
    db_permits: Arc<Semaphore>,
    pub(super) heavy_read_permits: Arc<Semaphore>,
    /// Process-wide admission gate shared with runtime and REST maintenance.
    pub(super) maintenance_permit: Arc<Semaphore>,
    integrity_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    integrity_task_failed: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    integrity_test_hook:
        Option<Arc<dyn Fn() -> anyhow::Result<Vec<String>> + Send + Sync + 'static>>,
    #[cfg(test)]
    integrity_test_spawn_failure: bool,
    acquire_timeout: Duration,
    /// OS-level adapter for journalctl / systemd shell-outs.
    pub(super) os: Arc<dyn OsAdapter + Send + Sync>,
    file_tail_registry: Option<Arc<FileTailRegistry>>,
    file_tail_reconcile: Option<Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>>,
    file_tail_statuses: Option<Arc<dyn Fn() -> Vec<FileTailStatus> + Send + Sync>>,
    llm_runner: Arc<crate::app::llm_runner::LlmRunner>,
    /// Bounded presentation cache for recurring-error bundles. Entries are
    /// created only after irreversible redaction in `services/rag.rs`; raw
    /// signature rows never enter this map.
    pub(super) recurring_error_bundle_cache:
        Arc<Mutex<BTreeMap<String, RecurringErrorComparisonEntry>>>,
}

/// Number of read permits issued for a given r2d2 pool size.
///
/// Delegates to [`PoolBudget`], which is computed from
/// `config::UNPERMITTED_CONNECTION_LANES` — the enumerated set of subsystems
/// that call `DbPool::get()` without holding one of these permits. Reserving a
/// single connection for "the writer" was accurate when there was one; by the
/// time there were a dozen, readers could still hold `pool_size - 1`
/// connections and every writer queued for the same last slot, which is what
/// produced `permit_ms=0` alongside a 6s `pool.get()` timeout (syslog-mcp-0firx).
fn read_permits_for_pool(pool_size: u32) -> usize {
    PoolBudget::for_pool_size(pool_size).read_permits()
}

impl CortexService {
    pub(crate) fn new(pool: Arc<DbPool>, storage: StorageConfig) -> Self {
        let permits = read_permits_for_pool(storage.pool_size);
        let heavy_read_concurrency = storage.heavy_read_concurrency;
        let llm_runner = Arc::new(crate::app::llm_runner::LlmRunner::new(
            pool.clone(),
            crate::config::LlmConfig::default(),
        ));
        Self {
            pool,
            storage,
            db_permits: Arc::new(Semaphore::new(permits)),
            heavy_read_permits: Arc::new(Semaphore::new(heavy_read_concurrency)),
            maintenance_permit: Arc::new(Semaphore::new(1)),
            integrity_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
            integrity_task_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            integrity_test_hook: None,
            #[cfg(test)]
            integrity_test_spawn_failure: false,
            acquire_timeout: DB_ACQUIRE_TIMEOUT,
            os: Arc::new(SystemOsAdapter),
            file_tail_registry: None,
            file_tail_reconcile: None,
            file_tail_statuses: None,
            llm_runner,
            recurring_error_bundle_cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Test constructor that injects a custom `OsAdapter`.
    #[cfg(test)]
    pub(crate) fn with_os_adapter(
        pool: Arc<DbPool>,
        storage: StorageConfig,
        os: Arc<dyn OsAdapter + Send + Sync>,
    ) -> Self {
        let permits = read_permits_for_pool(storage.pool_size);
        let heavy_read_concurrency = storage.heavy_read_concurrency;
        let llm_runner = Arc::new(crate::app::llm_runner::LlmRunner::new(
            pool.clone(),
            crate::config::LlmConfig::default(),
        ));
        Self {
            pool,
            storage,
            db_permits: Arc::new(Semaphore::new(permits)),
            heavy_read_permits: Arc::new(Semaphore::new(heavy_read_concurrency)),
            maintenance_permit: Arc::new(Semaphore::new(1)),
            integrity_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
            integrity_task_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            integrity_test_hook: None,
            integrity_test_spawn_failure: false,
            acquire_timeout: DB_ACQUIRE_TIMEOUT,
            os,
            file_tail_registry: None,
            file_tail_reconcile: None,
            file_tail_statuses: None,
            llm_runner,
            recurring_error_bundle_cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn with_file_tail_registry(mut self, registry: Arc<FileTailRegistry>) -> Self {
        self.file_tail_registry = Some(registry);
        self
    }

    pub(crate) fn with_maintenance_permit(mut self, permit: Arc<Semaphore>) -> Self {
        self.maintenance_permit = permit;
        self
    }

    pub(crate) fn maintenance_permit(&self) -> Arc<Semaphore> {
        Arc::clone(&self.maintenance_permit)
    }

    pub(crate) async fn drain_integrity_tasks(&self, timeout: std::time::Duration) -> bool {
        let mut tasks = {
            let mut tasks = self
                .integrity_tasks
                .lock()
                .expect("integrity task registry mutex poisoned");
            std::mem::take(&mut *tasks)
        };
        let abort_handles: Vec<_> = tasks
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect();
        let joined =
            tokio::time::timeout(timeout, futures_util::future::join_all(&mut tasks)).await;
        let Ok(results) = joined else {
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                "Integrity task drain timed out; aborting async wrappers"
            );
            for handle in abort_handles {
                handle.abort();
            }
            let _ = futures_util::future::join_all(tasks).await;
            self.integrity_task_failed
                .store(true, std::sync::atomic::Ordering::Release);
            return false;
        };
        let mut clean = !self
            .integrity_task_failed
            .load(std::sync::atomic::Ordering::Acquire);
        for result in results {
            if let Err(error) = result {
                clean = false;
                self.integrity_task_failed
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::error!(%error, "Integrity completion task failed during drain");
            }
        }
        clean
    }

    #[cfg(test)]
    pub(crate) fn with_integrity_test_hook(
        mut self,
        hook: Arc<dyn Fn() -> anyhow::Result<Vec<String>> + Send + Sync + 'static>,
    ) -> Self {
        self.integrity_test_hook = Some(hook);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_integrity_spawn_failure(mut self) -> Self {
        self.integrity_test_spawn_failure = true;
        self
    }

    pub(crate) fn with_llm_config(mut self, config: crate::config::LlmConfig) -> Self {
        self.llm_runner = Arc::new(crate::app::llm_runner::LlmRunner::new(
            self.pool.clone(),
            config,
        ));
        self
    }

    pub fn llm(&self) -> &crate::app::llm_runner::LlmRunner {
        &self.llm_runner
    }

    pub(crate) fn with_file_tail_control(
        mut self,
        registry: Arc<FileTailRegistry>,
        reconcile: Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>,
        statuses: Arc<dyn Fn() -> Vec<FileTailStatus> + Send + Sync>,
    ) -> Self {
        self.file_tail_registry = Some(registry);
        self.file_tail_reconcile = Some(reconcile);
        self.file_tail_statuses = Some(statuses);
        self
    }

    /// One-shot SQLite schema-version probe. Sync because callers run during
    /// startup construction (e.g. `ApiState::new` caches it for /api/version)
    /// before the runtime serves requests. Exists so transport layers never
    /// reach into `db::` directly (full-review AL1).
    pub fn schema_version(&self) -> anyhow::Result<i64> {
        Ok(crate::db::read_schema_version_info(&self.pool)?.version)
    }

    /// Test-only accessor for the underlying pool, used by service submodule
    /// tests that need to seed fixtures directly via SQL before exercising a
    /// service method (e.g. `skill_backfill_tests.rs`).
    #[cfg(test)]
    pub(crate) fn pool_for_test(&self) -> Arc<DbPool> {
        Arc::clone(&self.pool)
    }

    pub(super) async fn run_db<F, T>(&self, op: &'static str, f: F) -> ServiceResult<T>
    where
        F: FnOnce(&DbPool) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let wait_start = Instant::now();
        let permit_result = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.db_permits).acquire_owned(),
        )
        .await;
        let permit_ms = wait_start.elapsed().as_millis();

        let permit = match permit_result {
            Err(_) => {
                tracing::warn!(op, permit_ms, "db acquire timeout");
                return Err(ServiceError::Busy("database worker limit reached".into()));
            }
            Ok(Err(_)) => {
                tracing::warn!(op, permit_ms, "db semaphore closed");
                return Err(ServiceError::Busy("database worker limit closed".into()));
            }
            Ok(Ok(p)) => p,
        };

        let exec_start = Instant::now();
        let pool = Arc::clone(&self.pool);
        let join_result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f(&pool)
        })
        .await;
        let exec_ms = exec_start.elapsed().as_millis();

        let result = match join_result {
            Err(e) => {
                if e.is_cancelled() {
                    tracing::warn!(op, permit_ms, exec_ms, "db task cancelled");
                } else {
                    tracing::warn!(op, permit_ms, exec_ms, error = %e, "db task panic");
                }
                return Err(ServiceError::Internal(anyhow::anyhow!(
                    "Task join error: {e}"
                )));
            }
            // Preserve typed ServiceErrors raised inside the closure, and
            // promote retryable SQLite/pool pressure into stable sanitized
            // categories instead of surfacing opaque internal errors.
            Ok(r) => r.map_err(ServiceError::classify_db_error),
        };

        if exec_ms > SLOW_DB_MS {
            match &result {
                Ok(_) => tracing::warn!(op, permit_ms, exec_ms, "db op ok"),
                Err(e) => tracing::warn!(op, permit_ms, exec_ms, error = %e, "db op err"),
            }
        } else {
            match &result {
                Ok(_) => tracing::debug!(op, permit_ms, exec_ms, "db op ok"),
                Err(e) => tracing::debug!(op, permit_ms, exec_ms, error = %e, "db op err"),
            }
        }
        result
    }

    async fn run_heavy_db<F, T>(&self, op: &'static str, f: F) -> ServiceResult<T>
    where
        F: FnOnce(&DbPool) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.with_heavy_read_permit(op, || async move { self.run_db(op, f).await })
            .await
    }

    async fn with_heavy_read_permit<F, Fut, T>(&self, op: &'static str, f: F) -> ServiceResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ServiceResult<T>>,
    {
        let wait_start = Instant::now();
        let permit_result = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.heavy_read_permits).acquire_owned(),
        )
        .await;

        let heavy_permit = match permit_result {
            Err(_) => {
                tracing::warn!(
                    op,
                    wait_ms = wait_start.elapsed().as_millis(),
                    "heavy read limited"
                );
                return Err(ServiceError::Busy("heavy_read_limited".to_string()));
            }
            Ok(Err(_)) => {
                tracing::warn!(op, "heavy read limiter closed");
                return Err(ServiceError::Busy("heavy_read_limited".to_string()));
            }
            Ok(Ok(permit)) => permit,
        };

        let _heavy_permit = heavy_permit;
        f().await
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
