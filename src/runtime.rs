//! `RuntimeCore` — the composition root shared by every long-running mode.
//!
//! Owns config loading, the SQLite pool, the ingest writer, the resolved auth
//! policy, and `spawn_maintenance_tasks`: retention purge (hourly), storage
//! budget enforcement (`CORTEX_CLEANUP_INTERVAL_SECS`), error-signature scan,
//! the three notification tasks (dispatcher / evaluator / digest), inventory
//! refresh (5 min) and one-shot graph backfill, AI session rollup (300s),
//! timeline rollup (60s), `PRAGMA optimize` (6h), and Docker ingest streams.
//! Syslog listeners are started separately via `start_syslog` and supervised
//! with restart + backoff; their liveness gates `/health`.
//!
//! Invariant: maintenance work serializes on a single `maintenance_permit`
//! semaphore so background jobs never contend with each other for the write
//! lock. Shutdown drains the ingest channel, then checkpoints the WAL.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::app::CortexService;
use crate::config::{AuthMode, Config, mcp_bind_is_loopback, validate_auth_config};
use crate::db::{self, DbPool, StorageBudgetState};
use crate::file_tail::{FileTailRegistry, FileTailSupervisor};
use crate::heartbeat::HeartbeatState;
use crate::ingest::IngestTx;
use crate::mcp::AuthPolicy;
use crate::observability::RuntimeObservability;
use crate::otlp::{self, OtlpCounters, OtlpState};
use crate::receiver::enrichment::EnrichmentConfig;
use crate::{docker_ingest, mcp, receiver};

mod agent_observatory;
mod graph_refresh;
mod inventory_refresh;

pub struct RuntimeCore {
    pub config: Config,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<StorageBudgetState>>>,
    service: CortexService,
    /// Semaphore for DB-heavy maintenance tasks: retention purge, storage
    /// guardrail enforcement, error scan, notification evaluator.
    maintenance_permit: Arc<Semaphore>,
    /// Separate semaphore for the notification dispatcher. The dispatcher
    /// makes outbound HTTP calls (5s timeout); keeping it separate prevents
    /// HTTP back-pressure from starving the DB maintenance tasks.
    dispatcher_permit: Arc<Semaphore>,
    ingest: IngestTx,
    file_tail_supervisor: FileTailSupervisor,
    otlp_counters: Arc<OtlpCounters>,
    auth_policy: AuthPolicy,
    observability: Arc<RuntimeObservability>,
    fatal_shutdown: CancellationToken,
}

fn forwarding_agent_tokens(config: &Config) -> std::collections::HashMap<String, String> {
    config
        .mcp
        .forwarding_agents
        .iter()
        .map(|(identity, secret)| {
            (
                secret
                    .0
                    .clone()
                    .expect("forwarding credentials are validated at runtime construction"),
                identity.clone(),
            )
        })
        .collect()
}

pub struct MaintenanceHandles {
    /// Cooperative cancellation signal. Cancelling this token requests all
    /// background task loops to break at their next `select!` iteration.
    /// Call [`MaintenanceHandles::shutdown`] rather than cancelling the token
    /// directly — `shutdown` coordinates the drain order (ingest first, then
    /// tasks) and waits for completion with a timeout.
    token: CancellationToken,
    purge: Option<JoinHandle<()>>,
    storage: Option<JoinHandle<()>>,
    docker_ingest: Vec<JoinHandle<()>>,
    file_tail: Option<JoinHandle<()>>,
    error_scan: Option<JoinHandle<()>>,
    notification_dispatcher: Option<JoinHandle<()>>,
    notification_evaluator: Option<JoinHandle<()>>,
    notification_digest: Option<JoinHandle<()>>,
    inventory_refresh: Option<JoinHandle<()>>,
    inventory_backfill: Option<JoinHandle<()>>,
    graph_refresh: Option<JoinHandle<()>>,
    session_rollup: Option<JoinHandle<()>>,
    timeline_rollup: Option<JoinHandle<()>>,
    optimize: Option<JoinHandle<()>>,
    agent_observatory_projector: Option<JoinHandle<()>>,
    agent_observatory_git: Option<JoinHandle<()>>,
    /// Monitors the two syslog supervisor JoinHandles (UDP + TCP). The
    /// supervisors loop forever under normal operation; this task logs an error
    /// if either exits unexpectedly (panic or abort) so silent ingest loss is
    /// observable. Stored here so shutdown can join/abort it like the other
    /// maintenance tasks.
    syslog_monitor: Option<JoinHandle<()>>,
}

impl MaintenanceHandles {
    /// Cooperatively cancel all background tasks and wait for them to finish,
    /// with a `timeout` budget. Tasks that do not finish within the budget are
    /// aborted (loud warning logged).
    ///
    /// Shutdown order:
    /// 1. Cancel the token — tasks observe this at their next `select!` tick.
    /// 2. Join all handles concurrently inside a timeout window.
    /// 3. Abort any task that did not exit in time.
    ///
    /// # Cooperative-cancellation coverage (Arch-H6 status)
    ///
    /// - `retention_purge`, `storage_budget`, `error_scan`: fully cooperative —
    ///   each loop uses `select! { biased; _ = token.cancelled() => break; ... }`.
    ///   They break at the next tick and exit cleanly.
    ///
    /// - `notification_dispatcher`, `notification_evaluator`, `notification_digest`:
    ///   fully cooperative between cycles. The wrapper still treats an inner
    ///   exit or panic before cancellation as a maintenance-task failure.
    ///
    /// - `docker_ingest` tasks: collected via `docker_ingest::spawn_all` which
    ///   does not yet accept a `CancellationToken`. Cancelled via `join_all`
    ///   timeout + implicit abort when handles are dropped. Deferred to a
    ///   follow-up.
    ///
    /// Net improvement over the previous `Drop::abort()` path: all tasks are
    /// awaited with an explicit timeout rather than being abandoned immediately
    /// on `Drop`, and the pure-Rust tasks (purge, storage, error_scan) exit
    /// without abort.
    pub async fn shutdown(self, timeout: std::time::Duration) -> bool {
        self.token.cancel();
        let all_handles: Vec<JoinHandle<()>> = [
            self.purge,
            self.storage,
            self.error_scan,
            self.notification_dispatcher,
            self.notification_evaluator,
            self.notification_digest,
            self.inventory_refresh,
            self.inventory_backfill,
            self.graph_refresh,
            self.session_rollup,
            self.timeline_rollup,
            self.optimize,
            self.agent_observatory_projector,
            self.agent_observatory_git,
            self.syslog_monitor,
            self.file_tail,
        ]
        .into_iter()
        .flatten()
        .chain(self.docker_ingest)
        .collect();

        await_or_abort_tasks(all_handles, timeout).await
    }
}

async fn await_or_abort_tasks(
    all_handles: Vec<JoinHandle<()>>,
    timeout: std::time::Duration,
) -> bool {
    let count = all_handles.len();
    let abort_handles: Vec<_> = all_handles.iter().map(JoinHandle::abort_handle).collect();
    let mut join_all = Box::pin(futures_util::future::join_all(all_handles));
    match tokio::time::timeout(timeout, &mut join_all).await {
        Ok(results) => {
            let mut clean = true;
            for result in results {
                if let Err(error) = result {
                    clean = false;
                    tracing::error!(%error, "Maintenance task failed during shutdown");
                }
            }
            if clean {
                tracing::info!(tasks = count, "All maintenance tasks completed cleanly");
            } else {
                tracing::error!(
                    tasks = count,
                    "Maintenance task shutdown completed with failures"
                );
            }
            clean
        }
        Err(_) => {
            tracing::warn!(
                tasks = count,
                timeout_secs = timeout.as_secs(),
                "Maintenance task shutdown timed out; aborting unfinished tasks"
            );
            for handle in abort_handles {
                handle.abort();
            }
            for result in join_all.await {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    tracing::error!(%error, "Maintenance task failed while aborting shutdown");
                }
            }
            false
        }
    }
}

fn spawn_notification_wrapper(
    name: &'static str,
    token: CancellationToken,
    mut inner: JoinHandle<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = token.cancelled() => {
                match inner.await {
                    Err(error) => panic!("notification {name} failed during shutdown: {error}"),
                    Ok(()) => tracing::debug!(task = name, "notification task stopped cleanly"),
                }
            }
            result = &mut inner => match result {
                Ok(()) => panic!("notification {name} exited unexpectedly"),
                Err(error) => panic!("notification {name} failed: {error}"),
            }
        }
    })
}

pub(crate) fn background_interval(period: tokio::time::Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

/// Initial retention delay. Production remains fixed at one hour. The live E2E
/// harness may shorten only the first tick by setting both the explicit test
/// mode gate and a bounded delay; the recurring cadence remains hourly.
fn retention_initial_delay() -> tokio::time::Duration {
    retention_initial_delay_from(
        std::env::var("CORTEX_LIVE_TEST_MODE").ok().as_deref(),
        std::env::var("CORTEX_LIVE_RETENTION_INITIAL_DELAY_SECS")
            .ok()
            .as_deref(),
    )
}

fn retention_initial_delay_from(
    test_mode: Option<&str>,
    raw: Option<&str>,
) -> tokio::time::Duration {
    const PRODUCTION: u64 = 3600;
    let seconds = if test_mode == Some("1") {
        raw.and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (1..=60).contains(value))
            .unwrap_or(PRODUCTION)
    } else {
        PRODUCTION
    };
    tokio::time::Duration::from_secs(seconds)
}

/// Tags whose retention is hard-capped at 7 days regardless of the global
/// `retention_days` setting. AdGuard query volume would otherwise dominate
/// the FTS5 index at homelab volumes (50k+ DNS queries/day).
const ADGUARD_RETENTION_TAGS: &[&str] = &["adguard-allowed", "adguard-query", "adguard-rewrite"];
const ADGUARD_RETENTION_DAYS: u32 = 7;
const HEARTBEAT_RETENTION_DAYS: u32 = 14;
/// Retention ticks between orphan-heartbeat sweeps. The retention task runs
/// hourly, so 24 makes the sweep daily.
const ORPHAN_SWEEP_EVERY_N_TICKS: u64 = 24;
/// Cadence for refreshing the AI session rollup (bead cortex-2vre). 5 min
/// bounds staleness of unbounded `sessions` results while keeping the periodic
/// full re-aggregation cost negligible relative to ingest.
const SESSION_ROLLUP_REFRESH_SECS: u64 = 300;

/// Cadence for the incremental `timeline_hourly` rollup refresh (bead
/// syslog-mcp-kcvq). 60s bounds how stale `timeline`/`stats` reads can be. Each
/// tick folds only the rows ingested since the last watermark (milliseconds), so
/// a short cadence is cheap.
const TIMELINE_ROLLUP_REFRESH_SECS: u64 = 60;
/// Cadence for `PRAGMA optimize` (keeps planner stats fresh). 6 hours — stats
/// track row-count *distribution*, which shifts slowly, so frequent runs add
/// little. `PRAGMA optimize` no-ops on tables that haven't changed enough.
const OPTIMIZE_INTERVAL_SECS: u64 = 21_600;

impl RuntimeCore {
    pub async fn load() -> Result<Self> {
        Self::for_server(Config::load()?).await
    }

    pub async fn load_query_only() -> Result<Self> {
        // Use load_for_stdio() to skip the non-loopback bind safety gate —
        // stdio mode never binds an HTTP port so the gate is irrelevant.
        let config = Config::load_for_stdio()?;
        for attempt in 0..3 {
            match Self::query_only(config.clone()).await {
                Ok(runtime) => return Ok(runtime),
                Err(error)
                    if attempt < 2
                        && (error.to_string().contains("database is locked")
                            || error.to_string().contains("SQLITE_BUSY")) =>
                {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("query-only runtime retry loop always returns")
    }

    pub async fn for_server(config: Config) -> Result<Self> {
        Self::from_config_inner(config, true, false).await
    }

    pub async fn query_only(config: Config) -> Result<Self> {
        // Stdio / query-only mode: build_auth_policy short-circuits to
        // LoopbackDev when is_stdio=true. Process isolation is the trust
        // boundary — no TCP port is bound, so AuthLayer and scope checks
        // don't apply.
        Self::from_config_inner(config, false, true).await
    }

    async fn from_config_inner(
        config: Config,
        enforce_initial_storage_budget: bool,
        is_stdio: bool,
    ) -> Result<Self> {
        if !is_stdio {
            validate_auth_config(&config, true)?;
        }
        reject_unsafe_otlp_oauth_only_exposure(&config, is_stdio)?;
        let pool = Arc::new(db::init_pool(&config.storage)?);
        if !is_stdio {
            db::reconcile_interrupted_server_work(&pool)?;
        }
        let storage_state = Arc::new(Mutex::new(None));
        if enforce_initial_storage_budget
            && (config.storage.max_db_size_mb > 0 || config.storage.min_free_disk_mb > 0)
        {
            let initial_outcome = db::enforce_storage_budget(&pool, &config.storage)?;
            *storage_state.lock() = Some(StorageBudgetState {
                metrics: initial_outcome.metrics.clone(),
                write_blocked: initial_outcome.write_blocked,
            });
            tracing::info!(
                deleted_rows = initial_outcome.deleted_rows,
                logical_db_size_bytes = initial_outcome.metrics.logical_db_size_bytes,
                physical_db_size_bytes = initial_outcome.metrics.physical_db_size_bytes,
                free_disk_bytes = ?initial_outcome.metrics.free_disk_bytes,
                write_blocked = initial_outcome.write_blocked,
                "Initial storage budget check completed"
            );
        }
        let enrichment = EnrichmentConfig {
            authelia_source_ip: config.enrichment.authelia_source_ip.clone(),
            adguard_source_ip: config.enrichment.adguard_source_ip.clone(),
            agent_docker_source_prefixes: config.enrichment.agent_docker_source_prefixes.clone(),
            agent_docker_trust_any_source: config.enrichment.agent_docker_trust_any_source,
            scrub_prompts: config.enrichment.scrub_prompts,
            api_token: config.mcp.api_token.0.clone(),
        };
        // Source-gate posture report. The gate itself is fail-closed
        // (`receiver::enrichment::agent_docker_source_trusted`), so an
        // unconfigured gate is safe-but-disabled rather than wide open —
        // which is exactly why it must be loud: the silent symptom is
        // agent-docker identity never being attributed. Stdio query-only
        // mode never ingests, so it stays quiet.
        if !is_stdio {
            if enrichment.agent_docker_trust_any_source {
                tracing::error!(
                    "CORTEX_AGENT_DOCKER_TRUST_ANY_SOURCE is enabled: the agent-docker identity \
                     marker is accepted from ANY syslog sender, so any host that can reach the \
                     syslog port can forge agent-docker identity. Unset it and list the agent \
                     hosts' source IPs in CORTEX_AGENT_DOCKER_SOURCE_PREFIXES (or [enrichment] \
                     agent_docker_source_prefixes) instead"
                );
            } else if enrichment.agent_docker_source_prefixes.is_empty() {
                tracing::error!(
                    "agent_docker_source_prefixes is empty: agent-docker identity extraction is \
                     DISABLED and every [cortex-agent-docker-meta:...] marker will be rejected. \
                     Set CORTEX_AGENT_DOCKER_SOURCE_PREFIXES (or [enrichment] \
                     agent_docker_source_prefixes) to the agent hosts' source IPs to enable it"
                );
            } else {
                tracing::info!(
                    prefix_count = enrichment.agent_docker_source_prefixes.len(),
                    "agent-docker identity source gate active"
                );
            }
        }
        let observability = Arc::new(RuntimeObservability::default());
        let ingest = crate::ingest::start_writer_from_receiver_config(
            &config.receiver,
            config.storage.clone(),
            Arc::clone(&pool),
            Arc::clone(&storage_state),
            enrichment,
            Arc::clone(&observability),
        );
        let file_tail_registry = Arc::new(FileTailRegistry::new(
            FileTailRegistry::path_from_storage_db(&config.storage.db_path),
        ));
        let file_tail_supervisor = FileTailSupervisor::new(
            Arc::clone(&file_tail_registry),
            ingest.clone(),
            CancellationToken::new(),
            config.receiver.max_message_size,
        );
        let maintenance_permit = Arc::new(Semaphore::new(1));
        let mut service = CortexService::new(Arc::clone(&pool), config.storage.clone())
            .with_llm_config(config.llm.clone())
            .with_maintenance_permit(Arc::clone(&maintenance_permit));
        if is_stdio {
            service = service.with_file_tail_registry(file_tail_registry);
        } else {
            let reconcile_supervisor = file_tail_supervisor.clone();
            let status_supervisor = file_tail_supervisor.clone();
            service = service.with_file_tail_control(
                file_tail_registry,
                Arc::new(move || {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(reconcile_supervisor.reconcile())
                    })
                }),
                Arc::new(move || status_supervisor.statuses()),
            );
        }

        let auth_policy = build_auth_policy(&config, is_stdio).await?;

        Ok(Self {
            config,
            pool,
            storage_state,
            service,
            maintenance_permit,
            dispatcher_permit: Arc::new(Semaphore::new(1)),
            ingest,
            file_tail_supervisor,
            otlp_counters: Arc::new(OtlpCounters::default()),
            auth_policy,
            observability,
            fatal_shutdown: CancellationToken::new(),
        })
    }

    pub fn service(&self) -> CortexService {
        self.service.clone()
    }

    pub fn maintenance_permit(&self) -> Arc<Semaphore> {
        Arc::clone(&self.maintenance_permit)
    }

    pub fn fatal_shutdown_token(&self) -> CancellationToken {
        self.fatal_shutdown.clone()
    }

    /// Shared SQLite pool — exposed for callers that need to read startup-time
    /// metadata (e.g. `api::ApiState::new` caches the schema version).
    pub fn pool(&self) -> &Arc<DbPool> {
        &self.pool
    }

    /// Build the OTLP router with shared counters and the MCP API token (if any).
    pub fn otlp_router(&self) -> axum::Router {
        let state = OtlpState::new(
            self.ingest.clone(),
            self.config.mcp.api_token.0.clone(),
            Arc::clone(&self.otlp_counters),
            self.auth_policy.clone(),
        )
        .with_trace_ingest(
            Arc::clone(&self.pool),
            Arc::clone(&self.storage_state),
            self.config.agent_observatory.privacy.clone(),
        );
        otlp::router(state)
    }

    /// Build the heartbeat telemetry ingest router.
    pub fn heartbeat_router(&self) -> axum::Router {
        let state = HeartbeatState::new(
            Arc::clone(&self.pool),
            self.config.mcp.api_token.0.clone(),
            self.auth_policy.clone(),
        );
        crate::heartbeat::router(state)
    }

    /// Build the forwarded agent-command ingest router.
    pub fn agent_command_router(&self) -> axum::Router {
        let state = crate::agent_command_ingest::AgentCommandIngestState::new(
            Arc::clone(&self.pool),
            self.config.mcp.api_token.0.clone(),
            self.auth_policy.clone(),
        );
        crate::agent_command_ingest::router(state)
    }

    /// Build the forwarded AI-transcript ingest router.
    pub fn ai_transcript_router(&self) -> axum::Router {
        let state = crate::ai_transcript_ingest::AiTranscriptIngestState::new(
            Arc::clone(&self.pool),
            self.config.mcp.api_token.0.clone(),
            forwarding_agent_tokens(&self.config),
            self.auth_policy.clone(),
        );
        crate::ai_transcript_ingest::router(state)
    }

    /// Build the receipt-backed forwarded-syslog ingest router.
    pub fn syslog_forward_router(&self) -> axum::Router {
        let state = crate::syslog_forward_ingest::SyslogForwardIngestState::new(
            Arc::clone(&self.pool),
            self.config.mcp.api_token.0.clone(),
            forwarding_agent_tokens(&self.config),
            self.auth_policy.clone(),
        );
        crate::syslog_forward_ingest::router(state)
    }

    /// Build the forwarded shell-history ingest router.
    pub fn shell_history_router(&self) -> axum::Router {
        let state = crate::shell_history_ingest::ShellHistoryIngestState::new(
            Arc::clone(&self.pool),
            self.config.mcp.api_token.0.clone(),
            self.auth_policy.clone(),
        );
        crate::shell_history_ingest::router(state)
    }

    pub fn mcp_state(&self) -> mcp::AppState {
        mcp::AppState {
            service: self.service(),
            config: self.config.mcp.clone(),
            notifications_config: self.config.notifications.clone(),
            otlp_counters: Arc::clone(&self.otlp_counters),
            auth_policy: self.auth_policy.clone(),
            observability: Arc::clone(&self.observability),
        }
    }

    /// Borrow the resolved authentication policy. Useful for boot-time
    /// diagnostics and for tests.
    pub fn auth_policy(&self) -> &AuthPolicy {
        &self.auth_policy
    }

    /// Signal the ingest pipeline to drain, wait up to `timeout` for the batch
    /// writer to flush, then checkpoint the WAL. Call this after the HTTP server
    /// has stopped accepting connections.
    pub async fn shutdown(self, timeout: std::time::Duration) -> bool {
        let pool = Arc::clone(&self.pool);
        // Integrity workers use independently managed OS threads so runtime
        // teardown remains bounded. If one outlives the drain budget, skip the
        // shutdown checkpoint rather than contend with its live SQLite read.
        let integrity_drained = self.service.drain_integrity_tasks(timeout).await;
        let ingest_drained = self.ingest.shutdown(timeout).await;
        if !integrity_drained || !ingest_drained {
            tracing::warn!(
                integrity_drained,
                ingest_drained,
                "Skipping shutdown WAL checkpoint because shutdown did not drain cleanly"
            );
            return false;
        }
        match db::db_wal_checkpoint(&pool, "truncate") {
            Err(e) => {
                tracing::warn!(error = %e, "WAL checkpoint on shutdown failed (non-fatal)");
                false
            }
            Ok((busy, log_frames, checkpointed_frames))
                if db::wal_checkpoint_complete(busy, log_frames, checkpointed_frames) =>
            {
                tracing::info!("WAL checkpoint completed on clean shutdown");
                true
            }
            Ok((busy, log_frames, checkpointed_frames)) => {
                tracing::warn!(
                    busy,
                    log_frames,
                    checkpointed_frames,
                    "WAL checkpoint incomplete on shutdown"
                );
                false
            }
        }
    }

    /// Start the supervised syslog listeners and attach a monitoring task to
    /// `handles`.
    ///
    /// The monitoring task awaits both supervisor `JoinHandle`s concurrently.
    /// Supervisors loop forever under normal operation; if either exits
    /// (unexpected panic or abort), the monitor logs a `tracing::error!` so
    /// silent ingest loss surfaces in logs and metrics rather than being
    /// invisible. The monitor handle is stored in
    /// [`MaintenanceHandles::syslog_monitor`] so it participates in the
    /// cooperative shutdown drain.
    pub async fn start_syslog(&self, handles: &mut MaintenanceHandles) -> Result<()> {
        let listener_handles = receiver::start_listeners_with_shutdown(
            self.config.receiver.clone(),
            self.ingest.clone(),
            Arc::clone(&self.observability),
            handles.token.clone(),
        )
        .await?;

        let fatal_shutdown = self.fatal_shutdown.clone();
        let shutdown = handles.token.clone();
        let monitor = tokio::spawn(async move {
            let mut udp = listener_handles.udp;
            let mut tcp = listener_handles.tcp;
            let protocol = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    // Both supervisors receive this token and abort their
                    // active recv/accept task before returning. Join them so
                    // graceful shutdown does not leave detached listeners or
                    // misclassify their expected exit as a fatal outage.
                    let (udp_result, tcp_result) = tokio::join!(udp, tcp);
                    for (listener, result) in [("udp", udp_result), ("tcp", tcp_result)] {
                        if let Err(error) = result {
                            tracing::warn!(listener, error = %error,
                                "syslog listener supervisor failed during shutdown");
                        }
                    }
                    tracing::debug!("syslog listener monitor stopped cleanly");
                    return;
                }
                res = &mut udp => {
                    match res {
                        Ok(()) => tracing::error!(
                            "syslog supervisor task (udp) exited unexpectedly — \
                             listener will not restart"
                        ),
                        Err(e) => tracing::error!(
                            error = %e,
                            "syslog supervisor task (udp) exited unexpectedly — \
                             listener will not restart: {}", e
                        ),
                    }
                    tcp.abort();
                    let _ = tcp.await;
                    "udp"
                }
                res = &mut tcp => {
                    match res {
                        Ok(()) => tracing::error!(
                            "syslog supervisor task (tcp) exited unexpectedly — \
                             listener will not restart"
                        ),
                        Err(e) => tracing::error!(
                            error = %e,
                            "syslog supervisor task (tcp) exited unexpectedly — \
                             listener will not restart: {}", e
                        ),
                    }
                    udp.abort();
                    let _ = udp.await;
                    "tcp"
                }
            };
            tracing::error!(
                protocol,
                "fatal syslog listener failure; requesting graceful shutdown"
            );
            fatal_shutdown.cancel();
        });
        handles.syslog_monitor = Some(monitor);
        Ok(())
    }

    pub fn spawn_maintenance_tasks(&self) -> MaintenanceHandles {
        let token = CancellationToken::new();
        let purge = self.spawn_retention_task(token.clone());
        let storage = self.spawn_storage_task(token.clone());
        let docker_ingest = docker_ingest::spawn_all(
            self.config.docker_ingest.clone(),
            Arc::clone(&self.pool),
            self.ingest.clone(),
        );
        let error_scan = self.spawn_error_scan_task(token.clone());
        let notification_dispatcher = self.spawn_notification_dispatcher(token.clone());
        let notification_evaluator = self.spawn_notification_evaluator(token.clone());
        let notification_digest = self.spawn_notification_digest(token.clone());
        let inventory_refresh = inventory_refresh::spawn(
            token.clone(),
            Arc::clone(&self.pool),
            Arc::clone(&self.maintenance_permit),
            Arc::clone(&self.observability),
        );
        let inventory_backfill = self.spawn_inventory_backfill_task(token.clone());
        let graph_refresh = graph_refresh::spawn(
            token.clone(),
            Arc::clone(&self.pool),
            Arc::clone(&self.maintenance_permit),
            Arc::clone(&self.observability),
        );
        let session_rollup = self.spawn_session_rollup_task(token.clone());
        let timeline_rollup = self.spawn_timeline_rollup_task(token.clone());
        let optimize = self.spawn_optimize_task(token.clone());
        let file_tail = self.spawn_file_tail_task(token.clone());
        let agent_observatory_projector = agent_observatory::spawn_projector(
            token.clone(),
            Arc::clone(&self.pool),
            self.config.agent_observatory.clone(),
        );
        let agent_observatory_git = agent_observatory::spawn_git_reconcile(
            token.clone(),
            Arc::clone(&self.pool),
            self.config.agent_observatory.clone(),
        );
        MaintenanceHandles {
            token,
            purge,
            storage,
            docker_ingest,
            file_tail,
            error_scan,
            notification_dispatcher,
            notification_evaluator,
            notification_digest,
            inventory_refresh,
            inventory_backfill,
            graph_refresh,
            session_rollup,
            timeline_rollup,
            optimize,
            agent_observatory_projector,
            agent_observatory_git,
            syslog_monitor: None,
        }
    }

    fn spawn_file_tail_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let supervisor = self.file_tail_supervisor.clone();
        Some(tokio::spawn(async move {
            if let Err(err) = supervisor.reconcile().await {
                tracing::warn!(error = %err, "initial file-tail reconcile failed");
            }
            let mut interval = background_interval(tokio::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        let report = supervisor.shutdown(std::time::Duration::from_secs(2)).await;
                        assert!(report.clean(), "file-tail shutdown was not clean");
                        tracing::debug!("file_tail: cooperative shutdown");
                        break;
                    }
                    _ = interval.tick() => {
                        if let Err(err) = supervisor.reconcile().await {
                            tracing::warn!(error = %err, "file-tail reconcile failed");
                        }
                    }
                }
            }
        }))
    }

    /// Periodically run `PRAGMA optimize` so the query planner keeps fresh
    /// `sqlite_stat1` statistics as the DB grows.
    ///
    /// This is load-bearing, not cosmetic: the AI/error covering indexes
    /// (migrations 23-24) are only *chosen* by the planner when stats exist —
    /// without them SQLite falls back to no-stats heuristics that pick
    /// `idx_logs_timestamp` and scan the whole recent partition (the ~28s
    /// `ai blocks` / ~16s `ai tools` pathology). Migration 24 lays down a
    /// baseline ANALYZE; this task prevents it from going stale. `PRAGMA
    /// optimize` is incremental (re-analyzes only tables that changed enough)
    /// and bounded by the connection's `analysis_limit=400`, so each run is
    /// cheap and holds the write lock only briefly.
    fn spawn_optimize_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let handle = tokio::spawn(async move {
            let mut interval =
                background_interval(tokio::time::Duration::from_secs(OPTIMIZE_INTERVAL_SECS));
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        tracing::debug!("optimize: cooperative shutdown");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                observability.record_task_tick("optimize"); // records loop scheduled (not completion)
                let Ok(_permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("Maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&pool);
                let started = Instant::now();
                let result = tokio::task::spawn_blocking(move || {
                    let conn = pool.get()?;
                    conn.execute_batch("PRAGMA optimize;")?;
                    anyhow::Ok(())
                })
                .await;
                match result {
                    Ok(Ok(())) => tracing::debug!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "PRAGMA optimize completed"
                    ),
                    Ok(Err(e)) => tracing::warn!(error = %e, "PRAGMA optimize failed"),
                    Err(e) => tracing::warn!(error = %e, "PRAGMA optimize task join error"),
                }
            }
        });
        Some(handle)
    }

    /// Periodically refresh the AI session rollup (beads cortex-2vre,
    /// cortex-g33v).
    ///
    /// `list_ai_sessions` (unbounded) reads from `ai_session_rollup` for an
    /// O(#sessions) indexed scan instead of the O(#AI-rows) live aggregation.
    /// This task recomputes the rollup on a fixed cadence so reads stay fast and
    /// staleness is bounded by `SESSION_ROLLUP_REFRESH_SECS`. The first refresh
    /// runs shortly after start so the rollup is warm before the first request.
    ///
    /// Each tick uses a cheap AI-row watermark to skip the (expensive) full
    /// re-aggregation when nothing changed since the last refresh — so an idle
    /// or write-but-no-AI-traffic host pays only the index-only fingerprint
    /// check, not a recurring GROUP-BY scan holding the maintenance permit.
    fn spawn_session_rollup_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let handle = tokio::spawn(async move {
            // Initial refresh after a short delay (lets startup settle), then on
            // a fixed interval. `background_interval` fires the first tick after
            // a full period, so do one eager refresh up front.
            let mut interval = background_interval(tokio::time::Duration::from_secs(
                SESSION_ROLLUP_REFRESH_SECS,
            ));
            let mut eager = true;
            loop {
                if !eager {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            tracing::debug!("session_rollup: cooperative shutdown");
                            break;
                        }
                        _ = interval.tick() => {}
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            tracing::debug!("session_rollup: cancelled before first refresh");
                            break;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                    }
                    eager = false;
                }
                observability.record_task_tick("session_rollup"); // records loop scheduled (not completion)
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("session_rollup: maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&pool);
                let started = Instant::now();
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    // Skip the full re-aggregation when the AI-row partition is
                    // unchanged since the last refresh (bead cortex-g33v).
                    let outcome = db::refresh_ai_session_rollup_if_stale(&pool)?;
                    Ok::<_, anyhow::Error>((outcome, db::ai_session_rollup_status(&pool)?))
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok((db::RollupRefresh::Skipped, _)) => tracing::debug!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "session_rollup: source unchanged, refresh skipped"
                    ),
                    Ok((db::RollupRefresh::Refreshed { .. }, status)) => tracing::info!(
                        status = %status.summary(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "session_rollup: refresh complete"
                    ),
                    Err(error) => {
                        tracing::error!(%error, "session_rollup: refresh failed")
                    }
                }
            }
        });
        Some(handle)
    }

    /// Periodically fold newly-ingested logs into the `timeline_hourly` rollup
    /// (bead syslog-mcp-kcvq) so `timeline` (hour/day/week/month) and
    /// `stats.total_logs` read O(#buckets) instead of scanning the whole table.
    ///
    /// Unlike the AI session rollup, this is INCREMENTAL: each tick aggregates
    /// only `logs WHERE id > watermark` and upsert-adds into the per-hour
    /// buckets (the rollup holds only COUNT(*), which is self-maintainable for
    /// adds). A no-op tick (watermark current) is a single cheap `MAX(id)` read.
    ///
    /// Retention DELETEs are handled separately by the retention task, which
    /// prunes stale low buckets after each purge — NOT here, because the
    /// watermark only advances on inserts and would never notice a delete.
    fn spawn_timeline_rollup_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(
                TIMELINE_ROLLUP_REFRESH_SECS,
            ));
            let mut eager = true;
            loop {
                if !eager {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            tracing::debug!("timeline_rollup: cooperative shutdown");
                            break;
                        }
                        _ = interval.tick() => {}
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            tracing::debug!("timeline_rollup: cancelled before first refresh");
                            break;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                    }
                    eager = false;
                }
                observability.record_task_tick("timeline_rollup"); // records loop scheduled (not completion)
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("timeline_rollup: maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&pool);
                let started = Instant::now();
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let folded = db::refresh_timeline_rollup(&pool)?;
                    db::prune_expired_stream_lineage(&pool)?;
                    Ok::<_, anyhow::Error>(folded)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok(0) => tracing::debug!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "timeline_rollup: watermark current, nothing folded"
                    ),
                    Ok(folded) => tracing::debug!(
                        folded,
                        elapsed_ms = started.elapsed().as_millis(),
                        "timeline_rollup: folded new rows"
                    ),
                    Err(error) => {
                        tracing::error!(%error, "timeline_rollup: refresh failed")
                    }
                }
            }
        });
        Some(handle)
    }

    fn spawn_inventory_backfill_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        match db::inventory_backfill_complete(&self.pool) {
            Ok(true) => return None,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "inventory_backfill: state probe failed");
                return None;
            }
        }
        let pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        Some(tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    tracing::debug!("inventory_backfill: cancelled before start");
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {}
            }
            if token.is_cancelled() {
                return;
            }
            let Ok(_permit) = limiter.acquire_owned().await else {
                return;
            };
            let result = tokio::task::spawn_blocking(move || db::backfill_inventory_stats(&pool))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|inner| inner);
            if let Err(error) = result {
                tracing::error!(%error, "inventory_backfill: failed");
            }
        }))
    }

    fn spawn_notification_dispatcher(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let inner = crate::notifications::dispatcher::spawn_dispatcher(
            Arc::clone(&self.pool),
            Arc::clone(&self.dispatcher_permit),
            self.config.notifications.clone(),
            token.clone(),
        )?;
        Some(spawn_notification_wrapper("dispatcher", token, inner))
    }

    fn spawn_notification_evaluator(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let inner = crate::notifications::evaluator::spawn_evaluator(
            Arc::clone(&self.pool),
            Arc::clone(&self.maintenance_permit),
            self.config.notifications.clone(),
            token.clone(),
        )?;
        Some(spawn_notification_wrapper("evaluator", token, inner))
    }

    fn spawn_notification_digest(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let inner = crate::notifications::digest::spawn_digest(
            Arc::clone(&self.pool),
            Arc::clone(&self.maintenance_permit),
            self.config.notifications.clone(),
            token.clone(),
        )?;
        Some(spawn_notification_wrapper("digest", token, inner))
    }

    fn spawn_error_scan_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let cfg = self.config.error_detection.clone();
        if !cfg.enabled {
            return None;
        }
        let pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let interval_secs = cfg.scan_interval_secs.max(1);
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        tracing::debug!("error_scan: cooperative shutdown");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                observability.record_task_tick("error_scan");
                tracing::debug!("error_scan: scan cycle starting");
                match crate::app::error_detection::run_error_scan(
                    Arc::clone(&pool),
                    Arc::clone(&limiter),
                    cfg.clone(),
                )
                .await
                {
                    Ok(n) => tracing::info!(rows_processed = n, "error_scan: cycle complete"),
                    Err(e) => tracing::error!(error = %e, "error_scan: cycle failed"),
                }
            }
        });
        Some(handle)
    }

    fn spawn_retention_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        let retention_days = self.config.storage.retention_days;
        if retention_days == 0 && HEARTBEAT_RETENTION_DAYS == 0 {
            return None;
        }
        let purge_pool = Arc::clone(&self.pool);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let fts_merge_pages = self.config.enrichment.fts_merge_pages;
        let cleanup_chunk_size = self.config.storage.cleanup_chunk_size;
        let handle = tokio::spawn(async move {
            let period = tokio::time::Duration::from_secs(3600);
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + retention_initial_delay(),
                period,
            );
            // Orphan child rows are rare by construction: both the write path
            // and `delete_heartbeat_chunk_where` delete children and parent
            // inside a single transaction, so neither can strand a child. Any
            // orphans are legacy or repair-only residue.
            // Sweeping for them means a full scan of every heartbeat child
            // table, which is wasted I/O at the hourly retention cadence even
            // now that the scan no longer holds the write lock. Run it on the
            // first tick after start (so a crash-induced backlog is cleared
            // promptly) and daily thereafter.
            let mut tick: u64 = 0;
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        tracing::debug!("retention_purge: cooperative shutdown");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                let orphan_sweep = if tick.is_multiple_of(ORPHAN_SWEEP_EVERY_N_TICKS) {
                    db::OrphanSweep::Run
                } else {
                    db::OrphanSweep::Skip
                };
                tick = tick.wrapping_add(1);
                let started = Instant::now();
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("Maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&purge_pool);
                observability.record_task_tick("retention_purge");
                tracing::debug!(retention_days, "Retention purge tick started");
                // Tag-based purge runs FIRST so the global purge below scans
                // a smaller working set and FTS merge work consolidates.
                // Hardcoded 7-day windows for AdGuard tags. Other tags fall
                // through to the global retention_days policy.
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    // Tag-window purges are independent maintenance ops. A
                    // transient SQLITE_BUSY on one tag must NOT abort the
                    // others or the global retention purge — that would stall
                    // all retention for an hour.
                    let mut tag_deleted: usize = 0;
                    for tag in ADGUARD_RETENTION_TAGS {
                        match db::purge_by_tag_window(
                            &pool,
                            tag,
                            ADGUARD_RETENTION_DAYS,
                            fts_merge_pages,
                        ) {
                            Ok(n) => tag_deleted += n,
                            Err(e) => tracing::error!(
                                tag,
                                error = %e,
                                "Tag-window purge failed; continuing"
                            ),
                        }
                    }
                    let heartbeat_deleted = match db::purge_old_heartbeats(
                        &pool,
                        HEARTBEAT_RETENTION_DAYS,
                        cleanup_chunk_size,
                        orphan_sweep,
                    ) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Heartbeat retention purge failed; continuing"
                            );
                            0
                        }
                    };
                    let global_deleted =
                        db::purge_old_logs(&pool, retention_days, fts_merge_pages)?;
                    let receipt_deleted = db::purge_forward_receipts(&pool, cleanup_chunk_size)?;
                    if receipt_deleted > 0 {
                        tracing::info!(
                            deleted = receipt_deleted,
                            "Purged expired forwarding receipts"
                        );
                    }
                    // llm_invocations (migration 37) has no severity concept and no
                    // volume-driven need for its own hardcoded cap (unlike AdGuard
                    // tags/heartbeats above), so it rides the same global
                    // retention_days knob as logs.
                    let llm_invocations_deleted = match db::purge_old_llm_invocations(
                        &pool,
                        retention_days,
                        cleanup_chunk_size,
                    ) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "llm_invocations retention purge failed; continuing"
                            );
                            0
                        }
                    };
                    // Retention deletes OLDEST logs; the timeline_hourly rollup's
                    // ingest watermark only advances on inserts, so it would
                    // never notice these deletes and old buckets would ghost
                    // (stats SUM drifting up unbounded on idle hosts). Prune
                    // rollup buckets older than the oldest remaining log here.
                    // A failure must not abort the purge accounting.
                    if let Err(e) = db::prune_timeline_rollup(&pool) {
                        tracing::error!(error = %e, "timeline rollup prune failed; continuing");
                    }
                    Ok::<(usize, usize, usize, usize), anyhow::Error>((
                        tag_deleted,
                        heartbeat_deleted,
                        global_deleted,
                        llm_invocations_deleted,
                    ))
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok((
                        tag_deleted,
                        heartbeat_deleted,
                        global_deleted,
                        llm_invocations_deleted,
                    )) => tracing::info!(
                        retention_days,
                        tag_deleted,
                        heartbeat_deleted,
                        global_deleted,
                        llm_invocations_deleted,
                        total_deleted = tag_deleted
                            + heartbeat_deleted
                            + global_deleted
                            + llm_invocations_deleted,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Retention purge tick completed"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        retention_days,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to purge old logs"
                    ),
                }
            }
        });
        tracing::info!(retention_days, "Log retention purge task started (hourly)");
        Some(handle)
    }

    fn spawn_storage_task(&self, token: CancellationToken) -> Option<JoinHandle<()>> {
        if self.config.storage.max_db_size_mb == 0 && self.config.storage.min_free_disk_mb == 0 {
            return None;
        }
        let storage_pool = Arc::clone(&self.pool);
        let storage_config = self.config.storage.clone();
        let notifications_cfg = self.config.notifications.clone();
        let shared_storage_state = Arc::clone(&self.storage_state);
        let limiter = Arc::clone(&self.maintenance_permit);
        let observability = Arc::clone(&self.observability);
        let handle = tokio::spawn(async move {
            let mut last_full_transitions = 0u64;
            let mut last_udp_queue_drops = 0u64;
            let mut interval = background_interval(tokio::time::Duration::from_secs(
                storage_config.cleanup_interval_secs,
            ));
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        tracing::debug!("storage_budget: cooperative shutdown");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                let started = Instant::now();
                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    tracing::error!("Maintenance limiter closed");
                    continue;
                };
                let pool = Arc::clone(&storage_pool);
                let storage = storage_config.clone();
                // Carry the previous tick's write_blocked into enforcement so the
                // external disk-pressure block latches with hysteresis (engage at
                // min_free_disk_mb, clear only at recovery_free_disk_mb) rather than
                // flapping at the trigger threshold (syslog-mcp-w4hh).
                let prev_write_blocked = shared_storage_state
                    .lock()
                    .as_ref()
                    .map(|s| s.write_blocked)
                    .unwrap_or(false);
                observability.record_task_tick("storage_budget");
                tracing::debug!(
                    cleanup_interval_secs = storage_config.cleanup_interval_secs,
                    "Storage budget enforcement tick started"
                );
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let outcome = db::enforce_storage_budget_with_state(
                        &pool,
                        &storage,
                        &db::SystemDiskSpaceProbe,
                        prev_write_blocked,
                    )?;
                    // Storage guardrail also deletes OLDEST logs; prune ghosted
                    // timeline_hourly buckets so stats/timeline totals don't drift
                    // (same rationale as the retention task). Best-effort.
                    if outcome.deleted_rows > 0
                        && let Err(e) = db::prune_timeline_rollup(&pool)
                    {
                        tracing::error!(
                            error = %e,
                            "timeline rollup prune after storage enforcement failed; continuing"
                        );
                    }
                    if let Err(error) = db::checkpoint_wal_and_incremental_vacuum(&pool, &storage) {
                        tracing::warn!(
                            error = %error,
                            "Periodic SQLite maintenance skipped (non-fatal)"
                        );
                    }
                    Ok::<_, anyhow::Error>(outcome)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok(outcome) => {
                        let previous_blocked = {
                            let mut state = shared_storage_state.lock();
                            let previous_blocked = state.as_ref().map(|s| s.write_blocked);
                            *state = Some(StorageBudgetState {
                                metrics: outcome.metrics.clone(),
                                write_blocked: outcome.write_blocked,
                            });
                            previous_blocked
                        };

                        // Disk fill alert: fire when free disk is below storage guardrail thresholds.
                        // Uses the same min_free_disk_mb (critical) and recovery_free_disk_mb (warning)
                        // that the storage guardrail uses — no extra config needed.
                        if let Some(free_bytes) = outcome.metrics.free_disk_bytes
                            && notifications_cfg.enabled
                            && notifications_cfg.evaluators.disk_fill
                            && !notifications_cfg.apprise_urls.is_empty()
                        {
                            let critical_bytes =
                                storage_config.min_free_disk_mb.saturating_mul(1024 * 1024);
                            let warn_bytes = storage_config
                                .recovery_free_disk_mb
                                .saturating_mul(1024 * 1024);
                            let urls_json = serde_json::to_string(&notifications_cfg.apprise_urls)
                                .unwrap_or_else(|_| "[]".to_string());
                            let hostname = crate::env::var("HOSTNAME")
                                .unwrap_or_else(|_| "localhost".to_string());
                            if let Some(params) = crate::notifications::rules::evaluate_disk_fill(
                                &hostname,
                                free_bytes,
                                critical_bytes,
                                warn_bytes,
                                &urls_json,
                            ) {
                                let pool_n = Arc::clone(&storage_pool);
                                let result = tokio::task::spawn_blocking(move || {
                                    let conn = pool_n.get()?;
                                    crate::db::notifications::outbox_insert(&conn, &params)
                                        .map_err(anyhow::Error::from)
                                })
                                .await;
                                match result {
                                    Ok(Ok(())) => {
                                        tracing::debug!("disk_fill: outbox row queued")
                                    }
                                    Ok(Err(e)) => tracing::warn!(
                                        error = %e,
                                        "disk_fill: outbox_insert failed (non-fatal)"
                                    ),
                                    Err(e) => tracing::warn!(
                                        error = %e,
                                        "disk_fill: spawn_blocking failed (non-fatal)"
                                    ),
                                }
                            }
                        }

                        if notifications_cfg.enabled
                            && notifications_cfg.evaluators.ingest_queue_pressure
                            && !notifications_cfg.apprise_urls.is_empty()
                        {
                            let snapshot = observability.snapshot();
                            let full_transitions_delta = snapshot
                                .syslog_write_channel_full_transitions
                                .saturating_sub(last_full_transitions);
                            let udp_drops_delta = snapshot
                                .syslog_udp_packets_dropped_queue_full
                                .saturating_sub(last_udp_queue_drops);
                            last_full_transitions = snapshot.syslog_write_channel_full_transitions;
                            last_udp_queue_drops = snapshot.syslog_udp_packets_dropped_queue_full;

                            let urls_json = serde_json::to_string(&notifications_cfg.apprise_urls)
                                .unwrap_or_else(|_| "[]".to_string());
                            let hostname = crate::env::var("HOSTNAME")
                                .unwrap_or_else(|_| "localhost".to_string());
                            if let Some(params) =
                                crate::notifications::rules::evaluate_ingest_queue_pressure(
                                    &hostname,
                                    full_transitions_delta,
                                    udp_drops_delta,
                                    snapshot.ingest_queue_depth,
                                    snapshot.ingest_queue_capacity,
                                    &urls_json,
                                )
                            {
                                let pool_n = Arc::clone(&storage_pool);
                                let result = tokio::task::spawn_blocking(move || {
                                    let conn = pool_n.get()?;
                                    crate::db::notifications::outbox_insert(&conn, &params)
                                        .map_err(anyhow::Error::from)
                                })
                                .await;
                                match result {
                                    Ok(Ok(())) => {
                                        tracing::debug!("ingest_queue_pressure: outbox row queued")
                                    }
                                    Ok(Err(e)) => tracing::warn!(
                                        error = %e,
                                        "ingest_queue_pressure: outbox_insert failed (non-fatal)"
                                    ),
                                    Err(e) => tracing::warn!(
                                        error = %e,
                                        "ingest_queue_pressure: spawn_blocking failed (non-fatal)"
                                    ),
                                }
                            }
                        }

                        if outcome.deleted_rows > 0
                            || outcome.write_blocked
                            || previous_blocked != Some(outcome.write_blocked)
                        {
                            tracing::info!(
                                deleted_rows = outcome.deleted_rows,
                                logical_db_size_bytes = outcome.metrics.logical_db_size_bytes,
                                physical_db_size_bytes = outcome.metrics.physical_db_size_bytes,
                                free_disk_bytes = ?outcome.metrics.free_disk_bytes,
                                write_blocked = outcome.write_blocked,
                                elapsed_ms = started.elapsed().as_millis(),
                                "Storage budget enforcement tick completed"
                            );
                        } else {
                            tracing::debug!(
                                deleted_rows = outcome.deleted_rows,
                                logical_db_size_bytes = outcome.metrics.logical_db_size_bytes,
                                physical_db_size_bytes = outcome.metrics.physical_db_size_bytes,
                                free_disk_bytes = ?outcome.metrics.free_disk_bytes,
                                write_blocked = outcome.write_blocked,
                                elapsed_ms = started.elapsed().as_millis(),
                                "Storage budget enforcement tick completed"
                            );
                        }
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to enforce storage budget"
                    ),
                }
            }
        });
        tracing::info!(
            cleanup_interval_secs = self.config.storage.cleanup_interval_secs,
            "Storage budget enforcement task started"
        );
        Some(handle)
    }
}

/// Defense-in-depth duplicate of `validate_auth_config` for callers that use
/// `RuntimeCore::for_server(config)` without going through `Config::load()`.
fn reject_unsafe_otlp_oauth_only_exposure(config: &Config, is_stdio: bool) -> Result<()> {
    if is_stdio || config.mcp.auth.mode != AuthMode::OAuth {
        return Ok(());
    }

    if config.mcp.no_auth {
        if !mcp_bind_is_loopback(config) && !config.mcp.trusted_gateway_no_auth {
            anyhow::bail!(
                "refusing non-loopback CORTEX_NO_AUTH=true without \
                 CORTEX_TRUSTED_GATEWAY_NO_AUTH=true"
            );
        }
        return Ok(());
    }

    if !mcp_bind_is_loopback(config) && !mcp_static_token_active(config) {
        anyhow::bail!(
            "refusing to mount OTLP /v1/logs on non-loopback OAuth-only deployment: \
             OTLP only supports CORTEX_TOKEN Bearer auth today; set CORTEX_TOKEN, \
             bind to loopback, or set CORTEX_NO_AUTH=true plus \
             CORTEX_TRUSTED_GATEWAY_NO_AUTH=true when an upstream gateway protects all \
             mounted routes"
        );
    }

    Ok(())
}

fn mcp_static_token_active(config: &Config) -> bool {
    config
        .mcp
        .api_token
        .as_deref()
        .is_some_and(|t| !t.trim().is_empty())
}

/// Decide which [`AuthPolicy`] to install on [`mcp::AppState`] given the
/// fully-loaded [`Config`].
///
/// Decision table (locked by the OAuth epic, post eng-review):
///
/// | `auth.mode` | `api_token` | bind         | result                                         |
/// |-------------|-------------|--------------|------------------------------------------------|
/// | `OAuth`     | any         | any          | `Mounted { auth_state: Some(_) }` (full OAuth) |
/// | `Bearer`    | set         | any          | `Mounted { auth_state: None }` (bearer-only)   |
/// | `Bearer`    | unset       | loopback     | `LoopbackDev` (dev mode; no auth enforced)     |
/// | `Bearer`    | unset       | non-loopback | rejected by `validate_auth_config` at startup  |
/// | any          | any         | loopback     | `LoopbackDev` when `mcp.no_auth` is true       |
/// | any          | any         | non-loopback | `TrustedGatewayUnscoped` when both no-auth flags are true |
///
/// Bearer-only (`static_token` set, no OAuth) produces `Mounted { auth_state: None }` so
/// that scope checks in tool dispatch (S5) know middleware is enforcing auth.
/// `lab_auth::AuthState::new` is only called for the OAuth row — it requires
/// mode == OAuth and initialises Google OIDC + SQLite session storage.
async fn build_auth_policy(config: &Config, is_stdio: bool) -> Result<AuthPolicy> {
    if config.mcp.no_auth {
        if mcp_bind_is_loopback(config) {
            tracing::warn!(
                mcp_bind = %config.mcp.bind_addr(),
                "cortex auth policy: LoopbackDev (NO_AUTH=true on loopback)"
            );
            return Ok(AuthPolicy::LoopbackDev);
        }
        if config.mcp.trusted_gateway_no_auth {
            tracing::warn!(
                mcp_bind = %config.mcp.bind_addr(),
                "cortex auth policy: TrustedGatewayUnscoped (NO_AUTH=true; upstream gateway must enforce access)"
            );
            return Ok(AuthPolicy::TrustedGatewayUnscoped);
        }
        anyhow::bail!(
            "refusing non-loopback CORTEX_NO_AUTH=true without \
             CORTEX_TRUSTED_GATEWAY_NO_AUTH=true"
        );
    }

    if is_stdio {
        if config.mcp.auth.mode == AuthMode::OAuth {
            tracing::warn!(
                "CORTEX_AUTH_MODE=oauth is set but cortex is starting in stdio mode — \
                 OAuth config is ignored; LoopbackDev policy applies (process isolation is the \
                 trust boundary). If auth enforcement is required, use the HTTP server mode instead."
            );
        }
        tracing::info!(
            "cortex auth policy: LoopbackDev (stdio mode — process isolation is the trust boundary)"
        );
        return Ok(AuthPolicy::LoopbackDev);
    }

    let auth = &config.mcp.auth;
    let oauth_active = auth.mode == AuthMode::OAuth;
    let static_token_active = mcp_static_token_active(config);

    if !oauth_active {
        if static_token_active {
            // Bearer-only: middleware (AuthLayer) is mounted with just the
            // static token. Scope checks in S5 MUST run — use Mounted so the
            // tool dispatcher knows auth is enforced.
            tracing::info!(
                mcp_bind = %config.mcp.bind_addr(),
                "cortex auth policy: Mounted {{ auth_state: None }} (bearer-only; lab-auth OAuth not wired)"
            );
            return Ok(AuthPolicy::Mounted { auth_state: None });
        }

        // No auth at all — only legal on loopback (validated by validate_auth_config,
        // but double-checked here so LoopbackDev can never slip past on a non-loopback bind).
        // The early return above guarantees `is_stdio` is false here, so the bind
        // check always applies.
        if !mcp_bind_is_loopback(config) {
            anyhow::bail!(
                "internal invariant violated: no auth wired but bind `{}` is non-loopback",
                config.mcp.host
            );
        }
        tracing::info!(
            mcp_bind = %config.mcp.bind_addr(),
            "cortex auth policy: LoopbackDev (no auth wired; loopback bind)"
        );
        return Ok(AuthPolicy::LoopbackDev);
    }

    // Resolve auth file paths against the directory containing the cortex DB
    // so a single `/data` bind-mount captures everything.
    let storage_dir = config
        .storage
        .db_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let resolved_db_path = resolve_auth_path(storage_dir, &auth.sqlite_path);
    let resolved_key_path = resolve_auth_path(storage_dir, &auth.key_path);

    // Surface the refresh-token TTL override at info level — lab-auth's default
    // is 30 days; cortex deliberately ships a tighter (8h) ceiling.
    tracing::info!(
        refresh_token_ttl_secs = auth.refresh_token_ttl_secs,
        "cortex auth refresh TTL override (lab-auth default is 30d)"
    );

    // Build the env-var "fake source" that lab-auth's AuthConfigBuilder consumes.
    // Lab-auth never consults real `std::env::var` here — we hand it exactly
    // what we want it to see, derived from our typed `Config`.
    let mut vars: Vec<(String, String)> = Vec::with_capacity(16);
    push_var(
        &mut vars,
        "CORTEX_AUTH_MODE",
        if oauth_active { "oauth" } else { "bearer" },
    );
    if let Some(url) = auth.public_url.as_deref() {
        push_var(&mut vars, "CORTEX_PUBLIC_URL", url);
    }
    if let Some(id) = auth.google_client_id.as_deref() {
        push_var(&mut vars, "CORTEX_GOOGLE_CLIENT_ID", id);
    }
    if let Some(secret) = auth.google_client_secret.as_deref() {
        push_var(&mut vars, "CORTEX_GOOGLE_CLIENT_SECRET", secret);
    }
    if !auth.admin_email.is_empty() {
        push_var(&mut vars, "CORTEX_AUTH_ADMIN_EMAIL", &auth.admin_email);
    }
    // NOTE: lab-auth does not consume cortex's TOML `allowed_emails`.
    // It enforces `admin_email` plus lab-auth-managed allowed users.
    // cortex rejects non-empty config-level allowed_emails in OAuth mode
    // until that list is enforceable. Do NOT add a no-op push_var here; the
    // entries would be silently ignored by AuthConfigBuilder.build_from_sources.
    push_var(
        &mut vars,
        "CORTEX_AUTH_SQLITE_PATH",
        &resolved_db_path.to_string_lossy(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_KEY_PATH",
        &resolved_key_path.to_string_lossy(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_ACCESS_TOKEN_TTL_SECS",
        &auth.access_token_ttl_secs.to_string(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_REFRESH_TOKEN_TTL_SECS",
        &auth.refresh_token_ttl_secs.to_string(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_CODE_TTL_SECS",
        &auth.auth_code_ttl_secs.to_string(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_REGISTER_REQUESTS_PER_MINUTE",
        &auth.register_rpm.to_string(),
    );
    push_var(
        &mut vars,
        "CORTEX_AUTH_AUTHORIZE_REQUESTS_PER_MINUTE",
        &auth.authorize_rpm.to_string(),
    );
    if !auth.allowed_client_redirect_uris.is_empty() {
        push_var(
            &mut vars,
            "CORTEX_AUTH_ALLOWED_REDIRECT_URIS",
            &auth.allowed_client_redirect_uris.join(","),
        );
    }

    let auth_config = lab_auth::config::AuthConfigBuilder::new()
        .env_prefix("CORTEX")
        .session_cookie_name("cortex_session")
        .scopes_supported(vec!["cortex:read".into(), "cortex:admin".into()])
        .default_scope("cortex:read")
        .resource_path("/mcp")
        // Honour `static_token_is_admin` in OAuth+bearer hybrid mode too.
        // The same flag that gates `build_auth_layer` (bearer-only) must also
        // control the scopes injected by lab-auth's AuthConfigBuilder for the
        // OAuth path. Without this, setting `CORTEX_STATIC_TOKEN_ADMIN=false`
        // (the default) would be a no-op in OAuth+bearer hybrid deployments.
        .static_token_scopes(if config.mcp.static_token_is_admin {
            vec!["cortex:read".into(), "cortex:admin".into()]
        } else {
            vec!["cortex:read".into()]
        })
        .disable_static_token_with_oauth(auth.disable_static_token_with_oauth)
        .enable_dynamic_registration(true)
        .build_from_sources(vars)
        .context("failed to build lab-auth AuthConfig from cortex config")?;

    let auth_state = lab_auth::state::AuthState::new(auth_config)
        .await
        .context("failed to initialize lab-auth AuthState")?;

    // lab-auth's SqliteStore::open creates the DB but only *checks* perms when
    // the file pre-existed. Enforce 0600 explicitly for the freshly-created
    // case. The JWT key path is already chmodded by lab-auth's jwt::SigningKeys.
    enforce_restrictive_permissions(&resolved_db_path).with_context(|| {
        format!(
            "failed to enforce 0600 permissions on auth db `{}`",
            resolved_db_path.display()
        )
    })?;
    enforce_restrictive_permissions(&resolved_key_path).with_context(|| {
        format!(
            "failed to enforce 0600 permissions on auth key `{}`",
            resolved_key_path.display()
        )
    })?;

    tracing::info!(
        oauth_active,
        static_token_active,
        auth_db = %resolved_db_path.display(),
        auth_key = %resolved_key_path.display(),
        "cortex auth policy: Mounted (lab-auth state initialized)"
    );

    Ok(AuthPolicy::Mounted {
        auth_state: Some(Arc::new(auth_state)),
    })
}

fn push_var(vars: &mut Vec<(String, String)>, key: &str, value: &str) {
    vars.push((key.to_string(), value.to_string()));
}

/// Resolve `path` against `base` if it is relative. Absolute paths are
/// returned untouched. Mirrors the `[mcp.auth].sqlite_path` and `key_path`
/// resolution rules documented on `AuthConfig`.
fn resolve_auth_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Enforce `chmod 0600` on a file. Unix-only; on other platforms this is a
/// no-op (lab-auth makes the same trade-off — see `lab_auth::util`).
#[cfg(unix)]
fn enforce_restrictive_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        // Nothing to lock down. lab-auth owns creation; this guards against
        // an unexpected order of operations.
        anyhow::bail!("expected file at {} after auth init", path.display());
    }
    let metadata = std::fs::metadata(path).with_context(|| format!("stat `{}`", path.display()))?;
    let current = metadata.permissions().mode() & 0o777;
    if current & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 `{}`", path.display()))?;
        tracing::warn!(
            path = %path.display(),
            previous_mode = format!("{:o}", current),
            "Tightened auth file permissions to 0600"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_restrictive_permissions(_path: &Path) -> Result<()> {
    // File-permission enforcement is not implemented on non-Unix platforms.
    // OAuth mode must not be used in this configuration because the JWT signing
    // key and auth database cannot be protected to 0600 permissions.
    anyhow::bail!(
        "OAuth mode is not supported on non-Unix platforms: cannot enforce \
         restrictive file permissions (0600) on the JWT signing key and auth database. \
         Use bearer-token auth instead."
    )
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
