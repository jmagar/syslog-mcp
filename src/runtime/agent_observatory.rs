//! Bounded, cancellable Agent Observatory projector and Git reconcile workers.

use crate::agent_observatory::projector::{
    project_agent_source_with_cursor, project_log_row_with_cursor,
};
use crate::config::AgentObservatoryConfig;
use crate::db::agent_observatory::{
    AgentSourceKind, advance_projection_cursor, page_agent_sources, projection_cursor,
    projection_wake_receiver, record_projection_health,
};
use crate::db::page_agent_projection_logs;
use crate::db::{
    DbPool, TRANSIENT_SQLITE_RETRY_DELAYS_MS, is_pool_acquire_failure, is_transient_sqlite_lock,
};
use crate::git_observer::discovery::{DiscoveryOptions, discover_repositories};
use crate::git_observer::reconcile::{ReconcileOptions, reconcile_one_repository};
use crate::scanner::local_hostname;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const SOURCE_KINDS: [AgentSourceKind; 7] = [
    AgentSourceKind::Mcp,
    AgentSourceKind::Hook,
    AgentSourceKind::Skill,
    AgentSourceKind::Llm,
    AgentSourceKind::OtelSpan,
    AgentSourceKind::OtelMetric,
    AgentSourceKind::RepositoryObservation,
];

fn source_name(kind: AgentSourceKind) -> &'static str {
    kind.as_str()
}

/// A repository-round-robin checkpoint. Reconciliation itself commits its
/// topology, commit, and observation snapshot atomically. This cursor is
/// deliberately advanced only after that transaction succeeds, so a crash may
/// replay one repository but can never skip it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitReconcileCursor {
    #[serde(default)]
    after_repository: Option<String>,
}

fn decode_git_reconcile_cursor(raw: &str) -> anyhow::Result<GitReconcileCursor> {
    if raw.is_empty() {
        return Ok(GitReconcileCursor::default());
    }
    serde_json::from_str(raw).map_err(Into::into)
}

fn encode_git_reconcile_cursor(repository: &str) -> String {
    serde_json::to_string(&GitReconcileCursor {
        after_repository: Some(repository.to_string()),
    })
    .expect("Git reconcile cursor serialization cannot fail")
}

/// Load the durable Git cursor, replacing malformed legacy state with the
/// canonical initial cursor before returning. The decode error is returned as
/// metadata so the caller can report the repair once without retrying the same
/// corrupt value on every reconcile interval.
fn load_git_reconcile_cursor(
    pool: &DbPool,
) -> anyhow::Result<(GitReconcileCursor, Option<anyhow::Error>)> {
    let raw = projection_cursor(pool, "git")?;
    match decode_git_reconcile_cursor(&raw) {
        Ok(cursor) => Ok((cursor, None)),
        Err(decode_error) => {
            advance_projection_cursor(pool, "git", "").map_err(|repair_error| {
                anyhow::anyhow!(
                    "failed to reset malformed Git cursor ({decode_error}): {repair_error}"
                )
            })?;
            Ok((GitReconcileCursor::default(), Some(decode_error)))
        }
    }
}

fn next_repository_index(repositories: &[PathBuf], cursor: &GitReconcileCursor) -> Option<usize> {
    if repositories.is_empty() {
        return None;
    }
    cursor
        .after_repository
        .as_deref()
        .and_then(|after| {
            repositories
                .iter()
                .position(|path| path.display().to_string().as_str() > after)
        })
        .or(Some(0))
}

fn projector_retry_delay_ms(attempt: usize) -> u64 {
    let index = attempt
        .saturating_sub(1)
        .min(TRANSIENT_SQLITE_RETRY_DELAYS_MS.len() - 1);
    TRANSIENT_SQLITE_RETRY_DELAYS_MS[index]
}

/// Page limits for one projection cycle. Copied out of
/// `AgentObservatoryConfig` so the cycle body can move into `spawn_blocking`
/// without cloning the whole config every tick.
#[derive(Debug, Clone, Copy)]
struct ProjectionLimits {
    page_rows: usize,
    page_bytes: usize,
}

/// What one projection cycle did, returned from the blocking thread to the
/// async loop that owns the retry ladder and the health write.
///
/// The cycle used to accumulate these five values inline across a dozen
/// interleaved DB calls in the async task; they are a struct so the whole body
/// can move onto a blocking thread as a unit.
#[derive(Debug, Clone, Copy)]
struct ProjectionCycle {
    projected: usize,
    healthy: bool,
    had_error: bool,
    retry_safe_errors_only: bool,
    oversized_first_rows: usize,
}

impl ProjectionCycle {
    const fn new() -> Self {
        Self {
            projected: 0,
            healthy: true,
            had_error: false,
            retry_safe_errors_only: true,
            oversized_first_rows: 0,
        }
    }

    /// A cycle that never ran (blocking task panicked or was cancelled). Not
    /// retry-safe: a panic is not backpressure, so it must not feed the
    /// transient-retry ladder.
    const fn aborted() -> Self {
        Self {
            projected: 0,
            healthy: false,
            had_error: true,
            retry_safe_errors_only: false,
            oversized_first_rows: 0,
        }
    }

    fn record_error(&mut self, error: &anyhow::Error) {
        self.healthy = false;
        self.had_error = true;
        self.retry_safe_errors_only &= projection_error_is_retry_safe(error);
    }
}

/// True when a projection failure is worth backing off and retrying rather
/// than treated as a persistent fault.
///
/// Covers pool-acquisition failures as well as SQLite BUSY/LOCKED. Under
/// contention the projector's own `pool.get()` is what times out, and
/// classifying that as a hard error dropped it onto the plain poll interval
/// instead of the backoff ladder — adding pressure to the exact condition that
/// caused it.
fn projection_error_is_retry_safe(error: &anyhow::Error) -> bool {
    is_transient_sqlite_lock(error) || is_pool_acquire_failure(error)
}

/// One full projection pass: logs, then each agent source kind.
///
/// Every call in here is a blocking pool call, so this runs on a blocking
/// thread — see the `spawn_blocking` in [`spawn_projector`].
fn run_projection_cycle(pool: &DbPool, limits: ProjectionLimits) -> ProjectionCycle {
    let mut cycle = ProjectionCycle::new();
    let log_page = projection_cursor(pool, "logs")
        .and_then(|value| {
            if value.is_empty() {
                Ok(0)
            } else {
                value.parse::<i64>().map_err(anyhow::Error::from)
            }
        })
        .and_then(|cursor| page_agent_projection_logs(pool, cursor, limits.page_rows));
    match log_page {
        Ok(rows) => {
            let mut page_bytes = 0usize;
            for (processed, row) in rows.into_iter().enumerate() {
                page_bytes = page_bytes.saturating_add(row.message.len());
                if page_bytes > limits.page_bytes && processed > 0 {
                    break;
                }
                cycle.oversized_first_rows +=
                    usize::from(page_bytes > limits.page_bytes && processed == 0);
                match project_log_row_with_cursor(pool, &row) {
                    Ok(()) => cycle.projected += 1,
                    Err(error) => {
                        cycle.record_error(&error);
                        tracing::error!(error = %error, "Agent Observatory log projection failed");
                        break;
                    }
                }
            }
        }
        Err(error) => {
            cycle.record_error(&error);
            tracing::error!(error = %error, "Agent Observatory log page failed");
        }
    }
    for kind in SOURCE_KINDS {
        let name = source_name(kind);
        let cursor = match projection_cursor(pool, name) {
            Ok(cursor) => cursor,
            Err(error) => {
                cycle.record_error(&error);
                tracing::error!(source_kind = ?kind, error = %error,
                    "Agent Observatory source cursor load failed");
                continue;
            }
        };
        match page_agent_sources(pool, kind, &cursor, limits.page_rows) {
            Ok(page) => {
                let mut page_bytes = 0usize;
                for (processed, record) in page.records.iter().enumerate() {
                    page_bytes = page_bytes.saturating_add(format!("{record:?}").len());
                    if page_bytes > limits.page_bytes && processed > 0 {
                        break;
                    }
                    cycle.oversized_first_rows +=
                        usize::from(page_bytes > limits.page_bytes && processed == 0);
                    let next_cursor = record.next_cursor();
                    match project_agent_source_with_cursor(pool, record, name, &next_cursor) {
                        Ok(_) => cycle.projected += 1,
                        Err(error) => {
                            cycle.record_error(&error);
                            tracing::error!(
                                source_kind = ?kind,
                                error = %error,
                                "Agent Observatory source projection failed"
                            );
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                cycle.record_error(&error);
                tracing::error!(source_kind = ?kind, error = %error,
                    "Agent Observatory source page failed");
            }
        }
    }
    cycle
}

pub(super) fn spawn_projector(
    token: CancellationToken,
    pool: Arc<DbPool>,
    config: AgentObservatoryConfig,
) -> Option<JoinHandle<()>> {
    config.enabled.then(|| {
        let mut wake = projection_wake_receiver();
        let limits = ProjectionLimits {
            page_rows: config.projector_page_rows,
            page_bytes: config.projector_page_bytes,
        };
        tokio::spawn(async move {
            let mut consecutive_retry_safe_failures = 0usize;
            loop {
                if token.is_cancelled() {
                    break;
                }
                // spawn_blocking: every call in `run_projection_cycle` is a
                // blocking pool call that can wait out the full connection
                // timeout, and the cycle makes many of them. Running it on the
                // async task parked a runtime worker for up to that timeout,
                // which is the pathology docker_ingest/supervisor.rs already
                // fixed for checkpoint loads (full-review PM8).
                let cycle = {
                    let pool = Arc::clone(&pool);
                    match tokio::task::spawn_blocking(move || run_projection_cycle(&pool, limits))
                        .await
                    {
                        Ok(cycle) => cycle,
                        Err(error) => {
                            tracing::error!(error = %error,
                                "Agent Observatory projection cycle task failed");
                            ProjectionCycle::aborted()
                        }
                    }
                };
                let retry_safe_failure = cycle.had_error && cycle.retry_safe_errors_only;
                let retry_delay_ms = if retry_safe_failure {
                    consecutive_retry_safe_failures =
                        consecutive_retry_safe_failures.saturating_add(1);
                    Some(projector_retry_delay_ms(consecutive_retry_safe_failures))
                } else {
                    consecutive_retry_safe_failures = 0;
                    None
                };
                let status = if cycle.healthy { "ok" } else { "error" };
                let detail = format!(
                    "projected={},oversized_first_rows={},retry_safe={retry_safe_failure},retry_delay_ms={}",
                    cycle.projected,
                    cycle.oversized_first_rows,
                    retry_delay_ms.unwrap_or(0)
                );
                record_health_blocking(&pool, "projector", status, detail).await;
                tracing::debug!(
                    projected = cycle.projected,
                    "Agent Observatory projector cycle completed"
                );
                if cycle.healthy {
                    tokio::select! {
                        biased;
                        () = token.cancelled() => break,
                        _ = wake.recv() => {},
                        () = tokio::time::sleep(Duration::from_millis(config.projector_poll_ms)) => {}
                    }
                } else {
                    let delay_ms = retry_delay_ms.unwrap_or(config.projector_poll_ms);
                    tokio::select! {
                        biased;
                        () = token.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                    }
                }
            }
        })
    })
}

/// `record_projection_health` off the async task — it is another blocking pool
/// call, and it runs on the error path, which is exactly when the pool is
/// contended.
async fn record_health_blocking(
    pool: &Arc<DbPool>,
    lane: &'static str,
    status: &str,
    detail: String,
) {
    let pool = Arc::clone(pool);
    let status = status.to_string();
    let result = tokio::task::spawn_blocking(move || {
        record_projection_health(&pool, lane, &status, &detail)
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(lane, error = %error,
            "Agent Observatory health write failed"),
        Err(error) => tracing::error!(lane, error = %error,
            "Agent Observatory health write task failed"),
    }
}

fn expand_root(root: &str) -> PathBuf {
    root.strip_prefix("~/").map_or_else(
        || PathBuf::from(root),
        |suffix| {
            crate::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/nonexistent"))
                .join(suffix)
        },
    )
}

pub(super) fn spawn_git_reconcile(
    token: CancellationToken,
    pool: Arc<DbPool>,
    config: AgentObservatoryConfig,
) -> Option<JoinHandle<()>> {
    (config.enabled && config.git.enabled).then(|| {
        tokio::spawn(async move {
            let roots = config.git.roots.iter().map(|root| expand_root(root)).collect::<Vec<_>>();
            let discovery_options = DiscoveryOptions {
                max_depth: config.git.max_depth,
                max_repositories: config.git.max_repositories,
            };
            let options = ReconcileOptions {
                hostname: local_hostname(),
                command_timeout: Duration::from_millis(config.git.command_timeout_ms),
                max_commits_per_transition: config.git.max_commits_per_transition,
                store_changed_paths: config.git.store_changed_paths,
                store_author_name: config.git.store_author_name,
                store_author_email_hash: config.git.store_author_email_hash,
            };
            loop {
                if token.is_cancelled() { break; }
                // spawn_blocking: discovery walks every configured root to
                // `max_depth` on the calling thread.
                let discovery = {
                    let roots = roots.clone();
                    match tokio::task::spawn_blocking(move || {
                        discover_repositories(&roots, discovery_options)
                    })
                    .await
                    {
                        Ok(discovery) => discovery,
                        Err(error) => {
                            tracing::error!(error = %error,
                                "Agent Observatory Git discovery task failed");
                            tokio::select! {
                                biased;
                                () = token.cancelled() => break,
                                () = tokio::time::sleep(Duration::from_secs(
                                    config.git.reconcile_interval_secs,
                                )) => continue,
                            }
                        }
                    }
                };
                let mut healthy = discovery.warnings.is_empty();
                for warning in discovery.warnings {
                    tracing::warn!(path = %warning.path.display(), kind = ?warning.kind,
                        "Agent Observatory Git discovery warning");
                }
                let mut repositories = discovery.repositories;
                repositories.sort_by(|left, right| left.as_os_str().cmp(right.as_os_str()));
                let cursor_pool = Arc::clone(&pool);
                let cursor = match tokio::task::spawn_blocking(move || {
                    load_git_reconcile_cursor(&cursor_pool)
                })
                .await
                {
                    Ok(Ok((cursor, None))) => cursor,
                    Ok(Ok((cursor, Some(error)))) => {
                        healthy = false;
                        tracing::warn!(error = %error,
                            "Agent Observatory Git cursor was malformed and has been reset");
                        cursor
                    }
                    Ok(Err(error)) => {
                        healthy = false;
                        tracing::error!(error = %error, "Agent Observatory Git cursor load failed");
                        GitReconcileCursor::default()
                    }
                    Err(error) => {
                        healthy = false;
                        tracing::error!(error = %error, "Agent Observatory Git cursor load task failed");
                        GitReconcileCursor::default()
                    }
                };
                let selected = next_repository_index(&repositories, &cursor)
                    .and_then(|index| repositories.get(index).cloned());
                let mut reconciled = 0usize;
                if let Some(repository) = selected {
                    let observed_at = chrono::Utc::now().to_rfc3339_opts(
                        chrono::SecondsFormat::Millis,
                        true,
                    );
                    match reconcile_one_repository(&pool, &repository, &options, &observed_at).await {
                        Ok(report) => {
                            reconciled += usize::from(report.topology.is_some());
                            healthy &= report.warnings.is_empty();
                            for warning in report.warnings {
                                tracing::warn!(path = %repository.display(), warning = ?warning,
                                    "Agent Observatory Git reconcile warning");
                            }
                            let checkpoint = encode_git_reconcile_cursor(&repository.display().to_string());
                            let checkpoint_pool = Arc::clone(&pool);
                            let advance = tokio::task::spawn_blocking(move || {
                                projection_cursor(&checkpoint_pool, "git").and_then(|_| {
                                    advance_projection_cursor(&checkpoint_pool, "git", &checkpoint)
                                })
                            }).await;
                            match advance {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    healthy = false;
                                    tracing::error!(error = %error, "Agent Observatory Git progress cursor advance failed");
                                }
                                Err(error) => {
                                    healthy = false;
                                    tracing::error!(error = %error, "Agent Observatory Git progress cursor task failed");
                                }
                            }
                        }
                        Err(error) => {
                            healthy = false;
                            tracing::error!(path = %repository.display(), error = %error,
                                "Agent Observatory Git reconcile failed");
                        }
                    }
                }
                let status = if healthy { "ok" } else { "error" };
                record_health_blocking(&pool, "git", status, format!("reconciled={reconciled}"))
                    .await;
                tracing::debug!(reconciled, "Agent Observatory Git reconcile cycle completed");
                tokio::select! {
                    biased;
                    () = token.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(config.git.reconcile_interval_secs)) => {}
                }
            }
        })
    })
}

#[cfg(test)]
#[path = "agent_observatory_tests.rs"]
mod tests;
