mod config;
mod db;
mod mcp;
mod syslog;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

fn background_interval(period: tokio::time::Duration) -> tokio::time::Interval {
    tokio::time::interval_at(tokio::time::Instant::now() + period, period)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("syslog-mcp v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config = config::Config::load()?;
    info!(
        syslog_bind = %config.syslog.bind_addr(),
        mcp_bind = %config.mcp.bind_addr(),
        db_path = %config.storage.db_path.display(),
        retention_days = config.storage.retention_days,
        max_db_size_mb = config.storage.max_db_size_mb,
        recovery_db_size_mb = config.storage.recovery_db_size_mb,
        min_free_disk_mb = config.storage.min_free_disk_mb,
        recovery_free_disk_mb = config.storage.recovery_free_disk_mb,
        cleanup_interval_secs = config.storage.cleanup_interval_secs,
        pool_size = config.storage.pool_size,
        wal_mode = config.storage.wal_mode,
        auth_enabled = config.mcp.api_token.is_some(),
        "Configuration loaded"
    );

    // Initialize database
    let pool = Arc::new(db::init_pool(&config.storage)?);
    let storage_state = Arc::new(Mutex::new(None));
    if config.storage.max_db_size_mb > 0 || config.storage.min_free_disk_mb > 0 {
        let initial_outcome = db::enforce_storage_budget(&pool, &config.storage)?;
        *storage_state.lock().expect("storage state mutex poisoned") =
            Some(db::StorageBudgetState {
                metrics: initial_outcome.metrics.clone(),
                write_blocked: initial_outcome.write_blocked,
            });
        info!(
            deleted_rows = initial_outcome.deleted_rows,
            logical_db_size_bytes = initial_outcome.metrics.logical_db_size_bytes,
            physical_db_size_bytes = initial_outcome.metrics.physical_db_size_bytes,
            free_disk_bytes = ?initial_outcome.metrics.free_disk_bytes,
            write_blocked = initial_outcome.write_blocked,
            "Initial storage budget check completed"
        );
    }

    // Start syslog listeners
    syslog::start_with_storage_state(
        config.syslog.clone(),
        config.storage.clone(),
        pool.clone(),
        storage_state.clone(),
    )
    .await?;

    // Start retention purge task
    let retention_days = config.storage.retention_days;
    let purge_handle = if retention_days > 0 {
        let purge_pool = pool.clone();
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let started = Instant::now();
                let pool = Arc::clone(&purge_pool);
                tracing::debug!(retention_days, "Retention purge tick started");
                match tokio::task::spawn_blocking(move || db::purge_old_logs(&pool, retention_days))
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                    .and_then(|r| r)
                {
                    Ok(deleted) => tracing::info!(
                        retention_days,
                        deleted,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Retention purge tick completed"
                    ),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            retention_days,
                            elapsed_ms = started.elapsed().as_millis(),
                            "Failed to purge old logs"
                        );
                    }
                }
            }
        });
        info!(retention_days, "Log retention purge task started (hourly)");
        Some(handle)
    } else {
        None
    };

    let storage_handle = if config.storage.max_db_size_mb > 0 || config.storage.min_free_disk_mb > 0
    {
        let storage_pool = pool.clone();
        let storage_config = config.storage.clone();
        let shared_storage_state = storage_state.clone();
        let handle = tokio::spawn(async move {
            let mut interval = background_interval(tokio::time::Duration::from_secs(
                storage_config.cleanup_interval_secs,
            ));
            loop {
                interval.tick().await;
                let started = Instant::now();
                let pool = Arc::clone(&storage_pool);
                let storage = storage_config.clone();
                tracing::debug!(
                    cleanup_interval_secs = storage_config.cleanup_interval_secs,
                    "Storage budget enforcement tick started"
                );
                match tokio::task::spawn_blocking(move || {
                    db::enforce_storage_budget(&pool, &storage)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                .and_then(|r| r)
                {
                    Ok(outcome) => {
                        let previous_blocked = shared_storage_state
                            .lock()
                            .expect("storage state mutex poisoned")
                            .as_ref()
                            .map(|s| s.write_blocked);
                        *shared_storage_state
                            .lock()
                            .expect("storage state mutex poisoned") =
                            Some(db::StorageBudgetState {
                                metrics: outcome.metrics.clone(),
                                write_blocked: outcome.write_blocked,
                            });

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
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            elapsed_ms = started.elapsed().as_millis(),
                            "Failed to enforce storage budget"
                        );
                    }
                }
            }
        });
        info!(
            cleanup_interval_secs = config.storage.cleanup_interval_secs,
            "Storage budget enforcement task started"
        );
        Some(handle)
    } else {
        None
    };

    // Build and start MCP HTTP server
    let state = mcp::AppState {
        pool: pool.clone(),
        config: config.mcp.clone(),
        storage: config.storage.clone(),
    };

    let app = mcp::router(state)
        .layer(
            // Restrict CORS to localhost origins only.
            // MCP CLI clients (mcporter, curl) are not browser-based and ignore CORS entirely,
            // so this restriction has zero effect on them. It only prevents a malicious
            // webpage visited by a LAN user from silently exfiltrating the log database
            // via a cross-origin browser fetch().
            tower_http::cors::CorsLayer::new()
                .allow_origin([
                    "http://localhost:3100"
                        .parse::<axum::http::HeaderValue>()
                        .expect("valid localhost origin"),
                    "http://127.0.0.1:3100"
                        .parse::<axum::http::HeaderValue>()
                        .expect("valid 127.0.0.1 origin"),
                ])
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers(tower_http::cors::Any),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let mcp_bind = config.mcp.bind_addr();
    let listener = tokio::net::TcpListener::bind(&mcp_bind).await?;
    info!(bind = %mcp_bind, "MCP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    if let Some(handle) = purge_handle {
        handle.abort();
        let _ = handle.await;
    }
    if let Some(handle) = storage_handle {
        handle.abort();
        let _ = handle.await;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(error = %e, "Failed to install CTRL+C handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::background_interval;

    #[tokio::test]
    async fn background_interval_waits_full_period_before_first_tick() {
        let delay = tokio::time::Duration::from_millis(25);
        let mut interval = background_interval(delay);
        let started = std::time::Instant::now();
        interval.tick().await;
        assert!(
            started.elapsed() >= tokio::time::Duration::from_millis(20),
            "first tick should wait roughly one full period before firing"
        );
    }
}
