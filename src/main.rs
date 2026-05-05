use anyhow::Result;
use axum::Router;
use syslog_mcp::{api, mcp, runtime::RuntimeCore};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("syslog-mcp v{}", env!("CARGO_PKG_VERSION"));

    let runtime = RuntimeCore::load()?;
    info!(
        syslog_bind = %runtime.config.syslog.bind_addr(),
        mcp_bind = %runtime.config.mcp.bind_addr(),
        db_path = %runtime.config.storage.db_path.display(),
        retention_days = runtime.config.storage.retention_days,
        max_db_size_mb = runtime.config.storage.max_db_size_mb,
        recovery_db_size_mb = runtime.config.storage.recovery_db_size_mb,
        min_free_disk_mb = runtime.config.storage.min_free_disk_mb,
        recovery_free_disk_mb = runtime.config.storage.recovery_free_disk_mb,
        cleanup_interval_secs = runtime.config.storage.cleanup_interval_secs,
        pool_size = runtime.config.storage.pool_size,
        wal_mode = runtime.config.storage.wal_mode,
        mcp_auth_enabled = runtime.config.mcp.api_token.is_some(),
        api_enabled = runtime.config.api.enabled,
        "Configuration loaded"
    );

    runtime.start_syslog().await?;
    let _maintenance = runtime.spawn_maintenance_tasks();

    let mut app: Router = mcp::router(runtime.mcp_state());
    if runtime.config.api.enabled {
        app = app.merge(api::router(api::ApiState {
            service: runtime.service(),
            config: runtime.config.api.clone(),
        })?);
        info!("Non-MCP API mounted under /api");
    }
    app = app.layer(tower_http::trace::TraceLayer::new_for_http());

    let mcp_bind = runtime.config.mcp.bind_addr();
    let listener = tokio::net::TcpListener::bind(&mcp_bind).await?;
    info!(bind = %mcp_bind, "MCP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

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
    tracing::info!("Shutdown signal received");
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
