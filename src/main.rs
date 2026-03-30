mod config;
mod db;
mod mcp;
mod syslog;

use std::sync::Arc;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

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
    info!(config = ?config, "Configuration loaded");

    // Initialize database
    let pool = Arc::new(db::init_pool(&config.storage)?);

    // Start syslog listeners
    syslog::start(config.syslog.clone(), pool.clone()).await?;

    // Start retention purge task
    let retention_days = config.storage.retention_days;
    let purge_handle = if retention_days > 0 {
        let purge_pool = pool.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let pool = Arc::clone(&purge_pool);
                if let Err(e) =
                    tokio::task::spawn_blocking(move || db::purge_old_logs(&pool, retention_days))
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {e}"))
                        .and_then(|r| r)
                {
                    tracing::error!(error = %e, "Failed to purge old logs");
                }
            }
        });
        info!(retention_days, "Log retention purge task started (hourly)");
        Some(handle)
    } else {
        None
    };

    // Build and start MCP HTTP server
    let state = mcp::AppState {
        pool: pool.clone(),
        config: config.mcp.clone(),
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

    let listener = tokio::net::TcpListener::bind(&config.mcp.bind).await?;
    info!(bind = %config.mcp.bind, "MCP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    if let Some(handle) = purge_handle {
        handle.abort();
        let _ = handle.await;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received");
}
