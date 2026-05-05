use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use syslog_mcp::{mcp, runtime::RuntimeCore};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();

    let runtime = RuntimeCore::load_query_only()?;
    let service = mcp::rmcp_server(runtime.mcp_state()).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
