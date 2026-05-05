use crate::app::SyslogService;
use crate::config::McpConfig;

mod rmcp_server;
mod routes;
mod schemas;
mod tools;

pub use rmcp_server::{streamable_http_config, streamable_http_service, SyslogRmcpServer};
pub use routes::router;

/// Shared app state
#[derive(Clone)]
pub struct AppState {
    pub service: SyslogService,
    pub config: McpConfig,
}
