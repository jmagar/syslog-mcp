use crate::app::SyslogService;
use crate::config::McpConfig;

mod protocol;
mod routes;
mod schemas;
mod tools;

pub use routes::router;

/// Shared app state
#[derive(Clone)]
pub struct AppState {
    pub service: SyslogService,
    pub config: McpConfig,
}
