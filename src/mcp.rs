use std::sync::Arc;

use crate::config::{McpConfig, StorageConfig};
use crate::db::DbPool;

mod protocol;
mod routes;
mod schemas;
mod tools;

pub use routes::router;

/// Shared app state
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<DbPool>,
    pub config: McpConfig,
    pub storage: StorageConfig,
}
