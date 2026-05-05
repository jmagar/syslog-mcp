use anyhow::Result;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::config::{StorageConfig, SyslogConfig};
use crate::db::{self, DbPool};
use crate::ingest;

mod listener;
mod parser;
pub(crate) mod writer;

pub(crate) const WRITE_CHANNEL_CAPACITY: usize = ingest::WRITE_CHANNEL_CAPACITY;

pub async fn start_with_storage_state(
    config: SyslogConfig,
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
) -> Result<()> {
    let ingest_tx = ingest::start_writer_from_syslog_config(&config, storage, pool, storage_state);
    start_listeners(config, ingest_tx.sender()).await
}

pub async fn start_listeners(
    config: SyslogConfig,
    tx: mpsc::Sender<db::LogBatchEntry>,
) -> Result<()> {
    let bind_addr = config.bind_addr();

    let udp_tx = tx.clone();
    let udp_bind = bind_addr.clone();
    let max_size = config.max_message_size;
    tokio::spawn(async move {
        if let Err(e) = listener::udp_listener(&udp_bind, max_size, udp_tx).await {
            error!(error = %e, "UDP syslog listener failed");
        }
    });

    let tcp_tx = tx.clone();
    let tcp_bind = bind_addr.clone();
    let max_tcp_connections = config.max_tcp_connections;
    let tcp_idle_timeout_secs = config.tcp_idle_timeout_secs;
    tokio::spawn(async move {
        if let Err(e) = listener::tcp_listener(
            &tcp_bind,
            tcp_tx,
            max_size,
            max_tcp_connections,
            tcp_idle_timeout_secs,
        )
        .await
        {
            error!(error = %e, "TCP syslog listener failed");
        }
    });

    info!(
        bind = %bind_addr,
        max_message_size = config.max_message_size,
        max_tcp_connections = config.max_tcp_connections,
        tcp_idle_timeout_secs = config.tcp_idle_timeout_secs,
        write_channel_capacity = WRITE_CHANNEL_CAPACITY,
        "Syslog listeners started"
    );

    Ok(())
}
