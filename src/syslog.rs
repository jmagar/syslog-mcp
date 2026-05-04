use anyhow::Result;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::config::{StorageConfig, SyslogConfig};
use crate::db::{self, DbPool};

mod listener;
mod parser;
mod writer;

const WRITE_CHANNEL_CAPACITY: usize = 10_000;

pub async fn start_with_storage_state(
    config: SyslogConfig,
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<db::LogBatchEntry>(WRITE_CHANNEL_CAPACITY);

    let writer_pool = pool.clone();
    let writer_storage = storage.clone();
    let writer_storage_state = storage_state.clone();
    let batch_size = config.batch_size;
    let flush_interval = tokio::time::Duration::from_millis(config.flush_interval);
    tokio::spawn(async move {
        writer::batch_writer(
            rx,
            writer_pool,
            writer_storage,
            writer_storage_state,
            batch_size,
            flush_interval,
        )
        .await;
    });

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
        batch_size = config.batch_size,
        flush_interval_ms = config.flush_interval,
        max_message_size = config.max_message_size,
        max_tcp_connections = config.max_tcp_connections,
        tcp_idle_timeout_secs = config.tcp_idle_timeout_secs,
        write_channel_capacity = WRITE_CHANNEL_CAPACITY,
        "Syslog listeners started"
    );

    Ok(())
}
