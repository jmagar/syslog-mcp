use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::config::{StorageConfig, SyslogConfig};
use crate::db::{self, DbPool};
use crate::syslog;

pub const WRITE_CHANNEL_CAPACITY: usize = 10_000;

#[derive(Clone)]
pub(crate) struct IngestTx {
    tx: mpsc::Sender<db::LogBatchEntry>,
}

impl IngestTx {
    pub(crate) async fn send(
        &self,
        entry: db::LogBatchEntry,
    ) -> Result<(), mpsc::error::SendError<db::LogBatchEntry>> {
        self.tx.send(entry).await
    }

    pub(crate) fn sender(&self) -> mpsc::Sender<db::LogBatchEntry> {
        self.tx.clone()
    }
}

pub(crate) fn start_writer(
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
    batch_size: usize,
    flush_interval_ms: u64,
) -> IngestTx {
    let (tx, rx) = mpsc::channel::<db::LogBatchEntry>(WRITE_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        syslog::writer::batch_writer(
            rx,
            pool,
            storage,
            storage_state,
            batch_size,
            tokio::time::Duration::from_millis(flush_interval_ms),
        )
        .await;
    });
    IngestTx { tx }
}

pub(crate) fn start_writer_from_syslog_config(
    syslog: &SyslogConfig,
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
) -> IngestTx {
    start_writer(
        storage,
        pool,
        storage_state,
        syslog.batch_size,
        syslog.flush_interval,
    )
}
