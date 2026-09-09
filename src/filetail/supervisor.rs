use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ingest::IngestTx;

use super::models::{FileTailSource, FileTailStatus};
use super::platform::metadata_identity;
use super::registry::FileTailRegistry;

mod io;
mod line_entry;
mod tail_loop;

use self::tail_loop::tail_file_loop;

pub(crate) use self::io::{
    FileIdentity, open_tail_file, open_validated_tail_file_sync, path_identity_changed,
    read_bounded_line, reopen_if_rotated_or_truncated,
};
pub(crate) use self::line_entry::file_tail_line_to_entry;
#[cfg(test)]
pub(crate) use self::line_entry::tail_file_once_for_test;

#[derive(Clone)]
pub(crate) struct FileTailSupervisor {
    registry: Arc<FileTailRegistry>,
    ingest: IngestTx,
    token: CancellationToken,
    tasks: Arc<Mutex<HashMap<String, TailTask>>>,
    reconcile_error: Arc<Mutex<Option<String>>>,
    max_line_bytes: usize,
}

struct TailTask {
    handle: JoinHandle<()>,
    token: CancellationToken,
    status: Arc<Mutex<FileTailStatus>>,
    shutdown_error: Arc<Mutex<ActiveFailures>>,
    source: FileTailSource,
}

#[derive(Clone, Copy)]
pub(super) enum FailureKind {
    Registry,
    Open,
    Io,
    Durability,
}

#[derive(Clone, Default)]
pub(super) struct ActiveFailures {
    pub(super) registry: Option<String>,
    pub(super) open: Option<String>,
    pub(super) io: Option<String>,
    pub(super) durability: Option<String>,
}

impl ActiveFailures {
    pub(super) fn messages(&self) -> Vec<String> {
        [&self.registry, &self.open, &self.io, &self.durability]
            .into_iter()
            .filter_map(Clone::clone)
            .collect()
    }
}

pub(crate) struct FileTailShutdown {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) statuses: Vec<FileTailStatus>,
    failures: Vec<String>,
}

impl FileTailShutdown {
    pub(crate) fn clean(&self) -> bool {
        self.failures.is_empty()
    }
}

impl FileTailSupervisor {
    pub(crate) fn new(
        registry: Arc<FileTailRegistry>,
        ingest: IngestTx,
        token: CancellationToken,
        max_line_bytes: usize,
    ) -> Self {
        Self {
            registry,
            ingest,
            token,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            reconcile_error: Arc::new(Mutex::new(None)),
            max_line_bytes,
        }
    }

    pub(crate) fn statuses(&self) -> Vec<FileTailStatus> {
        let mut out: Vec<_> = self
            .tasks
            .lock()
            .values()
            .map(|task| task.status.lock().clone())
            .collect();
        if let Some(error) = self.reconcile_error.lock().clone() {
            out.push(FileTailStatus {
                id: "__supervisor__".to_string(),
                running: false,
                last_line_at: None,
                last_read_at: None,
                last_checkpoint_at: None,
                blocked_on_writer_since: None,
                last_error: Some(error),
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) -> FileTailShutdown {
        self.token.cancel();
        let tasks: Vec<_> = self.tasks.lock().drain().map(|(_, task)| task).collect();
        self.stop_tasks(tasks, timeout).await
    }

    async fn stop_tasks(&self, tasks: Vec<TailTask>, timeout: Duration) -> FileTailShutdown {
        for task in &tasks {
            task.token.cancel();
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let mut stopped = Vec::new();
        let mut failures = Vec::new();
        for mut task in tasks {
            let source_id = task.source.id.clone();
            let abort_handle = task.handle.abort_handle();
            let outcome = tokio::time::timeout_at(deadline, &mut task.handle).await;
            let failure = match outcome {
                Ok(Ok(())) => None,
                Ok(Err(err)) if err.is_panic() => {
                    Some(format!("file-tail task panicked during shutdown: {err}"))
                }
                Ok(Err(err)) if err.is_cancelled() => Some(format!(
                    "file-tail task was unexpectedly cancelled during shutdown: {err}"
                )),
                Ok(Err(err)) => Some(format!("file-tail task join failed during shutdown: {err}")),
                Err(_) => {
                    abort_handle.abort();
                    let _ = task.handle.await;
                    Some(format!(
                        "file-tail task shutdown timed out after {timeout:?}"
                    ))
                }
            }
            .or_else(|| {
                let messages = task.shutdown_error.lock().messages();
                (!messages.is_empty()).then(|| messages.join("; "))
            });
            let mut status = task.status.lock();
            status.running = false;
            if let Some(failure) = failure {
                tracing::error!(source_id = %source_id, error = %failure, "file-tail shutdown failed");
                failures.push(format!("{source_id}: {failure}"));
                append_status_error(&mut status, failure);
            }
            stopped.push(status.clone());
        }
        stopped.sort_by(|a, b| a.id.cmp(&b.id));
        FileTailShutdown {
            statuses: stopped,
            failures,
        }
    }

    pub(crate) async fn reconcile(&self) -> Result<()> {
        match self.reconcile_inner().await {
            Ok(()) => {
                *self.reconcile_error.lock() = None;
                Ok(())
            }
            Err(error) => {
                *self.reconcile_error.lock() = Some(error.to_string());
                Err(error)
            }
        }
    }

    async fn reconcile_inner(&self) -> Result<()> {
        let sources = self.registry.list()?;
        let enabled: HashMap<String, FileTailSource> = sources
            .iter()
            .filter(|source| source.enabled)
            .map(|source| (source.id.clone(), source.clone()))
            .collect();

        let retiring = {
            let mut tasks = self.tasks.lock();
            let retiring_ids: Vec<_> = tasks
                .iter()
                .filter_map(|(id, task)| {
                    let keep_running = enabled
                        .get(id)
                        .is_some_and(|source| source.same_definition(&task.source));
                    (!keep_running).then(|| id.clone())
                })
                .collect();
            retiring_ids
                .into_iter()
                .filter_map(|id| tasks.remove(&id))
                .collect::<Vec<_>>()
        };
        let retired = self.stop_tasks(retiring, Duration::from_secs(2)).await;
        if !retired.clean() {
            let failures = retired.failures.join("; ");
            anyhow::bail!("file-tail task drain failed during reconcile: {failures}");
        }

        let mut tasks = self.tasks.lock();
        for source in sources {
            if source.enabled && !tasks.contains_key(&source.id) {
                let source = self.ensure_initial_checkpoint(source)?;
                let (id, task) = self.build_task(source);
                tasks.insert(id, task);
            }
        }
        Ok(())
    }

    fn ensure_initial_checkpoint(&self, mut source: FileTailSource) -> Result<FileTailSource> {
        let has_checkpoint = source.checkpoint_dev.is_some()
            || source.checkpoint_ino.is_some()
            || source.checkpoint_offset.is_some();
        if has_checkpoint {
            return Ok(source);
        }

        let file = open_validated_tail_file_sync(&source.path)?;
        let metadata = file.metadata()?;
        let offset = if source.start_at_end {
            metadata.len()
        } else {
            0
        };
        let (dev, ino) = metadata_identity(&metadata);
        source.checkpoint_dev = Some(dev);
        source.checkpoint_ino = Some(ino);
        source.checkpoint_offset = Some(offset);
        self.registry
            .update_checkpoint(&source.id, dev, ino, offset, &now_iso())?;
        Ok(source)
    }

    fn build_task(&self, source: FileTailSource) -> (String, TailTask) {
        let id = source.id.clone();
        let initial_source = source.clone();
        let task_source = source;
        let status = Arc::new(Mutex::new(FileTailStatus {
            id: id.clone(),
            running: true,
            last_line_at: None,
            last_read_at: None,
            last_checkpoint_at: None,
            blocked_on_writer_since: None,
            last_error: None,
        }));
        let task_status = Arc::clone(&status);
        let shutdown_error = Arc::new(Mutex::new(ActiveFailures::default()));
        let task_shutdown_error = Arc::clone(&shutdown_error);
        let ingest = self.ingest.clone();
        let token = self.token.child_token();
        let task_token = token.clone();
        let registry = Arc::clone(&self.registry);
        let max_line_bytes = self.max_line_bytes;
        let handle = tokio::spawn(async move {
            tail_file_loop(
                initial_source,
                registry,
                ingest,
                token,
                task_status,
                task_shutdown_error,
                max_line_bytes,
            )
            .await;
        });
        (
            id,
            TailTask {
                handle,
                token: task_token,
                status,
                shutdown_error,
                source: task_source,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn running_source_for_test(&self, id: &str) -> Option<FileTailSource> {
        self.tasks.lock().get(id).map(|task| task.source.clone())
    }

    #[cfg(test)]
    pub(crate) fn fail_checkpoint_writes_for_test(&self, fail: bool) {
        self.registry.set_fail_checkpoint_writes(fail);
    }
}

fn append_status_error(status: &mut FileTailStatus, error: String) {
    status.last_error = Some(match status.last_error.take() {
        Some(previous) => format!("{previous}; {error}"),
        None => error,
    });
}

pub(super) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
