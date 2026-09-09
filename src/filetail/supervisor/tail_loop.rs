use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

use crate::ingest::IngestTx;

use super::{
    ActiveFailures, FailureKind, FileIdentity, file_tail_line_to_entry, now_iso, open_tail_file,
    path_identity_changed, read_bounded_line, reopen_if_rotated_or_truncated,
};
use crate::filetail::models::{FileTailSource, FileTailStatus};
use crate::filetail::registry::FileTailRegistry;

const FILE_TAIL_ROTATION_GRACE: Duration = Duration::from_millis(1000);
const CHECKPOINT_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

pub(super) async fn tail_file_loop(
    initial_source: FileTailSource,
    registry: Arc<FileTailRegistry>,
    ingest: IngestTx,
    token: CancellationToken,
    status: Arc<Mutex<FileTailStatus>>,
    shutdown_error: Arc<Mutex<ActiveFailures>>,
    max_line_bytes: usize,
) {
    let source_id = initial_source.id.clone();
    let mut initial_source = Some(initial_source);
    loop {
        if token.is_cancelled() {
            status.lock().running = false;
            return;
        }
        let live_source = match registry.get(&source_id) {
            Ok(Some(source)) if source.enabled => {
                clear_failure(&shutdown_error, FailureKind::Registry);
                source
            }
            Ok(_) => {
                clear_failure(&shutdown_error, FailureKind::Registry);
                status.lock().running = false;
                return;
            }
            Err(err) => {
                tracing::error!(source_id = %source_id, error = %err, "file-tail source reload failed; retrying");
                set_failure(&shutdown_error, FailureKind::Registry, err.to_string());
                status.lock().last_error = Some(err.to_string());
                tokio::select! {
                    _ = token.cancelled() => {
                        status.lock().running = false;
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }
        };
        let source = match initial_source.take() {
            Some(source) if source.same_definition(&live_source) => source,
            _ => live_source,
        };
        match tail_file_until_cancelled(
            &source,
            Arc::clone(&registry),
            ingest.clone(),
            token.clone(),
            Arc::clone(&status),
            Arc::clone(&shutdown_error),
            max_line_bytes,
        )
        .await
        {
            Ok(()) => {
                status.lock().running = false;
                return;
            }
            Err(err) => {
                tracing::error!(source_id = %source.id, path = %source.path, error = %err, "file-tail source failed; retrying");
                if shutdown_error.lock().messages().is_empty() {
                    set_failure(&shutdown_error, FailureKind::Io, err.to_string());
                }
                status.lock().last_error = Some(err.to_string());
                tokio::select! {
                    _ = token.cancelled() => {
                        status.lock().running = false;
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
}

async fn tail_file_until_cancelled(
    source: &FileTailSource,
    registry: Arc<FileTailRegistry>,
    ingest: IngestTx,
    token: CancellationToken,
    status: Arc<Mutex<FileTailStatus>>,
    shutdown_error: Arc<Mutex<ActiveFailures>>,
    max_line_bytes: usize,
) -> Result<()> {
    let opened = match open_tail_file(source, true)
        .await
        .with_context(|| format!("open {}", source.path))
    {
        Ok(opened) => {
            clear_failure(&shutdown_error, FailureKind::Open);
            clear_failure(&shutdown_error, FailureKind::Io);
            opened
        }
        Err(error) => {
            set_failure(&shutdown_error, FailureKind::Open, error.to_string());
            return Err(error);
        }
    };
    let mut reader = BufReader::new(opened.file);
    let mut position = opened.position;
    // `position` includes bytes buffered from an unterminated line. Only the
    // durable position is safe to checkpoint and resume from.
    let mut durable_position = opened.position;
    let mut identity = opened.identity;
    let mut fingerprint = opened.fingerprint;
    let mut line = Vec::new();
    let mut pending_rotation_since: Option<Instant> = None;
    let mut last_checkpoint_flush = Instant::now();
    let mut checkpoint_dirty = false;
    let mut checkpoint_time = now_iso();
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                if checkpoint_dirty {
                    persist_checkpoint_tracked(
                        Arc::clone(&registry), source.id.clone(), identity, durable_position,
                        checkpoint_time.clone(), &shutdown_error,
                    ).await?;
                    status.lock().last_checkpoint_at = Some(checkpoint_time.clone());
                }
                return Ok(())
            },
            read = read_bounded_line(&mut reader, &mut line, max_line_bytes) => {
                let read = read?;
                if read.bytes_read == 0 {
                    if checkpoint_dirty && last_checkpoint_flush.elapsed() >= CHECKPOINT_FLUSH_INTERVAL {
                        persist_checkpoint_tracked(
                            Arc::clone(&registry), source.id.clone(), identity, durable_position,
                            checkpoint_time.clone(), &shutdown_error,
                        ).await?;
                        checkpoint_dirty = false;
                        last_checkpoint_flush = Instant::now();
                        status.lock().last_checkpoint_at = Some(checkpoint_time.clone());
                    }
                    if path_identity_changed(source, identity).await? {
                        let since = pending_rotation_since.get_or_insert_with(Instant::now);
                        if since.elapsed() < FILE_TAIL_ROTATION_GRACE {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    } else {
                        pending_rotation_since = None;
                    }
                    if let Some(next) = reopen_if_rotated_or_truncated(source, identity, position, &fingerprint).await? {
                        if !line.is_empty() {
                            let now = now_iso();
                            let partial = PartialLineBeforeReopen {
                                source,
                                registry: &registry,
                                ingest: &ingest,
                                status: &status,
                                active_failure: &shutdown_error,
                                line: &line,
                                identity,
                                position,
                                now: &now,
                            };
                            ingest_partial_line_before_reopen(partial).await?;
                        }
                        reader = BufReader::new(next.file);
                        position = next.position;
                        durable_position = next.position;
                        identity = next.identity;
                        fingerprint = next.fingerprint;
                        pending_rotation_since = None;
                        line.clear();
                    } else {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    continue;
                }
                position = position.saturating_add(read.bytes_read as u64);
                pending_rotation_since = None;
                if !read.complete {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                let msg = String::from_utf8_lossy(&line);
                let msg = msg.trim_end_matches(['\r', '\n']);
                if msg.is_empty() {
                    durable_position = position;
                    checkpoint_time = now_iso();
                    checkpoint_dirty = true;
                    line.clear();
                    continue;
                }
                let now = now_iso();
                let entry = file_tail_line_to_entry(source, msg, &now);
                {
                    let mut status = status.lock();
                    status.last_read_at = Some(now.clone());
                    status.blocked_on_writer_since = Some(now.clone());
                }
                if let Err(error) = ingest.send_durable(entry).await {
                    set_failure(
                        &shutdown_error,
                        FailureKind::Durability,
                        error.to_string(),
                    );
                    return Err(error);
                }
                durable_position = position;
                checkpoint_time.clone_from(&now);
                checkpoint_dirty = true;
                let checkpoint_persisted = if last_checkpoint_flush.elapsed() >= CHECKPOINT_FLUSH_INTERVAL {
                    persist_checkpoint_tracked(
                        Arc::clone(&registry), source.id.clone(), identity, durable_position, now.clone(),
                        &shutdown_error,
                    ).await?;
                    checkpoint_dirty = false;
                    last_checkpoint_flush = Instant::now();
                    true
                } else {
                    false
                };
                line.clear();
                let mut status = status.lock();
                status.last_line_at = Some(now);
                if checkpoint_persisted {
                    status.last_checkpoint_at = status.last_line_at.clone();
                }
                status.blocked_on_writer_since = None;
                status.last_error = if read.truncated {
                    Some(format!("truncated oversized line from {} to {max_line_bytes} bytes", source.path))
                } else {
                    None
                };
            }
        }
    }
}

async fn persist_checkpoint(
    registry: Arc<FileTailRegistry>,
    source_id: String,
    identity: FileIdentity,
    position: u64,
    now: String,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        registry.update_checkpoint(&source_id, identity.dev, identity.ino, position, &now)
    })
    .await
    .context("join file-tail checkpoint persistence")??;
    Ok(())
}

async fn persist_checkpoint_tracked(
    registry: Arc<FileTailRegistry>,
    source_id: String,
    identity: FileIdentity,
    position: u64,
    now: String,
    active_failure: &Arc<Mutex<ActiveFailures>>,
) -> Result<()> {
    match persist_checkpoint(registry, source_id, identity, position, now).await {
        Ok(()) => {
            clear_failure(active_failure, FailureKind::Durability);
            Ok(())
        }
        Err(error) => {
            set_failure(active_failure, FailureKind::Durability, error.to_string());
            Err(error)
        }
    }
}

fn set_failure(active_failure: &Arc<Mutex<ActiveFailures>>, kind: FailureKind, message: String) {
    let mut failures = active_failure.lock();
    match kind {
        FailureKind::Registry => failures.registry = Some(message),
        FailureKind::Open => failures.open = Some(message),
        FailureKind::Io => failures.io = Some(message),
        FailureKind::Durability => failures.durability = Some(message),
    }
}

fn clear_failure(active_failure: &Arc<Mutex<ActiveFailures>>, recovered_kind: FailureKind) {
    let mut failures = active_failure.lock();
    match recovered_kind {
        FailureKind::Registry => failures.registry = None,
        FailureKind::Open => failures.open = None,
        FailureKind::Io => failures.io = None,
        FailureKind::Durability => failures.durability = None,
    }
}

struct PartialLineBeforeReopen<'a> {
    source: &'a FileTailSource,
    registry: &'a FileTailRegistry,
    ingest: &'a IngestTx,
    status: &'a Mutex<FileTailStatus>,
    active_failure: &'a Arc<Mutex<ActiveFailures>>,
    line: &'a [u8],
    identity: FileIdentity,
    position: u64,
    now: &'a str,
}

async fn ingest_partial_line_before_reopen(partial: PartialLineBeforeReopen<'_>) -> Result<()> {
    let msg = String::from_utf8_lossy(partial.line);
    let msg = msg.trim_end_matches(['\r', '\n']);
    if msg.is_empty() {
        return Ok(());
    }
    if let Err(error) = partial
        .ingest
        .send_durable(file_tail_line_to_entry(partial.source, msg, partial.now))
        .await
    {
        set_failure(
            partial.active_failure,
            FailureKind::Durability,
            error.to_string(),
        );
        return Err(error);
    }
    if let Err(error) = partial.registry.update_checkpoint(
        &partial.source.id,
        partial.identity.dev,
        partial.identity.ino,
        partial.position,
        partial.now,
    ) {
        set_failure(
            partial.active_failure,
            FailureKind::Durability,
            error.to_string(),
        );
        return Err(error);
    }
    clear_failure(partial.active_failure, FailureKind::Durability);
    let mut status = partial.status.lock();
    status.last_line_at = Some(partial.now.to_string());
    status.last_checkpoint_at = Some(partial.now.to_string());
    status.last_error = Some(format!(
        "ingested unterminated partial line before rotation/truncation for {}",
        partial.source.path
    ));
    Ok(())
}
