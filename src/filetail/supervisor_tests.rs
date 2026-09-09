use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::db::LogBatchEntry;
use crate::ingest::IngestTx;

use super::models::FileTailSource;
use super::registry::FileTailRegistry;
use super::supervisor::{
    FileTailSupervisor, file_tail_line_to_entry, open_tail_file, read_bounded_line,
    reopen_if_rotated_or_truncated, tail_file_once_for_test,
};

fn source(id: &str, path: &str, tag: &str) -> FileTailSource {
    FileTailSource {
        id: id.into(),
        path: path.into(),
        tag: tag.into(),
        hostname: Some("edgehost".into()),
        facility: Some("local4".into()),
        severity: "info".into(),
        start_at_end: true,
        enabled: true,
        checkpoint_dev: None,
        checkpoint_ino: None,
        checkpoint_offset: None,
        created_at: "2026-06-11T20:00:00Z".into(),
        updated_at: "2026-06-11T20:00:00Z".into(),
    }
}

#[tokio::test]
async fn reconcile_failure_is_visible_until_a_successful_reconcile() {
    let temp = tempfile::tempdir().unwrap();
    let registry_path = temp.path().join("file-tails.json");
    std::fs::write(&registry_path, "not-json").unwrap();
    let registry = Arc::new(FileTailRegistry::new(registry_path.clone()));
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let supervisor = FileTailSupervisor::new(
        registry,
        IngestTx::from_sender_for_test(tx),
        tokio_util::sync::CancellationToken::new(),
        8192,
    );

    let error = supervisor.reconcile().await.unwrap_err();
    assert!(error.to_string().contains("parse"));
    let statuses = supervisor.statuses();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].id, "__supervisor__");
    assert!(statuses[0].last_error.as_deref().unwrap().contains("parse"));

    std::fs::write(registry_path, "[]").unwrap();
    supervisor.reconcile().await.unwrap();
    assert!(supervisor.statuses().is_empty());
}

#[test]
fn file_tail_line_to_entry_sets_expected_envelope() {
    let source = source("swag-access", "/tmp/access.log", "swag-access");

    let entry = file_tail_line_to_entry(&source, "GET / HTTP/1.1\" 401", "2026-06-11T20:01:00Z");

    assert_eq!(entry.timestamp, "2026-06-11T20:01:00Z");
    assert_eq!(entry.hostname, "edgehost");
    assert_eq!(entry.facility.as_deref(), Some("local4"));
    assert_eq!(entry.severity, "info");
    assert_eq!(entry.app_name.as_deref(), Some("swag-access"));
    assert_eq!(entry.message, "GET / HTTP/1.1\" 401");
    assert_eq!(entry.raw, "GET / HTTP/1.1\" 401");
    assert_eq!(entry.source_ip, "file-tail://edgehost/swag-access");
    let metadata: serde_json::Value =
        serde_json::from_str(entry.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_kind"], "file-tail");
    assert_eq!(metadata["file_tail_id"], "swag-access");
    assert_eq!(metadata["tag"], "swag-access");
    assert_eq!(metadata["path_basename"], "access.log");
}

#[test]
fn file_tail_line_to_entry_never_uses_runtime_hostname_for_legacy_sources() {
    let mut source = source("swag-access", "/tmp/access.log", "swag-access");
    source.hostname = None;

    let entry = file_tail_line_to_entry(&source, "legacy registry row", "2026-07-16T20:00:00Z");

    assert_eq!(entry.hostname, "file-tail-swag-access");
    assert_eq!(
        entry.source_ip,
        "file-tail://file-tail-swag-access/swag-access"
    );
}

#[tokio::test]
async fn reconcile_restarts_task_when_source_definition_changes() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, _rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );

    let first_path = temp.path().join("one.log");
    let second_path = temp.path().join("two.log");
    tokio::fs::write(&first_path, b"one\n").await.unwrap();
    tokio::fs::write(&second_path, b"two\n").await.unwrap();

    registry
        .upsert(source(
            "swag-access",
            &first_path.to_string_lossy(),
            "swag-access",
        ))
        .unwrap();
    supervisor.reconcile().await.unwrap();
    assert_eq!(
        supervisor
            .running_source_for_test("swag-access")
            .unwrap()
            .path,
        first_path.to_string_lossy()
    );

    registry
        .upsert(source(
            "swag-access",
            &second_path.to_string_lossy(),
            "swag-access",
        ))
        .unwrap();
    supervisor.reconcile().await.unwrap();
    assert_eq!(
        supervisor
            .running_source_for_test("swag-access")
            .unwrap()
            .path,
        second_path.to_string_lossy()
    );
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn reconcile_does_not_restart_task_for_checkpoint_updates() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, _rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );

    let log_path = temp.path().join("one.log");
    tokio::fs::write(&log_path, b"one\n").await.unwrap();

    registry
        .upsert(source(
            "swag-access",
            &log_path.to_string_lossy(),
            "swag-access",
        ))
        .unwrap();
    supervisor.reconcile().await.unwrap();
    registry
        .update_checkpoint("swag-access", 1, 2, 3, "2026-06-11T20:01:00Z")
        .unwrap();
    supervisor.reconcile().await.unwrap();
    assert_eq!(
        supervisor
            .running_source_for_test("swag-access")
            .unwrap()
            .path,
        log_path.to_string_lossy()
    );
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn supervisor_ingests_appended_line_and_updates_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("loop.log");
    tokio::fs::write(&log_path, b"").await.unwrap();

    let mut source = source("loop", &log_path.to_string_lossy(), "loop");
    source.start_at_end = false;
    registry.upsert(source).unwrap();
    supervisor.reconcile().await.unwrap();

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    writer.write_all(b"hello from loop\n").await.unwrap();
    writer.flush().await.unwrap();

    let entry = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.message, "hello from loop");

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let stored = registry.get("loop").unwrap().unwrap();
            if stored.checkpoint_offset.unwrap_or_default() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let statuses = supervisor.statuses();
    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].last_line_at.is_some());

    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn supervisor_coalesces_checkpoint_writes_for_a_burst() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(256);
    let ingest = IngestTx::from_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("burst.log");
    tokio::fs::write(&log_path, b"").await.unwrap();
    let mut configured = source("burst", &log_path.to_string_lossy(), "burst");
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let baseline_writes = registry.write_count();
    supervisor.reconcile().await.unwrap();

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    for index in 0..200 {
        writer
            .write_all(format!("burst-{index}\n").as_bytes())
            .await
            .unwrap();
    }
    writer.flush().await.unwrap();

    for _ in 0..200 {
        tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let stored = registry.get("burst").unwrap().unwrap();
            if stored.checkpoint_offset == Some(tokio::fs::metadata(&log_path).await.unwrap().len())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    assert!(
        registry.write_count() - baseline_writes <= 4,
        "checkpoint persistence scaled with line count"
    );
    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn reconcile_initializes_start_at_end_checkpoint_before_returning() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("loop.log");
    tokio::fs::write(&log_path, b"already here\n")
        .await
        .unwrap();

    registry
        .upsert(source("loop", &log_path.to_string_lossy(), "loop"))
        .unwrap();
    supervisor.reconcile().await.unwrap();
    let initial = registry.get("loop").unwrap().unwrap();
    assert_eq!(
        initial.checkpoint_offset,
        Some("already here\n".len() as u64)
    );

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    writer.write_all(b"after reconcile\n").await.unwrap();
    writer.flush().await.unwrap();

    let entry = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.message, "after reconcile");

    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn first_open_uses_checkpoint_snapshot_created_by_reconcile() {
    use std::io::Write as _;

    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("loop.log");
    tokio::fs::write(&log_path, b"already here\n")
        .await
        .unwrap();

    registry
        .upsert(source("loop", &log_path.to_string_lossy(), "loop"))
        .unwrap();
    supervisor.reconcile().await.unwrap();

    // A current-thread runtime guarantees the spawned task has not performed
    // its first open while this synchronous section runs. Replacing the
    // persisted definition models a later registry read that no longer has the
    // checkpoint that reconcile just created. The first open must still use
    // the exact checkpoint snapshot handed to the task by reconcile.
    registry
        .upsert(source("loop", &log_path.to_string_lossy(), "loop"))
        .unwrap();
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    writer.write_all(b"after reconcile\n").unwrap();
    writer.flush().unwrap();

    let entry = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.message, "after reconcile");

    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn supervisor_waits_for_durable_ack_before_checkpointing() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("loop.log");
    tokio::fs::write(&log_path, b"").await.unwrap();

    let mut src = source("loop", &log_path.to_string_lossy(), "loop");
    src.start_at_end = false;
    registry.upsert(src).unwrap();
    supervisor.reconcile().await.unwrap();

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    writer.write_all(b"hello durable\n").await.unwrap();
    writer.flush().await.unwrap();

    let envelope = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(envelope.entry.message, "hello durable");
    assert_eq!(
        registry.get("loop").unwrap().unwrap().checkpoint_offset,
        Some(0)
    );

    envelope.ack_success();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if registry
                .get("loop")
                .unwrap()
                .unwrap()
                .checkpoint_offset
                .is_some_and(|offset| offset > 0)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn shutdown_checkpoints_only_complete_lines_before_partial_tail() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(8);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("partial-restart.log");
    tokio::fs::write(&log_path, b"complete\npartial")
        .await
        .unwrap();

    let mut configured = source(
        "partial-restart",
        &log_path.to_string_lossy(),
        "partial-restart",
    );
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();

    let first = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest.clone(),
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    first.reconcile().await.unwrap();
    let complete = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(complete.entry.message, "complete");
    complete.ack_success();

    let report = first.shutdown(Duration::from_secs(2)).await;
    assert!(!report.statuses[0].running);
    assert_eq!(
        registry
            .get("partial-restart")
            .unwrap()
            .unwrap()
            .checkpoint_offset,
        Some(b"complete\n".len() as u64)
    );

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    writer.write_all(b"\n").await.unwrap();
    writer.flush().await.unwrap();

    let second = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    second.reconcile().await.unwrap();
    let partial = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(partial.entry.message, "partial");
    partial.ack_success();
    second.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn shutdown_reports_checkpoint_persistence_failure() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("checkpoint-failure.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source(
        "checkpoint-failure",
        &log_path.to_string_lossy(),
        "checkpoint-failure",
    );
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();

    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    let envelope = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    envelope.ack_success();
    registry.set_fail_checkpoint_writes(true);

    let report = supervisor.shutdown(Duration::from_secs(2)).await;
    assert!(!report.clean());
    assert!(!report.statuses[0].running);
    assert!(
        report.statuses[0].last_error.as_deref().is_some_and(
            |error| error.contains("injected file-tail checkpoint persistence failure")
        )
    );
}

#[tokio::test]
async fn shutdown_reports_unresolved_periodic_checkpoint_failure() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("periodic-checkpoint-failure.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source(
        "periodic-checkpoint-failure",
        &log_path.to_string_lossy(),
        "periodic-checkpoint-failure",
    );
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();

    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    registry.set_fail_checkpoint_writes(true);
    let envelope = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    envelope.ack_success();

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if supervisor.statuses()[0]
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("checkpoint persistence failure"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    let replay = tokio::time::timeout(Duration::from_secs(7), rx.recv())
        .await
        .unwrap()
        .unwrap();
    replay.ack_success();

    let report = supervisor.shutdown(Duration::from_secs(2)).await;
    assert!(!report.clean());
}

#[tokio::test]
async fn periodic_checkpoint_failure_clears_only_after_durable_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("checkpoint-recovery.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source(
        "checkpoint-recovery",
        &log_path.to_string_lossy(),
        "recovery",
    );
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    registry.set_fail_checkpoint_writes(true);
    let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    first.ack_success();
    tokio::time::timeout(Duration::from_secs(3), async {
        while supervisor.statuses()[0].last_error.is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    registry.set_fail_checkpoint_writes(false);
    let replay = tokio::time::timeout(Duration::from_secs(7), rx.recv())
        .await
        .unwrap()
        .unwrap();
    replay.ack_success();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if registry
                .get("checkpoint-recovery")
                .unwrap()
                .unwrap()
                .checkpoint_offset
                == Some(b"line\n".len() as u64)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    assert!(supervisor.shutdown(Duration::from_secs(2)).await.clean());
}

#[tokio::test]
async fn failed_durable_send_remains_unclean_after_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(1);
    drop(rx);
    let log_path = temp.path().join("failed-send.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source("failed-send", &log_path.to_string_lossy(), "failed-send");
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let supervisor = FileTailSupervisor::new(
        registry,
        IngestTx::from_sender_for_test(tx),
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while supervisor.statuses()[0].last_error.is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    // Cross the retry/reopen boundary; opening the file must not clear the
    // unresolved durable-send failure.
    tokio::time::sleep(Duration::from_millis(5_250)).await;
    assert!(!supervisor.shutdown(Duration::from_secs(2)).await.clean());
}

#[tokio::test]
async fn transient_source_io_failure_clears_after_successful_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let log_path = temp.path().join("io-recovery.log");
    tokio::fs::write(&log_path, b"").await.unwrap();
    registry
        .upsert(source("io-recovery", &log_path.to_string_lossy(), "io"))
        .unwrap();
    let supervisor = FileTailSupervisor::new(
        registry,
        IngestTx::from_envelope_sender_for_test(tx),
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    tokio::fs::remove_file(&log_path).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while supervisor.statuses()[0].last_error.is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    tokio::fs::write(&log_path, b"recovered\n").await.unwrap();
    let envelope = tokio::time::timeout(Duration::from_secs(7), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(envelope.entry.message, "recovered");
    envelope.ack_success();
    assert!(supervisor.shutdown(Duration::from_secs(2)).await.clean());
}

#[tokio::test]
async fn unresolved_source_io_failure_remains_unclean_after_retry() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, _rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(1);
    let log_path = temp.path().join("io-failure.log");
    tokio::fs::write(&log_path, b"").await.unwrap();
    registry
        .upsert(source("io-failure", &log_path.to_string_lossy(), "io"))
        .unwrap();
    let supervisor = FileTailSupervisor::new(
        registry,
        IngestTx::from_sender_for_test(tx),
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    tokio::fs::remove_file(&log_path).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while supervisor.statuses()[0].last_error.is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(5_250)).await;
    assert!(!supervisor.shutdown(Duration::from_secs(2)).await.clean());
}

#[tokio::test]
async fn supervisor_reconcile_stops_disabled_and_removed_sources() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, _rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    let first_path = temp.path().join("one.log");
    let second_path = temp.path().join("two.log");
    tokio::fs::write(&first_path, b"").await.unwrap();
    tokio::fs::write(&second_path, b"").await.unwrap();

    registry
        .upsert(source("one", &first_path.to_string_lossy(), "one"))
        .unwrap();
    registry
        .upsert(source("two", &second_path.to_string_lossy(), "two"))
        .unwrap();
    supervisor.reconcile().await.unwrap();
    assert!(supervisor.running_source_for_test("one").is_some());
    assert!(supervisor.running_source_for_test("two").is_some());

    registry
        .set_enabled("one", false, "2026-06-11T20:01:00Z")
        .unwrap();
    supervisor.reconcile().await.unwrap();
    assert!(supervisor.running_source_for_test("one").is_none());
    assert!(supervisor.running_source_for_test("two").is_some());

    registry.remove("two").unwrap();
    supervisor.reconcile().await.unwrap();
    assert!(supervisor.running_source_for_test("two").is_none());
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn reconcile_flushes_dirty_checkpoint_before_replacing_task() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("changed.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source("changed", &log_path.to_string_lossy(), "old-tag");
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    let envelope = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    envelope.ack_success();

    let mut changed = registry.get("changed").unwrap().unwrap();
    changed.tag = "new-tag".into();
    registry.upsert(changed).unwrap();
    supervisor.reconcile().await.unwrap();

    assert_eq!(
        registry.get("changed").unwrap().unwrap().checkpoint_offset,
        Some(b"line\n".len() as u64)
    );
    assert_eq!(
        supervisor.running_source_for_test("changed").unwrap().tag,
        "new-tag"
    );
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn reconcile_surfaces_dirty_checkpoint_failure_before_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("changed-failure.log");
    tokio::fs::write(&log_path, b"line\n").await.unwrap();
    let mut configured = source("changed-failure", &log_path.to_string_lossy(), "old-tag");
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        8192,
    );
    supervisor.reconcile().await.unwrap();
    let envelope = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    envelope.ack_success();

    let mut changed = registry.get("changed-failure").unwrap().unwrap();
    changed.tag = "new-tag".into();
    registry.upsert(changed).unwrap();
    registry.set_fail_checkpoint_writes(true);
    let error = supervisor.reconcile().await.unwrap_err();

    assert!(error.to_string().contains("checkpoint persistence failure"));
    assert!(
        supervisor
            .running_source_for_test("changed-failure")
            .is_none()
    );
}

#[tokio::test]
async fn open_tail_file_resumes_matching_checkpoint_before_start_at_end() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"old\nnew\n").await.unwrap();
    let metadata = std::fs::metadata(&file_path).unwrap();
    let mut src = source("app", &file_path.to_string_lossy(), "app");
    src.start_at_end = true;
    src.checkpoint_dev = Some(metadata.dev());
    src.checkpoint_ino = Some(metadata.ino());
    src.checkpoint_offset = Some(4);

    let mut opened = open_tail_file(&src, true).await.unwrap();
    assert_eq!(opened.position, 4);
    let mut rest = String::new();
    opened.file.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "new\n");
}

#[tokio::test]
async fn open_tail_file_restarts_at_beginning_when_checkpoint_identity_mismatches() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"replacement\n")
        .await
        .unwrap();
    let mut src = source("app", &file_path.to_string_lossy(), "app");
    src.start_at_end = true;
    src.checkpoint_dev = Some(1);
    src.checkpoint_ino = Some(2);
    src.checkpoint_offset = Some(3);

    let mut opened = open_tail_file(&src, true).await.unwrap();

    assert_eq!(opened.position, 0);
    let mut rest = String::new();
    opened.file.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "replacement\n");
}

#[tokio::test]
async fn open_tail_file_rejects_symlink_paths() {
    let temp = tempfile::tempdir().unwrap();
    let target_path = temp.path().join("target.log");
    let symlink_path = temp.path().join("link.log");
    tokio::fs::write(&target_path, b"secret\n").await.unwrap();
    std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();
    let src = source("app", &symlink_path.to_string_lossy(), "app");

    let err = open_tail_file(&src, false).await.unwrap_err();

    assert!(err.to_string().contains("must not be a symlink"));
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_detects_rename_create_rotation() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"old\n").await.unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let old = open_tail_file(&src, false).await.unwrap();

    tokio::fs::rename(&file_path, temp.path().join("app.log.1"))
        .await
        .unwrap();
    tokio::fs::write(&file_path, b"new\n").await.unwrap();

    let reopened =
        reopen_if_rotated_or_truncated(&src, old.identity, old.position, &old.fingerprint)
            .await
            .unwrap()
            .expect("rotation should reopen");
    assert_eq!(reopened.position, 0);
    assert_ne!(reopened.identity, old.identity);
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_detects_copytruncate() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"first line\nsecond line\n")
        .await
        .unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let mut opened = open_tail_file(&src, false).await.unwrap();
    opened.position = 22;
    tokio::fs::write(&file_path, b"new\n").await.unwrap();

    let reopened =
        reopen_if_rotated_or_truncated(&src, opened.identity, opened.position, &opened.fingerprint)
            .await
            .unwrap()
            .expect("truncate should reopen");
    assert_eq!(reopened.position, 0);
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_ignores_append_beyond_original_fingerprint() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    let old_contents = b"already here\n";
    tokio::fs::write(&file_path, old_contents).await.unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let mut opened = open_tail_file(&src, false).await.unwrap();
    opened.position = old_contents.len() as u64;

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .await
        .unwrap();
    writer.write_all(b"after reconcile\n").await.unwrap();
    writer.flush().await.unwrap();

    let reopened =
        reopen_if_rotated_or_truncated(&src, opened.identity, opened.position, &opened.fingerprint)
            .await
            .unwrap();
    assert!(
        reopened.is_none(),
        "append-only growth must not be mistaken for same-inode replacement"
    );
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_refreshes_full_fingerprint_after_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    let old_contents = b"old
";
    tokio::fs::write(&file_path, old_contents).await.unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let mut opened = open_tail_file(&src, false).await.unwrap();
    opened.position = old_contents.len() as u64;

    let replacement = b"new replacement that is longer than the old prefix
";
    tokio::fs::write(&file_path, replacement).await.unwrap();

    let reopened =
        reopen_if_rotated_or_truncated(&src, opened.identity, opened.position, &opened.fingerprint)
            .await
            .unwrap()
            .expect("replacement should reopen");
    assert_eq!(reopened.position, 0);
    assert_eq!(reopened.fingerprint, replacement.to_vec());
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_detects_same_inode_copytruncate_regrow() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    let old_contents = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    tokio::fs::write(&file_path, old_contents).await.unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let mut opened = open_tail_file(&src, false).await.unwrap();
    opened.position = 40;
    tokio::fs::write(
        &file_path,
        b"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
    )
    .await
    .unwrap();

    let reopened =
        reopen_if_rotated_or_truncated(&src, opened.identity, opened.position, &opened.fingerprint)
            .await
            .unwrap()
            .expect("same-inode replacement should reopen");
    assert_eq!(reopened.position, 0);
}

#[tokio::test]
async fn reopen_if_rotated_or_truncated_errors_when_file_disappears() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"old\n").await.unwrap();
    let src = source("app", &file_path.to_string_lossy(), "app");
    let old = open_tail_file(&src, false).await.unwrap();
    tokio::fs::remove_file(&file_path).await.unwrap();

    let err = reopen_if_rotated_or_truncated(&src, old.identity, old.position, &old.fingerprint)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("disappeared"));
}

#[tokio::test]
async fn supervisor_ingests_partial_eof_buffer_before_rotation() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let token = tokio_util::sync::CancellationToken::new();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        token.clone(),
        8192,
    );
    let log_path = temp.path().join("app.log");
    tokio::fs::write(&log_path, b"partial").await.unwrap();
    let mut src = source("app", &log_path.to_string_lossy(), "app");
    src.start_at_end = false;
    registry.upsert(src).unwrap();
    supervisor.reconcile().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tokio::fs::rename(&log_path, temp.path().join("app.log.1"))
        .await
        .unwrap();
    tokio::fs::write(&log_path, b"next\n").await.unwrap();

    let envelope = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(envelope.entry.message, "partial");
    envelope.ack_success();

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let statuses = supervisor.statuses();
            if statuses.iter().any(|status| {
                status
                    .last_error
                    .as_deref()
                    .is_some_and(|err| err.contains("unterminated partial line"))
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    token.cancel();
    supervisor.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn truncated_line_status_does_not_fail_clean_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let registry = std::sync::Arc::new(FileTailRegistry::new(temp.path().join("file-tails.json")));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::ingest::IngestEnvelope>(4);
    let ingest = IngestTx::from_envelope_sender_for_test(tx);
    let log_path = temp.path().join("oversized.log");
    tokio::fs::write(&log_path, b"abcdef\n").await.unwrap();
    let mut configured = source("oversized", &log_path.to_string_lossy(), "oversized");
    configured.start_at_end = false;
    registry.upsert(configured).unwrap();
    let supervisor = FileTailSupervisor::new(
        std::sync::Arc::clone(&registry),
        ingest,
        tokio_util::sync::CancellationToken::new(),
        3,
    );
    supervisor.reconcile().await.unwrap();

    let envelope = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    envelope.ack_success();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if supervisor.statuses()[0].last_error.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    let mut changed = registry.get("oversized").unwrap().unwrap();
    changed.tag = "updated".into();
    registry.upsert(changed).unwrap();
    supervisor.reconcile().await.unwrap();
    assert_eq!(
        supervisor.running_source_for_test("oversized").unwrap().tag,
        "updated"
    );
    let report = supervisor.shutdown(Duration::from_secs(2)).await;
    assert!(report.clean());
}

#[tokio::test]
async fn read_bounded_line_truncates_oversized_records() {
    let cursor = std::io::Cursor::new(b"abcdef\nnext\n".to_vec());
    let mut reader = BufReader::new(cursor);
    let mut out = Vec::new();

    let first = read_bounded_line(&mut reader, &mut out, 3).await.unwrap();
    assert_eq!(first.bytes_read, 7);
    assert!(first.truncated);
    assert!(first.complete);
    assert_eq!(out, b"abc");

    out.clear();
    let second = read_bounded_line(&mut reader, &mut out, 3).await.unwrap();
    assert_eq!(second.bytes_read, 5);
    assert!(second.truncated);
    assert!(second.complete);
    assert_eq!(out, b"nex");
}

#[tokio::test]
async fn read_bounded_line_buffers_partial_eof_until_newline() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("app.log");
    tokio::fs::write(&file_path, b"abc").await.unwrap();
    let file = tokio::fs::File::open(&file_path).await.unwrap();
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();

    let partial = read_bounded_line(&mut reader, &mut out, 8192)
        .await
        .unwrap();
    assert_eq!(partial.bytes_read, 3);
    assert!(!partial.complete);
    assert_eq!(out, b"abc");

    let mut writer = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .await
        .unwrap();
    writer.write_all(b"def\n").await.unwrap();
    writer.flush().await.unwrap();

    let complete = read_bounded_line(&mut reader, &mut out, 8192)
        .await
        .unwrap();
    assert_eq!(complete.bytes_read, 4);
    assert!(complete.complete);
    assert_eq!(out, b"abcdef\n");
}

#[tokio::test]
async fn tail_file_once_sends_existing_lines_when_not_starting_at_end() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("authelia.log");
    let mut file = tokio::fs::File::create(&file_path).await.unwrap();
    file.write_all(b"time=one level=info\n").await.unwrap();
    file.write_all(b"time=two level=error\n").await.unwrap();
    file.flush().await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogBatchEntry>(4);
    let ingest = IngestTx::from_sender_for_test(tx);
    let source = FileTailSource {
        id: "authelia".into(),
        path: file_path.to_string_lossy().into_owned(),
        tag: "authelia".into(),
        hostname: Some("edgehost".into()),
        facility: Some("local5".into()),
        severity: "info".into(),
        start_at_end: false,
        enabled: true,
        checkpoint_dev: None,
        checkpoint_ino: None,
        checkpoint_offset: None,
        created_at: "2026-06-11T20:00:00Z".into(),
        updated_at: "2026-06-11T20:00:00Z".into(),
    };

    tail_file_once_for_test(source, ingest).await.unwrap();

    assert_eq!(rx.recv().await.unwrap().message, "time=one level=info");
    assert_eq!(rx.recv().await.unwrap().message, "time=two level=error");
    assert!(rx.try_recv().is_err());
}
