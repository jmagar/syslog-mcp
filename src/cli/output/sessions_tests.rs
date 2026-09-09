use super::*;
use cortex::app::AiIndexingOperatorHealth;
use cortex::app::{IncidentEvent, ServiceJournalEntry};
use cortex::scanner::{CheckpointEntry, IndexFileError, ParseErrorEntry, TranscriptRootStatus};
use std::path::PathBuf;

#[test]
fn checkpoint_json_output_is_accepted_for_empty_response() {
    print_checkpoints_response(&[], true).unwrap();
}

#[test]
fn parse_error_json_output_is_accepted_for_empty_response() {
    print_ai_parse_errors_response(&[], true).unwrap();
}

#[test]
fn human_ai_output_branches_accept_representative_payloads() {
    let checkpoints = vec![CheckpointEntry {
        canonical_path: "/tmp/transcript.jsonl".to_string(),
        source_kind: "codex".to_string(),
        file_size: Some(123),
        file_mtime: Some(456),
        content_hash: Some("abc".to_string()),
        last_offset: Some(99),
        last_indexed_at: Some("2026-06-13T00:00:00Z".to_string()),
        last_error: Some("bad row".to_string()),
        imported_records: 12,
        missing: true,
        parse_errors: 2,
    }];
    print_checkpoints_response(&checkpoints, false).unwrap();

    let parse_errors = vec![ParseErrorEntry {
        canonical_path: "/tmp/transcript.jsonl".to_string(),
        source_kind: "codex".to_string(),
        line_no: 42,
        error: "invalid json".to_string(),
        record_preview: Some("{nope".to_string()),
        seen_at: "2026-06-13T00:00:00Z".to_string(),
    }];
    print_ai_parse_errors_response(&parse_errors, false).unwrap();

    let prune = PruneCheckpointsResult {
        matched: 2,
        pruned: 1,
        dry_run: false,
        paths: vec!["/tmp/missing.jsonl".to_string()],
    };
    print_prune_checkpoints_response(&prune, false).unwrap();

    let mut index = IndexResult::default();
    index.discovered_files = 3;
    index.ingested = 2;
    index.skipped_dupes = 1;
    index.unsupported_files = 1;
    index.dropped_metadata_fields = 1;
    index.checkpoint_updates = 2;
    print_index_response(&index, false).unwrap();
    index.file_errors.push(IndexFileError {
        path: "/tmp/bad.jsonl".to_string(),
        error: "permission denied".to_string(),
    });
    print_index_response(&index, false).unwrap();
}

fn root_status(exists: bool, strict_ok: bool) -> TranscriptRootStatus {
    TranscriptRootStatus {
        path: "/tmp/transcripts".to_string(),
        exists,
        readable: exists,
        writable: exists,
        owner_uid: Some(1000),
        owner_gid: Some(1000),
        mode: Some(0o700),
        strict_ok,
    }
}

#[test]
fn human_status_and_incident_outputs_accept_optional_branches() {
    let report = ai_doctor_report(
        root_status(true, true),
        root_status(false, false),
        root_status(false, false),
    );
    print_ai_doctor_response(&report, false).unwrap();

    let watch = AiWatchStatusReport {
        service: "cortex-sessions-watch.service".to_string(),
        active: Some("active".to_string()),
        enabled: Some("enabled".to_string()),
        main_pid: Some(1234),
        exec_start: Some("/usr/bin/cortex sessions watch".to_string()),
        exec_main_start_timestamp: Some("Sat 2026-06-13".to_string()),
        process_start_time: Some("2026-06-13T00:00:00Z".to_string()),
        health: Some(AiIndexingOperatorHealth {
            db_schema_version: 2,
            known_schema_version: 2,
            schema_current: true,
            schema_drift_detected: false,
            last_successful_ingest_at: Some("2026-06-13T00:00:00Z".to_string()),
            recent_failure_count: 0,
            first_failure_at: None,
            last_failure_at: None,
            recent_schema_error_count: 0,
            stale_indicators: vec!["lagging".to_string()],
            provider_coverage: Vec::new(),
        }),
        health_error: None,
        latest_journal: vec!["one log line".to_string()],
        journal_error: None,
    };
    print_sessions_watch_status_response(&watch, false).unwrap();

    let watch_unhealthy = AiWatchStatusReport {
        health: None,
        health_error: Some("db unavailable".to_string()),
        latest_journal: Vec::new(),
        journal_error: Some("journalctl failed".to_string()),
        ..watch
    };
    print_sessions_watch_status_response(&watch_unhealthy, false).unwrap();

    let service_logs = cortex::app::ServiceLogsResponse {
        service: "cortex.service".to_string(),
        from: None,
        to: None,
        tail: Some(10),
        entries: vec![ServiceJournalEntry {
            timestamp: Some("2026-06-13T00:00:00Z".to_string()),
            realtime_timestamp_us: None,
            unit: Some("cortex.service".to_string()),
            priority: Some("6".to_string()),
            syslog_identifier: Some("cortex".to_string()),
            pid: Some("123".to_string()),
            message: Some("started".to_string()),
            cursor: None,
        }],
        dropped_lines: 1,
    };
    print_service_logs_response(&service_logs, false).unwrap();

    let incident = IncidentResponse {
        around: "2026-06-13T00:00:00Z".to_string(),
        window_minutes: 5,
        window_from: "2026-06-12T23:55:00Z".to_string(),
        window_to: "2026-06-13T00:05:00Z".to_string(),
        event_count: 1,
        truncated: true,
        warnings: vec!["limited".to_string()],
        events: vec![IncidentEvent {
            timestamp: "2026-06-13T00:00:00Z".to_string(),
            source: "syslog".to_string(),
            host: Some("host-a".to_string()),
            severity: Some("err".to_string()),
            app: Some("nginx".to_string()),
            message: "boom".to_string(),
            log_id: Some(1),
        }],
    };
    print_incident_response(&incident, false).unwrap();
}

#[test]
fn human_smoke_watch_output_accepts_report() {
    let report = AiSmokeWatchReport {
        session_id: "session-1".to_string(),
        transcript_path: PathBuf::from("/tmp/session.jsonl"),
        ingested: true,
        pruned_missing_checkpoint: true,
        missing_checkpoint_count: 0,
    };

    print_ai_smoke_watch_response(&report, false).unwrap();
}

fn ai_doctor_report(
    claude_root: TranscriptRootStatus,
    codex_root: TranscriptRootStatus,
    gemini_root: TranscriptRootStatus,
) -> AiDoctorReport {
    AiDoctorReport {
        db_path: "/tmp/cortex.db".to_string(),
        db_schema_version: 1,
        db_last_migration_at: None,
        known_schema_version: 1,
        schema_current: true,
        claude_root,
        codex_root,
        gemini_root,
        checkpoint_count: 0,
        checkpoint_error_count: 0,
        missing_checkpoint_count: 0,
        imported_record_count: 0,
        parse_error_count: 0,
        newest_indexed_path: None,
        newest_indexed_at: None,
    }
}

#[test]
fn ensure_index_success_accepts_clean_result_and_dropped_metadata_warning() {
    let clean = IndexResult::default();
    ensure_index_success(&clean).unwrap();

    let mut dropped_metadata = IndexResult::default();
    dropped_metadata.dropped_metadata_fields = 2;
    ensure_index_success(&dropped_metadata).unwrap();
}

#[test]
fn ensure_index_success_reports_storage_parse_and_file_failures() {
    let mut storage_blocked = IndexResult::default();
    storage_blocked.storage_blocked_chunks = 2;
    let err = ensure_index_success(&storage_blocked).unwrap_err();
    assert!(err.to_string().contains("blocked by storage guardrails"));

    let mut parse_errors = IndexResult::default();
    parse_errors.parse_errors = 3;
    let err = ensure_index_success(&parse_errors).unwrap_err();
    assert!(err.to_string().contains("failed to parse"));

    let mut file_errors = IndexResult::default();
    file_errors.file_errors.push(IndexFileError {
        path: "/tmp/bad.jsonl".to_string(),
        error: "permission denied".to_string(),
    });
    let err = ensure_index_success(&file_errors).unwrap_err();
    assert!(err.to_string().contains("failed to index"));
}

#[test]
fn ensure_ai_doctor_success_enforces_strict_permissions_only_for_existing_roots() {
    let strict_failure = ai_doctor_report(
        root_status(true, false),
        root_status(false, false),
        root_status(false, false),
    );
    let err = ensure_ai_doctor_success(&strict_failure, true).unwrap_err();
    assert!(
        err.to_string()
            .contains("AI transcript root permission check failed")
    );

    ensure_ai_doctor_success(&strict_failure, false).unwrap();

    // A bad gemini_root must fail the strict gate just like claude_root/codex_root.
    // Claude and Codex roots are absent here, so only the gemini disjunct can trip it.
    let gemini_strict_failure = ai_doctor_report(
        root_status(false, false),
        root_status(false, false),
        root_status(true, false),
    );
    let err = ensure_ai_doctor_success(&gemini_strict_failure, true).unwrap_err();
    assert!(
        err.to_string()
            .contains("AI transcript root permission check failed")
    );

    ensure_ai_doctor_success(&gemini_strict_failure, false).unwrap();

    let missing_roots = ai_doctor_report(
        root_status(false, false),
        root_status(false, false),
        root_status(false, false),
    );
    ensure_ai_doctor_success(&missing_roots, true).unwrap();
}
