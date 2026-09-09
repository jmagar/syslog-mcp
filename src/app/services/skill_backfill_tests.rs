use super::*;
use crate::app::CortexService;
use crate::config::StorageConfig;
use crate::db::{DbPool, init_pool};
use serial_test::serial;
use std::path::Path;
use std::sync::Arc;

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn backfill_requires_persisted_completed_read_provenance() {
    let (service, _dir) = test_service();
    let pool = service.pool_for_test();
    {
        let conn = pool.get().unwrap();
        for kind in ["user", "assistant", "unknown", "codex_skill_read"] {
            conn.execute("INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip, ai_tool, metadata_json)
                VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', ?1, '', 'transcript://codex_session', 'codex', ?2)",
                rusqlite::params![r#"{"cortex_skill_read":"test"}"#, serde_json::json!({"event_kind":kind}).to_string()]).unwrap();
        }
    }
    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();
    assert_eq!(result.scanned, 4);
    assert_eq!(result.inserted, 1);
    let conn = pool.get().unwrap();
    let kind: String = conn.query_row("SELECT json_extract(l.metadata_json, '$.event_kind') FROM ai_skill_events s JOIN logs l ON l.id=s.log_id", [], |row| row.get(0)).unwrap();
    assert_eq!(kind, "codex_skill_read");
}

// All tests below share the process-wide `backfill_guard()` singleton
// semaphore, so they must not run concurrently with each other (a parallel
// test run would otherwise race on the same permit and produce spurious
// `Busy` failures unrelated to the behavior under test — see eng review
// Fix 7's single-flight guard).

fn test_service() -> (CortexService, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let storage = StorageConfig::for_test(db_path);
    let pool: Arc<DbPool> = Arc::new(init_pool(&storage).unwrap());
    (CortexService::new(pool, storage), dir)
}

/// Single source of truth for the `logs` INSERT used by every helper below —
/// `ai_transcript_path`/`metadata_json.line_no` are always written together
/// (`Some`) or omitted together (`None`, the legacy no-source shape), so the
/// column list can't drift between the recoverable and unrecoverable fixtures.
/// `logs.message` is always the scrubbed plain text (`'hi'`), matching what the
/// real ingest pipeline stores for a Claude row.
fn insert_claude_row(pool: &DbPool, source: Option<(&str, usize)>) -> i64 {
    let conn = pool.get().unwrap();
    match source {
        Some((transcript_path, line_no)) => {
            let metadata_json = serde_json::json!({ "line_no": line_no }).to_string();
            conn.execute(
                "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip, ai_tool, ai_project, ai_session_id, ai_transcript_path, metadata_json)
                 VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', 'hi', 'hi', 'transcript://claude_project', 'claude', 'cortex', 'sess-1', ?1, ?2)",
                rusqlite::params![transcript_path, metadata_json],
            )
            .unwrap();
        }
        None => {
            conn.execute(
                "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip, ai_tool, ai_project, ai_session_id, ai_transcript_path, metadata_json)
                 VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', 'hi', 'hi', 'transcript://claude_project', 'claude', 'cortex', 'sess-1', NULL, NULL)",
                [],
            )
            .unwrap();
        }
    }
    conn.last_insert_rowid()
}

/// Writes `raw_line` as the only line of a fresh transcript file under `dir`
/// and inserts a matching `logs` row with `ai_transcript_path`/`metadata_json`
/// set the way `scanner.rs::flush_chunk` sets them at real ingest time — this
/// is what a genuinely re-ingested Claude row looks like, as opposed to the
/// old fixture shape (raw JSON stuffed directly into `logs.message`), which
/// cannot occur from the real ingest pipeline (see module doc comment).
fn insert_claude_log_row(pool: &DbPool, dir: &Path, file_name: &str, raw_line: &str) -> i64 {
    let path = dir.join(file_name);
    std::fs::write(&path, format!("{raw_line}\n")).unwrap();
    // 0-based, matching scanner.rs's `flush_chunk` line_no counter — the
    // first line of a file is line_no 0.
    insert_claude_log_row_for_path(pool, &path.to_string_lossy(), 0)
}

fn insert_claude_log_row_for_path(pool: &DbPool, transcript_path: &str, line_no: usize) -> i64 {
    insert_claude_row(pool, Some((transcript_path, line_no)))
}

/// A legacy-shaped row with no `ai_transcript_path`/`metadata_json` at all —
/// what rows ingested before either column existed look like. Unrecoverable
/// by design; the backfill can only report it as `source_unavailable`.
fn insert_legacy_claude_log_row_without_source(pool: &DbPool) -> i64 {
    insert_claude_row(pool, None)
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn dry_run_reports_counts_without_inserting() {
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    insert_claude_log_row(
        &pool,
        dir.path(),
        "session.jsonl",
        r#"{"attributionSkill":"cortex-troubleshoot"}"#,
    );

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: true,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.source_unavailable, 0);
    assert!(result.dry_run);

    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ai_skill_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn real_run_inserts_events_and_is_idempotent() {
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    insert_claude_log_row(
        &pool,
        dir.path(),
        "session.jsonl",
        r#"{"attributionSkill":"cortex-troubleshoot"}"#,
    );

    let first = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();
    assert_eq!(first.scanned, 1);
    assert_eq!(first.inserted, 1);
    assert_eq!(first.skipped_duplicates, 0);
    assert_eq!(first.source_unavailable, 0);

    let second = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();
    assert_eq!(second.scanned, 1);
    assert_eq!(second.inserted, 0);
    assert_eq!(second.skipped_duplicates, 1);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_row_without_transcript_path_counts_as_source_unavailable() {
    // The gap this fix addresses: a legacy row with no `ai_transcript_path`/
    // `metadata_json` has no way to recover the raw JSON that once carried
    // `attributionSkill`. It must be reported, not silently dropped or
    // (worse) misreported as a successful no-op scan.
    let (service, _dir) = test_service();
    let pool = service.pool_for_test();
    insert_legacy_claude_log_row_without_source(&pool);

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.source_unavailable, 1);
    assert_eq!(result.parse_errors, 0);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_row_with_missing_source_file_counts_as_source_unavailable() {
    // ai_transcript_path/metadata_json are present but the file has since
    // been deleted or rotated away — also unrecoverable, also reported.
    let (service, _dir) = test_service();
    let pool = service.pool_for_test();
    insert_claude_log_row_for_path(&pool, "/nonexistent/path/session.jsonl", 0);

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.source_unavailable, 1);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_row_with_out_of_range_line_no_counts_as_source_unavailable() {
    // The file exists but no longer has a line at the recorded line_no
    // (truncated/rewritten since ingest).
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    let path = dir.path().join("session.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    insert_claude_log_row_for_path(&pool, &path.to_string_lossy(), 5);

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.source_unavailable, 1);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_row_source_line_without_skill_produces_no_event_or_error() {
    // The common case: the recovered line is valid JSON but genuinely has no
    // skill attribution. Not an error, not "unavailable" — just nothing to
    // insert.
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    insert_claude_log_row(&pool, dir.path(), "session.jsonl", r#"{"content":"hi"}"#);

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.source_unavailable, 0);
    assert_eq!(result.parse_errors, 0);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_row_with_malformed_source_line_counts_as_parse_error() {
    // The recovered line contains the attributionSkill substring but isn't
    // valid JSON — distinct failure mode from a missing source, so it must
    // land in `parse_errors`, not `source_unavailable`.
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    insert_claude_log_row(
        &pool,
        dir.path(),
        "session.jsonl",
        r#"{"attributionSkill":"cortex" not valid json"#,
    );

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.inserted, 0);
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.source_unavailable, 0);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn claude_rows_sharing_a_transcript_file_are_both_recovered() {
    // Two rows pointing at different lines of the SAME file — exercises the
    // inline per-chunk file grouping in `run_backfill` (`wanted_by_file` →
    // one `scanner::read_transcript_lines` pass per file, not one file-open
    // per row).
    let (service, dir) = test_service();
    let pool = service.pool_for_test();
    let path = dir.path().join("session.jsonl");
    std::fs::write(
        &path,
        concat!(
            r#"{"attributionSkill":"cortex-troubleshoot"}"#,
            "\n",
            r#"{"attributionSkill":"cortex-report"}"#,
            "\n",
        ),
    )
    .unwrap();
    insert_claude_log_row_for_path(&pool, &path.to_string_lossy(), 0);
    insert_claude_log_row_for_path(&pool, &path.to_string_lossy(), 1);

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();

    assert_eq!(result.scanned, 2);
    assert_eq!(result.inserted, 2);
    assert_eq!(result.source_unavailable, 0);
    assert_eq!(result.parse_errors, 0);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn limit_is_clamped_to_hard_upper_bound() {
    // Eng review Fix 7 — an operator/caller passing an absurd limit doesn't
    // drive an unbounded scan; it's silently clamped to the hard cap.
    let (service, dir) = test_service();
    insert_claude_log_row(
        &service.pool_for_test(),
        dir.path(),
        "session.jsonl",
        r#"{"attributionSkill":"cortex"}"#,
    );

    // 10_000_000 exceeds the hard cap (1_000_000) — should not error, should
    // just clamp. We can't easily observe the internal clamp directly
    // without a huge fixture, so this asserts the call succeeds rather than
    // erroring or hanging (a stronger unit test for the clamp arithmetic
    // itself lives at the module level below, not through the service).
    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(10_000_000),
            dry_run: true,
        })
        .await
        .unwrap();
    assert_eq!(result.scanned, 1);
}

#[tokio::test]
#[serial(skill_backfill_guard)]
async fn concurrent_backfill_calls_return_busy_instead_of_racing() {
    // Eng review Fix 7 — single-flight guard. Two concurrent calls: one
    // proceeds, the other observes the guard held and returns a clear
    // "already running" error rather than both scanning the same corpus
    // simultaneously. This test drives the guard directly (a real two-task
    // race is flaky to assert deterministically in a unit test) — it holds
    // the guard manually to simulate an in-flight backfill, then asserts the
    // service call observes it and fails fast.
    let (service, dir) = test_service();
    insert_claude_log_row(
        &service.pool_for_test(),
        dir.path(),
        "session.jsonl",
        r#"{"attributionSkill":"cortex"}"#,
    );

    let _held = super::backfill_guard()
        .clone()
        .try_acquire_owned()
        .expect("guard should be free at test start");

    let result = service
        .backfill_skill_events(SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: true,
        })
        .await;

    assert!(
        result.is_err(),
        "second concurrent backfill call must be rejected"
    );
}
