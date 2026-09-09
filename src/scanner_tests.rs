use super::*;
use crate::config::StorageConfig;
use crate::db::{
    ListAiSessionsParams, SearchAiSessionsParams, SearchParams, init_pool, list_ai_sessions,
    search_ai_sessions, search_logs, tail_logs,
};
use serial_test::serial;

fn test_pool() -> (crate::db::DbPool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    (pool, dir)
}

fn write_codex_app_worktree_git_pointer(worktree: &std::path::Path, project: &std::path::Path) {
    std::fs::create_dir_all(worktree).unwrap();
    let gitdir = project.join(".git/worktrees/codex-app");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
}

#[test]
fn index_file_is_idempotent() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session.jsonl");
    std::fs::write(&file, "{\"sessionId\":\"sess-1\",\"content\":\"hello\"}\n").unwrap();

    let first = index_file(&pool, &file, "explicit_file").unwrap();
    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(first.ingested, 1);
    assert_eq!(second.ingested, 0);
    assert_eq!(second.skipped_dupes, 1);
    let metadata_json: String = pool
        .get()
        .unwrap()
        .query_row("SELECT metadata_json FROM logs", [], |row| row.get(0))
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
    assert_eq!(metadata["source_type"], "transcript");
    assert_eq!(metadata["source_kind"], "explicit_file");
    assert_eq!(metadata["tool"], "claude");
    assert_eq!(metadata["line_no"], 0);
    assert_eq!(metadata["content_scrubbed"], true);
}

#[test]
fn force_reindexes_file_without_duplicate_logs() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("force.jsonl");
    std::fs::write(&file, "{\"sessionId\":\"sess-1\",\"content\":\"first\"}\n").unwrap();
    assert_eq!(
        index_file(&pool, &file, "explicit_file").unwrap().ingested,
        1
    );

    let forced = index_file_with_options(
        &pool,
        &file,
        "explicit_file",
        IndexFileOptions {
            force: true,
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(forced.ingested, 1);
    assert_eq!(forced.skipped_dupes, 0);
    let log_count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(log_count, 1);
}

#[test]
fn list_checkpoints_reports_errors_and_import_counts() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("broken.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"ok\"}\nnot-json\n",
    )
    .unwrap();
    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.parse_errors, 1);

    let checkpoints = list_checkpoints(
        &pool,
        &CheckpointListOptions {
            errors_only: true,
            missing_only: false,
            limit: Some(10),
        },
    )
    .unwrap();

    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].imported_records, 1);
    assert!(
        checkpoints[0]
            .last_error
            .as_deref()
            .unwrap()
            .contains("failed to parse")
    );
}

#[test]
fn prune_checkpoints_dry_run_and_delete_only_missing_sources() {
    let (pool, dir) = test_pool();
    let missing_file = dir.path().join("missing.jsonl");
    std::fs::write(
        &missing_file,
        "{\"sessionId\":\"sess-missing\",\"content\":\"gone\"}\nnot-json\n",
    )
    .unwrap();
    let present_file = dir.path().join("present.jsonl");
    std::fs::write(
        &present_file,
        "{\"sessionId\":\"sess-present\",\"content\":\"still here\"}\n",
    )
    .unwrap();

    assert_eq!(
        index_file(&pool, &missing_file, "explicit_file")
            .unwrap()
            .ingested,
        1
    );
    assert_eq!(
        index_file(&pool, &present_file, "explicit_file")
            .unwrap()
            .ingested,
        1
    );
    std::fs::remove_file(&missing_file).unwrap();
    let canonical_missing_file = missing_file
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(missing_file.file_name().unwrap());

    let missing = list_checkpoints(
        &pool,
        &CheckpointListOptions {
            errors_only: false,
            missing_only: true,
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(
        missing[0].canonical_path,
        canonical_missing_file.display().to_string()
    );

    let dry_run = prune_checkpoints(
        &pool,
        &PruneCheckpointsOptions {
            missing_only: true,
            dry_run: true,
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(dry_run.matched, 1);
    assert_eq!(dry_run.pruned, 0);
    assert!(dry_run.dry_run);

    let pruned = prune_checkpoints(
        &pool,
        &PruneCheckpointsOptions {
            missing_only: true,
            dry_run: false,
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(pruned.matched, 1);
    assert_eq!(pruned.pruned, 1);

    let remaining = list_checkpoints(
        &pool,
        &CheckpointListOptions {
            errors_only: false,
            missing_only: false,
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].canonical_path,
        present_file.canonicalize().unwrap().display().to_string()
    );
}

#[test]
fn validate_path_rejects_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    std::fs::write(&target, "hi").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = validate_path(&link).unwrap_err();
    assert!(err.to_string().contains("symlinks"));
}

#[test]
fn collect_supported_files_skips_build_artifact_directories() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".codex/worktrees/session-id/lab");
    let target = project.join("target/debug/.fingerprint/package");
    let node_modules = project.join("node_modules/package");
    let cache = project.join(".cache/cargo/release/deps/rustc123");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    let transcript = project.join("rollout-session.jsonl");
    std::fs::write(&transcript, "{}\n").unwrap();
    std::fs::write(target.join("not-a-transcript.jsonl"), "{}\n").unwrap();
    std::fs::write(node_modules.join("also-not-a-transcript.jsonl"), "{}\n").unwrap();
    std::fs::write(cache.join("transient-not-a-transcript.jsonl"), "{}\n").unwrap();

    let mut result = IndexResult::default();
    let mut files = Vec::new();
    collect_supported_files(dir.path(), &mut files, &mut result);

    assert_eq!(files, vec![transcript]);
}

#[test]
fn parse_errors_are_counted_without_panicking() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("broken.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"ok\"}\nnot-json\n{\"sessionId\":\"sess-1\",\"content\":\"still ok\"}\n",
    )
    .unwrap();
    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 2);
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.checkpoint_updates, 0);

    let last_error: Option<String> = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT last_error FROM transcript_sources WHERE canonical_path = ?1",
            [file.canonicalize().unwrap().to_string_lossy().to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        last_error
            .unwrap()
            .contains("1 transcript record(s) failed to parse")
    );
}

#[test]
fn parse_error_retry_imports_only_fixed_rows_and_clears_checkpoint_error() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("repair.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"first\"}\nnot-json\n{\"sessionId\":\"sess-1\",\"content\":\"third\"}\n",
    )
    .unwrap();

    let first = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(first.ingested, 2);
    assert_eq!(first.parse_errors, 1);

    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"first\"}\n{\"sessionId\":\"sess-1\",\"content\":\"second\"}\n{\"sessionId\":\"sess-1\",\"content\":\"third\"}\n",
    )
    .unwrap();
    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(second.ingested, 1);
    assert_eq!(second.skipped_dupes, 2);
    assert_eq!(second.parse_errors, 0);
    assert_eq!(second.checkpoint_updates, 1);

    let (last_error, last_indexed_at): (Option<String>, Option<String>) = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT last_error, last_indexed_at FROM transcript_sources WHERE canonical_path = ?1",
            [file.canonicalize().unwrap().to_string_lossy().to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(last_error, None);
    assert!(last_indexed_at.is_some());
}

#[test]
fn oversized_records_are_counted_without_importing() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("oversized.jsonl");
    let oversized = "x".repeat(MAX_RECORD_SIZE_BYTES + 10);
    std::fs::write(
        &file,
        format!("{{\"sessionId\":\"sess-1\",\"content\":\"{oversized}\"}}\n"),
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 0);
    assert_eq!(result.parse_errors, 1);
}

#[test]
fn invalid_timestamp_does_not_record_import_identity() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("bad-time.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"timestamp\":\"not-a-time\",\"content\":\"bad time\"}\n",
    )
    .unwrap();

    let err = index_file(&pool, &file, "explicit_file").unwrap_err();
    assert!(err.to_string().contains("invalid transcript timestamp"));

    let conn = pool.get().unwrap();
    let import_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_import_records",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let log_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(import_count, 0);
    assert_eq!(log_count, 0);
}

#[test]
fn index_file_commits_multiple_chunks_but_marks_completion_once() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("multi.jsonl");
    let mut content = String::new();
    for i in 0..(MAX_INDEX_CHUNK_RECORDS + 1) {
        content.push_str(&format!(
            "{{\"sessionId\":\"sess-1\",\"content\":\"chunk {i}\"}}\n"
        ));
    }
    std::fs::write(&file, content).unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, MAX_INDEX_CHUNK_RECORDS + 1);
    assert_eq!(result.checkpoint_updates, 1);
}

#[test]
fn storage_write_block_returns_error_without_importing() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("blocked.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"blocked\"}\n",
    )
    .unwrap();
    let storage = crate::config::StorageConfig {
        db_path: dir.path().join("test.db"),
        min_free_disk_mb: u64::MAX / 1_048_576,
        recovery_free_disk_mb: u64::MAX / 1_048_576,
        ..crate::config::StorageConfig::for_test(dir.path().join("test.db"))
    };

    let result = index_file_with_storage(&pool, &file, "explicit_file", Some(&storage)).unwrap();
    assert_eq!(result.storage_blocked_chunks, 1);
    assert_eq!(result.ingested, 0);
    let log_count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(log_count, 0);
}

#[test]
fn index_file_reimports_rewritten_line_with_different_content() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session.jsonl");
    std::fs::write(&file, "{\"sessionId\":\"sess-1\",\"content\":\"first\"}\n").unwrap();
    assert_eq!(
        index_file(&pool, &file, "explicit_file").unwrap().ingested,
        1
    );

    std::fs::write(&file, "{\"sessionId\":\"sess-1\",\"content\":\"second\"}\n").unwrap();
    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(second.ingested, 1);
    assert_eq!(second.skipped_dupes, 0);
}

#[test]
fn scanner_drops_oversized_metadata_fields() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("metadata.jsonl");
    let long_project = "p".repeat(MAX_AI_PROJECT_CHARS + 1);
    let long_session = "s".repeat(MAX_AI_SESSION_ID_CHARS + 1);
    std::fs::write(
        &file,
        format!(
            "{{\"sessionId\":\"{long_session}\",\"cwd\":\"{long_project}\",\"content\":\"metadata kept\"}}\n\
             {{\"sessionId\":\"{long_session}\",\"cwd\":\"{long_project}\",\"content\":\"metadata kept again\"}}\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.dropped_metadata_fields, 2);
    let row = tail_logs(&pool, None, None, None, None, 1).unwrap();
    assert_eq!(row[0].ai_project, None);
    assert_eq!(row[0].ai_session_id, None);
}

#[test]
fn session_id_is_not_used_as_record_identity() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("shared-session.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"session\":{\"id\":\"same-session\"},\"message\":{\"content\":\"first event\"}}\n",
            "{\"session\":{\"id\":\"same-session\"},\"message\":{\"content\":\"second event\"}}\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 2);
    assert_eq!(result.skipped_dupes, 0);

    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("event".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn committed_chunk_can_be_retried_after_later_timestamp_failure() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("retry.jsonl");
    let mut content = String::new();
    for i in 0..MAX_INDEX_CHUNK_RECORDS {
        content.push_str(&format!(
            "{{\"sessionId\":\"sess-1\",\"content\":\"chunk {i}\"}}\n"
        ));
    }
    content.push_str("{\"sessionId\":\"sess-1\",\"timestamp\":\"bad\",\"content\":\"bad\"}\n");
    std::fs::write(&file, content).unwrap();

    let err = index_file(&pool, &file, "explicit_file").unwrap_err();
    assert!(err.to_string().contains("invalid transcript timestamp"));
    let first_count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(first_count, MAX_INDEX_CHUNK_RECORDS as i64);

    let mut fixed = String::new();
    for i in 0..MAX_INDEX_CHUNK_RECORDS {
        fixed.push_str(&format!(
            "{{\"sessionId\":\"sess-1\",\"content\":\"chunk {i}\"}}\n"
        ));
    }
    fixed.push_str("{\"sessionId\":\"sess-1\",\"content\":\"fixed tail\"}\n");
    std::fs::write(&file, fixed).unwrap();

    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(second.ingested, 1);
    assert_eq!(second.skipped_dupes, MAX_INDEX_CHUNK_RECORDS);
}

#[test]
fn index_file_scrubs_secrets_before_fts_storage() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\"}\n",
    )
    .unwrap();

    index_file(&pool, &file, "explicit_file").unwrap();
    let rows = tail_logs(&pool, None, None, None, None, 1).unwrap();
    assert_eq!(rows[0].message, "token [REDACTED]");

    let leaked = search_logs(
        &pool,
        &SearchParams {
            query: Some("ghp".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(leaked.is_empty());
}

#[test]
fn index_file_parses_realistic_codex_transcript_shape() {
    let (pool, dir) = test_pool();
    let codex_root = dir.path().join(".codex/sessions/2026/05/11");
    std::fs::create_dir_all(&codex_root).unwrap();
    let file = codex_root.join("rollout-codex-1.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-1\",\"cwd\":\"/home/jmagar/workspace/cortex\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"id\":\"codex-1\",\"content\":[{\"type\":\"output_text\",\"text\":\"fixed parser bug\"}]},\"timestamp\":\"2026-05-11T00:00:00Z\"}\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "parser".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions.len(), 1);
    assert_eq!(search.sessions[0].ai_tool, "codex");
    assert_eq!(
        search.sessions[0].ai_project,
        "/home/jmagar/workspace/cortex"
    );
    assert_eq!(search.sessions[0].ai_session_id, "codex-1");
}

#[test]
fn index_file_uses_claude_sessions_index_project_path() {
    let (pool, dir) = test_pool();
    let project_dir = dir.path().join(".claude/projects/-tmp-fallback");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        project_dir.join("sessions-index.json"),
        "{\"originalPath\":\"/tmp/project-with-hyphen\"}",
    )
    .unwrap();
    let file = project_dir.join("session.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"claude-1\",\"content\":\"hyphen project\"}\n",
    )
    .unwrap();

    index_file(&pool, &file, "claude_project").unwrap();
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "hyphen".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_project, "/tmp/project-with-hyphen");
}

#[test]
fn index_roots_ignores_claude_sessions_index_metadata() {
    let (pool, dir) = test_pool();
    let project_dir = dir.path().join(".claude/projects/-tmp-project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        project_dir.join("sessions-index.json"),
        "{\n  \"version\": 1,\n  \"entries\": []\n}\n",
    )
    .unwrap();
    std::fs::write(
        project_dir.join("session.jsonl"),
        "{\"sessionId\":\"claude-1\",\"content\":\"real transcript line\"}\n",
    )
    .unwrap();

    let result = index_roots(&pool, Some(dir.path())).unwrap();
    assert_eq!(result.ingested, 1);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.skipped_files, 0);
}

#[test]
#[serial]
fn index_roots_rejects_broad_home_root_and_repo_paths() {
    let (pool, _dir) = test_pool();
    let home = std::path::PathBuf::from(crate::env::var("HOME").unwrap());
    let repo = std::env::current_dir().unwrap();

    for path in [std::path::Path::new("/"), home.as_path(), repo.as_path()] {
        let result = index_roots(&pool, Some(path)).unwrap();
        assert_eq!(
            result.ingested,
            0,
            "unsafe path ingested rows: {}",
            path.display()
        );
        assert_eq!(
            result.skipped_unsafe_paths,
            1,
            "unsafe path not counted: {}",
            path.display()
        );
        assert_eq!(
            result.discovered_files,
            0,
            "unsafe path was scanned: {}",
            path.display()
        );
    }
}

#[test]
fn index_roots_counts_unsupported_files_without_parsing_them() {
    let (pool, dir) = test_pool();
    let transcripts = dir.path().join("transcripts");
    std::fs::create_dir(&transcripts).unwrap();
    std::fs::write(transcripts.join("notes.txt"), "not a transcript").unwrap();
    std::fs::write(
        transcripts.join("session.jsonl"),
        "{\"sessionId\":\"safe\",\"content\":\"indexed\"}\n",
    )
    .unwrap();

    let result = index_roots(&pool, Some(&transcripts)).unwrap();

    assert_eq!(result.ingested, 1);
    assert_eq!(result.unsupported_files, 1);
    assert_eq!(result.skipped_unsafe_paths, 0);
}

#[test]
fn scanner_exposes_default_roots_and_supported_file_policy() {
    let roots = default_transcript_roots();
    assert!(roots.iter().any(|path| path.ends_with(".claude/projects")));
    assert!(roots.iter().any(|path| path.ends_with(".codex/sessions")));
    assert!(roots.iter().any(|path| path.ends_with(".gemini/tmp")));
    assert!(is_supported_transcript_file(std::path::Path::new(
        "session.jsonl"
    )));
    assert!(is_supported_transcript_file(std::path::Path::new(
        ".gemini/tmp/hash/chats/session-2026-04-02T22-02-da13.json"
    )));
    assert!(!is_supported_transcript_file(std::path::Path::new(
        ".gemini/tmp/hash/chats/notes.json"
    )));
    assert!(is_supported_transcript_file(std::path::Path::new(
        "/mounted/.gemini/antigravity/brain/session/.system_generated/logs/transcript.jsonl"
    )));
    assert!(!is_supported_transcript_file(std::path::Path::new(
        "/mounted/.gemini/antigravity/brain/session/private-notes.jsonl"
    )));
}

#[test]
#[serial]
fn antigravity_discovery_is_narrow_and_sessions_remain_queryable() {
    let (pool, home) = test_pool();
    let _home = HomeOverride::set(home.path());
    let brain = home.path().join(".gemini/antigravity/brain");
    let transcript = brain.join("session-1/.system_generated/logs/transcript.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(
        &transcript,
        concat!(
            r#"{"source":"USER","type":"USER_INPUT","content":"investigate storage"}"#,
            "\n",
            r#"{"source":"MODEL","type":"PLANNER_RESPONSE","content":"checking storage"}"#,
            "\n"
        ),
    )
    .unwrap();
    std::fs::write(
        brain.join("session-1/unrelated.jsonl"),
        r#"{"source":"USER","content":"private unrelated artifact"}"#,
    )
    .unwrap();

    let result = index_roots(&pool, Some(&brain)).unwrap();
    assert_eq!(result.ingested, 2);
    assert_eq!(result.unsupported_files, 1);

    let sessions = list_ai_sessions(&pool, &ListAiSessionsParams::default()).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].ai_project, "antigravity://desktop");
    assert_eq!(sessions[0].ai_session_id, "session-1");
    assert_eq!(sessions[0].event_count, 2);

    let leaked: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message LIKE '%private unrelated artifact%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaked, 0);
}

#[test]
fn append_only_file_indexes_only_new_records_after_checkpoint() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session.jsonl");
    std::fs::write(
        &file,
        "{\"uuid\":\"one\",\"type\":\"user\",\"timestamp\":\"2026-05-14T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"first\"}}\n",
    )
    .unwrap();

    let first = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(first.ingested, 1);

    let mut open = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap();
    use std::io::Write;
    writeln!(
        open,
        "{{\"uuid\":\"two\",\"type\":\"user\",\"timestamp\":\"2026-05-14T00:00:01Z\",\"message\":{{\"role\":\"user\",\"content\":\"second\"}}}}"
    )
    .unwrap();

    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(second.ingested, 1);
    assert_eq!(second.skipped_dupes, 0);
}

#[test]
fn append_start_requires_stored_content_hash() {
    let stored = checkpoint::SourceMetadata {
        file_size: Some(10),
        file_mtime: Some(1),
        content_hash: None,
        last_offset: Some(10),
        last_error: None,
        source_revision: None,
        scan_state: checkpoint::SourceScanState::Complete,
    };
    let current = FileMetadata {
        size: 20,
        mtime: Some(2),
        content_hash: "new".to_string(),
    };

    assert_eq!(append_start_offset(&stored, &current).unwrap(), None);
}

#[test]
fn rewritten_file_falls_back_to_duplicate_safe_full_scan() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session.jsonl");
    std::fs::write(
        &file,
        "{\"uuid\":\"one\",\"type\":\"user\",\"timestamp\":\"2026-05-14T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"first\"}}\n",
    )
    .unwrap();
    assert_eq!(
        index_file(&pool, &file, "explicit_file").unwrap().ingested,
        1
    );

    std::fs::write(
        &file,
        "{\"uuid\":\"one\",\"type\":\"user\",\"timestamp\":\"2026-05-14T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"first changed\"}}\n",
    )
    .unwrap();

    let second = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(second.ingested, 0);
    assert!(second.skipped_dupes >= 1);
}

#[test]
#[serial]
fn index_roots_default_scans_claude_codex_codex_app_and_gemini_roots() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    // The default-root fixture is intentionally scoped to its temporary
    // home. A caller-supplied CODEX_HOME is an additional supported root and
    // must be covered in its own test rather than leaking real sessions into
    // this denominator.
    let _codex_home = EnvOverride::remove("CODEX_HOME");

    let claude_root = dir.path().join(".claude/projects/-tmp-default");
    std::fs::create_dir_all(&claude_root).unwrap();
    std::fs::write(
        claude_root.join("sessions-index.json"),
        "{\"originalPath\":\"/tmp/default-claude\"}",
    )
    .unwrap();
    std::fs::write(
        claude_root.join("session.jsonl"),
        "{\"sessionId\":\"claude-default\",\"content\":\"default claude root\"}\n",
    )
    .unwrap();

    let codex_root = dir.path().join(".codex/sessions/2026/05/13");
    std::fs::create_dir_all(&codex_root).unwrap();
    std::fs::write(
        codex_root.join("rollout-codex-default.jsonl"),
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-default\",\"cwd\":\"/tmp/default-codex\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"text\":\"default codex root\"}]},\"timestamp\":\"2026-05-13T00:00:00Z\"}\n"
        ),
    )
    .unwrap();

    let codex_app_project = dir.path().join("workspace/cortex");
    let codex_app_root = dir
        .path()
        .join(".codex/worktrees/ade935ee-48ec-49f4-8e89-ccb0294e73eb/cortex");
    write_codex_app_worktree_git_pointer(&codex_app_root, &codex_app_project);
    std::fs::write(
        codex_app_root.join("rollout-codex-app-default.jsonl"),
        format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"codex-app-default\",\"cwd\":\"{}\"}}}}\n\
             {{\"type\":\"response_item\",\"payload\":{{\"content\":[{{\"text\":\"default codex app worktree\"}}]}},\"timestamp\":\"2026-05-13T00:00:00Z\"}}\n",
            codex_app_root.display()
        ),
    )
    .unwrap();

    let gemini_root = dir.path().join(".gemini/tmp/hash/chats");
    std::fs::create_dir_all(&gemini_root).unwrap();
    std::fs::write(
        gemini_root.join("session-2026-04-02T22-02-da13.json"),
        r#"{
          "sessionId": "gemini-default",
          "projectHash": "hash",
          "startTime": "2026-04-02T22:02:55.537Z",
          "messages": [
            {
              "id": "gemini-message",
              "timestamp": "2026-04-02T22:03:29.818Z",
              "type": "gemini",
              "content": "default gemini root"
            }
          ]
        }"#,
    )
    .unwrap();

    let result = index_roots(&pool, None).unwrap();

    assert_eq!(result.discovered_files, 4);
    assert_eq!(result.ingested, 4);
    let claude = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "claude".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(claude.sessions[0].ai_tool, "claude");
    assert_eq!(claude.sessions[0].ai_project, "/tmp/default-claude");

    let codex = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"default codex root\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(codex.sessions[0].ai_tool, "codex");
    assert_eq!(codex.sessions[0].ai_project, "/tmp/default-codex");
    assert_eq!(codex.sessions[0].ai_session_id, "codex-default");

    let codex_app = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"default codex app worktree\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(codex_app.sessions[0].ai_tool, "codex");
    assert_eq!(
        codex_app.sessions[0].ai_project,
        codex_app_project.to_string_lossy()
    );
    assert_eq!(codex_app.sessions[0].ai_session_id, "codex-app-default");

    let (gemini_tool, gemini_session): (String, String) = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT ai_tool, ai_session_id FROM logs WHERE ai_tool = 'gemini'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(gemini_tool, "gemini");
    assert_eq!(gemini_session, "gemini-default");
    let gemini_sessions = list_ai_sessions(
        &pool,
        &crate::db::ListAiSessionsParams {
            ai_project: Some("gemini://project/hash".into()),
            ai_tool: Some("gemini".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(gemini_sessions.len(), 1);
    assert_eq!(gemini_sessions[0].ai_session_id, "gemini-default");
}

#[test]
#[serial]
fn validate_transcript_scan_path_allows_codex_app_worktree_root() {
    let dir = tempfile::tempdir().unwrap();
    let _home = HomeOverride::set(dir.path());
    let worktrees = dir.path().join(".codex/worktrees");
    std::fs::create_dir_all(&worktrees).unwrap();

    let canonical = validate_transcript_scan_path(&worktrees).unwrap();
    assert_eq!(canonical, worktrees.canonicalize().unwrap());
}

#[test]
fn index_file_uses_session_meta_for_codex_response_items() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("rollout-session.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-session\",\"cwd\":\"/work/project\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"id\":\"response-item-1\",\"content\":[{\"type\":\"output_text\",\"text\":\"session context preserved\"}]},\"timestamp\":\"2026-05-11T00:00:00Z\"}\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "preserved".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_session_id, "codex-session");
    assert_eq!(search.sessions[0].ai_project, "/work/project");
}

#[test]
fn index_file_normalizes_codex_project_local_worktree_cwd() {
    let (pool, dir) = test_pool();
    let project = dir.path().join("workspace/cortex");
    std::fs::create_dir_all(&project).unwrap();
    let file = dir.path().join("rollout-worktree.jsonl");
    let worktree = project.join(".worktrees/session-indexing");
    std::fs::write(
        &file,
        format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"worktree-session\",\"cwd\":\"{}\"}}}}\n\
             {{\"type\":\"response_item\",\"payload\":{{\"content\":[{{\"type\":\"output_text\",\"text\":\"worktree normalized\"}}]}},\"timestamp\":\"2026-05-11T00:00:00Z\"}}\n",
            worktree.display()
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "normalized".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_project, project.to_string_lossy());
}

#[test]
fn index_file_normalizes_claude_project_local_worktree_cwd() {
    let (pool, dir) = test_pool();
    let project = dir.path().join("workspace/cortex");
    std::fs::create_dir_all(&project).unwrap();
    let file = dir.path().join("claude-worktree.jsonl");
    let worktree = project.join(".claude/worktrees/session-indexing");
    std::fs::write(
        &file,
        format!(
            "{{\"session_id\":\"claude-worktree\",\"cwd\":\"{}\",\"content\":\"claude worktree normalized\",\"timestamp\":\"2026-05-11T00:00:00Z\"}}\n",
            worktree.display()
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "claude_project").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"claude worktree\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_tool, "claude");
    assert_eq!(search.sessions[0].ai_project, project.to_string_lossy());
}

#[test]
#[serial]
fn index_file_normalizes_codex_app_worktree_cwd_to_workspace_project() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let project = dir.path().join("workspace/cortex");
    std::fs::create_dir_all(&project).unwrap();
    let file = dir.path().join("rollout-codex-app-worktree.jsonl");
    let worktree = dir
        .path()
        .join(".codex/worktrees/ade935ee-48ec-49f4-8e89-ccb0294e73eb/cortex");
    write_codex_app_worktree_git_pointer(&worktree, &project);
    std::fs::write(
        &file,
        format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"codex-app-worktree\",\"cwd\":\"{}\"}}}}\n\
             {{\"type\":\"response_item\",\"payload\":{{\"content\":[{{\"type\":\"output_text\",\"text\":\"codex app worktree normalized\"}}]}},\"timestamp\":\"2026-05-11T00:00:00Z\"}}\n",
            worktree.display()
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"codex app worktree\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_project, project.to_string_lossy());
}

#[test]
#[serial]
fn index_file_keeps_codex_app_worktree_when_workspace_project_missing() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let file = dir.path().join("rollout-codex-app-worktree-missing.jsonl");
    let worktree = dir
        .path()
        .join(".codex/worktrees/ade935ee-48ec-49f4-8e89-ccb0294e73eb/cortex");
    std::fs::write(
        &file,
        format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"codex-app-worktree-missing\",\"cwd\":\"{}\"}}}}\n\
             {{\"type\":\"response_item\",\"payload\":{{\"content\":[{{\"type\":\"output_text\",\"text\":\"codex app worktree fallback\"}}]}},\"timestamp\":\"2026-05-11T00:00:00Z\"}}\n",
            worktree.display()
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"codex app worktree fallback\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_project, worktree.to_string_lossy());
}

#[test]
#[serial]
fn explicit_file_normalizes_current_dir_worktree_project() {
    let (pool, dir) = test_pool();
    let project = dir.path().join("workspace/cortex");
    let worktree = project.join(".worktrees/session-indexing");
    std::fs::create_dir_all(&worktree).unwrap();
    let _cwd = CurrentDirGuard::set(&worktree);
    let file = dir.path().join("explicit-claude.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"explicit-worktree\",\"content\":\"explicit worktree normalized\",\"timestamp\":\"2026-05-11T00:00:00Z\"}\n",
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"explicit worktree\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        search.sessions[0].ai_project,
        project.canonicalize().unwrap().to_string_lossy()
    );
}

#[test]
fn index_file_normalizes_gemini_cwd_worktree_project() {
    let (pool, dir) = test_pool();
    let project = dir.path().join("workspace/cortex");
    let worktree = project.join(".worktrees/session-indexing");
    std::fs::create_dir_all(&worktree).unwrap();
    let file = dir.path().join("session-2026-04-02T22-02-da13.json");
    std::fs::write(
        &file,
        format!(
            r#"{{
              "sessionId": "gemini-worktree",
              "cwd": "{}",
              "startTime": "2026-04-02T22:02:55.537Z",
              "messages": [
                {{
                  "id": "gemini-worktree-message",
                  "timestamp": "2026-04-02T22:03:29.818Z",
                  "type": "gemini",
                  "content": "gemini worktree normalized"
                }}
              ]
            }}"#,
            worktree.display()
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "\"gemini worktree\"".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_tool, "gemini");
    assert_eq!(search.sessions[0].ai_project, project.to_string_lossy());
}

#[test]
fn index_file_persists_scrubbed_gemini_session_metadata() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session-gemini-metadata.json");
    std::fs::write(
        &file,
        r#"{
          "sessionId": "gemini-metadata",
          "title": "Useful session title",
          "model": "gemini-test",
          "version": "1.2.3",
          "messages": [{
            "id": "gemini-metadata-message",
            "timestamp": "2026-01-01T00:00:00Z",
            "content": "hello"
          }]
        }"#,
    )
    .unwrap();

    let result = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(result.ingested, 1);
    let conn = pool.get().unwrap();
    let raw: String = conn
        .query_row(
            "SELECT metadata_json FROM logs WHERE ai_session_id = 'gemini-metadata'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(metadata["session"]["title"], "Useful session title");
    assert_eq!(metadata["session"]["title_provenance"], "provider");
    assert_eq!(metadata["session"]["model"], "gemini-test");
    assert_eq!(metadata["session"]["client_version"], "1.2.3");
    assert_eq!(metadata["session"]["source_format"], "gemini-legacy-json");
}

#[test]
fn explicit_file_detects_codex_transcript_shape_outside_codex_root() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("exported-codex.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"explicit-codex\",\"cwd\":\"/tmp/exported-codex\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"type\":\"output_text\",\"text\":\"explicit codex imported\"}]},\"timestamp\":\"2026-05-11T00:00:00Z\"}\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "imported".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_tool, "codex");
    assert_eq!(search.sessions[0].ai_session_id, "explicit-codex");
    assert_eq!(search.sessions[0].ai_project, "/tmp/exported-codex");
}

#[test]
#[serial]
fn default_index_does_not_skip_same_size_rewrite_with_new_mtime_nanos() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());

    let codex_root = dir.path().join(".codex/sessions/2026/05/14");
    std::fs::create_dir_all(&codex_root).unwrap();
    let file = codex_root.join("rollout-rewrite.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"rewrite-session\",\"cwd\":\"/tmp/rewrite\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"text\":\"alpha\"}]},\"timestamp\":\"2026-05-14T00:00:00Z\"}\n"
        ),
    )
    .unwrap();
    set_mtime(&file, 1_800_000_000, 1);

    let first = index_roots(&pool, None).unwrap();
    assert_eq!(first.ingested, 1);

    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"rewrite-session\",\"cwd\":\"/tmp/rewrite\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"text\":\"bravo\"}]},\"timestamp\":\"2026-05-14T00:00:00Z\"}\n"
        ),
    )
    .unwrap();
    set_mtime(&file, 1_800_000_000, 2);

    let second = index_roots(&pool, None).unwrap();

    assert_eq!(second.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "bravo".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_session_id, "rewrite-session");
}

#[test]
#[serial]
fn default_index_does_not_skip_same_size_rewrite_with_preserved_mtime() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());

    let codex_root = dir.path().join(".codex/sessions/2026/05/14");
    std::fs::create_dir_all(&codex_root).unwrap();
    let file = codex_root.join("rollout-rewrite-preserved-mtime.jsonl");
    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"rewrite-preserved\",\"cwd\":\"/tmp/rewrite\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"text\":\"alpha\"}]},\"timestamp\":\"2026-05-14T00:00:00Z\"}\n"
        ),
    )
    .unwrap();
    set_mtime(&file, 1_800_000_001, 1);

    let first = index_roots(&pool, None).unwrap();
    assert_eq!(first.ingested, 1);

    std::fs::write(
        &file,
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"rewrite-preserved\",\"cwd\":\"/tmp/rewrite\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"content\":[{\"text\":\"bravo\"}]},\"timestamp\":\"2026-05-14T00:00:00Z\"}\n"
        ),
    )
    .unwrap();
    set_mtime(&file, 1_800_000_001, 1);

    let second = index_roots(&pool, None).unwrap();

    assert_eq!(second.ingested, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "bravo".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_session_id, "rewrite-preserved");
}

#[test]
fn index_roots_since_skips_older_file_mtimes() {
    let (pool, dir) = test_pool();
    let old_file = dir.path().join("old.jsonl");
    let new_file = dir.path().join("new.jsonl");
    std::fs::write(
        &old_file,
        "{\"sessionId\":\"old\",\"content\":\"oldtoken\"}\n",
    )
    .unwrap();
    std::fs::write(
        &new_file,
        "{\"sessionId\":\"new\",\"content\":\"newtoken\"}\n",
    )
    .unwrap();
    set_mtime(&old_file, 1_700_000_000, 0);
    set_mtime(&new_file, 1_800_000_000, 0);

    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: Some(dir.path().to_path_buf()),
            since_mtime_nanos: Some(1_750_000_000_000_000_000),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.ingested, 1);
    assert_eq!(result.skipped_files, 1);
    assert_eq!(result.discovered_files, 1);
    let search = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "newtoken".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(search.sessions[0].ai_session_id, "new");
}

#[test]
#[serial]
fn bounded_snapshot_timeout_yields_to_later_source_without_late_persistence() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let root = dir.path().join(".codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    let stalled = root.join("000-stalled-codex.jsonl");
    let fast = root.join("999-fast-codex.jsonl");
    std::fs::write(
        &stalled,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"stalled-session"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"must never persist after timeout"}}"#,
            "\n"
        ),
    )
    .unwrap();
    std::fs::write(
        &fast,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"fast-session"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"later source reached canonical ingestion"}}"#,
            "\n"
        ),
    )
    .unwrap();

    let _delay = SnapshotDelayGuard::for_file(
        "000-stalled-codex.jsonl",
        std::time::Duration::from_millis(450),
    );
    let started = std::time::Instant::now();
    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: Some(root.clone()),
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 4_096,
                scan_max_bytes: 8_192,
                per_source_deadline: std::time::Duration::from_millis(100),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.source_deadline_exceeded, 1, "result={result:#?}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(300),
        "a stalled reader held the scan longer than its deadline"
    );
    let ingested_fast: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'later source reached canonical ingestion'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ingested_fast, 1);

    // The worker remains intentionally detached until the OS read returns.
    // It owns no persistence capability, so completion cannot create a source
    // or imports after the scanner classified it as deferred.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let late_source_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM transcript_sources WHERE canonical_path LIKE '%000-stalled-codex.jsonl'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        late_source_rows, 0,
        "timed-out source persisted after return"
    );
}

#[test]
#[serial]
fn bounded_gemini_snapshot_timeout_yields_to_later_gemini_without_late_persistence() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let _codex_home = EnvOverride::remove("CODEX_HOME");
    let root = dir.path().join(".gemini/tmp/hash/chats");
    std::fs::create_dir_all(&root).unwrap();
    let stalled = root.join("session-000-stalled.json");
    let fast = root.join("session-999-fast.json");
    std::fs::write(
        &stalled,
        r#"{"sessionId":"stalled","messages":[{"id":"stalled","content":"gemini must not persist late"}]}"#,
    )
    .unwrap();
    std::fs::write(
        &fast,
        r#"{"sessionId":"fast","messages":[{"id":"fast","content":"later Gemini source reached canonical ingestion"}]}"#,
    )
    .unwrap();

    let _delay = SnapshotDelayGuard::for_file(
        "session-000-stalled.json",
        std::time::Duration::from_millis(450),
    );
    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            // Default provider roots preserve the `/var`↔`/private/var`
            // identity used by the HOME override on macOS.
            root_override: None,
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 4_096,
                scan_max_bytes: 8_192,
                per_source_deadline: std::time::Duration::from_millis(100),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.source_deadline_exceeded, 1, "result={result:#?}");
    let fast_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'later Gemini source reached canonical ingestion'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fast_rows, 1);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let late_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM transcript_sources WHERE canonical_path LIKE '%session-000-stalled.json'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(late_rows, 0);
}

#[test]
#[serial]
fn saturated_snapshot_workers_defer_without_starving_later_source_on_retry() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let root = dir.path().join(".codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    for name in ["000-stalled.jsonl", "001-stalled.jsonl"] {
        std::fs::write(
            root.join(name),
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"stalled"}}"#,
        )
        .unwrap();
    }
    std::fs::write(
        root.join("999-healthy.jsonl"),
        r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"healthy source after saturation"}}"#,
    )
    .unwrap();
    let delay = SnapshotDelayGuard::for_files([
        ("000-stalled.jsonl", std::time::Duration::from_millis(450)),
        ("001-stalled.jsonl", std::time::Duration::from_millis(450)),
    ]);
    let options = IndexOptions {
        root_override: Some(root),
        scan_budget: Some(ScanBudget {
            per_source_max_bytes: 4_096,
            scan_max_bytes: 16_384,
            per_source_deadline: std::time::Duration::from_millis(100),
        }),
        ..Default::default()
    };
    let first = index_roots_with_options(&pool, options.clone(), None).unwrap();
    assert_eq!(first.source_deadline_exceeded, 2, "result={first:#?}");
    assert_eq!(first.snapshot_capacity_deferred, 1, "result={first:#?}");
    assert!(
        first.next_scan_cursor.is_some(),
        "attempted sources advance cursor"
    );

    std::thread::sleep(std::time::Duration::from_millis(500));
    drop(delay);
    let second = index_roots_with_options(&pool, options, None).unwrap();
    assert_eq!(second.snapshot_capacity_deferred, 0, "result={second:#?}");
    let healthy_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'healthy source after saturation'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(healthy_rows, 1, "later healthy source gets a fair retry");
}

#[test]
#[serial]
fn snapshot_bytes_count_when_gemini_utf8_validation_fails_before_records() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let root = dir.path().join(".gemini/tmp/hash/chats");
    std::fs::create_dir_all(&root).unwrap();
    let invalid = root.join("session-invalid.json");
    let later = root.join("session-later.json");
    std::fs::write(&invalid, *b"{\xff}").unwrap();
    std::fs::write(
        &later,
        r#"{"sessionId":"later","messages":[{"id":"later","content":"must defer after invalid bytes"}]}"#,
    )
    .unwrap();
    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: None,
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 64,
                scan_max_bytes: 3,
                per_source_deadline: std::time::Duration::from_secs(1),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(result.parse_errors, 1, "result={result:#?}");
    assert_eq!(result.scanned_bytes, 3, "invalid source bytes must count");
    assert!(result.scan_budget_cap_hit, "later source must be deferred");
}

#[test]
fn oversized_gemini_session_is_deferred_without_whole_file_ingestion() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("oversized-gemini.json");
    std::fs::write(
        &file,
        format!(
            r#"{{"sessionId":"large","messages":[{{"id":"m","content":"{}"}}]}}"#,
            "x".repeat(512)
        ),
    )
    .unwrap();

    let result = index_file_with_options(
        &pool,
        &file,
        "gemini_session",
        IndexFileOptions {
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 64,
                scan_max_bytes: 64,
                per_source_deadline: std::time::Duration::from_secs(1),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.source_budget_cap_hits, 1);
    assert_eq!(result.ingested, 0);
    let checkpoints = list_checkpoints(&pool, &CheckpointListOptions::default()).unwrap();
    assert_eq!(
        checkpoints.len(),
        1,
        "source registration is not a scan cursor"
    );
    assert_eq!(checkpoints[0].last_offset, Some(0));
    assert_eq!(checkpoints[0].file_size, None);
}

#[test]
#[serial]
fn bounded_discovery_yields_huge_provider_root_to_later_provider_root() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    // The scanner honors an operator-supplied alternate Codex root. Isolate
    // this scheduling test from the developer's real `CODEX_HOME`, whose
    // discovery cost is outside the fixture and would make the elapsed-time
    // assertion non-deterministic.
    let _codex_home = EnvOverride::remove("CODEX_HOME");
    let huge_root = dir.path().join(".claude/projects");
    std::fs::create_dir_all(&huge_root).unwrap();
    for index in 0..=MAX_DISCOVERY_ENTRIES_PER_ROOT {
        std::fs::write(huge_root.join(format!("noise-{index:04}.txt")), "noise").unwrap();
    }
    let deferred_claude = huge_root.join("zz-late-project/session.jsonl");
    std::fs::create_dir_all(deferred_claude.parent().unwrap()).unwrap();
    std::fs::write(
        &deferred_claude,
        r#"{"sessionId":"late-claude","content":"deferred root continuation completed"}"#,
    )
    .unwrap();
    let gemini_root = dir.path().join(".gemini/tmp/hash/chats");
    std::fs::create_dir_all(&gemini_root).unwrap();
    std::fs::write(
        gemini_root.join("session-later-provider.json"),
        r#"{"sessionId":"later-provider","messages":[{"id":"later","content":"later provider discovered despite huge root"}]}"#,
    )
    .unwrap();
    let _delay = SnapshotDelayGuard::for_file("projects", std::time::Duration::from_secs(3));
    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 4_096,
                scan_max_bytes: 16_384,
                per_source_deadline: std::time::Duration::from_millis(25),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.discovery_cap_hits, 1, "result={result:#?}");
    assert_eq!(result.discovery_deferred_roots, 1, "result={result:#?}");
    let mut continuations = result.next_discovery_cursors.clone();
    assert!(
        !continuations.is_empty(),
        "capped discovery records its last visited entry"
    );
    assert!(
        !snapshot_test_delay_completed("projects"),
        "a slow provider-root discovery blocked until the delayed worker completed"
    );
    let later_provider_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'later provider discovered despite huge root'",
            [],
            |row| row.get(0),
    )
    .unwrap();
    assert_eq!(later_provider_rows, 1);

    // Only the first pass models a stalled root. Subsequent incremental work
    // must prove that the recorded entry cursor itself, not another timeout,
    // reaches the deferred descendant.
    drop(_delay);
    std::thread::sleep(std::time::Duration::from_millis(250));
    for _ in 0..4 {
        let pass = index_roots_with_options(
            &pool,
            IndexOptions {
                discovery_start_after: continuations.clone(),
                scan_budget: Some(ScanBudget {
                    per_source_max_bytes: 4_096,
                    scan_max_bytes: 16_384,
                    per_source_deadline: std::time::Duration::from_secs(1),
                }),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let found: i64 = pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE message = 'deferred root continuation completed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if found == 1 {
            break;
        }
        continuations = pass.next_discovery_cursors;
        assert!(
            !continuations.is_empty(),
            "incomplete discovery produces a continuation cursor"
        );
    }
    let continued_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'deferred root continuation completed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        continued_rows, 1,
        "capped root resumes past its prior cursor"
    );
}

#[test]
#[serial]
fn bounded_discovery_retains_continuations_for_multiple_capped_roots() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let _codex_home = EnvOverride::remove("CODEX_HOME");
    let claude_root = dir.path().join(".claude/projects");
    let codex_root = dir.path().join(".codex/sessions");
    for (root, message) in [
        (&claude_root, "claude continuation survives"),
        (&codex_root, "codex continuation survives"),
    ] {
        std::fs::create_dir_all(root).unwrap();
        for index in 0..=MAX_DISCOVERY_ENTRIES_PER_ROOT {
            std::fs::write(root.join(format!("noise-{index:04}.txt")), "noise").unwrap();
        }
        let deferred = root.join("zz-deferred/session.jsonl");
        std::fs::create_dir_all(deferred.parent().unwrap()).unwrap();
        let record = if root == &claude_root {
            format!(r#"{{"sessionId":"late-claude","content":"{message}"}}"#)
        } else {
            format!(r#"{{"type":"response_item","payload":{{"content":"{message}"}}}}"#)
        };
        std::fs::write(deferred, record).unwrap();
    }
    let first = index_roots_with_options(
        &pool,
        IndexOptions {
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 4_096,
                scan_max_bytes: 16_384,
                per_source_deadline: std::time::Duration::from_secs(1),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    // Discovery keys use canonical paths so `/var` and `/private/var` share
    // one cursor on macOS rather than repeatedly scanning the same source.
    let canonical_claude_root = claude_root.canonicalize().unwrap();
    let canonical_codex_root = codex_root.canonicalize().unwrap();
    assert!(
        first
            .next_discovery_cursors
            .contains_key(&canonical_claude_root)
    );
    assert!(
        first
            .next_discovery_cursors
            .contains_key(&canonical_codex_root)
    );

    let mut continuations = first.next_discovery_cursors;
    for _ in 0..4 {
        let pass = index_roots_with_options(
            &pool,
            IndexOptions {
                discovery_start_after: continuations.clone(),
                scan_budget: Some(ScanBudget {
                    per_source_max_bytes: 4_096,
                    scan_max_bytes: 16_384,
                    per_source_deadline: std::time::Duration::from_secs(1),
                }),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let found: i64 = pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE message IN \
                 ('claude continuation survives', 'codex continuation survives')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if found == 2 {
            break;
        }
        continuations = pass.next_discovery_cursors;
        assert!(
            !continuations.is_empty(),
            "incomplete multi-root discovery retains every outstanding cursor"
        );
    }
    let found: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message IN \
             ('claude continuation survives', 'codex continuation survives')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        found, 2,
        "both simultaneously capped roots eventually complete"
    );
}

#[test]
#[serial]
fn bounded_root_scan_yields_from_a_valid_slow_source_to_the_next_source() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let root = dir.path().join(".codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    let slow = root.join("000-slow-codex.jsonl");
    let fast = root.join("999-fast-codex.jsonl");

    let mut slow_records =
        String::from(r#"{"type":"session_meta","payload":{"id":"slow-session"}}"#);
    slow_records.push('\n');
    for record in 0..200 {
        slow_records.push_str(&format!(
            r#"{{"type":"response_item","payload":{{"type":"message","role":"user","content":"slow valid record {record} {}"}}}}"#,
            "x".repeat(160)
        ));
        slow_records.push('\n');
    }
    std::fs::write(&slow, slow_records).unwrap();
    std::fs::write(
        &fast,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"fast-session"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"fast source reached canonical ingestion"}}"#,
            "\n"
        ),
    )
    .unwrap();

    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: Some(root.clone()),
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 1_200,
                scan_max_bytes: 8_000,
                per_source_deadline: std::time::Duration::from_secs(30),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(result.source_budget_cap_hits, 1, "result={result:#?}");
    assert_eq!(result.source_deadline_exceeded, 0);
    assert!(!result.scan_budget_cap_hit);
    let ingested_fast: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'fast source reached canonical ingestion'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        ingested_fast, 1,
        "a valid but byte-capped source must yield before a later valid source is starved"
    );
}

#[test]
#[serial]
fn bounded_root_scan_reports_scan_wide_cap_and_defers_remaining_sources() {
    let (pool, dir) = test_pool();
    let _home = HomeOverride::set(dir.path());
    let root = dir.path().join(".codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    let slow = root.join("000-budget-source.jsonl");
    let deferred = root.join("999-deferred-source.jsonl");
    std::fs::write(
        &slow,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"budget-session"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":""#,
            "x",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "\"}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        &deferred,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"deferred-session"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"must wait for next pass"}}"#,
            "\n"
        ),
    )
    .unwrap();

    let result = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: Some(root.clone()),
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 10_000,
                scan_max_bytes: 120,
                per_source_deadline: std::time::Duration::from_secs(1),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    assert!(result.scan_budget_cap_hit);
    assert_eq!(result.deferred_sources, 1);
    let cursor = result
        .next_scan_cursor
        .clone()
        .expect("a source was attempted before the scan-wide cap");
    let deferred_ingested: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'must wait for next pass'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deferred_ingested, 0);

    let second = index_roots_with_options(
        &pool,
        IndexOptions {
            root_override: Some(root),
            start_after: Some(cursor),
            scan_budget: Some(ScanBudget {
                per_source_max_bytes: 10_000,
                scan_max_bytes: 20_000,
                per_source_deadline: std::time::Duration::from_secs(30),
            }),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert!(second.next_scan_cursor.is_some());
    let deferred_ingested: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'must wait for next pass'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deferred_ingested, 1,
        "the next bounded scan begins after the last attempted source"
    );
}

#[test]
fn oversized_jsonl_source_resumes_from_a_checkpointed_prefix() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("oversized-session.jsonl");
    std::fs::write(
        &file,
        concat!(
            r#"{"sessionId":"s","content":"one"}"#,
            "\n",
            r#"{"sessionId":"s","content":"two"}"#,
            "\n",
            r#"{"sessionId":"s","content":"three"}"#,
            "\n",
            r#"{"sessionId":"s","content":"four"}"#,
            "\n",
            r#"{"sessionId":"s","content":"five"}"#,
            "\n",
            r#"{"sessionId":"s","content":"second bounded chunk becomes visible later"}"#,
            "\n"
        ),
    )
    .unwrap();
    let options = IndexFileOptions {
        scan_budget: Some(ScanBudget {
            per_source_max_bytes: 132,
            scan_max_bytes: 1_000,
            per_source_deadline: std::time::Duration::from_secs(1),
        }),
        ..Default::default()
    };

    let first =
        index_file_with_options(&pool, &file, "explicit_file", options.clone(), None).unwrap();
    assert_eq!(first.source_budget_cap_hits, 1, "result={first:#?}");
    let checkpoint = list_checkpoints(
        &pool,
        &CheckpointListOptions {
            errors_only: false,
            missing_only: false,
            limit: Some(10),
        },
    )
    .unwrap();
    assert!(checkpoint[0].last_offset.unwrap_or_default() > 0);
    assert!(
        checkpoint[0].last_offset.unwrap_or_default() < checkpoint[0].file_size.unwrap_or_default(),
        "partial checkpoints retain full source metadata plus a separate cursor: {checkpoint:#?}"
    );

    // Active transcripts normally grow between bounded passes. An append must
    // preserve the already-imported prefix and continue from its exact line,
    // rather than looking like an in-place rewrite and resetting to byte zero.
    use std::io::Write as _;
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap(),
        r#"{{"sessionId":"s","content":"appended while continuation is pending"}}"#
    )
    .unwrap();

    let mut pass_results = Vec::new();
    for _ in 0..3 {
        let pass =
            index_file_with_options(&pool, &file, "explicit_file", options.clone(), None).unwrap();
        let found: i64 = pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE message = 'second bounded chunk becomes visible later'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if found == 1 {
            break;
        }
        pass_results.push(pass.clone());
        assert_eq!(pass.source_budget_cap_hits, 1, "result={pass:#?}");
    }
    let later_rows: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'second bounded chunk becomes visible later'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        later_rows,
        1,
        "first={first:#?} passes={pass_results:#?} checkpoint={:#?}",
        list_checkpoints(
            &pool,
            &CheckpointListOptions {
                errors_only: false,
                missing_only: false,
                limit: Some(10),
            },
        )
        .unwrap()
    );
    let conn = pool.get().unwrap();
    let first_row_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        first_row_count, 1,
        "append must not delete/replay the prefix"
    );
    let recovered_line_no: i64 = conn
        .query_row(
            "SELECT json_extract(metadata_json, '$.line_no') FROM logs WHERE message = 'second bounded chunk becomes visible later'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        recovered_line_no, 5,
        "metadata retains physical line numbers"
    );
}

#[test]
fn bounded_jsonl_discards_an_oversized_physical_record_across_passes() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("physical-record-boundary.jsonl");
    let trailing = r#"{"sessionId":"later","content":"visible after oversized physical record"}"#;
    std::fs::write(&file, format!("{}\n{trailing}\n", "x".repeat(256))).unwrap();
    let options = IndexFileOptions {
        scan_budget: Some(ScanBudget {
            per_source_max_bytes: 128,
            scan_max_bytes: 1_024,
            per_source_deadline: std::time::Duration::from_secs(1),
        }),
        ..Default::default()
    };

    for _ in 0..16 {
        let result =
            index_file_with_options(&pool, &file, "explicit_file", options.clone(), None).unwrap();
        assert!(
            result.scanned_bytes <= 128,
            "one pass consumed more than its physical allowance: {result:#?}"
        );
        let found: i64 = pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE message = 'visible after oversized physical record'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if found == 1 {
            break;
        }
    }
    let found: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'visible after oversized physical record'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        found, 1,
        "later JSONL records are not stranded by a giant row"
    );
}

fn set_mtime(path: &std::path::Path, secs: u64, nanos: u32) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
        .unwrap();
}

struct HomeOverride(Option<std::ffi::OsString>);

impl HomeOverride {
    fn set(path: &std::path::Path) -> Self {
        let previous = crate::env::var_os("HOME");
        crate::env::set_test_var("HOME", path);
        Self(previous)
    }
}

impl Drop for HomeOverride {
    fn drop(&mut self) {
        if let Some(home) = &self.0 {
            crate::env::set_test_var("HOME", home);
        } else {
            crate::env::remove_test_var("HOME");
        }
    }
}

struct EnvOverride {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvOverride {
    fn remove(key: &'static str) -> Self {
        let previous = crate::env::var_os(key);
        crate::env::remove_test_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            crate::env::set_test_var(self.key, value);
        } else {
            crate::env::remove_test_var(self.key);
        }
    }
}

struct CurrentDirGuard(std::path::PathBuf);

impl CurrentDirGuard {
    fn set(path: &std::path::Path) -> Self {
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self(previous)
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).unwrap();
    }
}

#[test]
fn index_roots_reports_file_errors_with_paths() {
    let (pool, dir) = test_pool();
    let target = dir.path().join("target.jsonl");
    let link = dir.path().join("bad.jsonl");
    std::fs::write(&target, "{\"sessionId\":\"sess-1\",\"content\":\"hi\"}\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = index_roots(&pool, Some(dir.path())).unwrap();
    assert_eq!(result.skipped_files, 1);
    assert_eq!(result.skipped_symlinks, 1);
    assert_eq!(result.file_errors.len(), 1);
    assert!(result.file_errors[0].path.contains("bad.jsonl"));
    assert!(result.file_errors[0].error.contains("symlinks"));
}

#[test]
fn index_roots_skips_unreadable_directories_and_continues() {
    use std::os::unix::fs::PermissionsExt;

    let (pool, dir) = test_pool();
    let good = dir.path().join("good.jsonl");
    let blocked = dir.path().join("blocked");
    std::fs::write(
        &good,
        "{\"sessionId\":\"sess-1\",\"content\":\"rust mention\"}\n",
    )
    .unwrap();
    std::fs::create_dir(&blocked).unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let result = index_roots(&pool, Some(dir.path()));

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();

    let result = result.expect("unreadable directories should be skipped, not abort indexing");
    assert_eq!(result.ingested, 1);
    assert_eq!(result.skipped_files, 1);
    assert_eq!(result.file_errors.len(), 1);
    assert!(
        result.file_errors[0]
            .error
            .to_ascii_lowercase()
            .contains("permission denied")
    );
}

#[test]
fn gemini_reindex_skips_existing_and_ingests_appended_messages() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session-gemini.json");
    std::fs::write(
        &file,
        r#"{"sessionId":"g","startTime":"2026-04-02T22:02:55.537Z","messages":[
            {"id":"m1","timestamp":"2026-04-02T22:03:00.000Z","content":"first"},
            {"id":"m2","timestamp":"2026-04-02T22:03:01.000Z","content":"second"}
        ]}"#,
    )
    .unwrap();

    let first = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(first.ingested, 2);
    assert_eq!(first.parse_errors, 0);

    // Append a third message; the size changes so the whole file is re-read and
    // dedup must skip the two already-imported records.
    std::fs::write(
        &file,
        r#"{"sessionId":"g","startTime":"2026-04-02T22:02:55.537Z","messages":[
            {"id":"m1","timestamp":"2026-04-02T22:03:00.000Z","content":"first"},
            {"id":"m2","timestamp":"2026-04-02T22:03:01.000Z","content":"second"},
            {"id":"m3","timestamp":"2026-04-02T22:03:02.000Z","content":"third"}
        ]}"#,
    )
    .unwrap();

    let second = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(second.ingested, 1, "only the appended message is new");
    assert_eq!(
        second.skipped_dupes, 2,
        "existing messages dedup by record_key on re-read"
    );

    let log_count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(log_count, 3, "no duplicate rows across re-index");
}

#[test]
fn gemini_bad_timestamp_skips_record_keeps_others_and_records_error() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session-bad-ts.json");
    std::fs::write(
        &file,
        r#"{"sessionId":"g","messages":[
            {"id":"good","timestamp":"2026-04-02T22:03:00.000Z","content":"good record"},
            {"id":"bad","timestamp":"not-a-timestamp","content":"bad record"}
        ]}"#,
    )
    .unwrap();

    let result = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(result.ingested, 1, "the good record is still ingested");
    assert_eq!(
        result.parse_errors, 1,
        "one bad timestamp is a per-record parse error, not a whole-file abort"
    );

    let log_count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(log_count, 1);

    // The failure is observable to the AI doctor: a recorded parse error and a
    // source-level last_error.
    let parse_errors: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM transcript_parse_errors", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(parse_errors, 1);
    let source_errors: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM transcript_sources WHERE last_error IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(source_errors, 1);

    // The file is not checkpointed clean: a re-index retries the bad record
    // while the good one dedups — no data lost, failure still surfaced.
    let second = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(second.ingested, 0);
    assert_eq!(second.skipped_dupes, 1);
    assert_eq!(second.parse_errors, 1);
}

#[test]
fn gemini_missing_messages_array_records_parse_error() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("session-drift.json");
    std::fs::write(
        &file,
        r#"{"sessionId":"g","history":[{"content":"renamed key"}]}"#,
    )
    .unwrap();

    let result = index_file(&pool, &file, "gemini_session").unwrap();
    assert_eq!(result.ingested, 0);
    assert_eq!(
        result.parse_errors, 1,
        "a chat file with no messages array is recorded as a parse error"
    );
    assert_eq!(result.discovered_files, 1);

    let source_errors: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM transcript_sources WHERE last_error LIKE '%messages%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        source_errors, 1,
        "missing messages array surfaces as a recorded source error, not a clean checkpoint"
    );
}

#[test]
fn indexing_claude_transcript_extracts_skill_events() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("claude-skill.jsonl");
    std::fs::write(
        &file,
        concat!(
            r#"{"sessionId":"sess-1","attributionSkill":"cortex-troubleshoot","attributionPlugin":"cortex","content":"ran troubleshoot"}"#,
            "\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "explicit_file").unwrap();
    assert_eq!(result.ingested, 1);

    let conn = pool.get().unwrap();
    let (skill_name, plugin, event_kind): (String, Option<String>, String) = conn
        .query_row(
            "SELECT skill_name, skill_plugin, event_kind FROM ai_skill_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(skill_name, "cortex-troubleshoot");
    assert_eq!(plugin.as_deref(), Some("cortex"));
    assert_eq!(event_kind, "claude_attribution");
}

#[test]
fn indexing_codex_transcript_extracts_skill_events() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("codex-skill.jsonl");
    std::fs::write(
        &file,
        concat!(
            r#"{"type":"response_item","payload":{"type":"message","content":"<skill><name>rustarr</name></skill> deploying now"},"timestamp":"2026-06-01T00:00:00Z"}"#,
            "\n"
        ),
    )
    .unwrap();

    let result = index_file(&pool, &file, "codex_session").unwrap();
    assert_eq!(result.ingested, 1);

    let conn = pool.get().unwrap();
    let (skill_name, event_kind): (String, String) = conn
        .query_row(
            "SELECT skill_name, event_kind FROM ai_skill_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(skill_name, "rustarr");
    assert_eq!(event_kind, "codex_skill_block");
}

#[test]
fn reindexing_same_transcript_does_not_duplicate_skill_events() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("claude-skill-idem.jsonl");
    std::fs::write(
        &file,
        concat!(
            r#"{"sessionId":"sess-1","attributionSkill":"cortex","content":"hi"}"#,
            "\n"
        ),
    )
    .unwrap();

    index_file(&pool, &file, "explicit_file").unwrap();
    let forced = index_file_with_options(
        &pool,
        &file,
        "explicit_file",
        IndexFileOptions {
            force: true,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(forced.ingested, 1);

    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ai_skill_events", [], |row| row.get(0))
        .unwrap();
    // force=true re-inserts the logs row (new log_id), so the skill event
    // row is NOT a duplicate by the UNIQUE(log_id, ...) constraint — it is
    // correctly re-created against the new log_id. This asserts the count
    // tracks 1-per-logs-row rather than silently growing unbounded on
    // ordinary (non-forced) re-scans, which is covered by the next test.
    assert_eq!(count, 1);
}

#[test]
fn transcript_row_with_no_skill_reference_creates_no_skill_event() {
    let (pool, dir) = test_pool();
    let file = dir.path().join("no-skill.jsonl");
    std::fs::write(
        &file,
        "{\"sessionId\":\"sess-1\",\"content\":\"just chatting\"}\n",
    )
    .unwrap();

    index_file(&pool, &file, "explicit_file").unwrap();

    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ai_skill_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn end_to_end_ingest_then_backfill_is_idempotent_across_both_paths() {
    // Codex row: `logs.message` for a Codex row IS the scannable transcript
    // text (the `<skill><name>` regex reads it directly), so it stays intact
    // through `scrub_ai_message` and remains recoverable by the backfill's
    // `row.message` re-scan. Claude rows are different: `logs.message` is
    // `extract_message`'s plain-text `content` extraction (e.g. "hi"), which
    // NEVER contains the raw `attributionSkill` JSON field. The backfill
    // recovers Claude rows instead by re-reading the source transcript file
    // via the persisted `ai_transcript_path` column and the `line_no`
    // recorded in `metadata_json` at ingest time — see
    // `src/app/services/skill_backfill.rs`'s module doc comment.
    let (pool, dir) = test_pool();

    // Row 1 (Codex, ingested normally): picks up the skill event via
    // flush_chunk at ingest time.
    let codex_file = dir.path().join("codex.jsonl");
    std::fs::write(
        &codex_file,
        concat!(
            r#"{"type":"response_item","payload":{"type":"message","content":"<skill><name>rustarr</name></skill> deploying"},"timestamp":"2026-06-01T00:00:00Z"}"#,
            "\n"
        ),
    )
    .unwrap();
    index_file(&pool, &codex_file, "codex_session").unwrap();

    // Row 2 (Codex, pre-existing/legacy): inserted directly into `logs`
    // bypassing the scanner entirely, simulating a Codex transcript row
    // ingested BEFORE this phase shipped. Codex's `message` column already
    // holds the raw transcript text (never JSON-extracted away), so a
    // pre-existing Codex row's skill tag is recoverable straight from
    // `logs.message` via backfill.
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip, ai_tool, ai_project, ai_session_id)
             VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', ?1, ?1, 'transcript://codex_session', 'codex', 'cortex', 'sess-2')",
            rusqlite::params!["<skill><name>web-app-testing</name></skill> testing now"],
        )
        .unwrap();
    }

    // Row 3 (Claude, ingested normally): picks up the skill event via
    // flush_chunk at ingest time, same as row 1.
    let claude_file = dir.path().join("claude.jsonl");
    std::fs::write(
        &claude_file,
        concat!(
            r#"{"sessionId":"sess-3","attributionSkill":"cortex-troubleshoot","attributionPlugin":"cortex","content":"ran troubleshoot"}"#,
            "\n"
        ),
    )
    .unwrap();
    index_file(&pool, &claude_file, "explicit_file").unwrap();

    // Row 4 (Claude, pre-existing/legacy): inserted directly into `logs`
    // with a real `ai_transcript_path` + `metadata_json.line_no` pointing at
    // a source file on disk, simulating a row ingested before this phase's
    // ingest-time skill extraction existed but whose transcript file is
    // still present — exactly the case the backfill's file re-read recovers.
    let legacy_claude_file = dir.path().join("legacy-claude.jsonl");
    std::fs::write(
        &legacy_claude_file,
        concat!(
            r#"{"sessionId":"sess-4","attributionSkill":"cortex-report","content":"ran report"}"#,
            "\n"
        ),
    )
    .unwrap();
    {
        let conn = pool.get().unwrap();
        let metadata_json = serde_json::json!({ "line_no": 0 }).to_string();
        conn.execute(
            "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip, ai_tool, ai_project, ai_session_id, ai_transcript_path, metadata_json)
             VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', 'ran report', 'ran report', 'transcript://claude_project', 'claude', 'cortex', 'sess-4', ?1, ?2)",
            rusqlite::params![legacy_claude_file.to_string_lossy().to_string(), metadata_json],
        )
        .unwrap();
    }

    let conn = pool.get().unwrap();
    let pre_backfill_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ai_skill_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        pre_backfill_count, 2,
        "only the scanner-ingested rows (1 and 3) should have a skill event pre-backfill"
    );
    drop(conn);

    // Backfill catches the pre-existing rows 2 and 4 without duplicating
    // rows 1 and 3's events.
    let service = crate::app::CortexService::new(
        std::sync::Arc::new(pool.clone()),
        StorageConfig::for_test(dir.path().join("unused.db")),
    );
    let result = service
        .backfill_skill_events(crate::app::SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();
    assert_eq!(result.scanned, 4, "all four rows should be scanned");
    assert_eq!(result.inserted, 2, "rows 2 and 4's events are new");
    assert_eq!(
        result.skipped_duplicates, 2,
        "rows 1 and 3's events were already present from ingest-time extraction"
    );
    assert_eq!(result.source_unavailable, 0);
    assert_eq!(result.parse_errors, 0);

    let conn = pool.get().unwrap();
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM ai_skill_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total, 4);
    drop(conn);

    // Running backfill again is fully idempotent.
    let second = service
        .backfill_skill_events(crate::app::SkillBackfillRequest {
            since: None,
            limit: Some(100),
            dry_run: false,
        })
        .await
        .unwrap();
    assert_eq!(second.inserted, 0);
    assert_eq!(second.skipped_duplicates, 4);
}

#[test]
fn read_transcript_lines_recovers_requested_lines_and_skips_oversized() {
    // Exercises the shared bounded-read helper the skill-event backfill uses to
    // recover Claude rows: requested 0-based lines are returned with trailing
    // newlines trimmed, a line exceeding MAX_RECORD_SIZE_BYTES is omitted (not
    // read unbounded into memory), line_no counting stays aligned across the
    // oversized line, and a request beyond EOF is simply absent.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transcript.jsonl");
    let oversized = "x".repeat(MAX_RECORD_SIZE_BYTES + 16);
    let contents = format!("line-zero\n{oversized}\nline-two\n");
    std::fs::write(&path, contents).unwrap();

    // Want every line plus one past EOF.
    let wanted: HashSet<usize> = [0usize, 1, 2, 3].into_iter().collect();
    let got = read_transcript_lines(&path, &wanted).unwrap();

    assert_eq!(got.get(&0).map(String::as_str), Some("line-zero"));
    assert_eq!(got.get(&2).map(String::as_str), Some("line-two"));
    // Oversized line 1 is skipped rather than buffered into memory.
    assert!(!got.contains_key(&1), "oversized line must be omitted");
    // Line 3 is beyond EOF.
    assert!(!got.contains_key(&3), "out-of-range line must be omitted");
    assert_eq!(got.len(), 2);
}

#[test]
fn session_metadata_scrubbing_neutralizes_terminal_controls_and_bounds_labels() {
    let metadata = TranscriptSessionMetadata {
        title: Some(format!("safe\u{1b}[31m title\nnext {}", "x".repeat(600))),
        title_provenance: Some("provider\r\nspoofed".to_string()),
        ..Default::default()
    }
    .scrubbed();

    let title = metadata.title.expect("safe title should be retained");
    let provenance = metadata
        .title_provenance
        .expect("safe provenance should be retained");
    assert!(!title.chars().any(char::is_control));
    assert!(!provenance.chars().any(char::is_control));
    assert!(title.chars().count() <= MAX_SESSION_METADATA_CHARS);
    assert!(provenance.contains("provider  spoofed"));
}

#[test]
fn session_metadata_scrubbing_drops_control_only_labels() {
    let metadata = TranscriptSessionMetadata {
        title: Some("\u{1b}\n\r".to_string()),
        title_provenance: Some("\t".to_string()),
        ..Default::default()
    }
    .scrubbed();

    assert!(metadata.title.is_none());
    assert!(metadata.title_provenance.is_none());
}
