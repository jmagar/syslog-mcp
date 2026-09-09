use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

#[test]
fn pending_files_deduplicate_and_requeue_with_cap() {
    let start = Instant::now();
    let path = PathBuf::from("/tmp/session.jsonl");
    let mut pending = PendingFiles::default();
    assert!(pending.push(path.clone(), start));
    assert!(pending.push(path.clone(), start + Duration::from_millis(25)));

    assert_eq!(pending.files.len(), 1);
    assert!(
        pending
            .debounced_paths(
                start + Duration::from_millis(100),
                Duration::from_millis(200)
            )
            .is_empty()
    );
    assert_eq!(
        pending.debounced_paths(
            start + Duration::from_millis(300),
            Duration::from_millis(200)
        ),
        vec![path.clone()]
    );
    assert!(pending.requeue(path.clone(), start + Duration::from_millis(301), 1));
    assert!(!pending.requeue(path, start + Duration::from_millis(302), 1));
}

#[test]
fn pending_files_wait_until_file_is_stable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("session.jsonl");
    std::fs::write(&path, "{}\n").unwrap();

    let start = Instant::now();
    let mut pending = PendingFiles::default();
    assert!(pending.push(path.clone(), start));

    assert_eq!(
        pending
            .stable(&path, start, Duration::from_millis(100))
            .unwrap(),
        PendingState::NotReady
    );
    assert_eq!(
        pending
            .stable(
                &path,
                start + Duration::from_millis(50),
                Duration::from_millis(100)
            )
            .unwrap(),
        PendingState::NotReady
    );
    assert_eq!(
        pending
            .stable(
                &path,
                start + Duration::from_millis(150),
                Duration::from_millis(100)
            )
            .unwrap(),
        PendingState::Stable
    );
    assert_eq!(pending.files.get(&path).unwrap().retries, 0);
}

#[test]
fn pending_files_drops_terminal_paths() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("deleted.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    let start = Instant::now();
    let mut pending = PendingFiles::default();
    assert!(pending.push(path.clone(), start));
    std::fs::remove_file(&path).unwrap();

    assert_eq!(
        pending
            .stable(
                &path,
                start + Duration::from_millis(1),
                Duration::from_millis(1)
            )
            .unwrap(),
        PendingState::Terminal
    );
}

#[test]
fn pending_files_enforces_capacity() {
    let start = Instant::now();
    let mut pending = PendingFiles::default();
    for index in 0..MAX_PENDING_FILES {
        assert!(pending.push(PathBuf::from(format!("/tmp/{index}.jsonl")), start));
    }
    assert!(!pending.push(PathBuf::from("/tmp/overflow.jsonl"), start));
}

#[test]
fn collect_watch_dirs_includes_accessible_directories_without_file_recursion() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("project");
    std::fs::create_dir(&nested).unwrap();
    let file = nested.join("session.jsonl");
    std::fs::write(&file, "{}\n").unwrap();

    let dirs = collect_watch_dirs(temp.path()).unwrap();

    assert!(dirs.contains(&temp.path().to_path_buf()));
    assert!(dirs.contains(&nested));
    assert!(!dirs.contains(&file));
}

#[test]
fn collect_watch_dirs_skips_build_artifact_directories() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join(".codex/worktrees/session-id/lab");
    let target = project.join("target/debug/.fingerprint/package");
    let node_modules = project.join("node_modules/package");
    let cache = project.join(".cache/cargo/release/deps/rustc123");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&node_modules).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(project.join("rollout-session.jsonl"), "{}\n").unwrap();

    let dirs = collect_watch_dirs(temp.path()).unwrap();

    assert!(dirs.contains(&project));
    assert!(!dirs.iter().any(|dir| dir.ends_with("target")));
    assert!(
        !dirs
            .iter()
            .any(|dir| dir.to_string_lossy().contains("/target/"))
    );
    assert!(!dirs.iter().any(|dir| dir.ends_with("node_modules")));
    assert!(
        !dirs
            .iter()
            .any(|dir| dir.to_string_lossy().contains("/node_modules/"))
    );
    assert!(!dirs.iter().any(|dir| dir.ends_with(".cache")));
    assert!(
        !dirs
            .iter()
            .any(|dir| dir.to_string_lossy().contains("/.cache/"))
    );
}

#[test]
fn collect_watch_dirs_skips_missing_root() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");

    let dirs = collect_watch_dirs(&missing).unwrap();

    assert!(dirs.is_empty());
}

#[cfg(unix)]
#[test]
fn collect_watch_dirs_skips_unreadable_nested_directory() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let blocked = temp.path().join("blocked");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let dirs = collect_watch_dirs(temp.path()).unwrap();

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(dirs.contains(&temp.path().to_path_buf()));
    assert!(!dirs.contains(&blocked));
}

#[test]
fn exact_file_watch_target_rejects_sibling_events() {
    let temp = tempfile::tempdir().unwrap();
    let watched = temp.path().join("watched.jsonl");
    let sibling = temp.path().join("sibling.jsonl");
    std::fs::write(&watched, "{}\n").unwrap();
    std::fs::write(&sibling, "{}\n").unwrap();

    let targets = watch_targets(&test_watch_options(watched.clone())).unwrap();

    assert!(event_path_allowed(&watched, &targets));
    assert!(!event_path_allowed(&sibling, &targets));
}

#[test]
fn watch_targets_rejects_broad_current_directory() {
    let err = watch_targets(&test_watch_options(std::env::current_dir().unwrap())).unwrap_err();

    assert!(err.to_string().contains("unsafe transcript scan path"));
}

#[test]
fn remove_event_drops_pending_file_and_requests_checkpoint_prune() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("session.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    let targets = vec![WatchTarget::Directory(temp.path().canonicalize().unwrap())];
    let mut pending = PendingFiles::default();
    assert!(pending.push(path.clone(), Instant::now()));
    std::fs::remove_file(&path).unwrap();
    let overflow_rescan = std::sync::atomic::AtomicBool::new(false);
    let prune_missing = std::sync::atomic::AtomicBool::new(false);
    let event = notify::Event::new(notify::EventKind::Remove(notify::event::RemoveKind::File))
        .add_path(path.clone());

    let new_dirs = handle_event(
        Ok(event),
        &targets,
        &mut pending,
        &overflow_rescan,
        &prune_missing,
    );

    assert!(new_dirs.is_empty());
    assert!(pending.files.is_empty());
    assert!(!overflow_rescan.load(std::sync::atomic::Ordering::Relaxed));
    assert!(prune_missing.load(std::sync::atomic::Ordering::Relaxed));
}

#[cfg(target_os = "macos")]
#[test]
fn removed_event_under_var_alias_matches_canonical_watch_root() {
    let temp = tempfile::tempdir_in("/var/tmp").unwrap();
    let path = temp.path().join("removed.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    let targets = vec![WatchTarget::Directory(temp.path().canonicalize().unwrap())];
    std::fs::remove_file(&path).unwrap();

    assert!(path.starts_with("/var"));
    assert!(event_path_allowed_missing_ok(&path, &targets));
}

#[test]
fn overflow_rescan_since_uses_recent_safety_window() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800);

    assert_eq!(
        overflow_rescan_since(now),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_500)
    );
}

#[test]
fn overflow_rescan_since_saturates_at_epoch() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(30);

    assert_eq!(overflow_rescan_since(now), SystemTime::UNIX_EPOCH);
}

#[test]
fn bounded_rescan_deferral_requests_the_existing_retry_path() {
    let result = IndexResult {
        scan_budget_cap_hit: true,
        deferred_sources: 2,
        ..Default::default()
    };

    assert_eq!(rescan_status_for_result(&result), RescanStatus::Retry);
    assert_eq!(
        rescan_status_for_result(&IndexResult::default()),
        RescanStatus::Completed
    );
}

#[test]
fn rescan_cursor_advances_only_after_an_attempted_source() {
    let mut cursor = RescanCursor::default();
    let no_attempt = IndexResult::default();
    if let Some(next) = no_attempt.next_scan_cursor.clone() {
        cursor.start_after = Some(next);
    }
    assert!(cursor.start_after.is_none());

    let attempted = IndexResult {
        next_scan_cursor: Some(PathBuf::from("/safe/root/b.jsonl")),
        ..Default::default()
    };
    if let Some(next) = attempted.next_scan_cursor.clone() {
        cursor.start_after = Some(next);
    }
    assert_eq!(
        cursor.start_after,
        Some(PathBuf::from("/safe/root/b.jsonl"))
    );
}

#[test]
fn bounded_backlog_continuation_drops_overflow_since_filter_until_cursor_clears() {
    let old_overflow_filter = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500);
    let mut cursor = RescanCursor {
        start_after: Some(PathBuf::from("/safe/root/deferred-old.jsonl")),
        ..Default::default()
    };

    assert_eq!(
        rescan_since_for_cursor(Some(old_overflow_filter), &cursor),
        None,
        "an old deferred source must not be skipped by a new five-minute lookback"
    );

    cursor.start_after = None;
    cursor.discovery_start_after.insert(
        PathBuf::from("/safe/root/.claude/projects"),
        PathBuf::from("/safe/root/.claude/projects/entry"),
    );
    assert_eq!(
        rescan_since_for_cursor(Some(old_overflow_filter), &cursor),
        None,
        "a bounded provider-root continuation also keeps the backlog unfiltered"
    );

    cursor.discovery_start_after.clear();
    assert_eq!(
        rescan_since_for_cursor(Some(old_overflow_filter), &cursor),
        Some(old_overflow_filter),
        "a fresh overflow rescan keeps its lookback after backlog completion"
    );
}

#[test]
fn system_time_to_rfc3339_is_parseable_by_cortex_time_parser() {
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800);

    assert_eq!(
        system_time_to_rfc3339(time),
        "1970-01-01T00:30:00.000000000Z"
    );
}

fn test_watch_options(path: PathBuf) -> WatchOptions {
    WatchOptions {
        path: Some(path),
        debounce: Duration::from_millis(1),
        settle: Duration::from_millis(1),
        max_retries: 1,
        initial_scan: false,
        json: false,
    }
}
