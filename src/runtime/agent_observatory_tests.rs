use super::*;
use crate::db::agent_observatory::{
    advance_projection_cursor, projection_cursor, projection_health,
};
use crate::db::{LogBatchEntry, insert_logs_batch};

/// More than one connection on purpose. `StorageConfig::for_test` defaults to
/// `pool_size: 1`, which was survivable only while the projector ran its DB
/// work on the same runtime thread as the test body — the two could never be
/// in the pool at once. Now that each cycle runs on `spawn_blocking`, a test
/// polling `projection_health` and a projector mid-cycle are genuinely
/// concurrent, and on a one-connection pool they starve each other until one
/// hits the r2d2 connection timeout.
fn pool() -> (tempfile::TempDir, Arc<DbPool>) {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = crate::config::StorageConfig::for_test(directory.path().join("runtime.db"));
    storage.pool_size = 4;
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    (directory, pool)
}

#[test]
fn projector_sqlite_retry_backoff_reuses_ingest_policy_and_caps() {
    assert_eq!(projector_retry_delay_ms(1), 25);
    assert_eq!(projector_retry_delay_ms(2), 100);
    assert_eq!(projector_retry_delay_ms(3), 250);
    assert_eq!(projector_retry_delay_ms(4), 250);
    assert_eq!(projector_retry_delay_ms(100), 250);
}

#[test]
fn workers_stay_dormant_when_agent_observatory_is_disabled() {
    let (_directory, pool) = pool();
    let config = AgentObservatoryConfig::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(
            spawn_projector(CancellationToken::new(), Arc::clone(&pool), config.clone()).is_none()
        );
        assert!(spawn_git_reconcile(CancellationToken::new(), pool, config).is_none());
    });
}

#[test]
fn enabled_projector_advances_durable_log_cursor_and_shuts_down() {
    let (_directory, pool) = pool();
    pool.get()
        .unwrap()
        .execute(
            "INSERT INTO logs
            (timestamp, hostname, facility, severity, app_name, message, raw, received_at, source_ip)
         VALUES (?1, 'test-host', 1, 6, 'unrelated', 'bounded test row', 'bounded test row', ?1, '127.0.0.1')",
            ["2026-08-09T12:00:00.000Z"],
        )
        .unwrap();
    let config = AgentObservatoryConfig {
        enabled: true,
        projector_poll_ms: 10,
        projector_page_bytes: 1,
        ..AgentObservatoryConfig::default()
    };
    let token = CancellationToken::new();
    // Multi-threaded on purpose: the projector now hands each cycle to
    // `spawn_blocking`, so progress needs a worker free to poll it while this
    // test's own synchronous DB calls occupy a thread. On a current-thread
    // runtime the two starve each other under suite load.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let handle = spawn_projector(token.clone(), Arc::clone(&pool), config).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if projection_cursor(&pool, "logs").unwrap() == "1" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        for source in [
            "mcp_events",
            "hook_events",
            "skill_events",
            "llm_invocations",
        ] {
            assert_eq!(projection_cursor(&pool, source).unwrap(), "");
        }
        // Assert the field reaches the health row, not the value it held on one
        // particular cycle. `oversized_first_rows=1` is true only for the cycle
        // that projects the row: the next cycle finds the cursor advanced,
        // counts zero, and overwrites the single health record. Polling for
        // that value is a race against a window a few milliseconds wide, and
        // the projector's own wake notification makes the overwrite immediate.
        // The count itself is pinned deterministically by
        // `projection_cycle_counts_an_oversized_first_row`, which calls the
        // cycle directly.
        //
        // Parallel DB tests share Cortex's process-wide SQLite write lock; under
        // suite load health persistence can legitimately queue behind other writers.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if projection_health(&pool, "projector")
                    .unwrap()
                    .is_some_and(|health| health.contains("oversized_first_rows="))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
    });
}

/// A first row larger than the whole byte budget is projected anyway and
/// counted, rather than stalling the cursor forever behind a row that can never
/// fit. Calling the cycle directly makes this deterministic; observing it
/// through the health row cannot be, because the next cycle overwrites it.
#[test]
fn projection_cycle_counts_an_oversized_first_row() {
    let (_directory, pool) = pool();
    pool.get()
        .unwrap()
        .execute(
            "INSERT INTO logs
            (timestamp, hostname, facility, severity, app_name, message, raw, received_at, source_ip)
         VALUES (?1, 'test-host', 1, 6, 'unrelated', 'bounded test row', 'bounded test row', ?1, '127.0.0.1')",
            ["2026-08-09T12:00:00.000Z"],
        )
        .unwrap();

    let cycle = run_projection_cycle(
        &pool,
        ProjectionLimits {
            // Log backfill may use a wider page than the 500-row source
            // tables; the cycle must clamp those readers independently.
            page_rows: 2_000,
            page_bytes: 1,
        },
    );

    assert_eq!(cycle.oversized_first_rows, 1);
    assert_eq!(cycle.projected, 1);
    assert!(cycle.healthy);
    assert!(!cycle.had_error);
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "1");

    // Drained: the next cycle finds nothing oversized, which is why the health
    // row cannot be polled for the count above.
    let drained = run_projection_cycle(
        &pool,
        ProjectionLimits {
            page_rows: 2_000,
            page_bytes: 1,
        },
    );
    assert_eq!(drained.oversized_first_rows, 0);
    assert_eq!(drained.projected, 0);
}

#[test]
fn projector_wakes_on_committed_log_ingest_before_fallback_poll() {
    let (_directory, pool) = pool();
    let config = AgentObservatoryConfig {
        enabled: true,
        projector_poll_ms: 60_000,
        ..AgentObservatoryConfig::default()
    };
    let token = CancellationToken::new();
    // Multi-threaded on purpose: the projector now hands each cycle to
    // `spawn_blocking`, so progress needs a worker free to poll it while this
    // test's own synchronous DB calls occupy a thread. On a current-thread
    // runtime the two starve each other under suite load.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let handle = spawn_projector(token.clone(), Arc::clone(&pool), config).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if projection_health(&pool, "projector").unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();

        insert_logs_batch(
            &pool,
            &[LogBatchEntry {
                timestamp: "2026-08-09T12:00:00.000Z".to_string(),
                hostname: "test-host".to_string(),
                facility: None,
                severity: "info".to_string(),
                app_name: Some("wake-test".to_string()),
                process_id: None,
                message: "wake test row".to_string(),
                raw: "wake test row".to_string(),
                source_ip: "test://wake".to_string(),
                docker_checkpoint: None,
                ai_tool: None,
                ai_project: None,
                ai_session_id: None,
                ai_transcript_path: None,
                metadata_json: None,
                http_status: None,
                auth_outcome: None,
                dns_blocked: None,
                event_action: None,
                parse_error: None,
            }],
        )
        .unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if projection_cursor(&pool, "logs").unwrap() == "1" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("committed ingest should wake projector without waiting for fallback poll");

        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
    });
}

#[test]
fn enabled_git_worker_records_progress_and_shuts_down() {
    let (directory, pool) = pool();
    let repository = directory.path().join("repo");
    std::fs::create_dir(&repository).unwrap();
    crate::env::command("git")
        .args(["init", "-q"])
        .current_dir(&repository)
        .status()
        .unwrap();
    crate::env::command("git")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "--allow-empty",
            "-qm",
            "initial",
        ])
        .current_dir(&repository)
        .status()
        .unwrap();
    let config = AgentObservatoryConfig {
        enabled: true,
        git: crate::config::AgentObservatoryGitConfig {
            roots: vec![repository.display().to_string()],
            reconcile_interval_secs: 60,
            ..crate::config::AgentObservatoryGitConfig::default()
        },
        ..AgentObservatoryConfig::default()
    };
    let token = CancellationToken::new();
    // Multi-threaded on purpose: the projector now hands each cycle to
    // `spawn_blocking`, so progress needs a worker free to poll it while this
    // test's own synchronous DB calls occupy a thread. On a current-thread
    // runtime the two starve each other under suite load.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let handle = spawn_git_reconcile(token.clone(), Arc::clone(&pool), config).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if !projection_cursor(&pool, "git").unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
    });
}

#[test]
fn projector_failure_is_queryable_retries_without_advancing_and_stops_after_cancel() {
    let (_directory, pool) = pool();
    projection_cursor(&pool, "logs").unwrap();
    advance_projection_cursor(&pool, "logs", "invalid").unwrap();
    let config = AgentObservatoryConfig {
        enabled: true,
        projector_poll_ms: 10,
        ..AgentObservatoryConfig::default()
    };
    let token = CancellationToken::new();
    // Multi-threaded on purpose: the projector now hands each cycle to
    // `spawn_blocking`, so progress needs a worker free to poll it while this
    // test's own synchronous DB calls occupy a thread. On a current-thread
    // runtime the two starve each other under suite load.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let handle = spawn_projector(token.clone(), Arc::clone(&pool), config).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let health = projection_health(&pool, "projector")
                    .unwrap()
                    .unwrap_or_default();
                if health.contains("\"status\":\"error\"") && health.contains("\"attempts\":2") {
                    assert!(health.contains("retry_safe=false"));
                    assert!(health.contains("retry_delay_ms=0"));
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(projection_cursor(&pool, "logs").unwrap(), "invalid");
        token.cancel();
        tokio::time::timeout(Duration::from_secs(15), handle)
            .await
            .unwrap()
            .unwrap();
        let stopped = projection_health(&pool, "projector").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(projection_health(&pool, "projector").unwrap(), stopped);
    });
}
