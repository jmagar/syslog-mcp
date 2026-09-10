use std::sync::Arc;

use super::*;
use crate::config::StorageConfig;

fn service() -> (tempfile::TempDir, CortexService) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("observatory.db"));
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    (dir, CortexService::new(pool, storage))
}

#[tokio::test]
async fn invalid_filters_fail_before_database_reads() {
    let (_dir, service) = service();
    let error = service
        .observatory_runs(
            ao::AgentRunQuery {
                statuses: vec!["active".into(); MAX_FILTER_VALUES + 1],
                ..Default::default()
            },
            None,
            10,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ServiceError::InvalidInput(ref value) if value == "invalid_statuses"));

    let error = service
        .observatory_events(
            "run".into(),
            ao::AgentEventQuery {
                severity_min: Some(8),
                ..Default::default()
            },
            None,
            10,
            false,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ServiceError::InvalidInput(ref value) if value == "invalid_severity_min")
    );

    let error = service
        .observatory_telemetry(
            "run".into(),
            ao::TelemetryQuery {
                since_nano: Some(2),
                until_nano: Some(1),
                ..Default::default()
            },
            None,
            None,
            10,
            10,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ServiceError::InvalidInput(ref value) if value == "invalid_nano_range")
    );

    for query in [
        ao::AgentRunQuery {
            repository_id: Some(0),
            ..Default::default()
        },
        ao::AgentRunQuery {
            worktree_id: Some(-1),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            service.observatory_runs(query, None, 10).await,
            Err(ServiceError::InvalidInput(_))
        ));
    }
}

#[tokio::test]
async fn repository_cursor_keeps_original_high_water_snapshot() {
    let (_dir, service) = service();
    let pool = service.pool_for_test();
    for (key, seen) in [("a", "2026-08-21T10:00:00Z"), ("b", "2026-08-21T11:00:00Z")] {
        pool.get().unwrap().execute("INSERT INTO repositories(repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at) VALUES(?1,'host','/'||?1||'/git','/'||?1,?1,?2,?2)", rusqlite::params![key, seen]).unwrap();
    }
    let first = service
        .observatory_repositories(Default::default(), None, 1)
        .await
        .unwrap();
    let cursor = first.pagination.next_cursor.unwrap();
    pool.get().unwrap().execute("INSERT INTO repositories(repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at) VALUES('new','host','/new/git','/new','new','2026-08-21T12:00:00Z','2026-08-21T12:00:00Z')", []).unwrap();
    let second = service
        .observatory_repositories(Default::default(), Some(cursor), 1)
        .await
        .unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|r| r.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a"]
    );
}

#[tokio::test]
async fn events_distinguish_unknown_run_from_known_run_without_events() {
    let (_dir, service) = service();
    let events = |run_key: &str| {
        service.observatory_events(run_key.into(), Default::default(), None, 10, false)
    };
    let error = events("missing").await.unwrap_err();
    assert!(matches!(error, ServiceError::NotFound(ref value) if value == "run_not_found"));

    service.pool_for_test().get().unwrap().execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('quiet','session','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let page = events("quiet").await.unwrap();
    assert!(page.items.is_empty());
    assert!(!page.pagination.truncated);
}
