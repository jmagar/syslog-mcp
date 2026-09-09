use super::*;
use crate::config::StorageConfig;
use crate::db::init_pool;

#[test]
fn repository_pages_are_stable_when_a_newer_row_arrives() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("reads.db"))).unwrap();
    let conn = pool.get().unwrap();
    for (key, seen) in [
        ("a", "2026-08-21T10:00:00Z"),
        ("b", "2026-08-21T11:00:00Z"),
        ("c", "2026-08-21T12:00:00Z"),
    ] {
        conn.execute("INSERT INTO repositories(repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at) VALUES(?1,'host','/'||?1||'/git','/'||?1,?1,?2,?2)", rusqlite::params![key,seen]).unwrap();
    }
    drop(conn);
    let query = RepositoryQuery::default();
    let first = list_observatory_repositories(&pool, &query, None, 2, i64::MAX).unwrap();
    assert_eq!(
        first.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
        vec!["c", "b", "a"]
    );
    let boundary = &first[1];
    pool.get().unwrap().execute("INSERT INTO repositories(repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at) VALUES('new','host','/newgit','/new','new','2026-08-21T13:00:00Z','2026-08-21T13:00:00Z')",[]).unwrap();
    let second = list_observatory_repositories(
        &pool,
        &query,
        Some((boundary.last_seen_at.as_str(), boundary.id)),
        2,
        i64::MAX,
    )
    .unwrap();
    assert_eq!(
        second.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
        vec!["a"]
    );
}

#[test]
fn contract_indexes_cover_run_event_span_and_metric_ordering() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("plans.db"))).unwrap();
    let conn = pool.get().unwrap();
    for (sql, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT id FROM agent_runs WHERE status='active' ORDER BY last_activity_at DESC,id DESC LIMIT 10",
            "idx_agent_runs_status_activity",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT id FROM agent_run_events WHERE run_id=1 ORDER BY observed_at DESC,id DESC LIMIT 10",
            "idx_agent_run_events_run_order",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT id FROM otel_spans WHERE run_id=1 ORDER BY start_time_unix_nano DESC,id DESC LIMIT 10",
            "idx_otel_spans_run_time",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT id FROM otel_metric_points WHERE run_id=1 ORDER BY time_unix_nano DESC,id DESC LIMIT 10",
            "idx_otel_metric_points_run_time",
        ),
    ] {
        let details = conn
            .prepare(sql)
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            details.iter().any(|d| d.contains(index)),
            "{index}: {details:?}"
        );
    }
}

#[test]
fn event_paging_is_bidirectional_and_payload_is_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("events.db"))).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('run','session','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let run_id = conn.last_insert_rowid();
    for (key, at) in [
        ("one", "2026-08-21T10:00:00Z"),
        ("two", "2026-08-21T10:00:00Z"),
        ("three", "2026-08-21T11:00:00Z"),
    ] {
        conn.execute("INSERT INTO agent_run_events(event_key,run_id,observed_at,ingested_at,event_kind,source_kind,source_id,severity,title,summary,payload_json) VALUES(?1,?2,?3,?3,'transcript','transcript',?1,'info',?1,?1,'{\"secret\":true}')", rusqlite::params![key, run_id, at]).unwrap();
    }
    drop(conn);
    let hidden = list_observatory_events(
        &pool,
        "run",
        &AgentEventQuery::default(),
        None,
        10,
        false,
        i64::MAX,
    )
    .unwrap();
    assert!(hidden.iter().all(|row| row.payload_json.is_none()));
    let visible = list_observatory_events(
        &pool,
        "run",
        &AgentEventQuery {
            include_payload: true,
            ..Default::default()
        },
        None,
        10,
        true,
        i64::MAX,
    )
    .unwrap();
    assert_eq!(
        visible
            .iter()
            .map(|r| r.event_key.as_str())
            .collect::<Vec<_>>(),
        vec!["one", "two", "three"]
    );
    assert!(
        visible
            .iter()
            .all(|row| row.payload_json.as_deref() == Some("{\"secret\":true}"))
    );
}

#[test]
fn scoped_evidence_resolves_branch_and_worktree_with_durable_watermark() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("scope.db"))).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO repositories(repository_key,hostname,common_git_dir,primary_path,display_name,first_seen_at,last_seen_at) VALUES('repo','host','/repo/.git','/repo','repo','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let repository_id = conn.last_insert_rowid();
    conn.execute("INSERT INTO repository_worktrees(worktree_key,repository_id,hostname,path,git_dir,branch_ref,branch_name,first_seen_at,last_seen_at) VALUES('wt',?1,'host','/repo/.worktrees/fix','/repo/.git/worktrees/fix','refs/heads/codex/fix','codex/fix','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", [repository_id]).unwrap();
    let worktree_id = conn.last_insert_rowid();
    conn.execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at,primary_worktree_id,primary_branch) VALUES('run','session','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z',?1,'codex/fix')", [worktree_id]).unwrap();
    let run_id = conn.last_insert_rowid();
    conn.execute("INSERT INTO agent_run_worktrees(relation_key,run_id,worktree_id,evidence_kind,evidence_source,trust_level,confidence,is_primary,first_seen_at,last_seen_at) VALUES('relation',?1,?2,'hook_cwd','fixture','verified',1.0,1,'2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", rusqlite::params![run_id,worktree_id]).unwrap();
    for key in ["one", "two"] {
        conn.execute("INSERT INTO agent_run_events(event_key,run_id,worktree_id,observed_at,ingested_at,event_kind,source_kind,source_id,severity,title,summary,payload_json) VALUES(?1,?2,?3,'2026-08-21T10:00:00Z','2026-08-21T10:00:01Z','transcript','transcript',?1,'info',?1,?1,'{\"token\":\"secret\"}')", rusqlite::params![key,run_id,worktree_id]).unwrap();
    }
    drop(conn);
    let branch = scoped_evidence_events(
        &pool,
        &EvidenceScopeQuery {
            branch: Some("codex/fix".into()),
            ..Default::default()
        },
        0,
        1,
    )
    .unwrap();
    assert_eq!(branch.items.len(), 1);
    assert!(branch.high_watermark > branch.next_after);
    assert!(branch.items[0].payload_json.is_none());
    let worktree = scoped_evidence_events(
        &pool,
        &EvidenceScopeQuery {
            worktree: Some("/repo/.worktrees/fix".into()),
            include_payload: true,
            ..Default::default()
        },
        branch.next_after,
        10,
    )
    .unwrap();
    assert_eq!(worktree.items.len(), 1);
    assert!(worktree.items[0].payload_json.is_some());
}

#[test]
fn scoped_evidence_includes_exact_legacy_scope_references_without_exposing_payload() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("legacy-scope.db"))).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('legacy-run','session','claude','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let run_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO agent_run_events(event_key,run_id,observed_at,ingested_at,event_kind,source_kind,source_id,severity,title,summary,payload_json) VALUES('branch-reference',?1,'2026-08-21T10:00:00Z','2026-08-21T10:00:01Z','transcript','logs','1','info','legacy transcript','working on fix/hidden-red-integration-tests','{\"secret\":true}')",
        [run_id],
    ).unwrap();
    conn.execute(
        "INSERT INTO agent_run_events(event_key,run_id,observed_at,ingested_at,event_kind,source_kind,source_id,severity,title,summary,payload_json) VALUES('worktree-reference',?1,'2026-08-21T10:01:00Z','2026-08-21T10:01:01Z','transcript','logs','2','info','legacy transcript','no structured scope','{\"cwd\":\"/repo/.worktrees/fix\",\"secret\":true}')",
        [run_id],
    ).unwrap();
    drop(conn);

    let branch = scoped_evidence_events(
        &pool,
        &EvidenceScopeQuery {
            branch: Some("fix/hidden-red-integration-tests".into()),
            ..Default::default()
        },
        0,
        10,
    )
    .unwrap();
    assert_eq!(branch.items.len(), 1);
    assert!(branch.items[0].payload_json.is_none());

    let worktree = scoped_evidence_events(
        &pool,
        &EvidenceScopeQuery {
            worktree: Some("/repo/.worktrees/fix".into()),
            ..Default::default()
        },
        0,
        10,
    )
    .unwrap();
    assert_eq!(worktree.items.len(), 1);
    assert!(worktree.items[0].payload_json.is_none());
}

#[test]
fn telemetry_includes_only_unambiguous_unlinked_identity_rows() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("telemetry.db"))).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('run','session','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let run_id = conn.last_insert_rowid();
    conn.execute("INSERT INTO otel_spans(trace_id,span_id,span_name,span_kind,start_time_unix_nano,end_time_unix_nano,duration_nano,hostname,ai_tool,ai_session_id,received_at) VALUES(?1,?2,'span',1,100,200,100,'host','codex','session','2026-08-21T10:00:00Z')", rusqlite::params!["11".repeat(16), "22".repeat(8)]).unwrap();
    drop(conn);
    let identity = RunTelemetryIdentity {
        hostname: "host".into(),
        tool: "codex".into(),
        provider_tool: None,
        native_session_id: "session".into(),
    };
    assert_eq!(
        list_observatory_spans(
            &pool,
            run_id,
            &identity,
            &TelemetryQuery::default(),
            None,
            10,
            i64::MAX
        )
        .unwrap()
        .len(),
        1
    );
    pool.get().unwrap().execute("INSERT INTO agent_runs(run_key,native_session_id,tool,provider_tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('other','session','other','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    assert!(
        list_observatory_spans(
            &pool,
            run_id,
            &identity,
            &TelemetryQuery::default(),
            None,
            10,
            i64::MAX
        )
        .unwrap()
        .is_empty()
    );
}
