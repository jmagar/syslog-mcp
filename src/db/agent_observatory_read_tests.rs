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
fn telemetry_reads_only_persisted_trace_relations_not_runtime_identity_matches() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("telemetry.db"))).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO agent_runs(run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at) VALUES('run','session','codex','host','active','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z','2026-08-21T10:00:00Z')", []).unwrap();
    let run_id = conn.last_insert_rowid();
    conn.execute("INSERT INTO otel_spans(trace_id,span_id,span_name,span_kind,start_time_unix_nano,end_time_unix_nano,duration_nano,hostname,ai_tool,ai_session_id,received_at) VALUES(?1,?2,'span',1,100,200,100,'host','codex','session','2026-08-21T10:00:00Z')", rusqlite::params!["11".repeat(16), "22".repeat(8)]).unwrap();
    conn.execute(
        "INSERT INTO agent_run_trace_relations
            (relation_key,trace_id,span_id,run_id,identifier_namespace,evidence_kind,
             confidence,reason,projection_version,candidate_count,observed_at,metadata_json)
         VALUES ('relation','11111111111111111111111111111111','2222222222222222',?1,
                 'otel.gen_ai.conversation.id','exact_provider_id',0.98,'fixture',1,1,
                 '2026-08-21T10:00:00Z','{}')",
        [run_id],
    )
    .unwrap();
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
}

#[test]
fn persisted_trace_relation_run_lookup_uses_its_bounded_index() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("trace-index.db"))).unwrap();
    let conn = pool.get().unwrap();
    let details = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT os.id FROM agent_run_trace_relations r
             JOIN otel_spans os ON os.trace_id=r.trace_id AND os.span_id=r.span_id
             WHERE r.run_id=?1 ORDER BY os.start_time_unix_nano DESC,os.id DESC LIMIT ?2",
        )
        .unwrap()
        .query_map(rusqlite::params![1_i64, 501_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("idx_agent_run_trace_relations_run_span")),
        "query plan must retain the persisted trace/run index: {details:?}"
    );
}
