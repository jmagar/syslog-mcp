use super::*;
use crate::config::StorageConfig;
use crate::db::{AiRelatedWindow, DbPool, LogBatchEntry, init_pool, insert_logs_batch};

fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
    StorageConfig::for_test(db_path)
}

/// Create an isolated test pool using a temp file (not :memory: — FTS5 needs file)
fn test_pool() -> (DbPool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config = test_storage_config(db_path);
    let pool = init_pool(&config).unwrap();
    (pool, dir) // keep dir alive for test duration
}

fn query_plan(pool: &DbPool, sql: &str, bindings: &[rusqlite::types::Value]) -> String {
    let conn = pool.get().unwrap();
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    stmt.query_map(rusqlite::params_from_iter(bindings.iter()), |row| {
        row.get::<_, String>(3)
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
    .join("\n")
}

fn make_entry(ts: &str, host: &str, severity: &str, msg: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: None,
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: "127.0.0.1:514".to_string(),
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
    }
}

#[test]
fn search_logs_fts_plan_uses_bounded_candidate_window() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "err",
            "bounded search candidate",
        )],
    )
    .unwrap();

    let params = SearchParams {
        query: Some("bounded".to_string()),
        ..Default::default()
    };
    let (sql, bindings) = search_logs_fts_sql(params.query.as_deref().unwrap(), &params, 100);
    assert!(sql.contains("fts_candidates"));
    assert!(sql.contains("LIMIT ?"));
    assert!(
        bindings
            .iter()
            .any(|value| matches!(value, rusqlite::types::Value::Integer(limit) if *limit == SEARCH_FTS_CANDIDATE_CAP as i64)),
        "FTS candidate cap should be carried as a bound parameter"
    );

    let plan = query_plan(&pool, &sql, &bindings);
    assert!(
        plan.contains("MATERIALIZE fts_candidates"),
        "FTS search should cap candidates before final sort; got:\n{plan}"
    );
    assert!(
        plan.contains("SCAN logs_fts VIRTUAL TABLE"),
        "FTS search should remain FTS-driven; got:\n{plan}"
    );
}

#[test]
fn tail_logs_severity_only_uses_per_severity_index_probes() {
    // full-review PM6: severity-only tails previously walked
    // idx_logs_timestamp newest-first and filtered — O(table) for rare
    // severities. The fast path probes idx_logs_sev_time once per severity.
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T00:00:01Z", "host-a", "emerg", "kernel meltdown"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "routine chatter"),
            make_entry("2026-01-01T00:00:03Z", "host-b", "alert", "raid degraded"),
        ],
    )
    .unwrap();

    let levels = vec!["emerg".to_string(), "alert".to_string()];
    let (sql, bindings) = tail_logs_sql(None, None, None, Some(&levels), 50);
    assert!(
        sql.contains("UNION ALL"),
        "severity-only tail must use per-severity probes, got:\n{sql}"
    );
    let plan = query_plan(&pool, &sql, &bindings);
    assert!(
        plan.contains("idx_logs_sev_time"),
        "each arm must probe the (severity, timestamp) index; got:\n{plan}"
    );
    assert!(
        !plan.contains("SCAN logs USING INDEX idx_logs_timestamp"),
        "severity-only tail must not walk the global timestamp index; got:\n{plan}"
    );

    // Behavior: newest-first across severities, info excluded.
    let rows = tail_logs(&pool, None, None, None, Some(&levels), 50).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].severity, "alert");
    assert_eq!(rows[1].severity, "emerg");

    // A second filter still takes the generic plan.
    let (sql, _) = tail_logs_sql(Some("host-a"), None, None, Some(&levels), 50);
    assert!(!sql.contains("UNION ALL"));
}

#[test]
fn tail_logs_limit_is_bound_and_clamped() {
    let levels = vec!["err".to_string(), "warning".to_string()];
    let (sql, bindings) = tail_logs_sql(
        Some("host-a"),
        Some("10.0.0.1:514"),
        Some("sshd"),
        Some(&levels),
        50_000,
    );
    assert!(
        sql.contains("LIMIT ?"),
        "tail_logs must bind LIMIT instead of interpolating it: {sql}"
    );
    assert!(
        bindings
            .iter()
            .any(|value| matches!(value, rusqlite::types::Value::Integer(limit) if *limit == 500)),
        "tail_logs should clamp and bind limit=500, got: {bindings:?}"
    );
}

#[test]
fn host_filters_accept_the_canonical_name_returned_by_list_hosts() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_entry(
                "2026-01-01T00:00:01Z",
                "The-Gatewayhost",
                "info",
                "case variant",
            ),
            make_entry("2026-01-01T00:00:02Z", "nashost", "info", "short name"),
            make_entry(
                "2026-01-01T00:00:03Z",
                "nashost.example.test",
                "info",
                "fqdn variant",
            ),
        ],
    )
    .unwrap();

    let hosts = list_hosts(&pool).unwrap();
    assert!(hosts.iter().any(|host| host.hostname == "the-gatewayhost"));
    assert!(hosts.iter().any(|host| host.hostname == "nashost"));

    let case_rows = tail_logs(&pool, Some("the-gatewayhost"), None, None, None, 10).unwrap();
    assert_eq!(case_rows.len(), 1);
    assert_eq!(case_rows[0].hostname, "The-Gatewayhost");

    let alias_rows = tail_logs(&pool, Some("nashost"), None, None, None, 10).unwrap();
    assert_eq!(alias_rows.len(), 2);
    assert!(
        alias_rows
            .iter()
            .any(|row| row.hostname == "nashost.example.test")
    );

    let params = SearchParams {
        host: Some("the-gatewayhost".to_string()),
        limit: Some(10),
        ..Default::default()
    };
    let filtered = search_logs(&pool, &params).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].hostname, "The-Gatewayhost");
}

#[test]
fn get_error_summary_limit_is_bound_and_min_clamped() {
    let (sql, bindings) = get_error_summary_sql(
        Some("2026-01-01T00:00:00Z"),
        Some("2026-01-01T01:00:00Z"),
        true,
        Some(0),
    );
    assert!(
        sql.contains("LIMIT ?"),
        "get_error_summary must bind LIMIT instead of interpolating it: {sql}"
    );
    assert!(
        bindings
            .iter()
            .any(|value| matches!(value, rusqlite::types::Value::Integer(limit) if *limit == 1)),
        "get_error_summary should clamp and bind limit=1, got: {bindings:?}"
    );
}

#[test]
fn app_filtered_search_order_uses_app_timestamp_index() {
    let (pool, _dir) = test_pool();
    let plan = query_plan(
        &pool,
        "SELECT l.id
         FROM logs l
         WHERE l.app_name = ?1
         ORDER BY l.timestamp DESC
         LIMIT 100",
        &[rusqlite::types::Value::Text("nginx".into())],
    );
    assert!(
        plan.contains("idx_logs_app_name_timestamp"),
        "app filtered timestamp-ordered search should use app/timestamp index; got:\n{plan}"
    );
    assert!(
        !plan.contains("USE TEMP B-TREE"),
        "app filtered timestamp-ordered search should not temp-sort; got:\n{plan}"
    );
}

#[test]
fn test_search_fts() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry(
            "2026-01-01T00:00:01Z",
            "host-a",
            "err",
            "disk full on /dev/sda",
        ),
        make_entry(
            "2026-01-01T00:00:02Z",
            "host-b",
            "info",
            "connection established",
        ),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    let params = SearchParams {
        query: Some("disk".to_string()),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].message.contains("disk full"));
}

#[test]
fn search_fts_hostname_filter_returns_only_that_host() {
    // Both hosts emit a matching message; the hostname filter must scope to one.
    // Exercises the index-led intersect plan (the fix for the ~200s host-scoped
    // search) and verifies it stays correct/complete.
    let (pool, _dir) = test_pool();
    let mut entries = Vec::new();
    for i in 0..50 {
        entries.push(make_entry(
            &format!("2026-01-01T00:{:02}:00Z", i % 60),
            "host-a",
            "err",
            "kernel panic detected",
        ));
        entries.push(make_entry(
            &format!("2026-01-01T01:{:02}:00Z", i % 60),
            "host-b",
            "err",
            "kernel panic detected",
        ));
    }
    insert_logs_batch(&pool, &entries).unwrap();

    let params = SearchParams {
        query: Some("panic".to_string()),
        host: Some("host-a".to_string()),
        limit: Some(1000),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 50, "should return all 50 host-a matches");
    assert!(
        results.iter().all(|r| r.hostname == "host-a"),
        "hostname filter must exclude host-b rows"
    );
    // Newest-first ordering preserved.
    assert!(results.windows(2).all(|w| w[0].timestamp >= w[1].timestamp));
}

#[test]
fn search_fts_plan_selection_branches_on_indexed_filter() {
    // No indexed equality filter → capped materialized-candidate plan.
    let plain = SearchParams {
        query: Some("disk".to_string()),
        ..Default::default()
    };
    assert!(!plain.has_indexed_equality_filter());
    let (sql, _) = search_logs_fts_sql("disk", &plain, 50);
    assert!(sql.contains("fts_candidates"), "unfiltered uses CTE plan");
    assert!(!sql.contains("l.id IN (SELECT rowid"));

    // Selective indexed equality filter → index-led intersect plan with a
    // bounded match-set subquery (full-review PH1: the non-correlated IN
    // subquery is materialized in full, so it must carry a cap).
    let filtered = SearchParams {
        host: Some("host-a".to_string()),
        ..plain.clone()
    };
    assert!(filtered.has_indexed_equality_filter());
    let (sql, _) = search_logs_fts_sql("disk", &filtered, 50);
    assert!(
        sql.contains("l.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?1"),
        "filtered search must use the intersect plan, got:\n{sql}"
    );
    assert!(
        sql.contains(&format!(
            "ORDER BY rowid DESC LIMIT {SEARCH_FTS_FAST_PATH_MATCH_CAP}"
        )),
        "intersect plan must bound the materialized match set, got:\n{sql}"
    );
    assert!(
        !sql.contains("fts_candidates"),
        "intersect plan has no CTE cap"
    );
    assert!(
        sql.contains("l.hostname IN (") && sql.contains("FROM hosts h"),
        "canonical host filter applied via append_filters"
    );
}

#[test]
fn search_fts_severity_only_filter_uses_capped_candidate_plan() {
    // Severity partitions are huge (a single severity can be >90% of the
    // table); a rare term + severity-only filter previously walked the whole
    // partition via the fast path (full-review PH1). Severity-only must take
    // the capped-candidate plan.
    let severity_only = SearchParams {
        query: Some("disk".to_string()),
        severity: Some("info".to_string()),
        ..Default::default()
    };
    assert!(!severity_only.has_indexed_equality_filter());
    let (sql, _) = search_logs_fts_sql("disk", &severity_only, 50);
    assert!(
        sql.contains("fts_candidates"),
        "severity-only search must use the capped CTE plan, got:\n{sql}"
    );

    let severity_in_only = SearchParams {
        query: Some("disk".to_string()),
        severity_in: Some(vec!["emerg".to_string(), "alert".to_string()]),
        ..Default::default()
    };
    assert!(!severity_in_only.has_indexed_equality_filter());

    // Severity combined with a selective filter still gets the fast path
    // (the selective column's index leads).
    let combined = SearchParams {
        query: Some("disk".to_string()),
        severity: Some("info".to_string()),
        host: Some("host-a".to_string()),
        ..Default::default()
    };
    assert!(combined.has_indexed_equality_filter());
}

#[test]
fn test_search_invalid_fts_returns_error() {
    let (pool, _dir) = test_pool();
    // FTS5 treats bare parentheses as a syntax error
    let params = SearchParams {
        query: Some("(invalid fts syntax".to_string()),
        ..Default::default()
    };
    let result = search_logs(&pool, &params);
    assert!(result.is_err(), "invalid FTS5 query should return Err");
    // Error message must be generic — no schema details leaked
    let msg = result.unwrap_err().to_string();
    assert_eq!(msg, "Search query failed", "error must be generic");
}

// --- validate_fts_query unit tests ---

#[test]
fn test_validate_fts_query_valid() {
    assert!(validate_fts_query("disk error").is_ok());
    assert!(validate_fts_query("nginx AND 502").is_ok());
    // Exactly 16 terms should pass
    let sixteen = (0..16)
        .map(|i| format!("term{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(validate_fts_query(&sixteen).is_ok());
    // Exactly 512 chars should pass
    let at_limit = "a".repeat(512);
    assert!(validate_fts_query(&at_limit).is_ok());
}

#[test]
fn test_validate_fts_query_too_long() {
    let long_query = "a".repeat(513);
    let result = validate_fts_query(&long_query);
    assert!(result.is_err(), "query > 512 chars should be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("513"), "error should mention actual length");
    assert!(msg.contains("512"), "error should mention the limit");
}

#[test]
fn test_validate_fts_query_too_many_terms() {
    let many_terms = (0..17)
        .map(|i| format!("term{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let result = validate_fts_query(&many_terms);
    assert!(result.is_err(), "query with 17 terms should be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("17"), "error should mention actual term count");
    assert!(msg.contains("16"), "error should mention the limit");
}

#[test]
fn test_get_stats_empty_db() {
    let (pool, dir) = test_pool();
    let stats = get_stats(&pool, &test_storage_config(dir.path().join("test.db"))).unwrap();
    assert_eq!(stats.total_logs, 0);
    assert_eq!(stats.total_hosts, 0);
    // oldest_log and newest_log should be None on empty DB
    assert!(stats.oldest_log.is_none());
    assert!(stats.newest_log.is_none());
    assert!(stats.free_disk_mb.is_some());
}

#[test]
fn test_get_stats_total_logs_matches_across_rollup_states() {
    // stats.total_logs = SUM(timeline_hourly.event_count) + COUNT(logs WHERE
    // id > watermark). It must equal the true row count whether the rollup is
    // empty (all rows in the live delta), fully refreshed (all rows in rollup),
    // or partially refreshed (some in each). (bead syslog-mcp-kcvq)
    let (pool, dir) = test_pool();
    let cfg = test_storage_config(dir.path().join("test.db"));

    let entries = vec![
        make_entry("2026-01-01T00:00:01Z", "h1", "info", "a"),
        make_entry("2026-01-01T00:30:00Z", "h1", "info", "b"),
        make_entry("2026-01-01T01:00:00Z", "h2", "err", "c"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    // Rollup empty: everything counted via the live delta.
    assert_eq!(get_stats(&pool, &cfg).unwrap().total_logs, 3);

    // Fully refreshed: everything counted via the rollup, delta empty.
    crate::db::refresh_timeline_rollup(&pool).unwrap();
    assert_eq!(get_stats(&pool, &cfg).unwrap().total_logs, 3);

    // Insert more after refresh: partial — rollup holds 3, delta holds 2.
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T02:00:00Z", "h1", "info", "d"),
            make_entry("2026-01-01T02:05:00Z", "h1", "info", "e"),
        ],
    )
    .unwrap();
    assert_eq!(get_stats(&pool, &cfg).unwrap().total_logs, 5);

    // Refresh again: all 5 now in the rollup.
    crate::db::refresh_timeline_rollup(&pool).unwrap();
    assert_eq!(get_stats(&pool, &cfg).unwrap().total_logs, 5);
}

#[test]
fn test_get_stats_skips_fts_diagnostic_by_default() {
    // Issue 4: the default stats path must NOT run COUNT(*) FROM logs_fts
    // (expensive on large DBs), reflected as phantom_fts_rows == None. The
    // opt-in path computes it.
    let (pool, dir) = test_pool();
    let cfg = test_storage_config(dir.path().join("test.db"));

    let fast = get_stats(&pool, &cfg).unwrap();
    assert_eq!(
        fast.phantom_fts_rows, None,
        "default stats must skip the FTS diagnostic"
    );

    let full = get_stats_with_options(&pool, &cfg, true).unwrap();
    assert_eq!(
        full.phantom_fts_rows,
        Some(0),
        "opt-in stats must compute phantom_fts_rows (0 on a clean DB)"
    );
}

#[test]
fn test_tail_filter_by_host() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:01Z", "host-a", "info", "from a"),
        make_entry("2026-01-01T00:00:02Z", "host-b", "info", "from b"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    let rows = tail_logs(&pool, Some("host-a"), None, None, None, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hostname, "host-a");
}

#[test]
fn test_search_timestamp_range_filtering() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:00Z", "host-a", "info", "early message"),
        make_entry("2026-06-15T12:00:00Z", "host-a", "info", "mid message"),
        make_entry("2026-12-31T23:59:59Z", "host-a", "info", "late message"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    // from only
    let params = SearchParams {
        since: Some("2026-06-01T00:00:00Z".into()),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 2, "from filter should return mid + late");

    // to only
    let params = SearchParams {
        until: Some("2026-06-30T00:00:00Z".into()),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 2, "to filter should return early + mid");

    // from + to (narrow window)
    let params = SearchParams {
        since: Some("2026-06-01T00:00:00Z".into()),
        until: Some("2026-06-30T00:00:00Z".into()),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 1, "from+to filter should return only mid");
    assert_eq!(results[0].message, "mid message");
}

#[test]
fn test_search_received_at_range_filtering() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T00:00:00Z", "host-a", "info", "received early"),
            make_entry("2026-01-01T00:00:00Z", "host-a", "info", "received mid"),
            make_entry("2026-01-01T00:00:00Z", "host-a", "info", "received late"),
        ],
    )
    .unwrap();

    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE logs SET received_at = ?1 WHERE message = ?2",
        rusqlite::params!["2026-01-01T00:00:00Z", "received early"],
    )
    .unwrap();
    conn.execute(
        "UPDATE logs SET received_at = ?1 WHERE message = ?2",
        rusqlite::params!["2026-01-01T00:30:00Z", "received mid"],
    )
    .unwrap();
    conn.execute(
        "UPDATE logs SET received_at = ?1 WHERE message = ?2",
        rusqlite::params!["2026-01-01T01:00:00Z", "received late"],
    )
    .unwrap();
    drop(conn);

    let results = search_logs(
        &pool,
        &SearchParams {
            received_since: Some("2026-01-01T00:15:00Z".into()),
            received_until: Some("2026-01-01T00:45:00Z".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].message, "received mid");
}

#[test]
fn test_search_exclude_facility_keeps_unknown_facility_rows() {
    let (pool, _dir) = test_pool();
    let mut auth = make_entry("2026-01-01T00:00:00Z", "host-a", "info", "auth event");
    auth.facility = Some("auth".into());
    let mut daemon = make_entry("2026-01-01T00:00:01Z", "host-a", "info", "daemon event");
    daemon.facility = Some("daemon".into());
    let unknown = make_entry("2026-01-01T00:00:02Z", "host-a", "info", "unknown event");
    insert_logs_batch(&pool, &[auth, daemon, unknown]).unwrap();

    let results = search_logs(
        &pool,
        &SearchParams {
            exclude_facility: Some("auth".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let messages: Vec<&str> = results.iter().map(|row| row.message.as_str()).collect();
    assert_eq!(messages, vec!["unknown event", "daemon event"]);
}

#[test]
fn test_severity_to_num() {
    assert_eq!(severity_to_num("emerg"), Some(0));
    assert_eq!(severity_to_num("alert"), Some(1));
    assert_eq!(severity_to_num("crit"), Some(2));
    assert_eq!(severity_to_num("err"), Some(3));
    assert_eq!(severity_to_num("warning"), Some(4));
    assert_eq!(severity_to_num("notice"), Some(5));
    assert_eq!(severity_to_num("info"), Some(6));
    assert_eq!(severity_to_num("debug"), Some(7));
    // Edge cases
    assert_eq!(severity_to_num(""), None);
    // Aliases (case-insensitive)
    assert_eq!(severity_to_num("ERROR"), Some(3), "case-insensitive alias");
    assert_eq!(severity_to_num("Error"), Some(3), "mixed-case alias");
    assert_eq!(severity_to_num("critical"), Some(2), "alias for 'crit'");
    assert_eq!(severity_to_num("warn"), Some(4), "alias for 'warning'");
    assert_eq!(severity_to_num("emergency"), Some(0), "alias for 'emerg'");
    assert_eq!(severity_to_num("fatal"), Some(3), "alias for 'err'");
    assert_eq!(severity_to_num("panic"), Some(3), "alias for 'err'");
    // Truly invalid
    assert_eq!(severity_to_num("bogus"), None);
    assert_eq!(
        severity_to_num("trace"),
        None,
        "syslog has no 'trace' level"
    );
}

#[test]
fn test_error_summary_severity_filter() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:00Z", "host-a", "err", "error msg"),
        make_entry("2026-01-01T00:00:01Z", "host-a", "warning", "warn msg"),
        make_entry("2026-01-01T00:00:02Z", "host-a", "info", "info msg"),
        make_entry("2026-01-01T00:00:03Z", "host-a", "debug", "debug msg"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    let summary = get_error_summary(&pool, None, None, false, None).unwrap();
    // Only err and warning should appear (not info, debug)
    assert_eq!(summary.len(), 2);
    let severities: Vec<&str> = summary.iter().map(|e| e.severity.as_str()).collect();
    assert!(severities.contains(&"err"));
    assert!(severities.contains(&"warning"));
}

#[test]
fn test_search_severity_in_filter() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:00Z", "host-a", "emerg", "emerg msg"),
        make_entry("2026-01-01T00:00:01Z", "host-a", "err", "err msg"),
        make_entry("2026-01-01T00:00:02Z", "host-a", "warning", "warn msg"),
        make_entry("2026-01-01T00:00:03Z", "host-a", "info", "info msg"),
        make_entry("2026-01-01T00:00:04Z", "host-a", "debug", "debug msg"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    let params = SearchParams {
        severity_in: Some(vec!["emerg".into(), "err".into(), "warning".into()]),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 3, "severity_in should match exactly 3");
    for r in &results {
        assert!(
            ["emerg", "err", "warning"].contains(&r.severity.as_str()),
            "unexpected severity: {}",
            r.severity
        );
    }
}

#[test]
fn tail_logs_filters_multiple_severities() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T00:00:00Z", "host-a", "err", "err msg"),
            make_entry("2026-01-01T00:00:01Z", "host-a", "warning", "warn msg"),
            make_entry("2026-01-01T00:00:02Z", "host-a", "info", "info msg"),
        ],
    )
    .unwrap();

    let severities = vec!["err".to_string(), "warning".to_string()];
    let rows = tail_logs(&pool, Some("host-a"), None, None, Some(&severities), 10).unwrap();

    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.hostname == "host-a"));
    assert!(
        rows.iter()
            .all(|row| ["err", "warning"].contains(&row.severity.as_str()))
    );
}

#[test]
fn search_logs_ignores_deleted_fts_phantom_rows() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "info",
            "live message",
        )],
    )
    .unwrap();

    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO logs_fts(rowid, message) VALUES (?1, ?2)",
        rusqlite::params![999_999_i64, "phantom-token orphan row"],
    )
    .unwrap();
    drop(conn);

    let params = SearchParams {
        query: Some("\"phantom-token\"".to_string()),
        ..Default::default()
    };
    let results = search_logs(&pool, &params).unwrap();
    assert!(results.is_empty(), "FTS-only phantom rows must not leak");
}

fn make_ai_entry(
    ts: &str,
    host: &str,
    tool: &str,
    project: &str,
    session_id: &str,
    message: &str,
) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: Some("local0".to_string()),
        severity: "info".to_string(),
        app_name: Some("ai-transcript".to_string()),
        process_id: None,
        message: message.to_string(),
        raw: message.to_string(),
        source_ip: "127.0.0.1:514".to_string(),
        docker_checkpoint: None,
        ai_tool: Some(tool.to_string()),
        ai_project: Some(project.to_string()),
        ai_session_id: Some(session_id.to_string()),
        ai_transcript_path: Some(format!("{project}/{session_id}.jsonl")),
        metadata_json: None,
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

#[test]
fn search_logs_exclude_ai_filters_structured_and_transcript_app_rows() {
    let (pool, _dir) = test_pool();
    let mut legacy_transcript = make_entry(
        "2026-01-01T00:00:00Z",
        "localhost",
        "info",
        "legacy codex transcript event",
    );
    legacy_transcript.app_name = Some("codex-transcript".into());

    insert_logs_batch(
        &pool,
        &[
            legacy_transcript,
            make_ai_entry(
                "2026-01-01T00:00:01Z",
                "localhost",
                "codex",
                "/tmp/project",
                "sess-1",
                "structured ai transcript event",
            ),
            make_entry(
                "2026-01-01T00:00:02Z",
                "host-a",
                "warning",
                "real host event",
            ),
        ],
    )
    .unwrap();

    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("event".into()),
            exclude_ai: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message, "real host event");
}

#[test]
fn search_logs_filters_by_source_ip_prefix_without_fts() {
    let (pool, _dir) = test_pool();
    let mut docker_stdout = make_entry(
        "2026-01-01T00:00:00Z",
        "devhost",
        "info",
        "container stdout line",
    );
    docker_stdout.source_ip = "docker://devhost/cortex/stdout".into();

    let mut docker_stderr = make_entry(
        "2026-01-01T00:00:01Z",
        "devhost",
        "warning",
        "container stderr line",
    );
    docker_stderr.source_ip = "docker://devhost/cortex/stderr".into();

    let mut other = make_entry(
        "2026-01-01T00:00:02Z",
        "devhost",
        "info",
        "different container line",
    );
    other.source_ip = "docker://devhost/other/stdout".into();

    insert_logs_batch(&pool, &[docker_stdout, docker_stderr, other]).unwrap();

    let rows = search_logs(
        &pool,
        &SearchParams {
            source_ip_prefix: Some("docker://devhost/cortex/".into()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.source_ip.starts_with("docker://devhost/cortex/"))
    );
}

#[test]
fn search_logs_filters_by_multiple_source_prefixes_with_indexed_or() {
    let (pool, _dir) = test_pool();
    let mut direct = make_entry(
        "2026-01-01T00:00:00Z",
        "devhost",
        "info",
        "direct shell history",
    );
    direct.source_ip = "shell-history://devhost/user/zsh".into();
    direct.app_name = Some("zsh".into());

    let mut forwarded = make_entry(
        "2026-01-01T00:00:01Z",
        "devhost",
        "info",
        "forwarded shell history",
    );
    forwarded.source_ip = "agent-shell-history://devhost/user/bash".into();
    forwarded.app_name = Some("zsh".into());

    let mut boundary = make_entry(
        "2026-01-01T00:00:02Z",
        "devhost",
        "info",
        "prefix boundary neighbor",
    );
    boundary.source_ip = "shell-historz://devhost/user/zsh".into();
    boundary.app_name = Some("zsh".into());
    insert_logs_batch(&pool, &[direct, forwarded, boundary]).unwrap();

    let params = SearchParams {
        host: Some("devhost".into()),
        app: Some("zsh".into()),
        source_ip_prefixes: Some(vec![
            "shell-history://".into(),
            "agent-shell-history://".into(),
        ]),
        ..Default::default()
    };
    let rows = search_logs(&pool, &params).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.message != "prefix boundary neighbor")
    );

    let mut sql = String::from("SELECT l.id FROM logs l WHERE 1=1");
    let mut bindings = Vec::new();
    let mut idx = 1;
    append_filters(&mut sql, &mut bindings, &mut idx, &params);
    assert!(sql.contains("l.source_ip >= ?2 AND l.source_ip < ?3"));
    assert!(sql.contains("l.source_ip >= ?4 AND l.source_ip < ?5"));
    assert_eq!(
        bindings,
        vec![
            rusqlite::types::Value::Text("devhost".into()),
            rusqlite::types::Value::Text("shell-history://".into()),
            rusqlite::types::Value::Text("shell-history:/0".into()),
            rusqlite::types::Value::Text("agent-shell-history://".into()),
            rusqlite::types::Value::Text("agent-shell-history:/0".into()),
            rusqlite::types::Value::Text("zsh".into()),
        ]
    );

    let plan_params = SearchParams {
        source_ip_prefixes: params.source_ip_prefixes.clone(),
        ..Default::default()
    };
    let mut plan_sql = String::from("SELECT l.id FROM logs l WHERE 1=1");
    let mut plan_bindings = Vec::new();
    let mut plan_idx = 1;
    append_filters(
        &mut plan_sql,
        &mut plan_bindings,
        &mut plan_idx,
        &plan_params,
    );
    let plan = query_plan(&pool, &plan_sql, &plan_bindings);
    assert!(
        plan.contains("MULTI-INDEX OR"),
        "expected indexed OR plan:\n{plan}"
    );
    assert!(
        plan.matches("idx_logs_source_ip_timestamp").count() >= 2,
        "both prefix arms must use the source index:\n{plan}"
    );
    assert!(
        !plan.contains("SCAN l"),
        "must not scan the logs table:\n{plan}"
    );
}

#[test]
fn empty_source_prefixes_neither_match_all_nor_select_the_fts_fast_path() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_entry(
            "2026-01-01T00:00:00Z",
            "devhost",
            "info",
            "must not be returned",
        )],
    )
    .unwrap();

    for prefixes in [
        vec![],
        vec![String::new()],
        vec![String::new(), String::new()],
    ] {
        let params = SearchParams {
            source_ip_prefixes: Some(prefixes),
            ..Default::default()
        };
        assert!(!params.has_indexed_equality_filter());

        let mut sql = String::from("SELECT l.id FROM logs l WHERE 1=1");
        let mut bindings = Vec::new();
        let mut idx = 1;
        append_filters(&mut sql, &mut bindings, &mut idx, &params);
        assert_eq!(sql, "SELECT l.id FROM logs l WHERE 1=1");
        assert!(bindings.is_empty());
        assert_eq!(idx, 1);

        let error = search_logs(&pool, &params).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source prefixes must be non-empty")
        );
    }

    let singular = SearchParams {
        source_ip_prefix: Some(String::new()),
        ..Default::default()
    };
    assert!(!singular.has_indexed_equality_filter());
    let error = search_logs(&pool, &singular).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source prefixes must be non-empty")
    );
}

#[test]
fn search_logs_filters_by_event_action_column() {
    let (pool, _dir) = test_pool();
    let mut die = make_entry(
        "2026-01-01T00:00:00Z",
        "devhost",
        "notice",
        "container died",
    );
    die.source_ip = "docker-event://devhost/cortex/die".into();
    die.event_action = Some("die".into());

    let mut start = make_entry(
        "2026-01-01T00:00:01Z",
        "devhost",
        "notice",
        "container started",
    );
    start.source_ip = "docker-event://devhost/cortex/start".into();
    start.event_action = Some("start".into());

    insert_logs_batch(&pool, &[die, start]).unwrap();

    let rows = search_logs(
        &pool,
        &SearchParams {
            source_ip_prefix: Some("docker-event://".into()),
            event_action: Some("die".into()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message, "container died");
}

#[test]
fn search_ai_sessions_groups_results() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "sess-1",
                "authentication bug fixed",
            ),
            make_ai_entry(
                "2026-01-01T00:01:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "sess-1",
                "authentication tests passing",
            ),
            make_ai_entry(
                "2026-01-01T00:02:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "sess-1",
                "unmatched context",
            ),
        ],
    )
    .unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "authentication".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.sessions[0].match_count, 2);
    assert_eq!(result.sessions[0].event_count, 3);
}

#[test]
fn search_ai_sessions_query_plan_uses_session_host_time_index() {
    let (pool, _dir) = test_pool();
    let mut entries = Vec::new();
    for i in 0..150 {
        entries.push(make_ai_entry(
            &format!("2026-01-01T00:{:02}:00Z", i % 60),
            "host-a",
            "claude",
            "/tmp/project",
            "sess-1",
            if i % 10 == 0 {
                "indexed authentication match"
            } else {
                "background transcript event"
            },
        ));
    }
    for i in 0..50 {
        entries.push(make_ai_entry(
            &format!("2026-01-02T00:{:02}:00Z", i % 60),
            "host-b",
            "codex",
            "/tmp/other",
            "sess-2",
            "indexed authentication match",
        ));
    }
    insert_logs_batch(&pool, &entries).unwrap();
    refresh_ai_session_rollup(&pool).unwrap();

    let params = SearchAiSessionsParams {
        query: "authentication".into(),
        ai_project: Some("/tmp/project".into()),
        ai_tool: Some("claude".into()),
        limit: Some(10),
        ..Default::default()
    };
    let result = search_ai_sessions(&pool, &params).unwrap();
    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.sessions[0].event_count, 150);

    let (sql, bindings) = search_ai_sessions_sql(&params, 10);
    assert!(sql.contains("candidates AS MATERIALIZED"));
    assert!(
        sql.contains("FROM logs_fts") && sql.contains("WHERE logs_fts MATCH ?1"),
        "session search candidates must be FTS-first"
    );
    assert!(
        sql.contains("LIMIT 5000"),
        "session search must bound filtered matching rows"
    );
    assert!(
        sql.contains("LEFT JOIN ai_session_rollup rollup"),
        "selected sessions should combine rollup statistics with post-refresh rows"
    );

    let conn = pool.get().unwrap();
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let plan = stmt
        .query_map(rusqlite::params_from_iter(bindings.iter()), |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n");
    // Pin the EXACT index that the new (host, time) composite was added
    // for so a planner regression that falls back to the broader
    // `idx_logs_ai_session` is caught by this guard. If SQLite version
    // drift starts flapping this in CI, prefer documenting the SQLite
    // version pin over loosening this assertion.
    assert!(
        plan.contains("idx_logs_ai_session_host_time"),
        "expected AI session event-count plan to use idx_logs_ai_session_host_time, got:\n{plan}"
    );
}

#[test]
fn search_ai_sessions_finds_rows_inserted_after_rollup_refresh() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            "before-refresh",
            "background transcript event",
        )],
    )
    .unwrap();
    refresh_ai_session_rollup(&pool).unwrap();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:01:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            "after-refresh",
            "freshneedle appears immediately",
        )],
    )
    .unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "freshneedle".into(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.sessions[0].ai_session_id, "after-refresh");
    assert!(!result.truncated);
}

#[test]
fn search_ai_sessions_combines_rollup_with_post_refresh_session_rows() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            "shared-session",
            "background transcript event",
        )],
    )
    .unwrap();
    refresh_ai_session_rollup(&pool).unwrap();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:01:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            "shared-session",
            "freshneedle appears immediately",
        )],
    )
    .unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "freshneedle".into(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.sessions[0].event_count, 2);
    assert_eq!(result.sessions[0].first_seen, "2026-01-01T00:00:00Z");
    assert_eq!(result.sessions[0].last_seen, "2026-01-01T00:01:00Z");
}

#[test]
fn search_ai_sessions_finds_selective_match_older_than_newest_thousand_sessions() {
    let (pool, _dir) = test_pool();
    let mut entries = vec![make_ai_entry(
        "2026-01-01T00:00:00Z",
        "host-a",
        "claude",
        "/tmp/project",
        "historical-match",
        "historicalneedle remains discoverable",
    )];
    for i in 0..1_001 {
        entries.push(make_ai_entry(
            "2026-01-02T00:00:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            &format!("newer-{i}"),
            "routine newer transcript event",
        ));
    }
    insert_logs_batch(&pool, &entries).unwrap();
    refresh_ai_session_rollup(&pool).unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "historicalneedle".into(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.candidate_rows, 1);
    assert_eq!(result.sessions[0].ai_session_id, "historical-match");
    assert!(!result.candidate_window_truncated);
    assert!(!result.truncated);
}

#[test]
fn search_ai_sessions_metadata_counts_only_filtered_matches() {
    let (pool, _dir) = test_pool();
    let mut entries = Vec::new();
    for i in 0..1_001 {
        entries.push(make_ai_entry(
            "2026-01-02T00:00:00Z",
            "host-a",
            "claude",
            "/tmp/unrelated",
            &format!("unrelated-{i}"),
            "scopedneedle",
        ));
    }
    entries.push(make_ai_entry(
        "2026-01-01T00:00:00Z",
        "host-a",
        "claude",
        "/tmp/selected",
        "selected-a",
        "scopedneedle",
    ));
    entries.push(make_ai_entry(
        "2026-01-01T00:01:00Z",
        "host-a",
        "claude",
        "/tmp/selected",
        "selected-b",
        "scopedneedle",
    ));
    insert_logs_batch(&pool, &entries).unwrap();
    refresh_ai_session_rollup(&pool).unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "scopedneedle".into(),
            ai_project: Some("/tmp/selected".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.total_candidates, 2);
    assert_eq!(result.candidate_rows, 2);
    assert_eq!(result.sessions.len(), 2);
    assert!(!result.candidate_window_truncated);
    assert!(!result.truncated);
}

#[test]
fn search_ai_sessions_candidate_cap_prefers_newer_rows() {
    let (pool, _dir) = test_pool();
    let mut entries = Vec::new();
    for i in 0..=5000 {
        entries.push(make_ai_entry(
            &format!("2026-01-01T00:{:02}:00Z", i % 60),
            "host-a",
            "claude",
            "/tmp/old",
            &format!("old-{i}"),
            "commontoken",
        ));
    }
    entries.push(make_ai_entry(
        "2026-01-02T00:00:00Z",
        "host-a",
        "claude",
        "/tmp/new",
        "newest",
        "commontoken",
    ));
    insert_logs_batch(&pool, &entries).unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "commontoken".into(),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();

    assert!(result.truncated);
    assert_eq!(result.candidate_cap, 5000);
    assert_eq!(result.candidate_rows, 5000);
    assert!(result.candidate_window_truncated);
    assert_eq!(result.sessions[0].ai_session_id, "newest");
    assert_eq!(result.sessions[0].ai_project, "/tmp/new");
}

// Regression: results must be ranked by match recency (latest matching row),
// not full-session last_seen. `stale-match` matched earlier but kept logging
// unrelated activity afterward; it must still rank below `recent-match`, whose
// match is newer. A pre-fix `ORDER BY last_seen DESC` ranked `stale-match`
// first because its non-matching tail is the newest activity overall.
#[test]
fn search_ai_sessions_orders_by_match_recency_not_session_activity() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            // Older match, but newest overall activity (non-matching tail).
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "stale-match",
                "orderneedle historical hit",
            ),
            make_ai_entry(
                "2026-01-03T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "stale-match",
                "routine unrelated activity",
            ),
            // Newer match, no later activity.
            make_ai_entry(
                "2026-01-02T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/project",
                "recent-match",
                "orderneedle fresh hit",
            ),
        ],
    )
    .unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "orderneedle".into(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.sessions.len(), 2);
    assert_eq!(result.sessions[0].ai_session_id, "recent-match");
    assert_eq!(result.sessions[1].ai_session_id, "stale-match");
    // The stale session's displayed last_seen still reflects its full-session
    // tail; only the ordering key changed.
    assert_eq!(result.sessions[1].last_seen, "2026-01-03T00:00:00Z");
}

#[test]
fn search_ai_sessions_zero_limit_clamps_to_one_with_metadata() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "claude",
            "/tmp/project",
            "sess-1",
            "zerolimit",
        )],
    )
    .unwrap();

    let result = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "zerolimit".into(),
            limit: Some(0),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.candidate_rows, 1);
    assert!(!result.truncated);
}

#[test]
fn search_ai_related_logs_batches_windows_and_caps_per_anchor() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "localhost",
                "codex",
                "/tmp/project",
                "sess-1",
                "anchor one deploy failure",
            ),
            make_entry(
                "2026-01-01T00:00:30Z",
                "host-a",
                "err",
                "deploy failed on host-a",
            ),
            make_entry(
                "2026-01-01T00:00:40Z",
                "host-a",
                "warning",
                "deploy warning on host-a",
            ),
            make_entry(
                "2026-01-01T00:00:50Z",
                "host-a",
                "info",
                "deploy info below severity",
            ),
            make_ai_entry(
                "2026-01-01T00:10:00Z",
                "localhost",
                "codex",
                "/tmp/project",
                "sess-2",
                "anchor two deploy failure",
            ),
            make_entry(
                "2026-01-01T00:10:30Z",
                "host-b",
                "err",
                "deploy failed on host-b",
            ),
        ],
    )
    .unwrap();

    let rows = search_ai_related_logs(
        &pool,
        &AiRelatedLogsParams {
            windows: vec![
                AiRelatedWindow {
                    anchor_index: 0,
                    anchor_time: "2026-01-01T00:00:00Z".into(),
                    window_from: "2026-01-01T00:00:00.000Z".into(),
                    window_to: "2026-01-01T00:01:00.000Z".into(),
                },
                AiRelatedWindow {
                    anchor_index: 1,
                    anchor_time: "2026-01-01T00:10:00Z".into(),
                    window_from: "2026-01-01T00:10:00.000Z".into(),
                    window_to: "2026-01-01T00:11:00.000Z".into(),
                },
            ],
            query: Some("deploy".into()),
            severity_in: vec!["err".into(), "warning".into()],
            limit_per_anchor: 1,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].anchor_index, 0);
    assert_eq!(rows[0].logs.len(), 1);
    assert_eq!(rows[0].logs[0].message, "deploy failed on host-a");
    assert!(rows[0].truncated);
    assert_eq!(rows[1].anchor_index, 1);
    assert_eq!(rows[1].logs.len(), 1);
    assert_eq!(rows[1].logs[0].message, "deploy failed on host-b");
    assert!(!rows[1].truncated);
}

#[test]
fn search_ai_related_logs_prefers_rows_nearest_the_anchor() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_entry("2026-01-01T00:05:01Z", "host-a", "info", "near-after"),
            make_entry("2026-01-01T00:09:59Z", "host-a", "info", "far-after"),
            make_entry("2026-01-01T00:04:58Z", "host-a", "info", "near-before"),
        ],
    )
    .unwrap();

    let rows = search_ai_related_logs(
        &pool,
        &AiRelatedLogsParams {
            windows: vec![AiRelatedWindow {
                anchor_index: 0,
                anchor_time: "2026-01-01T00:05:00Z".into(),
                window_from: "2026-01-01T00:00:00Z".into(),
                window_to: "2026-01-01T00:10:00Z".into(),
            }],
            severity_in: vec!["info".into()],
            limit_per_anchor: 2,
            ..Default::default()
        },
    )
    .unwrap();

    let messages: Vec<_> = rows[0]
        .logs
        .iter()
        .map(|row| row.message.as_str())
        .collect();
    assert_eq!(messages, vec!["near-after", "near-before"]);
    assert!(rows[0].truncated);
}

#[test]
fn search_ai_abuse_returns_same_session_context() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "before row",
            ),
            make_ai_entry(
                "2026-01-01T00:01:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "this shit needs context",
            ),
            make_ai_entry(
                "2026-01-01T00:02:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "after row",
            ),
            make_ai_entry(
                "2026-01-01T00:03:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-2",
                "other session row",
            ),
            make_ai_entry(
                "2026-01-01T00:04:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "assistant is not a abuse false positive",
            ),
        ],
    )
    .unwrap();

    let result = search_ai_abuse(
        &pool,
        &AiAbuseParams {
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(10),
            before: Some(1),
            after: Some(1),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.matches.len(), 1);
    let hit = &result.matches[0];
    assert_eq!(hit.term, "shit");
    assert_eq!(hit.entry.message, "this shit needs context");
    assert_eq!(hit.before.len(), 1);
    assert_eq!(hit.before[0].message, "before row");
    assert_eq!(hit.after.len(), 1);
    assert_eq!(hit.after[0].message, "after row");
}

#[test]
fn search_ai_abuse_truncates_only_when_additional_match_exists() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "one shit",
            ),
            make_ai_entry(
                "2026-01-01T00:01:00Z",
                "host-a",
                "codex",
                "/tmp/project",
                "sess-1",
                "plain row",
            ),
        ],
    )
    .unwrap();

    let exact = search_ai_abuse(
        &pool,
        &AiAbuseParams {
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(exact.matches.len(), 1);
    assert!(!exact.truncated);

    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:02:00Z",
            "host-a",
            "codex",
            "/tmp/project",
            "sess-1",
            "two shit",
        )],
    )
    .unwrap();
    let truncated = search_ai_abuse(
        &pool,
        &AiAbuseParams {
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(truncated.matches.len(), 1);
    assert!(truncated.truncated);
}

#[test]
fn search_ai_incidents_anchor_plan_uses_selective_fts_first() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            "codex",
            "/tmp/project",
            "sess-1",
            "tooling transcript row",
        )],
    )
    .unwrap();
    let params = AiIncidentParams {
        terms: vec!["tooling".into()],
        limit: Some(1),
        ..Default::default()
    };
    let terms = normalized_abuse_terms(&params.terms);
    let (sql, bindings) = ai_incident_anchor_sql(&params, &terms, 10_000);

    let conn = pool.get().unwrap();
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let plan = stmt
        .query_map(rusqlite::params_from_iter(bindings.iter()), |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n");

    assert!(
        plan.contains("SCAN logs_fts VIRTUAL TABLE"),
        "incident anchor query must drive from selective FTS terms; got:\n{plan}"
    );
    assert!(
        plan.contains("SEARCH l USING INTEGER PRIMARY KEY"),
        "incident anchor query must resolve FTS rowids by the logs primary key; got:\n{plan}"
    );
}

#[test]
fn investigate_ai_incidents_exact_id_can_fetch_beyond_top_ten() {
    let (pool, _dir) = test_pool();
    let entries = (0..12)
        .map(|i| {
            make_ai_entry(
                &format!("2026-01-01T00:{i:02}:00Z"),
                "host-a",
                "codex",
                "/tmp/project",
                &format!("sess-{i:02}"),
                "this shit needs assessment",
            )
        })
        .collect::<Vec<_>>();
    insert_logs_batch(&pool, &entries).unwrap();

    let listed = search_ai_incidents(
        &pool,
        &AiIncidentParams {
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(12),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(listed.incidents.len(), 12);
    let target_id = listed.incidents.last().unwrap().incident_id.clone();

    let top_ten = investigate_ai_incidents(
        &pool,
        &AiInvestigateParams {
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !top_ten
            .evidence
            .iter()
            .any(|bundle| bundle.incident.incident_id == target_id)
    );

    let exact = investigate_ai_incidents(
        &pool,
        &AiInvestigateParams {
            incident_id: Some(target_id.clone()),
            ai_project: Some("/tmp/project".into()),
            ai_tool: Some("codex".into()),
            limit: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(exact.evidence.len(), 1);
    assert_eq!(exact.evidence[0].incident.incident_id, target_id);
    assert_eq!(exact.evidence[0].anchors.len(), 1);
}

#[test]
fn ai_session_queries_respect_filters() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/a",
                "s1",
                "auth needle",
            ),
            make_ai_entry(
                "2026-01-01T01:00:00Z",
                "host-b",
                "codex",
                "/tmp/b",
                "s2",
                "auth needle",
            ),
            make_ai_entry(
                "2026-01-02T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/a",
                "s3",
                "auth needle",
            ),
        ],
    )
    .unwrap();

    let listed = list_ai_sessions(
        &pool,
        &ListAiSessionsParams {
            ai_project: Some("/tmp/a".into()),
            ai_tool: Some("claude".into()),
            host: Some("host-a".into()),
            since: Some("2026-01-01T00:00:00Z".into()),
            until: Some("2026-01-01T23:59:59Z".into()),
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].ai_session_id, "s1");

    let searched = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "needle".into(),
            ai_project: Some("/tmp/b".into()),
            ai_tool: Some("codex".into()),
            host: None,
            app: None,
            since: Some("2026-01-01T00:30:00Z".into()),
            until: Some("2026-01-01T01:30:00Z".into()),
            limit: Some(10),
        },
    )
    .unwrap();
    assert_eq!(searched.sessions.len(), 1);
    assert_eq!(searched.sessions[0].ai_session_id, "s2");
    assert_eq!(searched.sessions[0].hostname, "host-b");
}

#[test]
fn ai_session_list_and_search_surface_redacted_title_provenance() {
    let (pool, _dir) = test_pool();
    let mut entry = make_ai_entry(
        "2026-01-01T00:00:00Z",
        "host-a",
        "codex",
        "/tmp/project",
        "session-title",
        "storage latency investigation",
    );
    entry.metadata_json = Some(
        serde_json::json!({
            "session": {
                "title": "Investigate storage latency",
                "title_provenance": "user"
            }
        })
        .to_string(),
    );
    insert_logs_batch(&pool, &[entry]).unwrap();

    let listed = list_ai_sessions(
        &pool,
        &ListAiSessionsParams {
            since: Some("2025-12-31T00:00:00Z".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        listed[0].title.as_deref(),
        Some("Investigate storage latency")
    );
    assert_eq!(listed[0].title_provenance.as_deref(), Some("user"));

    refresh_ai_session_rollup(&pool).unwrap();
    let rolled_up = list_ai_sessions(&pool, &ListAiSessionsParams::default()).unwrap();
    assert_eq!(
        rolled_up[0].title.as_deref(),
        Some("Investigate storage latency")
    );
    assert_eq!(rolled_up[0].title_provenance.as_deref(), Some("user"));

    let searched = search_ai_sessions(
        &pool,
        &SearchAiSessionsParams {
            query: "latency".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        searched.sessions[0].title.as_deref(),
        Some("Investigate storage latency")
    );
    assert_eq!(
        searched.sessions[0].title_provenance.as_deref(),
        Some("user")
    );
}

#[test]
fn live_ai_session_list_keeps_title_and_provenance_from_latest_title_row() {
    let (pool, _dir) = test_pool();
    let mut older = make_ai_entry(
        "2026-01-01T00:00:00Z",
        "host-a",
        "claude",
        "/tmp/project",
        "session-title-history",
        "older event",
    );
    older.metadata_json = Some(
        serde_json::json!({
            "session": {
                "title": "Zulu older title",
                "title_provenance": "aaa-old"
            }
        })
        .to_string(),
    );
    let mut latest = make_ai_entry(
        "2026-01-01T00:01:00Z",
        "host-a",
        "claude",
        "/tmp/project",
        "session-title-history",
        "latest event",
    );
    latest.metadata_json = Some(
        serde_json::json!({
            "session": {
                "title": "Alpha latest title",
                "title_provenance": "zzz-new"
            }
        })
        .to_string(),
    );
    insert_logs_batch(&pool, &[older, latest]).unwrap();

    let listed = list_ai_sessions_live(
        &pool,
        &ListAiSessionsParams {
            since: Some("2025-12-31T00:00:00Z".into()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title.as_deref(), Some("Alpha latest title"));
    assert_eq!(listed[0].title_provenance.as_deref(), Some("zzz-new"));
}

#[test]
fn list_ai_tool_and_project_inventory() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_ai_entry(
                "2026-01-01T00:00:00Z",
                "host-a",
                "claude",
                "/tmp/a",
                "s1",
                "one",
            ),
            make_ai_entry(
                "2026-01-01T00:01:00Z",
                "host-a",
                "codex",
                "/tmp/b",
                "s2",
                "two",
            ),
            make_ai_entry(
                "2026-01-01T00:02:00Z",
                "host-a",
                "claude",
                "/tmp/a",
                "s1",
                "three",
            ),
        ],
    )
    .unwrap();

    let tools = list_ai_tools(&pool, &ListAiToolsParams::default()).unwrap();
    assert_eq!(tools.tools.len(), 2);
    let projects = list_ai_projects(
        &pool,
        &ListAiProjectsParams {
            ai_tool: Some("claude".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(projects.projects.len(), 1);
    assert_eq!(projects.projects[0].project, "/tmp/a");
}

#[test]
fn list_ai_inventory_reports_truncation() {
    // When truncated, total_X == len (the limit); truncated flag is authoritative.
    let (pool, _dir) = test_pool();
    let mut entries = Vec::new();
    for i in 0..201 {
        entries.push(make_ai_entry(
            "2026-01-01T00:00:00Z",
            "host-a",
            &format!("tool-{i:03}"),
            &format!("/tmp/project-{i:03}"),
            &format!("session-{i:03}"),
            "inventory",
        ));
    }
    insert_logs_batch(&pool, &entries).unwrap();

    let tools = list_ai_tools(&pool, &ListAiToolsParams::default()).unwrap();
    assert_eq!(tools.tools.len(), 100);
    assert_eq!(tools.total_tools, 100);
    assert!(tools.truncated);

    let projects = list_ai_projects(&pool, &ListAiProjectsParams::default()).unwrap();
    assert_eq!(projects.projects.len(), 200);
    assert_eq!(projects.total_projects, 200);
    assert!(projects.truncated);
}

#[test]
fn list_ai_sessions_groups_by_project_tool_session_and_hostname() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            LogBatchEntry {
                timestamp: "2026-05-11T00:00:00Z".into(),
                hostname: "devhost".into(),
                facility: Some("local7".into()),
                severity: "info".into(),
                app_name: Some("codex-transcript".into()),
                process_id: None,
                message: "{}".into(),
                raw: "{}".into(),
                source_ip: "10.0.0.1:514".into(),
                docker_checkpoint: None,
                ai_tool: Some("codex".into()),
                ai_project: Some("/home/jmagar/workspace/cortex".into()),
                ai_session_id: Some("abc".into()),
                ai_transcript_path: Some(
                    "/home/jmagar/.codex/sessions/2026/05/11/rollout-abc.jsonl".into(),
                ),
                metadata_json: None,
                http_status: None,
                auth_outcome: None,
                dns_blocked: None,
                event_action: None,
                parse_error: None,
            },
            LogBatchEntry {
                timestamp: "2026-05-11T00:01:00Z".into(),
                hostname: "devhost".into(),
                facility: Some("local7".into()),
                severity: "info".into(),
                app_name: Some("codex-transcript".into()),
                process_id: None,
                message: "{}".into(),
                raw: "{}".into(),
                source_ip: "10.0.0.1:514".into(),
                docker_checkpoint: None,
                ai_tool: Some("codex".into()),
                ai_project: Some("/home/jmagar/workspace/cortex".into()),
                ai_session_id: Some("abc".into()),
                ai_transcript_path: Some(
                    "/home/jmagar/.codex/sessions/2026/05/11/rollout-abc.jsonl".into(),
                ),
                metadata_json: None,
                http_status: None,
                auth_outcome: None,
                dns_blocked: None,
                event_action: None,
                parse_error: None,
            },
        ],
    )
    .unwrap();

    let rows = list_ai_sessions(
        &pool,
        &ListAiSessionsParams {
            ai_project: Some("/home/jmagar/workspace/cortex".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ai_tool, "codex");
    assert_eq!(rows[0].ai_session_id, "abc");
    assert_eq!(rows[0].event_count, 2);
    assert_eq!(rows[0].first_seen, "2026-05-11T00:00:00Z");
    assert_eq!(rows[0].last_seen, "2026-05-11T00:01:00Z");
}

// ---------------------------------------------------------------------------
// AI session rollup (bead cortex-2vre) correctness tests
// ---------------------------------------------------------------------------

/// Insert a spread of AI sessions across projects/tools/sessions/hosts so the
/// rollup vs live comparison exercises real grouping.
fn seed_ai_sessions(pool: &DbPool) {
    let mut batch = Vec::new();
    for s in 0..12u32 {
        let tool = if s % 2 == 0 { "codex" } else { "claude" };
        let project = format!("/proj/{}", s % 3);
        let session = format!("sess-{s}");
        let host = format!("host{}", s % 2);
        let event_count = 3 + s % 4;
        // Globally DISTINCT, strictly increasing timestamps per session so each
        // session's MAX(last_seen) is unique — no ordering ties between the
        // live and rollup paths (both order by last_seen DESC only).
        for e in 0..event_count {
            // Encode (session, event) into a unique minute/second so no two
            // rows across sessions share a timestamp.
            let total = s * 10 + e; // < 120, fits in minutes
            let ts = format!("2026-05-01T{:02}:{:02}:00Z", total / 60, total % 60);
            batch.push(make_ai_entry(
                &ts,
                &host,
                tool,
                &project,
                &session,
                &format!("event {e} of {session}"),
            ));
        }
    }
    insert_logs_batch(pool, &batch).unwrap();
}

fn default_session_params() -> ListAiSessionsParams {
    ListAiSessionsParams {
        ai_project: None,
        ai_tool: None,
        host: None,
        since: None,
        until: None,
        limit: Some(100),
    }
}

#[test]
fn rollup_result_equals_live_aggregation() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);

    // Before refresh: rollup empty => list_ai_sessions falls back to live.
    let pre = list_ai_sessions(&pool, &default_session_params()).unwrap();
    let live = list_ai_sessions_live(&pool, &default_session_params()).unwrap();
    assert_eq!(
        pre.len(),
        live.len(),
        "fallback must match live before refresh"
    );

    // After refresh: list_ai_sessions serves from the rollup and must match.
    let total = refresh_ai_session_rollup(&pool).unwrap();
    assert_eq!(total, live.len(), "rollup row count must equal #sessions");
    assert_eq!(
        ai_session_rollup_status(&pool).unwrap().row_count,
        total as i64
    );

    let rolled = list_ai_sessions(&pool, &default_session_params()).unwrap();
    assert_eq!(rolled.len(), live.len());
    for (l, r) in live.iter().zip(rolled.iter()) {
        assert_eq!(l.ai_project, r.ai_project);
        assert_eq!(l.ai_tool, r.ai_tool);
        assert_eq!(l.ai_session_id, r.ai_session_id);
        assert_eq!(l.hostname, r.hostname);
        assert_eq!(l.first_seen, r.first_seen, "first_seen drift");
        assert_eq!(l.last_seen, r.last_seen, "last_seen drift");
        assert_eq!(l.event_count, r.event_count, "event_count drift");
        assert_eq!(l.ai_transcript_path, r.ai_transcript_path);
    }
}

#[test]
fn rollup_status_reports_refresh_time() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);

    // Never refreshed => no staleness timestamp.
    assert!(
        ai_session_rollup_status(&pool)
            .unwrap()
            .refreshed_at
            .is_none()
    );

    refresh_ai_session_rollup(&pool).unwrap();
    let status = ai_session_rollup_status(&pool).unwrap();
    assert!(status.refreshed_at.is_some(), "refreshed_at must be set");
    assert!(status.row_count > 0);
    assert!(status.summary().contains("refreshed"));
}

/// The key correctness guarantee the design rests on: a REFRESH-based rollup
/// stays exact under DELETE, including when the deleted rows held a session's
/// MIN/MAX timestamp — the exact case where a trigger-maintained rollup would
/// silently corrupt first_seen/last_seen.
#[test]
fn rollup_is_exact_after_deletes_recompute_min_max() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup(&pool).unwrap();

    // Delete the single newest event of every session (the rows holding MAX
    // timestamp) plus the oldest of one session (holding MIN). A stale rollup
    // would keep the now-deleted extremes; a refresh must recompute them.
    {
        let conn = pool.get().unwrap();
        // Delete the global newest 12 rows (roughly the MAX-holding rows).
        conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs
                 WHERE ai_session_id IS NOT NULL
                 ORDER BY timestamp DESC LIMIT 12
             )",
            [],
        )
        .unwrap();
        // Delete the global oldest row (a MIN-holding row).
        conn.execute(
            "DELETE FROM logs WHERE id IN (
                 SELECT id FROM logs
                 WHERE ai_session_id IS NOT NULL
                 ORDER BY timestamp ASC LIMIT 1
             )",
            [],
        )
        .unwrap();
    }

    // Stale rollup (not yet refreshed) may now disagree with live — prove the
    // refresh restores exactness against a fresh live aggregation.
    refresh_ai_session_rollup(&pool).unwrap();
    let live = list_ai_sessions_live(&pool, &default_session_params()).unwrap();
    let rolled = list_ai_sessions(&pool, &default_session_params()).unwrap();
    assert_eq!(live.len(), rolled.len(), "post-delete row count mismatch");
    for (l, r) in live.iter().zip(rolled.iter()) {
        assert_eq!(l.ai_session_id, r.ai_session_id);
        assert_eq!(
            l.first_seen, r.first_seen,
            "MIN not recomputed after delete"
        );
        assert_eq!(l.last_seen, r.last_seen, "MAX not recomputed after delete");
        assert_eq!(
            l.event_count, r.event_count,
            "count not recomputed after delete"
        );
    }
}

/// The staging+swap refresh (bead syslog-mcp-rvcz) MUST stay a correct FULL
/// recompute under retention DELETEs — the exact case a watermark-incremental
/// refresh would silently corrupt. This is the test that distinguishes the
/// (correct) staging+swap from the (corrupt) incremental trap:
///   * purge the OLDEST rows of a SURVIVING session  -> first_seen must advance
///     to the surviving MIN (an append-keyed incremental would keep the stale
///     deleted minimum);
///   * fully purge ANOTHER session's rows entirely    -> its rollup row must be
///     EVICTED (an append-keyed incremental would leave a ghost session);
///   * event_count must equal the live COUNT(*)        -> no upward drift.
///
/// The post-refresh rollup must be byte-for-byte equal to a from-scratch live
/// aggregation over the surviving rows.
#[test]
fn rollup_stays_correct_under_concurrent_retention() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    // Initial full materialization (all 12 seeded sessions present).
    refresh_ai_session_rollup(&pool).unwrap();
    let sessions_before = list_ai_sessions(&pool, &default_session_params())
        .unwrap()
        .len();
    assert!(
        sessions_before >= 2,
        "need >=2 sessions to exercise eviction"
    );

    // Pick a SURVIVING session and capture its current first_seen + the
    // timestamp of its single oldest row (which we will purge).
    let (surviving, old_first_seen, oldest_ts): (String, String, String) = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT ai_session_id, MIN(timestamp) FROM logs
             WHERE ai_session_id IS NOT NULL GROUP BY ai_session_id
             ORDER BY COUNT(*) DESC LIMIT 1",
            [],
            |r| {
                let sid: String = r.get(0)?;
                let min_ts: String = r.get(1)?;
                Ok((sid.clone(), min_ts.clone(), min_ts))
            },
        )
        .unwrap()
    };

    // Pick a DIFFERENT session to fully purge.
    let purged: String = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT ai_session_id FROM logs
             WHERE ai_session_id IS NOT NULL AND ai_session_id != ?1
             LIMIT 1",
            params![surviving],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_ne!(surviving, purged);

    // Retention purge (mimics maintenance.rs deleting oldest/budget rows with
    // NO severity exemption): drop the oldest row of the surviving session AND
    // every row of the purged session.
    {
        let conn = pool.get().unwrap();
        let dropped_old = conn
            .execute(
                "DELETE FROM logs
                 WHERE ai_session_id = ?1 AND timestamp = ?2",
                params![surviving, oldest_ts],
            )
            .unwrap();
        assert!(
            dropped_old >= 1,
            "must purge the surviving session's oldest row"
        );
        let dropped_all = conn
            .execute("DELETE FROM logs WHERE ai_session_id = ?1", params![purged])
            .unwrap();
        assert!(dropped_all >= 1, "must fully purge the other session");
    }

    // Refresh AFTER the purge. A correct full recompute (staging+swap) restores
    // exactness; the incremental trap would not.
    refresh_ai_session_rollup(&pool).unwrap();

    let rolled = list_ai_sessions(&pool, &default_session_params()).unwrap();
    let live = list_ai_sessions_live(&pool, &default_session_params()).unwrap();

    // (1) Ghost eviction: the fully-purged session must NOT remain in the rollup.
    assert!(
        rolled.iter().all(|s| s.ai_session_id != purged),
        "fully-purged session must be evicted from the rollup (no ghost row)"
    );
    assert_eq!(
        rolled.len(),
        sessions_before - 1,
        "exactly one session should have been evicted"
    );

    // (2) first_seen advanced: the surviving session's MIN must move past the
    // now-deleted oldest row.
    let surv = rolled
        .iter()
        .find(|s| s.ai_session_id == surviving)
        .expect("surviving session must remain in the rollup");
    assert_ne!(
        surv.first_seen, old_first_seen,
        "first_seen must advance after the oldest row was purged (incremental \
         would keep the stale minimum)"
    );
    let live_surv = live
        .iter()
        .find(|s| s.ai_session_id == surviving)
        .expect("surviving session must be in live aggregation");
    assert_eq!(
        surv.first_seen, live_surv.first_seen,
        "first_seen must equal the surviving MIN(timestamp)"
    );

    // (3) Byte-for-byte equal to a from-scratch live recompute over survivors.
    assert_eq!(
        rolled.len(),
        live.len(),
        "row count must match live recompute"
    );
    for (r, l) in rolled.iter().zip(live.iter()) {
        assert_eq!(r.ai_session_id, l.ai_session_id);
        assert_eq!(r.first_seen, l.first_seen, "first_seen drift vs live");
        assert_eq!(r.last_seen, l.last_seen, "last_seen drift vs live");
        assert_eq!(
            r.event_count, l.event_count,
            "event_count must equal actual COUNT(*) (no drift)"
        );
    }
}

/// Regression for the R1 guard (bead syslog-mcp-rvcz): rows that carry
/// `ai_project` but have NO recognized `ai_tool`/`ai_session_id` (e.g. OTLP
/// logs with only project.path) are counted by the broad `ai_rows_watermark`
/// predicate but correctly EXCLUDED by the rollup's full GROUP BY predicate.
/// The old guard compared `staged` against the broad watermark `src_count`, so
/// for this data shape `staged == 0` while `src_count > 0` and the refresh
/// ERRORED forever. A legitimately-empty rollup must SUCCEED (returning 0 and
/// still stamping the meta/fingerprint), not raise the R1 error.
#[test]
fn rollup_empty_when_only_broad_project_rows_present_succeeds() {
    let (pool, _dir) = test_pool();

    // Insert rows with ai_project set but ai_tool / ai_session_id EMPTY. These
    // match the broad watermark predicate (ai_project NOT NULL/!='') but fail
    // the full rollup predicate (which also requires ai_tool and ai_session_id
    // NOT NULL/!=''), so the staging GROUP BY yields zero groups.
    let batch = vec![
        // empty ai_tool
        make_ai_entry(
            "2026-05-01T00:00:00Z",
            "host0",
            "",
            "/proj/a",
            "sess-1",
            "otlp event, no tool",
        ),
        // empty ai_session_id
        make_ai_entry(
            "2026-05-01T00:01:00Z",
            "host0",
            "claude",
            "/proj/a",
            "",
            "otlp event, no session",
        ),
        // both empty
        make_ai_entry(
            "2026-05-01T00:02:00Z",
            "host1",
            "",
            "/proj/b",
            "",
            "otlp event, project only",
        ),
    ];
    insert_logs_batch(&pool, &batch).unwrap();

    // The watermark sees these rows (broad predicate) so src_count > 0; the
    // rollup predicate excludes them all so staging is legitimately empty.
    // Pre-fix this raised the R1 error; post-fix it must SUCCEED with 0 rows.
    let total = refresh_ai_session_rollup(&pool).unwrap();
    assert_eq!(
        total, 0,
        "rollup must be legitimately empty (no rollup-eligible rows)"
    );

    // The meta/fingerprint MUST still be stamped on an empty rollup so
    // refresh_ai_session_rollup_if_stale can skip subsequent no-op refreshes.
    let status = ai_session_rollup_status(&pool).unwrap();
    assert_eq!(status.row_count, 0, "rollup row_count must be 0");
    assert!(
        status.refreshed_at.is_some(),
        "meta/fingerprint must be stamped even for an empty rollup"
    );
}

#[test]
fn rollup_read_uses_last_seen_index_no_temp_btree() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup(&pool).unwrap();
    // The unbounded rollup read must be served by the last_seen index, NOT a
    // temp b-tree sort (the cost that plagued the live aggregation). The query
    // mirrors list_ai_sessions_from_rollup.
    let plan = query_plan(
        &pool,
        "SELECT ai_project, ai_tool, ai_session_id, ai_transcript_path,
                hostname, first_seen, last_seen, event_count
         FROM ai_session_rollup
         WHERE 1=1
         ORDER BY last_seen DESC LIMIT 100",
        &[],
    );
    assert!(
        plan.contains("idx_ai_session_rollup_last_seen"),
        "rollup read must use the last_seen index; plan was:\n{plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE"),
        "rollup read must avoid a temp b-tree sort; plan was:\n{plan}"
    );
}

#[test]
fn rollup_respects_project_and_tool_filters() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup(&pool).unwrap();

    for (project, tool) in [
        (Some("/proj/0".to_string()), None),
        (None, Some("codex".to_string())),
        (Some("/proj/1".to_string()), Some("claude".to_string())),
    ] {
        let params = ListAiSessionsParams {
            ai_project: project.clone(),
            ai_tool: tool.clone(),
            ..default_session_params()
        };
        let live = list_ai_sessions_live(&pool, &params).unwrap();
        let rolled = list_ai_sessions(&pool, &params).unwrap();
        assert_eq!(
            live.iter().map(|s| &s.ai_session_id).collect::<Vec<_>>(),
            rolled.iter().map(|s| &s.ai_session_id).collect::<Vec<_>>(),
            "filtered rollup ({project:?},{tool:?}) must match live"
        );
    }
}

#[test]
fn time_windowed_sessions_always_use_live_path() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup(&pool).unwrap();

    // Insert a brand-new event AFTER the rollup was built. A time-windowed
    // query must see it live (rollup is stale and must be bypassed).
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-06-01T12:00:00Z",
            "host0",
            "codex",
            "/proj/0",
            "sess-0",
            "fresh post-refresh event",
        )],
    )
    .unwrap();

    let windowed = ListAiSessionsParams {
        since: Some("2026-06-01T00:00:00Z".into()),
        until: Some("2026-06-02T00:00:00Z".into()),
        ..default_session_params()
    };
    let rows = list_ai_sessions(&pool, &windowed).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "windowed query must see the fresh event live"
    );
    assert_eq!(rows[0].last_seen, "2026-06-01T12:00:00Z");
    assert_eq!(
        rows[0].event_count, 1,
        "windowed count must be live, not rollup"
    );
}

// ---------------------------------------------------------------------------
// Rollup source-watermark dirty-check (bead cortex-g33v)
// ---------------------------------------------------------------------------

/// Helper: insert a single non-AI log row (no ai_* fields). Such rows must NOT
/// move the AI watermark, so a refresh that follows them is skipped.
fn insert_plain_log(pool: &DbPool, ts: &str, msg: &str) {
    insert_logs_batch(pool, &[make_entry(ts, "host0", "info", msg)]).unwrap();
}

#[test]
fn stale_check_first_refresh_runs_then_noop_is_skipped() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);

    // Never refreshed yet => must refresh.
    match refresh_ai_session_rollup_if_stale(&pool).unwrap() {
        RollupRefresh::Refreshed { row_count } => assert!(row_count > 0),
        RollupRefresh::Skipped => panic!("first refresh must not be skipped"),
    }

    // Nothing changed => the expensive re-aggregation must be skipped.
    assert_eq!(
        refresh_ai_session_rollup_if_stale(&pool).unwrap(),
        RollupRefresh::Skipped,
        "unchanged source must skip the refresh"
    );
}

#[test]
fn stale_check_detects_new_ai_row() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup_if_stale(&pool).unwrap();
    assert_eq!(
        refresh_ai_session_rollup_if_stale(&pool).unwrap(),
        RollupRefresh::Skipped
    );

    // A new AI row advances MAX(id) => must refresh.
    insert_logs_batch(
        &pool,
        &[make_ai_entry(
            "2026-07-01T00:00:00Z",
            "host9",
            "codex",
            "/proj/new",
            "sess-new",
            "brand new ai event",
        )],
    )
    .unwrap();
    assert!(
        matches!(
            refresh_ai_session_rollup_if_stale(&pool).unwrap(),
            RollupRefresh::Refreshed { .. }
        ),
        "a new AI row must trigger a refresh"
    );
    // And the new session is now visible from the rollup path.
    let rows = list_ai_sessions(&pool, &default_session_params()).unwrap();
    assert!(rows.iter().any(|s| s.ai_session_id == "sess-new"));
}

#[test]
fn stale_check_detects_deleted_ai_row() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup_if_stale(&pool).unwrap();
    assert_eq!(
        refresh_ai_session_rollup_if_stale(&pool).unwrap(),
        RollupRefresh::Skipped
    );

    // Deleting an AI row changes COUNT(*) (and likely MAX(id)) => must refresh.
    {
        let conn = pool.get().unwrap();
        let deleted = conn
            .execute(
                "DELETE FROM logs WHERE id IN (
                     SELECT id FROM logs WHERE ai_session_id IS NOT NULL LIMIT 1
                 )",
                [],
            )
            .unwrap();
        assert_eq!(deleted, 1, "test must delete exactly one AI row");
    }
    assert!(
        matches!(
            refresh_ai_session_rollup_if_stale(&pool).unwrap(),
            RollupRefresh::Refreshed { .. }
        ),
        "a deleted AI row must trigger a refresh"
    );
}

#[test]
fn stale_check_ignores_non_ai_rows() {
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup_if_stale(&pool).unwrap();

    // Plain syslog rows (the overwhelming majority of ingest) must NOT force a
    // re-aggregation — that is the whole point of an AI-scoped watermark.
    insert_plain_log(&pool, "2026-07-01T00:00:00Z", "ordinary syslog line");
    insert_plain_log(&pool, "2026-07-01T00:00:01Z", "another ordinary line");
    assert_eq!(
        refresh_ai_session_rollup_if_stale(&pool).unwrap(),
        RollupRefresh::Skipped,
        "non-AI ingest must not trigger a rollup refresh"
    );
}

#[test]
fn stale_check_watermark_is_index_only_no_table_scan() {
    // The watermark fingerprint must be cheap: served from the partial index
    // idx_logs_ai_project_time (WHERE ai_project IS NOT NULL), NOT a full scan
    // of `logs`. That index-only cost is the whole reason the dirty-check is
    // worth running on every cadence tick. Mirrors ai_rows_watermark's query.
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    let plan = query_plan(
        &pool,
        "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM logs
         WHERE ai_project IS NOT NULL AND ai_project != ''",
        &[],
    );
    assert!(
        plan.contains("idx_logs_ai_project_time"),
        "watermark must use the AI partial index; plan was:\n{plan}"
    );
    assert!(
        !plan.contains("SCAN logs\n") && !plan.ends_with("SCAN logs"),
        "watermark must not full-scan logs; plan was:\n{plan}"
    );
}

#[test]
fn stale_check_skip_keeps_rollup_correct_vs_live() {
    // A skipped refresh must leave the rollup serving results identical to a
    // fresh live aggregation (i.e. skipping never serves stale data when the
    // source genuinely did not change).
    let (pool, _dir) = test_pool();
    seed_ai_sessions(&pool);
    refresh_ai_session_rollup_if_stale(&pool).unwrap();
    assert_eq!(
        refresh_ai_session_rollup_if_stale(&pool).unwrap(),
        RollupRefresh::Skipped
    );

    let live = list_ai_sessions_live(&pool, &default_session_params()).unwrap();
    let rolled = list_ai_sessions(&pool, &default_session_params()).unwrap();
    assert_eq!(live.len(), rolled.len());
    for (l, r) in live.iter().zip(rolled.iter()) {
        assert_eq!(l.ai_session_id, r.ai_session_id);
        assert_eq!(l.last_seen, r.last_seen);
        assert_eq!(l.event_count, r.event_count);
    }
}

// ---------------------------------------------------------------------------
// RAG v1 tests
// ---------------------------------------------------------------------------

fn make_app_entry(ts: &str, host: &str, severity: &str, app: &str, msg: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: Some(app.to_string()),
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: "10.0.0.1:514".to_string(),
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
    }
}

#[test]
fn similar_incidents_clusters_returns_clusters_for_matching_logs() {
    let (pool, _dir) = test_pool();

    let logs = vec![
        make_app_entry(
            "2024-01-15T10:00:00Z",
            "web-01",
            "err",
            "nginx",
            "upstream connect error timeout",
        ),
        make_app_entry(
            "2024-01-15T10:05:00Z",
            "web-01",
            "crit",
            "nginx",
            "upstream connect error connection refused",
        ),
    ];
    insert_logs_batch(&pool, &logs).unwrap();

    let params = SimilarIncidentsParams {
        query: "upstream".into(),
        host: None,
        app: None,
        severity_min: None,
        since: None,
        until: None,
        window_minutes: Some(30),
        limit: Some(10),
    };
    let result = similar_incidents_clusters(&pool, &params).unwrap();
    assert!(!result.clusters.is_empty(), "expected at least one cluster");
    let cluster = &result.clusters[0];
    assert_eq!(cluster.hostname, "web-01");
    assert_eq!(cluster.app_name.as_deref(), Some("nginx"));
    assert!(cluster.log_count >= 2);
    // "crit" is more severe than "err"
    assert_eq!(cluster.severity_peak, "crit");
}

#[test]
fn similar_incidents_clusters_filters_by_hostname() {
    let (pool, _dir) = test_pool();

    let logs = vec![
        make_app_entry(
            "2024-01-15T10:00:00Z",
            "web-01",
            "err",
            "nginx",
            "upstream connect error",
        ),
        make_app_entry(
            "2024-01-15T10:01:00Z",
            "web-02",
            "err",
            "nginx",
            "upstream connect error",
        ),
    ];
    insert_logs_batch(&pool, &logs).unwrap();

    let params = SimilarIncidentsParams {
        query: "upstream".into(),
        host: Some("web-01".into()),
        ..Default::default()
    };
    let result = similar_incidents_clusters(&pool, &params).unwrap();
    assert!(result.clusters.iter().all(|c| c.hostname == "web-01"));
}

#[test]
fn similar_incidents_applies_fts_before_candidate_cap() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[make_app_entry(
            "2024-01-01T00:00:00Z",
            "web-01",
            "err",
            "nginx",
            "historicalincidentneedle connection refused",
        )],
    )
    .unwrap();

    // Populate exactly the old raw-log candidate cap with newer nonmatches.
    // A recency cap applied before FTS excludes the historical match above.
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "WITH digits(d) AS (
             VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
         ),
         rows(n) AS (
             SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d
             FROM digits a
             CROSS JOIN digits b
             CROSS JOIN digits c
             CROSS JOIN digits d
             CROSS JOIN digits e
         )
         INSERT INTO logs
             (timestamp, hostname, severity, app_name, message, raw, source_ip)
         SELECT '2024-01-02T00:00:00Z', 'web-01', 'info', 'nginx',
                'routine health check', 'routine health check', '10.0.0.1:514'
         FROM rows;",
    )
    .unwrap();
    drop(conn);

    let result = similar_incidents_clusters(
        &pool,
        &SimilarIncidentsParams {
            query: "historicalincidentneedle".into(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.clusters.len(), 1);
    assert_eq!(result.clusters[0].window_start, "2024-01-01T00:00:00Z");
    assert_eq!(result.clusters[0].log_count, 1);
}

#[test]
fn incident_context_summary_returns_window_stats() {
    let (pool, _dir) = test_pool();

    let logs = vec![
        make_app_entry(
            "2024-02-01T08:00:00Z",
            "db-01",
            "err",
            "postgres",
            "FATAL: out of shared memory",
        ),
        make_app_entry(
            "2024-02-01T08:01:00Z",
            "db-01",
            "info",
            "postgres",
            "database system is ready",
        ),
    ];
    insert_logs_batch(&pool, &logs).unwrap();

    let params = IncidentContextParams {
        since: "2024-02-01T07:00:00Z".into(),
        until: "2024-02-01T09:00:00Z".into(),
        host: None,
        app: None,
        query: None,
        severity_min: Some("err".into()),
        limit: Some(10),
    };
    let result = incident_context_summary(&pool, &params).unwrap();
    assert_eq!(result.total_logs, 2);
    assert!(!result.by_severity.is_empty());
    // Only the "err" row should be in error_logs (not "info")
    assert_eq!(result.error_logs.len(), 1);
    assert_eq!(result.error_logs[0].message, "FATAL: out of shared memory");
}

#[test]
fn incident_context_summary_empty_window_returns_zero() {
    let (pool, _dir) = test_pool();

    let params = IncidentContextParams {
        since: "2020-01-01T00:00:00Z".into(),
        until: "2020-01-02T00:00:00Z".into(),
        ..Default::default()
    };
    let result = incident_context_summary(&pool, &params).unwrap();
    assert_eq!(result.total_logs, 0);
    assert!(result.error_logs.is_empty());
    assert!(result.ai_sessions.is_empty());
}

#[test]
fn incident_context_summary_filters_error_logs_by_fts_query() {
    let (pool, _dir) = test_pool();
    insert_logs_batch(
        &pool,
        &[
            make_app_entry(
                "2024-02-01T08:00:00Z",
                "db-01",
                "err",
                "postgres",
                "shared memory exhausted",
            ),
            make_app_entry(
                "2024-02-01T08:01:00Z",
                "db-01",
                "err",
                "postgres",
                "connection pool exhausted",
            ),
        ],
    )
    .unwrap();

    let result = incident_context_summary(
        &pool,
        &IncidentContextParams {
            since: "2024-02-01T07:00:00Z".into(),
            until: "2024-02-01T09:00:00Z".into(),
            query: Some("memory".into()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(result.total_logs, 2, "window aggregates remain unfiltered");
    assert_eq!(result.error_logs.len(), 1);
    assert_eq!(result.error_logs[0].message, "shared memory exhausted");
}

#[test]
fn incident_context_window_queries_force_timestamp_index() {
    let (pool, _dir) = test_pool();
    let plan = query_plan(
        &pool,
        "SELECT COUNT(*)
         FROM logs INDEXED BY idx_logs_timestamp
         WHERE (ai_project IS NULL OR ai_project = '')
           AND timestamp BETWEEN ?1 AND ?2",
        &[
            rusqlite::types::Value::Text("2024-02-01T07:00:00Z".into()),
            rusqlite::types::Value::Text("2024-02-01T09:00:00Z".into()),
        ],
    );
    assert!(
        plan.contains("idx_logs_timestamp"),
        "incident context window scan should be timestamp-index driven; got:\n{plan}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Performance benchmark harness (Issue 4 / bead cortex-2vre).
//
// Builds a synthetic on-disk SQLite DB with a realistic row count and times
// `get_stats` and `list_ai_sessions` before/after the optimization work.
//
// IGNORED by default — it builds millions of rows and takes minutes, so it
// must never run in the normal `cargo nextest` suite. Run explicitly:
//
//   CORTEX_BENCH_ROWS=10000000 cargo test --lib \
//       db::queries::tests::bench_stats_and_sessions -- --ignored --nocapture
//
// Row count is controlled by CORTEX_BENCH_ROWS (default 5_000_000).
// ───────────────────────────────────────────────────────────────────────────

/// Insert `n` synthetic log rows through the live schema (FTS + inventory +
/// counter triggers all fire), in large transactions for throughput. ~20% of
/// rows carry AI session fields spread across many (project, tool, session)
/// groups so the sessions query has realistic cardinality.
fn bench_seed_rows(pool: &DbPool, n: usize) {
    use std::time::Instant;
    let started = Instant::now();
    const CHUNK: usize = 50_000;
    let mut inserted = 0usize;
    while inserted < n {
        let this = CHUNK.min(n - inserted);
        let mut conn = pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO logs (timestamp, hostname, facility, severity, app_name,
                        process_id, message, raw, received_at, source_ip,
                        ai_tool, ai_project, ai_session_id, ai_transcript_path)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                )
                .unwrap();
            for i in 0..this {
                let x = inserted + i;
                // Strictly-increasing timestamp per row (base + x seconds, full
                // date rollover). Monotonic in `x` => each session's MAX(ts) is
                // globally unique (no last_seen ties), so the rollup vs live
                // top-N comparison is deterministic at the LIMIT boundary.
                let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap();
                let dt = base + chrono::TimeDelta::seconds(x as i64);
                let ts = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
                let recv = ts.clone();
                let host = format!("host{:02}", x % 25);
                let app = format!("app{:02}", x % 60);
                let msg = format!("synthetic log line {x} some error retry connection text");
                let is_ai = x.is_multiple_of(5);
                let (tool, proj, sess, tpath): (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ) = if is_ai {
                    let proj = format!("/proj/{}", x % 40);
                    let tool = if x.is_multiple_of(2) {
                        "codex"
                    } else {
                        "claude"
                    }
                    .to_string();
                    // ~20k distinct sessions => realistic group cardinality.
                    let sess = format!("sess-{}", x % 20_000);
                    let tpath = format!("{proj}/{sess}.jsonl");
                    (Some(tool), Some(proj), Some(sess), Some(tpath))
                } else {
                    (None, None, None, None)
                };
                stmt.execute(rusqlite::params![
                    ts,
                    host,
                    Option::<String>::None,
                    "info",
                    app,
                    Option::<String>::None,
                    msg,
                    "raw",
                    recv,
                    "10.0.0.1:514",
                    tool,
                    proj,
                    sess,
                    tpath,
                ])
                .unwrap();
            }
        }
        tx.commit().unwrap();
        inserted += this;
    }
    eprintln!(
        "[bench] seeded {inserted} rows in {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

#[derive(Debug)]
struct BenchPercentiles {
    p50_ms: f64,
    p95_ms: f64,
}

/// p50/p95 of N timed runs of `f`, in milliseconds. One warm-up run first.
/// Uses nearest-rank p95 so the emitted values remain reproducible from the
/// captured sample count without interpolating measurements that never ran.
fn bench_percentiles_ms(runs: usize, mut f: impl FnMut()) -> BenchPercentiles {
    use std::time::Instant;
    assert!(runs > 0);
    f(); // warm-up
    let mut samples: Vec<f64> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50_index = (samples.len() - 1) / 2;
    let p95_index = ((samples.len() * 95).div_ceil(100)).saturating_sub(1);
    BenchPercentiles {
        p50_ms: samples[p50_index],
        p95_ms: samples[p95_index],
    }
}

#[test]
fn session_rollup_query_plan_uses_ordering_index_without_temp_sort() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&test_storage_config(dir.path().join("plan.db"))).unwrap();
    let conn = pool.get().unwrap();
    let plan = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT ai_project, ai_tool, ai_session_id, hostname, last_seen
             FROM ai_session_rollup
             WHERE 1=1
             ORDER BY last_seen DESC LIMIT 100",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|detail| detail.contains("idx_ai_session_rollup_last_seen")),
        "rollup query must use its last-seen index: {plan:?}"
    );
    assert!(
        plan.iter()
            .all(|detail| !detail.contains("USE TEMP B-TREE")),
        "rollup query must not perform a temporary sort: {plan:?}"
    );
}

#[test]
#[ignore = "performance benchmark; builds millions of rows. Run with --ignored."]
fn bench_stats_and_sessions() {
    let rows: usize = crate::env::var("CORTEX_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000_000);

    // Optional persistent DB path so a seeded DB can be reused across runs
    // (seeding 10M rows takes ~13 min). When unset, use a throwaway tempdir.
    let _guard_dir;
    let (pool, cfg) = if let Ok(path) = crate::env::var("CORTEX_BENCH_DB") {
        let db_path = std::path::PathBuf::from(&path);
        let fresh = !db_path.exists();
        let cfg = test_storage_config(db_path);
        let pool = init_pool(&cfg).unwrap();
        if fresh {
            bench_seed_rows(&pool, rows);
        } else {
            eprintln!("[bench] reusing existing DB at {path} (skipping seed)");
        }
        (pool, cfg)
    } else {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_storage_config(dir.path().join("test.db"));
        let pool = init_pool(&cfg).unwrap();
        bench_seed_rows(&pool, rows);
        _guard_dir = dir; // keep alive
        (pool, cfg)
    };

    let ground_truth: i64 = {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get(0))
            .unwrap()
    };
    eprintln!("[bench] ground-truth COUNT(*) FROM logs = {ground_truth}");

    // --- stats (default: FTS diagnostic skipped) ---
    let mut last_stats = None;
    let stats_latency = bench_percentiles_ms(20, || {
        last_stats = Some(get_stats(&pool, &cfg).unwrap());
    });
    let stats = last_stats.unwrap();
    eprintln!(
        "[bench] get_stats (default, FTS skipped): p50={:.1} ms p95={:.1} ms (total_logs={})",
        stats_latency.p50_ms, stats_latency.p95_ms, stats.total_logs
    );
    assert_eq!(
        stats.total_logs, ground_truth,
        "stats total_logs must equal ground-truth COUNT(*)"
    );

    // --- stats with FTS diagnostic ON (the expensive COUNT(*) FROM logs_fts) ---
    let stats_fts_latency = bench_percentiles_ms(20, || {
        let _ = get_stats_with_options(&pool, &cfg, true).unwrap();
    });
    eprintln!(
        "[bench] get_stats (FTS diagnostic ON): p50={:.1} ms p95={:.1} ms",
        stats_fts_latency.p50_ms, stats_fts_latency.p95_ms
    );

    // --- sessions BEFORE: live aggregation (GROUP BY + temp-btree sort) ---
    let params = ListAiSessionsParams {
        ai_project: None,
        ai_tool: None,
        host: None,
        since: None,
        until: None,
        limit: Some(100),
    };
    let mut live_rows = 0usize;
    let sessions_live_latency = bench_percentiles_ms(20, || {
        live_rows = list_ai_sessions_live(&pool, &params).unwrap().len();
    });
    eprintln!(
        "[bench] BEFORE list_ai_sessions_live(limit=100): p50={:.1} ms p95={:.1} ms ({live_rows} rows)",
        sessions_live_latency.p50_ms, sessions_live_latency.p95_ms
    );

    // --- refresh cost (background cadence; not on the request path) ---
    let mut rollup_total = 0usize;
    let refresh_latency = bench_percentiles_ms(10, || {
        rollup_total = refresh_ai_session_rollup(&pool).unwrap();
    });
    eprintln!(
        "[bench] refresh_ai_session_rollup: p50={:.1} ms p95={:.1} ms ({rollup_total} session rows total)",
        refresh_latency.p50_ms, refresh_latency.p95_ms
    );

    // --- sessions AFTER: indexed read from the rollup materialization ---
    let mut rollup_rows = 0usize;
    let sessions_rollup_latency = bench_percentiles_ms(20, || {
        rollup_rows = list_ai_sessions(&pool, &params).unwrap().len();
    });
    eprintln!(
        "[bench] AFTER list_ai_sessions(rollup, limit=100): p50={:.1} ms p95={:.1} ms ({rollup_rows} rows)",
        sessions_rollup_latency.p50_ms, sessions_rollup_latency.p95_ms
    );

    // Correctness: the rollup-served top-N must equal the live top-N. Both
    // paths order by `last_seen DESC` only, so rows that TIE on last_seen may
    // appear in different relative order between the two plans. Compare in a
    // tie-order-independent way: (a) the multiset of last_seen ordering keys
    // must be identical, and (b) the per-session (last_seen, event_count) facts
    // must match for every returned session.
    let live = list_ai_sessions_live(&pool, &params).unwrap();
    let rollup = list_ai_sessions(&pool, &params).unwrap();
    assert_eq!(live.len(), rollup.len(), "rollup/live row count mismatch");
    let mut live_keys: Vec<&String> = live.iter().map(|s| &s.last_seen).collect();
    let mut rollup_keys: Vec<&String> = rollup.iter().map(|s| &s.last_seen).collect();
    live_keys.sort();
    rollup_keys.sort();
    assert_eq!(
        live_keys, rollup_keys,
        "rollup/live last_seen ordering-key multisets differ"
    );
    let live_facts: std::collections::HashMap<_, _> = live
        .iter()
        .map(|s| {
            (
                (&s.ai_project, &s.ai_tool, &s.ai_session_id, &s.hostname),
                (&s.last_seen, s.event_count),
            )
        })
        .collect();
    for r in &rollup {
        let key = (&r.ai_project, &r.ai_tool, &r.ai_session_id, &r.hostname);
        match live_facts.get(&key) {
            Some((last_seen, count)) => {
                assert_eq!(*last_seen, &r.last_seen, "last_seen mismatch for {key:?}");
                assert_eq!(*count, r.event_count, "event_count mismatch for {key:?}");
            }
            None => panic!("rollup returned session not in live top-N: {key:?}"),
        }
    }

    let speedup = sessions_live_latency.p50_ms / sessions_rollup_latency.p50_ms.max(0.001);
    let minimum_speedup = crate::env::var("CORTEX_BENCH_MIN_SESSION_SPEEDUP")
        .ok()
        .map(|value| {
            value
                .parse::<f64>()
                .expect("CORTEX_BENCH_MIN_SESSION_SPEEDUP must be a number")
        });
    let maximum_p95 = crate::env::var("CORTEX_BENCH_MAX_SESSION_P95_MS")
        .ok()
        .map(|value| {
            value
                .parse::<f64>()
                .expect("CORTEX_BENCH_MAX_SESSION_P95_MS must be a number")
        });
    let speedup_passed = minimum_speedup.is_none_or(|minimum| speedup >= minimum);
    let p95_passed = maximum_p95.is_none_or(|maximum| sessions_rollup_latency.p95_ms <= maximum);
    if let Ok(path) = crate::env::var("CORTEX_BENCH_ARTIFACT") {
        let artifact = serde_json::json!({
            "rows": rows,
            "stats_default": {"p50_ms": stats_latency.p50_ms, "p95_ms": stats_latency.p95_ms},
            "stats_fts": {"p50_ms": stats_fts_latency.p50_ms, "p95_ms": stats_fts_latency.p95_ms},
            "sessions_live": {"p50_ms": sessions_live_latency.p50_ms, "p95_ms": sessions_live_latency.p95_ms},
            "sessions_rollup": {"p50_ms": sessions_rollup_latency.p50_ms, "p95_ms": sessions_rollup_latency.p95_ms},
            "refresh": {"p50_ms": refresh_latency.p50_ms, "p95_ms": refresh_latency.p95_ms},
            "session_speedup": speedup,
            "minimum_session_speedup": minimum_speedup,
            "maximum_session_p95_ms": maximum_p95,
            "outcome": {"speedup_passed": speedup_passed, "p95_passed": p95_passed},
        });
        std::fs::write(path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
    }
    if let Some(minimum_speedup) = minimum_speedup {
        assert!(
            speedup_passed,
            "session rollup speedup {speedup:.2}x is below the {minimum_speedup:.2}x configured threshold"
        );
    }
    assert!(
        p95_passed,
        "session rollup p95 {:.1}ms exceeds the configured diagnostic threshold",
        sessions_rollup_latency.p95_ms
    );
    eprintln!(
        "[bench] SUMMARY rows={rows} \
         stats_default_p50_ms={:.1} stats_default_p95_ms={:.1} \
         stats_fts_on_p50_ms={:.1} stats_fts_on_p95_ms={:.1} \
         sessions_BEFORE_live_p50_ms={:.1} sessions_BEFORE_live_p95_ms={:.1} \
         sessions_AFTER_rollup_p50_ms={:.1} sessions_AFTER_rollup_p95_ms={:.1} \
         refresh_p50_ms={:.1} refresh_p95_ms={:.1} sessions_p50_speedup={speedup:.1}x",
        stats_latency.p50_ms,
        stats_latency.p95_ms,
        stats_fts_latency.p50_ms,
        stats_fts_latency.p95_ms,
        sessions_live_latency.p50_ms,
        sessions_live_latency.p95_ms,
        sessions_rollup_latency.p50_ms,
        sessions_rollup_latency.p95_ms,
        refresh_latency.p50_ms,
        refresh_latency.p95_ms,
    );
}

/// full-review QM2: the 15-column log projection is written inline at ~14
/// sites across queries.rs / analytics.rs / ingest.rs, and `map_row` /
/// `map_row_offset` / `map_row_with_raw` read columns BY ORDINAL POSITION —
/// reordering or inserting a column at one site without updating the readers
/// silently mis-maps fields with no compile error. This drift test extracts
/// every projection that ends in `metadata_json` from the source text and
/// asserts it carries the canonical column order. (`map_row_with_raw` selects
/// `..., metadata_json, raw`; the canonical prefix still applies.)
#[test]
fn inline_log_projections_match_map_row_column_order() {
    // Two canonical shapes exist: `map_row` (15 cols) and `map_row_with_raw`
    // (16 cols, `raw` between `message` and `received_at`).
    const CANON: &str = "id timestamp hostname facility severity app_name process_id message \
         received_at source_ip ai_tool ai_project ai_session_id ai_transcript_path metadata_json";
    const CANON_WITH_RAW: &str = "id timestamp hostname facility severity app_name process_id \
         message raw received_at source_ip ai_tool ai_project ai_session_id ai_transcript_path \
         metadata_json";
    let canon_tokens: Vec<&str> = CANON.split_whitespace().collect();
    let canon_raw_tokens: Vec<&str> = CANON_WITH_RAW.split_whitespace().collect();

    let sources = [
        ("queries.rs", include_str!("queries.rs")),
        ("analytics.rs", include_str!("analytics.rs")),
        ("ingest.rs", include_str!("ingest.rs")),
    ];
    let re = regex::Regex::new(
        r"SELECT\s+((?:[a-zA-Z_][a-zA-Z_0-9]*\.)?id[\sa-zA-Z_0-9,.\\]*?metadata_json)",
    )
    .unwrap();

    let mut checked = 0usize;
    for (name, src) in sources {
        for cap in re.captures_iter(src) {
            let projection = &cap[1];
            let tokens: Vec<String> = projection
                .split([',', '\\'])
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(|t| {
                    // Strip any table alias prefix ("l.id" -> "id").
                    t.rsplit('.').next().unwrap_or(t).to_string()
                })
                .collect();
            assert!(
                tokens == canon_tokens || tokens == canon_raw_tokens,
                "{name}: inline log projection diverges from map_row / \
                 map_row_with_raw column order — update the projection AND the \
                 row readers together:\n{projection}\ngot: {tokens:?}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "expected to find at least 10 inline projections; the extraction regex \
         may have rotted (found {checked})"
    );
}

#[test]
fn lint_flags_unquoted_infix_hyphen_term() {
    let err = validate_fts_query("smoke-test").unwrap_err().to_string();
    assert!(
        err.contains("NOT operator"),
        "should explain hyphen trap: {err}"
    );
    assert!(
        err.contains("--grep") || err.contains("\"smoke-test\""),
        "should suggest a fix: {err}"
    );
}

#[test]
fn lint_accepts_quoted_phrase() {
    // Already-quoted hyphenated phrase is valid FTS5 and must pass.
    assert!(validate_fts_query("\"smoke-test\"").is_ok());
}

#[test]
fn lint_accepts_normal_boolean_query() {
    assert!(validate_fts_query("error AND nginx").is_ok());
}

#[test]
fn lint_leaves_leading_hyphen_not_term_alone() {
    // `-nginx` is an intentional FTS5 NOT, not the hyphenated-word trap.
    assert!(validate_fts_query("error -nginx").is_ok());
}

#[test]
fn lint_flags_unbalanced_quote() {
    let err = validate_fts_query("\"oops").unwrap_err().to_string();
    assert!(err.contains("unbalanced quote"), "{err}");
}

#[test]
fn lint_flags_unquoted_hyphen_term_alongside_a_quoted_phrase() {
    // The hyphen check is per-term: a quoted phrase elsewhere must not mask an
    // unquoted hyphenated term (regression for a query-wide quote gate).
    let err = validate_fts_query("\"disk full\" smoke-test")
        .unwrap_err()
        .to_string();
    assert!(err.contains("NOT operator"), "{err}");
}
