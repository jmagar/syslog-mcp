use super::*;
use crate::config::StorageConfig;
use crate::db::{init_pool, insert_logs_batch, DbPool, LogBatchEntry};

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
    }
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
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: None,
        to: None,
        limit: None,
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].message.contains("disk full"));
}

#[test]
fn test_search_invalid_fts_returns_error() {
    let (pool, _dir) = test_pool();
    // FTS5 treats bare parentheses as a syntax error
    let params = SearchParams {
        query: Some("(invalid fts syntax".to_string()),
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: None,
        to: None,
        limit: None,
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
fn test_tail_filter_by_host() {
    let (pool, _dir) = test_pool();
    let entries = vec![
        make_entry("2026-01-01T00:00:01Z", "host-a", "info", "from a"),
        make_entry("2026-01-01T00:00:02Z", "host-b", "info", "from b"),
    ];
    insert_logs_batch(&pool, &entries).unwrap();

    let rows = tail_logs(&pool, Some("host-a"), None, None, 10).unwrap();
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
        query: None,
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: Some("2026-06-01T00:00:00Z".into()),
        to: None,
        limit: None,
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 2, "from filter should return mid + late");

    // to only
    let params = SearchParams {
        query: None,
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: None,
        to: Some("2026-06-30T00:00:00Z".into()),
        limit: None,
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 2, "to filter should return early + mid");

    // from + to (narrow window)
    let params = SearchParams {
        query: None,
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: Some("2026-06-01T00:00:00Z".into()),
        to: Some("2026-06-30T00:00:00Z".into()),
        limit: None,
    };
    let results = search_logs(&pool, &params).unwrap();
    assert_eq!(results.len(), 1, "from+to filter should return only mid");
    assert_eq!(results[0].message, "mid message");
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
    assert_eq!(severity_to_num("ERROR"), None, "case sensitive");
    assert_eq!(severity_to_num("critical"), None, "not a valid syslog name");
    assert_eq!(
        severity_to_num("warn"),
        None,
        "must be 'warning' not 'warn'"
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

    let summary = get_error_summary(&pool, None, None).unwrap();
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
        query: None,
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: Some(vec!["emerg".into(), "err".into(), "warning".into()]),
        app_name: None,
        from: None,
        to: None,
        limit: None,
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
        hostname: None,
        source_ip: None,
        severity: None,
        severity_in: None,
        app_name: None,
        from: None,
        to: None,
        limit: None,
    };
    let results = search_logs(&pool, &params).unwrap();
    assert!(results.is_empty(), "FTS-only phantom rows must not leak");
}
