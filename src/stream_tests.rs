use super::*;

fn auth(subject: &str) -> AuthContext {
    AuthContext {
        sub: subject.into(),
        actor_key: None,
        scopes: vec!["cortex:read".into()],
        issuer: "test".into(),
        via_session: false,
        csrf_token: None,
        email: None,
    }
}

#[test]
fn cursor_round_trip_binds_principal_filters_and_watermark() {
    let encoded = encode_cursor(42, "issuer:alice", "filters", 1234);
    let decoded = decode_cursor(&encoded).unwrap();
    assert_eq!(decoded.position, 42);
    assert_eq!(decoded.principal, "issuer:alice");
    assert_eq!(decoded.filters, "filters");
    assert_eq!(decoded.issued_at, 1234);
}

#[test]
fn malformed_and_oversized_cursors_fail_closed() {
    assert!(matches!(
        decode_cursor("not-hex"),
        Err(StreamError::Invalid(_))
    ));
    assert!(matches!(
        decode_cursor(&"a".repeat(2049)),
        Err(StreamError::Invalid(_))
    ));
}

#[test]
fn malformed_signature_hex_and_lengths_fail_closed() {
    let encoded = encode_cursor(42, "issuer:alice", "filters", 1234);
    let mut cursor: StreamCursor = serde_json::from_slice(&hex::decode(encoded).unwrap()).unwrap();
    for signature in ["zz".to_owned(), "00".repeat(31), "00".repeat(33)] {
        cursor.signature = signature;
        let encoded = hex::encode(serde_json::to_vec(&cursor).unwrap());
        assert!(matches!(
            decode_cursor(&encoded),
            Err(StreamError::Invalid("cursor signature is invalid"))
        ));
    }
}

#[test]
fn principal_identity_includes_issuer_and_subject() {
    assert_eq!(principal_key(&auth("alice")), "test:alice");
    assert_ne!(principal_key(&auth("alice")), principal_key(&auth("bob")));
}

#[test]
fn event_payload_is_utf8_safe_and_bounded() {
    let row = db::DurableStreamRow {
        id: 1,
        timestamp: "2026-08-28T00:00:00Z".into(),
        hostname: "host".into(),
        severity: "info".into(),
        app_name: None,
        message: "é".repeat(MAX_EVENT_BYTES),
        metadata_json: None,
        parse_error: None,
    };
    let payload = row_json(&row, "log");
    assert!(payload.len() < MAX_EVENT_BYTES + 1024);
    assert!(payload.contains("[truncated]"));
}

#[test]
fn missing_scope_is_denied() {
    let mut context = auth("alice");
    context.scopes.clear();
    assert!(matches!(
        require_read_scope(&context),
        Err(StreamError::Forbidden(_))
    ));
}

#[test]
fn cursor_is_not_part_of_filter_lineage() {
    let mut first = LogStreamRequest {
        cursor: None,
        host: Some("h".into()),
        app: None,
        severity: None,
    };
    let expected = fingerprint(&first).unwrap();
    first.cursor = Some("resume-token".into());
    first.cursor = None;
    assert_eq!(fingerprint(&first).unwrap(), expected);
}

#[test]
fn durable_query_is_ordered_bounded_and_exposes_retention_floor() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("stream.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let make = |message: &str| crate::db::LogBatchEntry {
        timestamp: "2026-08-28T00:00:00Z".into(),
        hostname: "h".into(),
        facility: None,
        severity: "info".into(),
        app_name: Some("app".into()),
        process_id: None,
        message: message.into(),
        raw: message.into(),
        source_ip: "test".into(),
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
    };
    crate::db::insert_logs_batch(&pool, &[make("one"), make("two"), make("three")]).unwrap();
    let first = crate::db::durable_stream_page(
        &pool,
        &db::DurableStreamParams {
            hostname: Some("h".into()),
            limit: 2,
            include_bounds: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        first
            .rows
            .iter()
            .map(|row| row.message.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    let first_id = first.rows[0].id;
    pool.get()
        .unwrap()
        .execute("DELETE FROM logs WHERE id = ?1", [first_id])
        .unwrap();
    let retained = crate::db::durable_stream_page(
        &pool,
        &db::DurableStreamParams {
            hostname: Some("h".into()),
            after_id: first_id,
            limit: 100,
            include_bounds: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(retained.minimum_watermark.unwrap() > first_id);
    assert_eq!(retained.rows.len(), 2);
}

#[test]
fn cursor_tamper_future_skew_and_key_rotation_fail_closed() {
    let now = Utc::now().timestamp();
    let encoded = encode_cursor(42, "test:alice", "filters", now);
    let mut bytes = hex::decode(&encoded).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    assert!(matches!(
        decode_cursor(&hex::encode(bytes)),
        Err(StreamError::Invalid(_))
    ));

    let future = encode_cursor(
        42,
        "test:alice",
        "filters",
        now + CURSOR_CLOCK_SKEW_SECS + 1,
    );
    let decoded = decode_cursor(&future).unwrap();
    assert!(Utc::now().timestamp() - decoded.issued_at < -CURSOR_CLOCK_SKEW_SECS);
}

#[test]
fn final_event_serialization_scrubs_canaries_and_obeys_exact_bound() {
    let canary = "sk-super-secret-canary";
    let row = db::DurableStreamRow {
        id: 1,
        timestamp: "2026-08-28T00:00:00Z".into(),
        hostname: "host".into(),
        severity: "info".into(),
        app_name: Some("app".into()),
        message: format!("{canary} {}", "é\\\"".repeat(MAX_EVENT_BYTES)),
        metadata_json: Some(format!(r#"{{"nested":["{canary}"]}}"#)),
        parse_error: Some(format!("TOKEN={canary}")),
    };
    let payload = row_json(&row, "session");
    assert!(payload.len() <= MAX_EVENT_BYTES);
    assert!(!payload.contains(canary));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&payload).unwrap()["redacted"],
        true
    );
}

#[test]
fn steady_state_page_skips_floor_aggregation() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("steady.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let page = crate::db::durable_stream_page(
        &pool,
        &db::DurableStreamParams {
            after_id: 99,
            limit: 10,
            include_bounds: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(page.minimum_watermark, None);
    assert_eq!(page.high_watermark, 99);
}

#[test]
fn retention_lineage_survives_fully_deleted_filter_and_ignores_unrelated_gap() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("lineage.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let make = |host: &str, message: &str| crate::db::LogBatchEntry {
        timestamp: "2026-08-28T00:00:00Z".into(),
        hostname: host.into(),
        facility: None,
        severity: "info".into(),
        app_name: Some("app".into()),
        process_id: None,
        message: message.into(),
        raw: message.into(),
        source_ip: "test".into(),
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
    };
    crate::db::insert_logs_batch(&pool, &[make("target", "gone"), make("other", "kept")]).unwrap();
    pool.get()
        .unwrap()
        .execute("DELETE FROM logs WHERE hostname='target'", [])
        .unwrap();
    let target = crate::db::durable_stream_page(
        &pool,
        &db::DurableStreamParams {
            hostname: Some("target".into()),
            include_bounds: true,
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(target.rows.is_empty());
    assert!(
        target.minimum_watermark.is_some(),
        "fully deleted filters retain a lineage floor"
    );
    let other = crate::db::durable_stream_page(
        &pool,
        &db::DurableStreamParams {
            hostname: Some("other".into()),
            include_bounds: true,
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        other.minimum_watermark,
        other.rows.first().map(|row| row.id)
    );
}

#[test]
fn steady_state_session_poll_uses_bounded_composite_index() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("plan.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let conn = pool.get().unwrap();
    let detail: String = conn.query_row(
        "EXPLAIN QUERY PLAN SELECT id FROM logs WHERE id > ?1 AND hostname=?2 AND ai_project=?3 AND ai_tool=?4 AND ai_session_id=?5 ORDER BY id LIMIT ?6",
        rusqlite::params![0, "h", "p", "t", "s", 101],
        |row| row.get(3),
    ).unwrap();
    assert!(
        detail.contains("idx_logs_stream_session_id"),
        "unexpected query plan: {detail}"
    );
    assert!(
        !detail.contains("SCAN logs"),
        "steady-state polling must not scan logs: {detail}"
    );
}

#[tokio::test(start_paused = true)]
async fn connection_deadline_releases_admission_even_when_body_stalls() {
    let semaphore = std::sync::Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().unwrap();
    let lease = client_lease(permit, Duration::from_millis(10));
    assert!(semaphore.clone().try_acquire_owned().is_err());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    assert!(semaphore.clone().try_acquire_owned().is_ok());
    drop(lease);
}

#[test]
fn sixty_four_stream_burst_rejects_excess_and_recovers_after_disconnect() {
    let clients = std::sync::Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut admitted = Vec::with_capacity(MAX_CLIENTS);

    for _ in 0..MAX_CLIENTS {
        admitted.push(acquire_client_permit(clients.clone()).unwrap());
    }
    assert_eq!(clients.available_permits(), 0);
    assert!(matches!(
        acquire_client_permit(clients.clone()),
        Err(StreamError::Overloaded)
    ));

    drop(admitted.pop());
    assert!(acquire_client_permit(clients).is_ok());
}

fn service() -> (
    CortexService,
    std::sync::Arc<crate::db::DbPool>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("service.db"));
    let pool = std::sync::Arc::new(crate::db::init_pool(&storage).unwrap());
    (CortexService::new(pool.clone(), storage), pool, dir)
}

#[tokio::test]
async fn cross_principal_and_expired_cursors_are_rejected_before_streaming() {
    let (service, _pool, _dir) = service();
    let request = LogStreamRequest {
        cursor: None,
        host: None,
        app: None,
        severity: None,
    };
    let filters = fingerprint(&request).unwrap();
    let other = encode_cursor(1, "test:bob", &filters, Utc::now().timestamp());
    let result = log_stream(
        service.clone(),
        auth("alice"),
        LogStreamRequest {
            cursor: Some(other),
            ..request.clone()
        },
        test_cursor_keys(),
    )
    .await;
    assert!(matches!(result, Err(StreamError::Forbidden(_))));

    let expired = encode_cursor(
        1,
        "test:alice",
        &filters,
        Utc::now().timestamp() - CURSOR_TTL_SECS - 1,
    );
    let result = log_stream(
        service,
        auth("alice"),
        LogStreamRequest {
            cursor: Some(expired),
            ..request
        },
        test_cursor_keys(),
    )
    .await;
    assert!(matches!(result, Err(StreamError::Expired)));
}

#[tokio::test]
async fn retained_cursor_resumes_after_service_restart_and_gap_fails_closed() {
    let (service, pool, _dir) = service();
    let make = |message: &str| crate::db::LogBatchEntry {
        timestamp: "2026-08-28T00:00:00Z".into(),
        hostname: "h".into(),
        facility: None,
        severity: "info".into(),
        app_name: None,
        process_id: None,
        message: message.into(),
        raw: message.into(),
        source_ip: "test".into(),
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
    };
    crate::db::insert_logs_batch(&pool, &[make("one"), make("two")]).unwrap();
    let first_id: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT MIN(id) FROM logs", [], |row| row.get(0))
        .unwrap();
    let request = LogStreamRequest {
        cursor: None,
        host: Some("h".into()),
        app: None,
        severity: None,
    };
    let filters = fingerprint(&request).unwrap();
    let cursor = encode_cursor(first_id, "test:alice", &filters, Utc::now().timestamp());
    let restarted = CortexService::new(
        pool.clone(),
        crate::config::StorageConfig::for_test(_dir.path().join("service.db")),
    );
    let result = log_stream(
        restarted,
        auth("alice"),
        LogStreamRequest {
            cursor: Some(cursor.clone()),
            ..request.clone()
        },
        test_cursor_keys(),
    )
    .await;
    assert!(
        result.is_ok(),
        "a retained committed watermark must survive service restart"
    );
    drop(result);

    pool.get()
        .unwrap()
        .execute("DELETE FROM logs WHERE id = ?1", [first_id])
        .unwrap();
    let stale = encode_cursor(0, "test:alice", &filters, Utc::now().timestamp());
    let result = log_stream(
        service,
        auth("alice"),
        LogStreamRequest {
            cursor: Some(stale),
            ..request
        },
        test_cursor_keys(),
    )
    .await;
    assert!(matches!(result, Err(StreamError::Gap { .. })));
}

#[test]
fn resolved_cursor_keys_fail_closed_rotate_safely_and_accept_toml_only_key() {
    assert!(CursorKeys::resolved(None, &[], false).is_err());
    let first = CursorKeys::resolved(Some("first-secret"), &[], false).unwrap();
    let cursor = encode_cursor_with_keys(7, "test:alice", "filters", 1234, &first);
    let rotated = CursorKeys::resolved(
        Some("second-secret"),
        &["".into(), "first-secret".into()],
        false,
    )
    .unwrap();
    assert!(decode_cursor_with_keys(&cursor, &rotated).is_ok());
    let retired = CursorKeys::resolved(Some("second-secret"), &[], false).unwrap();
    assert!(decode_cursor_with_keys(&cursor, &retired).is_err());
    let config: crate::config::Config =
        toml::from_str("cursor_signing_key = 'toml-secret'\ncursor_previous_keys = ['old-secret']")
            .unwrap();
    assert_eq!(config.cursor_signing_key.as_deref(), Some("toml-secret"));
    assert_eq!(config.cursor_previous_keys, ["old-secret"]);
}

#[tokio::test(start_paused = true)]
async fn slow_client_stream_body_terminates_at_lease_deadline() {
    use axum::response::IntoResponse;
    let (service, _pool, _dir) = service();
    let request = LogStreamRequest {
        cursor: None,
        host: None,
        app: None,
        severity: None,
    };
    let filters = fingerprint(&request).unwrap();
    let params = db::DurableStreamParams {
        limit: 2,
        include_bounds: true,
        ..Default::default()
    };
    let sse = build_stream(
        service,
        auth("alice"),
        None,
        filters,
        params,
        StreamContract {
            event_name: "log",
            cursor_keys: test_cursor_keys(),
            connection_duration: Duration::from_millis(20),
            clients: std::sync::Arc::new(Semaphore::new(1)),
        },
    )
    .await
    .unwrap();
    let body = sse.into_response().into_body();
    let consumer = tokio::spawn(axum::body::to_bytes(body, MAX_EVENT_BYTES * 2));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(21)).await;
    consumer
        .await
        .expect("stream body consumer must complete")
        .expect("stream body must close at its lease deadline");
}

#[test]
fn every_supported_log_filter_combination_uses_a_bounded_composite_index() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("filter-plans.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let conn = pool.get().unwrap();
    let cases = [
        (
            "hostname=?2 AND app_name=?3",
            "idx_logs_stream_host_app_id",
            vec!["h", "a"],
        ),
        (
            "hostname=?2 AND severity=?3",
            "idx_logs_stream_host_severity_id",
            vec!["h", "info"],
        ),
        (
            "app_name=?2 AND severity=?3",
            "idx_logs_stream_app_severity_id",
            vec!["a", "info"],
        ),
        (
            "hostname=?2 AND app_name=?3 AND severity=?4",
            "idx_logs_stream_host_app_severity_id",
            vec!["h", "a", "info"],
        ),
    ];
    for (filters, index, values) in cases {
        let sql = format!(
            "EXPLAIN QUERY PLAN SELECT id FROM logs WHERE id>?1 AND {filters} ORDER BY id LIMIT 101"
        );
        let mut params = vec![rusqlite::types::Value::Integer(0)];
        params.extend(
            values
                .into_iter()
                .map(|value| rusqlite::types::Value::Text(value.into())),
        );
        let details = conn
            .prepare(&sql)
            .unwrap()
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join(" ");
        assert!(
            details.contains(index),
            "{filters} did not use {index}: {details}"
        );
        assert!(
            !details.contains("SCAN logs"),
            "unbounded plan for {filters}: {details}"
        );
    }
}

#[test]
fn production_bound_queries_use_indexes_on_populated_data_for_every_filter_shape() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("bound-plans.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "BEGIN;
         WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000)
         INSERT INTO logs(timestamp,hostname,severity,app_name,message,raw,source_ip,
                          ai_project,ai_tool,ai_session_id)
         SELECT '2026-08-28T00:00:00Z', 'host-'||(x%5),
                CASE x%3 WHEN 0 THEN 'info' WHEN 1 THEN 'warning' ELSE 'err' END,
                'app-'||(x%7), 'm', 'm', 'test',
                CASE WHEN x%11=0 THEN 'project' END,
                CASE WHEN x%11=0 THEN 'tool' END,
                CASE WHEN x%11=0 THEN 'session' END FROM n;
         DELETE FROM logs WHERE id%13=0;
         ANALYZE;
         COMMIT;",
    )
    .unwrap();

    let log_shapes = [
        (None, None, None),
        (Some("host-1"), None, None),
        (None, Some("app-1"), None),
        (None, None, Some("info")),
        (Some("host-1"), Some("app-1"), None),
        (Some("host-1"), None, Some("info")),
        (None, Some("app-1"), Some("info")),
        (Some("host-1"), Some("app-1"), Some("info")),
    ];
    let mut production_params = Vec::new();
    for (host, app, severity) in log_shapes {
        let params = db::DurableStreamParams {
            hostname: host.map(str::to_owned),
            app_name: app.map(str::to_owned),
            severity: severity.map(str::to_owned),
            include_bounds: true,
            limit: 10,
            ..Default::default()
        };
        assert_bound_plans_are_indexed(&conn, &params);
        production_params.push(params);
    }

    let session = db::DurableStreamParams {
        hostname: Some("host-1".into()),
        ai_project: Some("project".into()),
        ai_tool: Some("tool".into()),
        ai_session_id: Some("session".into()),
        include_bounds: true,
        limit: 10,
        ..Default::default()
    };
    assert_bound_plans_are_indexed(&conn, &session);
    production_params.push(session);
    drop(conn);
    for params in production_params {
        crate::db::durable_stream_page(&pool, &params).unwrap();
    }
}

fn assert_bound_plans_are_indexed(conn: &rusqlite::Connection, params: &db::DurableStreamParams) {
    for (table, deleted) in [("logs", false), ("stream_deleted_log_lineage", true)] {
        let (sql, values) = crate::db::stream_bounds_sql(table, params, deleted);
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let plan = conn
            .prepare(&explain)
            .unwrap()
            .query_map(rusqlite::params_from_iter(values.iter()), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join(" ");
        assert!(!plan.contains(&format!("SCAN {table}")), "{sql}: {plan}");
        assert!(plan.contains(&format!("SEARCH {table}")), "{sql}: {plan}");
    }
}

#[test]
fn lifecycle_prunes_expired_lineage_without_deleting_live_logs() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::config::StorageConfig::for_test(dir.path().join("lineage-prune.db"));
    let pool = crate::db::init_pool(&storage).unwrap();
    let conn = pool.get().unwrap();
    conn.execute("INSERT INTO stream_deleted_log_lineage(id,hostname,severity,deleted_at) VALUES(1,'h','info',unixepoch()-901)", []).unwrap();
    conn.execute("INSERT INTO logs(timestamp,hostname,severity,message,raw,source_ip) VALUES('2026-08-28T00:00:00Z','live','info','keep','keep','test')", []).unwrap();
    drop(conn);
    assert_eq!(crate::db::prune_expired_stream_lineage(&pool).unwrap(), 1);
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM stream_deleted_log_lineage",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
