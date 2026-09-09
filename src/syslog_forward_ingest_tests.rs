use super::*;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::connect_info::MockConnectInfo,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use tower::ServiceExt;

#[derive(Clone)]
struct ReceiptLossServerState {
    receiver: SyslogForwardIngestState,
    /// Models the only ambiguous network outcome that matters here: Cortex
    /// commits the transaction, but the sender never receives the receipt.
    lose_next_successful_receipt: Arc<AtomicBool>,
}

async fn receipt_loss_handler(
    State(state): State<ReceiptLossServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let response = ingest_handler(State(state.receiver), ConnectInfo(peer), headers, body).await;

    if response.status().is_success()
        && state
            .lose_next_successful_receipt
            .swap(false, Ordering::SeqCst)
    {
        // The request has already crossed the receiver's authenticated,
        // transactional boundary. Returning 503 intentionally discards its
        // receipt from the sender's point of view, forcing an exact replay.
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    } else {
        response
    }
}

async fn wait_for_sender(
    sender: &crate::agent::syslog_sender::SyslogSender,
    predicate: impl Fn(&crate::agent::syslog_sender::SyslogForwardStatus) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let status = sender.status();
            if predicate(&status) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("syslog sender did not reach the expected recovery state");
}

fn syslog_request(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/syslog-forward")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer forward-token")
        .body(Body::from(body))
        .unwrap()
}

async fn barrier_syslog_request(
    app: Router,
    barrier: Arc<tokio::sync::Barrier>,
    body: String,
) -> StatusCode {
    barrier.wait().await;
    app.oneshot(syslog_request(body)).await.unwrap().status()
}

#[tokio::test]
async fn sender_replays_an_authenticated_receipt_loss_once_after_outage_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("forward-spool.json");
    let token = "syslog-forward-test-token".to_owned();

    // Keep ownership of the ephemeral port for the entire test. The first
    // accepted connection is deliberately dropped to model a transport
    // outage; retaining the listener removes a port-release/rebind race.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let outage = tokio::spawn(async {
        let (connection, _) = listener.accept().await.unwrap();
        drop(connection);
        listener
    });
    let target = format!("http://{address}");

    let original_sender = crate::agent::syslog_sender::SyslogSender::new(
        target.clone(),
        Some(token.clone()),
        spool_path.clone(),
    );
    original_sender
        .send_from(
            "journald",
            "<134>1 2026-09-01T00:00:00Z agent-a cortex-agent - - - recovery-proof".to_owned(),
        )
        .await
        .unwrap();
    wait_for_sender(&original_sender, |status| {
        status.queued_records == 1 && status.last_error_code == Some("transport_unavailable")
    })
    .await;
    let listener = outage.await.unwrap();
    assert!(spool_path.exists(), "outage must be durable before restart");

    // Dropping the previous agent stops its delivery task. A new process then
    // loads exactly the same spool file after the receiver returns.
    drop(original_sender);

    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("syslog-forward-recovery.db"),
        ))
        .unwrap(),
    );
    let receiver = SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some(token),
        Default::default(),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    );
    let loss_state = ReceiptLossServerState {
        receiver,
        lose_next_successful_receipt: Arc::new(AtomicBool::new(true)),
    };
    let app = Router::new()
        .route("/v1/syslog-forward", post(receipt_loss_handler))
        .with_state(loss_state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let receiver_task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let restarted_sender = crate::agent::syslog_sender::SyslogSender::new(
        target,
        Some("syslog-forward-test-token".to_owned()),
        spool_path,
    );
    wait_for_sender(&restarted_sender, |status| status.queued_records == 0).await;
    drop(restarted_sender);
    let _ = shutdown_tx.send(());
    receiver_task.await.unwrap();

    let conn = pool.get().unwrap();
    let evidence_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'recovery-proof'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let receipt_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM syslog_forward_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        evidence_count, 1,
        "receipt-loss replay must not duplicate evidence"
    );
    assert_eq!(receipt_count, 1, "the exact replay must reuse one receipt");
}

#[test]
fn records_reject_unsafe_or_unbounded_inputs() {
    let valid = SyslogForwardRecord {
        source_instance: "host-a".into(),
        source_epoch: 1,
        sequence: 1,
        idempotency_key: "key".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        line: "<134>1 ts host app - - - message".into(),
    };
    assert!(!invalid_record(&valid));
    assert!(invalid_record(&SyslogForwardRecord {
        line: String::new(),
        ..valid
    }));
}

#[test]
fn forwarded_records_and_gaps_require_rfc3339_observation_times() {
    let record = SyslogForwardRecord {
        source_instance: "host-a".into(),
        source_epoch: 1,
        sequence: 1,
        idempotency_key: "record-time".into(),
        observed_at: "not-a-timestamp".into(),
        line: "<134>1 2026-01-01T00:00:00Z host app - - - message".into(),
    };
    assert!(invalid_record(&record));
    assert!(invalid_gap(&SyslogForwardGap {
        source_instance: "host-a".into(),
        source_epoch: 1,
        from_sequence: 1,
        to_sequence: 1,
        idempotency_key: "gap-time".into(),
        observed_at: "also-invalid".into(),
        reason_code: "record_too_large".into(),
    }));
}

#[test]
fn gap_rejects_reversed_window() {
    assert!(invalid_gap(&SyslogForwardGap {
        source_instance: "host-a".into(),
        source_epoch: 1,
        from_sequence: 2,
        to_sequence: 1,
        idempotency_key: "gap".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        reason_code: "local_retention_quota".into()
    }));
}

#[test]
fn gap_rejects_an_unrecognized_reason_code() {
    assert!(invalid_gap(&SyslogForwardGap {
        source_instance: "host-a".into(),
        source_epoch: 1,
        from_sequence: 1,
        to_sequence: 1,
        idempotency_key: "gap".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        reason_code: "token=gap-reason-canary".into(),
    }));
}

#[tokio::test]
async fn unsafe_gap_reason_is_rejected_before_persistence_or_fts() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("unsafe-gap.db");
    let pool =
        Arc::new(crate::db::init_pool(&crate::config::StorageConfig::for_test(database)).unwrap());
    let app = router(SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some("forward-token".into()),
        Default::default(),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    ))
    .layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let body = serde_json::to_string(&SyslogForwardRequest {
        records: vec![],
        gaps: vec![SyslogForwardGap {
            source_instance: "host-a".into(),
            source_epoch: 1,
            from_sequence: 1,
            to_sequence: 1,
            idempotency_key: "unsafe-gap".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            reason_code: "token=gap-reason-canary".into(),
        }],
    })
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/syslog-forward")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer forward-token")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let conn = pool.get().unwrap();
    let logs: i64 = conn
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    let fts_canary_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH 'canary'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(logs, 0);
    assert_eq!(fts_canary_count, 0);
}

#[tokio::test]
async fn named_syslog_forwarder_is_server_derived_when_host_claim_differs() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("named-forwarder.db");
    let pool =
        Arc::new(crate::db::init_pool(&crate::config::StorageConfig::for_test(database)).unwrap());
    let app = router(SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some("shared-token".into()),
        HashMap::from([("agent-a-token".into(), "agent-a".into())]),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    ))
    .layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let body = serde_json::to_string(&SyslogForwardRequest {
        records: vec![SyslogForwardRecord {
            source_instance: "host-b".into(),
            source_epoch: 1,
            sequence: 1,
            idempotency_key: "agent-a-host-b".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            line: "<134>1 2026-01-01T00:00:00Z host-b app - - - provenance-proof".into(),
        }],
        gaps: vec![],
    })
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/syslog-forward")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer agent-a-token")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let conn = pool.get().unwrap();
    let (hostname, metadata): (String, String) = conn
        .query_row(
            "SELECT hostname, metadata_json FROM logs LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(hostname, "agent-agent-a");
    assert!(metadata.contains("host-b"));
    assert!(metadata.contains("agent-a"));
    assert!(metadata.contains("verified_forwarder_claimed_host"));
}

#[tokio::test]
async fn named_and_shared_syslog_credentials_have_disjoint_receipt_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("typed-principal-syslog.db"),
        ))
        .unwrap(),
    );
    let state = SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some("shared-token-000".into()),
        HashMap::from([("named-token-0000".into(), "agent-a".into())]),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    );
    let app = router(state).layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let request = SyslogForwardRequest {
        records: vec![SyslogForwardRecord {
            source_instance: "same-source".into(),
            source_epoch: 1,
            sequence: 1,
            idempotency_key: "same-client-key".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            line: "<134>1 2026-01-01T00:00:00Z host-a app - - - typed principal".into(),
        }],
        gaps: vec![],
    };
    let body = serde_json::to_string(&request).unwrap();
    for token in ["named-token-0000", "shared-token-000"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/syslog-forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(
        pool.get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn duplicate_replay_returns_receipt_without_duplicate_canonical_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("syslog-forward.db"),
        ))
        .unwrap(),
    );
    let request = SyslogForwardRequest {
        records: vec![SyslogForwardRecord {
            source_instance: "host-a".into(),
            source_epoch: 1,
            sequence: 1,
            idempotency_key: "host-a:1:1:record".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            line: "<134>1 2026-01-01T00:00:00Z host-a app - - - replay-safe".into(),
        }],
        gaps: vec![],
    };
    let first = persist_request(&pool, request.clone(), "127.0.0.1", "shared_bearer").unwrap();
    let replay = persist_request(&pool, request, "127.0.0.1", "shared_bearer").unwrap();
    assert_eq!(first, replay);
    let conn = pool.get().unwrap();
    let logs: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM logs WHERE message = 'replay-safe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let receipts: i64 = conn
        .query_row("SELECT COUNT(*) FROM syslog_forward_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(logs, 1);
    assert_eq!(receipts, 1);
}

fn sample_gap() -> SyslogForwardGap {
    SyslogForwardGap {
        source_instance: "host-a".into(),
        source_epoch: 1,
        from_sequence: 2,
        to_sequence: 4,
        idempotency_key: "host-a:1:2-4:gap".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        reason_code: "quota_eviction".into(),
    }
}

#[test]
fn migrated_legacy_gap_binds_fingerprint_after_exact_replay() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("legacy-gap.db"),
        ))
        .unwrap(),
    );
    let request = SyslogForwardRequest {
        records: vec![],
        gaps: vec![sample_gap()],
    };
    persist_request(&pool, request.clone(), "127.0.0.1", "shared_bearer").unwrap();
    pool.get()
        .unwrap()
        .execute(
            "UPDATE syslog_forward_receipts SET request_fingerprint = ''",
            [],
        )
        .unwrap();

    persist_request(&pool, request, "127.0.0.1", "shared_bearer").unwrap();
    let fingerprint: String = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT request_fingerprint FROM syslog_forward_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!fingerprint.is_empty());
    assert_eq!(
        pool.get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn changed_gap_cannot_claim_migrated_empty_fingerprint_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("legacy-gap-conflict.db"),
        ))
        .unwrap(),
    );
    let gap = sample_gap();
    persist_request(
        &pool,
        SyslogForwardRequest {
            records: vec![],
            gaps: vec![gap.clone()],
        },
        "127.0.0.1",
        "shared_bearer",
    )
    .unwrap();
    pool.get()
        .unwrap()
        .execute(
            "UPDATE syslog_forward_receipts SET request_fingerprint = ''",
            [],
        )
        .unwrap();

    let error = persist_request(
        &pool,
        SyslogForwardRequest {
            records: vec![],
            gaps: vec![SyslogForwardGap {
                from_sequence: 3,
                ..gap
            }],
        },
        "127.0.0.1",
        "shared_bearer",
    )
    .unwrap_err();
    assert!(error.downcast_ref::<IdempotencyConflict>().is_some());
    let conn = pool.get().unwrap();
    let (logs, fingerprint): (i64, String) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM logs), request_fingerprint
             FROM syslog_forward_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(logs, 1);
    assert!(fingerprint.is_empty());
}

#[test]
fn conflicting_idempotency_replay_is_rejected_without_losing_new_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("syslog-forward-conflict.db"),
        ))
        .unwrap(),
    );
    let base = SyslogForwardRecord {
        source_instance: "host-a".into(),
        source_epoch: 1,
        sequence: 1,
        idempotency_key: "reused-key".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        line: "<134>1 2026-01-01T00:00:00Z host-a app - - - first".into(),
    };
    persist_request(
        &pool,
        SyslogForwardRequest {
            records: vec![base.clone()],
            gaps: vec![],
        },
        "127.0.0.1",
        "agent-a",
    )
    .unwrap();
    let error = persist_request(
        &pool,
        SyslogForwardRequest {
            records: vec![SyslogForwardRecord {
                line: "<134>1 2026-01-01T00:00:00Z host-a app - - - second".into(),
                ..base
            }],
            gaps: vec![],
        },
        "127.0.0.1",
        "agent-a",
    )
    .unwrap_err();
    assert!(error.downcast_ref::<IdempotencyConflict>().is_some());
    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_identical_replays_share_one_syslog_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage =
        crate::config::StorageConfig::for_test(dir.path().join("concurrent-syslog.db"));
    storage.pool_size = 4;
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let app = router(SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some("forward-token".into()),
        Default::default(),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    ))
    .layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let record = SyslogForwardRecord {
        source_instance: "host-a".into(),
        source_epoch: 1,
        sequence: 1,
        idempotency_key: "concurrent-key".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        line: "<134>1 2026-01-01T00:00:00Z host-a app - - - concurrent-safe".into(),
    };
    let body = serde_json::to_string(&SyslogForwardRequest {
        records: vec![record],
        gaps: vec![],
    })
    .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let first = tokio::spawn(barrier_syslog_request(
        app.clone(),
        barrier.clone(),
        body.clone(),
    ));
    let second = tokio::spawn(barrier_syslog_request(app, barrier.clone(), body));
    barrier.wait().await;
    assert_eq!(first.await.unwrap(), StatusCode::OK);
    assert_eq!(second.await.unwrap(), StatusCode::OK);
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM syslog_forward_receipts", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_conflicting_replays_return_success_and_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage =
        crate::config::StorageConfig::for_test(dir.path().join("concurrent-syslog-conflict.db"));
    storage.pool_size = 4;
    let pool = Arc::new(crate::db::init_pool(&storage).unwrap());
    let app = router(SyslogForwardIngestState::new(
        Arc::clone(&pool),
        Some("forward-token".into()),
        Default::default(),
        crate::mcp::AuthPolicy::TrustedGatewayUnscoped,
    ))
    .layer(MockConnectInfo(SocketAddr::from(([10, 0, 0, 7], 41000))));
    let original = SyslogForwardRecord {
        source_instance: "host-a".into(),
        source_epoch: 1,
        sequence: 1,
        idempotency_key: "concurrent-conflict".into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        line: "<134>1 2026-01-01T00:00:00Z host-a app - - - first".into(),
    };
    let changed = SyslogForwardRecord {
        line: "<134>1 2026-01-01T00:00:00Z host-a app - - - second".into(),
        ..original.clone()
    };
    let first_body = serde_json::to_string(&SyslogForwardRequest {
        records: vec![original],
        gaps: vec![],
    })
    .unwrap();
    let second_body = serde_json::to_string(&SyslogForwardRequest {
        records: vec![changed],
        gaps: vec![],
    })
    .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let first = tokio::spawn(barrier_syslog_request(
        app.clone(),
        barrier.clone(),
        first_body,
    ));
    let second = tokio::spawn(barrier_syslog_request(app, barrier.clone(), second_body));
    barrier.wait().await;
    let mut statuses = [first.await.unwrap(), second.await.unwrap()];
    statuses.sort_by_key(|status| status.as_u16());
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM logs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM syslog_forward_receipts", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn deleted_canonical_evidence_is_not_acknowledged_by_a_stale_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("stale-receipt.db"),
        ))
        .unwrap(),
    );
    let request = SyslogForwardRequest {
        records: vec![SyslogForwardRecord {
            source_instance: "host-a".into(),
            source_epoch: 1,
            sequence: 1,
            idempotency_key: "stale".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            line: "<134>1 2026-01-01T00:00:00Z host-a app - - - restored".into(),
        }],
        gaps: vec![],
    };
    persist_request(&pool, request.clone(), "127.0.0.1", "agent-a").unwrap();
    pool.get().unwrap().execute("DELETE FROM logs", []).unwrap();
    persist_request(&pool, request, "127.0.0.1", "agent-a").unwrap();
    let conn = pool.get().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM logs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM syslog_forward_receipts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn same_client_key_is_independent_across_authenticated_principals() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("principal-receipts.db"),
        ))
        .unwrap(),
    );
    let request = SyslogForwardRequest {
        records: vec![SyslogForwardRecord {
            source_instance: "host-a".into(),
            source_epoch: 1,
            sequence: 1,
            idempotency_key: "same".into(),
            observed_at: "2026-01-01T00:00:00Z".into(),
            line: "<134>1 2026-01-01T00:00:00Z host-a app - - - scoped".into(),
        }],
        gaps: vec![],
    };
    persist_request(&pool, request.clone(), "127.0.0.1", "agent-a").unwrap();
    persist_request(&pool, request, "127.0.0.1", "agent-b").unwrap();
    assert_eq!(
        pool.get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM logs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn receiver_never_persists_a_path_like_source_identity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        crate::db::init_pool(&crate::config::StorageConfig::for_test(
            dir.path().join("syslog-forward-private.db"),
        ))
        .unwrap(),
    );
    let source = "/Users/jmagar/private/production/access.log";
    persist_request(
        &pool,
        SyslogForwardRequest {
            records: vec![SyslogForwardRecord {
                source_instance: source.into(),
                source_epoch: 1,
                sequence: 1,
                idempotency_key: format!("{source}:1"),
                observed_at: "2026-01-01T00:00:00Z".into(),
                line: "<134>1 2026-01-01T00:00:00Z host-a app - - - safe".into(),
            }],
            gaps: vec![],
        },
        "127.0.0.1",
        "shared_bearer",
    )
    .unwrap();
    let conn = pool.get().unwrap();
    let receipt_source: String = conn
        .query_row(
            "SELECT source_instance FROM syslog_forward_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let receipt_key: String = conn
        .query_row(
            "SELECT idempotency_key FROM syslog_forward_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!receipt_source.contains(source));
    assert!(!receipt_key.contains(source));
}

#[test]
fn forwarded_metadata_rejects_corrupt_or_non_object_input() {
    assert!(forwarded_metadata(Some("{"), "agent-a", "127.0.0.1", "host-a".into()).is_err());
    assert!(forwarded_metadata(Some("[]"), "agent-a", "127.0.0.1", "host-a".into()).is_err());
}
