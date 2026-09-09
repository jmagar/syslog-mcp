use std::sync::Arc;

use serial_test::serial;

use crate::app::{HostStateRequest, UnaddressedErrorsRequest};
use crate::config::StorageConfig;
use crate::db::{DbPool, LogBatchEntry, init_pool, insert_logs_batch};

use super::*;

#[test]
fn high_volume_analysis_requests_allow_shared_defaults_on_every_transport() {
    assert!(serde_json::from_value::<CompareRequest>(serde_json::json!({})).is_ok());
    assert!(serde_json::from_value::<CorrelateStateRequest>(serde_json::json!({})).is_ok());
    assert!(serde_json::from_value::<IncidentContextRequest>(serde_json::json!({})).is_ok());
}

#[tokio::test]
async fn host_state_default_ignores_orphan_latest_rows() {
    let (service, pool, _dir) = test_service();
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO host_heartbeats_latest \
         (host_id, heartbeat_id, hostname, sampled_at, received_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            "orphan-host",
            999_999_i64,
            "orphan",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z"
        ],
    )
    .unwrap();
    drop(conn);

    let response = service
        .host_state(HostStateRequest::default())
        .await
        .expect("empty authoritative state is a valid response");
    assert!(response.is_none(), "orphan latest row must be ignored");
}

/// Env-var guard for tests that must set/restore process env vars.
/// Mirrors `src/assessment_tests.rs`'s private `EnvGuard` — kept local
/// rather than shared since both are test-only and crate-private.
struct EnvGuard {
    name: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let old = crate::env::var_os(name);
        crate::env::set_test_var(name, value);
        Self { name, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => crate::env::set_test_var(self.name, value),
            None => crate::env::remove_test_var(self.name),
        }
    }
}

fn test_service() -> (CortexService, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("app-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    (CortexService::new(Arc::clone(&pool), storage), pool, dir)
}

async fn wait_for_integrity_job(service: &CortexService, job_id: i64) -> MaintenanceJobStatus {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = service.db_integrity_job_status(job_id).await.unwrap();
            if status.status != "running" {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("integrity job should become terminal")
}

#[tokio::test]
async fn background_integrity_worker_panic_marks_job_failed() {
    let (service, _pool, _dir) = test_service();
    let service = service.with_integrity_test_hook(Arc::new(|| {
        panic!("injected integrity panic");
    }));

    let started = service.db_integrity_start_background(true).await.unwrap();
    let status = wait_for_integrity_job(&service, started.job_id).await;

    assert_eq!(status.status, "failed");
    assert!(
        status.error.as_deref().is_some_and(
            |error| error.contains("integrity worker panicked: injected integrity panic")
        ),
        "unexpected terminal error: {:?}",
        status.error
    );
    assert!(service.drain_integrity_tasks(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn background_integrity_spawn_failure_marks_inserted_job_failed() {
    let (service, pool, _dir) = test_service();
    let service = service.with_integrity_spawn_failure();

    let error = service
        .db_integrity_start_background(true)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected integrity worker spawn failure")
    );

    let job_id = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT id FROM maintenance_jobs ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
    };
    let status = service.db_integrity_job_status(job_id).await.unwrap();
    assert_eq!(status.status, "failed");
    assert!(status.finished_at.is_some());
    assert!(status.error.unwrap().contains("spawn failure"));
}

#[tokio::test]
async fn background_integrity_blocking_worker_holds_permit_and_drain_is_bounded() {
    let (service, _pool, _dir) = test_service();
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = Arc::clone(&gate);
    let service = service.with_integrity_test_hook(Arc::new(move || {
        worker_gate.wait();
        Ok(vec!["ok".to_string()])
    }));

    let started = service.db_integrity_start_background(true).await.unwrap();
    let error = service.db_integrity(true).await.unwrap_err();
    assert!(matches!(error, ServiceError::Busy(_)));
    assert!(
        !service
            .drain_integrity_tasks(Duration::from_millis(5))
            .await,
        "blocked integrity worker must exceed the bounded drain"
    );
    assert_eq!(
        service
            .db_integrity_job_status(started.job_id)
            .await
            .unwrap()
            .status,
        "running"
    );

    gate.wait();
    let status = wait_for_integrity_job(&service, started.job_id).await;
    assert_eq!(status.status, "done");
}

#[tokio::test]
async fn completed_integrity_waiter_failure_is_retained_across_later_jobs() {
    let (service, _pool, _dir) = test_service();
    let failed = tokio::spawn(async { panic!("injected completion waiter failure") });
    tokio::task::yield_now().await;
    service.integrity_tasks.lock().unwrap().push(failed);

    let started = service.db_integrity_start_background(true).await.unwrap();
    let status = wait_for_integrity_job(&service, started.job_id).await;
    assert_eq!(status.status, "done");
    assert!(
        !service.drain_integrity_tasks(Duration::from_secs(1)).await,
        "a later successful job must not erase an earlier waiter failure"
    );
}

fn refresh_graph_projection_for_test(pool: &DbPool) {
    let _guard = crate::db::graph::GRAPH_TEST_LOCK.lock();
    crate::db::graph::refresh_graph_projection(pool).unwrap();
}

fn entry(ts: &str, host: &str, severity: &str, msg: &str, source_ip: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: host.to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: None,
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: source_ip.to_string(),
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

fn ai_entry(ts: &str, msg: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: "localhost".into(),
        facility: Some("local0".into()),
        severity: "info".into(),
        app_name: Some("codex-transcript".into()),
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: "transcript://codex".into(),
        docker_checkpoint: None,
        ai_tool: Some("codex".into()),
        ai_project: Some("/tmp/project".into()),
        ai_session_id: Some("sess-1".into()),
        ai_transcript_path: Some("/tmp/project/sess-1.jsonl".into()),
        metadata_json: None,
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

#[tokio::test]
async fn heavy_read_limiter_times_out_when_permit_is_held() {
    let (mut service, _pool, _dir) = test_service();
    service.acquire_timeout = std::time::Duration::from_millis(10);
    let held = service
        .heavy_read_permits
        .clone()
        .acquire_owned()
        .await
        .expect("heavy permit");

    let err = service
        .run_heavy_db("heavy_test", |_pool| Ok::<_, anyhow::Error>(()))
        .await
        .unwrap_err();

    drop(held);
    assert!(matches!(err, ServiceError::Busy(message) if message == "heavy_read_limited"));
}

#[tokio::test]
async fn sqlite_heavy_public_reads_use_heavy_limiter() {
    async fn assert_heavy_limited<T>(result: ServiceResult<T>) {
        let err = match result {
            Ok(_) => panic!("held heavy permit should reject the read"),
            Err(err) => err,
        };
        assert!(
            matches!(err, ServiceError::Busy(ref message) if message == "heavy_read_limited"),
            "expected heavy_read_limited, got {err:?}"
        );
    }

    let (mut service, _pool, _dir) = test_service();
    service.acquire_timeout = std::time::Duration::from_millis(10);
    let held = service
        .heavy_read_permits
        .clone()
        .acquire_owned()
        .await
        .expect("heavy permit");

    assert_heavy_limited(service.fleet_state(FleetStateRequest::default()).await).await;
    assert_heavy_limited(service.ingest_rate(IngestRateRequest::default()).await).await;
    assert_heavy_limited(
        service
            .investigate_ai_incidents(AiInvestigateRequest::default())
            .await,
    )
    .await;
    assert_heavy_limited(
        service
            .graph_entity_lookup(GraphEntityLookupRequest {
                entity_type: Some("host".to_string()),
                key: Some("host-a".to_string()),
                ..GraphEntityLookupRequest::default()
            })
            .await,
    )
    .await;

    drop(held);
}

#[tokio::test]
async fn grouped_domain_facades_preserve_service_limiters() {
    async fn assert_busy<T>(result: ServiceResult<T>, expected: &str) {
        let err = match result {
            Ok(_) => panic!("held permit should reject the read"),
            Err(err) => err,
        };
        assert!(
            matches!(err, ServiceError::Busy(ref message) if message == expected),
            "expected {expected}, got {err:?}"
        );
    }

    let (mut service, _pool, _dir) = test_service();
    service.acquire_timeout = std::time::Duration::from_millis(10);

    let held_heavy = service
        .heavy_read_permits
        .clone()
        .acquire_owned()
        .await
        .expect("heavy permit");
    assert_busy(
        service.state().fleet(FleetStateRequest::default()).await,
        "heavy_read_limited",
    )
    .await;
    assert_busy(
        service
            .stats()
            .ingest_rate(IngestRateRequest::default())
            .await,
        "heavy_read_limited",
    )
    .await;
    assert_busy(
        service
            .analysis()
            .patterns(PatternsRequest::default())
            .await,
        "heavy_read_limited",
    )
    .await;
    assert_busy(
        service
            .analysis()
            .anomalies(AnomaliesRequest::default())
            .await,
        "heavy_read_limited",
    )
    .await;
    assert_busy(
        service
            .state()
            .clock_skew(ClockSkewRequest::default())
            .await,
        "heavy_read_limited",
    )
    .await;
    drop(held_heavy);

    let db_permits = service.db_permits.available_permits() as u32;
    let held_db = service
        .db_permits
        .clone()
        .acquire_many_owned(db_permits)
        .await
        .expect("db permits");
    assert_busy(
        service.hosts().list().await,
        "database worker limit reached",
    )
    .await;
    assert_busy(
        service
            .hosts()
            .source_ips(ListSourceIpsRequest::default())
            .await,
        "database worker limit reached",
    )
    .await;
    assert_busy(
        service
            .alerts()
            .signatures(UnaddressedErrorsRequest::default())
            .await,
        "database worker limit reached",
    )
    .await;
    drop(held_db);
}

// Regression: with only `until` supplied (no `since`), `patterns` must apply
// its 24h default anchored to `until` (until - 24h). A pre-fix build passed
// from=None, so it scanned all retained history before `until` and folded in
// stale rows outside the intended window.
#[tokio::test]
async fn patterns_until_only_bounds_window_to_24h_before_until() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            // >24h before `until` — outside the default window, must be excluded.
            entry(
                "2025-12-01T00:00:00.000Z",
                "host-a",
                "info",
                "patternwindow boundary marker",
                "10.0.0.1:514",
            ),
            // Inside the 24h window ending at `until` — must be included.
            entry(
                "2026-01-01T12:00:00.000Z",
                "host-a",
                "info",
                "patternwindow boundary marker",
                "10.0.0.1:514",
            ),
        ],
    )
    .unwrap();

    let result = service
        .analysis()
        .patterns(PatternsRequest {
            until: Some("2026-01-02T00:00:00Z".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        result.scanned, 1,
        "only the in-window row should be scanned"
    );
    assert_eq!(result.patterns.len(), 1);
    assert_eq!(result.patterns[0].count, 1);
}

#[tokio::test]
async fn graph_entity_lookup_resolves_exact_key_and_alias() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "host-a",
            "info",
            "boot complete",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);

    let exact = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let resolved = exact.resolved_entity.unwrap();
    assert_eq!(resolved.entity_type, "host");
    assert_eq!(resolved.canonical_key, "host-a");
    assert_eq!(resolved.trust_level, "claimed");
    assert_eq!(exact.metadata.projection_status, "ready");
    assert_eq!(exact.metadata.depth, 0);

    let by_id = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_id: Some(resolved.id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_id.resolved_entity.unwrap().id, resolved.id);

    let alias = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            alias_type: Some("hostname".into()),
            alias_key: Some("HOST-A".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(alias.resolved_entity.unwrap().id, resolved.id);
    assert_eq!(alias.candidates.len(), 1);
    assert_eq!(alias.candidates[0].match_reason, "alias");
}

#[tokio::test]
async fn graph_entity_lookup_rejects_mixed_or_partial_target_fields() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "host-a",
            "info",
            "ready",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);
    let host = crate::db::graph::find_graph_entity_by_key(&pool, "host", "host-a")
        .unwrap()
        .unwrap();

    let mixed = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_id: Some(host.id),
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        mixed.to_string().contains("exactly one lookup strategy"),
        "unexpected mixed-target error: {mixed}"
    );

    let partial = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_type: Some("host".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        partial.to_string().contains("`key` is required"),
        "unexpected partial-target error: {partial}"
    );
}

#[tokio::test]
async fn graph_entity_lookup_returns_candidates_for_ambiguous_alias() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00.000Z",
                "host-a",
                "info",
                "ready",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:01:00.000Z",
                "host-b",
                "info",
                "ready",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);

    let host_a = crate::db::graph::find_graph_entity_by_key(&pool, "host", "host-a")
        .unwrap()
        .unwrap();
    let host_b = crate::db::graph::find_graph_entity_by_key(&pool, "host", "host-b")
        .unwrap()
        .unwrap();
    {
        let conn = pool.get().unwrap();
        for entity_id in [host_a.id, host_b.id] {
            conn.execute(
                "INSERT INTO graph_entity_aliases (
                    entity_id, alias_type, alias_key, alias_value, source_kind,
                    trust_level, first_seen_at, last_seen_at
                 ) VALUES (
                    ?1, 'hostname', 'shared-host', 'shared-host', 'log',
                    'claimed', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'
                 )",
                [entity_id],
            )
            .unwrap();
        }
    }

    let response = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            alias_type: Some("hostname".into()),
            alias_key: Some("shared-host".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(response.resolved_entity.is_none());
    assert_eq!(response.candidates.len(), 2);
    assert!(
        response
            .candidates
            .iter()
            .all(|candidate| candidate.match_reason == "alias")
    );
}

#[tokio::test]
async fn graph_around_returns_one_hop_relationships_evidence_and_metadata() {
    let (service, pool, _dir) = test_service();
    let mut app_log = entry(
        "2026-01-01T00:00:00.000Z",
        "host-a",
        "info",
        "sshd accepted connection",
        "10.0.0.1:514",
    );
    app_log.app_name = Some("sshd".into());
    insert_logs_batch(&pool, &[app_log]).unwrap();
    refresh_graph_projection_for_test(&pool);

    let response = service
        .graph_around(GraphAroundRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            depth: Some(1),
            limit: Some(10),
            evidence_sample_limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();

    let resolved = response.resolved_entity.as_ref().unwrap();
    assert_eq!(resolved.canonical_key, "host-a");
    assert_eq!(response.metadata.projection_status, "ready");
    assert_eq!(response.metadata.depth, 1);
    assert_eq!(response.metadata.limit, 10);
    assert_eq!(response.metadata.evidence_sample_limit, 2);
    assert!(!response.metadata.truncated);
    assert!(!response.metadata.source_watermark.is_empty());
    assert!(!response.entities.is_empty());
    assert!(!response.relationships.is_empty());
    assert!(!response.evidence.is_empty());
    assert!(
        response
            .relationships
            .iter()
            .any(|rel| rel.relationship_type == "observed_as")
    );
    assert!(
        response
            .relationships
            .iter()
            .any(|rel| rel.relationship_type == "emitted_by")
    );
    assert!(
        response
            .relationships
            .iter()
            .all(|rel| !rel.evidence_ids.is_empty())
    );
    assert!(response.relationships.iter().all(|rel| {
        rel.src_entity.is_some()
            && rel.dst_entity.is_some()
            && rel.src_entity_id == rel.src_entity.as_ref().unwrap().id
            && rel.dst_entity_id == rel.dst_entity.as_ref().unwrap().id
    }));
    assert!(response.evidence.iter().all(|evidence| {
        evidence.source_log_id.is_some()
            && evidence.safe_excerpt.is_some()
            && evidence.source_kind == "log"
    }));
    assert!(
        response
            .next_queries
            .iter()
            .all(|query| query.mode == "around")
    );
}

#[tokio::test]
async fn graph_evidence_lookup_returns_safe_source_summary_and_relationship_context() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "proof-host",
            "info",
            "Autho\u{1b}rization: Bea\u{7}rer supersecret Cookie: sid=abc beginning client_secret=abc access_token=tok https://user:pass@example.test /home/jmagar/key \u{1b}[31m",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);
    let evidence_id = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT id FROM graph_relationship_evidence
             WHERE source_log_id IS NOT NULL
             ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };

    let response = service
        .graph_evidence_lookup(GraphEvidenceLookupRequest {
            evidence_id,
            payload_budget: Some(4096),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.evidence.id, evidence_id);
    assert_eq!(response.relationship.id, response.evidence.relationship_id);
    assert_eq!(response.relationship.src_entity_id, response.src_entity.id);
    assert_eq!(response.relationship.dst_entity_id, response.dst_entity.id);
    assert_eq!(
        response.relationship.src_entity.as_ref().unwrap().id,
        response.src_entity.id
    );
    assert_eq!(
        response.relationship.dst_entity.as_ref().unwrap().id,
        response.dst_entity.id
    );
    let summary = response.source_log_summary.as_ref().unwrap();
    assert_eq!(summary.id, response.evidence.source_log_id.unwrap());
    assert!(!summary.message.contains("Authorization"));
    assert!(!summary.message.contains("Bearer"));
    assert!(!summary.message.contains("supersecret"));
    assert!(!summary.message.contains("Cookie"));
    assert!(!summary.message.contains("sid=abc"));
    assert!(!summary.message.contains("client_secret"));
    assert!(!summary.message.contains("access_token"));
    assert!(!summary.message.contains("tok"));
    assert!(!summary.message.contains("user:pass"));
    assert!(!summary.message.contains("/home/jmagar"));
    assert!(summary.message.contains("beginning"));
    assert!(!summary.message.chars().any(char::is_control));
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains("raw"));
    assert!(!json.contains("metadata_json"));
}

#[tokio::test]
async fn graph_evidence_lookup_reports_deleted_source_log_without_losing_evidence() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "retained-out-host",
            "info",
            "short lived row",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);
    let (evidence_id, source_log_id): (i64, i64) = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT id, source_log_id FROM graph_relationship_evidence
             WHERE source_log_id IS NOT NULL
             ORDER BY id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    {
        let conn = pool.get().unwrap();
        conn.execute("DELETE FROM logs WHERE id = ?1", [source_log_id])
            .unwrap();
    }

    let response = service
        .graph_evidence_lookup(GraphEvidenceLookupRequest {
            evidence_id,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(response.evidence.id, evidence_id);
    assert_eq!(response.evidence.source_log_id, Some(source_log_id));
    assert!(response.source_log_summary.is_none());
    assert_eq!(
        response.missing_source_reason.as_deref(),
        Some("source_log_missing_or_retained_out")
    );
    assert_eq!(response.relationship.src_entity_id, response.src_entity.id);
    assert_eq!(response.relationship.dst_entity_id, response.dst_entity.id);
    assert_eq!(
        response.relationship.src_entity.as_ref().unwrap().id,
        response.src_entity.id
    );
    assert_eq!(
        response.relationship.dst_entity.as_ref().unwrap().id,
        response.dst_entity.id
    );
}

#[tokio::test]
async fn graph_evidence_lookup_keeps_signature_source_without_log_summary() {
    let (service, pool, _dir) = test_service();
    let mut log = entry(
        "2026-01-01T00:00:00.000Z",
        "sig-host",
        "err",
        "error 1",
        "10.0.0.1:514",
    );
    log.app_name = Some("cortex".into());
    insert_logs_batch(&pool, &[log]).unwrap();
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO error_signatures
                (signature_hash, normalizer_version, template, sample_message,
                 sample_hostname, sample_app_name, severity, first_seen_at,
                 last_seen_at, total_count)
             VALUES ('abc123', 1, 'error <id>', 'error 1', 'sig-host',
                     'cortex', 'err', '2026-01-01T00:00:00Z',
                     '2026-01-01T00:05:00Z', 3)",
            [],
        )
        .unwrap();
    }
    refresh_graph_projection_for_test(&pool);
    let evidence_id = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT id FROM graph_relationship_evidence
             WHERE source_signature_hash IS NOT NULL
             ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };

    let response = service
        .graph_evidence_lookup(GraphEvidenceLookupRequest {
            evidence_id,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        response.evidence.source_signature_hash.as_deref(),
        Some("abc123")
    );
    assert!(response.evidence.source_log_id.is_none());
    assert!(response.source_log_summary.is_none());
    assert_eq!(
        response.missing_source_reason.as_deref(),
        Some("evidence_source_is_not_a_log")
    );
}

#[tokio::test]
async fn graph_evidence_lookup_missing_id_returns_not_found() {
    let (service, pool, _dir) = test_service();
    refresh_graph_projection_for_test(&pool);
    let err = service
        .graph_evidence_lookup(GraphEvidenceLookupRequest {
            evidence_id: 999_999,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn graph_explain_returns_conservative_evidence_backed_chain() {
    let (service, pool, _dir) = test_service();
    let mut app_log = entry(
        "2026-01-01T00:00:00.000Z",
        "host-a",
        "info",
        "sshd accepted connection",
        "10.0.0.1:514",
    );
    app_log.app_name = Some("sshd".into());
    insert_logs_batch(&pool, &[app_log]).unwrap();
    refresh_graph_projection_for_test(&pool);

    let response = service
        .graph_explain(GraphExplainRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            depth: Some(2),
            beam_width: Some(10),
            max_chains: Some(20),
            evidence_sample_limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.metadata.depth, 2);
    assert!(response.narrative.is_some());
    let narrative = response.narrative.as_ref().unwrap();
    assert!(!narrative.relationship_ids.is_empty());
    assert!(!narrative.evidence_ids.is_empty());
    assert!(narrative.summary.contains("not a proven root cause"));
    assert!(!narrative.summary.contains("caused"));
    assert!(!response.chains.is_empty());
    assert!(
        response
            .chains
            .iter()
            .all(|chain| !chain.relationship_ids.is_empty() && !chain.evidence_ids.is_empty())
    );
    assert!(response.chains.iter().all(|chain| {
        chain
            .relationships
            .iter()
            .all(|rel| rel.src_entity.is_some() && rel.dst_entity.is_some())
    }));
    assert!(!response.evidence.is_empty());
    assert!(!response.next_queries.is_empty());
}

#[tokio::test]
async fn graph_explain_declines_without_relationship_evidence() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "",
            "info",
            "source only",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);

    let source = crate::db::graph::find_graph_entity_by_key(&pool, "source_ip", "10.0.0.1:514")
        .unwrap()
        .unwrap();
    let response = service
        .graph_explain(GraphExplainRequest {
            mode: None,
            entity_id: Some(source.id),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(response.narrative.is_none());
    assert!(response.chains.is_empty());
    assert!(
        response
            .missing_evidence
            .iter()
            .any(|item| item.contains("relationship evidence"))
    );
    assert!(!response.open_questions.is_empty());
}

#[tokio::test]
async fn investigation_ask_returns_safe_supported_claims_and_graph() {
    let (service, pool, _dir) = test_service();
    let mut app_log = entry(
        "2026-01-01T00:00:00.000Z",
        "host-a",
        "err",
        "nginx emitted password=secret token=abc <script>alert(1)</script>",
        "10.0.0.1:514",
    );
    app_log.app_name = Some("nginx".into());
    insert_logs_batch(&pool, &[app_log]).unwrap();
    refresh_graph_projection_for_test(&pool);

    let envelope = service
        .investigation_ask(AskInvestigationRequest {
            prompt: "Why did host-a start failing?".into(),
            host: Some("host-a".into()),
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(envelope.metadata.auth_state, "bearer");
    assert_eq!(
        envelope.metadata.graph_projection_status.as_deref(),
        Some("ready")
    );
    assert_eq!(
        envelope.result.resolved_entity.as_ref().unwrap().label,
        "host-a"
    );
    assert!(
        envelope
            .result
            .claims
            .iter()
            .any(|claim| claim.claim_type == InvestigationClaimType::SupportedCorrelation)
    );
    assert!(
        envelope
            .result
            .claims
            .iter()
            .all(|claim| !claim.summary.contains("caused"))
    );
    assert!(!envelope.result.graph.relationships.is_empty());
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(!json.contains("password="));
    assert!(!json.contains("token="));
    assert!(!json.contains("metadata_json"));
    assert!(!json.contains("source_signature_hash"));
}

#[tokio::test]
async fn graph_around_rejects_depth_above_one_and_redacts_safe_evidence() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[entry(
            "2026-01-01T00:00:00.000Z",
            "host-a",
            "info",
            "password=secret token=abc /home/jmagar/private",
            "10.0.0.1:514",
        )],
    )
    .unwrap();
    refresh_graph_projection_for_test(&pool);

    {
        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE graph_relationship_evidence
             SET safe_excerpt = 'password=secret token=abc /home/jmagar/private',
                 reason_text = 'secret token=abc',
                 source_id = '/home/jmagar/.cortex/token=abc'",
            [],
        )
        .unwrap();
    }

    let depth_err = service
        .graph_around(GraphAroundRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            depth: Some(2),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        depth_err.to_string().contains("depth=1"),
        "unexpected depth error: {depth_err}"
    );

    let zero_depth_err = service
        .graph_around(GraphAroundRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            depth: Some(0),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        zero_depth_err.to_string().contains("depth=1"),
        "unexpected depth=0 error: {zero_depth_err}"
    );

    let mixed_target_err = service
        .graph_around(GraphAroundRequest {
            mode: None,
            entity_id: Some(1),
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        mixed_target_err
            .to_string()
            .contains("exactly one lookup strategy"),
        "unexpected mixed-target error: {mixed_target_err}"
    );

    let response = service
        .graph_around(GraphAroundRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("host-a".into()),
            evidence_sample_limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let joined = response
        .evidence
        .iter()
        .filter_map(|evidence| evidence.safe_excerpt.as_deref())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(joined.contains("[redacted]"));
    assert!(!joined.contains("password=secret"));
    assert!(!joined.contains("token=abc"));
    assert!(!joined.contains("/home/jmagar"));
    let reason_text = response
        .evidence
        .iter()
        .filter_map(|evidence| evidence.reason_text.as_deref())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!reason_text.contains("secret"));
    assert!(!reason_text.contains("token=abc"));
    // Evidence source ids pass through the same redaction as the sibling
    // text fields — a secret-like source_id must never leak.
    let source_ids = response
        .evidence
        .iter()
        .map(|evidence| evidence.source_id.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(source_ids.contains("[redacted]"), "{source_ids}");
    assert!(!source_ids.contains("/home/jmagar"));
    assert!(!source_ids.contains("token=abc"));
}

#[tokio::test]
async fn graph_alias_miss_with_legacy_shape_returns_rejected_legacy_shape() {
    let (service, pool, _dir) = test_service();
    refresh_graph_projection_for_test(&pool);

    // Missed alias shaped like a legacy service identity → explicit signal.
    let err = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            alias_type: Some("hostname".into()),
            alias_key: Some("nashost:plex".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("rejected_legacy_shape"),
        "expected legacy rejection on alias miss: {err}"
    );

    // Missed alias with a canonical shape keeps the generic not-found.
    let err = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            alias_type: Some("hostname".into()),
            alias_key: Some("missing-host".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test]
async fn graph_lookup_rejects_retired_service_entity_type() {
    let (service, pool, _dir) = test_service();
    refresh_graph_projection_for_test(&pool);

    let err = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_type: Some("service".into()),
            key: Some("plex".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("unsupported graph entity_type"),
        "'service' must no longer validate as a lookup type: {err}"
    );
}

#[tokio::test]
async fn graph_entity_lookup_missing_entity_returns_not_found() {
    let (service, pool, _dir) = test_service();
    refresh_graph_projection_for_test(&pool);

    let err = service
        .graph_entity_lookup(GraphEntityLookupRequest {
            mode: None,
            entity_type: Some("host".into()),
            key: Some("missing-host".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "unexpected missing entity error: {err}"
    );
}

#[test]
fn normalize_syslog_owned_service_rejects_arbitrary_units() {
    assert_eq!(
        normalize_syslog_owned_service("cortex-sessions-watch").unwrap(),
        "cortex-sessions-watch.service"
    );

    let err = normalize_syslog_owned_service("ssh").unwrap_err();
    assert!(err.to_string().contains("unsupported cortex-owned service"));
}

#[test]
fn parse_journal_json_lines_extracts_service_log_fields() {
    let raw = r#"{"__REALTIME_TIMESTAMP":"1780000000123456","_SYSTEMD_USER_UNIT":"cortex-sessions-watch.service","PRIORITY":"3","CORTEX_IDENTIFIER":"syslog","_PID":"42","MESSAGE":"AI transcript indexing failed","__CURSOR":"cursor-1"}"#;

    let (entries, dropped) = parse_journal_json_lines(raw);
    assert_eq!(dropped, 0);

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].unit.as_deref(),
        Some("cortex-sessions-watch.service")
    );
    assert_eq!(entries[0].priority.as_deref(), Some("3"));
    assert_eq!(entries[0].syslog_identifier.as_deref(), Some("syslog"));
    assert_eq!(entries[0].pid.as_deref(), Some("42"));
    assert_eq!(
        entries[0].message.as_deref(),
        Some("AI transcript indexing failed")
    );
    assert_eq!(entries[0].cursor.as_deref(), Some("cursor-1"));
    assert!(entries[0].timestamp.is_some());
}

#[tokio::test]
async fn incident_returns_ordered_db_events_for_window() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00.000Z",
                "host-a",
                "info",
                "before",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:05:00.000Z",
                "host-a",
                "err",
                "middle",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:11:00.000Z",
                "host-a",
                "warning",
                "after",
                "10.0.0.1:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .incident(IncidentRequest {
            around: Some("2026-01-01T00:05:00Z".into()),
            minutes: Some(5),
            service: None,
            host: Some("host-a".into()),
            limit: Some(10),
        })
        .await
        .unwrap();

    assert_eq!(response.window_from, "2026-01-01T00:00:00.000Z");
    assert_eq!(response.window_to, "2026-01-01T00:10:00.000Z");
    assert_eq!(response.events.len(), 2);
    assert_eq!(response.events[0].message, "before");
    assert_eq!(response.events[1].message, "middle");
}

#[tokio::test]
async fn correlate_events_normalizes_window_groups_and_truncates() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00+00:00",
                "host-a",
                "err",
                "disk full",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:01:00+00:00",
                "host-b",
                "warning",
                "service slow",
                "10.0.0.2:514",
            ),
            entry(
                "2026-01-01T00:02:00+00:00",
                "host-b",
                "info",
                "ignored info",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_events(CorrelateEventsRequest {
            reference_time: Some("2026-01-01T01:00:00+01:00".into()),
            window_minutes: Some(2),
            severity_min: Some("warning".into()),
            host: None,
            source: None,
            query: None,
            limit: Some(1),
        })
        .await
        .unwrap();

    assert_eq!(response.window_from, "2025-12-31T23:58:00.000Z");
    assert_eq!(response.window_to, "2026-01-01T00:02:00.000Z");
    assert!(response.truncated);
    assert_eq!(response.total_events, 1);
    assert_eq!(response.hosts_count, 1);
}

#[tokio::test]
async fn correlate_events_derives_reference_time_from_query_when_omitted() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            ai_entry(
                "2026-03-01T10:00:00Z",
                "nginx ssl certificate error investigation",
            ),
            entry(
                "2026-03-01T10:00:30Z",
                "host-a",
                "err",
                "nginx: ssl certificate expired",
                "10.0.0.1:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_events(CorrelateEventsRequest {
            reference_time: None,
            window_minutes: Some(5),
            severity_min: None,
            host: None,
            source: None,
            query: Some("certificate".into()),
            limit: None,
        })
        .await
        .unwrap();

    assert!(response.matched_session.is_some());
    assert_eq!(response.reference_time, "2026-03-01T10:00:00.000Z");
    assert!(response.total_events >= 1);
}

#[tokio::test]
async fn correlate_events_defaults_to_now_without_reference_time_or_query() {
    let (service, _pool, _dir) = test_service();
    let response = service
        .correlate_events(CorrelateEventsRequest {
            reference_time: None,
            window_minutes: None,
            severity_min: None,
            host: None,
            source: None,
            query: None,
            limit: None,
        })
        .await
        .unwrap();
    assert_eq!(response.window_minutes, 5);
    assert_eq!(response.severity_min, "warning");
    assert!(response.matched_session.is_none());
    assert_eq!(response.total_events, 0);
}

#[tokio::test]
async fn correlate_events_errors_when_no_ai_session_matches_query() {
    let (service, _pool, _dir) = test_service();
    let err = service
        .correlate_events(CorrelateEventsRequest {
            reference_time: None,
            window_minutes: None,
            severity_min: None,
            host: None,
            source: None,
            query: Some("nonexistent_topic_xyz".into()),
            limit: None,
        })
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("no AI session found"));
}

#[tokio::test]
async fn correlate_ai_logs_cross_references_non_ai_logs_only() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            ai_entry("2026-01-01T00:00:00Z", "debug deployment failure"),
            entry(
                "2026-01-01T00:01:00Z",
                "host-a",
                "err",
                "container failed during deployment",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:02:00Z",
                "host-a",
                "info",
                "filtered by severity",
                "10.0.0.1:514",
            ),
            ai_entry("2026-01-01T00:03:00Z", "ai row should not be related"),
        ],
    )
    .unwrap();

    let response = service
        .correlate_ai_logs(AiCorrelateRequest {
            project: Some("/tmp/project".into()),
            tool: Some("codex".into()),
            ai_query: Some("deployment".into()),
            log_query: Some("container".into()),
            window_minutes: Some(5),
            severity_min: Some("warning".into()),
            limit: Some(1),
            events_per_anchor: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.total_anchors, 1);
    assert_eq!(response.total_related_events, 1);
    assert_eq!(
        response.anchors[0].related[0].message,
        "container failed during deployment"
    );
    assert!(response.anchors[0].related[0].ai_project.is_none());
}

#[tokio::test]
async fn correlate_ai_logs_defaults_to_info_evidence() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            ai_entry("2026-01-01T00:00:00Z", "investigate cargo deny"),
            entry(
                "2026-01-01T00:00:30Z",
                "runner-a",
                "info",
                "Cargo Deny succeeded",
                "10.0.0.1:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_ai_logs(AiCorrelateRequest {
            project: Some("/tmp/project".into()),
            ai_query: Some("cargo".into()),
            log_query: Some("Cargo Deny".into()),
            window_minutes: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.severity_min, "info");
    assert_eq!(response.total_related_events, 1);
    assert_eq!(
        response.anchors[0].related[0].message,
        "Cargo Deny succeeded"
    );
}

#[tokio::test]
async fn correlate_state_excludes_ai_transcript_rows() {
    let (service, pool, _dir) = test_service();

    // A heartbeat in the window makes host-a appear in the summaries.
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO host_heartbeats (
                 host_id, hostname, source_ip, sampled_at, received_at, boot_id,
                 uptime_secs, sequence, collection_ms, partial, agent_version,
                 os, architecture, metadata_json
             ) VALUES ('host-a', 'host-a', '10.0.0.1:41000',
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'boot-a',
                       60, 1, 5, 0, '0.1.0', 'linux', 'x86_64', '{}')",
            [],
        )
        .unwrap();
    }

    // A real syslog line and an AI-transcript line, both on host-a, in window.
    let mut ai_on_host = entry(
        "2026-01-01T00:01:00Z",
        "host-a",
        "info",
        "ai transcript noise that must not surface",
        "transcript://codex",
    );
    ai_on_host.app_name = Some("codex-transcript".into());
    ai_on_host.ai_tool = Some("codex".into());
    ai_on_host.ai_project = Some("/tmp/project".into());
    ai_on_host.ai_session_id = Some("sess-1".into());
    ai_on_host.ai_transcript_path = Some("/tmp/project/sess-1.jsonl".into());

    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:01:30Z",
                "host-a",
                "err",
                "real syslog line in window",
                "10.0.0.1:514",
            ),
            ai_on_host,
        ],
    )
    .unwrap();

    let response = service
        .correlate_state(CorrelateStateRequest {
            reference_time: Some("2026-01-01T00:00:00Z".into()),
            window_minutes: None,
            host: None,
            severity_min: None,
            limit: None,
        })
        .await
        .unwrap();

    let host = response
        .hosts
        .iter()
        .find(|h| h.hostname == "host-a")
        .expect("host-a should be present in correlate_state results");

    assert!(
        host.logs
            .iter()
            .any(|l| l.message == "real syslog line in window"),
        "non-AI syslog line should be correlated: {:?}",
        host.logs
    );
    assert!(
        host.logs.iter().all(|l| l.ai_project.is_none()
            && l.ai_transcript_path.is_none()
            && l.ai_session_id.is_none()),
        "correlate_state must never return AI transcript rows: {:?}",
        host.logs
    );
}

#[tokio::test]
async fn correlate_ai_logs_batches_related_windows_with_per_anchor_caps() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            ai_entry("2026-01-01T00:00:00Z", "deploy failure near host-a"),
            entry(
                "2026-01-01T00:00:10Z",
                "host-a",
                "err",
                "deploy failed on host-a",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:00:20Z",
                "host-a",
                "warning",
                "deploy warning on host-a",
                "10.0.0.1:514",
            ),
            ai_entry("2026-01-01T00:10:00Z", "deploy failure near host-b"),
            entry(
                "2026-01-01T00:10:10Z",
                "host-b",
                "err",
                "deploy failed on host-b",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_ai_logs(AiCorrelateRequest {
            project: Some("/tmp/project".into()),
            tool: Some("codex".into()),
            ai_query: Some("deploy".into()),
            log_query: Some("deploy".into()),
            window_minutes: Some(1),
            severity_min: Some("warning".into()),
            limit: Some(2),
            events_per_anchor: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.total_anchors, 2);
    assert_eq!(response.related_limit_per_anchor, 1);
    assert_eq!(response.total_related_events, 2);
    let truncated_count = response
        .anchors
        .iter()
        .filter(|anchor| anchor.related_truncated)
        .count();
    assert_eq!(truncated_count, 1);
    assert!(
        response
            .anchors
            .iter()
            .all(|anchor| anchor.related.len() == 1)
    );
}

#[tokio::test]
async fn correlate_ai_logs_rest_policy_reports_service_owned_clamp() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            ai_entry("2026-01-01T00:00:00Z", "deploy failure near host-a"),
            entry(
                "2026-01-01T00:00:10Z",
                "host-a",
                "err",
                "deploy failed on host-a",
                "10.0.0.1:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .correlate_ai_logs_with_limit_policy(
            AiCorrelateRequest {
                project: Some("/tmp/project".into()),
                tool: Some("codex".into()),
                ai_query: Some("deploy".into()),
                window_minutes: Some(1),
                limit: Some(1),
                events_per_anchor: Some(10_000),
                ..Default::default()
            },
            AiCorrelateLimitPolicy::REST,
        )
        .await
        .unwrap();

    assert_eq!(response.related_limit_per_anchor, 50);
    assert_eq!(response.events_per_anchor_clamped_to, Some(50));
}

#[tokio::test]
async fn source_ip_filter_uses_network_sender_identity() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "spoofed-host",
                "err",
                "from one",
                "10.0.0.1:514",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "spoofed-host",
                "err",
                "from two",
                "10.0.0.2:514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .search_logs(SearchLogsRequest {
            source: Some("10.0.0.2:514".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(response.count, 1);
    assert_eq!(response.logs[0].message, "from two");
}

#[tokio::test]
async fn search_logs_rejects_invalid_severity() {
    let (service, _pool, _dir) = test_service();

    let err = service
        .search_logs(SearchLogsRequest {
            severity: Some("bogus".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid severity 'bogus'"));
    assert!(err.to_string().contains("emerg, alert, crit"));
}

#[tokio::test]
async fn filter_logs_maps_docker_stream_alias_to_source_prefix() {
    let (service, pool, _dir) = test_service();
    let mut stdout = entry(
        "2026-01-01T00:00:00Z",
        "devhost",
        "info",
        "docker stdout",
        "docker://devhost/cortex/stdout",
    );
    stdout.app_name = Some("cortex".into());
    let mut other = entry(
        "2026-01-01T00:00:01Z",
        "devhost",
        "info",
        "other stdout",
        "docker://devhost/other/stdout",
    );
    other.app_name = Some("other".into());
    insert_logs_batch(&pool, &[stdout, other]).unwrap();

    let response = service
        .filter_logs(FilterLogsRequest {
            source_kind: Some("docker-stream".into()),
            docker_host: Some("devhost".into()),
            container: Some("cortex".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.count, 1);
    assert_eq!(response.logs[0].message, "docker stdout");
}

#[tokio::test]
async fn filter_logs_rejects_queryless_json_only_source_kind() {
    let (service, _pool, _dir) = test_service();

    let err = service
        .filter_logs(FilterLogsRequest {
            source_kind: Some("otlp".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(err.to_string().contains("not indexed separately in v1"));
}

#[tokio::test]
async fn filter_logs_file_tail_source_kind_uses_source_prefix() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "edgehost",
                "info",
                "file-tail row",
                "file-tail://edgehost/swag-access",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "edgehost",
                "info",
                "normal row",
                "10.0.0.5:1514",
            ),
        ],
    )
    .unwrap();

    let response = service
        .filter_logs(FilterLogsRequest {
            source_kind: Some("file-tail".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.count, 1);
    assert_eq!(response.logs[0].message, "file-tail row");
}

#[tokio::test]
async fn filter_logs_shell_history_alias_covers_direct_and_forwarded_rows() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[
            entry(
                "2026-01-01T00:00:00Z",
                "devhost",
                "info",
                "direct command",
                "shell-history://devhost/user/zsh",
            ),
            entry(
                "2026-01-01T00:00:01Z",
                "devhost",
                "info",
                "forwarded command",
                "agent-shell-history://devhost/user/bash",
            ),
            entry(
                "2026-01-01T00:00:02Z",
                "devhost",
                "info",
                "unrelated",
                "file-tail://devhost/messages",
            ),
        ],
    )
    .unwrap();

    let response = service
        .filter_logs(FilterLogsRequest {
            host: Some("devhost".into()),
            source_kind: Some("shell-history".into()),
            limit: Some(200),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.count, 2);
    let messages: Vec<_> = response
        .logs
        .iter()
        .map(|row| row.message.as_str())
        .collect();
    assert!(messages.contains(&"direct command"));
    assert!(messages.contains(&"forwarded command"));
}

#[tokio::test]
async fn filter_logs_rejects_conflicting_source_kind_tool_alias() {
    let (service, _pool, _dir) = test_service();

    let err = service
        .filter_logs(FilterLogsRequest {
            source_kind: Some("claude".into()),
            tool: Some("codex".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("source_kind=claude conflicts with tool=codex")
    );
}

#[tokio::test]
async fn filter_logs_transcript_source_kind_excludes_agent_commands() {
    let (service, pool, _dir) = test_service();

    let transcript = ai_entry("2026-01-01T00:00:00Z", "transcript row");
    let mut agent_command = entry(
        "2026-01-01T00:00:01Z",
        "localhost",
        "info",
        "agent command row",
        "agent-command://localhost/codex/sess-1",
    );
    agent_command.ai_tool = Some("codex".into());
    agent_command.ai_project = Some("/tmp/project".into());
    agent_command.ai_session_id = Some("sess-1".into());

    insert_logs_batch(&pool, &[transcript, agent_command]).unwrap();

    let response = service
        .filter_logs(FilterLogsRequest {
            source_kind: Some("transcript".into()),
            tool: Some("codex".into()),
            project: Some("/tmp/project".into()),
            session_id: Some("sess-1".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.count, 1);
    assert_eq!(response.logs[0].message, "transcript row");
    assert!(response.logs[0].source_ip.starts_with("transcript://"));
}

#[tokio::test]
async fn health_check_runs_simple_database_query() {
    let (service, _pool, _dir) = test_service();

    service.health_check().await.unwrap();
}

#[tokio::test]
async fn ai_service_methods_return_seeded_data() {
    let (service, pool, _dir) = test_service();
    insert_logs_batch(
        &pool,
        &[LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            hostname: "host-a".into(),
            facility: Some("local0".into()),
            severity: "info".into(),
            app_name: Some("claude".into()),
            process_id: None,
            message: "authentication bug fixed".into(),
            raw: "authentication bug fixed".into(),
            source_ip: "127.0.0.1:514".into(),
            docker_checkpoint: None,
            ai_tool: Some("claude".into()),
            ai_project: Some("/tmp/project".into()),
            ai_session_id: Some("sess-1".into()),
            ai_transcript_path: Some("/tmp/project/session.jsonl".into()),
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        }],
    )
    .unwrap();

    let search = service
        .search_sessions(SearchSessionsRequest {
            query: "authentication".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(search.sessions.len(), 1);

    let tools = service
        .list_ai_tools(ListAiToolsRequest::default())
        .await
        .unwrap();
    assert_eq!(tools.tools[0].tool, "claude");
}

#[tokio::test]
async fn run_gemini_assess_rejects_missing_incident_before_gemini() {
    let (service, _pool, _dir) = test_service();

    let err = service
        .run_gemini_assess_with_delta(
            AiAssessRequest {
                incident_id: "missing-incident".into(),
                model: Some("gemini-test-model".into()),
                project: None,
                tool: None,
                since: None,
                until: None,
                window_minutes: Some(30),
                correlation_window_minutes: Some(10),
                terms: vec!["panic".into()],
                limit: Some(1),
            },
            |_| panic!("gemini should not be invoked when the incident is absent"),
        )
        .await
        .unwrap_err();

    match err {
        ServiceError::InvalidInput(message) => {
            assert!(message.contains("no incident found with id 'missing-incident'"));
        }
        other => panic!("expected invalid input, got {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn ai_assess_writes_llm_invocation_audit_row_via_runner() {
    let (service, pool, _dir) = test_service();

    // Seed AI-transcript log rows containing an abuse term so
    // investigate_ai_incidents finds a real, deterministic incident_id
    // (a DefaultHasher digest of project/tool/session/hostname/anchor ids —
    // must be read back, never hardcoded).
    let entries: Vec<LogBatchEntry> = (0..3)
        .map(|i| LogBatchEntry {
            timestamp: format!("2026-01-01T00:0{i}:00Z"),
            hostname: "host-a".into(),
            facility: Some("local0".into()),
            severity: "info".into(),
            app_name: Some("ai-transcript".into()),
            process_id: None,
            message: "this shit needs assessment".into(),
            raw: "this shit needs assessment".into(),
            source_ip: "127.0.0.1:514".into(),
            docker_checkpoint: None,
            ai_tool: Some("codex".into()),
            ai_project: Some("/tmp/project".into()),
            ai_session_id: Some(format!("sess-{i:02}")),
            ai_transcript_path: Some(format!("/tmp/project/sess-{i:02}.jsonl")),
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        })
        .collect();
    insert_logs_batch(&pool, &entries).unwrap();

    let listed = service
        .investigate_ai_incidents(AiInvestigateRequest {
            project: Some("/tmp/project".into()),
            tool: Some("codex".into()),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    let incident_id = listed.evidence[0].incident.incident_id.clone();

    // Point CORTEX_HEADLESS_GEMINI_CMD at a fake "gemini" script that emits
    // a minimal valid stream-json assistant text event, so
    // run_gemini_assessment succeeds without needing a real Gemini CLI —
    // same fake-script-on-PATH pattern used by
    // src/assessment_tests.rs::gemini_assessment_timeout_kills_and_reaps_child.
    //
    // `cat >/dev/null` drains stdin before the script prints anything: the
    // parent's stdin_task is writing the prompt concurrently, and under
    // heavy parallel-test-suite scheduling pressure this script could
    // otherwise exit (closing its stdin read end) before that write
    // completed, surfacing a spurious "Broken pipe" from run_gemini_assessment.
    // Reading stdin to EOF first makes the child block until the parent's
    // write+shutdown finishes, removing the race deterministically.
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(source.path().join(".gemini")).unwrap();
    std::fs::write(source.path().join(".gemini").join("settings.json"), "{}").unwrap();
    let script = source.path().join("fake-gemini.sh");
    std::fs::write(
        &script,
        "#!/usr/bin/env bash\ncat >/dev/null\necho '{\"type\":\"message\",\"role\":\"assistant\",\"content\":\"ok\"}'\necho '{\"type\":\"result\",\"status\":\"success\"}'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    let _cmd = EnvGuard::set("CORTEX_HEADLESS_GEMINI_CMD", script.display().to_string());
    let _home = EnvGuard::set(
        "CORTEX_HEADLESS_GEMINI_HOME",
        source.path().display().to_string(),
    );

    let response = service
        .run_gemini_assess(AiAssessRequest {
            incident_id: incident_id.clone(),
            model: None,
            project: None,
            tool: None,
            since: None,
            until: None,
            window_minutes: None,
            correlation_window_minutes: None,
            terms: Vec::new(),
            limit: None,
        })
        .await
        .unwrap();
    assert_eq!(response.incident_id, incident_id);

    let conn = pool.get().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM llm_invocations WHERE action = 'ai_assess' AND status = 'success'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "run_gemini_assess must audit through LlmRunner");
}

// Eng review fix (code-simplicity-reviewer, GH issue #94): `LlmRunner::dry_run`
// was fully implemented and unit-tested but had zero CLI/MCP/REST callers.
// `dry_run_gemini_assess` wires it into `cortex sessions assess --dry-run`.
// This test proves the dry-run path short-circuits before any subprocess
// spawn: deliberately do NOT set CORTEX_HEADLESS_GEMINI_CMD/HOME (unlike
// the sibling `ai_assess_writes_llm_invocation_audit_row_via_runner` test
// above) — if `dry_run_gemini_assess` ever tried to spawn Gemini, it would
// fail loudly (missing binary) rather than silently succeed, since no fake
// script is on PATH here.
#[tokio::test]
#[serial]
async fn ai_assess_dry_run_previews_without_spawning_gemini_subprocess() {
    let (service, pool, _dir) = test_service();

    let entries: Vec<LogBatchEntry> = (0..3)
        .map(|i| LogBatchEntry {
            timestamp: format!("2026-01-01T00:0{i}:00Z"),
            hostname: "host-a".into(),
            facility: Some("local0".into()),
            severity: "info".into(),
            app_name: Some("ai-transcript".into()),
            process_id: None,
            message: "this shit needs assessment".into(),
            raw: "this shit needs assessment".into(),
            source_ip: "127.0.0.1:514".into(),
            docker_checkpoint: None,
            ai_tool: Some("codex".into()),
            ai_project: Some("/tmp/project-dry-run".into()),
            ai_session_id: Some(format!("sess-dr-{i:02}")),
            ai_transcript_path: Some(format!("/tmp/project-dry-run/sess-dr-{i:02}.jsonl")),
            metadata_json: None,
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        })
        .collect();
    insert_logs_batch(&pool, &entries).unwrap();

    let listed = service
        .investigate_ai_incidents(AiInvestigateRequest {
            project: Some("/tmp/project-dry-run".into()),
            tool: Some("codex".into()),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    let incident_id = listed.evidence[0].incident.incident_id.clone();

    // No CORTEX_HEADLESS_GEMINI_CMD/HOME set — if dry_run_gemini_assess
    // spawned a real subprocess it would fail to find `gemini` on PATH
    // (or hang), not silently pass.
    let outcome = service
        .dry_run_gemini_assess(AiAssessRequest {
            incident_id: incident_id.clone(),
            model: None,
            project: None,
            tool: None,
            since: None,
            until: None,
            window_minutes: None,
            correlation_window_minutes: None,
            terms: Vec::new(),
            limit: None,
        })
        .await
        .unwrap();

    assert!(outcome.prompt_bytes > 0);
    assert!(!outcome.would_exceed_prompt_limit);
    assert_eq!(outcome.evidence_counts.evidence_bundle_count, 1);

    let conn = pool.get().unwrap();
    let (status, incident_col): (String, Option<String>) = conn
        .query_row(
            "SELECT status, incident_id FROM llm_invocations WHERE id = ?1",
            [&outcome.invocation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "dry_run");
    assert_eq!(incident_col.as_deref(), Some(incident_id.as_str()));

    // No "running" or "success" row should exist for this action — proves
    // the real run_fn path (which would create those statuses) never ran.
    let real_run_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM llm_invocations WHERE action = 'ai_assess' AND status IN ('running', 'success')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        real_run_count, 0,
        "dry-run must never produce a running/success row (that would mean a real invocation happened)"
    );
}

#[tokio::test]
async fn llm_invocations_checked_returns_recent_rows_filtered() {
    let (service, pool, _dir) = test_service();
    let conn = pool.get().unwrap();
    let params = crate::db::llm_invocations::LlmInvocationInsertParams {
        caller_surface: "test".to_string(),
        action: "ai_assess".to_string(),
        provider: "gemini-cli".to_string(),
        model: Some("m".to_string()),
        program: Some("gemini".to_string()),
        incident_id: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        evidence_counts_json: None,
        prompt_bytes: Some(10),
        status: "running".to_string(),
        metadata_json: None,
    };
    crate::db::llm_invocations::insert_llm_invocation_running(&conn, "llm-x", &params).unwrap();
    crate::db::llm_invocations::finish_llm_invocation(&conn, "llm-x", "success", None, 5, Some(20))
        .unwrap();
    drop(conn);

    let rows = service
        .llm_invocations_checked(crate::app::LlmInvocationsRequest {
            limit: Some(10),
            since: None,
            action: Some("ai_assess".to_string()),
            status: None,
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "llm-x");
}

// `tracing_test::traced_test` captures TRACE-level events by default, so the
// `tracing::debug!` calls emitted by `run_db` are visible to `logs_contain`.
// We verify both the message tag and the structured timing fields are present.
#[tokio::test]
#[tracing_test::traced_test]
async fn run_db_emits_timing_trace_on_success() {
    let (service, _pool, _dir) = test_service();

    service.health_check().await.unwrap();

    assert!(logs_contain("db op ok"));
    assert!(logs_contain("op=\"health_check\""));
    assert!(logs_contain("permit_ms"));
    assert!(logs_contain("exec_ms"));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn run_db_emits_warn_on_slow_op() {
    use std::time::Duration;
    let (service, _pool, _dir) = test_service();

    service
        .run_db("slow_test", |_pool| {
            std::thread::sleep(Duration::from_millis(SLOW_DB_MS as u64 + 50));
            Ok(())
        })
        .await
        .unwrap();

    // Slow ops escalate to WARN level; message stays "db op ok" so aggregators
    // can filter a single message across all speeds, using exec_ms for the threshold.
    assert!(logs_contain("WARN"));
    assert!(logs_contain("db op ok"));
    assert!(logs_contain("op=\"slow_test\""));
    assert!(logs_contain("permit_ms"));
    assert!(logs_contain("exec_ms"));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn run_db_emits_warn_on_semaphore_closed() {
    let (service, _pool, _dir) = test_service();
    service.db_permits.close();

    let err = service.run_db("closed_test", |_| Ok(())).await.unwrap_err();

    assert!(
        matches!(err, ServiceError::Busy(_)),
        "expected Busy, got {err:?}"
    );
    assert!(logs_contain("db semaphore closed"));
    assert!(logs_contain("op=\"closed_test\""));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn run_db_emits_warn_on_slow_op_with_error() {
    use std::time::Duration;
    let (service, _pool, _dir) = test_service();

    let _: ServiceResult<()> = service
        .run_db("slow_err_test", |_pool| {
            std::thread::sleep(Duration::from_millis(SLOW_DB_MS as u64 + 50));
            Err(anyhow::anyhow!("simulated slow failure"))
        })
        .await;

    assert!(logs_contain("WARN"));
    assert!(logs_contain("db op err"));
    assert!(logs_contain("op=\"slow_err_test\""));
    assert!(logs_contain("error="));
}

#[tokio::test]
async fn timeline_applies_default_lookback_only_when_from_and_to_both_absent() {
    // Bead dyqw: the bucket-sized default lookback was centralized into
    // `CortexService::timeline`. It must apply ONLY when both `from` and `to`
    // are absent (preventing an unbounded full-table scan), and must be SKIPPED
    // whenever `to` is supplied — preserving the zl9y guard against injecting a
    // `from` that would create an impossible range.
    let (service, pool, _dir) = test_service();
    let now = chrono::Utc::now();
    let fmt = |dt: chrono::DateTime<chrono::Utc>| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let recent = fmt(now - chrono::Duration::days(2));
    let old = fmt(now - chrono::Duration::days(400));
    insert_logs_batch(
        &pool,
        &[
            entry(&recent, "host-a", "info", "recent", "10.0.0.1:514"),
            entry(&old, "host-a", "info", "old", "10.0.0.1:514"),
        ],
    )
    .unwrap();
    // The day bucket reads the timeline_hourly rollup; populate it (the
    // background task does this in prod). The default-lookback `from`/`to` are
    // applied above the rollup read, so this exercises that filtering path.
    crate::db::refresh_timeline_rollup(&pool).unwrap();

    // Both absent → day bucket default (30 days) excludes the 400-day-old log.
    let resp = service
        .timeline(TimelineRequest {
            bucket: Some("day".into()),
            group_by: None,
            since: None,
            until: None,
            host: None,
            app: None,
            severity_min: None,
        })
        .await
        .unwrap();
    let total: i64 = resp.points.iter().map(|p| p.count).sum();
    assert_eq!(
        total, 1,
        "default 30-day window must exclude the 400-day-old log"
    );

    // `to` set (1 day ago), `from` absent → the default MUST be skipped. The
    // 400-day-old log predates any 30-day default window; it is counted only if
    // no default `from` was injected. If the guard regressed (default applied
    // whenever from is None), the range would be [now-30d, now-1d] and the old
    // log would drop, yielding 1 instead of 2.
    let to = fmt(now - chrono::Duration::days(1));
    let resp2 = service
        .timeline(TimelineRequest {
            bucket: Some("day".into()),
            group_by: None,
            since: None,
            until: Some(to),
            host: None,
            app: None,
            severity_min: None,
        })
        .await
        .unwrap();
    let total2: i64 = resp2.points.iter().map(|p| p.count).sum();
    assert_eq!(
        total2, 2,
        "with `to` set and `from` omitted, the default must be skipped so both logs (<= to) are counted"
    );
}

#[tokio::test]
async fn run_db_preserves_typed_service_error_through_anyhow_chain() {
    let (service, _pool, _dir) = test_service();

    let err = service
        .run_db("test.invalid_input", |_pool| {
            Err::<(), _>(anyhow::Error::new(ServiceError::InvalidInput(
                "bad limit".into(),
            )))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ServiceError::InvalidInput(_)),
        "expected InvalidInput, got {err:?}"
    );

    let err = service
        .run_db("test.not_found", |_pool| {
            Err::<(), _>(anyhow::Error::new(ServiceError::NotFound("row 42".into())))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ServiceError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );

    let err = service
        .run_db("test.internal", |_pool| {
            Err::<(), _>(anyhow::anyhow!("disk I/O error"))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ServiceError::Internal(_)),
        "expected Internal, got {err:?}"
    );
}

#[test]
fn read_permits_reserve_a_writer_connection() {
    // full-review PH3: one pooled connection stays reachable by writers.
    assert_eq!(read_permits_for_pool(4), 3);
    assert_eq!(read_permits_for_pool(2), 1);
    // Floor of 1 keeps single-connection test pools usable (the writer
    // shares in that degenerate case).
    assert_eq!(read_permits_for_pool(1), 1);
    assert_eq!(read_permits_for_pool(0), 1);
}

/// full-review PH3/TH1: with every read permit held by slow MCP reads, the
/// The read semaphore must be sized from `PoolBudget`, not from an independent
/// formula that can drift away from the lane table it is supposed to reserve
/// for.
#[test]
fn service_read_permits_come_from_the_pool_budget() {
    for pool_size in [0u32, 1, 2, 4, 8, 16, 64] {
        assert_eq!(
            read_permits_for_pool(pool_size),
            PoolBudget::for_pool_size(pool_size).read_permits(),
            "pool_size {pool_size}"
        );
    }
    // The shipped default: 8 connections, 4 reserved, 4 read permits.
    assert_eq!(read_permits_for_pool(8), 4);
}

#[test]
fn service_semaphore_is_constructed_with_the_budgeted_permits() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = StorageConfig::for_test(dir.path().join("permit-count.db"));
    storage.pool_size = 8;
    let pool = Arc::new(init_pool(&storage).unwrap());
    let budget = storage.pool_budget();
    let service = CortexService::new(pool, storage);
    assert_eq!(
        service.db_permits.available_permits(),
        budget.read_permits()
    );
    assert_eq!(service.db_permits.available_permits(), 4);
}

/// batch-writer path (direct pool access, no service permit) must still reach
/// a connection promptly. Before the permit reservation, 4 concurrent reads
/// held all 4 pooled connections and the writer blocked up to the pool
/// timeout per flush — the ingest channel then filled and packets dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_writer_completes_under_saturated_read_permits() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = StorageConfig::for_test(dir.path().join("writer-liveness.db"));
    storage.pool_size = 4;
    let pool = Arc::new(init_pool(&storage).unwrap());
    let service = CortexService::new(Arc::clone(&pool), storage);

    // Saturate every read permit with reads that pin a pooled connection for
    // longer than the writer's deadline below. A 4-connection pool is below
    // `MIN_POOL_SIZE`, so `PoolBudget` falls back to reserving 1 and issues 3.
    let mut readers = Vec::new();
    for _ in 0..3 {
        let svc = service.clone();
        readers.push(tokio::spawn(async move {
            svc.run_db("test.slow_read", |pool| {
                let _conn = pool.get()?;
                std::thread::sleep(std::time::Duration::from_millis(1200));
                Ok(())
            })
            .await
        }));
    }
    // Let the readers acquire their permits and connections.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let pool_w = Arc::clone(&pool);
    let write_start = std::time::Instant::now();
    let written = tokio::task::spawn_blocking(move || {
        insert_logs_batch(
            &pool_w,
            &[entry(
                "2026-01-01T00:00:00Z",
                "host-w",
                "info",
                "writer liveness probe",
                "127.0.0.1:514",
            )],
        )
    })
    .await
    .expect("spawn_blocking join")
    .expect("batch insert should succeed");
    let elapsed = write_start.elapsed();

    assert_eq!(written, 1);
    assert!(
        elapsed < std::time::Duration::from_millis(800),
        "writer must reach the reserved connection promptly under read \
         saturation; took {elapsed:?}"
    );

    for reader in readers {
        reader
            .await
            .expect("reader join")
            .expect("slow read should succeed");
    }
}

#[tokio::test]
async fn file_tails_add_list_disable_enable_remove_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        registry,
        Arc::new(|| Ok(())),
        Arc::new(Vec::new),
    );
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let add = service
        .file_tails(crate::app::FileTailRequest::add(
            crate::app::FileTailAddRequest {
                id: "swag-access".into(),
                path: log_path.to_string_lossy().into_owned(),
                tag: "swag-access".into(),
                host: Some("edgehost".into()),
                facility: Some("local4".into()),
                severity: Some("info".into()),
                start_at_end: Some(true),
            },
        ))
        .await
        .unwrap();
    assert_eq!(add.sources.len(), 1);
    assert_eq!(add.sources[0].id, "swag-access");

    let disabled = service
        .file_tails(crate::app::FileTailRequest::id_op(
            crate::app::FileTailOp::Disable,
            "swag-access".into(),
        ))
        .await
        .unwrap();
    assert_eq!(disabled.sources.len(), 1);
    assert!(!disabled.sources[0].enabled);

    let enabled = service
        .file_tails(crate::app::FileTailRequest::id_op(
            crate::app::FileTailOp::Enable,
            "swag-access".into(),
        ))
        .await
        .unwrap();
    assert_eq!(enabled.sources.len(), 1);
    assert!(enabled.sources[0].enabled);

    let listed = service
        .file_tails(crate::app::FileTailRequest::list())
        .await
        .unwrap();
    assert_eq!(listed.sources.len(), 1);

    let removed = service
        .file_tails(crate::app::FileTailRequest::id_op(
            crate::app::FileTailOp::Remove,
            "swag-access".into(),
        ))
        .await
        .unwrap();
    assert!(removed.sources.is_empty());
}

#[tokio::test]
async fn file_tails_list_and_status_do_not_reconcile() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let reconcile_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        Arc::clone(&registry),
        {
            let reconcile_count = Arc::clone(&reconcile_count);
            Arc::new(move || {
                reconcile_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        },
        Arc::new(Vec::new),
    );
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    service
        .file_tails(crate::app::FileTailRequest::add(
            crate::app::FileTailAddRequest {
                id: "swag-access".into(),
                path: log_path.to_string_lossy().into_owned(),
                tag: "swag-access".into(),
                host: Some("edgehost".into()),
                facility: Some("local4".into()),
                severity: Some("info".into()),
                start_at_end: Some(true),
            },
        ))
        .await
        .unwrap();
    assert_eq!(reconcile_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    service
        .file_tails(crate::app::FileTailRequest::list())
        .await
        .unwrap();
    service
        .file_tails(crate::app::FileTailRequest::status())
        .await
        .unwrap();
    assert_eq!(reconcile_count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn file_tails_duplicate_add_is_rejected_without_resetting_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        Arc::clone(&registry),
        Arc::new(|| Ok(())),
        Arc::new(Vec::new),
    );
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let request = crate::app::FileTailRequest::add(crate::app::FileTailAddRequest {
        id: "swag-access".into(),
        path: log_path.to_string_lossy().into_owned(),
        tag: "swag-access".into(),
        host: Some("edgehost".into()),
        facility: Some("local4".into()),
        severity: Some("info".into()),
        start_at_end: Some(true),
    });
    service.file_tails(request.clone()).await.unwrap();
    registry
        .update_checkpoint("swag-access", 11, 22, 33, "2026-06-11T20:01:00Z")
        .unwrap();

    let err = service.file_tails(request).await.unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "unexpected error: {err}"
    );
    let stored = registry.get("swag-access").unwrap().unwrap();
    assert_eq!(stored.checkpoint_dev, Some(11));
    assert_eq!(stored.checkpoint_ino, Some(22));
    assert_eq!(stored.checkpoint_offset, Some(33));
}

#[tokio::test]
async fn file_tails_reconcile_failure_reports_rolled_back_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        Arc::clone(&registry),
        Arc::new(|| Err(anyhow::anyhow!("boom"))),
        Arc::new(Vec::new),
    );
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let err = service
        .file_tails(crate::app::FileTailRequest::add(
            crate::app::FileTailAddRequest {
                id: "swag-access".into(),
                path: log_path.to_string_lossy().into_owned(),
                tag: "swag-access".into(),
                host: Some("edgehost".into()),
                facility: Some("local4".into()),
                severity: Some("info".into()),
                start_at_end: Some(true),
            },
        ))
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("registry mutation rolled back"),
        "unexpected error: {err}"
    );
    assert!(registry.get("swag-access").unwrap().is_none());
}

#[tokio::test]
async fn file_tails_mutations_reject_registry_only_query_mode() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_registry(registry);
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let err = service
        .file_tails(crate::app::FileTailRequest::add(
            crate::app::FileTailAddRequest {
                id: "swag-access".into(),
                path: log_path.to_string_lossy().into_owned(),
                tag: "swag-access".into(),
                host: Some("edgehost".into()),
                facility: Some("local4".into()),
                severity: Some("info".into()),
                start_at_end: Some(true),
            },
        ))
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("query-only mode"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn file_tails_missing_source_maps_to_not_found() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        registry,
        Arc::new(|| Ok(())),
        Arc::new(Vec::new),
    );

    let err = service
        .file_tails(crate::app::FileTailRequest::id_op(
            crate::app::FileTailOp::Disable,
            "missing-source".into(),
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::NotFound(_)),
        "missing source should be NotFound, got {err:?}"
    );
}

fn add_file_tail_request(
    id: &str,
    path: impl Into<String>,
    facility: Option<&str>,
    severity: Option<&str>,
) -> crate::app::FileTailRequest {
    crate::app::FileTailRequest::add(crate::app::FileTailAddRequest {
        id: id.into(),
        path: path.into(),
        tag: id.into(),
        host: Some("edgehost".into()),
        facility: facility.map(str::to_string),
        severity: severity.map(str::to_string),
        start_at_end: Some(true),
    })
}

#[tokio::test]
async fn file_tails_rejects_invalid_facility_severity_and_disallowed_paths() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(temp.path().join("file-tail-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    let registry = Arc::new(crate::filetail::FileTailRegistry::new(
        temp.path().join("file-tails.json"),
    ));
    let service = CortexService::new(pool, storage).with_file_tail_control(
        registry,
        Arc::new(|| Ok(())),
        Arc::new(Vec::new),
    );
    let log_path = temp.path().join("access.log");
    std::fs::write(&log_path, "seed\n").unwrap();

    let invalid_severity = service
        .file_tails(add_file_tail_request(
            "bad-sev",
            log_path.to_string_lossy().into_owned(),
            Some("local4"),
            Some("bogus"),
        ))
        .await
        .unwrap_err();
    assert!(invalid_severity.to_string().contains("severity"));

    let invalid_facility = service
        .file_tails(add_file_tail_request(
            "bad-facility",
            log_path.to_string_lossy().into_owned(),
            Some("notafacility"),
            Some("info"),
        ))
        .await
        .unwrap_err();
    assert!(invalid_facility.to_string().contains("facility"));

    let disallowed = service
        .file_tails(add_file_tail_request(
            "hosts",
            "/etc/hosts",
            Some("local4"),
            Some("info"),
        ))
        .await
        .unwrap_err();
    assert!(disallowed.to_string().contains("allowed roots"));
}

#[tokio::test]
async fn service_exposes_llm_runner_with_configured_defaults() {
    let (service, _pool, _dir) = test_service();
    // Exercise the accessor exists and is wired to a real DbPool by running
    // a trivial audited call end to end. Full LlmRunner behavior coverage
    // lives in app::llm_runner_tests; this test only proves CortexService
    // wires a working runner through to a real pool.
    let spec = crate::app::llm_runner::LlmInvocationSpec {
        caller_surface: crate::app::llm_runner::LlmCallerSurface::Test,
        action: "ai_assess".to_string(),
        incident_id: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        evidence_counts: crate::app::llm_runner::LlmEvidenceCounts::default(),
        prompt: "ping".to_string(),
        provider: "test".to_string(),
        model: "test".to_string(),
        program: "test".to_string(),
        extra_metadata: serde_json::json!({}),
    };
    let outcome = service
        .llm()
        .run(spec, |_p| async { Ok("pong".to_string()) })
        .await
        .unwrap();
    assert_eq!(outcome.output, "pong");
}

#[tokio::test]
async fn list_ai_skill_incidents_empty_db_returns_no_data() {
    let (service, _pool, _dir) = test_service();
    let response = service
        .list_ai_skill_incidents(AiSkillIncidentRequest::default())
        .await
        .unwrap();
    assert_eq!(response.incidents.len(), 0);
    assert_eq!(response.total_incidents, 0);
}

#[tokio::test]
async fn investigate_ai_skill_incidents_empty_db_returns_no_data_flag() {
    let (service, _pool, _dir) = test_service();
    let response = service
        .investigate_ai_skill_incidents(AiSkillInvestigateRequest::default())
        .await
        .unwrap();
    assert_eq!(response.evidence.len(), 0);
    assert!(response.no_data);
    assert!(!response.suggested_filters.is_empty());
}

#[allow(clippy::too_many_arguments)]
fn insert_skill_event_for_service_test(
    pool: &DbPool,
    log_id: i64,
    ai_tool: &str,
    ai_project: &str,
    ai_session_id: &str,
    hostname: &str,
    timestamp: &str,
    skill_name: &str,
    skill_plugin: Option<&str>,
) {
    let conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO ai_skill_events
            (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
             skill_name, skill_plugin, event_kind, evidence_kind, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'skill_invoked', 'transcript', ?6)",
        rusqlite::params![
            log_id,
            ai_tool,
            ai_project,
            ai_session_id,
            hostname,
            timestamp,
            skill_name,
            skill_plugin,
        ],
    )
    .unwrap();
}

fn skill_ai_entry(ts: &str, session_id: &str, msg: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: ts.to_string(),
        hostname: "devhost".into(),
        facility: Some("local0".into()),
        severity: "info".into(),
        app_name: Some("ai-transcript".into()),
        process_id: None,
        message: msg.to_string(),
        raw: msg.to_string(),
        source_ip: "127.0.0.1:514".into(),
        docker_checkpoint: None,
        ai_tool: Some("codex".into()),
        ai_project: Some("/tmp/skill-svc-test".into()),
        ai_session_id: Some(session_id.to_string()),
        ai_transcript_path: Some(format!("/tmp/skill-svc-test/{session_id}.jsonl")),
        metadata_json: None,
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

#[tokio::test]
async fn investigate_ai_skill_incidents_by_skill_picks_top_priority_and_lists_others() {
    let (service, pool, _dir) = test_service();

    // Session "sess-low": skill event only, no negative signal.
    let low_skill = skill_ai_entry(
        "2026-01-01T00:00:00Z",
        "sess-low",
        "loaded skill lavra:lavra-plan",
    );
    // Session "sess-high": skill event + correction + tool failure.
    let high_skill = skill_ai_entry(
        "2026-01-01T00:00:00Z",
        "sess-high",
        "loaded skill lavra:lavra-plan",
    );
    let high_correction = skill_ai_entry(
        "2026-01-01T00:01:00Z",
        "sess-high",
        "you said you would run the tests but you didn't",
    );
    let high_failure = skill_ai_entry(
        "2026-01-01T00:02:00Z",
        "sess-high",
        "command exited with exit code 1",
    );
    insert_logs_batch(
        &pool,
        &[low_skill, high_skill, high_correction, high_failure],
    )
    .unwrap();

    let log_ids: Vec<i64> = {
        let conn = pool.get().unwrap();
        let mut stmt = conn.prepare("SELECT id FROM logs ORDER BY id ASC").unwrap();
        stmt.query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    insert_skill_event_for_service_test(
        &pool,
        log_ids[0],
        "codex",
        "/tmp/skill-svc-test",
        "sess-low",
        "devhost",
        "2026-01-01T00:00:00Z",
        "lavra:lavra-plan",
        Some("lavra"),
    );
    insert_skill_event_for_service_test(
        &pool,
        log_ids[1],
        "codex",
        "/tmp/skill-svc-test",
        "sess-high",
        "devhost",
        "2026-01-01T00:00:00Z",
        "lavra:lavra-plan",
        Some("lavra"),
    );

    let response = service
        .investigate_ai_skill_incidents(AiSkillInvestigateRequest {
            skill: Some("lavra:lavra-plan".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        response.evidence.len(),
        1,
        "skill-first default returns the single top incident"
    );
    assert_eq!(
        response.evidence[0].incident.session_id, "sess-high",
        "top-priority incident must be the higher-signal session"
    );
    assert_eq!(
        response.other_matching_incidents.len(),
        1,
        "the lower-priority incident must be summarized in other_matching_incidents"
    );
    assert_eq!(response.other_matching_incidents[0].priority_label, "low");
}

#[tokio::test]
async fn investigate_ai_skill_incidents_low_signal_returns_summary_not_error() {
    let (service, pool, _dir) = test_service();
    let skill_log = skill_ai_entry(
        "2026-01-01T00:00:00Z",
        "sess-only",
        "loaded skill lavra:lavra-plan",
    );
    insert_logs_batch(&pool, &[skill_log]).unwrap();
    let log_id: i64 = {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT id FROM logs LIMIT 1", [], |row| row.get(0))
            .unwrap()
    };
    insert_skill_event_for_service_test(
        &pool,
        log_id,
        "codex",
        "/tmp/skill-svc-test",
        "sess-only",
        "devhost",
        "2026-01-01T00:00:00Z",
        "lavra:lavra-plan",
        Some("lavra"),
    );

    let response = service
        .investigate_ai_skill_incidents(AiSkillInvestigateRequest {
            skill: Some("lavra:lavra-plan".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!response.no_data);
    assert_eq!(response.evidence.len(), 1);
    assert!(response.no_incident_low_severity_summary);
}
