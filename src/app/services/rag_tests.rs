use super::*;
use crate::config::StorageConfig;
use crate::db::{LogBatchEntry, init_pool, insert_logs_batch};
use std::sync::Arc;

fn test_service() -> (CortexService, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("rag-service-test.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    insert_logs_batch(
        &pool,
        &[
            app_log("memory pressure detected"),
            app_log("connection pressure detected"),
        ],
    )
    .unwrap();
    (CortexService::new(pool, storage), dir)
}

fn app_log(message: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: "2026-01-01T00:30:00Z".into(),
        hostname: "db-01".into(),
        facility: None,
        severity: "err".into(),
        app_name: Some("postgres".into()),
        process_id: None,
        message: message.into(),
        raw: message.into(),
        source_ip: "10.0.0.1:514".into(),
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

#[tokio::test]
async fn incident_context_forwards_query_to_db_filtering() {
    let (service, _dir) = test_service();
    let request = |query: &str| IncidentContextRequest {
        since: Some("2026-01-01T00:00:00Z".into()),
        until: Some("2026-01-01T01:00:00Z".into()),
        query: Some(query.into()),
        ..Default::default()
    };

    let memory = service.incident_context(request("memory")).await.unwrap();
    let connection = service
        .incident_context(request("connection"))
        .await
        .unwrap();

    assert_eq!(memory.error_logs.len(), 1);
    assert_eq!(memory.error_logs[0].message, "memory pressure detected");
    assert_eq!(connection.error_logs.len(), 1);
    assert_eq!(
        connection.error_logs[0].message,
        "connection pressure detected"
    );
}

#[tokio::test]
async fn recurring_error_comparison_replays_safely_and_never_serializes_raw_samples() {
    let (service, _dir) = test_service();
    let conn = service.pool.get().unwrap();
    crate::db::error_signatures::upsert_signature(
        &conn,
        crate::db::error_signatures::UpsertSignatureParams {
            hash: "canonical-hash",
            normalizer_version: crate::app::error_detection::NORMALIZER_VERSION,
            template: "failed with TOKEN=supersecret at /Users/alice/private",
            sample_message: "Authorization Bearer TOKEN=supersecret /Users/alice/private",
            sample_hostname: "host-a",
            sample_app_name: Some("app-a"),
            severity: "err",
            first_seen_at: "2026-01-01T00:00:00.000Z",
            last_seen_at: "2026-01-01T01:30:00.000Z",
            delta: 13,
        },
    )
    .unwrap();
    crate::db::error_signatures::insert_window(
        &conn,
        "canonical-hash",
        crate::app::error_detection::NORMALIZER_VERSION,
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T01:00:00.000Z",
        2,
    )
    .unwrap();
    crate::db::error_signatures::insert_window(
        &conn,
        "canonical-hash",
        crate::app::error_detection::NORMALIZER_VERSION,
        "2026-01-01T01:00:00.000Z",
        "2026-01-01T02:00:00.000Z",
        11,
    )
    .unwrap();
    drop(conn);
    crate::db::graph::refresh_graph_projection(&service.pool).unwrap();

    let request = RecurringErrorComparisonRequest {
        since: Some("2026-01-01T01:00:00Z".into()),
        until: Some("2026-01-01T02:00:00Z".into()),
        ..Default::default()
    };
    let first = service
        .compare_recurring_errors(request.clone())
        .await
        .unwrap();
    let second = service.compare_recurring_errors(request).await.unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
    let value = serde_json::to_string(&first).unwrap();
    assert!(!value.contains("supersecret"), "raw secret leaked: {value}");
    assert!(
        !value.contains("/Users/alice/private"),
        "raw path leaked: {value}"
    );
    let entry = first.comparisons.first().unwrap();
    assert_eq!(entry.focal_count, 11);
    assert_eq!(entry.baseline_count, 2);
    assert_eq!(entry.next_query.action, "graph");
    assert_eq!(entry.next_query.key, "canonical-hash:1");
    assert!(!entry.evidence.retention_or_projection_gap);
    assert!(!entry.evidence.graph_evidence_ids.is_empty());
    assert!(entry.evidence.bundle_id.starts_with("sha256:"));

    let cache = service.recurring_error_bundle_cache.lock();
    assert_eq!(cache.len(), 1);
    let cached = serde_json::to_string(&*cache).unwrap();
    assert!(
        !cached.contains("supersecret"),
        "raw secret reached cache: {cached}"
    );
    assert!(
        !cached.contains("/Users/alice/private"),
        "raw path reached cache: {cached}"
    );
}
