use super::*;
use crate::app::CortexService;
use crate::config::{McpConfig, StorageConfig};
use crate::db;
use crate::inventory::schema::{
    ArtifactRef, CollectionError, CollectionState, CollectorState, ComposeProject,
    HomelabInventory, InventoryNode, InventoryService, MountRef, PortMapping, Provenance,
    RedactionStatus, ReverseProxyRoute, TrustLevel,
};
use crate::inventory::storage::InventoryPaths;
use crate::mcp::AppState;
use serde_json::json;
use std::sync::Arc;

fn test_state_with_token(token: Option<String>) -> (AppState, Arc<db::DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let file_tail_registry = Arc::new(crate::filetail::FileTailRegistry::new(
        dir.path().join("file-tails.json"),
    ));
    (
        AppState {
            service: CortexService::new(Arc::clone(&pool), storage.clone())
                .with_file_tail_registry(file_tail_registry),
            config: McpConfig {
                host: "127.0.0.1".into(),
                port: 3100,
                server_name: "cortex".into(),
                no_auth: false,
                trusted_gateway_no_auth: false,
                api_token: crate::config::Secret(token),
                allowed_hosts: Vec::new(),
                allowed_origins: Vec::new(),
                auth: Default::default(),
                forwarding_agents: Default::default(),
                static_token_is_admin: false,
            },
            notifications_config: crate::config::NotificationsConfig::default(),
            otlp_counters: Arc::new(crate::otlp::OtlpCounters::default()),
            auth_policy: crate::mcp::AuthPolicy::LoopbackDev,
            observability: Arc::new(crate::observability::RuntimeObservability::default()),
        },
        pool,
        dir,
    )
}

struct TestHarness {
    state: AppState,
    pool: Arc<db::DbPool>,
    _dir: tempfile::TempDir,
}

struct EnvVarGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set_path(name: &'static str, value: &std::path::Path) -> Self {
        let previous = crate::env::var_os(name);
        crate::env::set_test_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => crate::env::set_test_var(self.name, value),
            None => crate::env::remove_test_var(self.name),
        }
    }
}

impl TestHarness {
    fn new() -> Self {
        let (state, pool, dir) = test_state_with_token(None);
        TestHarness {
            state,
            pool,
            _dir: dir,
        }
    }
}

fn test_provenance(source: &str, kind: &str) -> Provenance {
    Provenance::new(source, kind, "2026-01-01T00:00:00Z".to_string())
}

fn graph_inventory_fixture() -> HomelabInventory {
    let mut inventory = HomelabInventory::empty(
        "mcp-map-test".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    inventory.nodes.push(InventoryNode {
        id: "node:edgehost".to_string(),
        hostname: "edgehost".to_string(),
        trust_level: TrustLevel::Observed,
        provenance: test_provenance("ssh:edgehost", "source_inventory"),
        roles: vec!["edge".to_string()],
        ips: vec!["192.0.2.8".to_string()],
        os: Some("Ubuntu".to_string()),
        cpu: None,
        memory: None,
        listeners: Vec::new(),
        storage: Vec::new(),
        extras: Default::default(),
    });
    inventory.services.push(InventoryService {
        id: "container:edgehost:swag".to_string(),
        name: "swag".to_string(),
        kind: "container".to_string(),
        trust_level: TrustLevel::Observed,
        provenance: test_provenance("docker:edgehost", "app_inventory"),
        host: Some("edgehost".to_string()),
        image: Some("lscr.io/linuxserver/swag:latest".to_string()),
        status: Some("running".to_string()),
        domains: vec!["adguard.example.invalid".to_string()],
        ports: vec![PortMapping {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: Some(443),
            container_port: Some(443),
            protocol: "tcp".to_string(),
        }],
        mounts: vec![MountRef {
            source: Some("/var/run/docker.sock".to_string()),
            target: "/var/run/docker.sock".to_string(),
            read_only: false,
        }],
        env_keys: vec!["URL".to_string()],
        labels: Default::default(),
        details: Default::default(),
    });
    inventory.compose_projects.push(ComposeProject {
        name: "edge".to_string(),
        provenance: test_provenance("compose:edgehost:/opt/edge/compose.yaml", "app_inventory"),
        services: vec!["swag".to_string()],
        compose_files: vec!["/opt/edge/compose.yaml".to_string()],
        domains: vec!["adguard.example.invalid".to_string()],
        ports: Vec::new(),
    });
    inventory.reverse_proxies.push(ReverseProxyRoute {
        id: "proxy:adguard.example.invalid".to_string(),
        server_names: vec!["adguard.example.invalid".to_string()],
        upstreams: vec!["swag:443".to_string()],
        provenance: test_provenance("swag:edgehost:/config/nginx/proxy.conf", "app_inventory"),
    });
    inventory.artifact_refs.push(ArtifactRef {
        id: "artifact:compose:edgehost:edge".to_string(),
        kind: "compose".to_string(),
        collector: "raw_configs".to_string(),
        source_host: Some("edgehost".to_string()),
        source_path: Some("/opt/edge/compose.yaml".to_string()),
        cache_path: "/home/jmagar/.cortex/inventory/artifacts/edge.yaml".to_string(),
        redaction: RedactionStatus::Redacted,
        byte_len: 42,
        truncated: false,
    });
    inventory.collection_errors.push(CollectionError {
        collector: "raw_configs".to_string(),
        phase: "collect".to_string(),
        severity: "warning".to_string(),
        message: "raw path /secret/config.conf failed with token abc".to_string(),
        elapsed_ms: 25,
        truncated: false,
    });
    inventory.recompute_summary();
    inventory
}

fn graph_inventory_without_route_target_fixture() -> HomelabInventory {
    let mut inventory = HomelabInventory::empty(
        "mcp-map-no-target-test".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    inventory.nodes.push(InventoryNode {
        id: "node:edgehost".to_string(),
        hostname: "edgehost".to_string(),
        trust_level: TrustLevel::Observed,
        provenance: test_provenance("ssh:edgehost", "source_inventory"),
        roles: vec!["edge".to_string()],
        ips: vec!["192.0.2.8".to_string()],
        os: Some("Ubuntu".to_string()),
        cpu: None,
        memory: None,
        listeners: Vec::new(),
        storage: Vec::new(),
        extras: Default::default(),
    });
    inventory.reverse_proxies.push(ReverseProxyRoute {
        id: "proxy:orphan.example.invalid".to_string(),
        server_names: vec!["orphan.example.invalid".to_string()],
        upstreams: vec!["missing-service:443".to_string()],
        provenance: test_provenance("swag:edgehost:/config/nginx/orphan.conf", "app_inventory"),
    });
    inventory.recompute_summary();
    inventory
}

#[test]
fn artifact_evidence_actions_have_read_and_admin_scopes() {
    let read = crate::mcp::actions::ACTION_SPECS
        .iter()
        .find(|spec| spec.name == "artifact_evidence")
        .expect("artifact_evidence registered");
    assert_eq!(read.scope, crate::mcp::actions::Scope::Read);
    assert_eq!(read.cost.as_str(), "cheap");

    let write = crate::mcp::actions::ACTION_SPECS
        .iter()
        .find(|spec| spec.name == "artifact_evidence_record")
        .expect("artifact_evidence_record registered");
    assert_eq!(write.scope, crate::mcp::actions::Scope::Admin);
    assert_eq!(write.cost.as_str(), "write");
}

#[tokio::test]
async fn file_tails_action_requires_admin_scope() {
    let spec = crate::mcp::actions::ACTION_SPECS
        .iter()
        .find(|spec| spec.name == "file_tails")
        .expect("file_tails registered");
    assert_eq!(spec.scope, crate::mcp::actions::Scope::Admin);
    assert_eq!(spec.cost.as_str(), "write");
}

fn project_graph_fixture(pool: &db::DbPool) {
    db::graph::refresh_graph_projection(pool).unwrap();
    let inventory = graph_inventory_fixture();

    db::graph_inventory::project_inventory(pool, &inventory).unwrap();
}

fn write_inventory_cache_fixture(root: &std::path::Path, inventory: &HomelabInventory) {
    let paths = InventoryPaths::new(root.to_path_buf());
    std::fs::create_dir_all(&paths.normalized_dir).unwrap();
    std::fs::write(
        &paths.normalized_json,
        serde_json::to_vec_pretty(inventory).unwrap(),
    )
    .unwrap();
}

fn write_collection_state_fixture(root: &std::path::Path, collectors: Vec<CollectorState>) {
    let paths = InventoryPaths::new(root.to_path_buf());
    std::fs::create_dir_all(&paths.root).unwrap();
    let state = CollectionState {
        schema: "cortex.inventory.collection_state.v1".to_string(),
        run_id: "test-run".to_string(),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:01Z".to_string(),
        status: "partial".to_string(),
        collectors,
        artifact_refs: Vec::new(),
        errors: Vec::new(),
    };
    std::fs::write(
        &paths.collection_state_json,
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn collector_state(name: &str, status: &str, warnings: Vec<&str>) -> CollectorState {
    CollectorState {
        name: name.to_string(),
        status: status.to_string(),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:01Z".to_string(),
        elapsed_ms: 10,
        warnings: warnings.into_iter().map(str::to_string).collect(),
        artifacts: Vec::new(),
    }
}

#[tokio::test]
async fn tool_get_stats_returns_storage_guard_fields() {
    let h = TestHarness::new();
    let state = h.state;
    let value = status::tool_get_stats(&state, json!({})).await.unwrap();
    assert!(value.get("logical_db_size_mb").is_some());
    assert!(value.get("physical_db_size_mb").is_some());
    assert!(value.get("write_blocked").is_some());
    assert!(value.get("phantom_fts_rows").is_some());
    assert!(value.get("runtime_observability").is_some());
    assert!(value.get("otlp").is_some());
}

#[tokio::test]
async fn tool_get_status_returns_runtime_observability() {
    let h = TestHarness::new();
    let value = status::tool_get_status(&h.state, json!({})).await.unwrap();
    assert_eq!(value["status"], "ok");
    assert_eq!(value["db_ok"], true);
    assert_eq!(value["file_tails"]["blocked_count"], 0);
    assert!(value["file_tails"]["statuses"].as_array().is_some());
    assert!(value["runtime_observability"]["ingest_queue_depth"].is_number());
    assert!(value["otlp"]["logs_received"].is_number());
}

#[tokio::test]
async fn host_state_action_returns_bounded_heartbeat_state() {
    let h = TestHarness::new();
    let conn = h.pool.get().unwrap();
    for sequence in 1..=2 {
        conn.execute(
            "INSERT INTO host_heartbeats (
                 host_id, hostname, source_ip, sampled_at, received_at, boot_id,
                 uptime_secs, sequence, collection_ms, partial, agent_version,
                 os, architecture, metadata_json
             ) VALUES (
                 'host-a', 'nashost', '127.0.0.1:41000', ?1, ?1, 'boot-a',
                 60, ?2, 5, ?3, '0.1.0-test', 'linux', 'x86_64',
                 '{\"agent\":{\"interval_secs\":30}}'
             )",
            (
                format!("2026-05-25T00:0{sequence}:00Z"),
                sequence,
                (sequence == 2) as i64,
            ),
        )
        .unwrap();
    }
    drop(conn);

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({"action": "host_state", "host": "nashost", "limit": 1}),
        None,
    )
    .await
    .unwrap();
    assert_eq!(value["host_id"], "host-a");
    assert_eq!(value["samples"].as_array().unwrap().len(), 1);
    assert_eq!(value["flags"]["collector_partial"], true);
}

#[tokio::test]
async fn artifact_evidence_actions_record_replay_query_and_reject_raw_bodies() {
    let h = TestHarness::new();
    let digest = format!("sha256:{}", "a".repeat(64));
    let record = json!({
        "action": "artifact_evidence_record",
        "schemaVersion": "dinglebear.cortex-artifact-evidence/v1",
        "eventId": "evt-mcp-1",
        "eventKind": "runtime_call",
        "sourceSystem": "labby",
        "sourceIssuer": "gateway:personal/jake",
        "observedAt": "2026-08-19T12:00:00-04:00",
        "artifactId": "artifact-mcp-1",
        "revisionId": "revision-mcp-1",
        "contentDigest": digest,
        "correlationId": "corr-mcp-1",
        "targetId": "target-node-a",
        "operationRef": "mcp:tools/call",
        "outcome": "success",
        "metadata": {"message": "result sk-super-secret", "resultBytes": 91}
    });

    let first = execute_tool(&h.state, "cortex", record.clone(), None)
        .await
        .unwrap();
    assert_eq!(first["inserted"], true);
    assert_eq!(first["event"]["metadata"]["message"], "result [REDACTED]");
    let cortex_log_id = first["cortexLogId"].as_i64().unwrap();

    let replay = execute_tool(&h.state, "cortex", record, None)
        .await
        .unwrap();
    assert_eq!(replay["inserted"], false);
    assert_eq!(replay["cortexLogId"], cortex_log_id);

    let queried = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "artifact_evidence",
            "artifactId": "artifact-mcp-1",
            "correlationId": "corr-mcp-1",
            "since": "2026-08-19T15:59:00Z",
            "until": "2026-08-19T16:01:00Z"
        }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(queried["events"].as_array().unwrap().len(), 1);
    assert_eq!(queried["events"][0]["eventId"], "evt-mcp-1");

    let malformed = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "artifact_evidence_record",
            "schemaVersion": "dinglebear.cortex-artifact-evidence/v1",
            "eventId": "evt-mcp-bad",
            "eventKind": "runtime_call",
            "sourceSystem": "labby",
            "sourceIssuer": "gateway:personal/jake",
            "observedAt": "2026-08-19T12:00:00-04:00",
            "artifactId": "artifact-mcp-2",
            "metadata": {"requestBody": "raw payload"}
        }),
        None,
    )
    .await
    .unwrap_err();
    assert!(malformed.to_string().contains("forbidden"));
}

#[tokio::test]
async fn skill_events_action_returns_inserted_rows() {
    let h = TestHarness::new();
    let conn = h.pool.get().unwrap();
    conn.execute(
        "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip)
         VALUES ('2026-06-01T00:00:00.000Z', 'devhost', 'info', 'm', 'm', 'transcript://claude_project')",
        [],
    )
    .unwrap();
    let log_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO ai_skill_events (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp, skill_name, event_kind, evidence_kind)
         VALUES (?1, 'claude', 'cortex', 'sess-1', 'devhost', '2026-06-01T00:00:00.000Z', 'cortex-troubleshoot', 'claude_attribution', 'structured_json_field')",
        rusqlite::params![log_id],
    )
    .unwrap();
    drop(conn);

    let args = json!({"action": "skill_events", "project": "cortex"});
    let response = execute_tool(&h.state, "cortex", args, None).await.unwrap();
    assert_eq!(response["total"], 1);
    assert_eq!(response["events"][0]["skill_name"], "cortex-troubleshoot");
}

#[test]
fn event_request_models_accept_mcp_and_rest_time_names_and_reject_unknowns() {
    let skill: crate::app::ListSkillEventsRequest = action_payload(
        json!({"action": "skill_events", "since": "t0", "until": "t1"}),
        "skill_events",
    )
    .unwrap();
    assert_eq!(skill.from.as_deref(), Some("t0"));
    assert_eq!(skill.to.as_deref(), Some("t1"));

    let mcp: crate::app::ListMcpEventsRequest = action_payload(
        json!({"action": "mcp_events", "from": "t0", "to": "t1"}),
        "mcp_events",
    )
    .unwrap();
    assert_eq!(mcp.from.as_deref(), Some("t0"));
    assert_eq!(mcp.to.as_deref(), Some("t1"));

    let hook: crate::app::ListHookEventsRequest = action_payload(
        json!({"action": "hook_events", "since": "t0", "until": "t1"}),
        "hook_events",
    )
    .unwrap();
    assert_eq!(hook.from.as_deref(), Some("t0"));
    assert_eq!(hook.to.as_deref(), Some("t1"));

    let skill_error = action_payload::<crate::app::ListSkillEventsRequest>(
        json!({"action": "skill_events", "bogus": true}),
        "skill_events",
    )
    .unwrap_err();
    assert!(skill_error.to_string().contains("unknown field `bogus`"));

    let hook_error = action_payload::<crate::app::ListHookEventsRequest>(
        json!({"action": "hook_events", "bogus": true}),
        "hook_events",
    )
    .unwrap_err();
    assert!(hook_error.to_string().contains("unknown field `bogus`"));
}

#[tokio::test]
async fn event_actions_apply_mcp_since_and_until_bounds() {
    let h = TestHarness::new();
    let timestamps = [
        "2026-06-01T00:00:00.000Z",
        "2026-06-02T00:00:00.000Z",
        "2026-06-03T00:00:00.000Z",
    ];
    let conn = h.pool.get().unwrap();

    for (index, timestamp) in timestamps.iter().enumerate() {
        conn.execute(
            "INSERT INTO logs (timestamp, hostname, severity, message, raw, source_ip)
             VALUES (?1, 'devhost', 'info', ?2, ?2, 'transcript://codex_cortex')",
            rusqlite::params![timestamp, format!("event-{index}")],
        )
        .unwrap();
        let log_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO ai_skill_events
                (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
                 skill_name, event_kind, evidence_kind)
             VALUES (?1, 'codex', 'cortex', 'session-filter', 'devhost', ?2,
                     'test-skill', 'loaded', 'structured')",
            rusqlite::params![log_id, timestamp],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ai_mcp_events
                (ai_tool, ai_project, ai_session_id, hostname, timestamp, call_id,
                 tool_name, mcp_server, mcp_tool, event_kind)
             VALUES ('codex', 'cortex', 'session-filter', 'devhost', ?1, ?2,
                     'mcp__labby__search', 'labby', 'search', 'call')",
            rusqlite::params![timestamp, format!("call-{index}")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ai_hook_events
                (ai_tool, ai_project, ai_session_id, hostname, timestamp,
                 hook_event, hook_name, status, evidence_kind)
             VALUES ('codex', 'cortex', 'session-filter', 'devhost', ?1,
                     'PostToolUse', 'format', 'ok', 'runtime_transcript')",
            rusqlite::params![timestamp],
        )
        .unwrap();
    }
    drop(conn);

    for action in ["skill_events", "mcp_events", "hook_events"] {
        let response = execute_tool(
            &h.state,
            "cortex",
            json!({
                "action": action,
                "since": "2026-06-02T00:00:00Z",
                "until": "2026-06-02T23:59:59Z"
            }),
            None,
        )
        .await
        .unwrap();
        assert_eq!(response["total"], 1, "time bounds not applied for {action}");
        assert_eq!(response["events"][0]["timestamp"], timestamps[1]);
    }
}

#[tokio::test]
async fn fleet_state_action_returns_fleet_snapshot() {
    let h = TestHarness::new();
    let value = execute_tool(&h.state, "cortex", json!({"action": "fleet_state"}), None)
        .await
        .unwrap();
    assert!(
        value.get("hosts").is_some(),
        "fleet_state response missing hosts: {value}"
    );
    assert!(
        value.get("summary").is_some(),
        "fleet_state response missing summary: {value}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_returns_infra_snapshot_from_known_hosts() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    db::insert_logs_batch(
        &h.pool,
        &[
            db::LogBatchEntry {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                hostname: "nashost".to_string(),
                facility: Some("daemon".to_string()),
                severity: "info".to_string(),
                app_name: Some("plex".to_string()),
                process_id: None,
                message: "plex started".to_string(),
                raw: "<14>plex started".to_string(),
                source_ip: "192.0.2.2:514".to_string(),
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
            },
            db::LogBatchEntry {
                timestamp: "2026-01-01T00:01:00Z".to_string(),
                hostname: "edgehost".to_string(),
                facility: Some("daemon".to_string()),
                severity: "warning".to_string(),
                app_name: Some("swag".to_string()),
                process_id: None,
                message: "proxy warning".to_string(),
                raw: "<12>proxy warning".to_string(),
                source_ip: "192.0.2.8:514".to_string(),
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
            },
        ],
    )
    .unwrap();

    let value = execute_tool(&h.state, "cortex", json!({"action": "map"}), None)
        .await
        .unwrap();

    assert_eq!(value["schema"], "cortex.homelab_map.v2");
    assert_eq!(value["cache_status"], "missing");
    assert_eq!(value["summary"]["hosts"], 2);
    assert!(value["artifact_refs"].as_array().unwrap().is_empty());
    assert!(
        value["collection_errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| { error["collector"] == "cache" && error["severity"] == "warning" })
    );

    let nodes = value["nodes"].as_array().unwrap();
    let nashost = nodes
        .iter()
        .find(|node| node["hostname"] == "nashost")
        .expect("nashost node missing");
    assert_eq!(nashost["log_count"], 1);
    assert!(nashost["source_ips"].as_array().unwrap().is_empty());
    assert!(nashost["apps"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_host_services_mode_returns_graph_answer() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        project_graph_fixture(&h.pool);
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "host_services",
            "host": "edgehost",
            "answer_limit": 25,
            "evidence_sample_limit": 2
        }),
        None,
    )
    .await
    .unwrap();

    assert_eq!(value["schema"], "cortex.homelab_map.v2");
    let answer = &value["graph_answer"];
    assert_eq!(answer["mode"], "host_services");
    assert_eq!(answer["answer_status"], "ok");
    assert_eq!(answer["target"]["entity_type"], "host");
    assert_eq!(answer["target"]["key"], "edgehost");
    assert_eq!(value["summary"]["returned_hosts"], 0);
    assert_eq!(
        value["cortex_overlay"]["overlay_status"],
        "graph_answer_only"
    );
    assert!(
        answer["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["entity_type"] == "service_instance"
                && row["key"] == "edgehost/swag"
                && row["relationship_type"] == "runs_on"),
        "host_services should include service instances running on the host: {answer}"
    );
    assert!(
        answer["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|evidence| {
                evidence["source_kind"] == "app_inventory"
                    || evidence["source_kind"] == "source_inventory"
            }),
        "host_services should include safe evidence samples: {answer}"
    );
    assert!(
        answer["proof_queries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|query| query["action"] == "graph" && query["mode"] == "around"),
        "host_services should include graph proof query hints: {answer}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_domain_routes_mode_returns_proxy_graph_answer() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        project_graph_fixture(&h.pool);
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "domain_routes",
            "domain": "adguard.example.invalid"
        }),
        None,
    )
    .await
    .unwrap();

    let answer = &value["graph_answer"];
    assert_eq!(answer["mode"], "domain_routes");
    assert_eq!(answer["answer_status"], "ok");
    assert_eq!(answer["target"]["entity_type"], "domain");
    assert_eq!(answer["target"]["key"], "adguard.example.invalid");
    assert!(
        answer["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["entity_type"] == "reverse_proxy"
                && row["key"] == "proxy:adguard.example.invalid"
                && row["relationship_type"] == "exposes_domain"),
        "domain_routes should include the proxy config that exposes the domain: {answer}"
    );
    assert!(
        answer["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["entity_type"] == "service_instance"
                && row["key"] == "edgehost/swag"
                && row["relationship_type"] == "routes_to"),
        "domain_routes should include the route target service instance through the proxy: {answer}"
    );
    assert!(
        answer["proof_queries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|query| query["action"] == "graph" && query["mode"] == "evidence"),
        "domain_routes should include graph proof follow-up queries: {answer}"
    );
}

#[tokio::test]
async fn map_action_graph_mode_requires_target_fields_before_snapshot_work() {
    let h = TestHarness::new();
    let err = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "host_services"
        }),
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires `host`"), "{err}");
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_service_dependencies_mode_accepts_bare_service_with_host() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        project_graph_fixture(&h.pool);
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "service_dependencies",
            "host": "edgehost",
            "service": "swag"
        }),
        None,
    )
    .await
    .unwrap();

    let answer = &value["graph_answer"];
    assert_eq!(answer["mode"], "service_dependencies");
    assert_eq!(answer["answer_status"], "ok");
    assert_eq!(answer["target"]["entity_type"], "service_instance");
    assert_eq!(answer["target"]["key"], "edgehost/swag");
    assert!(
        answer["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["entity_type"] == "compose_project" && row["key"] == "edgehost:edge"),
        "service_dependencies should include compose project evidence: {answer}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_service_dependencies_mode_rejects_legacy_service_keys() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        project_graph_fixture(&h.pool);
    }

    // Legacy `host:service` / `host:project:service` identities are a
    // hard-break rejection, never a lookup.
    for service in ["edgehost:swag", "edgehost:edge:swag"] {
        let err = execute_tool(
            &h.state,
            "cortex",
            json!({
                "action": "map",
                "mode": "service_dependencies",
                "service": service
            }),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("rejected_legacy_shape"), "{service}: {err}");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_mode_returns_topology_findings_without_raw_leaks() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    let inventory = graph_inventory_fixture();
    write_inventory_cache_fixture(inventory_dir.path(), &inventory);
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
        db::graph_inventory::project_inventory(&h.pool, &inventory).unwrap();
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_limit": 10,
            "evidence_per_finding": 1
        }),
        None,
    )
    .await
    .unwrap();

    let answer = &value["graph_answer"];
    assert_eq!(answer["mode"], "findings");
    assert_eq!(answer["target"]["entity_type"], "topology");
    assert_eq!(value["summary"]["returned_hosts"], 0);
    assert!(
        answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |finding| finding["finding_type"] == "potential_public_route"
                    && finding["reason_code"] == "reverse_proxy_route_configured"
                    && finding["affected_entities"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|entity| entity["key"] == "adguard.example.invalid")
            ),
        "findings should include bounded public route proof: {answer}"
    );
    assert!(
        answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["finding_type"] == "risky_mounts"
                && finding["reason_code"] == "docker_socket_mount"
                && finding["affected_entities"].as_array().unwrap().iter().any(
                    |entity| entity["details"]["mount_source_kind"] == "docker_socket"
                        && entity["details"]["read_only"] == "false"
                )),
        "findings should include docker socket mount details: {answer}"
    );
    assert!(
        answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["finding_type"] == "collector_health"
                && finding["reason_code"] == "collector_partial"),
        "findings should include degraded collector context: {answer}"
    );
    let rendered = serde_json::to_string(answer).unwrap();
    assert!(!rendered.contains("/secret/config.conf"), "{rendered}");
    assert!(!rendered.contains("abc"), "{rendered}");
    assert!(
        !rendered.contains("/home/jmagar/.cortex/inventory"),
        "{rendered}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_payload_budget_trims_findings() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    let inventory = graph_inventory_fixture();
    write_inventory_cache_fixture(inventory_dir.path(), &inventory);
    write_collection_state_fixture(
        inventory_dir.path(),
        vec![
            collector_state("raw_configs", "partial", vec!["raw /secret/token abc"]),
            collector_state("docker", "partial", vec!["socket warning"]),
            collector_state("reverse_proxy", "partial", vec!["proxy warning"]),
            collector_state("compose", "partial", vec!["compose warning"]),
        ],
    );
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
        db::graph_inventory::project_inventory(&h.pool, &inventory).unwrap();
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_limit": 100,
            "evidence_per_finding": 5,
            "payload_budget": 4096
        }),
        None,
    )
    .await
    .unwrap();

    let answer = &value["graph_answer"];
    assert_eq!(answer["truncation"]["truncated"], true);
    assert_eq!(answer["truncation"]["reason"], "payload_budget");
    assert_eq!(answer["metadata"]["truncated_reason"], "payload_budget");
    assert!(
        answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["evidence_truncated"] == true),
        "budget trimming should mark at least one finding evidence-truncated: {answer}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_type_subset_and_invalid_value_are_enforced() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    let inventory = graph_inventory_fixture();
    write_inventory_cache_fixture(inventory_dir.path(), &inventory);
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
        db::graph_inventory::project_inventory(&h.pool, &inventory).unwrap();
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["collector_health"]
        }),
        None,
    )
    .await
    .unwrap();
    let findings = value["graph_answer"]["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "{value}");
    assert!(
        findings
            .iter()
            .all(|finding| finding["finding_type"] == "collector_health"),
        "subset should only return collector health findings: {value}"
    );

    let err = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["bad"]
        }),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("unsupported finding type"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_collector_health_cache_branches_are_safe() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();

    let missing_value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["collector_health"]
        }),
        None,
    )
    .await
    .unwrap();
    let missing_answer = &missing_value["graph_answer"];
    assert_eq!(missing_answer["answer_status"], "degraded");
    assert!(
        missing_answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |finding| finding["reason_code"] == "inventory_cache_missing"
                    || finding["reason_code"] == "collection_state_unavailable"
            ),
        "missing cache should surface collector health findings: {missing_answer}"
    );

    let inventory = graph_inventory_fixture();
    write_inventory_cache_fixture(inventory_dir.path(), &inventory);
    write_collection_state_fixture(
        inventory_dir.path(),
        vec![collector_state(
            "raw_configs",
            "ok",
            vec!["raw path /secret/config.conf token abc"],
        )],
    );
    let stale_value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["collector_health"]
        }),
        None,
    )
    .await
    .unwrap();
    let stale_answer = &stale_value["graph_answer"];
    assert!(
        stale_answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["reason_code"] == "inventory_cache_stale"
                || finding["reason_code"] == "collector_degraded"),
        "stale cache and collector warnings should surface: {stale_answer}"
    );
    let rendered = serde_json::to_string(stale_answer).unwrap();
    assert!(!rendered.contains("/secret/config.conf"), "{rendered}");
    assert!(!rendered.contains("abc"), "{rendered}");

    let paths = InventoryPaths::new(inventory_dir.path().to_path_buf());
    std::fs::write(&paths.normalized_json, b"{not json").unwrap();
    let corrupt_value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["collector_health"]
        }),
        None,
    )
    .await
    .unwrap();
    assert!(
        corrupt_value["graph_answer"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["reason_code"] == "inventory_cache_unreadable"),
        "corrupt cache should surface unreadable collector health: {corrupt_value}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_degrades_when_graph_projection_was_never_built() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    write_inventory_cache_fixture(inventory_dir.path(), &graph_inventory_fixture());

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["potential_public_route"]
        }),
        None,
    )
    .await
    .unwrap();
    let answer = &value["graph_answer"];
    assert_eq!(answer["answer_status"], "degraded");
    assert_eq!(answer["degraded_reason"], "graph_projection_not_ready");
    assert!(
        answer["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["reason_code"] == "graph_projection_not_ready"),
        "graph projection health finding should prevent empty-ok: {answer}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn map_action_findings_public_route_without_target_is_low_confidence() {
    let inventory_dir = tempfile::tempdir().unwrap();
    let _inventory_env = EnvVarGuard::set_path("CORTEX_INVENTORY_DIR", inventory_dir.path());
    let h = TestHarness::new();
    let inventory = graph_inventory_without_route_target_fixture();
    write_inventory_cache_fixture(inventory_dir.path(), &inventory);
    write_collection_state_fixture(
        inventory_dir.path(),
        vec![collector_state("raw_configs", "partial", vec!["redacted"])],
    );
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
        db::graph_inventory::project_inventory(&h.pool, &inventory).unwrap();
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "map",
            "mode": "findings",
            "finding_types": ["potential_public_route"]
        }),
        None,
    )
    .await
    .unwrap();

    let answer = &value["graph_answer"];
    let finding = answer["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["reason_code"] == "reverse_proxy_domain_without_target_proof")
        .unwrap_or_else(|| panic!("expected no-target route finding: {answer}"));
    assert_eq!(finding["severity"], "low");
    assert_eq!(finding["finding_type"], "potential_public_route");
    assert!(
        finding["confidence_context"]
            .as_str()
            .unwrap()
            .contains("Confidence reduced")
    );
    assert!(
        finding["affected_entities"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entity| entity["entity_type"] != "service"),
        "no-target finding should not invent a routed service: {finding}"
    );
}

#[tokio::test]
async fn correlate_state_action_defaults_reference_time_to_now() {
    let h = TestHarness::new();
    let value = execute_tool(
        &h.state,
        "cortex",
        json!({"action": "correlate_state"}),
        None,
    )
    .await
    .unwrap();
    assert_eq!(value["hosts"], json!([]));
    assert_eq!(value["truncated"], false);
    assert!(value["window"]["from"].is_string());
    assert!(value["window"]["to"].is_string());
}

#[tokio::test]
async fn correlate_state_action_returns_bounded_window() {
    let h = TestHarness::new();
    // Oversized window_minutes/limit must be clamped, not rejected, and an
    // empty DB must still return a well-formed bounded envelope (no broad scan).
    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "correlate_state",
            "reference_time": "2026-05-25T00:00:00Z",
            "window_minutes": 99999,
            "limit": 99999
        }),
        None,
    )
    .await
    .unwrap();
    assert!(
        value.get("window").is_some(),
        "correlate_state response missing window: {value}"
    );
    assert!(
        value["hosts"].is_array(),
        "correlate_state response missing hosts array: {value}"
    );
    assert_eq!(
        value["truncated"], false,
        "empty-DB correlate_state should not be truncated: {value}"
    );
}

#[tokio::test]
async fn correlate_action_with_topic_routes_to_topic_correlation() {
    let h = TestHarness::new();
    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "correlate",
            "topic": "edgehost dockersocket",
            "limit": 5
        }),
        None,
    )
    .await
    .unwrap();

    assert_eq!(value["topic"], "edgehost dockersocket");
    assert!(
        value.get("resolved_entities").is_some(),
        "topic correlation envelope missing resolved_entities: {value}"
    );
    assert!(
        value.get("timeline").is_some(),
        "topic correlation envelope missing timeline: {value}"
    );
}

#[tokio::test]
async fn host_state_action_reports_ambiguous_hostname() {
    let h = TestHarness::new();
    let conn = h.pool.get().unwrap();
    for host_id in ["host-a", "host-b"] {
        conn.execute(
            "INSERT INTO host_heartbeats (
                 host_id, hostname, source_ip, sampled_at, received_at, boot_id,
                 uptime_secs, sequence, collection_ms, partial, agent_version,
                 os, architecture
             ) VALUES (
                 ?1, 'shared', '127.0.0.1:41000', '2026-05-25T00:00:00Z',
                 '2026-05-25T00:00:01Z', 'boot-a', 60, 1, 5, 0,
                 '0.1.0-test', 'linux', 'x86_64'
             )",
            [host_id],
        )
        .unwrap();
    }
    drop(conn);

    let error = execute_tool(
        &h.state,
        "cortex",
        json!({"action": "host_state", "host": "shared"}),
        None,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("ambiguous_host"));
}

#[tokio::test]
async fn numeric_args_reject_out_of_range_values() {
    let h = TestHarness::new();
    let err = execute_tool(
        &h.state,
        "cortex",
        json!({"action": "tail", "n": u64::from(u32::MAX) + 1}),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("invalid tail arguments"));
}

#[tokio::test]
async fn numeric_args_reject_wrong_type_values() {
    let h = TestHarness::new();
    for args in [
        json!({"action": "tail", "n": "not-a-number"}),
        json!({"action": "search", "limit": "5"}),
        json!({"action": "correlate", "reference_time": "2026-01-01T00:00:00Z", "window_minutes": "5"}),
        json!({"action": "correlate", "reference_time": "2026-01-01T00:00:00Z", "limit": "10"}),
    ] {
        let err = execute_tool(&h.state, "cortex", args, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid ")
                && (err.to_string().contains("invalid type")
                    || err.to_string().contains("invalid value"))
        );
    }
}

fn sample_args_for_action(action: &str) -> Option<serde_json::Value> {
    Some(match action {
        "graph" => sample_graph_args_for_mode("entity"),
        "host_state" => json!({"action": action, "host_id": "schema-heartbeat"}),
        "correlate" => json!({"action": action, "reference_time": "2026-01-01T00:00:00Z"}),
        "correlate_state" => {
            json!({"action": action, "reference_time": "2026-01-01T00:00:00Z"})
        }
        "search_sessions" => json!({"action": action, "query": "schema"}),
        "ai_correlate" => json!({"action": action, "project": "/tmp/project"}),
        "topic_correlate" => json!({"action": action, "topic": "schema-test"}),
        "project_context" => json!({"action": action, "project": "/tmp/project"}),
        "context" => {
            json!({"action": action, "host": "schema-test-host", "timestamp": "2026-01-01T00:00:00Z"})
        }
        "get" => json!({"action": action, "id": 1}),
        "compare" => {
            json!({"action": action, "a_from": "2026-01-01T00:00:00Z", "a_to": "2026-01-01T00:01:00Z", "b_from": "2026-01-01T00:01:00Z", "b_to": "2026-01-01T00:02:00Z"})
        }
        "ack_error" | "unack_error" => {
            json!({"action": action, "signature_hash": "0000000000000000000000000000000000000000000000000000000000000000"})
        }
        "similar_incidents" => json!({"action": action, "query": "test"}),
        "recurring_error_comparison" => json!({
            "action": action,
            "until": "2026-01-01T01:00:00Z",
            "window_minutes": 60
        }),
        "incident_context" => {
            json!({"action": action, "since": "2026-01-01T00:00:00Z", "until": "2026-01-01T01:00:00Z"})
        }
        "file_tails" => json!({"action": action, "op": "status"}),
        "filter" => json!({"action": action, "host": "schema-test-host"}),
        "map" => json!({"action": action, "mode": "snapshot"}),
        "abuse" => json!({"action": action, "terms": ["schema"]}),
        "artifact_evidence_record" => json!({
            "action": action,
            "schemaVersion": "dinglebear.cortex-artifact-evidence/v1",
            "eventId": "schema-event",
            "eventKind": "discovery_observed",
            "sourceSystem": "axon",
            "sourceIssuer": "crawler:schema",
            "observedAt": "2026-01-01T00:00:00Z",
            "artifactId": "artifact-schema"
        }),
        "artifact_evidence" => json!({"action": action}),
        "fleet_state"
        | "search"
        | "tail"
        | "errors"
        | "hosts"
        | "stats"
        | "status"
        | "apps"
        | "sessions"
        | "abuse_incidents"
        | "abuse_investigate"
        | "usage_blocks"
        | "list_ai_tools"
        | "list_ai_projects"
        | "source_ips"
        | "timeline"
        | "patterns"
        | "ingest_rate"
        | "silent_hosts"
        | "clock_skew"
        | "anomalies"
        | "compose_status"
        | "compose_doctor"
        | "unaddressed_errors"
        | "notifications_recent"
        | "notifications_test"
        | "llm_invocations"
        | "skill_events"
        | "skill_incidents"
        | "mcp_events"
        | "mcp_incidents"
        | "mcp_investigate"
        | "hook_events"
        | "hook_incidents"
        | "hook_investigate"
        | "help" => json!({"action": action}),
        "skill_investigate" => json!({"action": action, "skill": "schema-test-skill"}),
        _ => return None,
    })
}

fn sample_graph_args_for_mode(mode: &str) -> serde_json::Value {
    match mode {
        "entity" => {
            json!({"action": "graph", "mode": "entity", "entity_type": "host", "key": "schema-test-host"})
        }
        "around" => {
            json!({"action": "graph", "mode": "around", "entity_type": "host", "key": "schema-test-host"})
        }
        "explain" => {
            json!({"action": "graph", "mode": "explain", "entity_type": "host", "key": "schema-test-host"})
        }
        "evidence" => json!({"action": "graph", "mode": "evidence", "evidence_id": 1}),
        other => panic!("unsupported graph test mode: {other}"),
    }
}

fn typed_unknown_field_samples() -> Vec<serde_json::Value> {
    let mut samples = [
        "search",
        "filter",
        "tail",
        "errors",
        "map",
        "host_state",
        "fleet_state",
        "correlate",
        "correlate_state",
        "apps",
        "sessions",
        "search_sessions",
        "abuse",
        "abuse_incidents",
        "abuse_investigate",
        "ai_correlate",
        "usage_blocks",
        "project_context",
        "list_ai_tools",
        "list_ai_projects",
        "source_ips",
        "timeline",
        "patterns",
        "context",
        "get",
        "ingest_rate",
        "silent_hosts",
        "clock_skew",
        "anomalies",
        "compare",
        "unaddressed_errors",
        "ack_error",
        "unack_error",
        "notifications_recent",
        "similar_incidents",
        "recurring_error_comparison",
        "incident_context",
        "artifact_evidence",
        "artifact_evidence_record",
    ]
    .into_iter()
    .filter_map(sample_args_for_action)
    .collect::<Vec<_>>();

    samples.extend(
        ["entity", "around", "explain", "evidence"]
            .into_iter()
            .map(sample_graph_args_for_mode),
    );
    samples
}

#[tokio::test]
async fn mcp_rejects_unknown_fields_for_typed_request_actions() {
    let h = TestHarness::new();
    for mut args in typed_unknown_field_samples() {
        let action = args["action"].as_str().unwrap().to_string();
        args.as_object_mut()
            .unwrap()
            .insert("bogus".to_string(), json!(true));
        let err = execute_tool(&h.state, "cortex", args, None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("invalid {action} arguments")) && msg.contains("unknown field"),
            "action={action} returned unexpected error: {msg}"
        );
    }
}

#[test]
fn action_registry_rows_have_executable_handlers() {
    for spec in super::actions::ACTION_SPECS {
        assert_eq!(
            super::actions::handler_for(spec.name),
            Some(spec.handler),
            "registered action lacks handler lookup: {}",
            spec.name
        );
        assert!(
            sample_args_for_action(spec.name).is_some(),
            "schema dispatch test lacks executable sample for handler-backed action: {}",
            spec.name
        );
    }
}

#[tokio::test]
async fn schema_actions_are_dispatchable() {
    let h = TestHarness::new();
    db::insert_logs_batch(
        &h.pool,
        &[db::LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "schema-test-host".to_string(),
            facility: Some("auth".to_string()),
            severity: "err".to_string(),
            app_name: Some("schema-test".to_string()),
            process_id: Some("42".to_string()),
            message: "schema dispatch test".to_string(),
            raw: "<11>schema dispatch test".to_string(),
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
        }],
    )
    .unwrap();
    {
        let conn = h.pool.get().unwrap();
        conn.execute(
            "INSERT INTO host_heartbeats (
                 host_id, hostname, source_ip, sampled_at, received_at, boot_id,
                 uptime_secs, sequence, collection_ms, partial, agent_version,
                 os, architecture, metadata_json
             ) VALUES (
                 'schema-heartbeat', 'schema-heartbeat-host', '127.0.0.1:41000',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'boot-a',
                 60, 1, 5, 0, '0.1.0-test', 'linux', 'x86_64',
                 '{\"agent\":{\"interval_secs\":30}}'
             )",
            [],
        )
        .unwrap();
    }
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
    }
    for action in &super::actions::action_names() {
        let args = sample_args_for_action(action).unwrap_or_else(|| {
            panic!("schema dispatch test lacks a sample for registered action: {action}")
        });
        let result = execute_tool(&h.state, "cortex", args, None).await;
        if *action == "compose_doctor" {
            if let Err(error) = result {
                assert!(
                    error.to_string().contains("compose doctor failed"),
                    "compose_doctor failed before dispatching: {error}"
                );
            }
        } else if matches!(*action, "ack_error" | "unack_error") {
            // These require an existing signature. When given a non-existent hash,
            // they must return Err (ServiceError::NotFound propagates via ?).
            match result {
                Err(ref error) => {
                    assert!(
                        error.to_string().to_lowercase().contains("not found")
                            || error.to_string().contains("Signature"),
                        "action={action} returned unexpected error: {error}"
                    );
                }
                Ok(_) => {
                    panic!("action={action} with non-existent hash should return NotFound, got Ok")
                }
            }
        } else if *action == "notifications_test" {
            // notifications_test requires a live Apprise server; transient/delivery
            // failures are expected in test environments.
            if let Err(ref error) = result {
                assert!(
                    error.to_string().contains("Apprise")
                        || error.to_string().contains("delivery")
                        || error.to_string().contains("Rate limit")
                        || error.to_string().contains("no_apprise"),
                    "action={action} failed unexpectedly: {error}"
                );
            }
        } else {
            result
                .unwrap_or_else(|error| panic!("schema action {action} did not dispatch: {error}"));
        }
    }
}

#[tokio::test]
async fn graph_evidence_mode_dispatches_and_schema_lists_modes() {
    let h = TestHarness::new();
    db::insert_logs_batch(
        &h.pool,
        &[db::LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "mcp-proof-host".to_string(),
            facility: Some("auth".to_string()),
            severity: "info".to_string(),
            app_name: Some("sshd".to_string()),
            process_id: Some("42".to_string()),
            message: "mcp graph proof".to_string(),
            raw: "<14>mcp graph proof".to_string(),
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
        }],
    )
    .unwrap();
    {
        let _guard = db::graph::GRAPH_TEST_LOCK.lock();
        db::graph::refresh_graph_projection(&h.pool).unwrap();
    }
    let evidence_id: i64 = {
        let conn = h.pool.get().unwrap();
        conn.query_row(
            "SELECT id FROM graph_relationship_evidence
             WHERE source_log_id IS NOT NULL
             ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    let value = execute_tool(
        &h.state,
        "cortex",
        json!({"action": "graph", "mode": "evidence", "evidence_id": evidence_id}),
        None,
    )
    .await
    .unwrap();
    assert_eq!(value["evidence"]["id"], evidence_id);
    assert!(value["src_entity"].is_object());
    assert!(value["dst_entity"].is_object());
    assert!(value["relationship"]["src_entity"].is_object());
    assert!(value["relationship"]["dst_entity"].is_object());
    assert!(value["source_log_summary"].is_object());

    let defs = crate::mcp::schemas::tool_definitions();
    let mode_enum = defs[0]["inputSchema"]["properties"]["mode"]["enum"]
        .as_array()
        .unwrap();
    for expected in ["entity", "around", "explain", "evidence"] {
        assert!(mode_enum.iter().any(|value| value == expected));
    }
    assert!(
        defs[0]["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .contains_key("evidence_id")
    );
    assert_eq!(
        defs[0]["inputSchema"]["properties"]["evidence_id"]["minimum"],
        1
    );
}

#[tokio::test]
async fn graph_action_rejects_mixed_target_fields_and_depth_zero() {
    let h = TestHarness::new();
    let mixed = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "graph",
            "mode": "around",
            "entity_id": 1,
            "entity_type": "host",
            "key": "schema-test-host"
        }),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        mixed.to_string().contains("exactly one lookup strategy"),
        "unexpected graph mixed-target error: {mixed}"
    );

    let depth_zero = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "graph",
            "mode": "around",
            "entity_type": "host",
            "key": "schema-test-host",
            "depth": 0
        }),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        depth_zero.to_string().contains("depth=1"),
        "unexpected graph depth=0 error: {depth_zero}"
    );
}

#[tokio::test]
async fn public_action_references_cover_schema_registry() {
    let help = tool_cortex_help().await.unwrap();
    let help = help["help"].as_str().unwrap().to_ascii_lowercase();
    for action in &super::actions::action_names() {
        assert!(
            help.contains(&format!("## cortex {action}")),
            "help text missing action section: {action}"
        );
    }

    for (path, content) in [
        (
            "scripts/smoke-test.sh",
            include_str!("../../scripts/smoke-test.sh"),
        ),
        (
            "tests/test_live.sh",
            include_str!("../../tests/test_live.sh"),
        ),
    ] {
        assert!(
            content.contains("tests/live/run-profile.sh"),
            "{path} must remain a thin wrapper around the registry-derived live runner"
        );
    }

    for (path, content) in [
        ("docs/INVENTORY.md", include_str!("../../docs/INVENTORY.md")),
        (
            "docs/mcp/SCHEMA.md",
            include_str!("../../docs/mcp/SCHEMA.md"),
        ),
        ("docs/mcp/TOOLS.md", include_str!("../../docs/mcp/TOOLS.md")),
        ("docs/mcp/TESTS.md", include_str!("../../docs/mcp/TESTS.md")),
        (
            "plugins/cortex/skills/cortex/SKILL.md",
            include_str!("../../plugins/cortex/skills/cortex/SKILL.md"),
        ),
    ] {
        for action in &super::actions::action_names() {
            assert!(
                content.contains(&format!("`{action}`"))
                    || content.contains(&format!("cortex {action}")),
                "{path} missing action reference for {action}"
            );
        }
    }
}

#[tokio::test]
async fn syslog_tool_requires_known_action() {
    let h = TestHarness::new();
    let missing = execute_tool(&h.state, "cortex", json!({}), None)
        .await
        .unwrap_err();
    assert!(missing.to_string().contains("action is required"));

    let unknown = execute_tool(&h.state, "cortex", json!({"action": "reboot"}), None)
        .await
        .unwrap_err();
    assert!(unknown.to_string().contains("unknown cortex action"));
}

#[tokio::test]
async fn compose_action_rejects_target_override() {
    let h = TestHarness::new();
    for action in ["compose_status", "compose_doctor"] {
        for key in [
            "container",
            "container_name",
            "project_dir",
            "compose_file",
            "project_name",
            "service",
        ] {
            let mut args = json!({"action": action});
            args.as_object_mut()
                .unwrap()
                .insert(key.into(), json!("override-value"));
            let err = execute_tool(&h.state, "cortex", args, None)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("target override"),
                "expected target override rejection for {action}.{key}, got: {err}"
            );
        }
    }
}

#[test]
fn parse_optional_timestamp_normalizes_offsets_to_utc() {
    let parsed = crate::app::parse_optional_timestamp(Some("2026-01-01T01:00:00+01:00"), "from")
        .unwrap()
        .unwrap();
    assert_eq!(parsed, "2026-01-01T00:00:00.000Z");
}

#[test]
fn parse_optional_timestamp_rejects_invalid_values() {
    let err = crate::app::parse_optional_timestamp(Some("not-a-date"), "from").unwrap_err();
    assert!(err.to_string().contains("Invalid from"));
}

#[tokio::test]
async fn graph_action_redacts_sensitive_identifiers_in_entity_responses() {
    let h = TestHarness::new();
    {
        let conn = h.pool.get().unwrap();
        conn.execute(
            "INSERT INTO graph_entities
                (entity_type, canonical_key, display_label, source_kind, source_id, trust_level)
             VALUES ('config_artifact', 'leaky-artifact',
                     '/home/jmagar/.cortex/compose.yaml',
                     'app_inventory', 'api_key=super-sensitive', 'verified')",
            [],
        )
        .unwrap();
    }

    let value = execute_tool(
        &h.state,
        "cortex",
        json!({
            "action": "graph",
            "mode": "entity",
            "entity_type": "config_artifact",
            "key": "leaky-artifact"
        }),
        None,
    )
    .await
    .unwrap();

    let entity = &value["resolved_entity"];
    assert_eq!(entity["canonical_key"], "leaky-artifact");
    assert_eq!(entity["display_label"], "[redacted]");
    assert_eq!(entity["source_id"], "[redacted]");
}
