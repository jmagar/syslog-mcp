//! Tests for the enrichment pipeline.

use std::fs;

use serial_test::serial;

use super::*;

fn entry(app: &str, msg: &str, source_ip: &str, severity: &str) -> LogBatchEntry {
    LogBatchEntry {
        timestamp: "2026-05-07T00:00:00.000Z".to_string(),
        hostname: "test".to_string(),
        facility: None,
        severity: severity.to_string(),
        app_name: Some(app.to_string()),
        process_id: None,
        message: msg.to_string(),
        raw: String::new(),
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

// ---- authelia severity parsing ----

#[test]
fn authelia_level_warn_promotes_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry(
        "authelia",
        "time=2026-05-07 level=warn msg=\"failed login\"",
        "10.0.0.1:1234",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "warning");
}

#[test]
fn authelia_level_error_promotes_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry("authelia", "level=error msg=test", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "err");
}

#[test]
fn authelia_no_level_keeps_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry("authelia", "no level field here", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "info");
}

#[test]
fn authelia_unknown_level_keeps_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry("authelia", "level=galaxy", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "info");
}

#[test]
fn authelia_source_ip_gating_blocks_non_matching() {
    let cfg = EnrichmentConfig {
        authelia_source_ip: Some("192.168.1.10".into()),
        ..Default::default()
    };
    let e = entry("authelia", "level=error msg=foo", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    // Severity must NOT be promoted because source IP doesn't match.
    assert_eq!(out.severity, "info");
}

#[test]
fn authelia_source_ip_gating_allows_matching() {
    let cfg = EnrichmentConfig {
        authelia_source_ip: Some("192.168.1.10".into()),
        ..Default::default()
    };
    let e = entry(
        "authelia",
        "level=error msg=foo",
        "192.168.1.10:5000",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "err");
}

/// Regression: prefix `10.0.0.1` must NOT match a spoofer at `10.0.0.10`.
/// Plain `starts_with` would have, allowing an attacker one IP off from the
/// configured authelia host to inject `level=` reclassifications.
#[test]
fn authelia_source_ip_gating_blocks_prefix_collision() {
    let cfg = EnrichmentConfig {
        authelia_source_ip: Some("10.0.0.1".into()),
        ..Default::default()
    };
    // Attacker on 10.0.0.10 — would pass naive starts_with(10.0.0.1)
    let e = entry("authelia", "level=err msg=spoof", "10.0.0.10:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(
        out.severity, "info",
        "prefix-collision must not bypass gate"
    );
}

/// Subnet match: prefix ending in `.` (e.g. `10.0.0.`) matches any host in
/// that octet boundary.
#[test]
fn authelia_source_ip_gating_subnet_match_with_trailing_dot() {
    let cfg = EnrichmentConfig {
        authelia_source_ip: Some("10.0.0.".into()),
        ..Default::default()
    };
    let e = entry("authelia", "level=warn msg=ok", "10.0.0.42:9000", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "warning");
}

// ---- adguard tag classification ----

#[test]
fn adguard_filtered_becomes_blocked() {
    let cfg = EnrichmentConfig::default();
    let body = r#"{"QH":"ads.example.com","Result":{"IsFiltered":true,"Reason":"FilteredBlackList"},"Upstream":""}"#;
    let e = entry("adguard-query", body, "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.app_name.as_deref(), Some("adguard-blocked"));
}

#[test]
fn adguard_unfiltered_with_upstream_becomes_allowed() {
    let cfg = EnrichmentConfig::default();
    let body =
        r#"{"QH":"github.com","Result":{"IsFiltered":false,"Reason":""},"Upstream":"9.9.9.9:53"}"#;
    let e = entry("adguard-query", body, "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.app_name.as_deref(), Some("adguard-allowed"));
}

#[test]
fn adguard_rewrite_classified() {
    let cfg = EnrichmentConfig::default();
    let body =
        r#"{"QH":"local.lan","Result":{"IsFiltered":false,"Reason":"Rewrite"},"Upstream":""}"#;
    let e = entry("adguard-query", body, "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.app_name.as_deref(), Some("adguard-rewrite"));
}

#[test]
fn adguard_malformed_json_passes_through() {
    let cfg = EnrichmentConfig::default();
    let e = entry("adguard-query", "{not json", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.app_name.as_deref(), Some("adguard-query"));
}

#[test]
fn adguard_source_ip_gating_blocks_spoof() {
    let cfg = EnrichmentConfig {
        adguard_source_ip: Some("192.168.1.20".into()),
        ..Default::default()
    };
    let body = r#"{"Result":{"IsFiltered":true},"Upstream":""}"#;
    let e = entry("adguard-query", body, "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.app_name.as_deref(), Some("adguard-query"));
}

// ---- non-target apps unchanged ----

#[test]
fn non_authelia_non_adguard_passes_unchanged() {
    let cfg = EnrichmentConfig::default();
    let e = entry("nginx", "level=error this is nginx", "10.0.0.1:1", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.severity, "info");
    assert_eq!(out.app_name.as_deref(), Some("nginx"));
}

#[test]
fn structured_warn_token_promotes_loose_syslog_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry(
        "lab-serve-wrapper.sh",
        "08:09:22   WARN  node websocket reconnect scheduled  action=ws.reconnect_attempt",
        "192.0.2.8:46502",
        "info",
    );

    let out = enrich_entry(e, &cfg);

    assert_eq!(out.severity, "warning");
}

#[test]
fn structured_level_never_demotes_explicit_syslog_severity() {
    let cfg = EnrichmentConfig::default();
    let e = entry(
        "worker",
        "08:09:22 INFO request failed after retries",
        "192.0.2.8:46502",
        "err",
    );

    let out = enrich_entry(e, &cfg);

    assert_eq!(out.severity, "err");
}

// ---- secret scrubbing ----

#[test]
fn scrub_aws_access_key() {
    let cfg = EnrichmentConfig {
        scrub_prompts: true,
        ..Default::default()
    };
    let e = entry(
        "claude-code",
        "Found AKIAIOSFODNN7EXAMPLE in the env file",
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert!(out.message.contains("[REDACTED]"));
    assert!(!out.message.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn scrub_github_token() {
    let cfg = EnrichmentConfig {
        scrub_prompts: true,
        ..Default::default()
    };
    let e = entry(
        "claude-transcript",
        "use token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa here",
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert!(out.message.contains("[REDACTED]"));
    assert!(!out.message.contains("ghp_aaaa"));
}

#[test]
fn scrub_api_token_value() {
    let cfg = EnrichmentConfig {
        scrub_prompts: true,
        api_token: Some("super-secret-token-value-123".into()),
        ..Default::default()
    };
    let e = entry(
        "claude-code",
        "the token is super-secret-token-value-123 do not share",
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert!(!out.message.contains("super-secret-token-value-123"));
    assert!(out.message.contains("[REDACTED]"));
}

#[test]
fn scrub_generic_credential_assignments() {
    let cases = [
        "token=ordinary-value",
        "access_token: ordinary-value",
        "client-secret=ordinary-value",
        "credential: ordinary-value",
        "private_key=ordinary-value",
        "\"token\":\"ordinary-value\"",
    ];
    for credential_case in cases {
        let scrubbed = scrub_ai_message(&format!("before {credential_case} after"), None);
        assert_eq!(scrubbed, "before [REDACTED] after");
        assert!(!scrubbed.contains("ordinary-value"));
    }
}

#[test]
fn scrub_disabled_leaves_message_untouched() {
    let cfg = EnrichmentConfig {
        scrub_prompts: false,
        ..Default::default()
    };
    let e = entry(
        "claude-code",
        "AKIAIOSFODNN7EXAMPLE in plain text",
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert!(out.message.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn scrub_skips_non_ai_source() {
    let cfg = EnrichmentConfig {
        scrub_prompts: true,
        ..Default::default()
    };
    let e = entry(
        "nginx",
        "AKIAIOSFODNN7EXAMPLE in nginx log",
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    // nginx is not in AI_SOURCES, scrubber doesn't touch it
    assert!(out.message.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ---- AI transcript enrichment ----

#[test]
fn enriches_codex_session_meta_with_project_and_session() {
    let cfg = EnrichmentConfig::default();
    let e = entry(
        "codex-transcript",
        r#"{"timestamp":"2026-05-11T03:16:18.603Z","type":"session_meta","payload":{"id":"019e1506-dc81-7881-9926-4d6d4efda1ac","cwd":"/home/jmagar/workspace/mem0"}}"#,
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("codex"));
    assert_eq!(
        out.ai_project.as_deref(),
        Some("/home/jmagar/workspace/mem0")
    );
    assert_eq!(
        out.ai_session_id.as_deref(),
        Some("019e1506-dc81-7881-9926-4d6d4efda1ac")
    );
}

#[test]
fn enriches_codex_function_call_workdir_when_session_meta_absent() {
    let cfg = EnrichmentConfig::default();
    let e = entry(
        "codex-transcript",
        r#"{"type":"response_item","payload":{"type":"function_call","arguments":"{\"cmd\":\"cargo test\",\"workdir\":\"/home/jmagar/code/swag-mcp\"}"}}"#,
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("codex"));
    assert_eq!(
        out.ai_project.as_deref(),
        Some("/home/jmagar/code/swag-mcp")
    );
}

#[test]
fn enriches_codex_workdir_normalizes_project_local_worktree() {
    let cfg = EnrichmentConfig::default();
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("workspace/cortex");
    let worktree = project.join(".worktrees/session-indexing");
    let e = entry(
        "codex-transcript",
        &format!(
            "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"function_call\",\"arguments\":\"{{\\\"cmd\\\":\\\"cargo test\\\",\\\"workdir\\\":\\\"{}\\\"}}\"}}}}",
            worktree.display()
        ),
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("codex"));
    assert_eq!(out.ai_project.as_deref(), Some(project.to_str().unwrap()));
}

#[test]
fn enriches_codex_workdir_keeps_codex_app_worktree_even_when_workspace_project_exists() {
    let cfg = EnrichmentConfig::default();
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("workspace/cortex");
    fs::create_dir_all(&project).unwrap();
    let worktree = tmp
        .path()
        .join(".codex/worktrees/ade935ee-48ec-49f4-8e89-ccb0294e73eb/cortex");
    let e = entry(
        "codex-transcript",
        &format!(
            "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"function_call\",\"arguments\":\"{{\\\"cmd\\\":\\\"cargo test\\\",\\\"workdir\\\":\\\"{}\\\"}}\"}}}}",
            worktree.display()
        ),
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("codex"));
    assert_eq!(out.ai_project.as_deref(), Some(worktree.to_str().unwrap()));
}

#[test]
fn enriches_codex_workdir_keeps_codex_app_worktree_when_workspace_project_missing() {
    let cfg = EnrichmentConfig::default();
    let tmp = tempfile::tempdir().unwrap();
    let worktree = tmp
        .path()
        .join(".codex/worktrees/ade935ee-48ec-49f4-8e89-ccb0294e73eb/cortex");
    let e = entry(
        "codex-transcript",
        &format!(
            "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"function_call\",\"arguments\":\"{{\\\"cmd\\\":\\\"cargo test\\\",\\\"workdir\\\":\\\"{}\\\"}}\"}}}}",
            worktree.display()
        ),
        "10.0.0.1:1",
        "info",
    );
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("codex"));
    assert_eq!(out.ai_project.as_deref(), Some(worktree.to_str().unwrap()));
}

#[test]
fn enriches_claude_project_from_transcript_path_in_raw() {
    let cfg = EnrichmentConfig::default();
    let mut e = entry(
        "claude-transcript",
        r#"{"sessionId":"3a8bdaf9-721c-4e0b-8a6b-cffe2740c8d5","cwd":"/home/jmagar/workspace/cortex"}"#,
        "10.0.0.1:1",
        "info",
    );
    e.raw = r#"<165>1 2026-05-11T00:00:00Z devhost claude-transcript - - [origin file="/home/jmagar/.claude/projects/-home-jmagar-workspace-cortex/3a8bdaf9-721c-4e0b-8a6b-cffe2740c8d5.jsonl"] {"sessionId":"3a8bdaf9-721c-4e0b-8a6b-cffe2740c8d5"}"#.to_string();
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.ai_tool.as_deref(), Some("claude"));
    assert_eq!(
        out.ai_project.as_deref(),
        Some("/home/jmagar/workspace/cortex")
    );
    assert_eq!(
        out.ai_session_id.as_deref(),
        Some("3a8bdaf9-721c-4e0b-8a6b-cffe2740c8d5")
    );
    assert_eq!(
        out.ai_transcript_path.as_deref(),
        Some(
            "/home/jmagar/.claude/projects/-home-jmagar-workspace-cortex/3a8bdaf9-721c-4e0b-8a6b-cffe2740c8d5.jsonl"
        )
    );
}

#[test]
fn project_from_transcript_path_prefers_sessions_index_original_path() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("cortex");
    fs::create_dir_all(&project).unwrap();

    let transcript_dir = tmp.path().join(".claude/projects/-tmp-cortex");
    fs::create_dir_all(&transcript_dir).unwrap();
    fs::write(
        transcript_dir.join("sessions-index.json"),
        format!(
            "{{\"version\":1,\"entries\":[],\"originalPath\":\"{}\"}}",
            project.display()
        ),
    )
    .unwrap();

    let transcript = transcript_dir.join("session-123.jsonl");
    assert_eq!(
        project_from_transcript_path(transcript.to_str().unwrap()).as_deref(),
        Some(project.to_str().unwrap())
    );
}

#[test]
fn project_from_transcript_path_normalizes_sessions_index_worktree_path() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("workspace/cortex");
    let worktree = project.join(".claude/worktrees/session-indexing");
    fs::create_dir_all(&worktree).unwrap();

    let transcript_dir = tmp.path().join(".claude/projects/-tmp-cortex");
    fs::create_dir_all(&transcript_dir).unwrap();
    fs::write(
        transcript_dir.join("sessions-index.json"),
        format!(
            "{{\"version\":1,\"entries\":[{{\"projectPath\":\"{}\"}}]}}",
            worktree.display()
        ),
    )
    .unwrap();

    let transcript = transcript_dir.join("session-123.jsonl");
    assert_eq!(
        project_from_transcript_path(transcript.to_str().unwrap()).as_deref(),
        Some(project.to_str().unwrap())
    );
}

#[test]
fn project_from_transcript_path_normalizes_decoded_claude_worktree_fallback() {
    let transcript = "/home/jmagar/.claude/projects/-home-jmagar-workspace-cortex-.claude-worktrees-session-indexing/session-123.jsonl";

    assert_eq!(
        project_from_transcript_path(transcript).as_deref(),
        Some("/home/jmagar/workspace/cortex")
    );
}

// ---- agent docker identity metadata extraction ----

/// The agent-docker source gate is fail-closed, so extraction tests must
/// supply a gate that admits the `10.0.0.*` source IPs used by `entry()`.
/// Tests covering the gate itself build their own config instead.
fn agent_docker_cfg() -> EnrichmentConfig {
    EnrichmentConfig {
        agent_docker_source_prefixes: vec!["10.0.0.".to_string()],
        ..EnrichmentConfig::default()
    }
}

#[test]
fn agent_docker_meta_prefix_is_extracted_into_metadata_json_and_stripped() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"source_kind":"agent-docker","agent_docker":{"host":"nashost","container_id":"abcdef1234567890","container_name":"plex","compose_project":"plex","compose_service":"plex","image":"lscr.io/linuxserver/plex:latest","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] Plex library scan");
    let e = entry("plex/plex/plex", &msg, "10.0.0.1:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, "Plex library scan");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_kind"], "agent-docker");
    assert_eq!(metadata["agent_docker"]["host"], "nashost");
    assert_eq!(metadata["agent_docker"]["compose_service"], "plex");
    assert_eq!(metadata["agent_docker"]["stream"], "stdout");
}

#[test]
fn agent_docker_lifecycle_metadata_becomes_a_canonical_docker_event() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abcdef1234567890","container_name":"plex","compose_project":"plex","compose_service":"plex","image":"plex:latest","stream":"event","event_action":"die","exit_code":137}}"#;
    let msg = format!(
        "[cortex-agent-docker-meta:{meta}] docker container event: die container=plex exit_code=137"
    );
    let e = entry("plex", &msg, "10.0.0.1:1234", "info");
    let out = enrich_entry(e, &cfg);
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();

    assert_eq!(metadata["source_kind"], "docker-event");
    assert_eq!(metadata["docker"]["event_action"], "die");
    assert_eq!(metadata["docker"]["exit_code"], 137);
    assert_eq!(out.facility.as_deref(), Some("docker"));
    assert_eq!(out.source_ip, "10.0.0.1:1234");
}

#[test]
fn sender_asserted_lifecycle_identity_cannot_spoof_transport_source_ip() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"agent_docker":{"host":"trusted-looking-host","container_id":"abc","container_name":"victim","stream":"event","event_action":"oom"}}"#;
    let msg =
        format!("[cortex-agent-docker-meta:{meta}] docker container event: oom container=victim");
    let out = enrich_entry(entry("victim", &msg, "10.0.0.66:1514", "err"), &cfg);
    assert_eq!(out.source_ip, "10.0.0.66:1514");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["docker"]["host"], "trusted-looking-host");
    assert_eq!(metadata["docker"]["event_action"], "oom");
}

#[test]
fn agent_docker_meta_prefix_merges_with_existing_metadata() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"source_kind":"agent-docker","agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    let mut e = entry("plex", &msg, "10.0.0.1:1234", "info");
    e.metadata_json = Some(r#"{"source_type":"syslog","input_format":"syslog"}"#.to_string());
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, "hello");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_type"], "syslog");
    assert_eq!(metadata["source_kind"], "agent-docker");
    assert_eq!(metadata["agent_docker"]["container_name"], "plex");
}

#[test]
fn malformed_agent_docker_meta_prefix_leaves_message_untouched() {
    let cfg = agent_docker_cfg();
    let msg = "[cortex-agent-docker-meta:{not json] hello";
    let e = entry("plex", msg, "10.0.0.1:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, msg);
}

#[test]
// Shares the `AGENT_DOCKER_GATE_BLOCKED_COUNT` process-lifetime static with
// `agent_docker_gate_blocked_counter_increments_on_forged_source` — serialize
// so that test's before/after delta assertion isn't racy against this test's
// own gate-blocked calls.
#[serial(agent_docker_gate_blocked_counter)]
fn agent_docker_meta_prefix_ignored_from_non_matching_source_ip() {
    let cfg = EnrichmentConfig {
        agent_docker_source_prefixes: vec!["10.0.0.5".to_string(), "198.51.100.".to_string()],
        ..EnrichmentConfig::default()
    };
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] forged");
    // Forged marker from an unlisted sender: not extracted, message kept.
    let e = entry("plex", &msg, "10.0.0.99:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, msg);
    assert!(out.metadata_json.is_none());
    // Octet-boundary check: 10.0.0.50 must not pass an exact-host 10.0.0.5.
    let e = entry("plex", &msg, "10.0.0.50:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, msg);
    // Matching senders (exact host, subnet prefix) still extract.
    for ip in ["10.0.0.5:900", "198.51.100.8:900"] {
        let e = entry("plex", &msg, ip, "info");
        let out = enrich_entry(e, &cfg);
        assert_eq!(out.message, "forged");
        let metadata: serde_json::Value =
            serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["agent_docker"]["container_name"], "plex");
        assert_eq!(metadata["source_kind"], "agent-docker");
    }
}

#[test]
// See comment on `agent_docker_meta_prefix_ignored_from_non_matching_source_ip`.
#[serial(agent_docker_gate_blocked_counter)]
fn agent_docker_gate_blocked_counter_increments_on_forged_source() {
    let cfg = EnrichmentConfig {
        agent_docker_source_prefixes: vec!["10.0.0.5".to_string()],
        ..EnrichmentConfig::default()
    };
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] forged");

    let before = agent_docker_gate_blocked_count();
    // Sender IP does not match the configured gate: extraction is blocked
    // and the counter must record it.
    let e = entry("plex", &msg, "10.0.0.99:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, msg, "marker must stay in the message");
    assert!(out.metadata_json.is_none());
    assert_eq!(
        agent_docker_gate_blocked_count(),
        before + 1,
        "gate-blocked counter must increment exactly once for the blocked entry"
    );

    // A matching sender extracts normally and must NOT increment the
    // gate-blocked counter.
    let e = entry("plex", &msg, "10.0.0.5:1234", "info");
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, "forged");
    assert_eq!(
        agent_docker_gate_blocked_count(),
        before + 1,
        "counter must not increment for a gate-matching entry"
    );
}

#[test]
// See comment on `agent_docker_meta_prefix_ignored_from_non_matching_source_ip`.
#[serial(agent_docker_gate_blocked_counter)]
fn agent_docker_source_gate_matches_bracketed_ipv6_exact_entry() {
    let cfg = EnrichmentConfig {
        agent_docker_source_prefixes: vec!["2001:db8::1".to_string(), "10.0.0.5".to_string()],
        ..EnrichmentConfig::default()
    };
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    // Bracketed IPv6 source with a matching exact IPv6 entry extracts.
    let out = enrich_entry(entry("plex", &msg, "[2001:db8::1]:514", "info"), &cfg);
    assert_eq!(out.message, "hello");
    // Non-canonical spelling of the same address still matches (parsed
    // address comparison, not string comparison).
    let out = enrich_entry(
        entry("plex", &msg, "[2001:0db8:0000::0001]:514", "info"),
        &cfg,
    );
    assert_eq!(out.message, "hello");
    // A different IPv6 source does not match.
    let out = enrich_entry(entry("plex", &msg, "[2001:db8::2]:514", "info"), &cfg);
    assert_eq!(out.message, msg);
    // IPv4 behavior is unchanged alongside the IPv6 entry: octet-boundary
    // semantics still hold (10.0.0.50 must not pass exact-host 10.0.0.5).
    let out = enrich_entry(entry("plex", &msg, "10.0.0.50:1234", "info"), &cfg);
    assert_eq!(out.message, msg);
    let out = enrich_entry(entry("plex", &msg, "10.0.0.5:1234", "info"), &cfg);
    assert_eq!(out.message, "hello");
}

#[test]
fn agent_docker_meta_payload_cannot_overwrite_existing_metadata_keys() {
    let cfg = agent_docker_cfg();
    // Payload tries to smuggle extra top-level keys and clobber parser-set
    // metadata; only `agent_docker` may be taken, `source_kind` is set from
    // the receiver constant, and existing keys survive.
    let meta = r#"{"source_kind":"otlp","source_type":"evil","injected":"x","agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    let mut e = entry("plex", &msg, "10.0.0.1:1234", "info");
    e.metadata_json = Some(r#"{"source_type":"syslog"}"#.to_string());
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, "hello");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_type"], "syslog");
    assert_eq!(metadata["source_kind"], "agent-docker");
    assert!(metadata.get("injected").is_none());
    assert_eq!(metadata["agent_docker"]["container_name"], "plex");
}

#[test]
fn agent_docker_meta_overwrites_preexisting_source_kind_with_constant() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    let mut e = entry("plex", &msg, "10.0.0.1:1234", "info");
    // Pins the documented exception: a pre-existing denormalised
    // `source_kind` IS deliberately overwritten by the receiver constant
    // (never by the payload) when the marker is extracted.
    e.metadata_json = Some(r#"{"source_kind":"syslog-tcp"}"#.to_string());
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, "hello");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_kind"], "agent-docker");
}

#[test]
fn agent_docker_meta_backs_out_when_merged_metadata_would_truncate() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    // Pre-existing metadata large enough that the merged object exceeds the
    // 64 KiB bound even after sanitization. Truncating would drop the
    // freshly extracted agent_docker identity, so extraction must back out
    // and leave the entry untouched (marker stays in the message).
    let big: String = (0..120)
        .map(|i| format!("\"field_{i}\":\"{}\"", "x".repeat(600)))
        .collect::<Vec<_>>()
        .join(",");
    let original_metadata = format!("{{{big}}}");
    let mut e = entry("plex", &msg, "10.0.0.1:1234", "info");
    e.metadata_json = Some(original_metadata.clone());
    let out = enrich_entry(e, &cfg);
    assert_eq!(out.message, msg, "marker must stay in the message");
    assert_eq!(
        out.metadata_json.as_deref(),
        Some(original_metadata.as_str()),
        "pre-existing metadata must be untouched"
    );
}

#[test]
fn agent_docker_meta_payload_cannot_replace_existing_agent_docker_object() {
    let cfg = agent_docker_cfg();
    let meta = r#"{"agent_docker":{"host":"evil","container_id":"abc","container_name":"forged","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    let mut e = entry("plex", &msg, "10.0.0.1:1234", "info");
    e.metadata_json = Some(r#"{"agent_docker":{"host":"nashost"}}"#.to_string());
    let out = enrich_entry(e, &cfg);
    // Entry left untouched: existing agent_docker identity is never replaced.
    assert_eq!(out.message, msg);
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["agent_docker"]["host"], "nashost");
}

#[test]
// See comment on `agent_docker_meta_prefix_ignored_from_non_matching_source_ip`.
#[serial(agent_docker_gate_blocked_counter)]
fn agent_docker_marker_is_rejected_when_no_prefixes_are_configured() {
    // Fail-closed default. An empty allowlist means "trust nobody": the gate
    // must reject the marker rather than honour it from every sender. The
    // syslog port is reachable by the whole fleet, so the inverse (an empty
    // list accepting anyone) is a forgeable identity channel.
    let cfg = EnrichmentConfig::default();
    assert!(cfg.agent_docker_source_prefixes.is_empty());
    assert!(!cfg.agent_docker_trust_any_source);

    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] forged");

    let before = agent_docker_gate_blocked_count();
    let out = enrich_entry(entry("plex", &msg, "10.0.0.1:1234", "info"), &cfg);
    assert_eq!(out.message, msg, "marker must stay in the message");
    assert!(
        out.metadata_json.is_none(),
        "no identity may be extracted through an unconfigured gate"
    );
    assert_eq!(
        agent_docker_gate_blocked_count(),
        before + 1,
        "rejection must be counted so operators can see the gate is closed"
    );
}

#[test]
fn agent_docker_trust_any_source_opt_in_restores_extraction() {
    // The explicit escape hatch for deployments where every sender that can
    // reach the syslog port is trusted. It must be opt-in and separate from
    // the allowlist being empty.
    let cfg = EnrichmentConfig {
        agent_docker_trust_any_source: true,
        ..EnrichmentConfig::default()
    };
    let meta = r#"{"agent_docker":{"host":"nashost","container_id":"abc","container_name":"plex","stream":"stdout"}}"#;
    let msg = format!("[cortex-agent-docker-meta:{meta}] hello");
    let out = enrich_entry(entry("plex", &msg, "203.0.113.9:1234", "info"), &cfg);
    assert_eq!(out.message, "hello");
    let metadata: serde_json::Value =
        serde_json::from_str(out.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["agent_docker"]["container_name"], "plex");
    assert_eq!(metadata["source_kind"], "agent-docker");
}
