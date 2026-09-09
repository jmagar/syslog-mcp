use super::{
    SourceProjectionOutcome, SourceProjectionSkipReason, project_agent_source,
    project_agent_source_with_cursor,
};
use crate::config::StorageConfig;
use crate::db::agent_observatory::{
    AgentEventKind, AgentHookSourceRow, AgentLlmSourceRow, AgentMcpSourceRow,
    AgentOtelSpanSourceRow, AgentSkillSourceRow, AgentSourceKind, AgentSourceRecord,
    RepositoryObservationInput, RepositoryObservationKind, RepositoryUpsert,
    RepositoryWorktreeUpsert, page_agent_sources, projection_cursor, reconcile_repository,
    record_repository_observations_if_changed,
};
use crate::db::otlp_traces::{OtelSpanInput, insert_otel_spans_batch};
use crate::db::{LogBatchEntry, init_pool, insert_logs_batch};

const PROJECT: &str = "/workspace/cortex/.worktrees/ao038";
const HEAD: &str = "0123456789012345678901234567890123456789";

fn log_entry() -> LogBatchEntry {
    LogBatchEntry {
        timestamp: "2026-08-05T12:00:00.000Z".to_string(),
        hostname: "devhost".to_string(),
        facility: None,
        severity: "info".to_string(),
        app_name: Some("fixture".to_string()),
        process_id: None,
        message: "skill fixture".to_string(),
        raw: "skill fixture".to_string(),
        source_ip: "test://ao038-projector".to_string(),
        docker_checkpoint: None,
        ai_tool: Some("claude".to_string()),
        ai_project: Some(PROJECT.to_string()),
        ai_session_id: Some("session-one".to_string()),
        ai_transcript_path: None,
        metadata_json: Some("{}".to_string()),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    }
}

fn setup() -> (crate::db::DbPool, tempfile::TempDir, i64) {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("projection.db"))).unwrap();
    reconcile_repository(
        &pool,
        &RepositoryUpsert {
            repository_key: "repo-key".to_string(),
            hostname: "devhost".to_string(),
            common_git_dir: "/workspace/cortex/.git".to_string(),
            primary_path: "/workspace/cortex".to_string(),
            display_name: "cortex".to_string(),
            remote_url_hash: None,
            metadata_json: "{}".to_string(),
        },
        &[RepositoryWorktreeUpsert {
            worktree_key: "worktree-key".to_string(),
            hostname: "devhost".to_string(),
            path: PROJECT.to_string(),
            git_dir: format!("{PROJECT}/.git"),
            branch_ref: Some("refs/heads/main".to_string()),
            branch_name: Some("main".to_string()),
            head_sha: Some(HEAD.to_string()),
            upstream_ref: None,
            detached: false,
            bare: false,
            locked: false,
            lock_reason: None,
            prunable: false,
            prune_reason: None,
            dirty: false,
            staged_count: 0,
            unstaged_count: 0,
            untracked_count: 0,
            ahead: None,
            behind: None,
            status_hash: Some("clean".to_string()),
        }],
        "2026-08-05T12:00:00.000Z",
    )
    .unwrap();
    insert_logs_batch(&pool, &[log_entry()]).unwrap();
    let log_id = pool
        .get()
        .unwrap()
        .query_row("SELECT MAX(id) FROM logs", [], |row| row.get(0))
        .unwrap();
    (pool, dir, log_id)
}

fn records(log_id: i64) -> Vec<AgentSourceRecord> {
    vec![
        AgentSourceRecord::Mcp(AgentMcpSourceRow {
            cursor_id: 11,
            call_log_id: None,
            result_log_id: None,
            ai_tool: "claude".to_string(),
            ai_project: Some(PROJECT.to_string()),
            ai_session_id: Some("session-one".to_string()),
            hostname: "devhost".to_string(),
            timestamp: "2026-08-05T12:01:00.000Z".to_string(),
            turn_id: Some("turn-one".to_string()),
            call_id: "call-one".to_string(),
            tool_name: "mcp__server__tool".to_string(),
            mcp_server: Some("server".to_string()),
            mcp_tool: Some("tool".to_string()),
            event_kind: "call".to_string(),
            status: Some("ok".to_string()),
            duration_ms: Some(25),
            is_error: Some(false),
            arguments_json: Some("{}".to_string()),
            output_preview: None,
            error_text: None,
            metadata_json: Some("{}".to_string()),
        }),
        AgentSourceRecord::Hook(AgentHookSourceRow {
            cursor_id: 12,
            log_id: None,
            ai_tool: "claude".to_string(),
            ai_project: Some(PROJECT.to_string()),
            ai_session_id: Some("session-one".to_string()),
            hostname: "devhost".to_string(),
            timestamp: "2026-08-05T12:02:00.000Z".to_string(),
            hook_event: "post_tool".to_string(),
            hook_name: Some("audit".to_string()),
            hook_source: Some("settings".to_string()),
            hook_command: Some("echo scrubbed".to_string()),
            status: "success".to_string(),
            exit_code: Some(0),
            duration_ms: Some(10),
            stdout_preview: None,
            stderr_preview: None,
            persisted_output_path: None,
            trusted_hash: Some("sha256:test".to_string()),
            evidence_kind: "runtime".to_string(),
            metadata_json: Some("{}".to_string()),
        }),
        AgentSourceRecord::Skill(AgentSkillSourceRow {
            cursor_id: 13,
            log_id,
            ai_tool: "claude".to_string(),
            ai_project: Some(PROJECT.to_string()),
            ai_session_id: Some("session-one".to_string()),
            hostname: "devhost".to_string(),
            timestamp: "2026-08-05T12:03:00.000Z".to_string(),
            skill_name: "pdfs".to_string(),
            skill_plugin: Some("core".to_string()),
            event_kind: "invoked".to_string(),
            evidence_kind: "tag".to_string(),
        }),
        AgentSourceRecord::Llm(AgentLlmSourceRow {
            id: "llm-one".to_string(),
            started_at: "2026-08-05T12:04:00.000Z".to_string(),
            finished_at: Some("2026-08-05T12:04:01.000Z".to_string()),
            duration_ms: Some(1000),
            caller_surface: "cli".to_string(),
            action: "summarize".to_string(),
            provider: "openai".to_string(),
            model: Some("gpt-test".to_string()),
            program: None,
            incident_id: None,
            ai_tool: Some("claude".to_string()),
            ai_project: Some(PROJECT.to_string()),
            ai_session_id: Some("session-one".to_string()),
            evidence_counts_json: Some("{}".to_string()),
            prompt_bytes: Some(20),
            output_bytes: Some(40),
            status: "success".to_string(),
            error: None,
            metadata_json: Some("{}".to_string()),
        }),
    ]
}

fn otlp_span_record() -> AgentSourceRecord {
    AgentSourceRecord::OtelSpan(AgentOtelSpanSourceRow {
        cursor_id: 91,
        trace_id: "1".repeat(32),
        span_id: "2".repeat(16),
        span_name: "project source".to_string(),
        span_kind: 1,
        start_time_unix_nano: 1_754_395_200_000_000_000,
        end_time_unix_nano: 1_754_395_201_000_000_000,
        status_code: 0,
        status_message: None,
        hostname: "devhost".to_string(),
        service_name: Some("cortex".to_string()),
        ai_tool: Some("claude".to_string()),
        ai_project: Some(PROJECT.to_string()),
        ai_session_id: Some("session-one".to_string()),
        attributes_json: "{\"bounded\":true}".to_string(),
        received_at: "2026-08-05T12:00:01.000Z".to_string(),
    })
}

fn repository_observation() -> RepositoryObservationInput {
    RepositoryObservationInput {
        worktree_key: Some("worktree-key".to_string()),
        observation_kind: RepositoryObservationKind::Head,
        new_head_sha: Some(HEAD.to_string()),
        summary: "worktree HEAD changed".to_string(),
        payload_json: r#"{"new_commit_shas":[]}"#.to_string(),
    }
}

#[test]
fn repository_observation_projects_only_to_an_existing_evidenced_run_without_extending_activity() {
    let (pool, _dir, log_id) = setup();
    let seed = records(log_id).remove(0);
    let SourceProjectionOutcome::Projected(seed) = project_agent_source(&pool, &seed).unwrap()
    else {
        panic!("MCP fixture should create the explicitly identified run");
    };
    let last_activity_before = seed.run.last_activity_at.clone();
    let observation = record_repository_observations_if_changed(
        &pool,
        "repo-key",
        &[repository_observation()],
        "2026-08-05T12:02:00.000Z",
    )
    .unwrap();
    assert_eq!(observation.len(), 1);
    assert_eq!(
        projection_cursor(&pool, "repository_observations").unwrap(),
        ""
    );
    let connection = pool.get().unwrap();
    let plan = connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT o.id FROM repository_observations o
             JOIN repositories r ON r.id = o.repository_id
        LEFT JOIN repository_worktrees w ON w.id = o.worktree_id
            WHERE o.id > ?1 ORDER BY o.id LIMIT ?2",
        )
        .unwrap()
        .query_map(rusqlite::params![0_i64, 2_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter().any(|detail| detail.contains("PRIMARY KEY")),
        "repository observation page must seek by its durable cursor: {plan:?}"
    );
    drop(connection);
    let page = page_agent_sources(&pool, AgentSourceKind::RepositoryObservation, "", 10).unwrap();
    assert_eq!(page.records.len(), 1);
    let SourceProjectionOutcome::Projected(projected) = project_agent_source_with_cursor(
        &pool,
        &page.records[0],
        "repository_observations",
        &page.next_cursor,
    )
    .unwrap() else {
        panic!("durably evidenced worktree observation should project");
    };
    assert_eq!(projected.run.id, seed.run.id);
    assert_eq!(projected.run.last_activity_at, last_activity_before);
    assert_eq!(
        projection_cursor(&pool, "repository_observations").unwrap(),
        page.next_cursor
    );
    let payload: serde_json::Value = serde_json::from_str(&projected.event.payload_json).unwrap();
    assert_eq!(payload["association"]["trust"], "correlated");
    assert_eq!(payload["source"]["observation"]["kind"], "head");
    assert_eq!(projected.event.source_id, observation[0].observation_key);
    assert!(projected.event_inserted);
    assert!(projected.outbox.is_some());

    let SourceProjectionOutcome::Projected(replay) =
        project_agent_source(&pool, &page.records[0]).unwrap()
    else {
        panic!("replay remains a safe no-op");
    };
    assert!(!replay.event_inserted);
    assert!(replay.outbox.is_none());
}

#[test]
fn repository_observation_without_existing_run_is_skipped_and_never_creates_a_synthetic_run() {
    let (pool, _dir, _log_id) = setup();
    let observation = record_repository_observations_if_changed(
        &pool,
        "repo-key",
        &[repository_observation()],
        "2026-08-05T12:02:00.000Z",
    )
    .unwrap();
    assert_eq!(
        projection_cursor(&pool, "repository_observations").unwrap(),
        ""
    );
    let page = page_agent_sources(&pool, AgentSourceKind::RepositoryObservation, "", 10).unwrap();
    let SourceProjectionOutcome::Skipped(diagnostic) = project_agent_source_with_cursor(
        &pool,
        &page.records[0],
        "repository_observations",
        &page.next_cursor,
    )
    .unwrap() else {
        panic!("unidentified Git state must not create a faux agent run");
    };
    assert_eq!(diagnostic.reason, SourceProjectionSkipReason::NoMatchingRun);
    assert_eq!(
        projection_cursor(&pool, "repository_observations").unwrap(),
        page.next_cursor
    );
    let connection = pool.get().unwrap();
    let runs: i64 = connection
        .query_row("SELECT COUNT(*) FROM agent_runs", [], |row| row.get(0))
        .unwrap();
    let events: i64 = connection
        .query_row("SELECT COUNT(*) FROM agent_run_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(runs, 0);
    assert_eq!(events, 0);
    assert_eq!(observation.len(), 1);
}

#[test]
fn failed_typed_source_uses_queryable_err_severity_and_increments_run_errors() {
    let (pool, _dir, log_id) = setup();
    let AgentSourceRecord::Mcp(mut failed) = records(log_id).remove(0) else {
        unreachable!("fixture index zero is the MCP source");
    };
    failed.call_id = "call-failed".to_string();
    failed.status = Some("error".to_string());
    failed.is_error = Some(true);
    failed.error_text = Some("receiver rejected request".to_string());

    let SourceProjectionOutcome::Projected(written) =
        project_agent_source(&pool, &AgentSourceRecord::Mcp(failed)).unwrap()
    else {
        panic!("failed MCP source should project");
    };
    assert_eq!(written.event.severity, "err");
    assert_eq!(written.run.error_count, 1);
}

#[test]
fn cursor_aware_llm_replay_consumes_legacy_projected_event_without_collision() {
    let (pool, _dir, log_id) = setup();
    let source_records = records(log_id);

    let SourceProjectionOutcome::Projected(_) =
        project_agent_source(&pool, &source_records[0]).unwrap()
    else {
        panic!("MCP fixture should seed the owning run");
    };

    let AgentSourceRecord::Llm(mut running) = source_records[3].clone() else {
        unreachable!("fixture index 3 is the LLM source");
    };
    running.finished_at = None;
    running.duration_ms = None;
    running.status = "running".to_string();
    running.output_bytes = None;
    let running_record = AgentSourceRecord::Llm(running);
    let SourceProjectionOutcome::Projected(first) =
        project_agent_source(&pool, &running_record).unwrap()
    else {
        panic!("legacy running LLM source should project");
    };
    assert!(first.event_inserted);

    assert_eq!(projection_cursor(&pool, "llm_invocations").unwrap(), "");
    let terminal_record = source_records[3].clone();
    let terminal_cursor = terminal_record.next_cursor();
    let outcome = project_agent_source_with_cursor(
        &pool,
        &terminal_record,
        "llm_invocations",
        &terminal_cursor,
    )
    .unwrap();
    assert_eq!(
        outcome,
        SourceProjectionOutcome::Skipped(super::SourceProjectionDiagnostic {
            source_kind: crate::db::agent_observatory::AgentSourceKind::Llm,
            source_id: "llm-one".to_string(),
            reason: SourceProjectionSkipReason::AlreadyProjected,
        })
    );
    assert_eq!(
        projection_cursor(&pool, "llm_invocations").unwrap(),
        terminal_cursor
    );

    let conn = pool.get().unwrap();
    let llm_events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_run_events
              WHERE source_kind = 'llm_invocations' AND source_id = 'llm-one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(llm_events, 1);
}

#[test]
fn cursor_aware_final_llm_replay_preserves_collision_detection() {
    let (pool, _dir, log_id) = setup();
    let source_records = records(log_id);

    let SourceProjectionOutcome::Projected(_) =
        project_agent_source(&pool, &source_records[0]).unwrap()
    else {
        panic!("MCP fixture should seed the owning run");
    };

    let terminal_record = source_records[3].clone();
    let SourceProjectionOutcome::Projected(first) =
        project_agent_source(&pool, &terminal_record).unwrap()
    else {
        panic!("terminal LLM source should project");
    };
    assert!(first.event_inserted);

    let AgentSourceRecord::Llm(mut changed) = terminal_record.clone() else {
        unreachable!("fixture index 3 is the LLM source");
    };
    changed.output_bytes = Some(41);
    let changed_record = AgentSourceRecord::Llm(changed);
    let changed_cursor = changed_record.next_cursor();
    let error = project_agent_source_with_cursor(
        &pool,
        &changed_record,
        "llm_invocations",
        &changed_cursor,
    )
    .unwrap_err();
    assert!(error.to_string().contains("event identity conflict"));
    assert_eq!(projection_cursor(&pool, "llm_invocations").unwrap(), "");

    let terminal_cursor = terminal_record.next_cursor();
    let SourceProjectionOutcome::Projected(replay) = project_agent_source_with_cursor(
        &pool,
        &terminal_record,
        "llm_invocations",
        &terminal_cursor,
    )
    .unwrap() else {
        panic!("exact final LLM replay should use the strict idempotent writer");
    };
    assert!(!replay.event_inserted);
    assert_eq!(
        projection_cursor(&pool, "llm_invocations").unwrap(),
        terminal_cursor
    );
}

#[test]
fn otlp_span_conflict_cannot_advance_its_durable_source_cursor() {
    let (pool, _dir, log_id) = setup();
    let SourceProjectionOutcome::Projected(_) =
        project_agent_source(&pool, &records(log_id)[0]).unwrap()
    else {
        panic!("MCP fixture should seed the owning run");
    };

    let span = otlp_span_record();
    let SourceProjectionOutcome::Projected(first) = project_agent_source(&pool, &span).unwrap()
    else {
        panic!("OTLP span should project");
    };
    assert!(first.event_inserted);
    assert_eq!(projection_cursor(&pool, "otel_spans").unwrap(), "");

    let AgentSourceRecord::OtelSpan(mut changed) = span.clone() else {
        unreachable!("OTLP fixture is a span");
    };
    changed.attributes_json = "{\"bounded\":false}".to_string();
    let changed = AgentSourceRecord::OtelSpan(changed);
    let error =
        project_agent_source_with_cursor(&pool, &changed, "otel_spans", &changed.next_cursor())
            .unwrap_err();
    assert!(error.to_string().contains("event identity conflict"));
    assert_eq!(projection_cursor(&pool, "otel_spans").unwrap(), "");

    let SourceProjectionOutcome::Projected(replay) =
        project_agent_source_with_cursor(&pool, &span, "otel_spans", &span.next_cursor()).unwrap()
    else {
        panic!("exact OTLP span replay should use the strict idempotent writer");
    };
    assert!(!replay.event_inserted);
    assert_eq!(projection_cursor(&pool, "otel_spans").unwrap(), "91");
}

#[test]
fn four_source_types_project_typed_events_and_replay_without_duplicates() {
    let (pool, _dir, log_id) = setup();
    let mut results = Vec::new();
    for record in records(log_id) {
        let SourceProjectionOutcome::Projected(result) =
            project_agent_source(&pool, &record).unwrap()
        else {
            panic!("source should project");
        };
        assert!(result.event_inserted);
        results.push(result);
    }
    assert_eq!(results[0].event.event_kind, AgentEventKind::Mcp);
    assert_eq!(results[1].event.event_kind, AgentEventKind::Hook);
    assert_eq!(results[2].event.event_kind, AgentEventKind::Skill);
    assert_eq!(results[3].event.event_kind, AgentEventKind::Llm);
    assert_eq!(
        results
            .iter()
            .map(|result| result.event.source_id.as_str())
            .collect::<Vec<_>>(),
        vec!["11", "12", "13", "llm-one"]
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.event.source_kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "mcp_events",
            "hook_events",
            "skill_events",
            "llm_invocations"
        ]
    );
    assert!(results.iter().all(|result| result.actor.is_some()));
    assert!(
        results
            .iter()
            .all(|result| result.run.provider_tool.as_deref() == Some("claude"))
    );
    assert_eq!(
        results
            .iter()
            .map(|result| {
                result
                    .actor
                    .as_ref()
                    .and_then(|actor| actor.display_name.as_deref())
            })
            .collect::<Vec<_>>(),
        vec![
            Some("server/tool"),
            Some("audit"),
            Some("core/pdfs"),
            Some("openai/gpt-test")
        ]
    );
    let run_id = results[0].run.id;
    assert!(results.iter().all(|result| result.run.id == run_id));

    for record in records(log_id) {
        let SourceProjectionOutcome::Projected(result) =
            project_agent_source(&pool, &record).unwrap()
        else {
            panic!("replay should project idempotently");
        };
        assert!(!result.event_inserted);
        assert!(result.outbox.is_none());
    }
    let conn = pool.get().unwrap();
    let counts: (i64, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM agent_run_events),
                (SELECT COUNT(*) FROM agent_run_actors),
                (SELECT COUNT(*) FROM agent_stream_outbox)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (4, 4, 4));
    let verified_project_evidence: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_run_worktrees
              WHERE run_id = ?1
                AND evidence_kind = 'transcript_project_path'
                AND trust_level = 'verified'
                AND confidence = 0.95
                AND is_primary = 1",
            [run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(verified_project_evidence, 3);
}

#[test]
fn unknown_source_event_is_typed_payload_is_capped_and_missing_session_skips() {
    let (pool, _dir, log_id) = setup();
    let mut record = records(log_id).remove(0);
    let AgentSourceRecord::Mcp(row) = &mut record else {
        unreachable!()
    };
    row.event_kind = "future-provider-shape".to_string();
    row.output_preview = Some("x".repeat(100_000));
    let SourceProjectionOutcome::Projected(result) = project_agent_source(&pool, &record).unwrap()
    else {
        panic!("unknown source event should use fallback");
    };
    assert_eq!(result.event.event_kind, AgentEventKind::Mcp);
    assert!(result.event.payload_json.len() <= 16 * 1024);
    assert!(result.event.payload_json.contains("future-provider-shape"));

    let AgentSourceRecord::Mcp(row) = &mut record else {
        unreachable!()
    };
    row.cursor_id = 15;
    row.ai_session_id = None;
    let SourceProjectionOutcome::Skipped(diagnostic) =
        project_agent_source(&pool, &record).unwrap()
    else {
        panic!("missing session should skip");
    };
    assert_eq!(
        diagnostic.reason,
        SourceProjectionSkipReason::MissingSession
    );
}

#[test]
fn exact_span_association_is_versioned_private_and_atomic_with_projection() {
    let (pool, _dir, log_id) = setup();
    let seed = records(log_id).remove(0);
    let SourceProjectionOutcome::Projected(run) = project_agent_source(&pool, &seed).unwrap()
    else {
        panic!("MCP fixture should seed an exact run");
    };
    let AgentSourceRecord::OtelSpan(mut span) = otlp_span_record() else {
        unreachable!()
    };
    span.attributes_json = serde_json::json!({
        "gen_ai.request.model": "gpt-test",
        "mcp.server.name": "cortex",
        "mcp.tool.name": "search",
        "gen_ai.input.messages": "do not persist this prompt",
        "future.vendor.attribute": "kept only on source evidence"
    })
    .to_string();
    let SourceProjectionOutcome::Projected(written) =
        project_agent_source(&pool, &AgentSourceRecord::OtelSpan(span)).unwrap()
    else {
        panic!("exact OTLP identity should project");
    };
    let relation = written.trace_relation.as_ref().expect("trace relation");
    assert_eq!(relation.run_id, Some(run.run.id));
    assert_eq!(relation.evidence_kind, "exact_provider_id");
    assert_eq!(relation.identifier_namespace, "otel.gen_ai.conversation.id");
    assert_eq!(relation.projection_version, 1);
    assert_eq!(relation.candidate_count, 1);
    assert!(relation.metadata_json.contains("gpt-test"));
    assert!(relation.metadata_json.contains("cortex"));
    assert!(!relation.metadata_json.contains("do not persist"));
    assert!(!relation.metadata_json.contains("future.vendor.attribute"));
    let count: i64 = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM agent_run_trace_relations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn no_match_cross_provider_and_late_span_resolution_never_claim_causality() {
    let (pool, _dir, log_id) = setup();
    let span = otlp_span_record();
    let AgentSourceRecord::OtelSpan(source_span) = &span else {
        unreachable!()
    };
    let persisted = OtelSpanInput {
        trace_id: source_span.trace_id.clone(),
        span_id: source_span.span_id.clone(),
        parent_span_id: None,
        trace_state: None,
        flags: 0,
        span_name: source_span.span_name.clone(),
        span_kind: source_span.span_kind,
        start_time_unix_nano: source_span.start_time_unix_nano,
        end_time_unix_nano: source_span.end_time_unix_nano,
        duration_nano: source_span.end_time_unix_nano - source_span.start_time_unix_nano,
        status_code: source_span.status_code,
        status_message: source_span.status_message.clone(),
        hostname: source_span.hostname.clone(),
        service_name: source_span.service_name.clone(),
        service_version: None,
        scope_name: None,
        scope_version: None,
        ai_tool: source_span.ai_tool.clone(),
        ai_project: source_span.ai_project.clone(),
        ai_session_id: source_span.ai_session_id.clone(),
        run_id: None,
        resource_json: "{}".to_string(),
        attributes_json: source_span.attributes_json.clone(),
        events_json: "[]".to_string(),
        links_json: "[]".to_string(),
        received_at: source_span.received_at.clone(),
        content_scrubbed: true,
    };
    insert_otel_spans_batch(&pool, &[persisted]).unwrap();
    let SourceProjectionOutcome::Skipped(no_match) = project_agent_source(&pool, &span).unwrap()
    else {
        panic!("span without a pre-existing provider run must not create one");
    };
    assert_eq!(no_match.reason, SourceProjectionSkipReason::NoMatchingRun);
    let no_match_row: (Option<i64>, String, f64) = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT run_id,evidence_kind,confidence FROM agent_run_trace_relations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    assert_eq!(no_match_row, (None, "no_match".to_string(), 1.0));

    // A Codex run with the same host/session is an explicit cross-provider
    // collision, not a relationship to upgrade by timestamp.
    let mut cross_provider = records(log_id).remove(0);
    let AgentSourceRecord::Mcp(row) = &mut cross_provider else {
        unreachable!()
    };
    row.cursor_id = 111;
    row.call_id = "cross-provider-call".to_string();
    row.ai_tool = "codex".to_string();
    let SourceProjectionOutcome::Projected(_) =
        project_agent_source(&pool, &cross_provider).unwrap()
    else {
        panic!("cross-provider fixture should seed Codex only");
    };
    let SourceProjectionOutcome::Skipped(ambiguous) = project_agent_source(&pool, &span).unwrap()
    else {
        panic!("cross-provider collision must not create a Claude run");
    };
    assert_eq!(
        ambiguous.reason,
        SourceProjectionSkipReason::AmbiguousMatchingRun
    );
    let ambiguous_row: (Option<i64>, String, i64) = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT run_id,evidence_kind,candidate_count FROM agent_run_trace_relations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    assert_eq!(ambiguous_row, (None, "ambiguous".to_string(), 1));

    // A later exact Claude transcript/source resolves only the prior no-match
    // evidence; it does not use the Codex collision as a causal fallback.
    let seed = records(log_id).remove(0);
    let SourceProjectionOutcome::Projected(claude) = project_agent_source(&pool, &seed).unwrap()
    else {
        panic!("Claude source should create the exact provider run");
    };
    let resolved: (Option<i64>, String, f64) = {
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT run_id,evidence_kind,confidence FROM agent_run_trace_relations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    assert_eq!(
        resolved,
        (Some(claude.run.id), "exact_provider_id".to_string(), 0.98)
    );
}

#[test]
fn trace_association_caps_high_cardinality_candidate_evidence() {
    let (pool, _dir, _log_id) = setup();
    let conn = pool.get().unwrap();
    for index in 0..12 {
        conn.execute(
            "INSERT INTO agent_runs
                (run_key,native_session_id,tool,hostname,status,status_observed_at,started_at,last_activity_at)
             VALUES (?1,'session-one',?2,'devhost','active',
                     '2026-08-05T12:00:00.000Z','2026-08-05T12:00:00.000Z','2026-08-05T12:00:00.000Z')",
            rusqlite::params![format!("candidate-{index}"), format!("provider-{index}")],
        )
        .unwrap();
    }
    drop(conn);
    let source = super::projection_parts(&otlp_span_record());
    assert_eq!(
        super::classify_telemetry_association(&pool, &source).unwrap(),
        super::SpanAssociation::Ambiguous(8)
    );
}
