use super::{AgentSourceKind, AgentSourceRecord, page_agent_sources};
use crate::config::StorageConfig;
use crate::db::{LogBatchEntry, init_pool, insert_logs_batch};
use rusqlite::params;

fn log_entry() -> LogBatchEntry {
    LogBatchEntry {
        timestamp: "2026-08-05T12:00:00.000Z".to_string(),
        hostname: "devhost".to_string(),
        facility: None,
        severity: "info".to_string(),
        app_name: Some("fixture".to_string()),
        process_id: None,
        message: "fixture".to_string(),
        raw: "fixture".to_string(),
        source_ip: "test://ao038".to_string(),
        docker_checkpoint: None,
        ai_tool: Some("claude".to_string()),
        ai_project: Some("/workspace/cortex".to_string()),
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

#[test]
fn pages_all_projection_sources_in_cursor_order_with_hard_limits() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("sources.db"))).unwrap();
    insert_logs_batch(&pool, &[log_entry()]).unwrap();
    let conn = pool.get().unwrap();
    let log_id: i64 = conn
        .query_row("SELECT MAX(id) FROM logs", [], |row| row.get(0))
        .unwrap();

    for suffix in ["one", "two"] {
        conn.execute(
            "INSERT INTO ai_mcp_events
                (ai_tool, ai_project, ai_session_id, hostname, timestamp, call_id,
                 tool_name, mcp_server, mcp_tool, event_kind, status, is_error,
                 arguments_json, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                "claude",
                "/workspace/cortex",
                "session-one",
                "devhost",
                "2026-08-05T12:00:00.000Z",
                format!("call-{suffix}"),
                "mcp__server__tool",
                "server",
                "tool",
                suffix,
                "ok",
                0,
                "{}",
                "{}",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ai_hook_events
                (ai_tool, ai_project, ai_session_id, hostname, timestamp,
                 hook_event, hook_name, status, evidence_kind, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                "claude",
                "/workspace/cortex",
                "session-one",
                "devhost",
                "2026-08-05T12:00:00.000Z",
                suffix,
                "fixture-hook",
                "success",
                "runtime",
                "{}",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ai_skill_events
                (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
                 skill_name, skill_plugin, event_kind, evidence_kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                log_id,
                "claude",
                "/workspace/cortex",
                "session-one",
                "devhost",
                "2026-08-05T12:00:00.000Z",
                format!("skill-{suffix}"),
                "fixture-plugin",
                suffix,
                "tag",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO llm_invocations
                (id, started_at, finished_at, duration_ms, caller_surface, action,
                 provider, model, ai_tool, ai_project, ai_session_id, status,
                 metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                format!("llm-{suffix}"),
                "2026-08-05T12:00:00.000Z",
                "2026-08-05T12:00:01.000Z",
                1000,
                "cli",
                suffix,
                "openai",
                "gpt-test",
                "claude",
                "/workspace/cortex",
                "session-one",
                "success",
                "{}",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO otel_spans
                (trace_id, span_id, span_name, span_kind, start_time_unix_nano,
                 end_time_unix_nano, duration_nano, hostname, ai_tool, ai_project,
                 ai_session_id, received_at)
             VALUES (?1, ?2, ?3, 1, 1, 2, 1, 'devhost', 'claude',
                     '/workspace/cortex', 'session-one', '2026-08-05T12:00:01.000Z')",
            params![
                format!("{suffix:0>32}"),
                format!("{suffix:0>16}"),
                format!("span-{suffix}"),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO otel_metric_points
                (point_key, metric_name, instrument_kind, time_unix_nano, hostname,
                 ai_tool, ai_project, ai_session_id, value_json, received_at)
             VALUES (?1, ?2, 'gauge', 1, 'devhost', 'claude', '/workspace/cortex',
                     'session-one', '{\"value\": 1}', '2026-08-05T12:00:01.000Z')",
            params![format!("metric-{suffix}"), format!("metric-{suffix}")],
        )
        .unwrap();
    }
    drop(conn);

    for kind in [
        AgentSourceKind::Mcp,
        AgentSourceKind::Hook,
        AgentSourceKind::Skill,
        AgentSourceKind::Llm,
        AgentSourceKind::OtelSpan,
        AgentSourceKind::OtelMetric,
    ] {
        let first = page_agent_sources(&pool, kind, "", 1).unwrap();
        assert_eq!(first.records.len(), 1);
        assert!(first.truncated);
        assert!(!first.next_cursor.is_empty());
        assert!(matches!(
            (&kind, &first.records[0]),
            (AgentSourceKind::Mcp, AgentSourceRecord::Mcp(_))
                | (AgentSourceKind::Hook, AgentSourceRecord::Hook(_))
                | (AgentSourceKind::Skill, AgentSourceRecord::Skill(_))
                | (AgentSourceKind::Llm, AgentSourceRecord::Llm(_))
                | (AgentSourceKind::OtelSpan, AgentSourceRecord::OtelSpan(_))
                | (
                    AgentSourceKind::OtelMetric,
                    AgentSourceRecord::OtelMetric(_)
                )
        ));
        if kind == AgentSourceKind::Llm {
            pool.get().unwrap().execute_batch("VACUUM").unwrap();
        }
        let second = page_agent_sources(&pool, kind, &first.next_cursor, 500).unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(!second.truncated);
        assert_ne!(second.next_cursor, first.next_cursor);
        let empty = page_agent_sources(&pool, kind, &second.next_cursor, 500).unwrap();
        assert!(empty.records.is_empty());
        assert_eq!(empty.next_cursor, second.next_cursor);
    }
}

#[test]
fn llm_cursor_tracks_terminal_time_and_cannot_skip_late_completion() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("llm-cursor.db"))).unwrap();
    let conn = pool.get().unwrap();

    conn.execute(
        "INSERT INTO llm_invocations
            (id, started_at, caller_surface, action, provider, status)
         VALUES (?1, ?2, 'cli', 'older', 'openai', 'running')",
        params!["llm-older", "2026-08-05T12:00:00.000Z"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO llm_invocations
            (id, started_at, finished_at, caller_surface, action, provider, status)
         VALUES (?1, ?2, ?3, 'cli', 'newer', 'openai', 'success')",
        params![
            "llm-newer",
            "2026-08-05T12:01:00.000Z",
            "2026-08-05T12:02:00.000Z"
        ],
    )
    .unwrap();
    let plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id FROM llm_invocations
              WHERE finished_at IS NOT NULL
                AND (finished_at, id) > (?1, ?2)
              ORDER BY finished_at, id LIMIT ?3",
        )
        .unwrap()
        .query_map(params!["2026-08-05T12:00:00.000Z", "", 500], |row| {
            row.get(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|detail| detail.contains("idx_llm_invocations_finished_id")),
        "terminal LLM cursor query must use migration 48 index: {plan:?}"
    );
    drop(conn);

    let first = page_agent_sources(&pool, AgentSourceKind::Llm, "", 500).unwrap();
    assert_eq!(first.records.len(), 1);
    assert!(matches!(
        &first.records[0],
        AgentSourceRecord::Llm(row) if row.id == "llm-newer"
    ));
    let first_cursor: serde_json::Value = serde_json::from_str(&first.next_cursor).unwrap();
    assert_eq!(first_cursor["ready_at"], "2026-08-05T12:02:00.000Z");

    let conn = pool.get().unwrap();
    conn.execute(
        "UPDATE llm_invocations
            SET finished_at = ?2, status = 'success'
          WHERE id = ?1",
        params!["llm-older", "2026-08-05T12:03:00.000Z"],
    )
    .unwrap();
    drop(conn);

    let second = page_agent_sources(&pool, AgentSourceKind::Llm, &first.next_cursor, 500).unwrap();
    assert_eq!(second.records.len(), 1);
    assert!(matches!(
        &second.records[0],
        AgentSourceRecord::Llm(row) if row.id == "llm-older"
    ));
    let second_cursor: serde_json::Value = serde_json::from_str(&second.next_cursor).unwrap();
    assert_eq!(second_cursor["ready_at"], "2026-08-05T12:03:00.000Z");

    let empty = page_agent_sources(&pool, AgentSourceKind::Llm, &second.next_cursor, 500).unwrap();
    assert!(empty.records.is_empty());
}

#[test]
fn old_llm_started_at_cursor_json_remains_readable() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(
        dir.path().join("llm-legacy-cursor.db"),
    ))
    .unwrap();
    let legacy = r#"{"started_at":"2026-08-05T12:00:00.000Z","id":"llm-old"}"#;
    let page = page_agent_sources(&pool, AgentSourceKind::Llm, legacy, 1).unwrap();
    assert!(page.records.is_empty());
}

#[test]
fn source_page_rejects_zero_and_over_limit_pages() {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("limits.db"))).unwrap();
    assert!(page_agent_sources(&pool, AgentSourceKind::Mcp, "", 0).is_err());
    assert!(page_agent_sources(&pool, AgentSourceKind::Mcp, "", 501).is_err());
    assert!(page_agent_sources(&pool, AgentSourceKind::Mcp, "-1", 1).is_err());
    assert!(page_agent_sources(&pool, AgentSourceKind::Llm, "not-json", 1).is_err());
}
