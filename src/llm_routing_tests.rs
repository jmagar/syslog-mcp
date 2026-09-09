//! Exercise every production assessment path with both provider protocols.
use super::tests::EnvGuard;
use crate::app::CortexService;
use crate::app::{
    AbuseAssessRequest, AiAssessRequest, HookAssessRequest, McpAssessRequest, SkillAssessRequest,
};
use crate::config::StorageConfig;
use crate::db::{DbPool, LogBatchEntry, init_pool, insert_logs_batch};
use serial_test::serial;
use std::sync::Arc;

fn fixture() -> (CortexService, Arc<DbPool>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("routing.db"));
    let pool = Arc::new(init_pool(&storage).unwrap());
    insert_logs_batch(
        &pool,
        &[LogBatchEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            hostname: "routing-host".into(),
            facility: None,
            severity: "err".into(),
            app_name: Some("ai-transcript".into()),
            process_id: None,
            message: "this shit failed: wrong tool, permission denied".into(),
            raw: "this shit failed: wrong tool, permission denied".into(),
            source_ip: "127.0.0.1".into(),
            docker_checkpoint: None,
            ai_tool: Some("codex".into()),
            ai_project: Some("/routing".into()),
            ai_session_id: Some("routing-session".into()),
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
    pool.get()
        .unwrap()
        .execute_batch(
            "INSERT INTO ai_skill_events
            (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
             skill_name, event_kind, evidence_kind, created_at)
         SELECT id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
            'routing-skill', 'skill_invoked', 'transcript', timestamp FROM logs;
         INSERT INTO ai_mcp_events
            (call_log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
             call_id, tool_name, mcp_server, mcp_tool, event_kind, is_error, created_at)
         SELECT id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
            'routing-call', 'mcp__routing__search', 'routing', 'search', 'call', 1,
            timestamp FROM logs;
         INSERT INTO ai_hook_events
            (log_id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
             hook_event, hook_name, status, evidence_kind)
         SELECT id, ai_tool, ai_project, ai_session_id, hostname, timestamp,
            'PreToolUse', 'routing-hook', 'failed', 'runtime' FROM logs;",
        )
        .unwrap();
    (CortexService::new(Arc::clone(&pool), storage), pool, dir)
}

async fn assess_all(service: &CortexService, run_llm: bool) -> Vec<Option<String>> {
    let skill = service
        .run_skill_assessment_with_delta(
            SkillAssessRequest {
                skill: Some("routing-skill".into()),
                ..Default::default()
            },
            run_llm,
            |_| Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(skill.results.len(), 1);
    let mcp = service
        .run_mcp_assessment_with_delta(
            McpAssessRequest {
                mcp_server: Some("routing".into()),
                ..Default::default()
            },
            run_llm,
            |_| Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(mcp.results.len(), 1);
    let hooks = service
        .run_hook_assessment_with_delta(
            HookAssessRequest {
                hook_name: Some("routing-hook".into()),
                ..Default::default()
            },
            run_llm,
            |_| Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(hooks.results.len(), 1);
    let abuse = service
        .assess_top_abuse_incident_with_delta(AbuseAssessRequest::default(), run_llm, |_| Ok(()))
        .await
        .unwrap();
    vec![
        skill.results[0].assessment.clone(),
        mcp.results[0].assessment.clone(),
        hooks.results[0].assessment.clone(),
        (!abuse.assessed.assessment.is_empty()).then_some(abuse.assessed.assessment),
    ]
}

#[cfg(unix)]
fn fake_provider(dir: &std::path::Path, provider: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join(provider);
    let body = if provider == "codex" {
        // Match the app-server handshake and check the globally pinned model
        // reaches thread/start; subsequent output identifies the adapter used.
        r#"#!/bin/sh
read -r initialize
printf '%s\n' '{"id":1,"result":{}}'
read -r initialized
read -r thread
case "$thread" in *'"model":"routing-model"'*) ;; *) exit 7 ;; esac
printf '%s\n' '{"id":2,"result":{"thread":{"id":"routing-thread"}}}'
read -r turn
printf '%s\n' '{"method":"item/agentMessage/delta","params":{"delta":"codex-output"}}'
printf '%s\n' '{"method":"turn/completed","params":{"turn":{"status":"completed"}}}'
"#
    } else {
        r#"#!/bin/sh
case " $* " in *' --model routing-model '*) ;; *) exit 7 ;; esac
cat >/dev/null
printf '%s\n' '{"type":"message","role":"assistant","content":"gemini-output"}'
printf '%s\n' '{"type":"result","status":"success"}'
"#
    };
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn every_llm_operation_routes_to_the_selected_provider_and_audits_it() {
    for (provider, audit_provider) in [("codex", "codex-app-server"), ("gemini", "gemini-cli")] {
        let (service, pool, dir) = fixture();
        let script = fake_provider(dir.path(), provider);
        std::fs::write(dir.path().join("auth.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join(".gemini")).unwrap();
        std::fs::write(dir.path().join(".gemini/settings.json"), "{}").unwrap();
        let _selector = EnvGuard::set("CORTEX_LLM", Some(&format!("{provider}/routing-model")));
        let _codex_cmd = EnvGuard::set("CORTEX_CODEX_CMD", Some(script.to_str().unwrap()));
        let _gemini_cmd =
            EnvGuard::set("CORTEX_HEADLESS_GEMINI_CMD", Some(script.to_str().unwrap()));
        let _codex_home = EnvGuard::set("CORTEX_CODEX_HOME", Some(dir.path().to_str().unwrap()));
        let _gemini_home = EnvGuard::set(
            "CORTEX_HEADLESS_GEMINI_HOME",
            Some(dir.path().to_str().unwrap()),
        );

        let results = assess_all(&service, true).await;
        assert_eq!(results, vec![Some(format!("{provider}-output")); 4]);
        let conn = pool.get().unwrap();
        let mut statement = conn.prepare(
            "SELECT action, provider, model, program, status FROM llm_invocations ORDER BY action"
        ).unwrap();
        let rows: Vec<(String, String, String, String, String)> = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 4);
        for (row, action) in
            rows.iter()
                .zip(["ai_assess", "hook_assess", "mcp_assess", "skill_assess"])
        {
            assert_eq!(
                row,
                &(
                    action.into(),
                    audit_provider.into(),
                    "routing-model".into(),
                    script.to_str().unwrap().into(),
                    "success".into()
                )
            );
        }
        // Dry runs use the same selection but do not require a working executable.
        let _codex_cmd = EnvGuard::set("CORTEX_CODEX_CMD", Some("/absent/provider"));
        let _gemini_cmd = EnvGuard::set("CORTEX_HEADLESS_GEMINI_CMD", Some("/absent/provider"));
        let incident_id: String = conn
            .query_row(
                "SELECT incident_id FROM llm_invocations WHERE action='ai_assess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(statement);
        drop(conn);
        service
            .dry_run_assess(AiAssessRequest {
                incident_id,
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
        let (actual_provider, model): (String, String) = pool
            .get()
            .unwrap()
            .query_row(
                "SELECT provider, model FROM llm_invocations WHERE status='dry_run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(actual_provider, audit_provider);
        assert_eq!(model, "routing-model");
    }
}

#[tokio::test]
#[serial]
async fn deterministic_assessments_ignore_invalid_provider_without_invocations() {
    let _selector = EnvGuard::set("CORTEX_LLM", Some("invalid"));
    let (service, pool, _dir) = fixture();
    assert_eq!(assess_all(&service, false).await, vec![None; 4]);
    let count: i64 = pool
        .get()
        .unwrap()
        .query_row("SELECT count(*) FROM llm_invocations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
