use super::*;

#[test]
fn search_json_output_accepts_empty_response() {
    let response = cortex::app::SearchLogsResponse {
        logs: Vec::new(),
        count: 0,
    };

    print_search_response(&response, true).unwrap();
}

#[test]
fn session_title_display_escapes_terminal_controls_from_legacy_rows() {
    let displayed = safe_session_title(Some("safe\u{1b}[31m title\nspoofed"), 80);

    assert!(!displayed.chars().any(char::is_control));
    assert_eq!(displayed, "safe\\u{1b}[31m title\\nspoofed");
}

#[test]
fn session_fields_redact_credentials_before_terminal_output() {
    assert_eq!(
        safe_session_field("project token=do-not-print"),
        "project [REDACTED]"
    );
}

#[test]
fn human_log_summary_outputs_accept_representative_payloads() {
    print_search_response(
        &cortex::app::SearchLogsResponse {
            logs: vec![sample_log(1, "err", "nginx exploded")],
            count: 1,
        },
        false,
    )
    .unwrap();

    print_errors_response(
        &cortex::app::GetErrorsResponse {
            summary: vec![cortex::app::ErrorSummaryEntry {
                hostname: "host-a".to_string(),
                app_name: Some("nginx".to_string()),
                severity: "err".to_string(),
                count: 3,
            }],
        },
        false,
    )
    .unwrap();

    print_hosts_response(
        &cortex::app::ListHostsResponse {
            hosts: vec![cortex::app::HostEntry {
                hostname: "host-a".to_string(),
                first_seen: "2026-06-12T00:00:00Z".to_string(),
                last_seen: "2026-06-13T00:00:00Z".to_string(),
                log_count: 10,
            }],
        },
        false,
    )
    .unwrap();

    print_stats_response(
        &cortex::app::DbStats {
            total_logs: 10,
            total_hosts: 1,
            oldest_log: Some("2026-06-12T00:00:00Z".to_string()),
            newest_log: Some("2026-06-13T00:00:00Z".to_string()),
            logical_db_size_mb: "1.0".to_string(),
            physical_db_size_mb: "2.0".to_string(),
            free_disk_mb: Some("100.0".to_string()),
            max_db_size_mb: 1024,
            min_free_disk_mb: 0,
            write_blocked: false,
            phantom_fts_rows: Some(0),
            agent_docker_gate_blocked_count: 0,
        },
        false,
    )
    .unwrap();
}

#[test]
fn human_ai_inventory_outputs_accept_truncated_and_context_payloads() {
    print_sessions_response(
        &cortex::app::ListSessionsResponse {
            count: 1,
            sessions: vec![cortex::app::AiSessionEntry {
                session_key: "key".to_string(),
                project: "cortex".to_string(),
                tool: "codex".to_string(),
                session_id: "session-1".to_string(),
                transcript_path: Some("/tmp/session.jsonl".to_string()),
                hostname: "host-a".to_string(),
                first_seen: "2026-06-12T00:00:00Z".to_string(),
                last_seen: "2026-06-13T00:00:00Z".to_string(),
                event_count: 4,
                title: Some("Investigate storage latency".to_string()),
                title_provenance: Some("user".to_string()),
            }],
            rollup_as_of: Some("2026-06-13T00:00:00Z".to_string()),
        },
        false,
    )
    .unwrap();

    print_usage_blocks_response_with_options(
        &cortex::app::UsageBlocksResponse {
            total_blocks: 2,
            truncated: false,
            blocks: vec![cortex::app::UsageBlock {
                bucket_start: "2026-06-13T00:00:00Z".to_string(),
                bucket_end: "2026-06-13T05:00:00Z".to_string(),
                project: "cortex".to_string(),
                tool: "codex".to_string(),
                session_count: 1,
                event_count: 12,
            }],
        },
        false,
        UsageBlocksPrintOptions {
            detail: SessionsOutputDetail::Compact,
            limit: Some(1),
        },
    )
    .unwrap();

    print_project_context_response(
        &cortex::app::ProjectContextResponse {
            project: "cortex".to_string(),
            tools: vec!["codex".to_string()],
            sessions: vec!["session-1".to_string()],
            hostnames: vec!["host-a".to_string()],
            first_seen: Some("2026-06-12T00:00:00Z".to_string()),
            last_seen: Some("2026-06-13T00:00:00Z".to_string()),
            event_count: 1,
            recent_entries_truncated: true,
            recent_entries: vec![sample_log(2, "info", "context")],
        },
        false,
    )
    .unwrap();

    print_ai_tools_response(
        &cortex::app::ListAiToolsResponse {
            total_tools: 1,
            truncated: true,
            tools: vec![cortex::app::AiToolEntry {
                tool: "codex".to_string(),
                event_count: 10,
                session_count: 2,
                first_seen: "2026-06-12T00:00:00Z".to_string(),
                last_seen: "2026-06-13T00:00:00Z".to_string(),
            }],
        },
        false,
    )
    .unwrap();

    print_ai_projects_response(
        &cortex::app::ListAiProjectsResponse {
            total_projects: 1,
            truncated: true,
            projects: vec![cortex::app::AiProjectEntry {
                project: "cortex".to_string(),
                tools: vec!["codex".to_string()],
                event_count: 10,
                session_count: 2,
                first_seen: "2026-06-12T00:00:00Z".to_string(),
                last_seen: "2026-06-13T00:00:00Z".to_string(),
            }],
        },
        false,
    )
    .unwrap();
}

#[test]
fn human_correlate_and_ai_search_outputs_accept_contextual_payloads() {
    print_search_sessions_response(
        &cortex::app::SearchSessionsResponse {
            total_candidates: 5,
            candidate_rows: 2,
            candidate_cap: 100,
            candidate_window_truncated: true,
            truncated: true,
            sessions: vec![cortex::app::SearchedSessionEntry {
                session_key: "key".to_string(),
                project: "cortex".to_string(),
                tool: "codex".to_string(),
                session_id: "session-1".to_string(),
                hostname: "host-a".to_string(),
                first_seen: "2026-06-12T00:00:00Z".to_string(),
                last_seen: "2026-06-13T00:00:00Z".to_string(),
                event_count: 4,
                match_count: 2,
                best_snippet: Some("snippet".to_string()),
                title: Some("Investigate storage latency".to_string()),
                title_provenance: Some("user".to_string()),
            }],
            limit_clamped_to: Some(100),
        },
        false,
    )
    .unwrap();

    print_abuse_search_response(
        &cortex::app::AbuseSearchResponse {
            terms: vec!["panic".to_string()],
            candidate_rows: 1,
            candidate_cap: 100,
            candidate_window_truncated: true,
            truncated: true,
            matches: vec![cortex::app::AbuseMatch {
                term: "panic".to_string(),
                entry: sample_log(3, "err", "panic"),
                before: vec![sample_log(2, "info", "before")],
                after: vec![sample_log(4, "info", "after")],
            }],
            limit_clamped_to: None,
        },
        false,
    )
    .unwrap();

    print_correlate_response(
        &cortex::app::CorrelateEventsResponse {
            reference_time: "2026-06-13T00:00:00Z".to_string(),
            window_minutes: 5,
            window_from: "2026-06-12T23:55:00Z".to_string(),
            window_to: "2026-06-13T00:05:00Z".to_string(),
            severity_min: "warning".to_string(),
            total_events: 1,
            truncated: true,
            hosts_count: 1,
            hosts: vec![cortex::app::CorrelatedHost {
                hostname: "host-a".to_string(),
                event_count: 1,
                events: vec![sample_log(5, "warning", "related")],
            }],
            matched_session: None,
        },
        false,
    )
    .unwrap();
}

fn sample_log(id: i64, severity: &str, message: &str) -> cortex::app::LogEntry {
    cortex::app::LogEntry {
        id,
        timestamp: "2026-06-13T00:00:00Z".to_string(),
        hostname: "host-a".to_string(),
        facility: Some("daemon".to_string()),
        severity: severity.to_string(),
        app_name: Some("cortex".to_string()),
        process_id: Some("123".to_string()),
        message: message.to_string(),
        received_at: "2026-06-13T00:00:01Z".to_string(),
        source_ip: "127.0.0.1:1514".to_string(),
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: None,
    }
}
