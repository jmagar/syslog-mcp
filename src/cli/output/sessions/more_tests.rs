use super::*;

fn log_entry(id: i64, message: &str) -> LogEntry {
    LogEntry {
        id,
        timestamp: "2026-06-13T12:00:00Z".to_string(),
        hostname: "devhost".to_string(),
        facility: Some("local0".to_string()),
        severity: "err".to_string(),
        app_name: Some("cortex".to_string()),
        process_id: Some("123".to_string()),
        message: message.to_string(),
        received_at: "2026-06-13T12:00:01Z".to_string(),
        source_ip: "127.0.0.1".to_string(),
        ai_tool: Some("codex".to_string()),
        ai_project: Some("/home/jmagar/workspace/cortex".to_string()),
        ai_session_id: Some("sess-1".to_string()),
        ai_transcript_path: None,
        metadata_json: None,
    }
}

fn abuse_incident() -> cortex::app::AbuseIncident {
    cortex::app::AbuseIncident {
        incident_id: "incident-1".to_string(),
        project: "/home/jmagar/workspace/cortex".to_string(),
        tool: "codex".to_string(),
        session_id: "sess-1".to_string(),
        hostname: "devhost".to_string(),
        first_seen: "2026-06-13T12:00:00Z".to_string(),
        last_seen: "2026-06-13T12:01:00Z".to_string(),
        duration_secs: 60,
        abuse_count: 1,
        terms: vec!["panic".to_string()],
        anchor_ids: vec![1],
        priority_score: 42.0,
        priority_label: "high".to_string(),
        window_minutes: 15,
    }
}

fn investigate_response() -> AiInvestigateResponse {
    AiInvestigateResponse {
        total_incidents: 2,
        truncated: true,
        evidence: vec![cortex::app::IncidentEvidence {
            incident: abuse_incident(),
            transcript_before: vec![log_entry(10, "before transcript window")],
            transcript_before_truncated: true,
            transcript_after: vec![log_entry(11, "after transcript window")],
            transcript_after_truncated: false,
            anchors: vec![log_entry(1, "anchor message with plenty of bytes")],
            nearby_logs: vec![log_entry(2, "nearby non-error log")],
            nearby_logs_truncated: true,
            nearby_errors: vec![log_entry(3, "nearby error message")],
            findings: cortex::app::IncidentFindings::default(),
        }],
    }
}

#[test]
fn similar_incidents_json_output_accepts_empty_response() {
    let response = cortex::app::SimilarIncidentsResponse {
        query: "disk".to_string(),
        clusters: Vec::new(),
        total_clusters: 0,
        truncated: false,
    };

    print_similar_incidents_response(&response, true).unwrap();
}

#[test]
fn compact_ai_investigate_json_omits_transcript_by_default_and_preserves_counts() {
    let value = compact_ai_investigate_json(
        &investigate_response(),
        AiInvestigatePrintOptions {
            detail: SessionsOutputDetail::Compact,
            include_transcript: false,
            max_bytes: 12,
        },
    );

    let evidence = &value["evidence"][0];
    assert_eq!(value["total_incidents"], 2);
    assert_eq!(value["truncated"], true);
    assert_eq!(value["include_transcript"], false);
    assert_eq!(evidence["counts"]["anchors"], 1);
    assert_eq!(evidence["counts"]["transcript_before"], 1);
    assert_eq!(evidence["counts"]["nearby_logs"], 1);
    assert_eq!(evidence["truncated"]["transcript_before"], true);
    assert_eq!(evidence["truncated"]["nearby_logs"], true);
    assert!(evidence.get("transcript_before").is_none());
    assert!(evidence.get("transcript_after").is_none());
    let anchor_message = evidence["anchors"][0]["message"].as_str().unwrap();
    assert!(anchor_message.starts_with("anchor me"));
    assert_ne!(anchor_message, "anchor message with plenty of bytes");
}

#[test]
fn compact_ai_investigate_json_includes_transcript_when_requested() {
    let value = compact_ai_investigate_json(
        &investigate_response(),
        AiInvestigatePrintOptions {
            detail: SessionsOutputDetail::Compact,
            include_transcript: true,
            max_bytes: 64,
        },
    );

    let evidence = &value["evidence"][0];
    assert_eq!(value["include_transcript"], true);
    assert_eq!(
        evidence["transcript_before"][0]["message"],
        "before transcript window"
    );
    assert_eq!(
        evidence["transcript_after"][0]["message"],
        "after transcript window"
    );
    assert_eq!(
        evidence["nearby_errors"][0]["message"],
        "nearby error message"
    );
}

#[test]
fn human_ai_more_outputs_accept_representative_payloads() {
    print_similar_incidents_response(
        &cortex::app::SimilarIncidentsResponse {
            query: "panic".to_string(),
            total_clusters: 1,
            truncated: true,
            clusters: vec![cortex::app::IncidentCluster {
                hostname: "devhost".to_string(),
                app_name: Some("cortex".to_string()),
                window_start: "2026-06-13T12:00:00Z".to_string(),
                window_end: "2026-06-13T12:30:00Z".to_string(),
                log_count: 3,
                severity_peak: "err".to_string(),
                representative_messages: vec!["panic".to_string()],
                correlated_sessions: vec![cortex::app::CorrelatedSession {
                    session_id: "sess-1".to_string(),
                    project: "/home/jmagar/workspace/cortex".to_string(),
                    tool: "codex".to_string(),
                    match_count: 2,
                    best_snippet: Some("panic".to_string()),
                }],
            }],
        },
        false,
    )
    .unwrap();

    print_incident_context_response(
        &cortex::app::IncidentContextResponse {
            window_from: "2026-06-13T12:00:00Z".to_string(),
            window_to: "2026-06-13T12:30:00Z".to_string(),
            total_logs: 4,
            by_severity: vec![cortex::app::SeverityCount {
                severity: "err".to_string(),
                count: 2,
            }],
            by_app: vec![cortex::app::AppLogCount {
                app_name: Some("cortex".to_string()),
                count: 2,
            }],
            error_logs: vec![log_entry(21, "error")],
            error_logs_truncated: true,
            ai_sessions: vec![cortex::app::AiSessionEntry {
                session_key: "key".to_string(),
                project: "/home/jmagar/workspace/cortex".to_string(),
                tool: "codex".to_string(),
                session_id: "sess-1".to_string(),
                transcript_path: None,
                hostname: "devhost".to_string(),
                first_seen: "2026-06-13T12:00:00Z".to_string(),
                last_seen: "2026-06-13T12:01:00Z".to_string(),
                event_count: 4,
                title: Some("Investigate storage latency".to_string()),
                title_provenance: Some("user".to_string()),
            }],
        },
        false,
    )
    .unwrap();

    print_ai_incidents_response(
        &cortex::app::AiIncidentResponse {
            incidents: vec![abuse_incident()],
            total_incidents: 2,
            candidate_rows: 100,
            candidate_cap: 50,
            candidate_window_truncated: true,
            truncated: true,
        },
        false,
    )
    .unwrap();

    print_ai_investigate_response_with_options(
        &investigate_response(),
        false,
        AiInvestigatePrintOptions {
            detail: SessionsOutputDetail::Full,
            include_transcript: true,
            max_bytes: 80,
        },
    )
    .unwrap();
}
