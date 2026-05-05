use crate::app::LogEntry;

use super::*;

fn log(hostname: &str, message: &str) -> LogEntry {
    LogEntry {
        id: 1,
        timestamp: "2026-01-01T00:00:00Z".into(),
        hostname: hostname.into(),
        facility: None,
        severity: "err".into(),
        app_name: None,
        process_id: None,
        message: message.into(),
        received_at: "2026-01-01T00:00:00Z".into(),
        source_ip: "192.0.2.10:514".into(),
    }
}

#[test]
fn severity_threshold_expands_to_more_severe_levels() {
    assert_eq!(
        severity_at_or_above("warning").unwrap(),
        vec!["emerg", "alert", "crit", "err", "warning"]
    );
    assert_eq!(severity_at_or_above("debug").unwrap().len(), 8);
}

#[test]
fn severity_threshold_rejects_unknown_levels() {
    let err = severity_at_or_above("fatal").expect_err("invalid severity should fail");
    assert!(err.to_string().contains("Invalid severity_min 'fatal'"));
}

#[test]
fn group_by_host_sorts_hosts_and_preserves_events() {
    let grouped = group_by_host(vec![
        log("host-b", "second"),
        log("host-a", "first"),
        log("host-b", "third"),
    ]);

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[0].hostname, "host-a");
    assert_eq!(grouped[0].event_count, 1);
    assert_eq!(grouped[0].events[0].message, "first");
    assert_eq!(grouped[1].hostname, "host-b");
    assert_eq!(grouped[1].event_count, 2);
}
