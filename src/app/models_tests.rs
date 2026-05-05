use crate::db;

use super::*;

#[test]
fn log_entry_conversion_preserves_network_sender_identity() {
    let entry = LogEntry::from(db::LogEntry {
        id: 42,
        timestamp: "2026-01-01T00:00:00Z".into(),
        hostname: "claimed-host".into(),
        facility: Some("local0".into()),
        severity: "warning".into(),
        app_name: Some("rsyslogd".into()),
        process_id: Some("123".into()),
        message: "message".into(),
        received_at: "2026-01-01T00:00:01Z".into(),
        source_ip: "192.0.2.10:514".into(),
    });

    assert_eq!(entry.hostname, "claimed-host");
    assert_eq!(entry.source_ip, "192.0.2.10:514");
    assert_eq!(entry.app_name.as_deref(), Some("rsyslogd"));
}

#[test]
fn summary_and_host_conversions_preserve_counts() {
    let summary = ErrorSummaryEntry::from(db::ErrorSummaryEntry {
        hostname: "host-a".into(),
        severity: "err".into(),
        count: 7,
    });
    let host = HostEntry::from(db::HostEntry {
        hostname: "host-a".into(),
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T01:00:00Z".into(),
        log_count: 11,
    });

    assert_eq!(summary.count, 7);
    assert_eq!(host.log_count, 11);
}

#[test]
fn db_stats_conversion_preserves_guardrail_fields() {
    let stats = DbStats::from(db::DbStats {
        total_logs: 10,
        total_hosts: 2,
        oldest_log: Some("2026-01-01T00:00:00Z".into()),
        newest_log: Some("2026-01-02T00:00:00Z".into()),
        logical_db_size_mb: "1.25".into(),
        physical_db_size_mb: "2.50".into(),
        free_disk_mb: Some("512.00".into()),
        max_db_size_mb: 1024,
        min_free_disk_mb: 512,
        write_blocked: true,
        phantom_fts_rows: 3,
    });

    assert_eq!(stats.total_logs, 10);
    assert_eq!(stats.free_disk_mb.as_deref(), Some("512.00"));
    assert!(stats.write_blocked);
    assert_eq!(stats.phantom_fts_rows, 3);
}
