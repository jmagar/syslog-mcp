use super::*;

#[test]
fn log_batch_entry_keeps_claimed_hostname_separate_from_source_ip() {
    let entry = LogBatchEntry {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        hostname: "claimed-host".to_string(),
        facility: Some("local0".to_string()),
        severity: "info".to_string(),
        app_name: Some("app".to_string()),
        process_id: Some("123".to_string()),
        message: "message".to_string(),
        raw: "raw".to_string(),
        source_ip: "192.0.2.10:514".to_string(),
        docker_checkpoint: None,
    };

    assert_eq!(entry.hostname, "claimed-host");
    assert_eq!(entry.source_ip, "192.0.2.10:514");
}
