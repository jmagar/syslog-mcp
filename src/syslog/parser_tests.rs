use super::*;
#[test]
fn test_looks_like_timestamp_true() {
    assert!(looks_like_timestamp("2026-03-29T02:52:21.587Z"));
    assert!(looks_like_timestamp("2026-03-29T02:52:21+00:00"));
    assert!(looks_like_timestamp("2024-01-01T00:00:00Z"));
}

#[test]
fn test_looks_like_timestamp_false() {
    assert!(!looks_like_timestamp("The Mothership"));
    assert!(!looks_like_timestamp("dookie"));
    assert!(!looks_like_timestamp("unknown"));
    assert!(!looks_like_timestamp(""));
    assert!(!looks_like_timestamp("192.168.1.1"));
}

#[test]
fn test_parse_syslog_unifi_cef_hostname() {
    // Real-world UniFi OS RFC 5424 message: timestamp in hostname field, device name split
    // across app_name ("The") and message body ("Mothership CEF:0|...")
    let raw = "<14>1 2026-03-29T02:52:21+00:00 2026-03-29T02:52:21.587Z The - - - Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.hostname, "The Mothership");
    assert_eq!(parsed.app_name.as_deref(), Some("Test Syslog"));
    assert_eq!(parsed.message, "Test Syslog");
}

#[test]
fn test_parse_syslog_normal_unaffected() {
    // Standard RFC 3164 message must still parse correctly
    let raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.hostname, "mymachine");
    assert_eq!(parsed.app_name.as_deref(), Some("su"));
    assert!(parsed.message.contains("su root"));
}

#[test]
fn test_cef_ext_value_simple() {
    let ext = "UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20";
    assert_eq!(
        cef_ext_value(ext, "UNIFIdeviceModel"),
        Some("UCGMAX".to_string())
    );
    assert_eq!(
        cef_ext_value(ext, "UNIFIdeviceIp"),
        Some("76.213.118.20".to_string())
    );
}

#[test]
fn test_cef_ext_value_with_spaces_in_value() {
    let ext = "UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX";
    assert_eq!(
        cef_ext_value(ext, "UNIFIdeviceName"),
        Some("The Mothership".to_string())
    );
}

#[test]
fn test_cef_ext_value_last_field() {
    let ext = "UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
    assert_eq!(cef_ext_value(ext, "msg"), Some("Test Syslog".to_string()));
}

#[test]
fn test_cef_ext_value_missing_key() {
    let ext = "UNIFIdeviceModel=UCGMAX";
    assert_eq!(cef_ext_value(ext, "nonexistent"), None);
}

#[test]
fn test_extract_cef_fields_test_syslog() {
    let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
    let cef = extract_cef_fields(text);
    assert_eq!(cef.hostname, Some("The Mothership".to_string()));
    assert_eq!(cef.app_name, Some("Test Syslog".to_string()));
    assert_eq!(cef.message, Some("Test Syslog".to_string()));
}

#[test]
fn test_extract_cef_fields_config_change() {
    let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1005|Admin Made Config Changes|2|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
    let cef = extract_cef_fields(text);
    assert_eq!(cef.hostname, Some("The Mothership".to_string()));
    assert_eq!(cef.app_name, Some("Admin Made Config Changes".to_string()));
    assert!(cef
        .message
        .unwrap()
        .starts_with("Jacob Magar changed Syslog Settings"));
}

#[test]
fn test_extract_cef_fields_no_cef() {
    let cef = extract_cef_fields("normal syslog message");
    assert_eq!(cef.hostname, None);
    assert_eq!(cef.app_name, None);
    assert_eq!(cef.message, None);
}

#[test]
fn test_extract_cef_fields_fallback_hostname() {
    // When UNIFIdeviceName is absent, fall back to CEF Device Product (field 2)
    let text = "CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test|1|msg=hello";
    let cef = extract_cef_fields(text);
    assert_eq!(cef.hostname, Some("UniFi OS".to_string()));
    assert_eq!(cef.app_name, Some("Test".to_string()));
}

#[test]
fn test_cef_ext_value_long_msg() {
    let ext = "UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
    assert_eq!(
        cef_ext_value(ext, "msg"),
        Some("Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20".to_string())
    );
}

#[test]
fn test_cef_ext_value_no_substring_match() {
    // "name" must not match inside "UNIFIdeviceName"
    let ext = "UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX";
    assert_eq!(cef_ext_value(ext, "name"), None);
}

#[test]
fn test_cef_ext_value_empty_value() {
    // Empty value after key= returns None
    let ext = "key= nextkey=val";
    assert_eq!(cef_ext_value(ext, "key"), None);
}

#[test]
fn test_extract_cef_fields_malformed() {
    // Fewer than 8 pipe-delimited fields returns all None fields
    let text = "CEF:0|Ubiquiti|UniFi OS|5.1.5";
    let cef = extract_cef_fields(text);
    assert_eq!(cef.hostname, None);
    assert_eq!(cef.app_name, None);
    assert_eq!(cef.message, None);
}

#[test]
fn test_parse_syslog_large_message_truncation() {
    // Verify parse_syslog handles a large input without panicking
    let big = "x".repeat(100_000);
    let raw = format!("<14>1 2026-01-01T00:00:00Z host app - - - {big}");
    let parsed = parse_syslog(&raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.hostname, "host");
    // message will be the big string — just verify no panic
    assert!(!parsed.message.is_empty());
}

#[test]
fn test_parse_syslog_cef_all_none_no_panic() {
    // CEF heuristic fires (timestamp hostname + "CEF:" in body) but body is malformed
    // (< 8 pipe fields). Should not panic and should fall back to raw fields.
    let raw =
        "<14>1 2026-01-01T00:00:00Z 2026-01-01T00:00:00Z App - - - body with CEF: but no pipes";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // Should fall back gracefully — no panic
    assert!(!parsed.hostname.is_empty());
}

// ------------------------------------------------------------------ //
// parse_syslog() — new comprehensive tests (bead syslog-mcp-8g4)     //
// ------------------------------------------------------------------ //

/// RFC 3164: severity and facility are derived from the PRI value.
/// PRI=34 → facility=4 (auth), severity=2 (crit).
#[test]
fn test_parse_syslog_rfc3164_severity_facility() {
    let raw = "<34>Oct 11 22:14:15 mymachine su: test message";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // PRI 34 = (4 << 3) | 2 → facility=auth (index 4), severity=crit (index 2)
    assert_eq!(parsed.severity, "crit");
    assert_eq!(parsed.facility.as_deref(), Some("auth"));
    assert_eq!(parsed.hostname, "mymachine");
    assert_eq!(parsed.app_name.as_deref(), Some("su"));
    assert!(parsed.message.contains("test message"));
}

/// RFC 5424: structured-data and numeric process ID must parse correctly.
/// PRI=165 → facility=20 (local4), severity=5 (notice).
#[test]
fn test_parse_syslog_rfc5424_with_structured_data() {
    let raw = "<165>1 2003-10-11T22:14:15.003Z mymachine su 77 - - test message body";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // PRI 165 = (20 << 3) | 5 → facility=local4 (index 20), severity=notice (index 5)
    assert_eq!(parsed.severity, "notice");
    assert_eq!(parsed.facility.as_deref(), Some("local4"));
    assert_eq!(parsed.hostname, "mymachine");
    assert_eq!(parsed.app_name.as_deref(), Some("su"));
    assert_eq!(parsed.process_id.as_deref(), Some("77"));
    assert!(parsed.message.contains("test message body"));
}

/// Missing PRI (no <N> prefix) must default to severity "info" (numeric 6).
#[test]
fn test_parse_syslog_missing_pri_defaults_to_info() {
    let raw = "Oct 11 22:14:15 myhost myapp: something happened";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.severity, "info");
}

/// Missing hostname in the message must fall back to "unknown", not an empty string.
#[test]
fn test_parse_syslog_missing_hostname_falls_back_to_unknown() {
    // syslog_loose may not populate hostname for very bare messages.
    // We feed a minimal bare message without a recognisable hostname field.
    let raw = "just a plain log line with no syslog structure at all";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // When syslog_loose returns no hostname the code inserts "unknown"
    assert_eq!(
        parsed.hostname, "unknown",
        "bare string with no hostname should fall back to 'unknown'"
    );
}

/// Empty string input must not panic and must return a valid db::LogBatchEntry.
#[test]
fn test_parse_syslog_empty_string_no_panic() {
    let parsed = parse_syslog("", "192.168.1.1:514".to_string());
    // timestamp must be non-empty RFC 3339
    assert!(!parsed.timestamp.is_empty());
    // severity must default to info
    assert_eq!(parsed.severity, "info");
    // hostname must not be empty
    assert!(!parsed.hostname.is_empty());
}

/// Malformed priority `<999>` is out of the 0-191 valid PRI range.
/// parse_syslog must not panic and must still return a usable db::LogBatchEntry.
#[test]
fn test_parse_syslog_malformed_priority_no_panic() {
    let raw = "<999>Oct 11 22:14:15 myhost myapp: overflow priority";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // Must not panic; severity must be a known string (syslog_loose may or
    // may not extract a value, but SEVERITY_LEVELS.get() falls back to "info").
    assert!(!parsed.severity.is_empty());
    assert!(!parsed.hostname.is_empty());
}

/// Timestamp must always be a valid RFC 3339 string (ends with Z or +HH:MM).
/// Covers both messages with a timestamp and those without (fallback to Utc::now).
#[test]
fn test_parse_syslog_timestamp_is_rfc3339() {
    // Message with a well-formed ISO timestamp
    let raw_with_ts = "<14>1 2024-06-15T12:34:56.789Z myhost myapp 42 - - hello";
    let p1 = parse_syslog(raw_with_ts, "192.168.1.1:514".to_string());
    // RFC 3339 ends with Z or +offset
    assert!(
        p1.timestamp.ends_with('Z') || p1.timestamp.contains('+'),
        "timestamp not RFC 3339: {}",
        p1.timestamp
    );
    // Must parse as a valid datetime
    assert!(chrono::DateTime::parse_from_rfc3339(&p1.timestamp).is_ok());

    // Message with no timestamp (syslog_loose fallback → Utc::now())
    let raw_no_ts = "just a plain line";
    let p2 = parse_syslog(raw_no_ts, "192.168.1.1:514".to_string());
    assert!(
        p2.timestamp.ends_with('Z') || p2.timestamp.contains('+'),
        "fallback timestamp not RFC 3339: {}",
        p2.timestamp
    );
    assert!(chrono::DateTime::parse_from_rfc3339(&p2.timestamp).is_ok());
}

/// RFC 3164 message with severity=emerg (PRI=0 → facility=kern, severity=emerg).
#[test]
fn test_parse_syslog_rfc3164_severity_emerg() {
    let raw = "<0>Oct 11 22:14:15 myhost kernel: system halt";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.severity, "emerg");
    assert_eq!(parsed.facility.as_deref(), Some("kern"));
}

/// RFC 3164 message with severity=debug (PRI=7 → facility=kern, severity=debug).
#[test]
fn test_parse_syslog_rfc3164_severity_debug() {
    let raw = "<7>Oct 11 22:14:15 myhost kernel: verbose output";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.severity, "debug");
}

/// CEF message: looks_like_timestamp in hostname field + "CEF:" in body triggers CEF branch.
/// Verify the CEF branch fires and produces populated fields.
#[test]
fn test_parse_syslog_cef_branch_fires() {
    let raw = concat!(
        "<166>1 2024-10-11T10:00:00Z 2024-10-11T10:00:00Z ",
        "The - - - Mothership ",
        "CEF:0|Ubiquiti|UniFi OS|5.0|E|SomeEvent|5|",
        "UNIFIdeviceName=MyDevice msg=event occurred"
    );
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    // CEF branch should extract device name from UNIFIdeviceName
    assert_eq!(parsed.hostname, "MyDevice");
    assert_eq!(parsed.app_name.as_deref(), Some("SomeEvent"));
    assert_eq!(parsed.message, "event occurred");
}

/// raw field must always equal the original input string verbatim.
#[test]
fn test_parse_syslog_raw_field_preserved() {
    let raw = "<34>Oct 11 22:14:15 mymachine su: verbatim check";
    let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
    assert_eq!(parsed.raw, raw);
}

#[test]
fn unifi_device_name_is_hostname_but_source_ip_remains_network_sender() {
    let raw = "<14>1 2026-03-29T02:52:21+00:00 2026-03-29T02:52:21.587Z The - - - Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIdeviceName=trusted-router msg=hello";
    let parsed = parse_syslog(raw, "198.51.100.44:5514".to_string());

    assert_eq!(parsed.hostname, "trusted-router");
    assert_eq!(parsed.source_ip, "198.51.100.44:5514");
}
