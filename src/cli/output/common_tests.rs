use super::*;

#[test]
fn truncate_is_utf8_safe_and_preserves_short_strings() {
    assert_eq!(truncate("short", 10), "short");
    assert_eq!(truncate("éclair", 4), "écl…");
    assert_eq!(truncate("anything", 0), "");
}

#[test]
fn truncate_bytes_respects_byte_budget_on_char_boundaries() {
    // Short input untouched.
    assert_eq!(truncate_bytes("short", 10), "short");
    // Multibyte: each "é" is 2 bytes. The result (prefix + 3-byte ellipsis) must
    // never exceed the byte budget, and must cut on a char boundary.
    let s = "ééééééé"; // 7 × 2 = 14 bytes
    let out = truncate_bytes(s, 10);
    assert!(out.len() <= 10, "byte budget exceeded: {} bytes", out.len());
    assert!(out.ends_with('…'));
    assert!(out.is_char_boundary(out.len() - '…'.len_utf8()));
    // A char-based truncate(s, 10) would keep 9 chars = 18 bytes — far over budget.
    assert!(truncate_bytes(s, 14).len() <= 14);
}

#[test]
fn truncate_bytes_tiny_budget_returns_prefix_not_empty() {
    // Budgets smaller than the 3-byte ellipsis must still yield a byte-bounded
    // prefix, never an empty string (regression: budget was zeroed first).
    assert_eq!(truncate_bytes("hello", 2), "he");
    assert_eq!(truncate_bytes("hello", 1), "h");
    // Multibyte: a 1-byte budget can't fit a 2-byte 'é', so empty is correct;
    // a 2-byte budget yields exactly one 'é'.
    assert_eq!(truncate_bytes("ééé", 1), "");
    assert_eq!(truncate_bytes("ééé", 2), "é");
}

#[test]
fn transcript_detection_accepts_source_ip_and_app_suffix() {
    let mut log = cortex::app::LogEntry {
        id: 1,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        received_at: "2026-01-01T00:00:00Z".to_string(),
        hostname: "host".to_string(),
        source_ip: "transcript://session".to_string(),
        facility: Some("user".to_string()),
        severity: "info".to_string(),
        app_name: None,
        process_id: None,
        message: "hello".to_string(),
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: None,
    };
    assert!(is_transcript_log(&log));

    log.source_ip = "127.0.0.1".to_string();
    log.app_name = Some("codex-transcript".to_string());
    assert!(is_transcript_log(&log));
}

#[test]
fn terminal_safe_line_neutralizes_transcript_control_sequences() {
    assert_eq!(
        terminal_safe_line("project\u{1b}[2J\rspoof\nnext\tfield"),
        "project [2J spoof next field"
    );
}

#[test]
fn terminal_safe_multiline_preserves_layout_but_drops_terminal_controls() {
    assert_eq!(
        terminal_safe_multiline("first\n\u{1b}[31mred\r\tsecond"),
        "first\n[31mredsecond"
    );
}
