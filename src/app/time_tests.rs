use super::*;

#[test]
fn parse_optional_timestamp_normalizes_to_utc() {
    let parsed = parse_optional_timestamp(Some("2026-01-01T01:00:00+01:00"), "from")
        .unwrap()
        .unwrap();
    assert_eq!(parsed, "2026-01-01T00:00:00+00:00");
}

#[test]
fn parse_optional_timestamp_accepts_absent_value() {
    assert_eq!(parse_optional_timestamp(None, "from").unwrap(), None);
}

#[test]
fn parse_required_timestamp_reports_field_name_and_expected_format() {
    let err = parse_required_timestamp("not-a-date", "reference_time")
        .expect_err("invalid timestamp should fail");

    assert!(err.to_string().contains("Invalid reference_time"));
    assert!(err
        .to_string()
        .contains("Expected ISO 8601 / RFC3339 format"));
}
