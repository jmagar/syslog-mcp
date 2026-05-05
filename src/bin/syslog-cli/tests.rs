use super::Options;

#[test]
fn parser_accepts_space_and_equals_values() {
    let options = Options::parse(vec![
        "--query=error".into(),
        "--limit".into(),
        "5".into(),
        "--source-ip".into(),
        "10.0.0.1:514".into(),
    ])
    .unwrap();

    assert_eq!(options.get("query").as_deref(), Some("error"));
    assert_eq!(options.get_parse::<u32>("limit").unwrap(), Some(5));
    assert_eq!(options.get("source-ip").as_deref(), Some("10.0.0.1:514"));
}

#[test]
fn parser_prefers_later_duplicate_values() {
    let options = Options::parse(vec![
        "--limit".into(),
        "5".into(),
        "--limit".into(),
        "10".into(),
    ])
    .unwrap();

    assert_eq!(options.get_parse::<u32>("limit").unwrap(), Some(10));
}

#[test]
fn parser_rejects_missing_value_before_next_option() {
    let err = Options::parse(vec!["--query".into(), "--limit".into(), "5".into()])
        .expect_err("parser should reject missing option values");
    assert!(err.to_string().contains("missing value for --query"));
}

#[test]
fn parser_rejects_positional_arguments() {
    let err = Options::parse(vec!["unexpected".into()])
        .expect_err("parser should reject positional arguments");
    assert!(err.to_string().contains("unexpected positional argument"));
}

#[test]
fn parser_reports_invalid_typed_values() {
    let options = Options::parse(vec!["--limit".into(), "many".into()]).unwrap();
    let err = options
        .get_parse::<u32>("limit")
        .expect_err("invalid integer should fail");

    assert!(err.to_string().contains("invalid value for --limit=many"));
}

#[test]
fn parser_falls_back_to_alias_when_preferred_key_is_absent() {
    let options = Options::parse(vec!["--window_minutes".into(), "7".into()]).unwrap();

    assert_eq!(
        options
            .get_parse_alias::<u32>("window-minutes", "window_minutes")
            .unwrap(),
        Some(7)
    );
}
