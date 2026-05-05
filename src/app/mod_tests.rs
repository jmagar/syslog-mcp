use super::*;

#[test]
fn module_reexports_request_types_and_helpers() {
    let search = SearchLogsRequest {
        query: Some("error".into()),
        ..Default::default()
    };
    let tail = TailLogsRequest {
        n: Some(25),
        ..Default::default()
    };

    assert_eq!(search.query.as_deref(), Some("error"));
    assert_eq!(tail.n, Some(25));
    assert_eq!(
        parse_optional_timestamp(Some("2026-01-01T01:00:00+01:00"), "from")
            .unwrap()
            .as_deref(),
        Some("2026-01-01T00:00:00+00:00")
    );
    assert_eq!(
        severity_at_or_above("err").unwrap(),
        vec!["emerg", "alert", "crit", "err"]
    );
}
