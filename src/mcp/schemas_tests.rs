use super::*;

#[test]
fn tool_definitions_include_expected_public_tools() {
    let tools = tool_definitions();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    for expected in [
        "search_logs",
        "tail_logs",
        "get_errors",
        "list_hosts",
        "correlate_events",
        "get_stats",
        "syslog_help",
    ] {
        assert!(names.contains(&expected), "missing tool: {expected}");
    }
}
