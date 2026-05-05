use super::*;

#[test]
fn tool_definitions_include_expected_public_tools() {
    let tools = tool_definitions();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["syslog"]);

    let action = &tools[0]["inputSchema"]["properties"]["action"];
    assert_eq!(action["type"], "string");
    let actions: Vec<&str> = action["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        vec![
            "search",
            "tail",
            "errors",
            "hosts",
            "correlate",
            "stats",
            "help"
        ]
    );
}
