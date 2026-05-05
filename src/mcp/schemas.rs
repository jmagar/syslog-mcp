use serde_json::{json, Value};

/// Define the public MCP tool surface.
pub(super) fn tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": "syslog",
        "description": "Query syslog-mcp logs with action-based subcommands: syslog search, syslog tail, syslog errors, syslog hosts, syslog correlate, syslog stats, and syslog help.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "tail", "errors", "hosts", "correlate", "stats", "help"],
                    "description": "Action to run: search, tail, errors, hosts, correlate, stats, or help."
                },
                "query": {
                    "type": "string",
                    "description": "For action=search or action=correlate: FTS5 query. Examples: 'kernel panic', 'OOM AND killer', '\"connection refused\"', 'error*'."
                },
                "hostname": {
                    "type": "string",
                    "description": "For action=search, tail, or correlate: exact hostname filter. Use action=hosts to enumerate."
                },
                "source_ip": {
                    "type": "string",
                    "description": "For action=search, tail, or correlate: exact source identifier. Syslog uses IP:port; Docker ingest uses docker://host/container/stream."
                },
                "severity": {
                    "type": "string",
                    "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                    "description": "For action=search: syslog severity filter."
                },
                "severity_min": {
                    "type": "string",
                    "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                    "description": "For action=correlate: minimum severity to include. Defaults to warning."
                },
                "app_name": {
                    "type": "string",
                    "description": "For action=search or action=tail: application name filter, e.g. sshd, dockerd, kernel."
                },
                "from": {
                    "type": "string",
                    "description": "For action=search or action=errors: start of time range as ISO 8601/RFC3339."
                },
                "to": {
                    "type": "string",
                    "description": "For action=search or action=errors: end of time range as ISO 8601/RFC3339."
                },
                "limit": {
                    "type": "integer",
                    "description": "For action=search: max results, default 100, max 1000. For action=correlate: max total events, default 500, max 999."
                },
                "n": {
                    "type": "integer",
                    "description": "For action=tail: number of recent entries, default 50, max 500."
                },
                "reference_time": {
                    "type": "string",
                    "description": "For action=correlate: required center timestamp for the correlation window as ISO 8601/RFC3339."
                },
                "window_minutes": {
                    "type": "integer",
                    "description": "For action=correlate: minutes before and after reference_time to search, default 5, max 60."
                }
            },
            "required": ["action"]
        }
    })]
}

#[cfg(test)]
#[path = "schemas_tests.rs"]
mod tests;
