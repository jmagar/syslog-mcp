use serde_json::{json, Value};

/// Define all MCP tools
pub(super) fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "search_logs",
            "description": "Full-text search across all syslog messages with optional filters. Uses SQLite FTS5 with porter stemming. Supports FTS5 query syntax: AND, OR, NOT, phrase matching with quotes, prefix matching with *.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Full-text search query (FTS5 syntax). Examples: 'kernel panic', 'OOM AND killer', '\"connection refused\"', 'error*'"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Filter by hostname (exact match). Use list_hosts to see available hostnames."
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Filter by syslog severity level"
                    },
                    "app_name": {
                        "type": "string",
                        "description": "Filter by application name (e.g., 'sshd', 'dockerd', 'kernel')"
                    },
                    "from": {
                        "type": "string",
                        "description": "Start of time range (ISO 8601, e.g., '2025-01-15T00:00:00Z')"
                    },
                    "to": {
                        "type": "string",
                        "description": "End of time range (ISO 8601)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 100, max 1000)"
                    }
                }
            }
        }),
        json!({
            "name": "tail_logs",
            "description": "Get the N most recent log entries, optionally filtered by host and/or application. Like 'tail -f' but across all hosts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Filter to a specific host"
                    },
                    "app_name": {
                        "type": "string",
                        "description": "Filter to a specific application"
                    },
                    "n": {
                        "type": "integer",
                        "description": "Number of recent entries (default 50, max 500)",
                        "default": 50
                    }
                }
            }
        }),
        json!({
            "name": "get_errors",
            "description": "Get a summary of errors and warnings across all hosts in a time window. Groups by hostname and severity level, showing counts. Useful for quick health assessments.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {
                        "type": "string",
                        "description": "Start of time range (ISO 8601). Defaults to all time."
                    },
                    "to": {
                        "type": "string",
                        "description": "End of time range (ISO 8601). Defaults to now."
                    }
                }
            }
        }),
        json!({
            "name": "list_hosts",
            "description": "List all hosts that have sent syslog messages, with first/last seen timestamps and total log counts.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "correlate_events",
            "description": "Search for related events across multiple hosts within a time window. Useful for debugging cascading failures — finds events on all hosts within ±N minutes of a reference timestamp. Results are grouped by host and ordered by time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reference_time": {
                        "type": "string",
                        "description": "Center timestamp for correlation window (ISO 8601, e.g. '2025-01-15T14:30:00Z')"
                    },
                    "window_minutes": {
                        "type": "integer",
                        "description": "Minutes before and after reference_time to search (default 5, max 60)",
                        "default": 5
                    },
                    "severity_min": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Minimum severity to include (default 'warning'). 'warning' returns warning/err/crit/alert/emerg. 'debug' returns everything.",
                        "default": "warning"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Optional: limit correlation to a specific host"
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional FTS query to narrow results (FTS5 syntax)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max total events to return (default 500, max 999)"
                    }
                },
                "required": ["reference_time"]
            }
        }),
        json!({
            "name": "get_stats",
            "description": "Get database statistics: total logs, total hosts, time range covered, logical and physical DB size, free disk, configured thresholds, and current write-block status.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "syslog_help",
            "description": "Returns markdown documentation for all syslog-mcp tools: search_logs, tail_logs, get_errors, list_hosts, correlate_events, get_stats.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
    ]
}

#[cfg(test)]
#[path = "schemas_tests.rs"]
mod tests;
