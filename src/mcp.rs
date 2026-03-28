use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::McpConfig;
use crate::db::{self, DbPool, SearchParams};

/// Shared app state
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<DbPool>,
    pub config: McpConfig,
}

/// MCP JSON-RPC request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[expect(dead_code, reason = "required by JSON-RPC 2.0 spec; serde needs the field for deserialization")]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// MCP JSON-RPC response
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl JsonRpcResponse {
    fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

/// Build the MCP router
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/sse", get(handle_sse))
        .route("/health", get(health))
        .with_state(state)
}

/// Health check
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match db::get_stats(&state.pool) {
        Ok(stats) => Json(json!({ "status": "ok", "stats": stats })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Streamable HTTP transport (POST /mcp)
async fn handle_mcp_post(
    State(state): State<AppState>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let response = dispatch(&state, &req).await;
    Json(response)
}

/// SSE endpoint for MCP (legacy transport support)
async fn handle_sse(
    State(_state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = tokio_stream::once(Ok(Event::default()
        .event("endpoint")
        .data("/mcp")));
    Sse::new(stream)
}

/// Route MCP methods to handlers
async fn dispatch(state: &AppState, req: &JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    let params = req.params.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        // --- MCP lifecycle ---
        "initialize" => JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": state.config.server_name,
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),

        "notifications/initialized" => JsonRpcResponse::success(id, json!({})),

        // --- Tool listing ---
        "tools/list" => JsonRpcResponse::success(id, json!({ "tools": tool_definitions() })),

        // --- Tool execution ---
        "tools/call" => {
            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));

            match execute_tool(state, tool_name, arguments).await {
                Ok(result) => JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                        }]
                    }),
                ),
                Err(e) => JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Error: {e}")
                        }],
                        "isError": true
                    }),
                ),
            }
        }

        // Unknown method
        _ => JsonRpcResponse::error(id, -32601, format!("Method not found: {}", req.method)),
    }
}

/// Define all MCP tools
fn tool_definitions() -> Vec<Value> {
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
            "description": "Search for related events across multiple hosts within a time window. Useful for debugging cascading failures — finds events on all hosts within ±N minutes of a reference timestamp.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reference_time": {
                        "type": "string",
                        "description": "Center timestamp for correlation window (ISO 8601)"
                    },
                    "window_minutes": {
                        "type": "integer",
                        "description": "Minutes before and after reference_time to search (default 5)",
                        "default": 5
                    },
                    "severity_min": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Minimum severity to include (default 'warning')",
                        "default": "warning"
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional FTS query to narrow results"
                    }
                },
                "required": ["reference_time"]
            }
        }),
        json!({
            "name": "get_stats",
            "description": "Get database statistics: total logs, total hosts, time range covered, and database file size.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
    ]
}

/// Execute a tool by name
async fn execute_tool(state: &AppState, name: &str, args: Value) -> anyhow::Result<Value> {
    match name {
        "search_logs" => {
            let params = SearchParams {
                query: args.get("query").and_then(|v| v.as_str()).map(String::from),
                hostname: args.get("hostname").and_then(|v| v.as_str()).map(String::from),
                severity: args.get("severity").and_then(|v| v.as_str()).map(String::from),
                app_name: args.get("app_name").and_then(|v| v.as_str()).map(String::from),
                from: args.get("from").and_then(|v| v.as_str()).map(String::from),
                to: args.get("to").and_then(|v| v.as_str()).map(String::from),
                limit: args.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32),
            };
            let results = db::search_logs(&state.pool, &params)?;
            Ok(json!({
                "count": results.len(),
                "logs": results
            }))
        }

        "tail_logs" => {
            let hostname = args.get("hostname").and_then(|v| v.as_str());
            let app_name = args.get("app_name").and_then(|v| v.as_str());
            let n = args.get("n").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
            let results = db::tail_logs(&state.pool, hostname, app_name, n)?;
            Ok(json!({
                "count": results.len(),
                "logs": results
            }))
        }

        "get_errors" => {
            let from = args.get("from").and_then(|v| v.as_str());
            let to = args.get("to").and_then(|v| v.as_str());
            let results = db::get_error_summary(&state.pool, from, to)?;
            Ok(json!({
                "summary": results
            }))
        }

        "list_hosts" => {
            let results = db::list_hosts(&state.pool)?;
            Ok(json!({
                "hosts": results
            }))
        }

        "correlate_events" => {
            let reference_time = args
                .get("reference_time")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("reference_time is required"))?;

            let window = args
                .get("window_minutes")
                .and_then(|v| v.as_u64())
                .unwrap_or(5) as i64;

            let severity_min = args
                .get("severity_min")
                .and_then(|v| v.as_str())
                .unwrap_or("warning");

            // Parse reference time and compute window
            let ref_dt = chrono::DateTime::parse_from_rfc3339(reference_time)
                .or_else(|_| chrono::DateTime::parse_from_str(reference_time, "%Y-%m-%dT%H:%M:%S%.fZ"))
                .map_err(|e| anyhow::anyhow!("Invalid reference_time: {e}"))?;

            let from = (ref_dt - chrono::Duration::minutes(window)).to_rfc3339();
            let to = (ref_dt + chrono::Duration::minutes(window)).to_rfc3339();

            // Map severity to numeric for filtering
            let sev_threshold = severity_to_num(severity_min);

            let search = SearchParams {
                query: args.get("query").and_then(|v| v.as_str()).map(String::from),
                hostname: None,
                severity: None,
                app_name: None,
                from: Some(from.clone()),
                to: Some(to.clone()),
                limit: Some(500),
            };

            let mut results = db::search_logs(&state.pool, &search)?;

            // Filter by severity threshold
            results.retain(|log| severity_to_num(&log.severity) <= sev_threshold);

            // Group by hostname for readability
            let mut by_host: std::collections::BTreeMap<String, Vec<&db::LogEntry>> =
                std::collections::BTreeMap::new();
            for log in &results {
                by_host
                    .entry(log.hostname.clone())
                    .or_default()
                    .push(log);
            }

            let grouped: Vec<Value> = by_host
                .into_iter()
                .map(|(host, logs)| {
                    json!({
                        "hostname": host,
                        "event_count": logs.len(),
                        "events": logs
                    })
                })
                .collect();

            Ok(json!({
                "reference_time": reference_time,
                "window_minutes": window,
                "severity_min": severity_min,
                "total_events": results.len(),
                "hosts": grouped
            }))
        }

        "get_stats" => {
            let stats = db::get_stats(&state.pool)?;
            Ok(stats)
        }

        _ => Err(anyhow::anyhow!("Unknown tool: {name}")),
    }
}

fn severity_to_num(s: &str) -> u8 {
    match s {
        "emerg" => 0,
        "alert" => 1,
        "crit" => 2,
        "err" => 3,
        "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => 7,
    }
}
