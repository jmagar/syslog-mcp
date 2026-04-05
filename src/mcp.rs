use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{
        sse::{Event, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use subtle::ConstantTimeEq;

use crate::config::{McpConfig, StorageConfig};
use crate::db::{self, DbPool, SearchParams};

/// Shared app state
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<DbPool>,
    pub config: McpConfig,
    pub storage: StorageConfig,
}

/// MCP JSON-RPC request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[expect(
        dead_code,
        reason = "required by JSON-RPC 2.0 spec; serde needs the field for deserialization"
    )]
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

enum DispatchResult {
    Response(JsonRpcResponse),
    Notification,
}

/// Build the MCP router
pub fn router(state: AppState) -> Router {
    // Authenticated routes: /mcp and /sse require Bearer token when api_token is set
    let authenticated = Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/sse", get(handle_sse))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Unauthenticated routes: /health must be accessible without credentials
    // so Docker HEALTHCHECK, docker-compose health probes, and SWAG can reach it
    let unauthenticated = Router::new().route("/health", get(health));

    Router::new()
        .merge(authenticated)
        .merge(unauthenticated)
        .fallback(|| async { (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))) })
        .layer(DefaultBodyLimit::max(65_536))
        .with_state(state)
}

/// Bearer-token authentication middleware.
///
/// When `config.api_token` is `Some(token)`, every request must carry:
///   `Authorization: Bearer <token>`
/// Requests with a missing or incorrect token receive HTTP 401.
/// When `api_token` is `None` (the default), all requests pass through unchanged.
async fn require_auth(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if let Some(ref expected) = state.config.api_token {
        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let provided = auth.and_then(|v| v.strip_prefix("Bearer "));
        let authorized = match provided {
            Some(token) => token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1,
            None => false,
        };
        if !authorized {
            tracing::warn!(
                method = %method,
                path = %path,
                has_auth_header = auth.is_some(),
                "Unauthorized MCP request rejected"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32001, "message": "unauthorized"}
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Health check — lightweight probe that verifies DB connectivity without
/// running COUNT(*) over the entire logs table.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let started = Instant::now();
    let pool = Arc::clone(&state.pool);
    match tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let conn = pool.get()?;
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    })
    .await
    {
        Ok(Ok(())) => {
            tracing::debug!(
                elapsed_ms = started.elapsed().as_millis(),
                "Health check passed"
            );
            Json(json!({ "status": "ok" })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!(
                error = %e,
                elapsed_ms = started.elapsed().as_millis(),
                "Health check failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                elapsed_ms = started.elapsed().as_millis(),
                "Health check task join failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// Streamable HTTP transport (POST /mcp)
async fn handle_mcp_post(
    State(state): State<AppState>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    match dispatch(&state, &req).await {
        DispatchResult::Response(response) => Json(response).into_response(),
        // JSON-RPC notifications must not produce a response body.
        DispatchResult::Notification => StatusCode::ACCEPTED.into_response(),
    }
}

/// SSE endpoint for MCP (legacy transport support)
async fn handle_sse(
    State(_state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = tokio_stream::once(Ok(Event::default().event("endpoint").data("/mcp")));
    Sse::new(stream)
}

/// Route MCP methods to handlers
async fn dispatch(state: &AppState, req: &JsonRpcRequest) -> DispatchResult {
    let id = req.id.clone().unwrap_or(Value::Null);
    let params = req.params.clone().unwrap_or(Value::Null);
    let request_id = summarize_json_rpc_id(&id);
    tracing::info!(
        request_id = %request_id,
        method = %req.method,
        params_summary = %summarize_json_value(&params, 160),
        "MCP request received"
    );

    match req.method.as_str() {
        // --- MCP lifecycle ---
        "initialize" => {
            tracing::debug!(request_id = %request_id, "MCP initialize handled");
            DispatchResult::Response(JsonRpcResponse::success(
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
            ))
        }

        "notifications/initialized" => {
            tracing::debug!(request_id = %request_id, "MCP initialized notification received");
            DispatchResult::Notification
        }

        // --- Tool listing ---
        "tools/list" => {
            let tools = tool_definitions();
            tracing::info!(request_id = %request_id, tool_count = tools.len(), "MCP tools listed");
            DispatchResult::Response(JsonRpcResponse::success(id, json!({ "tools": tools })))
        }

        // --- Tool execution ---
        "tools/call" => {
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");

            if tool_name.is_empty() {
                tracing::warn!(request_id = %request_id, "MCP tools/call missing tool name");
                return DispatchResult::Response(JsonRpcResponse::error(
                    id,
                    -32602,
                    "Missing required parameter: name".into(),
                ));
            }

            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            let args_summary = summarize_json_value(&arguments, 240);
            let started = Instant::now();
            tracing::info!(
                request_id = %request_id,
                tool = %tool_name,
                arguments_summary = %args_summary,
                "MCP tool execution started"
            );

            match execute_tool(state, tool_name, arguments).await {
                Ok(result) => {
                    tracing::info!(
                        request_id = %request_id,
                        tool = %tool_name,
                        elapsed_ms = started.elapsed().as_millis(),
                        result_summary = %summarize_json_value(&result, 240),
                        "MCP tool execution completed"
                    );
                    DispatchResult::Response(JsonRpcResponse::success(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&result)
                                    .unwrap_or_else(|e| format!("serialization error: {e}"))
                            }]
                        }),
                    ))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        request_id = %request_id,
                        tool = %tool_name,
                        elapsed_ms = started.elapsed().as_millis(),
                        arguments_summary = %args_summary,
                        "MCP tool execution failed"
                    );
                    DispatchResult::Response(JsonRpcResponse::success(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": "Tool execution failed"
                            }],
                            "isError": true
                        }),
                    ))
                }
            }
        }

        // Unknown method
        _ => {
            tracing::warn!(request_id = %request_id, method = %req.method, "Unknown MCP method");
            DispatchResult::Response(JsonRpcResponse::error(
                id,
                -32601,
                format!("Method not found: {}", req.method),
            ))
        }
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

/// Run a blocking db operation on the threadpool, converting join errors to anyhow.
async fn run_db<F, T>(pool: &Arc<DbPool>, f: F) -> anyhow::Result<T>
where
    F: FnOnce(&DbPool) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = Arc::clone(pool);
    tokio::task::spawn_blocking(move || f(&pool))
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))?
}

/// Execute a tool by name
async fn execute_tool(state: &AppState, name: &str, args: Value) -> anyhow::Result<Value> {
    match name {
        "search_logs" => tool_search_logs(&state.pool, args).await,
        "tail_logs" => tool_tail_logs(&state.pool, args).await,
        "get_errors" => tool_get_errors(&state.pool, args).await,
        "list_hosts" => tool_list_hosts(&state.pool, args).await,
        "correlate_events" => tool_correlate_events(&state.pool, args).await,
        "get_stats" => tool_get_stats(state, args).await,
        "syslog_help" => tool_syslog_help().await,
        _ => Err(anyhow::anyhow!("Unknown tool: {name}")),
    }
}

async fn tool_search_logs(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let params = SearchParams {
        query: args.get("query").and_then(|v| v.as_str()).map(String::from),
        hostname: args
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity: args
            .get("severity")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity_in: None,
        app_name: args
            .get("app_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        from: parse_optional_timestamp(args.get("from").and_then(|v| v.as_str()), "from")?,
        to: parse_optional_timestamp(args.get("to").and_then(|v| v.as_str()), "to")?,
        limit: args.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32),
    };
    let results = run_db(pool, move |pool| db::search_logs(pool, &params)).await?;
    tracing::debug!(result_count = results.len(), "search_logs completed");
    Ok(json!({
        "count": results.len(),
        "logs": results
    }))
}

async fn tool_tail_logs(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let hostname = args
        .get("hostname")
        .and_then(|v| v.as_str())
        .map(String::from);
    let app_name = args
        .get("app_name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let n = args.get("n").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
    let results = run_db(pool, move |pool| {
        db::tail_logs(pool, hostname.as_deref(), app_name.as_deref(), n)
    })
    .await?;
    tracing::debug!(result_count = results.len(), n, "tail_logs completed");
    Ok(json!({
        "count": results.len(),
        "logs": results
    }))
}

async fn tool_get_errors(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let from = parse_optional_timestamp(args.get("from").and_then(|v| v.as_str()), "from")?;
    let to = parse_optional_timestamp(args.get("to").and_then(|v| v.as_str()), "to")?;
    let results = run_db(pool, move |pool| {
        db::get_error_summary(pool, from.as_deref(), to.as_deref())
    })
    .await?;
    tracing::debug!(summary_rows = results.len(), "get_errors completed");
    Ok(json!({
        "summary": results
    }))
}

async fn tool_list_hosts(pool: &Arc<DbPool>, _args: Value) -> anyhow::Result<Value> {
    let results = run_db(pool, db::list_hosts).await?;
    tracing::debug!(host_count = results.len(), "list_hosts completed");
    Ok(json!({
        "hosts": results
    }))
}

async fn tool_correlate_events(pool: &Arc<DbPool>, args: Value) -> anyhow::Result<Value> {
    let reference_time = args
        .get("reference_time")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("reference_time is required"))?;

    let window = args
        .get("window_minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(5)
        .min(60) as i64;

    let severity_min = args
        .get("severity_min")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");

    // Validate severity_min before using it
    let sev_threshold = db::severity_to_num(severity_min).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid severity_min '{}'. Must be one of: emerg, alert, crit, err, warning, notice, info, debug",
            severity_min
        )
    })?;

    // Slice SEVERITY_LEVELS up to and including sev_threshold — lower index = more severe,
    // so levels[0..=threshold] gives everything at or above the requested minimum.
    let severity_levels: Vec<String> = db::SEVERITY_LEVELS[..=sev_threshold as usize]
        .iter()
        .map(|&s| s.to_string())
        .collect();

    // Parse reference time and normalize to UTC so window bounds compare
    // correctly against UTC-stored timestamps (mixed offsets misorder TEXT).
    let ref_dt = chrono::DateTime::parse_from_rfc3339(reference_time)
        .map_err(|e| anyhow::anyhow!("Invalid reference_time '{}': {e}", reference_time))?
        .with_timezone(&chrono::Utc);

    let delta = chrono::TimeDelta::try_minutes(window)
        .ok_or_else(|| anyhow::anyhow!("duration overflow"))?;
    let from = (ref_dt - delta).to_rfc3339();
    let to = (ref_dt + delta).to_rfc3339();

    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(500)
        // Cap at 999: search_logs hard-limits to 1000 rows, so limit+1 must
        // stay ≤ 1000 for the truncation sentinel to work correctly.
        .min(999) as u32;

    let search = SearchParams {
        query: args.get("query").and_then(|v| v.as_str()).map(String::from),
        hostname: args
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from),
        severity: None,
        severity_in: Some(severity_levels),
        app_name: None,
        from: Some(from.clone()),
        to: Some(to.clone()),
        // Fetch one extra to detect truncation without a separate COUNT query
        limit: Some(limit + 1),
    };

    let mut results = run_db(pool, move |pool| db::search_logs(pool, &search)).await?;
    let truncated = results.len() > limit as usize;
    results.truncate(limit as usize);

    // Group by hostname, preserving time order within each host
    let mut by_host: std::collections::BTreeMap<String, Vec<&db::LogEntry>> = Default::default();
    for log in &results {
        by_host.entry(log.hostname.clone()).or_default().push(log);
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
        "window_from": from,
        "window_to": to,
        "severity_min": severity_min,
        "total_events": results.len(),
        "truncated": truncated,
        "hosts_count": grouped.len(),
        "hosts": grouped
    }))
}

async fn tool_get_stats(state: &AppState, _args: Value) -> anyhow::Result<Value> {
    let pool = Arc::clone(&state.pool);
    let storage = state.storage.clone();
    let stats = tokio::task::spawn_blocking(move || db::get_stats(&pool, &storage))
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))??;
    tracing::debug!(
        total_logs = stats.total_logs,
        total_hosts = stats.total_hosts,
        logical_db_size_mb = %stats.logical_db_size_mb,
        physical_db_size_mb = %stats.physical_db_size_mb,
        write_blocked = stats.write_blocked,
        phantom_fts_rows = stats.phantom_fts_rows,
        "get_stats completed"
    );
    Ok(serde_json::to_value(&stats)?)
}

async fn tool_syslog_help() -> anyhow::Result<Value> {
    let help = r#"# syslog-mcp Tool Reference

## search_logs
Full-text search across all syslog messages with optional filters.
Uses SQLite FTS5 with porter stemming. Supports FTS5 query syntax: AND, OR, NOT,
phrase matching with quotes, prefix matching with *.

**Parameters:**
- `query` (string) — FTS5 search query, e.g. `'kernel panic'`, `'OOM AND killer'`, `'"connection refused"'`, `'error*'`
- `hostname` (string, optional) — filter by hostname (exact match); use `list_hosts` to enumerate
- `severity` (string, optional) — one of: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`
- `app_name` (string, optional) — filter by application name, e.g. `sshd`, `dockerd`, `kernel`
- `from` (string, optional) — start of time range (ISO 8601 / RFC3339, e.g. `2025-01-15T00:00:00Z`)
- `to` (string, optional) — end of time range (ISO 8601)
- `limit` (integer, optional) — max results (default 100, max 1000)

---

## tail_logs
Get the N most recent log entries, optionally filtered by host and/or application.
Equivalent to `tail -f` across all hosts.

**Parameters:**
- `hostname` (string, optional) — filter to a specific host
- `app_name` (string, optional) — filter to a specific application
- `n` (integer, optional) — number of recent entries (default 50, max 500)

---

## get_errors
Get a summary of errors and warnings across all hosts in a time window.
Groups by hostname and severity level, showing counts. Useful for quick health assessments.

**Parameters:**
- `from` (string, optional) — start of time range (ISO 8601); defaults to all time
- `to` (string, optional) — end of time range (ISO 8601); defaults to now

---

## list_hosts
List all hosts that have sent syslog messages, with first/last seen timestamps and total log counts.

**Parameters:** none

---

## correlate_events
Search for related events across multiple hosts within a time window.
Useful for debugging cascading failures — finds events on all hosts within ±N minutes
of a reference timestamp. Results are grouped by host and ordered by time.

**Parameters:**
- `reference_time` (string, **required**) — center timestamp (ISO 8601, e.g. `2025-01-15T14:30:00Z`)
- `window_minutes` (integer, optional) — minutes before and after reference_time to search (default 5, max 60)
- `severity_min` (string, optional) — minimum severity to include (default `warning`); `debug` returns everything
- `hostname` (string, optional) — limit correlation to a specific host
- `query` (string, optional) — optional FTS query to narrow results
- `limit` (integer, optional) — max total events to return (default 500, max 999)

---

## get_stats
Get database statistics: total logs, total hosts, time range covered, logical and physical
DB size, free disk, configured thresholds, and current write-block status.

**Parameters:** none

---

## syslog_help
Returns this markdown documentation for all available syslog-mcp tools.

**Parameters:** none
"#;
    Ok(json!({ "help": help }))
}

fn summarize_json_rpc_id(id: &Value) -> String {
    summarize_json_value(id, 48)
}

fn summarize_json_value(value: &Value, limit: usize) -> String {
    let raw = match value {
        Value::Null => "null".to_string(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    };
    if raw.len() <= limit {
        raw
    } else {
        let mut end = limit;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &raw[..end])
    }
}

/// Parse an optional RFC3339 timestamp string and normalize it to UTC.
///
/// Returns `Ok(None)` when `raw` is `None`. Returns a descriptive error when
/// `raw` is `Some` but not valid RFC3339 — callers get a clear message rather
/// than a silent wrong-result query against UTC-stored timestamps.
fn parse_optional_timestamp(raw: Option<&str>, field_name: &str) -> anyhow::Result<Option<String>> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid {field_name} '{}': {e}. Expected ISO 8601 / RFC3339 format, e.g. '2025-01-15T00:00:00Z'",
                    s
                )
            })?;
            Ok(Some(dt.with_timezone(&chrono::Utc).to_rfc3339()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn test_state() -> (AppState, tempfile::TempDir) {
        test_state_with_token(None)
    }

    fn test_state_with_token(token: Option<String>) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageConfig::for_test(dir.path().join("mcp-test.db"));
        let pool = Arc::new(db::init_pool(&storage).unwrap());
        (
            AppState {
                pool,
                config: McpConfig {
                    host: "127.0.0.1".into(),
                    port: 3100,
                    server_name: "syslog-mcp".into(),
                    api_token: token,
                },
                storage,
            },
            dir,
        )
    }

    /// Owns both `AppState` and the `TempDir` backing the SQLite DB so the
    /// directory cannot be accidentally dropped (e.g. via `let (state, _) = …`)
    /// while the connection pool still holds the path.
    struct TestHarness {
        state: AppState,
        _dir: tempfile::TempDir,
    }

    impl TestHarness {
        fn new() -> Self {
            let (state, dir) = test_state_with_token(None);
            TestHarness { state, _dir: dir }
        }

        fn with_token(token: String) -> Self {
            let (state, dir) = test_state_with_token(Some(token));
            TestHarness { state, _dir: dir }
        }
    }

    #[tokio::test]
    async fn tool_get_stats_returns_storage_guard_fields() {
        let h = TestHarness::new();
        let state = h.state;
        let value = tool_get_stats(&state, json!({})).await.unwrap();
        assert!(value.get("logical_db_size_mb").is_some());
        assert!(value.get("physical_db_size_mb").is_some());
        assert!(value.get("write_blocked").is_some());
        assert!(value.get("phantom_fts_rows").is_some());
    }

    #[tokio::test]
    async fn initialized_notification_returns_no_jsonrpc_body() {
        let h = TestHarness::new();
        let state = h.state;
        let response = handle_mcp_post(
            State(state),
            Json(JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: None,
                method: "notifications/initialized".into(),
                params: Some(json!({})),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn summarize_json_value_truncates_long_values() {
        let value = json!({"query": "x".repeat(80)});
        let summary = summarize_json_value(&value, 24);
        assert!(summary.len() <= 27);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn summarize_json_value_handles_multibyte_utf8() {
        // Each Greek letter is 2 bytes; limit=5 falls inside the 3rd letter
        let value = json!("αβγδεζ");
        let summary = summarize_json_value(&value, 5);
        // Should not panic, should be valid UTF-8
        assert!(summary.is_char_boundary(summary.len()));
        assert!(summary.ends_with('…'));
    }

    // ---- Integration tests: HTTP-level through the axum router ----

    mod integration_tests {
        use super::*;
        use axum::http::Request;
        use tower::util::ServiceExt;

        /// Build a JSON-RPC request body
        fn jsonrpc_request(
            id: u64,
            method: &str,
            params: Option<serde_json::Value>,
        ) -> serde_json::Value {
            let mut req = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
            });
            if let Some(p) = params {
                req.as_object_mut().unwrap().insert("params".into(), p);
            }
            req
        }

        /// Send a POST /mcp request through the router and return (status, parsed body).
        /// Pass `auth` to include an `Authorization: Bearer <token>` header.
        async fn mcp_post(
            app: Router,
            body: serde_json::Value,
            auth: Option<&str>,
        ) -> (axum::http::StatusCode, serde_json::Value) {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("Content-Type", "application/json");
            if let Some(token) = auth {
                builder = builder.header("Authorization", format!("Bearer {token}"));
            }
            let request = builder
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, value)
        }

        #[tokio::test]
        async fn integration_health_returns_200() {
            let h = TestHarness::new();
            let app = router(h.state);
            let request = Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
        }

        #[tokio::test]
        async fn integration_initialize() {
            let h = TestHarness::new();
            let body = jsonrpc_request(1, "initialize", None);
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            assert!(value["result"]["protocolVersion"].is_string());
            assert!(value["result"]["serverInfo"]["name"].is_string());
        }

        #[tokio::test]
        async fn integration_tools_list() {
            let h = TestHarness::new();
            let body = jsonrpc_request(2, "tools/list", None);
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let tools = value["result"]["tools"].as_array().unwrap();
            let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
            for expected in &[
                "search_logs",
                "tail_logs",
                "get_errors",
                "list_hosts",
                "correlate_events",
                "get_stats",
            ] {
                assert!(names.contains(expected), "missing tool: {}", expected);
            }
        }

        #[tokio::test]
        async fn integration_get_stats() {
            let h = TestHarness::new();
            let body = jsonrpc_request(
                3,
                "tools/call",
                Some(serde_json::json!({"name": "get_stats", "arguments": {}})),
            );
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let content = value["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                content.contains("total_logs"),
                "expected total_logs in: {}",
                content
            );
        }

        #[tokio::test]
        async fn integration_tail_logs_empty_db() {
            let h = TestHarness::new();
            let body = jsonrpc_request(
                4,
                "tools/call",
                Some(serde_json::json!({"name": "tail_logs", "arguments": {"n": 10}})),
            );
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            assert!(value["error"].is_null(), "unexpected error: {}", value);
        }

        #[tokio::test]
        async fn integration_search_logs_empty_db() {
            let h = TestHarness::new();
            let body = jsonrpc_request(
                5,
                "tools/call",
                Some(serde_json::json!({"name": "search_logs", "arguments": {"query": "error", "limit": 5}})),
            );
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            assert!(value["error"].is_null(), "unexpected error: {}", value);
        }

        #[tokio::test]
        async fn integration_unknown_method_returns_error() {
            let h = TestHarness::new();
            let body = jsonrpc_request(6, "nonexistent/method", None);
            let (status, value) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            assert_eq!(value["error"]["code"].as_i64().unwrap(), -32601);
        }

        #[tokio::test]
        async fn integration_auth_missing_token_returns_401() {
            let h = TestHarness::with_token("secret-token".into());
            let body = jsonrpc_request(7, "tools/list", None);
            let (status, _) = mcp_post(router(h.state), body, None).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn integration_auth_correct_token_succeeds() {
            let h = TestHarness::with_token("secret-token".into());
            let body = jsonrpc_request(8, "tools/list", None);
            let (status, _) = mcp_post(router(h.state), body, Some("secret-token")).await;
            assert_eq!(status, axum::http::StatusCode::OK);
        }
    }
}
