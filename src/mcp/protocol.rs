use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::schemas::tool_definitions;
use super::tools::execute_tool;
use super::AppState;

/// MCP JSON-RPC request
#[derive(Debug, Deserialize)]
pub(super) struct JsonRpcRequest {
    #[expect(
        dead_code,
        reason = "required by JSON-RPC 2.0 spec; serde needs the field for deserialization"
    )]
    pub(super) jsonrpc: String,
    pub(super) id: Option<Value>,
    pub(super) method: String,
    pub(super) params: Option<Value>,
}

/// MCP JSON-RPC response
#[derive(Debug, Serialize)]
pub(super) struct JsonRpcResponse {
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

pub(super) enum DispatchResult {
    Response(JsonRpcResponse),
    Notification,
}
/// Route MCP methods to handlers
pub(super) async fn dispatch(state: &AppState, req: &JsonRpcRequest) -> DispatchResult {
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
pub(super) fn summarize_json_rpc_id(id: &Value) -> String {
    summarize_json_value(id, 48)
}

pub(super) fn summarize_json_value(value: &Value, limit: usize) -> String {
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

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
