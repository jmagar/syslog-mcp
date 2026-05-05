use std::{borrow::Cow, net::Ipv6Addr, sync::Arc, time::Instant};

use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ErrorData, RoleServer, ServerHandler,
};
use serde_json::{Map, Value};

use crate::app::ServiceError;
use crate::config::McpConfig;

use super::{schemas::tool_definitions, tools::execute_tool, AppState};

#[derive(Clone)]
pub struct SyslogRmcpServer {
    state: AppState,
}

impl SyslogRmcpServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl ServerHandler for SyslogRmcpServer {
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = rmcp_tool_definitions()?;
        tracing::info!(tool_count = tools.len(), "MCP tools listed");
        Ok(ListToolsResult {
            tools,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name = request.name.to_string();
        let arguments = request
            .arguments
            .map(Value::Object)
            .unwrap_or_else(|| Value::Object(Map::new()));
        let started = Instant::now();
        tracing::info!(tool = %tool_name, "MCP tool execution started");

        match execute_tool(&self.state, &tool_name, arguments).await {
            Ok(result) => {
                let result_count = safe_result_count(&result);
                tracing::info!(
                    tool = %tool_name,
                    elapsed_ms = started.elapsed().as_millis(),
                    result_count,
                    "MCP tool execution completed"
                );
                tool_result_from_json(result)
            }
            Err(error) if is_validation_error(&error) => {
                tracing::warn!(
                    tool = %tool_name,
                    elapsed_ms = started.elapsed().as_millis(),
                    error_class = "invalid_params",
                    "MCP tool execution rejected invalid params"
                );
                Err(ErrorData::invalid_params(error.to_string(), None))
            }
            Err(error) => {
                tracing::error!(
                    tool = %tool_name,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %error,
                    error_class = "tool_execution",
                    "MCP tool execution failed"
                );
                Ok(CallToolResult::error(vec![Content::text(
                    "Tool execution failed",
                )]))
            }
        }
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(
                self.state.config.server_name.clone(),
                env!("CARGO_PKG_VERSION"),
            ),
        )
    }
}

pub fn streamable_http_config(config: &McpConfig) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts(config))
        .with_allowed_origins(allowed_origins(config))
}

pub fn streamable_http_service(
    state: AppState,
    config: StreamableHttpServerConfig,
) -> StreamableHttpService<SyslogRmcpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(SyslogRmcpServer::new(state.clone())),
        Default::default(),
        config,
    )
}

fn rmcp_tool_definitions() -> Result<Vec<Tool>, ErrorData> {
    tool_definitions()
        .into_iter()
        .map(rmcp_tool_from_json)
        .collect()
}

fn rmcp_tool_from_json(value: Value) -> Result<Tool, ErrorData> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ErrorData::internal_error("tool definition missing name", None))?;
    let description = value
        .get("description")
        .and_then(Value::as_str)
        .map(|description| Cow::Owned(description.to_string()));
    let input_schema = value
        .get("inputSchema")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("tool definition missing inputSchema", None))?;

    Ok(Tool::new_with_raw(
        Cow::Owned(name.to_string()),
        description,
        Arc::new(input_schema),
    ))
}

fn tool_result_from_json(value: Value) -> Result<CallToolResult, ErrorData> {
    let text = serde_json::to_string_pretty(&value).map_err(|error| {
        ErrorData::internal_error(format!("serialization error: {error}"), None)
    })?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn is_validation_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<ServiceError>(),
        Some(ServiceError::InvalidInput(_))
    ) || error.to_string().contains(" is required")
        || error.to_string().contains(" must be <=")
}

fn safe_result_count(value: &Value) -> Option<usize> {
    value
        .get("count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .or_else(|| value.get("hosts").and_then(Value::as_array).map(Vec::len))
        .or_else(|| value.get("summary").and_then(Value::as_array).map(Vec::len))
}

fn allowed_hosts(config: &McpConfig) -> Vec<String> {
    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    for host in &config.allowed_hosts {
        push_host_variants(&mut hosts, host, config.port);
    }
    push_host_variants(&mut hosts, &config.host, config.port);
    push_host_variants(&mut hosts, "localhost", config.port);
    push_host_variants(&mut hosts, "127.0.0.1", config.port);
    push_host_variants(&mut hosts, "::1", config.port);
    hosts.sort();
    hosts.dedup();
    hosts
}

fn push_host_variants(hosts: &mut Vec<String>, host: &str, port: u16) {
    let host = host.trim();
    if host.is_empty() {
        return;
    }
    hosts.push(host.to_string());
    if host.starts_with('[') && host.contains("]:") {
        return;
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if !inner.is_empty() {
            hosts.push(format!("[{inner}]:{port}"));
        }
    } else if host.parse::<Ipv6Addr>().is_ok() {
        hosts.push(format!("[{host}]"));
        hosts.push(format!("[{host}]:{port}"));
    } else if !has_port(host) {
        hosts.push(format!("{host}:{port}"));
    }
}

fn has_port(host: &str) -> bool {
    host.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some()
}

pub(super) fn allowed_origins(config: &McpConfig) -> Vec<String> {
    let mut origins = vec![
        format!("http://localhost:{}", config.port),
        format!("http://127.0.0.1:{}", config.port),
    ];
    origins.extend(config.allowed_origins.iter().cloned());
    origins.sort();
    origins.dedup();
    origins
}

#[cfg(test)]
#[path = "rmcp_server_tests.rs"]
mod tests;
