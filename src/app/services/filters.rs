use super::*;

pub(super) fn search_request_to_params(req: SearchLogsRequest) -> ServiceResult<SearchParams> {
    request_parts_to_params(FilterRequestParts {
        hostname: req.host.clone(),
        source_ip: req.source.clone(),
        severity: req.severity,
        app_name: req.app.clone(),
        facility: req.facility.clone(),
        exclude_facility: req.exclude_facility.clone(),
        process_id: req.process_id.clone(),
        from: req.since,
        to: req.until,
        received_since: req.received_since,
        received_until: req.received_until,
        limit: req.limit,
        source_kind: req.source_kind,
        tool: req.tool,
        project: req.project,
        session_id: req.session_id,
        container: req.container,
        docker_host: req.docker_host,
        stream: req.stream,
        event_action: req.event_action.clone(),
    })
}

pub(super) fn filter_request_to_params(req: FilterLogsRequest) -> ServiceResult<SearchParams> {
    request_parts_to_params(FilterRequestParts {
        hostname: req.host,
        source_ip: req.source,
        severity: req.severity,
        app_name: req.app,
        facility: req.facility,
        exclude_facility: req.exclude_facility,
        process_id: req.process_id,
        from: req.since,
        to: req.until,
        received_since: req.received_since,
        received_until: req.received_until,
        limit: req.limit,
        source_kind: req.source_kind,
        tool: req.tool,
        project: req.project,
        session_id: req.session_id,
        container: req.container,
        docker_host: req.docker_host,
        stream: req.stream,
        event_action: req.event_action.clone(),
    })
}

struct FilterRequestParts {
    hostname: Option<String>,
    source_ip: Option<String>,
    severity: Option<String>,
    app_name: Option<String>,
    facility: Option<String>,
    exclude_facility: Option<String>,
    process_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    received_since: Option<String>,
    received_until: Option<String>,
    limit: Option<u32>,
    source_kind: Option<String>,
    tool: Option<String>,
    project: Option<String>,
    session_id: Option<String>,
    container: Option<String>,
    docker_host: Option<String>,
    stream: Option<String>,
    event_action: Option<String>,
}

fn request_parts_to_params(req: FilterRequestParts) -> ServiceResult<SearchParams> {
    let severity = validate_optional_severity(req.severity.clone())?;
    let mut params = SearchParams {
        query: None,
        host: req.hostname.clone(),
        source: req.source_ip.clone(),
        source_ip_prefix: None,
        source_ip_prefixes: None,
        severity,
        severity_in: None,
        app: req.app_name.clone(),
        facility: req.facility.clone(),
        exclude_facility: req.exclude_facility.clone(),
        process_id: req.process_id.clone(),
        since: parse_optional_timestamp(req.from.as_deref(), "since")?,
        until: parse_optional_timestamp(req.to.as_deref(), "until")?,
        received_since: parse_optional_timestamp(req.received_since.as_deref(), "received_since")?,
        received_until: parse_optional_timestamp(req.received_until.as_deref(), "received_until")?,
        limit: req.limit,
        ai_tool: req.tool.clone(),
        ai_project: req.project.clone(),
        ai_session_id: req.session_id.clone(),
        event_action: req.event_action.clone(),
        exclude_ai: false,
    };

    apply_log_filter_aliases(&mut params, req.source_kind.as_deref(), &req)?;
    Ok(params)
}

fn apply_log_filter_aliases(
    params: &mut SearchParams,
    source_kind: Option<&str>,
    req: &FilterRequestParts,
) -> ServiceResult<()> {
    if req.stream.is_some() && source_kind != Some("docker-stream") {
        return Err(ServiceError::InvalidInput(
            "`stream` is only supported with source_kind=docker-stream".into(),
        ));
    }
    if req.stream.is_some() && (req.docker_host.is_none() || req.container.is_none()) {
        return Err(ServiceError::InvalidInput(
            "`stream` requires docker_host and container".into(),
        ));
    }
    match source_kind {
        None => {
            if let Some(container) = &req.container {
                params.app.get_or_insert_with(|| container.clone());
            }
        }
        Some("docker-stream") => {
            params.source_ip_prefix = Some(docker_source_prefix("docker://", req));
            if let Some(container) = &req.container {
                params.app.get_or_insert_with(|| container.clone());
            }
        }
        Some("docker-event") => {
            params.source_ip_prefix = Some(docker_source_prefix("docker-event://", req));
            if let Some(container) = &req.container {
                params.app.get_or_insert_with(|| container.clone());
            }
        }
        Some("agent-command") => {
            params.source_ip_prefix = Some("agent-command://".to_string());
        }
        Some("shell-history") => {
            params.source_ip_prefixes = Some(vec![
                "shell-history://".to_string(),
                "agent-shell-history://".to_string(),
            ]);
        }
        Some("file-tail") => {
            params.source_ip_prefix = Some("file-tail://".to_string());
        }
        Some("claude") | Some("claude-transcript") => {
            apply_source_kind_tool_alias(params, "claude")?;
        }
        Some("codex") | Some("codex-transcript") => {
            apply_source_kind_tool_alias(params, "codex")?;
        }
        Some("gemini") | Some("gemini-transcript") => {
            apply_source_kind_tool_alias(params, "gemini")?;
        }
        Some("transcript") => {
            params.source_ip_prefix = Some("transcript://".to_string());
        }
        Some("syslog-udp") | Some("syslog-tcp") | Some("otlp") => {
            return Err(ServiceError::InvalidInput(format!(
                "source_kind={} is not indexed separately in v1; filter by host, source, app, facility, and time range instead",
                source_kind.unwrap()
            )));
        }
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported source_kind '{other}'. Supported: docker-stream, docker-event, agent-command, shell-history, file-tail, transcript, claude, codex, gemini"
            )));
        }
    }
    Ok(())
}

fn apply_source_kind_tool_alias(
    params: &mut SearchParams,
    expected_tool: &str,
) -> ServiceResult<()> {
    match params.ai_tool.as_deref() {
        Some(actual_tool) if actual_tool != expected_tool => Err(ServiceError::InvalidInput(
            format!("source_kind={expected_tool} conflicts with tool={actual_tool}"),
        )),
        Some(_) => Ok(()),
        None => {
            params.ai_tool = Some(expected_tool.to_string());
            Ok(())
        }
    }
}

fn docker_source_prefix(scheme: &str, req: &FilterRequestParts) -> String {
    let mut prefix = scheme.to_string();
    if let Some(host) = &req.docker_host {
        prefix.push_str(host);
        prefix.push('/');
        if let Some(container) = &req.container {
            prefix.push_str(container);
            prefix.push('/');
            if let Some(stream) = &req.stream {
                prefix.push_str(stream);
            }
        }
    }
    prefix
}

pub(super) fn validate_optional_severity(
    severity: Option<String>,
) -> ServiceResult<Option<String>> {
    let Some(severity) = severity else {
        return Ok(None);
    };
    if db::severity_to_num(&severity).is_some() {
        return Ok(Some(severity));
    }
    Err(ServiceError::InvalidInput(format!(
        "Invalid severity '{}'. Must be one of: {}",
        severity,
        db::SEVERITY_LEVELS.join(", ")
    )))
}
