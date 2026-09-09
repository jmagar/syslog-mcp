use anyhow::Result;
use bollard::container::LogOutput;
use bollard::models::{EventActor, EventMessage};
use chrono::TimeZone;

use crate::db;
use crate::enrich::{SourceKind, stamp_source_kind};
use crate::ingest_metadata::bounded_metadata_json;

use super::models::ContainerMeta;

pub(super) fn log_output_to_entry(
    host_name: &str,
    container: &ContainerMeta,
    output: LogOutput,
) -> Result<Option<db::LogBatchEntry>> {
    let (stream, fallback_severity, bytes) = match output {
        LogOutput::StdOut { message } => ("stdout", "info", message),
        LogOutput::StdErr { message } => ("stderr", "warning", message),
        _ => return Ok(None),
    };

    let raw_line = String::from_utf8_lossy(&bytes)
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if raw_line.is_empty() {
        return Ok(None);
    }

    let (timestamp, message) = split_docker_timestamp(&raw_line);
    let severity = infer_docker_severity(&message).unwrap_or(fallback_severity);
    let checkpoint_timestamp = timestamp.clone();
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "docker_stream",
        "docker_host": host_name,
        "container_id": container.id,
        "container_name": container.name,
        "image": container.image,
        "compose_project": container.compose_project,
        "compose_service": container.compose_service,
        "stream": stream,
        "fallback_severity": fallback_severity,
        "checkpoint_timestamp": checkpoint_timestamp,
    }));
    let mut entry = db::LogBatchEntry {
        timestamp,
        hostname: host_name.to_string(),
        facility: Some("local0".to_string()),
        severity: severity.to_string(),
        app_name: Some(container.app_name()),
        process_id: Some(container.short_id()),
        message,
        raw: raw_line,
        source_ip: format!("docker://{}/{}/{}", host_name, container.name, stream),
        docker_checkpoint: Some(db::DockerCheckpoint {
            host_name: host_name.to_string(),
            container_id: container.id.clone(),
            timestamp: checkpoint_timestamp,
        }),
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::DockerStream);
    Ok(Some(entry))
}

pub(super) fn docker_event_to_entry(
    host_name: &str,
    event: &EventMessage,
) -> Result<Option<db::LogBatchEntry>> {
    let Some(action) = event.action.as_deref() else {
        return Ok(None);
    };
    let Some(actor) = event.actor.as_ref() else {
        return Ok(None);
    };
    let Some(severity) = docker_event_severity(action, actor) else {
        return Ok(None);
    };
    let Some(container_id) = actor.id.as_deref() else {
        return Ok(None);
    };

    let meta = container_meta_from_event_actor(container_id, actor);
    let app_name = meta.app_name();
    let timestamp = docker_event_timestamp(event);
    let message = docker_event_message(action, &meta, actor);
    let raw = serde_json::to_string(event)?;
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "docker_event",
        "docker_host": host_name,
        "container_id": container_id,
        "container_name": meta.name,
        "image": meta.image,
        "compose_project": meta.compose_project,
        "compose_service": meta.compose_service,
        "action": action,
        "source_action": docker_event_source_action(action),
        "exit_code": docker_event_exit_code(actor),
    }));
    let mut entry = db::LogBatchEntry {
        timestamp,
        hostname: host_name.to_string(),
        facility: Some("docker".to_string()),
        severity: severity.to_string(),
        app_name: Some(app_name),
        process_id: Some(meta.short_id()),
        message,
        raw,
        source_ip: format!(
            "docker-event://{}/{}/{}",
            host_name,
            meta.name,
            docker_event_source_action(action)
        ),
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::DockerEvent);
    Ok(Some(entry))
}

fn split_docker_timestamp(raw: &str) -> (String, String) {
    match raw.split_once(' ') {
        Some((ts, rest)) if chrono::DateTime::parse_from_rfc3339(ts).is_ok() => {
            (ts.to_string(), rest.to_string())
        }
        _ => (
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            raw.to_string(),
        ),
    }
}

fn container_meta_from_event_actor(container_id: &str, actor: &EventActor) -> ContainerMeta {
    let attributes = actor.attributes.as_ref();
    let name = attributes
        .and_then(|attrs| attrs.get("name"))
        .map(|name| name.trim_start_matches('/').to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| container_id.chars().take(12).collect());
    ContainerMeta {
        id: container_id.to_string(),
        name,
        image: attributes
            .and_then(|attrs| attrs.get("image"))
            .cloned()
            .unwrap_or_default(),
        compose_project: attributes
            .and_then(|attrs| attrs.get("com.docker.compose.project"))
            .cloned(),
        compose_service: attributes
            .and_then(|attrs| attrs.get("com.docker.compose.service"))
            .cloned(),
    }
}

pub(crate) fn docker_event_timestamp(event: &EventMessage) -> String {
    if let Some(time_nano) = event.time_nano {
        let secs = time_nano.div_euclid(1_000_000_000);
        let nanos = time_nano.rem_euclid(1_000_000_000) as u32;
        if let Some(timestamp) = chrono::Utc.timestamp_opt(secs, nanos).single() {
            return timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        }
    }

    if let Some(secs) = event.time
        && let Some(timestamp) = chrono::Utc.timestamp_opt(secs, 0).single()
    {
        return timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }

    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn docker_event_severity(action: &str, actor: &EventActor) -> Option<&'static str> {
    match action {
        "create" | "start" | "rename" | "unpause" | "stop" | "destroy" => Some("notice"),
        "restart" | "kill" | "pause" => Some("warning"),
        "die" => match docker_event_exit_code(actor) {
            Some(0) => Some("notice"),
            Some(_) | None => Some("warning"),
        },
        "oom" => Some("err"),
        _ if action == "health_status: healthy" => Some("notice"),
        _ if action.starts_with("health_status:") => Some("warning"),
        _ => None,
    }
}

fn docker_event_exit_code(actor: &EventActor) -> Option<i32> {
    actor
        .attributes
        .as_ref()
        .and_then(|attrs| attrs.get("exitCode").or_else(|| attrs.get("exit_code")))
        .and_then(|value| value.parse().ok())
}

pub(crate) fn docker_event_source_action(action: &str) -> String {
    let mut out = String::with_capacity(action.len());
    let mut previous_separator = false;
    for ch in action.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
            previous_separator = false;
        } else if !previous_separator {
            out.push('_');
            previous_separator = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn docker_event_message(action: &str, meta: &ContainerMeta, actor: &EventActor) -> String {
    // Use the normalized (single-token) action so the enrich docker_event regex
    // captures it as one \S+ token. Raw Docker actions like "health_status: healthy"
    // contain spaces and colons which would break the capture group.
    let normalized_action = docker_event_source_action(action);
    let mut parts = vec![
        format!("docker container event: {normalized_action}"),
        format!("container={}", meta.name),
    ];
    if !meta.image.is_empty() {
        parts.push(format!("image={}", meta.image));
    }
    if let Some(project) = &meta.compose_project {
        parts.push(format!("compose_project={project}"));
    }
    if let Some(service) = &meta.compose_service {
        parts.push(format!("compose_service={service}"));
    }
    if let Some(exit_code) = actor
        .attributes
        .as_ref()
        .and_then(|attrs| attrs.get("exitCode").or_else(|| attrs.get("exit_code")))
    {
        parts.push(format!("exit_code={exit_code}"));
    }
    parts.join(" ")
}

pub(crate) fn infer_docker_severity(message: &str) -> Option<&'static str> {
    infer_json_severity(message).or_else(|| infer_text_severity(&strip_ansi(message)))
}

fn infer_json_severity(message: &str) -> Option<&'static str> {
    let trimmed = message.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let candidates = [
        parsed.get("level"),
        parsed.get("severity"),
        parsed.get("severity_text"),
        parsed.get("log").and_then(|log| log.get("level")),
    ];

    candidates
        .into_iter()
        .flatten()
        .find_map(|value| value.as_str().and_then(normalize_level))
}

fn infer_text_severity(message: &str) -> Option<&'static str> {
    let normalized = message
        .split_whitespace()
        .take(24)
        .collect::<Vec<_>>()
        .join(" ");

    for marker in ["level", "lvl", "severity"] {
        if let Some(level) = extract_keyed_level(&normalized, marker) {
            return Some(level);
        }
    }

    for token in normalized.split(|c: char| !c.is_ascii_alphanumeric()) {
        if let Some(level) = normalize_level(token) {
            return Some(level);
        }
    }

    None
}

fn extract_keyed_level(message: &str, key: &str) -> Option<&'static str> {
    for separator in ['=', ':'] {
        let needle = format!("{key}{separator}");
        let Some(start) = message.to_ascii_lowercase().find(&needle) else {
            continue;
        };
        let value_start = start + needle.len();
        let value = message[value_start..]
            .trim_start_matches([' ', '"', '\''])
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default();
        if let Some(level) = normalize_level(value) {
            return Some(level);
        }
    }
    None
}

fn normalize_level(level: &str) -> Option<&'static str> {
    match level.to_ascii_lowercase().as_str() {
        "trace" | "debug" => Some("debug"),
        "info" | "information" | "log" => Some("info"),
        "notice" => Some("notice"),
        "warn" | "warning" => Some("warning"),
        "error" | "err" => Some("err"),
        "fatal" | "panic" | "critical" | "crit" => Some("crit"),
        "alert" => Some("alert"),
        "emerg" | "emergency" => Some("emerg"),
        _ => None,
    }
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for code_ch in chars.by_ref() {
                if code_ch.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
