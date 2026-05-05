use anyhow::Result;
use bollard::container::LogOutput;

use crate::db;

use super::models::ContainerMeta;

pub(super) fn log_output_to_entry(
    host_name: &str,
    container: &ContainerMeta,
    output: LogOutput,
) -> Result<Option<db::LogBatchEntry>> {
    let (stream, severity, bytes) = match output {
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
    let checkpoint_timestamp = timestamp.clone();
    Ok(Some(db::LogBatchEntry {
        timestamp,
        hostname: host_name.to_string(),
        facility: Some("local0".to_string()),
        severity: severity.to_string(),
        app_name: Some(container.app_name()),
        process_id: Some(container.short_id()),
        message,
        raw: raw_line,
        source_ip: format!("docker://{}/{}/{}", host_name, container.id, stream),
        docker_checkpoint: Some(db::DockerCheckpoint {
            host_name: host_name.to_string(),
            container_id: container.id.clone(),
            timestamp: checkpoint_timestamp,
        }),
    }))
}

fn split_docker_timestamp(raw: &str) -> (String, String) {
    match raw.split_once(' ') {
        Some((ts, rest)) if chrono::DateTime::parse_from_rfc3339(ts).is_ok() => {
            (ts.to_string(), rest.to_string())
        }
        _ => (chrono::Utc::now().to_rfc3339(), raw.to_string()),
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
