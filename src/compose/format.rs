use anyhow::{Result, anyhow};

use super::types::{
    ComposeDiagnostic, ComposeMcpDiagnostic, ComposeMcpStatus, ComposeOwnershipState,
    ComposeRuntimeState, ComposeStatus, DiagnosticSeverity, PublicPortSummary,
};

pub(crate) const DIAG_DOCKER_UNAVAILABLE: &str = "docker_unavailable";

pub fn redact_sensitive(input: &str) -> String {
    let sensitive = [
        "token",
        "secret",
        "key",
        "password",
        "client_secret",
        "authorization",
    ];
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
        redact_json_secrets(&mut value, &sensitive);
        return value.to_string();
    }
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if sensitive.iter().any(|term| lower.contains(term)) {
                "[REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_json_secrets(value: &mut serde_json::Value, sensitive: &[&str]) {
    match value {
        serde_json::Value::Object(entries) => {
            for (key, value) in entries {
                let lower = key.to_ascii_lowercase();
                if sensitive.iter().any(|term| lower.contains(term)) {
                    *value = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json_secrets(value, sensitive);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_secrets(value, sensitive);
            }
        }
        _ => {}
    }
}

pub fn mcp_projection(status: &ComposeStatus) -> ComposeMcpStatus {
    let has_hard_diagnostic = status.diagnostics.iter().any(|d| {
        matches!(
            d.severity,
            DiagnosticSeverity::Error | DiagnosticSeverity::Unsafe
        )
    });
    let ownership = if status
        .diagnostics
        .iter()
        .any(|d| d.code == "owner_mismatch")
    {
        ComposeOwnershipState::OwnerMismatch
    } else if status.systemd.as_ref().is_some_and(|s| s.active) {
        ComposeOwnershipState::SystemdOwned
    } else if has_hard_diagnostic {
        ComposeOwnershipState::Unknown
    } else if status.compose_project.is_some() {
        ComposeOwnershipState::ComposeOwned
    } else {
        ComposeOwnershipState::Unknown
    };

    let runtime_state = if status
        .diagnostics
        .iter()
        .any(|d| d.code == DIAG_DOCKER_UNAVAILABLE)
    {
        ComposeRuntimeState::DockerUnavailable
    } else if has_hard_diagnostic {
        ComposeRuntimeState::Degraded
    } else {
        match status.health.as_deref() {
            Some("healthy") => ComposeRuntimeState::Healthy,
            Some("unhealthy") => ComposeRuntimeState::Degraded,
            _ if status.status.as_deref().is_some_and(is_stopped_status) => {
                ComposeRuntimeState::Stopped
            }
            _ => ComposeRuntimeState::Unknown,
        }
    };

    ComposeMcpStatus {
        container_name: status.container_name.clone(),
        ownership,
        runtime_state,
        health: status.health.clone(),
        published_ports: status
            .ports
            .iter()
            .filter_map(|port| {
                port.public_port.map(|public| PublicPortSummary {
                    port: public,
                    protocol: port.protocol.clone(),
                })
            })
            .collect(),
        diagnostics: status
            .diagnostics
            .iter()
            .map(|d| ComposeMcpDiagnostic {
                severity: d.severity.clone(),
                code: d.code.clone(),
            })
            .collect(),
    }
}

pub fn ensure_doctor_ready(status: &ComposeStatus) -> Result<()> {
    let projected = mcp_projection(status);
    if projected.ownership != ComposeOwnershipState::ComposeOwned
        || projected.runtime_state != ComposeRuntimeState::Healthy
        || status.diagnostics.iter().any(|d| {
            matches!(
                d.severity,
                DiagnosticSeverity::Error | DiagnosticSeverity::Unsafe
            )
        })
    {
        return Err(anyhow!(
            "compose doctor failed: ownership={:?} runtime_state={:?} diagnostics={:?}",
            projected.ownership,
            projected.runtime_state,
            status.diagnostics
        ));
    }
    Ok(())
}

pub(super) fn is_stopped_status(status: &str) -> bool {
    let status = status.to_ascii_lowercase();
    status.contains("exited") || status == "stopped"
}

pub(crate) fn status_from_target(
    target: super::types::ResolvedComposeTarget,
    info: Option<super::types::ContainerInfo>,
    systemd: Option<super::types::SystemdStatus>,
) -> ComposeStatus {
    let mut diagnostics = target.diagnostics.clone();
    if target.source == super::types::TargetSource::CurrentWorkingDirectory {
        diagnostics.push(ComposeDiagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "cwd_target".into(),
            message: "resolved from current working directory".into(),
        });
    }
    ComposeStatus {
        container_name: target.target.container_name,
        container_id: info.as_ref().map(|i| i.id.clone()),
        status: info.as_ref().and_then(|i| i.status.clone()),
        health: info.as_ref().and_then(|i| i.health.clone()),
        image: info.as_ref().and_then(|i| i.image.clone()),
        image_id: info.as_ref().and_then(|i| i.image_id.clone()),
        compose_project: target.compose_project,
        compose_working_dir: target.compose_working_dir,
        compose_files: target.compose_files,
        service: Some(target.target.service),
        data_mounts: info.as_ref().map(|i| i.mounts.clone()).unwrap_or_default(),
        ports: info.as_ref().map(|i| i.ports.clone()).unwrap_or_default(),
        systemd,
        diagnostics,
    }
}

pub(crate) fn unresolved_status(
    requested: &super::types::ComposeTarget,
    defaults: &super::types::ComposeDefaults,
    code: &str,
    message: String,
) -> ComposeStatus {
    ComposeStatus {
        container_name: requested
            .container_name
            .clone()
            .unwrap_or_else(|| defaults.container_name.clone()),
        container_id: None,
        status: None,
        health: None,
        image: None,
        image_id: None,
        compose_project: requested.project_name.clone(),
        compose_working_dir: requested.project_dir.clone(),
        compose_files: requested.compose_file.clone().into_iter().collect(),
        service: Some(
            requested
                .service
                .clone()
                .unwrap_or_else(|| defaults.service.clone()),
        ),
        data_mounts: Vec::new(),
        ports: Vec::new(),
        systemd: None,
        diagnostics: vec![ComposeDiagnostic {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            message,
        }],
    }
}
