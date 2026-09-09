use std::collections::HashMap;

use bollard::container::LogOutput;
use bollard::models::{EventActor, EventMessage};
use bytes::Bytes;

use super::*;
use crate::docker_ingest::models::ContainerMeta;

fn meta() -> ContainerMeta {
    ContainerMeta {
        id: "abcdef1234567890".into(),
        name: "nginx-1".into(),
        image: "nginx:latest".into(),
        compose_project: Some("edge".into()),
        compose_service: Some("nginx".into()),
    }
}

#[test]
fn stdout_frame_maps_to_info_log_entry() {
    let entry = log_output_to_entry(
        "edge-host-a",
        &meta(),
        LogOutput::StdOut {
            message: Bytes::from_static(b"2026-05-05T01:02:03.123456789Z started nginx\n"),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.timestamp, "2026-05-05T01:02:03.123456789Z");
    assert_eq!(entry.hostname, "edge-host-a");
    assert_eq!(entry.facility.as_deref(), Some("local0"));
    assert_eq!(entry.severity, "info");
    assert_eq!(entry.app_name.as_deref(), Some("nginx"));
    assert_eq!(entry.process_id.as_deref(), Some("abcdef123456"));
    assert_eq!(entry.message, "started nginx");
    assert_eq!(entry.source_ip, "docker://edge-host-a/nginx-1/stdout");
    let metadata: serde_json::Value =
        serde_json::from_str(entry.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_type"], "docker_stream");
    assert_eq!(metadata["docker_host"], "edge-host-a");
    assert_eq!(metadata["container_id"], "abcdef1234567890");
    assert_eq!(metadata["image"], "nginx:latest");
    assert_eq!(metadata["compose_project"], "edge");
    assert_eq!(metadata["stream"], "stdout");
}

#[test]
fn stderr_frame_maps_to_warning_log_entry() {
    let entry = log_output_to_entry(
        "app-host-b",
        &meta(),
        LogOutput::StdErr {
            message: Bytes::from_static(b"2026-05-05T01:02:04Z failed health check\n"),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "warning");
    assert_eq!(entry.message, "failed health check");
    assert_eq!(entry.source_ip, "docker://app-host-b/nginx-1/stderr");
}

#[test]
fn stderr_frame_uses_inner_info_level_when_present() {
    let entry = log_output_to_entry(
        "app-host-b",
        &meta(),
        LogOutput::StdErr {
            message: Bytes::from_static(
                b"2026-05-05T01:02:04Z 2026-05-05 01:02:04,100 - gateway - INFO - probe succeeded\n",
            ),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "info");
    assert_eq!(
        entry.message,
        "2026-05-05 01:02:04,100 - gateway - INFO - probe succeeded"
    );
    assert_eq!(entry.source_ip, "docker://app-host-b/nginx-1/stderr");
}

#[test]
fn stderr_frame_treats_postgres_log_level_as_info() {
    let entry = log_output_to_entry(
        "db-host",
        &meta(),
        LogOutput::StdErr {
            message: Bytes::from_static(
                b"2026-09-07T23:05:23Z 2026-09-07 23:05:23 EDT [27] LOG: checkpoint starting\n",
            ),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "info");
}

#[test]
fn stderr_frame_uses_inner_ansi_info_level_when_present() {
    let entry = log_output_to_entry(
        "app-host-b",
        &meta(),
        LogOutput::StdErr {
            message: Bytes::from_static(
                b"2026-05-05T01:02:04Z \x1b[2m01:02:04\x1b[0m   INFO  \x1b[32mupstream\x1b[0m heartbeat succeeded\n",
            ),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "info");
    assert_eq!(
        entry.message,
        "\x1b[2m01:02:04\x1b[0m   INFO  \x1b[32mupstream\x1b[0m heartbeat succeeded"
    );
}

#[test]
fn stdout_frame_promotes_inner_error_level() {
    let entry = log_output_to_entry(
        "edge-host-a",
        &meta(),
        LogOutput::StdOut {
            message: Bytes::from_static(b"2026-05-05T01:02:03Z level=error failed request\n"),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "err");
    assert_eq!(entry.source_ip, "docker://edge-host-a/nginx-1/stdout");
}

#[test]
fn json_log_level_overrides_stream_default() {
    let entry = log_output_to_entry(
        "app-host-b",
        &meta(),
        LogOutput::StdErr {
            message: Bytes::from_static(
                br#"2026-05-05T01:02:04Z {"level":"debug","message":"poll complete"}"#,
            ),
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(entry.severity, "debug");
}

#[test]
fn docker_start_event_maps_to_notice_log_entry() {
    let entry = docker_event_to_entry("edge-host-a", &event("start"))
        .unwrap()
        .unwrap();

    assert_eq!(entry.timestamp, "2026-05-05T01:02:03.123456789Z");
    assert_eq!(entry.hostname, "edge-host-a");
    assert_eq!(entry.facility.as_deref(), Some("docker"));
    assert_eq!(entry.severity, "notice");
    assert_eq!(entry.app_name.as_deref(), Some("nginx"));
    assert_eq!(entry.process_id.as_deref(), Some("abcdef123456"));
    assert_eq!(
        entry.message,
        "docker container event: start container=nginx-1 image=nginx:latest compose_project=edge compose_service=nginx"
    );
    assert_eq!(entry.source_ip, "docker-event://edge-host-a/nginx-1/start");
    assert!(entry.docker_checkpoint.is_none());
    assert!(entry.raw.contains("\"Action\":\"start\""));
    let metadata: serde_json::Value =
        serde_json::from_str(entry.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(metadata["source_type"], "docker_event");
    assert_eq!(metadata["action"], "start");
    assert_eq!(metadata["source_action"], "start");
    assert_eq!(metadata["compose_service"], "nginx");
}

#[test]
fn docker_die_event_maps_to_warning_and_preserves_exit_code() {
    let entry = docker_event_to_entry("edge-host-a", &event("die"))
        .unwrap()
        .unwrap();

    assert_eq!(entry.severity, "warning");
    assert!(entry.message.contains("exit_code=137"));
    assert_eq!(entry.source_ip, "docker-event://edge-host-a/nginx-1/die");
}

#[test]
fn docker_die_event_with_zero_exit_code_maps_to_notice() {
    let mut event = event("die");
    event
        .actor
        .as_mut()
        .unwrap()
        .attributes
        .as_mut()
        .unwrap()
        .insert("exitCode".to_string(), "0".to_string());

    let entry = docker_event_to_entry("edge-host-a", &event)
        .unwrap()
        .unwrap();

    assert_eq!(entry.severity, "notice");
    assert!(entry.message.contains("exit_code=0"));
}

#[test]
fn docker_health_status_event_sanitizes_source_action_and_maps_unhealthy_warning() {
    let entry = docker_event_to_entry("edge-host-a", &event("health_status: unhealthy"))
        .unwrap()
        .unwrap();

    assert_eq!(entry.severity, "warning");
    assert_eq!(
        entry.source_ip,
        "docker-event://edge-host-a/nginx-1/health_status_unhealthy"
    );
}

#[test]
fn docker_healthy_status_event_maps_to_notice() {
    let entry = docker_event_to_entry("edge-host-a", &event("health_status: healthy"))
        .unwrap()
        .unwrap();

    assert_eq!(entry.severity, "notice");
    assert_eq!(
        entry.source_ip,
        "docker-event://edge-host-a/nginx-1/health_status_healthy"
    );
}

#[test]
fn docker_oom_event_maps_to_error() {
    let entry = docker_event_to_entry("edge-host-a", &event("oom"))
        .unwrap()
        .unwrap();

    assert_eq!(entry.severity, "err");
}

#[test]
fn docker_untracked_event_is_ignored() {
    let entry = docker_event_to_entry("edge-host-a", &event("exec_start")).unwrap();

    assert!(entry.is_none());
}

#[test]
fn non_output_frames_are_ignored() {
    let entry = log_output_to_entry(
        "edge-host-a",
        &meta(),
        LogOutput::Console {
            message: Bytes::from_static(b"ignored\n"),
        },
    )
    .unwrap();
    assert!(entry.is_none());
}

fn event(action: &str) -> EventMessage {
    let mut attributes = HashMap::new();
    attributes.insert("name".to_string(), "nginx-1".to_string());
    attributes.insert("image".to_string(), "nginx:latest".to_string());
    attributes.insert("com.docker.compose.project".to_string(), "edge".to_string());
    attributes.insert(
        "com.docker.compose.service".to_string(),
        "nginx".to_string(),
    );
    if matches!(action, "die" | "oom") {
        attributes.insert("exitCode".to_string(), "137".to_string());
    }

    EventMessage {
        action: Some(action.to_string()),
        actor: Some(EventActor {
            id: Some("abcdef1234567890".to_string()),
            attributes: Some(attributes),
        }),
        time_nano: Some(1_777_942_923_123_456_789),
        ..Default::default()
    }
}

#[test]
fn ordinary_log_word_is_not_a_postgres_severity_marker() {
    assert_eq!(infer_docker_severity("cannot open log file"), None);
    assert_eq!(
        infer_docker_severity("log writer ERROR database unavailable"),
        Some("err")
    );
}
