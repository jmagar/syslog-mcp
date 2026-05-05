use bollard::container::LogOutput;
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
    assert_eq!(entry.app_name.as_deref(), Some("edge/nginx/nginx-1"));
    assert_eq!(entry.process_id.as_deref(), Some("abcdef123456"));
    assert_eq!(entry.message, "started nginx");
    assert_eq!(
        entry.source_ip,
        "docker://edge-host-a/abcdef1234567890/stdout"
    );
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
    assert_eq!(
        entry.source_ip,
        "docker://app-host-b/abcdef1234567890/stderr"
    );
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
