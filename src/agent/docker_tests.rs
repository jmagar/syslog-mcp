use super::*;
use bollard::models::{EventActor, EventMessage};

#[test]
fn container_display_name_prefers_first_docker_name_without_leading_slash() {
    assert_eq!(
        container_display_name(
            "abcdef1234567890",
            Some(vec!["/cortex".to_string(), "/alias".to_string()])
        ),
        "cortex"
    );
}

#[test]
fn container_display_name_falls_back_to_short_id_when_names_missing() {
    assert_eq!(
        container_display_name("abcdef1234567890", Some(Vec::new())),
        "abcdef123456"
    );
    assert_eq!(container_display_name("short", None), "short");
}

#[test]
fn container_app_name_is_flat_compose_service_when_present() {
    // Compose project is intentionally ignored: canonical identity (project,
    // service, container id/name, image) now rides in structured
    // `metadata_json.agent_docker`, so APP-NAME only needs a short,
    // human-readable, non-slash label.
    let labels = HashMap::from([
        (
            "com.docker.compose.project".to_string(),
            "cortex".to_string(),
        ),
        (
            "com.docker.compose.service".to_string(),
            "server".to_string(),
        ),
    ]);

    assert_eq!(container_app_name("cortex-1", &labels), "server");
}

#[test]
fn container_app_name_falls_back_to_container_name_without_service_label() {
    assert_eq!(container_app_name("cortex-1", &HashMap::new()), "cortex-1");
}

#[test]
fn container_app_name_never_contains_a_slash() {
    let labels = HashMap::from([
        (
            "com.docker.compose.project".to_string(),
            "go.opentelemetry.io/collector".to_string(),
        ),
        (
            "com.docker.compose.service".to_string(),
            "receiver".to_string(),
        ),
    ]);
    assert!(!container_app_name("cortex-1", &labels).contains('/'));
    assert!(!container_app_name("cortex-1", &HashMap::new()).contains('/'));
}

#[test]
fn should_forward_container_logs_excludes_cortex_server_containers() {
    let compose_cortex = HashMap::from([
        (
            "com.docker.compose.project".to_string(),
            "cortex".to_string(),
        ),
        (
            "com.docker.compose.service".to_string(),
            "cortex".to_string(),
        ),
    ]);
    assert!(!should_forward_container_logs("cortex", &compose_cortex));

    let plain_cortex = HashMap::new();
    assert!(!should_forward_container_logs("cortex", &plain_cortex));

    let agent = HashMap::from([(
        "com.docker.compose.service".to_string(),
        "cortex-agent".to_string(),
    )]);
    assert!(should_forward_container_logs("cortex-agent", &agent));

    let unrelated = HashMap::from([
        ("com.docker.compose.project".to_string(), "lab".to_string()),
        (
            "com.docker.compose.service".to_string(),
            "labby".to_string(),
        ),
    ]);
    assert!(should_forward_container_logs("labby", &unrelated));
}

#[test]
fn connect_constructs_http_client_without_eager_network_io() {
    connect("http://127.0.0.1:2375").unwrap();
}

#[cfg(unix)]
#[test]
fn connect_constructs_unix_socket_client_without_eager_network_io() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("docker.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

    connect(&format!("unix://{}", socket.display())).unwrap();
}

#[test]
fn container_identity_metadata_carries_compose_context() {
    let labels = HashMap::from([
        ("com.docker.compose.project".to_string(), "plex".to_string()),
        ("com.docker.compose.service".to_string(), "plex".to_string()),
        (
            "com.docker.compose.config-hash".to_string(),
            "abc".to_string(),
        ),
    ]);
    let metadata = container_identity_metadata(
        "nashost",
        "abcdef1234567890",
        "plex",
        "stdout",
        Some("lscr.io/linuxserver/plex:latest"),
        &labels,
    );
    assert_eq!(metadata["source_kind"], "agent-docker");
    assert_eq!(metadata["agent_docker"]["host"], "nashost");
    assert_eq!(metadata["agent_docker"]["container_id"], "abcdef1234567890");
    assert_eq!(metadata["agent_docker"]["compose_project"], "plex");
    assert_eq!(metadata["agent_docker"]["compose_service"], "plex");
}

#[test]
fn long_compose_app_name_still_has_structured_metadata() {
    let labels = HashMap::from([
        (
            "com.docker.compose.project".to_string(),
            "very-long-compose-project-name-for-plex-media-stack".to_string(),
        ),
        (
            "com.docker.compose.service".to_string(),
            "very-long-plex-service-name-that-exceeds-the-forty-eight-byte-app-name-limit"
                .to_string(),
        ),
    ]);
    // APP-NAME is flat (compose_service alone) but can still overflow the
    // RFC 5424 48-byte APP-NAME limit on its own; `sanitise_field` (in
    // `agent::syslog_sender`) replaces an overlong APP-NAME wholesale with
    // the `cortex-agent` fallback at send time, but structured
    // `metadata_json.agent_docker` is unaffected either way.
    let app_name = container_app_name("very-long-container-name-for-plex", &labels);
    assert!(app_name.len() > 48);
    let metadata = container_identity_metadata(
        "nashost",
        "abcdef1234567890",
        "very-long-container-name-for-plex",
        "stderr",
        None,
        &labels,
    );
    assert_eq!(
        metadata["agent_docker"]["compose_service"],
        "very-long-plex-service-name-that-exceeds-the-forty-eight-byte-app-name-limit"
    );
}

#[test]
fn forwarded_stderr_uses_embedded_info_severity() {
    assert_eq!(
        docker_log_pri(
            true,
            "2026-09-07 23:06:45,636 - INFO - plex: Log Stream started"
        ),
        PRI_LOCAL0_INFO
    );
}

#[test]
fn forwarded_stderr_uses_embedded_postgres_log_severity() {
    assert_eq!(
        docker_log_pri(
            true,
            "2026-09-07 23:05:23.496 EDT [27] LOG: checkpoint starting"
        ),
        PRI_LOCAL0_INFO
    );
}

#[test]
fn forwarded_stderr_preserves_explicit_error_severity() {
    assert_eq!(
        docker_log_pri(true, "2026-09-07T23:06:00Z ERROR database unavailable"),
        local0_pri(3)
    );
}

#[test]
fn forwarded_unstructured_stderr_remains_warning() {
    assert_eq!(
        docker_log_pri(true, "connection unexpectedly closed"),
        PRI_LOCAL0_WARN
    );
}

#[test]
fn docker_die_event_is_rendered_with_lifecycle_metadata() {
    let attributes = HashMap::from([
        ("name".to_string(), "plex".to_string()),
        ("image".to_string(), "plex:latest".to_string()),
        ("com.docker.compose.project".to_string(), "plex".to_string()),
        ("com.docker.compose.service".to_string(), "plex".to_string()),
        ("exitCode".to_string(), "137".to_string()),
    ]);
    let event = EventMessage {
        action: Some("die".to_string()),
        actor: Some(EventActor {
            id: Some("abcdef1234567890".to_string()),
            attributes: Some(attributes),
        }),
        time_nano: Some(1_777_942_923_123_456_789),
        ..Default::default()
    };

    let line = docker_event_line("nashost", &event).expect("supported lifecycle event");
    assert!(line.contains("2026-05-05T01:02:03.123456789Z"));
    assert!(line.contains("docker container event: die container=plex"));
    assert!(line.contains("\"stream\":\"event\""));
    assert!(line.contains("\"event_action\":\"die\""));
    assert!(line.contains("\"exit_code\":137"));
}

fn lifecycle_event(action: &str, exit_code: Option<i32>) -> EventMessage {
    let mut attributes = HashMap::from([("name".to_string(), "plex".to_string())]);
    if let Some(code) = exit_code {
        attributes.insert("exitCode".to_string(), code.to_string());
    }
    EventMessage {
        action: Some(action.to_string()),
        actor: Some(EventActor {
            id: Some("abcdef1234567890".to_string()),
            attributes: Some(attributes),
        }),
        ..Default::default()
    }
}

#[test]
fn forwarded_health_action_uses_canonical_collapsed_normalization() {
    let line = docker_event_line(
        "nashost",
        &lifecycle_event("health_status:   unhealthy", None),
    )
    .unwrap();
    assert!(
        line.starts_with("<132>"),
        "unhealthy must be warning: {line}"
    );
    assert!(line.contains("\"event_action\":\"health_status_unhealthy\""));
    assert!(line.contains("docker container event: health_status_unhealthy"));
}

#[test]
fn forwarded_event_severity_matches_canonical_mapping() {
    for (action, exit_code, pri) in [
        ("create", None, 133),
        ("start", None, 133),
        ("restart", None, 132),
        ("die", Some(0), 133),
        ("die", Some(137), 132),
        ("oom", None, 131),
        ("health_status: healthy", None, 133),
        ("health_status: unhealthy", None, 132),
    ] {
        let line = docker_event_line("nashost", &lifecycle_event(action, exit_code)).unwrap();
        assert!(line.starts_with(&format!("<{pri}>")), "{action}: {line}");
    }
}

#[test]
fn clean_event_stream_eof_is_a_restartable_error() {
    let error = event_stream_ended().unwrap_err();
    assert!(error.to_string().contains("ended unexpectedly"));
}

#[test]
fn forwarded_log_severity_preserves_structured_levels_and_fallbacks() {
    for (stderr, message, expected) in [
        (
            false,
            r#"{"level":"error","message":"database unavailable"}"#,
            local0_pri(3),
        ),
        (true, "\u{1b}[32mINFO\u{1b}[0m listening", PRI_LOCAL0_INFO),
        (true, "cannot open log file", PRI_LOCAL0_WARN),
        (true, "log writer ERROR database unavailable", local0_pri(3)),
        (false, "connection accepted", PRI_LOCAL0_INFO),
        (true, "level=debug cache lookup", local0_pri(7)),
    ] {
        assert_eq!(docker_log_pri(stderr, message), expected, "{message}");
    }
}
