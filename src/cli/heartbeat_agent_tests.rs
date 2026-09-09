use super::*;

fn base_args() -> HeartbeatAgentArgs {
    HeartbeatAgentArgs {
        env_file: None,
        target: None,
        token: None,
        interval_secs: 30,
        probe_deadline_ms: 2_000,
        collection_deadline_ms: 5_000,
        retry_buffer: 32,
        once: false,
        emit: false,
        json: false,
        host_id_path: Some("/tmp/cortex-host-id".to_string()),
        docker: false,
        docker_url: None,
        journald: false,
        syslog_target: None,
        ai_transcripts: false,
        agent_command_forward: false,
        shell_history_forward: false,
    }
}

#[test]
fn into_config_maps_explicit_cli_flags() {
    let config = HeartbeatAgentArgs {
        env_file: None,
        target: Some("http://cortex.example".to_string()),
        token: Some("secret".to_string()),
        interval_secs: 7,
        probe_deadline_ms: 800,
        collection_deadline_ms: 1_500,
        retry_buffer: 3,
        once: true,
        emit: true,
        json: true,
        host_id_path: Some("/tmp/host-id".to_string()),
        docker: true,
        docker_url: Some("unix:///tmp/docker.sock".to_string()),
        journald: true,
        syslog_target: Some("127.0.0.1:1514".to_string()),
        ai_transcripts: true,
        agent_command_forward: true,
        shell_history_forward: true,
    }
    .into_config()
    .unwrap();

    assert_eq!(config.target.as_deref(), Some("http://cortex.example"));
    assert_eq!(config.token.as_deref(), Some("secret"));
    assert_eq!(config.interval, Duration::from_secs(7));
    assert_eq!(config.probe_deadline, Duration::from_millis(800));
    assert_eq!(config.collection_deadline, Duration::from_millis(1_500));
    assert_eq!(config.retry_buffer_limit, 3);
    assert!(config.once);
    assert!(config.emit);
    assert!(config.json);
    assert_eq!(config.host_id_path, PathBuf::from("/tmp/host-id"));
    assert!(config.docker);
    assert_eq!(config.docker_url, "unix:///tmp/docker.sock");
    assert!(config.journald);
    assert_eq!(config.syslog_target.as_deref(), Some("127.0.0.1:1514"));
    assert!(config.ai_transcripts);
    assert!(config.agent_command_forward);
    assert!(config.shell_history_forward);
}

#[cfg(unix)]
#[test]
fn env_file_is_loaded_without_shell_and_process_values_win() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.env");
    std::fs::write(
        &path,
        "CORTEX_HEARTBEAT_TARGET=https://from-file.example\nCORTEX_AGENT_DOCKER=true\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut args = base_args();
    args.env_file = Some(path.to_string_lossy().into_owned());
    args.target = Some("https://cli.example".into());
    let config = args.into_config().unwrap();
    assert_eq!(config.target.as_deref(), Some("https://cli.example"));
    assert!(config.docker);
}

#[test]
fn into_config_preserves_env_defaults_when_optional_flags_are_absent() {
    let config = base_args().into_config().unwrap();

    assert_eq!(config.host_id_path, PathBuf::from("/tmp/cortex-host-id"));
    assert_eq!(config.interval, Duration::from_secs(30));
    assert_eq!(config.probe_deadline, Duration::from_millis(2_000));
    assert_eq!(config.collection_deadline, Duration::from_millis(5_000));
    assert_eq!(config.retry_buffer_limit, 32);
    assert!(!config.once);
    assert!(!config.emit);
    assert!(!config.json);
    assert!(!config.docker);
    assert!(!config.journald);
    assert_eq!(config.syslog_target, None);
}
