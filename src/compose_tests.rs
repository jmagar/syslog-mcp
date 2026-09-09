use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Output;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::*;

fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[allow(dead_code)]
struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

#[allow(dead_code)]
impl EnvGuard {
    fn new(keys: &[&'static str]) -> Self {
        Self {
            saved: keys
                .iter()
                .map(|key| (*key, crate::env::var(key).ok()))
                .collect(),
        }
    }

    fn set(&self, key: &str, value: &str) {
        crate::env::set_test_var(key, value);
    }

    fn remove(&self, key: &str) {
        crate::env::remove_test_var(key);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(value) => crate::env::set_test_var(key, value),
                None => crate::env::remove_test_var(key),
            }
        }
    }
}

#[derive(Default)]
struct FakeInspector {
    container: Option<ContainerInfo>,
    candidates: Vec<ContainerInfo>,
    systemd: Option<SystemdStatus>,
    listeners: Vec<ListenerInfo>,
    systemd_error: Option<String>,
    listeners_error: Option<String>,
    published_port_owners: BTreeMap<u16, String>,
}

impl DockerInspect for FakeInspector {
    fn inspect_container(&self, _name: &str) -> Result<Option<ContainerInfo>> {
        Ok(self.container.clone())
    }

    fn find_candidates(&self, _service: &str, _container_name: &str) -> Result<Vec<ContainerInfo>> {
        Ok(self.candidates.clone())
    }

    fn systemd_status(&self, _unit: &str) -> Result<Option<SystemdStatus>> {
        if let Some(error) = &self.systemd_error {
            anyhow::bail!("{error}");
        }
        Ok(self.systemd.clone())
    }

    fn listeners(&self, _ports: &[u16]) -> Result<Vec<ListenerInfo>> {
        if let Some(error) = &self.listeners_error {
            anyhow::bail!("{error}");
        }
        Ok(self.listeners.clone())
    }

    fn published_port_owner(&self, port: u16) -> Result<Option<String>> {
        Ok(self.published_port_owners.get(&port).cloned())
    }
}

#[derive(Default)]
struct FakeRunner;

impl CommandRunner for FakeRunner {
    fn run(&self, _invocation: &ComposeInvocation) -> Result<CommandOutput> {
        Ok(CommandOutput {
            exit_status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            timeout_cleanup: None,
        })
    }
}

fn labelled_container() -> ContainerInfo {
    let compose_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let project_dir = compose_file.parent().unwrap().to_path_buf();
    let mut labels = BTreeMap::new();
    labels.insert(
        "com.docker.compose.project".into(),
        "syslog-jmagar-lab".into(),
    );
    labels.insert(
        "com.docker.compose.project.working_dir".into(),
        project_dir.display().to_string(),
    );
    labels.insert(
        "com.docker.compose.project.config_files".into(),
        compose_file.display().to_string(),
    );
    labels.insert("com.docker.compose.service".into(), "cortex".into());
    ContainerInfo {
        id: "abc".into(),
        name: "cortex".into(),
        status: Some("Up".into()),
        health: Some("healthy".into()),
        image: Some("ghcr.io/dinglebear-ai/cortex:latest".into()),
        image_id: Some("sha256:abc".into()),
        labels,
        mounts: vec![MountInfo {
            source: None,
            target: "/data".into(),
            kind: "volume".into(),
            volume_name: Some("cortex-data".into()),
        }],
        ports: vec![PortInfo {
            private_port: 3100,
            public_port: Some(3100),
            protocol: "tcp".into(),
            host_ip: Some("0.0.0.0".into()),
        }],
    }
}

fn unlabelled_container() -> ContainerInfo {
    ContainerInfo {
        labels: BTreeMap::new(),
        ..labelled_container()
    }
}

#[test]
fn redacts_sensitive_lines() {
    let input = "ok=true\nCORTEX_TOKEN=abc\nclient_secret = \"secret\"\nport=3100";
    let redacted = redact_sensitive(input);
    assert!(redacted.contains("ok=true"));
    assert!(redacted.contains("port=3100"));
    assert!(!redacted.contains("abc"));
    assert!(!redacted.contains("client_secret"));
    assert_eq!(redacted.matches("[REDACTED]").count(), 2);
}

#[test]
fn redacts_json_secrets_without_destroying_compose_config_shape() {
    let input = r#"{"services":{"cortex":{"environment":{"CORTEX_TOKEN":"abc"},"volumes":[{"type":"bind","source":"/safe/backups","target":"/backups"}]}}}"#;
    let redacted = redact_sensitive(input);
    let value: serde_json::Value = serde_json::from_str(&redacted).unwrap();
    assert_eq!(
        value["services"]["cortex"]["environment"]["CORTEX_TOKEN"],
        "[REDACTED]"
    );
    assert_eq!(
        value["services"]["cortex"]["volumes"][0]["source"],
        "/safe/backups"
    );
    assert!(!redacted.contains("abc"));
}

#[test]
fn mcp_projection_omits_host_paths_and_image_ids() {
    let status = ComposeStatus {
        container_name: "cortex".into(),
        container_id: Some("container-id".into()),
        status: Some("Up 1 minute".into()),
        health: Some("healthy".into()),
        image: Some("ghcr.io/dinglebear-ai/cortex:latest".into()),
        image_id: Some("sha256:secret-image-id".into()),
        compose_project: Some("syslog-jmagar-lab".into()),
        compose_working_dir: Some(PathBuf::from("/home/jmagar/private")),
        compose_files: vec![PathBuf::from("/home/jmagar/private/docker-compose.yml")],
        service: Some("cortex".into()),
        data_mounts: vec![MountInfo {
            source: Some(PathBuf::from("/home/jmagar/private/data")),
            target: "/data".into(),
            kind: "bind".into(),
            volume_name: None,
        }],
        ports: vec![PortInfo {
            private_port: 3100,
            public_port: Some(3100),
            protocol: "tcp".into(),
            host_ip: Some("0.0.0.0".into()),
        }],
        systemd: None,
        diagnostics: vec![],
    };

    let projected = mcp_projection(&status);
    let json = serde_json::to_string(&projected).unwrap();
    assert_eq!(projected.ownership, ComposeOwnershipState::ComposeOwned);
    assert_eq!(projected.runtime_state, ComposeRuntimeState::Healthy);
    assert!(json.contains("3100"));
    assert!(!json.contains("/home/jmagar"));
    assert!(!json.contains("secret-image-id"));
    assert!(!json.contains("/data"));
}

#[test]
fn mcp_projection_treats_lowercase_docker_exited_as_stopped() {
    let status = ComposeStatus {
        container_name: "cortex".into(),
        container_id: Some("container-id".into()),
        status: Some("exited".into()),
        health: None,
        image: Some("ghcr.io/dinglebear-ai/cortex:latest".into()),
        image_id: Some("sha256:secret-image-id".into()),
        compose_project: Some("syslog-jmagar-lab".into()),
        compose_working_dir: None,
        compose_files: Vec::new(),
        service: Some("cortex".into()),
        data_mounts: Vec::new(),
        ports: Vec::new(),
        systemd: None,
        diagnostics: vec![],
    };

    let projected = mcp_projection(&status);

    assert_eq!(projected.runtime_state, ComposeRuntimeState::Stopped);
}

#[test]
fn mcp_projection_degrades_hard_diagnostics() {
    let mut status = ComposeStatus {
        container_name: "cortex".into(),
        container_id: Some("container-id".into()),
        status: Some("running".into()),
        health: Some("healthy".into()),
        image: Some("ghcr.io/dinglebear-ai/cortex:latest".into()),
        image_id: None,
        compose_project: Some("syslog-jmagar-lab".into()),
        compose_working_dir: None,
        compose_files: Vec::new(),
        service: Some("cortex".into()),
        data_mounts: Vec::new(),
        ports: Vec::new(),
        systemd: None,
        diagnostics: vec![ComposeDiagnostic {
            severity: DiagnosticSeverity::Unsafe,
            code: "incomplete_compose_labels".into(),
            message: "missing labels".into(),
        }],
    };

    let projected = mcp_projection(&status);
    assert_eq!(projected.ownership, ComposeOwnershipState::Unknown);
    assert_eq!(projected.runtime_state, ComposeRuntimeState::Degraded);
    assert!(ensure_doctor_ready(&status).is_err());

    status.diagnostics.clear();
    assert!(ensure_doctor_ready(&status).is_ok());
}

#[test]
fn ss_header_only_output_is_not_listener() {
    assert!(!ss_output_has_listener(
        b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    ));
    assert!(!ss_output_has_listener(b"\n"));
    assert!(ss_output_has_listener(
        b"tcp LISTEN 0 4096 0.0.0.0:3100 0.0.0.0:* users:((\"docker-proxy\",pid=123,fd=4))\n"
    ));
}

#[test]
fn resolves_live_container_labels() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = service.resolve_target(&ComposeTarget::default()).unwrap();
    assert_eq!(target.source, TargetSource::LiveContainerLabels);
    assert_eq!(target.confidence, TargetConfidence::Confirmed);
    assert_eq!(target.compose_project.as_deref(), Some("syslog-jmagar-lab"));
}

#[test]
fn inspect_json_extracts_compose_fields_ports_and_mounts() {
    let info = container_info_from_inspect(serde_json::json!({
        "Id": "abcdef123456",
        "Name": "/cortex",
        "Image": "sha256:image-id",
        "State": {
            "Status": "running",
            "Health": {"Status": "healthy"}
        },
        "Config": {
            "Image": "ghcr.io/dinglebear-ai/cortex:latest",
            "Labels": {
                "com.docker.compose.project": "syslog-jmagar-lab",
                "com.docker.compose.service": "cortex",
                "com.docker.compose.project.working_dir": "/srv/syslog",
                "com.docker.compose.project.config_files": "/srv/syslog/docker-compose.yml"
            }
        },
        "Mounts": [
            {"Type": "bind", "Source": "/srv/syslog/data", "Destination": "/data"}
        ],
        "NetworkSettings": {
            "Ports": {
                "3100/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3100"}],
                "1514/udp": null
            }
        }
    }))
    .unwrap();

    assert_eq!(info.id, "abcdef123456");
    assert_eq!(info.name, "cortex");
    assert_eq!(info.status.as_deref(), Some("running"));
    assert_eq!(info.health.as_deref(), Some("healthy"));
    assert_eq!(
        info.image.as_deref(),
        Some("ghcr.io/dinglebear-ai/cortex:latest")
    );
    assert_eq!(info.image_id.as_deref(), Some("sha256:image-id"));
    assert_eq!(info.mounts[0].target, "/data");
    assert_eq!(info.ports.len(), 2);
    assert!(
        info.ports
            .iter()
            .any(|port| port.private_port == 3100 && port.public_port == Some(3100))
    );
    assert!(
        info.ports
            .iter()
            .any(|port| port.private_port == 1514 && port.public_port.is_none())
    );
}

#[test]
fn cwd_fallback_is_unsafe_and_refused_for_mutation() {
    let _guard = cwd_lock();
    let old_cwd = std::env::current_dir().unwrap();
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(tempdir.path().join("docker-compose.yml"), "services: {}\n").unwrap();
    std::env::set_current_dir(tempdir.path()).unwrap();

    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = service.resolve_target(&ComposeTarget::default()).unwrap();
    assert_eq!(target.source, TargetSource::CurrentWorkingDirectory);
    assert_eq!(target.confidence, TargetConfidence::Unsafe);
    let err = service
        .preflight_mutation(ComposeMutation::Pull, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("cwd target"));

    std::env::set_current_dir(old_cwd).unwrap();
}

#[test]
fn requested_project_or_service_must_match_live_labels() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let err = service
        .resolve_target(&ComposeTarget {
            project_name: Some("staging".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("project_name"));

    let err = service
        .resolve_target(&ComposeTarget {
            service: Some("other".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("service"));
}

#[test]
fn matching_requested_selectors_are_accepted() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = service
        .resolve_target(&ComposeTarget {
            project_name: Some("syslog-jmagar-lab".into()),
            service: Some("cortex".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(target.confidence, TargetConfidence::Confirmed);
}

#[cfg(unix)]
fn output_with_status(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[cfg(unix)]
#[test]
fn systemd_status_distinguishes_inactive_from_probe_failure() {
    let active = systemd_status_from_output("cortex.service", &output_with_status(0, "", ""))
        .unwrap()
        .unwrap();
    assert!(active.active);

    let inactive =
        systemd_status_from_output("cortex.service", &output_with_status(3, "inactive\n", ""))
            .unwrap()
            .unwrap();
    assert!(!inactive.active);

    let failed = systemd_status_from_output(
        "cortex.service",
        &output_with_status(1, "", "dbus unavailable"),
    )
    .unwrap_err();
    assert!(failed.to_string().contains("probe failure") || failed.to_string().contains("failed"));
}

#[cfg(unix)]
#[test]
fn absent_systemctl_reports_no_unit_instead_of_a_probe_failure() {
    // GNU `timeout` exits 127 when the program is missing. cortex runs inside
    // a container with no systemd, so this is the ordinary case -- and a host
    // with no systemd cannot be running a conflicting cortex.service. It must
    // read as "no unit", not as an Error diagnostic that pins compose_doctor
    // red permanently.
    let absent = systemd_status_from_output(
        "cortex.service",
        &output_with_status(
            127,
            "",
            "timeout: failed to run command 'systemctl': No such file or directory",
        ),
    )
    .expect("absent systemctl must not be an error");
    assert!(
        absent.is_none(),
        "a host without systemd reports no unit, not an inactive one"
    );
}

#[cfg(unix)]
#[test]
fn absent_docker_cli_is_reported_as_a_missing_binary() {
    // The runtime image ships no docker client, so this is what
    // compose_status actually hits. The message has to name the cause --
    // a bare "docker inspect failed" sent this to a full investigation.
    let output = output_with_status(
        127,
        "",
        "timeout: failed to run command 'docker': No such file or directory",
    );
    let err = docker_cli_error("docker inspect", &output);
    let msg = err.to_string();
    assert!(msg.contains("not found on PATH"), "{msg}");
    assert!(msg.contains("DOCKER_HOST"), "{msg}");

    // A docker CLI that ran and failed keeps its own stderr.
    let ran = output_with_status(1, "", "Cannot connect to the Docker daemon");
    let ran_msg = docker_cli_error("docker inspect", &ran).to_string();
    assert!(
        ran_msg.contains("Cannot connect to the Docker daemon"),
        "{ran_msg}"
    );
    assert!(!ran_msg.contains("not found on PATH"), "{ran_msg}");
}

#[test]
fn docker_unavailable_code_uses_typed_error() {
    let err: anyhow::Error = DockerUnavailableError("daemon is down".into()).into();
    assert_eq!(unresolved_code(&err), DIAG_DOCKER_UNAVAILABLE);

    let plain_err = anyhow::anyhow!("docker unavailable: text only");
    assert_eq!(unresolved_code(&plain_err), DIAG_TARGET_UNRESOLVED);
}

#[test]
fn status_reports_systemd_check_failures_as_diagnostics() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            systemd_error: Some("systemctl unavailable".into()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    assert_eq!(status.diagnostics[0].code, DIAG_SYSTEMD_CHECK_FAILED);
    assert_eq!(status.diagnostics[0].severity, DiagnosticSeverity::Error);
}

#[test]
fn status_errors_when_data_volume_has_unexpected_name() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_VOLUME_NAME"]);
    env.set("CORTEX_DATA_VOLUME", "");
    env.remove("CORTEX_VOLUME_NAME");

    // Regression guard: if the container was started with a stale COMPOSE_PROJECT_NAME
    // the named volume gets an unexpected prefix (e.g. "compose_cortex-data" instead
    // of "cortex-data"). The status check must detect and surface this as an Error.
    let mut container = labelled_container();
    container.mounts[0].kind = "volume".into();
    container.mounts[0].volume_name = Some("compose_cortex-data".into()); // wrong prefix
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    let drift = status
        .diagnostics
        .iter()
        .find(|d| d.code == "data_mount_unexpected")
        .expect("drift diagnostic must be present");
    assert_eq!(drift.severity, DiagnosticSeverity::Error);
    assert!(drift.message.contains("compose_cortex-data"));

    // Sanity: a named volume with the correct name should NOT produce an error.
    let mut good_container = labelled_container();
    good_container.mounts[0].kind = "volume".into();
    good_container.mounts[0].volume_name = Some("cortex-data".into()); // correct name
    let good_service = ComposeService::new(
        FakeInspector {
            container: Some(good_container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let good_status = good_service.status(&ComposeTarget::default()).unwrap();
    assert!(
        good_status
            .diagnostics
            .iter()
            .all(|d| d.code != "data_mount_unexpected"),
        "correct named volume must not produce drift error"
    );
}

#[test]
fn status_errors_when_bind_mount_does_not_match_configured_data_volume() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "/home/jmagar/.cortex/data");
    env.remove("CORTEX_ENV_FILE");

    let mut container = labelled_container();
    container.mounts[0].kind = "bind".into();
    container.mounts[0].source = Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"));
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    let drift = status
        .diagnostics
        .iter()
        .find(|d| d.code == "data_mount_unexpected")
        .expect("bind drift diagnostic must be present");
    assert_eq!(drift.severity, DiagnosticSeverity::Error);
    assert!(drift.message.contains("/home/jmagar/.cortex/data"));
}

#[test]
fn status_expected_data_mount_uses_configured_env_file() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_ENV_FILE", "CORTEX_DATA_VOLUME", "CORTEX_HOME"]);
    env.remove("CORTEX_DATA_VOLUME");
    env.remove("CORTEX_HOME");
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let env_file = dir.path().join("syslog.env");
    std::fs::write(
        &env_file,
        format!("CORTEX_DATA_VOLUME=\"{}\"\n", data_dir.display()),
    )
    .unwrap();
    env.set("CORTEX_ENV_FILE", env_file.to_str().unwrap());

    let mut container = labelled_container();
    container.mounts[0].kind = "bind".into();
    container.mounts[0].volume_name = None;
    container.mounts[0].source = Some(data_dir);
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    assert!(
        status
            .diagnostics
            .iter()
            .all(|d| d.code != "data_mount_unexpected"),
        "CORTEX_ENV_FILE should drive the same /data expectation as compose invocation"
    );
}

#[test]
fn status_expected_data_mount_uses_cortex_home_env_file() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_ENV_FILE", "CORTEX_DATA_VOLUME", "CORTEX_HOME"]);
    env.remove("CORTEX_ENV_FILE");
    env.remove("CORTEX_DATA_VOLUME");
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join(".cortex");
    let data_dir = home_dir.join("data");
    std::fs::create_dir(&home_dir).unwrap();
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::write(
        home_dir.join(".env"),
        format!("CORTEX_DATA_VOLUME=\"{}\"\n", data_dir.display()),
    )
    .unwrap();
    env.set("CORTEX_HOME", home_dir.to_str().unwrap());

    let mut container = labelled_container();
    container.mounts[0].kind = "bind".into();
    container.mounts[0].volume_name = None;
    container.mounts[0].source = Some(data_dir);
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    assert!(
        status
            .diagnostics
            .iter()
            .all(|d| d.code != "data_mount_unexpected"),
        "CORTEX_HOME .env should drive the same /data expectation as compose invocation"
    );
}

#[test]
fn status_errors_when_data_volume_is_missing() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");
    let mut container = labelled_container();
    container.mounts.clear(); // no /data mount at all
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );

    let status = service.status(&ComposeTarget::default()).unwrap();

    let missing = status
        .diagnostics
        .iter()
        .find(|d| d.code == "data_volume_missing")
        .expect("missing-volume diagnostic must be present");
    assert_eq!(missing.severity, DiagnosticSeverity::Error);
}

#[test]
fn containers_without_required_compose_labels_are_unsafe_for_mutation() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(unlabelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = service.resolve_target(&ComposeTarget::default()).unwrap();
    assert_eq!(target.source, TargetSource::LiveContainerLabels);
    assert_eq!(target.confidence, TargetConfidence::Unsafe);
    assert_eq!(target.diagnostics[0].code, "incomplete_compose_labels");
    let err = service
        .preflight_mutation(ComposeMutation::Down, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("required compose labels"));
}

#[test]
fn partial_compose_labels_are_unsafe_for_mutation() {
    let mut container = labelled_container();
    container
        .labels
        .remove("com.docker.compose.project.config_files");
    let service = ComposeService::new(
        FakeInspector {
            container: Some(container),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = service.resolve_target(&ComposeTarget::default()).unwrap();
    assert_eq!(target.confidence, TargetConfidence::Unsafe);
    let err = service
        .preflight_mutation(
            ComposeMutation::Restart,
            &target,
            &MutationOptions::default(),
        )
        .unwrap_err();
    assert!(err.to_string().contains("required compose labels"));
}

#[test]
fn project_name_alone_is_rejected_for_mutation() {
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: None,
            compose_file: None,
            project_name: Some("cortex".into()),
            service: "cortex".into(),
            container_name: "cortex".into(),
        },
        source: TargetSource::Explicit,
        confidence: TargetConfidence::Confirmed,
        diagnostics: Vec::new(),
        compose_files: Vec::new(),
        compose_working_dir: None,
        compose_project: Some("cortex".into()),
    };
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("--project-name alone"));
}

#[test]
fn up_refuses_active_systemd_owner() {
    let service = ComposeService::new(
        FakeInspector {
            systemd: Some(SystemdStatus {
                unit: "cortex.service".into(),
                active: true,
            }),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("systemd"));
}

#[test]
fn mutation_refuses_unverified_systemd_or_listener_state() {
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let systemd_service = ComposeService::new(
        FakeInspector {
            systemd_error: Some("systemctl unavailable".into()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let err = systemd_service
        .preflight_mutation(
            ComposeMutation::Restart,
            &target,
            &MutationOptions::default(),
        )
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("could not verify systemd ownership")
    );

    let listener_service = ComposeService::new(
        FakeInspector {
            listeners_error: Some("ss unavailable".into()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let err = listener_service
        .preflight_mutation(
            ComposeMutation::Restart,
            &target,
            &MutationOptions::default(),
        )
        .unwrap_err();
    assert!(err.to_string().contains("could not verify port listeners"));
}

#[test]
fn pull_does_not_require_systemd_or_listener_probes() {
    let service = ComposeService::new(
        FakeInspector {
            systemd_error: Some("systemctl unavailable".into()),
            listeners_error: Some("ss unavailable".into()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());

    service
        .preflight_mutation(ComposeMutation::Pull, &target, &MutationOptions::default())
        .unwrap();
}

#[test]
fn down_requires_yes_and_stops_only_target_service() {
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(
            ComposeMutation::Down,
            &target,
            &MutationOptions {
                non_interactive: true,
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("--yes"));

    service
        .preflight_mutation(
            ComposeMutation::Down,
            &target,
            &MutationOptions {
                non_interactive: true,
                yes: true,
                ..Default::default()
            },
        )
        .unwrap();
    let invocation = service.compose_invocation(&target, ComposeMutation::Down);
    assert!(invocation.args.ends_with(&["stop".into(), "cortex".into()]));
    assert!(!invocation.args.iter().any(|arg| arg == "down"));
}

#[test]
fn up_refuses_non_target_listener() {
    let service = ComposeService::new(
        FakeInspector {
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("users:((\"other\",pid=123,fd=7))".into()),
                belongs_to_target: false,
            }],
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let mut target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    target.source = TargetSource::Explicit;
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("non-target listener"));
}

#[test]
fn live_target_allows_listener_on_published_target_port() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let mut owners = BTreeMap::new();
    owners.insert(3100, "abc".into());
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("users:((\"docker-proxy\",pid=123,fd=7))".into()),
                belongs_to_target: false,
            }],
            published_port_owners: owners,
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap();
}

#[test]
fn live_target_refuses_foreign_docker_proxy_on_published_port() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let mut owners = BTreeMap::new();
    owners.insert(3100, "foreign-container".into());
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("users:((\"docker-proxy\",pid=123,fd=7))".into()),
                belongs_to_target: false,
            }],
            published_port_owners: owners,
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("non-target listener"));
}

#[test]
fn live_target_refuses_listener_on_unpublished_target_port() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 1514,
                process: Some("other".into()),
                belongs_to_target: false,
            }],
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("non-target listener"));
}

#[test]
fn live_target_refuses_foreign_listener_even_on_published_port() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("users:((\"other\",pid=123,fd=7))".into()),
                belongs_to_target: false,
            }],
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("non-target listener"));
}

#[test]
fn live_target_refuses_published_listener_with_unknown_owner() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("LISTEN 0 4096 0.0.0.0:3100 0.0.0.0:*".into()),
                belongs_to_target: false,
            }],
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let err = service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("non-target listener"));
}

#[test]
fn live_target_allows_listener_without_process_info_when_docker_confirms_owner() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_DATA_VOLUME", "CORTEX_ENV_FILE"]);
    env.set("CORTEX_DATA_VOLUME", "cortex-data");
    env.remove("CORTEX_ENV_FILE");

    // Non-root scenario: ss cannot report process names so the listener has no
    // "users:" field, but docker ps confirms the target container owns the port.
    let mut owners = BTreeMap::new();
    owners.insert(3100, "abc".into());
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            listeners: vec![ListenerInfo {
                port: 3100,
                process: Some("LISTEN 0 4096 0.0.0.0:3100 0.0.0.0:*".into()),
                belongs_to_target: false,
            }],
            published_port_owners: owners,
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    service
        .preflight_mutation(ComposeMutation::Up, &target, &MutationOptions::default())
        .unwrap();
}

#[test]
fn up_invocation_is_detached_and_uses_project_directory_and_all_files() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_ENV_FILE", "CORTEX_HOME", "CORTEX_COMPOSE_PROGRAM"]);
    env.remove("CORTEX_ENV_FILE");
    env.remove("CORTEX_COMPOSE_PROGRAM");
    let dir = tempfile::tempdir().unwrap();
    let empty_home = dir.path().join(".cortex");
    std::fs::create_dir(&empty_home).unwrap();
    env.set("CORTEX_HOME", empty_home.to_str().unwrap());
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: Some(PathBuf::from("/tmp/project")),
            compose_file: Some(PathBuf::from("/tmp/project/base.yml")),
            project_name: Some("syslog-jmagar-lab".into()),
            service: "cortex".into(),
            container_name: "cortex".into(),
        },
        source: TargetSource::LiveContainerLabels,
        confidence: TargetConfidence::Confirmed,
        diagnostics: Vec::new(),
        compose_files: vec![
            PathBuf::from("/tmp/project/base.yml"),
            PathBuf::from("/tmp/project/override.yml"),
        ],
        compose_working_dir: Some(PathBuf::from("/tmp/project")),
        compose_project: Some("syslog-jmagar-lab".into()),
    };

    let invocation = service.compose_invocation(&target, ComposeMutation::Up);
    assert_eq!(invocation.program, "docker");
    assert_eq!(invocation.current_dir, Some(PathBuf::from("/tmp/project")));
    assert_eq!(
        invocation.args,
        vec![
            "compose",
            "--project-directory",
            "/tmp/project",
            "-f",
            "/tmp/project/base.yml",
            "-f",
            "/tmp/project/override.yml",
            "--project-name",
            "syslog-jmagar-lab",
            "up",
            "-d",
            "cortex",
        ]
    );
}

#[test]
fn compose_invocation_honors_explicit_compose_program() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_COMPOSE_PROGRAM"]);
    env.set("CORTEX_COMPOSE_PROGRAM", "/run/cortex/compose-runner");
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());

    let invocation = service.logs_invocation(&target, 20);

    assert_eq!(invocation.program, "/run/cortex/compose-runner");
    assert_eq!(invocation.args.first().map(String::as_str), Some("compose"));
}

#[test]
fn compose_invocation_uses_syslog_env_file_for_substitution() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_ENV_FILE"]);
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("runtime.env");
    std::fs::write(&env_file, "CORTEX_DATA_VOLUME=/tmp/syslog-data\n").unwrap();
    env.set("CORTEX_ENV_FILE", env_file.to_str().unwrap());
    let compose_file = dir.path().join("docker-compose.yml");
    std::fs::write(&compose_file, "services: {}\n").unwrap();

    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: Some(dir.path().to_path_buf()),
            compose_file: Some(compose_file.clone()),
            project_name: Some("syslog-jmagar-lab".into()),
            service: "cortex".into(),
            container_name: "cortex".into(),
        },
        source: TargetSource::Explicit,
        confidence: TargetConfidence::Confirmed,
        diagnostics: Vec::new(),
        compose_files: vec![compose_file],
        compose_working_dir: Some(dir.path().to_path_buf()),
        compose_project: Some("syslog-jmagar-lab".into()),
    };

    let invocation = service.compose_invocation(&target, ComposeMutation::Up);

    assert!(
        invocation
            .args
            .windows(2)
            .any(|args| { args[0] == "--env-file" && args[1] == env_file.display().to_string() })
    );
    assert_eq!(
        invocation.env,
        vec![(
            "CORTEX_ENV_FILE".to_string(),
            env_file.display().to_string()
        )]
    );
}

#[test]
fn compose_invocation_uses_cortex_home_env_file_for_substitution_and_service_env() {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let env = EnvGuard::new(&["CORTEX_ENV_FILE", "CORTEX_HOME"]);
    env.remove("CORTEX_ENV_FILE");
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    let home_dir = dir.path().join(".cortex");
    std::fs::create_dir(&project_dir).unwrap();
    std::fs::create_dir(&home_dir).unwrap();
    let home_env = home_dir.join(".env");
    std::fs::write(&home_env, "CORTEX_DATA_VOLUME=/tmp/cortex-data\n").unwrap();
    env.set("CORTEX_HOME", home_dir.to_str().unwrap());
    let compose_file = project_dir.join("docker-compose.yml");
    std::fs::write(&compose_file, "services: {}\n").unwrap();

    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: Some(project_dir.clone()),
            compose_file: Some(compose_file.clone()),
            project_name: Some("cortex".into()),
            service: "cortex".into(),
            container_name: "cortex".into(),
        },
        source: TargetSource::Explicit,
        confidence: TargetConfidence::Confirmed,
        diagnostics: Vec::new(),
        compose_files: vec![compose_file],
        compose_working_dir: Some(project_dir),
        compose_project: Some("cortex".into()),
    };

    let invocation = service.compose_invocation(&target, ComposeMutation::Up);

    assert!(
        invocation
            .args
            .windows(2)
            .any(|args| { args[0] == "--env-file" && args[1] == home_env.display().to_string() })
    );
    assert_eq!(
        invocation.env,
        vec![(
            "CORTEX_ENV_FILE".to_string(),
            home_env.display().to_string()
        )]
    );
}

#[test]
fn mutation_invocations_scope_service_where_supported() {
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    for (mutation, expected) in [
        (ComposeMutation::Pull, vec!["pull", "cortex"]),
        (ComposeMutation::Restart, vec!["restart", "cortex"]),
        (ComposeMutation::Down, vec!["stop", "cortex"]),
    ] {
        let invocation = service.compose_invocation(&target, mutation);
        assert!(
            invocation
                .args
                .ends_with(&expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "unexpected args for {mutation:?}: {:?}",
            invocation.args
        );
    }
}

#[test]
fn dry_run_does_not_invoke_runner() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(labelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let result = service
        .run_mutation(
            ComposeMutation::Pull,
            &ComposeTarget::default(),
            &MutationOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
    let ComposeCommandResult::DryRun(dry_run) = result else {
        panic!("expected dry-run result");
    };
    assert!(dry_run.dry_run);
    assert!(dry_run.command.ends_with(&["pull".into(), "cortex".into()]));
    assert_eq!(dry_run.preflight, "passed");
}

#[derive(Default)]
struct RecordingRunner {
    invocations: std::sync::Mutex<Vec<ComposeInvocation>>,
    backup_source: PathBuf,
}

impl CommandRunner for RecordingRunner {
    fn run(&self, invocation: &ComposeInvocation) -> Result<CommandOutput> {
        self.invocations.lock().unwrap().push(invocation.clone());
        let is_config =
            invocation
                .args
                .ends_with(&["config".into(), "--format".into(), "json".into()]);
        Ok(CommandOutput {
            exit_status: Some(0),
            stdout: if is_config {
                serde_json::json!({
                    "services": {
                        "cortex": {"volumes": [{
                            "type": "bind",
                            "source": self.backup_source,
                            "target": "/backups"
                        }]}
                    }
                })
                .to_string()
            } else {
                String::new()
            },
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            timeout_cleanup: None,
        })
    }
}

#[test]
fn compose_up_provisions_resolved_backup_bind_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    let compose_file = dir.path().join("docker-compose.yml");
    std::fs::write(&compose_file, "services: {cortex: {}}\n").unwrap();
    let backup_source = dir.path().join("custom-backups");
    let service = ComposeService::new(
        FakeInspector::default(),
        RecordingRunner {
            invocations: Default::default(),
            backup_source: backup_source.clone(),
        },
        ComposeDefaults::default(),
    );
    service
        .run_mutation(
            ComposeMutation::Up,
            &ComposeTarget {
                project_dir: Some(dir.path().to_path_buf()),
                compose_file: Some(compose_file),
                ..Default::default()
            },
            &MutationOptions::default(),
        )
        .unwrap();

    assert!(backup_source.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup_source)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let invocations = service.runner.invocations.lock().unwrap();
    assert!(
        invocations[0]
            .args
            .ends_with(&["config".into(), "--format".into(), "json".into()])
    );
    assert!(
        invocations[1]
            .args
            .ends_with(&["up".into(), "-d".into(), "cortex".into()])
    );
}

#[test]
fn compose_up_dry_run_does_not_provision_backup_bind() {
    let dir = tempfile::tempdir().unwrap();
    let compose_file = dir.path().join("docker-compose.yml");
    std::fs::write(&compose_file, "services: {cortex: {}}\n").unwrap();
    let backup_source = dir.path().join("must-not-exist");
    let service = ComposeService::new(
        FakeInspector::default(),
        RecordingRunner {
            invocations: Default::default(),
            backup_source: backup_source.clone(),
        },
        ComposeDefaults::default(),
    );
    service
        .run_mutation(
            ComposeMutation::Up,
            &ComposeTarget {
                project_dir: Some(dir.path().to_path_buf()),
                compose_file: Some(compose_file),
                ..Default::default()
            },
            &MutationOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!backup_source.exists());
    assert!(service.runner.invocations.lock().unwrap().is_empty());
}

#[test]
fn logs_invocation_is_bounded_tail() {
    let service = ComposeService::new(
        FakeInspector::default(),
        FakeRunner,
        ComposeDefaults::default(),
    );
    let target = target_from_container(&labelled_container(), &ComposeDefaults::default());
    let invocation = service.logs_invocation(&target, 20);
    assert!(invocation.args.ends_with(&[
        "logs".into(),
        "--tail".into(),
        "20".into(),
        "cortex".into(),
    ]));
}

#[test]
fn logs_refuses_unsafe_target() {
    let service = ComposeService::new(
        FakeInspector {
            container: Some(unlabelled_container()),
            ..Default::default()
        },
        FakeRunner,
        ComposeDefaults::default(),
    );
    let err = service
        .logs(&ComposeTarget::default(), Some(20))
        .unwrap_err();
    assert!(err.to_string().contains("target is not confirmed"));
}

#[cfg(unix)]
#[test]
fn process_runner_truncates_and_redacts_output() {
    let runner = ProcessRunner;
    let invocation = ComposeInvocation {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            "printf 'token=secret-value\\nvisible-line\\nmore-output\\n'".into(),
        ],
        env: Vec::new(),
        current_dir: None,
        timeout: Duration::from_secs(5),
        output_limit_bytes: 32,
    };
    let output = runner.run(&invocation).unwrap();
    assert_eq!(output.exit_status, Some(0));
    assert!(output.stdout.contains("[REDACTED]"));
    assert!(!output.stdout.contains("secret-value"));
    assert!(output.stdout_truncated);
}

#[cfg(unix)]
#[test]
fn process_runner_applies_invocation_env() {
    let runner = ProcessRunner;
    let invocation = ComposeInvocation {
        program: "sh".into(),
        args: vec!["-c".into(), "printf '%s' \"$CORTEX_ENV_FILE\"".into()],
        env: vec![("CORTEX_ENV_FILE".into(), "/tmp/cortex-home.env".into())],
        current_dir: None,
        timeout: Duration::from_secs(5),
        output_limit_bytes: 1024,
    };

    let output = runner.run(&invocation).unwrap();

    assert_eq!(output.exit_status, Some(0));
    assert_eq!(output.stdout, "/tmp/cortex-home.env");
}

#[cfg(unix)]
#[test]
fn process_runner_times_out_and_reports_cleanup() {
    let runner = ProcessRunner;
    let invocation = ComposeInvocation {
        program: "sh".into(),
        args: vec!["-c".into(), "sleep 5".into()],
        env: Vec::new(),
        current_dir: None,
        timeout: Duration::from_millis(100),
        output_limit_bytes: 1024,
    };
    let output = runner.run(&invocation).unwrap();
    assert!(output.timed_out);
    assert!(output.timeout_cleanup.as_ref().is_some_and(|c| c.reaped));
}

#[cfg(unix)]
#[test]
fn process_runner_kills_term_ignoring_process_group() {
    let runner = ProcessRunner;
    let invocation = ComposeInvocation {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            "trap '' TERM; sh -c 'trap \"\" TERM; while true; do sleep 1; done' & wait".into(),
        ],
        env: Vec::new(),
        current_dir: None,
        timeout: Duration::from_millis(100),
        output_limit_bytes: 1024,
    };
    let output = runner.run(&invocation).unwrap();
    assert!(output.timed_out);
    let cleanup = output.timeout_cleanup.unwrap();
    assert!(cleanup.terminate_sent);
    assert!(cleanup.kill_sent);
    assert!(cleanup.reaped);
}

#[test]
fn pipe_reader_surfaces_non_interrupted_read_failure() {
    struct PrefixThenError(bool);
    impl std::io::Read for PrefixThenError {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                Err(std::io::Error::other("injected pipe failure"))
            } else {
                self.0 = true;
                buffer[..6].copy_from_slice(b"prefix");
                Ok(6)
            }
        }
    }

    let target = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), false)));
    let handle = super::runner::drain_pipe_for_test(
        PrefixThenError(false),
        std::sync::Arc::clone(&target),
        1024,
    );
    let error = handle.join().unwrap().unwrap_err();
    assert_eq!(error.to_string(), "injected pipe failure");
    assert_eq!(target.lock().unwrap().0, b"prefix");
}

#[test]
fn compose_host_allowlist_is_operator_configurable_with_safe_internal_default() {
    for compose in [
        include_str!("../docker-compose.yml"),
        include_str!("../docker-compose.prod.yml"),
    ] {
        assert!(
            compose
                .contains("CORTEX_ALLOWED_HOSTS: \"cortex,cortex:3100,${CORTEX_ALLOWED_HOSTS:-}\"")
        );
    }
}
