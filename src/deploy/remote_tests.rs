use super::super::remote_support::{RemoteOutput, RemoteRunner};
use super::*;

#[derive(Default)]
struct FakeRemoteRunner {
    commands: Vec<String>,
    fail_contains: Option<&'static str>,
    error_contains: Option<&'static str>,
    existing_env: Option<String>,
}

impl FakeRemoteRunner {
    fn ok() -> Self {
        Self::default()
    }

    fn fail_on(needle: &'static str) -> Self {
        Self {
            commands: Vec::new(),
            fail_contains: Some(needle),
            error_contains: None,
            existing_env: None,
        }
    }

    fn error_on(needle: &'static str) -> Self {
        Self {
            commands: Vec::new(),
            fail_contains: None,
            error_contains: Some(needle),
            existing_env: None,
        }
    }

    fn with_existing_env(existing_env: impl Into<String>) -> Self {
        Self {
            commands: Vec::new(),
            fail_contains: None,
            error_contains: None,
            existing_env: Some(existing_env.into()),
        }
    }
}

impl RemoteRunner for FakeRemoteRunner {
    fn run(&mut self, host: &str, script: &str, _stdin: Option<&str>) -> io::Result<RemoteOutput> {
        self.commands.push(format!("{host}: {script}"));
        if self
            .error_contains
            .is_some_and(|needle| script.contains(needle))
        {
            return Err(io::Error::new(io::ErrorKind::NotFound, "ssh not found"));
        }
        if self
            .fail_contains
            .is_some_and(|needle| script.contains(needle))
        {
            return Ok(RemoteOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "forced failure\n".to_string(),
            });
        }
        let stdout = if script.contains("cat ")
            && (script.contains("/.env'") || script.contains("/compose/.env'"))
        {
            self.existing_env.clone().unwrap_or_default()
        } else if script.contains("id -u") {
            "/home/syslog\n1001\n1002\n".to_string()
        } else {
            "ok\n".to_string()
        };
        Ok(RemoteOutput {
            status_success: true,
            stdout,
            stderr: String::new(),
        })
    }
}

#[test]
fn remote_dry_run_only_checks_ssh_and_docker() {
    let mut runner = FakeRemoteRunner::ok();
    let report = run_remote_deploy_with_runner("host-a", true, &mut runner).unwrap();

    assert_eq!(report.host, "host-a");
    assert!(
        runner
            .commands
            .iter()
            .any(|cmd| cmd.contains("docker --version"))
    );
    assert!(
        !runner
            .commands
            .iter()
            .any(|cmd| cmd.contains("docker compose") && cmd.contains("up -d"))
    );
    assert!(
        !runner
            .commands
            .iter()
            .any(|cmd| cmd.contains("cat > ~/.cortex/.env"))
    );
}

#[test]
fn remote_repair_writes_assets_before_compose_up() {
    let mut runner = FakeRemoteRunner::ok();
    let report = run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    assert!(!report.has_errors);
    let index = |needle: &str| {
        runner
            .commands
            .iter()
            .position(|cmd| cmd.contains(needle))
            .unwrap_or_else(|| panic!("missing command containing {needle}"))
    };
    let mkdir = index(
        "mkdir -p '/home/syslog/.cortex/compose/config' '/home/syslog/.cortex/data' '/home/syslog/.cortex/backups' && chmod 700 '/home/syslog/.cortex/backups'",
    );
    let docker_check = index("docker --version && docker compose version");
    let env_write = index("cat > '/home/syslog/.cortex/.env.tmp'");
    let assets_write = index("docker-compose.yml.tmp");
    let compose_pull = index("pull --ignore-buildable");
    let compose_up = index("up -d");
    assert!(mkdir < docker_check);
    assert!(docker_check < env_write);
    assert!(env_write < assets_write);
    assert!(assets_write < compose_pull);
    assert!(compose_pull < compose_up);
}

#[test]
fn remote_repair_health_check_retries_after_compose_up() {
    let mut runner = FakeRemoteRunner::ok();
    run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    let health = runner
        .commands
        .iter()
        .find(|cmd| cmd.contains("http://127.0.0.1:3100/health"))
        .expect("remote health command should run");
    assert!(health.contains("while [ \"$attempt\" -lt 30 ]"));
    assert!(health.contains("sleep 1"));
}

#[test]
fn remote_repair_home_override_targets_existing_home_and_preserves_remote_env() {
    let mut runner = FakeRemoteRunner::with_existing_env(
        "CORTEX_AUTH_MODE=oauth\nCORTEX_VERSION=dev\nCORTEX_TOKEN=keep-token\n",
    );
    let report = run_remote_deploy_with_runner(
        "nashost",
        RemoteDeployOptions {
            dry_run: false,
            home: Some("/mnt/cache/appdata/cortex".to_string()),
        },
        &mut runner,
    )
    .unwrap();

    assert!(!report.has_errors);
    assert_eq!(report.home, "/mnt/cache/appdata/cortex");
    assert_eq!(report.env_path, "/mnt/cache/appdata/cortex/.env");
    assert_eq!(report.compose_dir, "/mnt/cache/appdata/cortex/compose");
    assert_eq!(report.data_dir, "/mnt/cache/appdata/cortex/data");
    assert!(
        runner
            .commands
            .iter()
            .any(|cmd| cmd.contains("cat '/mnt/cache/appdata/cortex/.env'")
                && cmd.contains("cat '/mnt/cache/appdata/cortex/compose/.env'"))
    );
    assert!(runner.commands.iter().any(|cmd| cmd.contains(
        "mkdir -p '/mnt/cache/appdata/cortex/compose/config' '/mnt/cache/appdata/cortex/data' '/mnt/cache/appdata/cortex/backups' && chmod 700 '/mnt/cache/appdata/cortex/backups'"
    )));
    let env_write = runner
        .commands
        .iter()
        .find(|cmd| cmd.contains("cat > '/mnt/cache/appdata/cortex/.env.tmp'"))
        .expect("env write command should target the override home");
    assert!(env_write.contains("CORTEX_AUTH_MODE=oauth"));
    assert!(env_write.contains("CORTEX_TOKEN=keep-token"));
    assert!(!env_write.contains("CORTEX_VERSION=dev"));
    assert!(env_write.contains("CORTEX_DATA_VOLUME=/mnt/cache/appdata/cortex/data"));
    assert!(env_write.contains("CORTEX_BACKUP_DIR=/mnt/cache/appdata/cortex/backups"));
    assert!(env_write.contains(
        "mv '/mnt/cache/appdata/cortex/compose/.env' '/mnt/cache/appdata/cortex/compose/.env.legacy'"
    ));
    assert!(env_write.contains("chmod 600 '/mnt/cache/appdata/cortex/compose/.env.legacy'"));
    assert!(!runner.commands.iter().any(|cmd| cmd.contains("~/.cortex")));
}

#[test]
fn remote_deploy_preserves_and_provisions_custom_backup_bind_before_up() {
    let mut runner =
        FakeRemoteRunner::with_existing_env("CORTEX_BACKUP_DIR=/srv/cortex-recovery\n");
    run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    let index = |needle: &str| {
        runner
            .commands
            .iter()
            .position(|cmd| cmd.contains(needle))
            .unwrap_or_else(|| panic!("missing command containing {needle}"))
    };
    let provision = index(
        "mkdir -p '/home/syslog/.cortex/compose/config' '/home/syslog/.cortex/data' '/srv/cortex-recovery' && chmod 700 '/srv/cortex-recovery'",
    );
    let compose_up = index("up -d");
    assert!(provision < compose_up);
}

#[test]
fn remote_dry_run_does_not_provision_backup_bind() {
    let mut runner = FakeRemoteRunner::ok();
    run_remote_deploy_with_runner("host-a", true, &mut runner).unwrap();
    assert!(
        !runner
            .commands
            .iter()
            .any(|command| { command.contains("backups") || command.contains("chmod 700") })
    );
}

#[test]
fn remote_env_uses_remote_uid_and_gid() {
    let mut runner = FakeRemoteRunner::ok();
    let report = run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    let env_write = runner
        .commands
        .iter()
        .find(|cmd| cmd.contains(&format!("cat > '{}/.env.tmp'", report.home)))
        .expect("env write command should run");
    assert!(env_write.contains("CORTEX_UID=1001"));
    assert!(env_write.contains("CORTEX_GID=1002"));
}

#[test]
fn remote_deploy_skips_mutations_after_identity_failure() {
    let mut runner = FakeRemoteRunner::fail_on("id -u");
    let report = run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    assert!(report.has_errors);
    assert!(!runner.commands.iter().any(|cmd| cmd.contains("up -d")));
    assert!(report.phases.iter().any(|phase| {
        phase.name == "remote-compose-up" && matches!(phase.status, SetupStatus::Skipped)
    }));
}

#[test]
fn remote_deploy_reports_identity_spawn_error_as_phase_failure() {
    let mut runner = FakeRemoteRunner::error_on("id -u");
    let report = run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    assert!(report.has_errors);
    let identity = report
        .phases
        .iter()
        .find(|phase| phase.name == "remote-identity")
        .expect("identity phase should be present");
    assert!(matches!(identity.status, SetupStatus::Error));
    assert!(identity.detail.contains("ssh failed"));
    assert!(!runner.commands.iter().any(|cmd| cmd.contains("up -d")));
}

#[test]
fn remote_deploy_does_not_source_env_as_shell() {
    let mut runner = FakeRemoteRunner::ok();
    run_remote_deploy_with_runner("host-a", false, &mut runner).unwrap();

    assert!(
        !runner
            .commands
            .iter()
            .any(|cmd| cmd.contains(". ~/.cortex/.env"))
    );
}

#[test]
fn remote_deploy_rejects_option_like_hosts_before_running_ssh() {
    let mut runner = FakeRemoteRunner::ok();

    let error = run_remote_deploy_with_runner("-oProxyCommand=touch /tmp/pwned", true, &mut runner)
        .unwrap_err();

    assert!(error.to_string().contains("unsafe ssh host"));
    assert!(runner.commands.is_empty());
}

#[test]
fn remote_deploy_rejects_relative_home_before_running_ssh() {
    let mut runner = FakeRemoteRunner::ok();

    let error = run_remote_deploy_with_runner(
        "nashost",
        RemoteDeployOptions {
            dry_run: true,
            home: Some("relative/path".to_string()),
        },
        &mut runner,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("--home must be an absolute path")
    );
    assert!(runner.commands.is_empty());
}

#[test]
fn remote_deploy_accepts_safe_hosts() {
    let mut runner = FakeRemoteRunner::ok();

    let report = run_remote_deploy_with_runner("nashost", true, &mut runner).unwrap();

    assert_eq!(report.host, "nashost");
    assert!(
        runner
            .commands
            .iter()
            .all(|command| command.starts_with("nashost:"))
    );
}
