use std::io;
use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use super::remote_support::{
    RemoteRunner, SshRemoteRunner, append_skipped, phases_have_errors, remote_identity_phase,
    remote_phase, shell_quote, skip_phase,
};
use crate::setup::{
    SetupPhase, SetupStatus, default_env_for_data_dir, dockerfile_asset, installed_compose_asset,
    parse_env, render_env,
};

const REMOTE_HOME_SUFFIX: &str = ".cortex";

#[derive(Debug, Clone, Default)]
pub struct RemoteDeployOptions {
    pub dry_run: bool,
    pub home: Option<String>,
}

impl From<bool> for RemoteDeployOptions {
    fn from(dry_run: bool) -> Self {
        Self {
            dry_run,
            home: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDeployReport {
    pub mode: &'static str,
    pub host: String,
    pub home: String,
    pub env_path: String,
    pub compose_dir: String,
    pub data_dir: String,
    pub health_url: String,
    pub mcp_url: String,
    pub phases: Vec<SetupPhase>,
    pub has_errors: bool,
    pub elapsed_ms: u128,
}

pub fn run_remote_deploy(
    host: &str,
    options: impl Into<RemoteDeployOptions>,
) -> io::Result<RemoteDeployReport> {
    let mut runner = SshRemoteRunner;
    run_remote_deploy_with_runner(host, options, &mut runner)
}

fn run_remote_deploy_with_runner(
    host: &str,
    options: impl Into<RemoteDeployOptions>,
    runner: &mut dyn RemoteRunner,
) -> io::Result<RemoteDeployReport> {
    let options = options.into();
    let dry_run = options.dry_run;
    if !crate::inventory::ssh::is_safe_ssh_host(host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe ssh host: {host}"),
        ));
    }
    let remote_home_override = options
        .home
        .as_deref()
        .map(validate_remote_home)
        .transpose()?;
    let started = Instant::now();
    let mut phases = Vec::new();

    let ssh_phase = remote_phase(runner, host, "ssh", "true", None)?;
    phases.push(ssh_phase);

    let identity = remote_identity_phase(runner, host)?;
    let identity_values = identity.values;
    phases.push(identity.phase);
    let Some(identity_values) = identity_values else {
        append_skipped(
            &mut phases,
            &[
                "remote-filesystem",
                "remote-env",
                "remote-compose-assets",
                "remote-docker",
                "remote-docker-network",
                "remote-compose-pull",
                "remote-compose-up",
                "remote-health",
            ],
            "skipped because remote identity failed",
        );
        return Ok(report(
            host,
            dry_run,
            "$HOME/.cortex",
            "$HOME/.cortex/data",
            "3100",
            phases,
            started.elapsed().as_millis(),
        ));
    };
    let remote_home = remote_home_override
        .unwrap_or_else(|| format!("{}/{}", identity_values.home, REMOTE_HOME_SUFFIX));
    let remote_data_dir = format!("{remote_home}/data");
    let mut env = default_env_for_data_dir(Path::new(&remote_data_dir))?;
    env.insert("CORTEX_DATA_VOLUME".to_string(), remote_data_dir.clone());
    env.insert(
        "CORTEX_BACKUP_DIR".to_string(),
        format!("{remote_home}/backups"),
    );
    env.insert("CORTEX_UID".to_string(), identity_values.uid.clone());
    env.insert("CORTEX_GID".to_string(), identity_values.gid.clone());
    if !dry_run {
        let existing_env = read_existing_remote_env(runner, host, &remote_home)?;
        for (key, value) in parse_env(&existing_env) {
            if key == "CORTEX_VERSION" {
                continue;
            }
            env.insert(key, value);
        }
    }
    let docker_network = env
        .get("DOCKER_NETWORK")
        .cloned()
        .unwrap_or_else(|| "cortex".to_string());
    let mcp_port = env
        .get("CORTEX_PORT")
        .cloned()
        .unwrap_or_else(|| "3100".to_string());
    let remote_backup_dir = env
        .get("CORTEX_BACKUP_DIR")
        .expect("remote backup default is always populated");
    validate_remote_absolute_path(remote_backup_dir, "CORTEX_BACKUP_DIR")?;

    if dry_run {
        phases.push(remote_phase(
            runner,
            host,
            "remote-filesystem",
            &format!(
                "test -d {home} || test -w $(dirname {home})",
                home = shell_quote(&remote_home)
            ),
            None,
        )?);
        phases.push(remote_phase(
            runner,
            host,
            "remote-docker",
            "docker --version && docker compose version",
            None,
        )?);
        let dry_run_reason = "dry-run does not mutate remote Docker or files";
        phases.push(skip_phase("remote-env", dry_run_reason));
        phases.push(skip_phase("remote-compose-assets", dry_run_reason));
        phases.push(skip_phase(
            "remote-docker-network",
            "dry-run does not create Docker networks",
        ));
        phases.push(skip_phase(
            "remote-compose-pull",
            "dry-run does not pull images",
        ));
        phases.push(skip_phase(
            "remote-compose-up",
            "dry-run does not start Docker services",
        ));
        phases.push(skip_phase(
            "remote-health",
            "dry-run does not check service health",
        ));
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(remote_phase(
        runner,
        host,
        "remote-filesystem",
        &format!(
            "mkdir -p {compose_config} {data_dir} {backup_dir} && chmod 700 {backup_dir}",
            compose_config = shell_quote(&format!("{remote_home}/compose/config")),
            data_dir = shell_quote(&remote_data_dir),
            backup_dir = shell_quote(remote_backup_dir),
        ),
        None,
    )?);
    phases.push(remote_phase(
        runner,
        host,
        "remote-docker",
        "docker --version && docker compose version",
        None,
    )?);
    if phases_have_errors(&phases) {
        append_skipped(
            &mut phases,
            &[
                "remote-env",
                "remote-compose-assets",
                "remote-docker-network",
                "remote-compose-pull",
                "remote-compose-up",
                "remote-health",
            ],
            "skipped because remote prerequisites failed",
        );
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(write_remote_env_phase(runner, host, &remote_home, &env)?);
    phases.push(write_remote_assets_phase(runner, host, &remote_home)?);
    if phases_have_errors(&phases) {
        append_skipped(
            &mut phases,
            &[
                "remote-docker-network",
                "remote-compose-pull",
                "remote-compose-up",
                "remote-health",
            ],
            "skipped because remote asset setup failed",
        );
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(remote_phase(
        runner,
        host,
        "remote-docker-network",
        &format!(
            "docker network inspect {network} >/dev/null 2>&1 || docker network create {network}",
            network = shell_quote(&docker_network)
        ),
        None,
    )?);
    if phases_have_errors(&phases) {
        append_skipped(
            &mut phases,
            &["remote-compose-pull", "remote-compose-up", "remote-health"],
            "skipped because Docker network setup failed",
        );
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(remote_phase(
        runner,
        host,
        "remote-compose-pull",
        &format!(
            "docker compose --env-file {env_path} -f {compose_path} pull --ignore-buildable",
            env_path = shell_quote(&format!("{remote_home}/.env")),
            compose_path = shell_quote(&format!("{remote_home}/compose/docker-compose.yml")),
        ),
        None,
    )?);
    if phases_have_errors(&phases) {
        append_skipped(
            &mut phases,
            &["remote-compose-up", "remote-health"],
            "skipped because Compose pull failed",
        );
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(remote_phase(
        runner,
        host,
        "remote-compose-up",
        &format!(
            "docker compose --env-file {env_path} -f {compose_path} up -d",
            env_path = shell_quote(&format!("{remote_home}/.env")),
            compose_path = shell_quote(&format!("{remote_home}/compose/docker-compose.yml")),
        ),
        None,
    )?);
    if phases_have_errors(&phases) {
        append_skipped(
            &mut phases,
            &["remote-health"],
            "skipped because Compose up failed",
        );
        return Ok(report(
            host,
            dry_run,
            &remote_home,
            &remote_data_dir,
            &mcp_port,
            phases,
            started.elapsed().as_millis(),
        ));
    }

    phases.push(remote_phase(
        runner,
        host,
        "remote-health",
        &format!(
            "attempt=0\nwhile [ \"$attempt\" -lt 30 ]; do\n  if curl -fsS {health_url}; then\n    exit 0\n  fi\n  attempt=$((attempt + 1))\n  if [ \"$attempt\" -lt 30 ]; then\n    sleep 1\n  fi\ndone\nexit 1",
            health_url = shell_quote(&format!("http://127.0.0.1:{mcp_port}/health"))
        ),
        None,
    )?);
    Ok(report(
        host,
        dry_run,
        &remote_home,
        &remote_data_dir,
        &mcp_port,
        phases,
        started.elapsed().as_millis(),
    ))
}

fn write_remote_env_phase(
    runner: &mut dyn RemoteRunner,
    host: &str,
    remote_home: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> io::Result<SetupPhase> {
    let rendered = render_env(env);
    let env_path = format!("{remote_home}/.env");
    let tmp_path = format!("{env_path}.tmp");
    let legacy_env_path = format!("{remote_home}/compose/.env");
    let legacy_archive_path = format!("{remote_home}/compose/.env.legacy");
    let script = format!(
        "umask 077\ncat > {tmp_path} <<'__CORTEX_ENV__'\n{rendered}__CORTEX_ENV__\nchmod 600 {tmp_path}\nmv {tmp_path} {env_path}\nif test -f {legacy_env_path}; then rm -f {legacy_archive_path}; mv {legacy_env_path} {legacy_archive_path}; chmod 600 {legacy_archive_path}; fi",
        tmp_path = shell_quote(&tmp_path),
        env_path = shell_quote(&env_path),
        legacy_env_path = shell_quote(&legacy_env_path),
        legacy_archive_path = shell_quote(&legacy_archive_path),
    );
    remote_phase(runner, host, "remote-env", &script, None)
}

fn report(
    host: &str,
    dry_run: bool,
    remote_home: &str,
    remote_data_dir: &str,
    mcp_port: &str,
    phases: Vec<SetupPhase>,
    elapsed_ms: u128,
) -> RemoteDeployReport {
    let has_errors = phases
        .iter()
        .any(|phase| matches!(phase.status, SetupStatus::Error));
    RemoteDeployReport {
        mode: if dry_run { "remote dry-run" } else { "remote" },
        host: host.to_string(),
        home: remote_home.to_string(),
        env_path: format!("{remote_home}/.env"),
        compose_dir: format!("{remote_home}/compose"),
        data_dir: remote_data_dir.to_string(),
        health_url: format!("http://127.0.0.1:{mcp_port}/health"),
        mcp_url: format!("http://127.0.0.1:{mcp_port}/mcp"),
        phases,
        has_errors,
        elapsed_ms,
    }
}

fn write_remote_assets_phase(
    runner: &mut dyn RemoteRunner,
    host: &str,
    remote_home: &str,
) -> io::Result<SetupPhase> {
    let compose_path = format!("{remote_home}/compose/docker-compose.yml");
    let compose_tmp = format!("{compose_path}.tmp");
    let dockerfile_path = format!("{remote_home}/compose/config/Dockerfile");
    let dockerfile_tmp = format!("{dockerfile_path}.tmp");
    let script = format!(
        "cat > {compose_tmp} <<'__CORTEX_COMPOSE__'\n{}__CORTEX_COMPOSE__\ncat > {dockerfile_tmp} <<'__CORTEX_DOCKERFILE__'\n{}__CORTEX_DOCKERFILE__\nmv {compose_tmp} {compose_path}\nmv {dockerfile_tmp} {dockerfile_path}",
        installed_compose_asset(),
        dockerfile_asset(),
        compose_tmp = shell_quote(&compose_tmp),
        compose_path = shell_quote(&compose_path),
        dockerfile_tmp = shell_quote(&dockerfile_tmp),
        dockerfile_path = shell_quote(&dockerfile_path),
    );
    remote_phase(runner, host, "remote-compose-assets", &script, None)
}

fn read_existing_remote_env(
    runner: &mut dyn RemoteRunner,
    host: &str,
    remote_home: &str,
) -> io::Result<String> {
    let env_path = format!("{remote_home}/.env");
    let legacy_env_path = format!("{remote_home}/compose/.env");
    let script = format!(
        "if test -f {env_path}; then cat {env_path}; elif test -f {legacy_env_path}; then cat {legacy_env_path}; fi",
        env_path = shell_quote(&env_path),
        legacy_env_path = shell_quote(&legacy_env_path),
    );
    Ok(runner.run(host, &script, None)?.stdout)
}

fn validate_remote_home(home: &str) -> io::Result<String> {
    let trimmed = home.trim();
    if trimmed.is_empty() || trimmed.contains(['\0', '\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote deploy --home must be a non-empty single-line absolute path",
        ));
    }
    if !Path::new(trimmed).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote deploy --home must be an absolute path",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_remote_absolute_path(path: &str, name: &str) -> io::Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed.contains(['\0', '\n', '\r'])
        || !Path::new(trimmed).is_absolute()
        || trimmed == "/"
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("remote deploy {name} must be a safe single-line absolute path"),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
