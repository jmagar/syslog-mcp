use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{
    EnvResult, PhaseTimer, SetupMode, SetupPhase, SetupReport, SetupReportInput, SetupStatus,
    check_file_phase, setup_report,
};

pub async fn run_setup(mode: SetupMode) -> io::Result<SetupReport> {
    let started = Instant::now();
    let home = super::cortex_home_dir()?;
    let env_path = home.join(".env");
    let compose_dir = home.join("compose");
    let data_dir = home.join("data");
    let mut phases = Vec::new();

    phases.push(filesystem_phase(mode, &home, &data_dir, &compose_dir)?);
    let env = if mode.mutates() {
        let env_result = ensure_env_file(&env_path, &data_dir)?;
        phases.push(env_result.phase);
        phases.push(write_compose_assets(&compose_dir)?);
        Some(env_result.values)
    } else {
        phases.push(check_file_phase("env", &env_path, "run cortex setup"));
        phases.push(check_file_phase(
            "compose-assets",
            &compose_dir.join("docker-compose.yml"),
            "run cortex setup repair",
        ));
        None
    };

    phases.push(command_phase("docker", ["--version"]));
    phases.push(command_phase("docker compose", ["compose", "version"]));
    if mode.mutates() {
        let systemd_dir = super::user_home_dir()?.join(".config/systemd/user");
        phases.push(super::managed_units::rewrite_stale_managed_unit_commands(
            &systemd_dir,
        )?);
        phases.push(super::managed_units::cleanup_legacy_systemd());
    }

    let prereq_failed = phases
        .iter()
        .any(|phase| matches!(phase.status, SetupStatus::Error));
    if mode.mutates() && !prereq_failed {
        ensure_network_phase(&mut phases, env.as_ref());
        phases.push(run_compose_phase(
            &compose_dir,
            &env_path,
            &["pull", "--ignore-buildable"],
        ));
        let up_args: &[&str] = if compose_dir.join("docker-compose.override.yml").exists() {
            &["up", "-d", "--build"]
        } else {
            &["up", "-d"]
        };
        phases.push(run_compose_phase(&compose_dir, &env_path, up_args));
        phases.push(health_phase(&env));
    } else {
        phases.push(SetupPhase {
            name: "compose-up",
            status: SetupStatus::Skipped,
            issue_kind: None,
            detail: if prereq_failed {
                "skipped because earlier checks failed".to_string()
            } else {
                "check mode does not start Docker services".to_string()
            },
            elapsed_ms: 0,
        });
    }

    let elapsed_ms = started.elapsed().as_millis();
    let port = env
        .as_ref()
        .and_then(|values| values.get("CORTEX_PORT"))
        .cloned()
        .unwrap_or_else(|| "3100".to_string());
    Ok(setup_report(
        SetupReportInput {
            mode: mode.as_str(),
            elapsed_ms,
            home,
            env_path,
            compose_dir,
            data_dir,
            health_url: format!("http://127.0.0.1:{port}/health"),
            mcp_url: format!("http://127.0.0.1:{port}/mcp"),
        },
        phases,
    ))
}

pub(crate) fn filesystem_phase(
    mode: SetupMode,
    home: &Path,
    data_dir: &Path,
    compose_dir: &Path,
) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("filesystem");
    let backup_dir = crate::env::var_os("CORTEX_BACKUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("backups"));
    if mode.mutates() {
        ensure_private_dir(home)?;
        ensure_private_dir(data_dir)?;
        ensure_private_dir(&backup_dir)?;
        std::fs::create_dir_all(compose_dir)?;
        return Ok(timer.finish(SetupStatus::Ok, format!("initialized {}", home.display())));
    }
    if home.is_dir() && data_dir.is_dir() && backup_dir.is_dir() && compose_dir.is_dir() {
        Ok(timer.finish(SetupStatus::Ok, format!("found {}", home.display())))
    } else {
        Ok(timer.finish(
            SetupStatus::Warn,
            format!(
                "missing setup dirs under {}; run cortex setup",
                home.display()
            ),
        ))
    }
}

pub(super) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        std::fs::set_permissions(path, PermissionsExt::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

pub(crate) fn ensure_env_file(path: &Path, data_dir: &Path) -> io::Result<EnvResult> {
    let timer = PhaseTimer::start("env");
    let mut env = if path.exists() {
        parse_env(&std::fs::read_to_string(path)?)
    } else {
        BTreeMap::new()
    };
    let before = env.len();
    populate_env_defaults(&mut env, data_dir)?;

    write_env(path, &env)?;
    let added = env.len().saturating_sub(before);
    Ok(EnvResult {
        phase: timer.finish(
            SetupStatus::Ok,
            format!("{} {} keys; added {added}", path.display(), env.len()),
        ),
        values: env,
    })
}

pub(crate) fn default_env_for_data_dir(data_dir: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    populate_env_defaults(&mut env, data_dir)?;
    Ok(env)
}

fn populate_env_defaults(env: &mut BTreeMap<String, String>, data_dir: &Path) -> io::Result<()> {
    insert_process_or_default(env, "CORTEX_RECEIVER_HOST", "0.0.0.0");
    insert_process_or_default(env, "CORTEX_RECEIVER_PORT", "1514");
    insert_process_or_default(env, "CORTEX_RECEIVER_HOST_PORT", "1514");
    insert_process_or_default(env, "CORTEX_HOST", "0.0.0.0");
    insert_process_or_default(env, "CORTEX_PORT", "3100");
    insert_process_or_default(env, "NO_AUTH", "false");
    insert_process_or_default(env, "CORTEX_AUTH_MODE", "bearer");
    insert_process_or_default(env, "CORTEX_DB_PATH", "/data/cortex.db");
    insert_process_or_default(env, "CORTEX_DATA_VOLUME", &data_dir.display().to_string());
    insert_process_or_default(env, "CORTEX_MAX_DB_SIZE_MB", "8192");
    insert_process_or_default(env, "CORTEX_RETENTION_DAYS", "90");
    insert_process_or_default(env, "CORTEX_BATCH_SIZE", "100");
    insert_process_or_default(env, "CORTEX_WRITE_CHANNEL_CAPACITY", "10000");
    insert_process_or_default(env, "CORTEX_DOCKER_INGEST_ENABLED", "false");
    insert_process_or_default(env, "RUST_LOG", "info");
    insert_process_or_default(env, "COMPOSE_PROJECT_NAME", "syslog-jmagar-lab");
    insert_process_or_default(env, "DOCKER_NETWORK", "cortex");
    insert_process_optional(env, "CORTEX_DOCKER_HOSTS");
    insert_process_optional(env, "CORTEX_PUBLIC_URL");
    insert_process_optional(env, "CORTEX_GOOGLE_CLIENT_ID");
    insert_process_optional(env, "CORTEX_GOOGLE_CLIENT_SECRET");
    insert_process_optional(env, "CORTEX_AUTH_ADMIN_EMAIL");
    insert_process_optional(env, "CORTEX_AUTH_ALLOWED_REDIRECT_URIS");
    insert_process_optional(env, "CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH");

    let (uid, gid) = current_uid_gid();
    env.entry("CORTEX_UID".to_string()).or_insert(uid);
    env.entry("CORTEX_GID".to_string()).or_insert(gid);

    if env
        .get("NO_AUTH")
        .is_none_or(|value| !value.eq_ignore_ascii_case("true"))
        && env
            .get("CORTEX_TOKEN")
            .is_none_or(|value| value.trim().is_empty())
    {
        env.insert("CORTEX_TOKEN".to_string(), generate_token()?);
    }

    // CORTEX_API_TOKEN is always required — `/api/*` is unconditionally
    // mounted and the container fails to start without it. Mirror the
    // CORTEX_TOKEN pattern: preserve any existing value byte-for-byte
    // on re-runs, generate a fresh 64-char hex token only when missing or
    // blank. (entry().or_insert_with() is not sufficient here because the
    // key may exist with an empty value from an earlier upgrade.)
    if env
        .get("CORTEX_API_TOKEN")
        .is_none_or(|value| value.trim().is_empty())
    {
        env.insert("CORTEX_API_TOKEN".to_string(), generate_token()?);
    }

    // CORTEX_USE_HTTP=true is the v0.26 cutover default — the CLI defaults to
    // routing query/AI/DB commands through the container REST API. Unlike
    // CORTEX_API_TOKEN above, this is a behaviour toggle the operator may
    // legitimately set to `false` (or any other value) to opt out. Use
    // `entry().or_insert_with` so any existing value — including an empty
    // string or `false` — survives byte-for-byte. Operator intent wins.
    env.entry("CORTEX_USE_HTTP".to_string())
        .or_insert_with(|| "true".to_string());
    Ok(())
}

fn insert_process_or_default(env: &mut BTreeMap<String, String>, key: &str, default: &str) {
    if let Some(value) = process_env_value(key) {
        env.insert(key.to_string(), value);
    } else {
        env.entry(key.to_string())
            .or_insert_with(|| default.to_string());
    }
}

fn insert_process_optional(env: &mut BTreeMap<String, String>, key: &str) {
    if let Some(value) = process_env_value(key) {
        env.insert(key.to_string(), value);
    }
}

fn process_env_value(key: &str) -> Option<String> {
    crate::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.contains(['\n', '\r']))
}

pub(crate) fn parse_env(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

pub(crate) fn write_env(path: &Path, env: &BTreeMap<String, String>) -> io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let out = render_env(env);

    // Atomic write: temp file in the same directory (so rename(2) stays on
    // the same filesystem), fsync, then rename over the target. A kill
    // mid-write leaves the temp file orphaned but the live .env is either
    // the old content or the fully written new content — never partial.
    // Crucial because a corrupt .env breaks container startup
    // (api.rs bails on empty CORTEX_API_TOKEN).
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "env path must have a parent directory",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "env path has no file name"))?;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}.{nanos}"));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // O_NOFOLLOW protects against symlink races on the temp file; mode
        // 0o600 keeps the secrets out of any read-by-other process.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let write_result: io::Result<()> = (|| {
        let mut file = options.open(&tmp_path)?;
        file.write_all(out.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Re-assert 0o600 after rename in case the target inode picked up
        // a different mode from a pre-existing file.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    // fsync the parent directory so the rename — not just the file
    // content — is durable across a power loss. Without this, the file
    // content (rename target) can survive while the directory entry
    // pointing at it has not yet hit disk. Propagate the error: ignoring
    // it would let us return Ok while the rename is not yet on stable
    // storage, defeating the whole point of the atomic-write contract.
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

pub(crate) fn render_env(env: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    out.push_str("# cortex runtime environment.\n");
    out.push_str("# Managed by `cortex setup`; secrets are preserved on repair.\n");
    for (key, value) in env {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

pub(crate) fn write_compose_assets(compose_dir: &Path) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("compose-assets");
    std::fs::create_dir_all(compose_dir.join("config"))?;
    std::fs::write(
        compose_dir.join("docker-compose.yml"),
        installed_compose_asset(),
    )?;
    std::fs::write(
        compose_dir.join("config/Dockerfile"),
        super::DOCKERFILE_ASSET,
    )?;
    Ok(timer.finish(
        SetupStatus::Ok,
        format!("wrote compose assets under {}", compose_dir.display()),
    ))
}

pub(crate) fn installed_compose_asset() -> String {
    // The installed compose file lives one level deeper than the env file
    // (`compose/docker-compose.yml` vs `.env` in the parent), so rewrite the
    // env_file path. Panic if the template stops matching: a silent no-op
    // here would ship a compose file pointing at a non-existent env file.
    let installed = super::COMPOSE_ASSET.replace("      - path: .env\n", "      - path: ../.env\n");
    assert_ne!(
        installed,
        super::COMPOSE_ASSET,
        "installed compose asset transform failed: expected `      - path: .env\\n` was not found in docker-compose.prod.yml"
    );
    installed
}

pub(crate) fn dockerfile_asset() -> &'static str {
    super::DOCKERFILE_ASSET
}

pub(crate) fn command_phase<const N: usize>(name: &'static str, args: [&str; N]) -> SetupPhase {
    let timer = PhaseTimer::start(name);
    let program = if name == "docker compose" {
        "docker"
    } else {
        name
    };
    match crate::env::command(program).args(args).output() {
        Ok(output) if output.status.success() => timer.finish(
            SetupStatus::Ok,
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("available")
                .to_string(),
        ),
        Ok(output) => timer.finish(
            SetupStatus::Error,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("command failed")
                .to_string(),
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            timer.finish(SetupStatus::Error, "not found on PATH")
        }
        Err(err) => timer.finish(SetupStatus::Error, err.to_string()),
    }
}

pub(crate) fn ensure_network_phase(
    phases: &mut Vec<SetupPhase>,
    env: Option<&BTreeMap<String, String>>,
) {
    let timer = PhaseTimer::start("docker-network");
    let network = env
        .and_then(|env| env.get("DOCKER_NETWORK"))
        .map(String::as_str)
        .unwrap_or("cortex");
    let inspect = crate::env::command("docker")
        .args(["network", "inspect", network])
        .output();
    if inspect.as_ref().is_ok_and(|output| output.status.success()) {
        phases.push(timer.finish(SetupStatus::Ok, format!("{network} exists")));
        return;
    }
    match crate::env::command("docker")
        .args(["network", "create", network])
        .output()
    {
        Ok(output) if output.status.success() => {
            phases.push(timer.finish(SetupStatus::Ok, format!("created {network}")))
        }
        Ok(output) => phases.push(
            timer.finish(
                SetupStatus::Error,
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or("docker network create failed"),
            ),
        ),
        Err(err) => phases.push(timer.finish(SetupStatus::Error, err.to_string())),
    }
}

pub(crate) fn run_compose_phase(compose_dir: &Path, env_path: &Path, args: &[&str]) -> SetupPhase {
    let timer = PhaseTimer::start(if args.first() == Some(&"pull") {
        "compose-pull"
    } else {
        "compose-up"
    });
    let mut command = crate::env::command("docker");
    command
        .arg("compose")
        .arg("--env-file")
        .arg(env_path)
        .arg("-f")
        .arg(compose_dir.join("docker-compose.yml"));
    let override_path = compose_dir.join("docker-compose.override.yml");
    if override_path.exists() {
        command.arg("-f").arg(override_path);
    }
    command
        .args(args)
        .current_dir(compose_dir)
        .env("PWD", compose_dir);
    match command.output() {
        Ok(output) if output.status.success() => timer.finish(
            SetupStatus::Ok,
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .last()
                .unwrap_or("ok")
                .to_string(),
        ),
        Ok(output) => timer.finish(
            SetupStatus::Error,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("docker compose failed")
                .to_string(),
        ),
        Err(err) => timer.finish(SetupStatus::Error, err.to_string()),
    }
}

pub(crate) fn health_phase(env: &Option<BTreeMap<String, String>>) -> SetupPhase {
    let timer = PhaseTimer::start("health");
    let port = env
        .as_ref()
        .and_then(|env| env.get("CORTEX_PORT"))
        .map(String::as_str)
        .unwrap_or("3100");
    let url = format!("http://127.0.0.1:{port}/health");
    match crate::env::command("curl")
        .args(["-fsS", "--max-time", "5", &url])
        .output()
    {
        Ok(output) if output.status.success() => {
            timer.finish(SetupStatus::Ok, format!("{url} ready"))
        }
        Ok(output) => timer.finish(
            SetupStatus::Error,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("health check failed"),
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            timer.finish(SetupStatus::Error, "curl not found; skipped health check")
        }
        Err(err) => timer.finish(SetupStatus::Error, err.to_string()),
    }
}

pub(super) fn current_uid_gid() -> (String, String) {
    #[cfg(unix)]
    {
        // SAFETY: POSIX geteuid/getegid are infallible process queries.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        (uid.to_string(), gid.to_string())
    }
    #[cfg(not(unix))]
    {
        let uid = command_stdout("id", ["-u"]).unwrap_or_else(|| "1000".to_string());
        let gid = command_stdout("id", ["-g"]).unwrap_or_else(|| "1000".to_string());
        (uid, gid)
    }
}

#[cfg(not(unix))]
fn command_stdout<const N: usize>(program: &str, args: [&str; N]) -> Option<String> {
    let output = crate::env::command(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn generate_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        token.push_str(&format!("{byte:02x}"));
    }
    Ok(token)
}
