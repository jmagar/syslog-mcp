use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;

const PROBE_TIMEOUT_SECS: u64 = 5;
const REMOTE_BIN_TMP: &str = ".local/bin/cortex.new";

// ── public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HostProbe {
    pub host: String,
    pub reachable: bool,
    pub cortex_version: Option<String>,
    /// `Some(true)` = active, `Some(false)` = installed but inactive, `None` = cortex absent
    pub agent_active: Option<bool>,
}

impl HostProbe {
    pub fn display_label(&self) -> String {
        let cortex = match &self.cortex_version {
            Some(v) => format!("cortex {v}"),
            None => "absent".to_string(),
        };
        let agent = match self.agent_active {
            Some(true) => "agent:active",
            Some(false) => "agent:inactive",
            None => "—",
        };
        let ok = if self.reachable { "✓" } else { "✗" };
        format!("{:<22} {ok}  {:<18}  {}", self.host, cortex, agent)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentDeployConfig {
    pub target: Option<String>,
    pub token: Option<String>,
    /// Require an effective heartbeat token after flag/persisted-env resolution.
    /// `cortex update clients` sets this because it updates already configured
    /// agents and must not silently strip auth when a remote env read fails.
    pub require_token: bool,
    /// `None` = not specified on the CLI → preserve the host's existing value on
    /// an upgrade (rather than reset to the default).
    pub docker: Option<bool>,
    pub journald: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployResult {
    pub host: String,
    pub ok: bool,
    pub detail: String,
    pub elapsed_ms: u128,
}

// ── discovery ────────────────────────────────────────────────────────────────

/// Parse `~/.ssh/config` and return all concrete host aliases (no wildcards).
pub fn ssh_config_hosts() -> Vec<String> {
    let path = home_dir()
        .map(|h| h.join(".ssh/config"))
        .unwrap_or_default();
    let body = std::fs::read_to_string(path).unwrap_or_default();
    parse_ssh_config_hosts(&body)
}

fn parse_ssh_config_hosts(body: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed
            .strip_prefix("Host ")
            .or_else(|| trimmed.strip_prefix("host "))
        else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.contains('*') || token.contains('?') {
                continue;
            }
            if token.eq_ignore_ascii_case("github.com") {
                continue;
            }
            if !crate::inventory::ssh::is_safe_ssh_host(token) {
                continue;
            }
            if !hosts.contains(&token.to_string()) {
                hosts.push(token.to_string());
            }
        }
    }
    hosts
}

/// Probe all hosts in parallel (SSH, `BatchMode=yes`, `ConnectTimeout` capped).
/// Hosts that don't respond within the deadline appear as unreachable.
pub fn probe_hosts(hosts: Vec<String>) -> Vec<HostProbe> {
    if hosts.is_empty() {
        return Vec::new();
    }
    let count = hosts.len();
    let (tx, rx) = mpsc::channel::<HostProbe>();
    for host in hosts {
        let tx = tx.clone();
        std::thread::spawn(move || {
            tx.send(probe_one(&host)).ok();
        });
    }
    drop(tx);

    let deadline = Instant::now() + Duration::from_secs(PROBE_TIMEOUT_SECS + 3);
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(probe) => results.push(probe),
            Err(_) => break,
        }
    }
    results.sort_by(|a, b| a.host.cmp(&b.host));
    results
}

fn probe_one(host: &str) -> HostProbe {
    let script = "which cortex >/dev/null 2>&1 && cortex --version 2>/dev/null \
                  || echo 'cortex:absent'; \
                  systemctl --user is-active cortex-heartbeat-agent.service 2>/dev/null \
                  || echo 'inactive'";
    let out = crate::env::command("ssh")
        .args([
            "-o",
            &format!("ConnectTimeout={PROBE_TIMEOUT_SECS}"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            host,
            script,
        ])
        .output();

    let Ok(out) = out else {
        return HostProbe {
            host: host.to_string(),
            reachable: false,
            cortex_version: None,
            agent_active: None,
        };
    };
    if !out.status.success() {
        return HostProbe {
            host: host.to_string(),
            reachable: false,
            cortex_version: None,
            agent_active: None,
        };
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let first = lines.next().unwrap_or("cortex:absent").trim();
    let second = lines.next().unwrap_or("inactive").trim();

    let cortex_version = if first.contains("cortex:absent") {
        None
    } else {
        // `cortex --version` prints "cortex 1.17.0"
        first.split_whitespace().nth(1).map(str::to_string)
    };
    let agent_active = cortex_version.as_ref().map(|_| second == "active");

    HostProbe {
        host: host.to_string(),
        reachable: true,
        cortex_version,
        agent_active,
    }
}

// ── interactive selection ────────────────────────────────────────────────────

/// Show a simple stdin prompt over reachable hosts. Returns selected host names.
/// Unreachable hosts are excluded from the list but noted beforehand.
pub fn select_hosts_interactive(probes: &[HostProbe]) -> Result<Vec<String>> {
    let unreachable: Vec<&str> = probes
        .iter()
        .filter(|p| !p.reachable)
        .map(|p| p.host.as_str())
        .collect();
    if !unreachable.is_empty() {
        eprintln!("\n  unreachable (skipped): {}\n", unreachable.join(", "));
    }

    let reachable: Vec<&HostProbe> = probes.iter().filter(|p| p.reachable).collect();
    if reachable.is_empty() {
        anyhow::bail!("no reachable hosts found in ~/.ssh/config");
    }

    eprintln!("Select hosts to deploy the cortex heartbeat agent:");
    for (idx, probe) in reachable.iter().enumerate() {
        eprintln!("  {:>2}. {}", idx + 1, probe.display_label());
    }
    eprint!("Enter numbers separated by commas/spaces, or 'all': ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let selected_indexes = parse_host_selection(&input, reachable.len())?;

    Ok(selected_indexes
        .into_iter()
        .filter_map(|idx| reachable.get(idx))
        .map(|probe| probe.host.clone())
        .collect())
}

fn parse_host_selection(input: &str, reachable_count: usize) -> Result<Vec<usize>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("no hosts selected");
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok((0..reachable_count).collect());
    }

    let mut selected = BTreeSet::new();
    for token in trimmed.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let number: usize = token
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid host selection: {token}"))?;
        if number == 0 || number > reachable_count {
            anyhow::bail!("host selection {number} is out of range 1..={reachable_count}");
        }
        selected.insert(number - 1);
    }

    if selected.is_empty() {
        anyhow::bail!("no hosts selected");
    }
    Ok(selected.into_iter().collect())
}

// ── deploy ───────────────────────────────────────────────────────────────────

/// Locate the best local cortex binary for deployment (prefer the installed
/// production binary over whatever is currently executing).
pub fn find_local_binary() -> Option<PathBuf> {
    which_cortex().or_else(|| std::env::current_exe().ok())
}

fn which_cortex() -> Option<PathBuf> {
    let out = crate::env::command("which").arg("cortex").output().ok()?;
    if out.status.success() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

pub fn deploy_agent_to_host(
    host: &str,
    local_binary: &Path,
    config: &AgentDeployConfig,
) -> DeployResult {
    let started = Instant::now();
    if let Err(error) = validate_ssh_host(host) {
        return DeployResult {
            host: host.to_string(),
            ok: false,
            detail: error.to_string(),
            elapsed_ms: started.elapsed().as_millis(),
        };
    }
    match run_deploy(host, local_binary, config) {
        Ok(()) => DeployResult {
            host: host.to_string(),
            ok: true,
            detail: "installed and enabled".to_string(),
            elapsed_ms: started.elapsed().as_millis(),
        },
        Err(e) => DeployResult {
            host: host.to_string(),
            ok: false,
            detail: e.to_string(),
            elapsed_ms: started.elapsed().as_millis(),
        },
    }
}

fn is_unraid(host: &str) -> bool {
    if validate_ssh_host(host).is_err() {
        return false;
    }
    let out = crate::env::command("ssh")
        .args([
            "-o",
            &format!("ConnectTimeout={PROBE_TIMEOUT_SECS}"),
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "--",
            host,
            "test -f /etc/unraid-version && echo yes || echo no",
        ])
        .output();
    matches!(out, Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "yes")
}

fn run_deploy(host: &str, local_binary: &Path, config: &AgentDeployConfig) -> io::Result<()> {
    validate_ssh_host(host)?;
    if is_unraid(host) {
        return run_deploy_unraid(host, local_binary, config);
    }

    let env_pairs = resolve_linux_agent_env(
        &parse_env_file(&read_optional_remote_file(
            host,
            "$HOME/.cortex/heartbeat-agent.env",
        )?),
        config,
    );
    require_token_if_requested(&env_pairs, config)?;

    ssh_run(host, "mkdir -p ~/.local/bin")?;
    // scp to a temp path then mv atomically — avoids ETXTBSY if the binary is
    // currently running as a service on the remote host.
    scp_file(local_binary, host, REMOTE_BIN_TMP)?;
    ssh_run(
        host,
        "chmod +x ~/.local/bin/cortex.new && mv -f ~/.local/bin/cortex.new ~/.local/bin/cortex",
    )?;
    let env_body = render_env_file(&env_pairs)?;
    ssh_run_with_stdin(
        host,
        "umask 077; mkdir -p ~/.cortex; cat > ~/.cortex/heartbeat-agent.env.new && chmod 600 ~/.cortex/heartbeat-agent.env.new && mv -f ~/.cortex/heartbeat-agent.env.new ~/.cortex/heartbeat-agent.env",
        env_body.as_bytes(),
    )?;
    // Install the unit only after the fully resolved environment is atomically
    // in place. The setup command preserves an existing env file, so an
    // interruption cannot start the agent once with generated defaults.
    ssh_run(
        host,
        "CORTEX_SETUP_PRESERVE_HEARTBEAT_ENV=1 ~/.local/bin/cortex setup heartbeatagent install",
    )?;
    ssh_run(
        host,
        "systemctl --user restart cortex-heartbeat-agent.service",
    )
}

// Unraid: root fs is a RAM disk — nothing in /root survives reboot.
// Put everything in /mnt/user/appdata/cortex (array, persistent), then
// use `docker run --restart unless-stopped` so Docker itself persists the
// container definition across reboots without any file on disk.
const UNRAID_APPDATA: &str = "/mnt/user/appdata/cortex";
const UNRAID_ENV: &str = "/mnt/user/appdata/cortex/heartbeat-agent.env";
/// Published agent image. The agent runs the same baked binary as the server
/// (no bind-mounted host binary), pinned to this deploying binary's version so
/// server and agents stay in lockstep. Requires the matching tag to be present
/// on the registry before deploy.
const CORTEX_IMAGE_REPO: &str = "ghcr.io/dinglebear-ai/cortex";
const UNRAID_HOST_ID: &str = "/mnt/user/appdata/cortex/heartbeat-host-id";
const UNRAID_CONTAINER: &str = "cortex-heartbeat-agent";
const UNRAID_HOST_SYSLOG: &str = "/var/log/syslog";
const UNRAID_CONTAINER_SYSLOG: &str = "/host/var/log/syslog";

fn run_deploy_unraid(
    host: &str,
    _local_binary: &Path,
    config: &AgentDeployConfig,
) -> io::Result<()> {
    // Containerized agents run the published image with the binary baked in —
    // no host binary is staged or bind-mounted. Pin to this deploying binary's
    // version so server and agents stay in lockstep (the agent can still self-
    // update between republishes, but the image is the source of truth).
    let image = format!("{CORTEX_IMAGE_REPO}:{}", env!("CARGO_PKG_VERSION"));
    ssh_run(host, &format!("mkdir -p {UNRAID_APPDATA}"))?;

    // Config-preserving upgrade: resolve the container env from the host's
    // persisted heartbeat-agent.env (flag > persisted > default per key, custom
    // keys like CORTEX_AGENT_FILE_TAILS carried through), and carry forward any
    // non-standard mounts (e.g. the host log dir a file-tail reads) from the
    // running container.
    let env_pairs = resolve_agent_env(
        &parse_env_file(&read_optional_remote_file(host, UNRAID_ENV)?),
        config,
    );
    require_token_if_requested(&env_pairs, config)?;
    ssh_run(host, &format!("docker pull {image}"))?;

    let custom_mounts: String = preserved_custom_mount_flags(&ssh_capture(
        host,
        &format!(
            "docker inspect {UNRAID_CONTAINER} --format '{MOUNT_INSPECT_TMPL}' 2>/dev/null || true"
        ),
    )?)
    .concat();

    let env_body = render_env_file(&env_pairs)?;
    ssh_run_with_stdin(
        host,
        &format!(
            "umask 077; cat > {UNRAID_ENV}.new && chmod 600 {UNRAID_ENV}.new && mv -f {UNRAID_ENV}.new {UNRAID_ENV}"
        ),
        env_body.as_bytes(),
    )?;

    // Remove any previous container then start fresh with docker run.
    // --restart unless-stopped is stored in Docker's state (not a file),
    // so it survives the Unraid RAM-disk wipe on reboot.
    //
    // The image bakes in the binary and ca-certificates, so the only mounts are
    // host *data* the agent reads/writes: the Docker socket, the host syslog
    // file, and the appdata dir (host-id + reference env file). --user 0:0
    // overrides the image's unprivileged server user because the agent must read
    // root-owned host files (docker.sock, /var/log/syslog). --no-healthcheck
    // disables the image's server health probe (the agent runs no HTTP server).
    ssh_run(
        host,
        &format!(
            "docker rm -f {UNRAID_CONTAINER} 2>/dev/null; \
             docker run -d \
               --name {UNRAID_CONTAINER} \
               --restart unless-stopped \
               --network host \
               --user 0:0 \
               --no-healthcheck \
               --env-file {UNRAID_ENV} \
               -v {UNRAID_APPDATA}:{UNRAID_APPDATA} \
               -v /var/run/docker.sock:/var/run/docker.sock \
               -v {UNRAID_HOST_SYSLOG}:{UNRAID_CONTAINER_SYSLOG}:ro \
               {custom_mounts}\
               {image} \
               cortex heartbeat agent \
                 --host-id-path {UNRAID_HOST_ID}"
        ),
    )
}

fn deploy_syslog_target(heartbeat_target: Option<&str>) -> Option<String> {
    crate::env::var("CORTEX_SYSLOG_TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            heartbeat_target
                .and_then(crate::agent::AgentStreamsConfig::syslog_target_from_heartbeat)
        })
}

/// Parse an existing `heartbeat-agent.env` into ordered `(key, value)` pairs.
/// Splits on the first `=` so values containing `=`/spaces/`:` (file-tail specs)
/// round-trip intact; blank lines and comments are skipped.
fn parse_env_file(contents: &str) -> Vec<(String, String)> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .filter(|(k, _)| is_safe_env_key(k))
        .collect()
}

/// Resolve the host-local systemd agent env for a Linux (non-Unraid) deploy.
/// Only keys that the Linux setup writer consumes are carried forward. A fresh
/// no-flag deploy stays minimal, while upgrades preserve auth and forwarding
/// knobs unless the operator supplied an explicit override.
fn resolve_linux_agent_env(
    persisted: &[(String, String)],
    config: &AgentDeployConfig,
) -> Vec<(String, String)> {
    use std::collections::HashMap;
    let prev: HashMap<&str, &str> = persisted
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let prev_get = |k: &str| prev.get(k).map(|s| s.to_string());

    let mut out = Vec::new();
    let target = config
        .target
        .clone()
        .or_else(|| prev_get("CORTEX_HEARTBEAT_TARGET"));
    if let Some(target) = &target {
        out.push(("CORTEX_HEARTBEAT_TARGET".to_string(), target.clone()));
    }
    if let Some(token) = config
        .token
        .clone()
        .or_else(|| prev_get("CORTEX_HEARTBEAT_TOKEN"))
    {
        out.push(("CORTEX_HEARTBEAT_TOKEN".to_string(), token));
    }
    if let Some(docker) = config
        .docker
        .map(|value| value.to_string())
        .or_else(|| prev_get("CORTEX_AGENT_DOCKER"))
    {
        out.push(("CORTEX_AGENT_DOCKER".to_string(), docker));
    }
    if let Some(journald) = config
        .journald
        .map(|value| value.to_string())
        .or_else(|| prev_get("CORTEX_AGENT_JOURNALD"))
    {
        out.push(("CORTEX_AGENT_JOURNALD".to_string(), journald));
    }
    if let Some(docker_url) = prev_get("CORTEX_AGENT_DOCKER_URL") {
        out.push(("CORTEX_AGENT_DOCKER_URL".to_string(), docker_url));
    }
    if let Some(syslog_file) = prev_get("CORTEX_AGENT_SYSLOG_FILE") {
        out.push(("CORTEX_AGENT_SYSLOG_FILE".to_string(), syslog_file));
    }
    let transcript_forward = prev_get(crate::heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV)
        .or_else(|| prev_get(crate::heartbeat_agent::AI_TRANSCRIPT_FORWARD_LEGACY_ENV));
    if let Some(value) = transcript_forward {
        out.push((
            crate::heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV.to_string(),
            value,
        ));
    }
    for key in crate::heartbeat_agent::OPTIONAL_ENV_KEYS {
        if matches!(
            *key,
            crate::heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV
                | crate::heartbeat_agent::AI_TRANSCRIPT_FORWARD_LEGACY_ENV
        ) {
            continue;
        }
        if let Some(value) = prev_get(key) {
            out.push(((*key).to_string(), value));
        }
    }
    let syslog_target = if config.target.is_some() {
        deploy_syslog_target(target.as_deref())
    } else {
        prev_get("CORTEX_SYSLOG_TARGET").or_else(|| deploy_syslog_target(target.as_deref()))
    };
    if let Some(syslog_target) = syslog_target {
        out.push(("CORTEX_SYSLOG_TARGET".to_string(), syslog_target));
    }
    out
}

fn require_token_if_requested(
    env_pairs: &[(String, String)],
    config: &AgentDeployConfig,
) -> io::Result<()> {
    if !config.require_token
        || env_pairs
            .iter()
            .any(|(key, value)| key == "CORTEX_HEARTBEAT_TOKEN" && !value.trim().is_empty())
    {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "client update requires existing CORTEX_HEARTBEAT_TOKEN on the remote agent; repair the client with `cortex setup deploy agent --heartbeat-token-file PATH`",
    ))
}

/// Resolve the agent container env for a (re)deploy using precedence
/// **flag > persisted > default** for each managed key, then carry every other
/// key from the persisted env through unchanged (e.g. `CORTEX_AGENT_FILE_TAILS`).
///
/// This makes an upgrade config-preserving: running `cortex setup deploy agent` with no
/// flags keeps the host's existing target, token, docker/journald settings, and
/// custom additions, instead of resetting them to defaults. Output order is
/// deterministic (managed block in a fixed order, then custom keys sorted).
fn resolve_agent_env(
    persisted: &[(String, String)],
    config: &AgentDeployConfig,
) -> Vec<(String, String)> {
    use std::collections::{HashMap, HashSet};
    let prev: HashMap<&str, &str> = persisted
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let prev_get = |k: &str| prev.get(k).map(|s| s.to_string());

    // Effective heartbeat target (flag > persisted > default) drives syslog derivation.
    let target = config
        .target
        .clone()
        .or_else(|| prev_get("CORTEX_HEARTBEAT_TARGET"))
        .unwrap_or_else(|| crate::heartbeat_agent::DEFAULT_TARGET.to_string());

    // A new --target re-derives the syslog target; otherwise keep the persisted
    // value (falling back to a derivation for first-time deploys).
    let syslog_target = if config.target.is_some() {
        deploy_syslog_target(Some(&target)).unwrap_or_else(|| "127.0.0.1:1514".into())
    } else {
        prev_get("CORTEX_SYSLOG_TARGET")
            .or_else(|| deploy_syslog_target(Some(&target)))
            .unwrap_or_else(|| "127.0.0.1:1514".into())
    };

    let bool_key = |flag: Option<bool>, key: &str| -> String {
        match flag {
            Some(b) => b.to_string(),
            None => prev_get(key).unwrap_or_else(|| "false".into()),
        }
    };

    let mut out: Vec<(String, String)> = vec![
        ("CORTEX_HEARTBEAT_TARGET".into(), target),
        (
            "RUST_LOG".into(),
            prev_get("RUST_LOG").unwrap_or_else(|| "warn".into()),
        ),
        ("CORTEX_SYSLOG_TARGET".into(), syslog_target),
        (
            "CORTEX_AGENT_DOCKER".into(),
            bool_key(config.docker, "CORTEX_AGENT_DOCKER"),
        ),
        (
            "CORTEX_AGENT_DOCKER_URL".into(),
            prev_get("CORTEX_AGENT_DOCKER_URL")
                .unwrap_or_else(|| crate::heartbeat_agent::DEFAULT_DOCKER_URL.to_string()),
        ),
        // journald is meaningless inside a container — always false on Unraid,
        // regardless of any flag or persisted value.
        ("CORTEX_AGENT_JOURNALD".into(), "false".into()),
        (
            "CORTEX_AGENT_SYSLOG_FILE".into(),
            prev_get("CORTEX_AGENT_SYSLOG_FILE")
                .unwrap_or_else(|| UNRAID_CONTAINER_SYSLOG.to_string()),
        ),
    ];
    // Token: flag wins, else preserve the persisted token. Omitted if neither
    // exists (no auth configured).
    if let Some(token) = config
        .token
        .clone()
        .or_else(|| prev_get("CORTEX_HEARTBEAT_TOKEN"))
    {
        out.push(("CORTEX_HEARTBEAT_TOKEN".into(), token));
    }

    // Carry remaining custom keys (file-tails, etc.) in stable sorted order.
    let managed: HashSet<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
    let mut custom: Vec<(String, String)> = persisted
        .iter()
        .filter(|(k, _)| !managed.contains(k.as_str()))
        .cloned()
        .collect();
    custom.sort_by(|a, b| a.0.cmp(&b.0));
    out.extend(custom);
    out
}

/// Container mount destinations the deploy always provides itself. A mount with
/// any other destination (e.g. host log dirs a file-tail reads) is custom and
/// must survive an upgrade.
const STANDARD_MOUNT_DESTS: &[&str] = &[
    UNRAID_APPDATA,
    "/var/run/docker.sock",
    UNRAID_CONTAINER_SYSLOG,
];

/// `docker inspect --format` template emitting one `source\tdest\trw|ro` line per
/// mount. Uses `{{"\t"}}`/`{{"\n"}}` (Go interprets those) so the separators are
/// real control chars, not literal backslash sequences.
const MOUNT_INSPECT_TMPL: &str = r#"{{range .Mounts}}{{.Source}}{{"\t"}}{{.Destination}}{{"\t"}}{{if .RW}}rw{{else}}ro{{end}}{{"\n"}}{{end}}"#;

/// From `MOUNT_INSPECT_TMPL` output, return `-v source:dest[:ro]` flags for any
/// mount whose destination the deploy doesn't already provide, so a custom mount
/// (e.g. host Plex logs) survives an upgrade.
fn preserved_custom_mount_flags(inspect_mounts: &str) -> Vec<String> {
    inspect_mounts
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let src = parts.next()?.trim();
            let dest = parts.next()?.trim();
            let rw = parts.next().map(str::trim).unwrap_or("rw");
            if src.is_empty() || dest.is_empty() || STANDARD_MOUNT_DESTS.contains(&dest) {
                return None;
            }
            let spec = if rw == "ro" {
                format!("{src}:{dest}:ro")
            } else {
                format!("{src}:{dest}")
            };
            Some(format!("-v {} ", shell_quote(&spec)))
        })
        .collect()
}

/// Run an SSH command and capture stdout. Commands that may legitimately fail
/// (e.g. inspecting a not-yet-existing container) should append `|| true` so the
/// ssh invocation itself succeeds and returns empty output.
fn ssh_capture(host: &str, cmd: &str) -> io::Result<String> {
    validate_ssh_host(host)?;
    let out = crate::env::command("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "--",
            host,
            cmd,
        ])
        .output()?;
    if !out.status.success() {
        return Err(ssh_command_failed(host, cmd));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_optional_remote_file(host: &str, remote_path_expr: &str) -> io::Result<String> {
    ssh_capture(
        host,
        &format!("if [ -e {remote_path_expr} ]; then cat {remote_path_expr}; fi"),
    )
}

fn ssh_run(host: &str, cmd: &str) -> io::Result<()> {
    validate_ssh_host(host)?;
    let status = crate::env::command("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "--",
            host,
            cmd,
        ])
        .status()?;
    if !status.success() {
        return Err(ssh_command_failed(host, cmd));
    }
    Ok(())
}

/// The failure every remote step reports: which host, which command, redacted.
/// A deploy runs a fixed sequence of ssh commands, so naming the command is the
/// only way the operator learns *where* the deploy stopped.
fn ssh_command_failed(host: &str, cmd: &str) -> io::Error {
    io::Error::other(format!(
        "ssh {host}: '{}' exited non-zero",
        redact_secret_envs(cmd)
    ))
}

fn ssh_run_with_stdin(host: &str, cmd: &str, input: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    validate_ssh_host(host)?;
    let mut child = crate::env::command("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "--",
            host,
            cmd,
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("ssh stdin unavailable"))?;

    // Write, then *always* close stdin and reap the child before deciding.
    // A remote that dies or exits without reading breaks the pipe mid-write;
    // returning that `BrokenPipe` straight away would both leak the unreaped
    // child and report the symptom ("Broken pipe (os error 32)") instead of the
    // cause. The exit status names the failing command, so it wins; the write
    // error only surfaces when the remote claimed success without taking the
    // input, which means the env file was never written.
    let written = stdin.write_all(input);
    drop(stdin);
    let status = child.wait()?;
    if !status.success() {
        return Err(ssh_command_failed(host, cmd));
    }
    written.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "ssh {host}: '{}' exited before accepting its piped input: {error}",
                redact_secret_envs(cmd)
            ),
        )
    })
}

fn render_env_file(env_pairs: &[(String, String)]) -> io::Result<String> {
    let mut body = String::new();
    for (key, value) in env_pairs {
        if value.chars().any(char::is_control)
            || value.contains(['\'', '"', '\\', '#'])
            || value.trim() != value
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "agent environment value for {key} cannot be represented identically by systemd and Docker env-file parsers"
                ),
            ));
        }
        body.push_str(key);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    Ok(body)
}

fn scp_file(local: &Path, host: &str, remote_path: &str) -> io::Result<()> {
    validate_ssh_host(host)?;
    let dest = format!("{host}:{remote_path}");
    let status = crate::env::command("scp")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "--",
        ])
        .arg(local)
        .arg(&dest)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "scp {} → {dest} failed",
            local.display()
        )));
    }
    Ok(())
}

fn validate_ssh_host(host: &str) -> io::Result<()> {
    if crate::inventory::ssh::is_safe_ssh_host(host) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe ssh host: {host}"),
        ))
    }
}

fn redact_secret_envs(input: &str) -> String {
    let mut keys: BTreeSet<String> = ["CORTEX_HEARTBEAT_TOKEN", "CORTEX_TOKEN", "CORTEX_API_TOKEN"]
        .into_iter()
        .map(String::from)
        .collect();
    collect_secret_env_assignment_keys(input, &mut keys);

    let mut redacted = input.to_string();
    for key in keys {
        redacted = redact_env_assignment(&redacted, &key);
    }
    redacted
}

fn collect_secret_env_assignment_keys(input: &str, out: &mut BTreeSet<String>) {
    for (equals, ch) in input.char_indices() {
        if ch != '=' {
            continue;
        }
        let start = input[..equals]
            .char_indices()
            .rev()
            .find_map(|(idx, ch)| (!is_env_key_char(ch)).then_some(idx + ch.len_utf8()))
            .unwrap_or(0);
        let key = &input[start..equals];
        if is_safe_env_key(key)
            && is_env_assignment_boundary(input, start)
            && is_secret_env_key(key)
        {
            out.insert(key.to_string());
        }
    }
}

fn is_env_assignment_boundary(input: &str, start: usize) -> bool {
    start == 0
        || input[..start]
            .chars()
            .last()
            .is_none_or(|ch| ch.is_ascii_whitespace() || ch == '\'' || ch == '"')
}

fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("API_KEY")
        || upper == "KEY"
        || upper.ends_with("_KEY")
}

fn is_safe_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(is_env_key_char)
}

fn is_env_key_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn redact_env_assignment(input: &str, key: &str) -> String {
    let needle = format!("{key}=");
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(relative) = input[cursor..].find(&needle) {
        let start = cursor + relative;
        output.push_str(&input[cursor..start]);
        output.push_str(&needle);
        output.push_str("<redacted>");
        cursor = skip_shell_word(input, start + needle.len());
    }
    output.push_str(&input[cursor..]);
    output
}

fn skip_shell_word(input: &str, start: usize) -> usize {
    let mut quote: Option<char> = None;
    for (relative, ch) in input[start..].char_indices() {
        match quote {
            Some(active) if ch == active => quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_ascii_whitespace() => return start + relative,
            None => {}
        }
    }
    input.len()
}

fn home_dir() -> Option<PathBuf> {
    crate::env::var_os("HOME").map(PathBuf::from)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
#[path = "agent_deploy_tests.rs"]
mod tests;
