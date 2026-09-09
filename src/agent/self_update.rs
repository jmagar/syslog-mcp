//! Agent self-update — keeps the host agent binary in lockstep with the cortex
//! server it reports to.
//!
//! The server advertises its own version + a download directive in the heartbeat
//! `202` response (see `heartbeat.rs::AgentUpdateDirective`). When the agent's
//! compiled version differs from the server's, [`maybe_update`] downloads the
//! server's binary over the same bearer-authenticated channel, verifies its
//! SHA-256, sanity-checks that it runs and self-reports the expected version,
//! atomically swaps it into place (keeping a `.bak`), and re-execs.
//!
//! Safety model (matches the approved design):
//! - **integrity**: SHA-256 is either carried by the authenticated heartbeat or
//!   fetched from an authenticated same-origin server path, then verified
//!   before anything is written over the live path.
//! - **pre-swap validation**: the freshly downloaded binary must execute
//!   `--version` and report the advertised version, so a corrupt or incompatible
//!   download is never installed.
//! - **bounded rollback**: a marker file records the in-flight update. The new
//!   process clears it after its first successful heartbeat. If `MAX_ATTEMPTS`
//!   restarts elapse without that confirmation, [`confirm_or_rollback`] restores
//!   the `.bak` and re-execs the previous binary.
//!
//! Gated by `CORTEX_AGENT_AUTO_UPDATE` (default on) in the caller.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

/// Number of agent restarts allowed without a confirming heartbeat before the
/// in-flight update is rolled back to the previous `.bak` binary.
const MAX_ATTEMPTS: u32 = 3;

pub const SELF_UPDATE_DEADLINE: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_AGENT_BINARY_BYTES: usize = 128 * 1024 * 1024;
const MARKER_FILE: &str = ".cortex-update-state.json";
const RETAIN_BACKUPS: usize = 2;

/// Server-issued update directive, deserialized from the heartbeat `202` body.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentUpdateDirective {
    /// Target version the agent should converge to (the server's own version).
    pub version: String,
    /// Exact target platform. A directive for another platform fails closed.
    pub os: String,
    pub arch: String,
    /// Path on the server to download the matching binary from, resolved
    /// relative to the agent's configured heartbeat target.
    pub path: String,
    /// Lowercase hex SHA-256 of the target binary.
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub checksum_path: Option<String>,
    #[serde(default = "default_binary_format")]
    pub format: String,
}

fn default_binary_format() -> String {
    "binary".to_string()
}

/// Persisted record of an in-flight update, used for bounded auto-rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateMarker {
    /// Version we attempted to install (matches the running binary on success).
    target: String,
    /// Absolute path of the backed-up previous binary to roll back to.
    bak: PathBuf,
    /// Restarts observed since the swap without a confirming heartbeat.
    attempts: u32,
}

fn marker_path(exe: &Path) -> PathBuf {
    exe.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(MARKER_FILE)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Join a base URL with a server-supplied relative path.
fn join_url(base: &str, path: &str) -> Result<String> {
    if path.starts_with("//") || path.contains("://") {
        bail!("agent update path must be relative to the configured server");
    }
    let base_url = reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/')))
        .context("parse agent update base URL")?;
    let joined = base_url
        .join(path.trim_start_matches('/'))
        .context("resolve agent update path")?;
    if joined.scheme() != base_url.scheme()
        || joined.host_str() != base_url.host_str()
        || joined.port_or_known_default() != base_url.port_or_known_default()
    {
        bail!("agent update path escaped the configured server origin");
    }
    Ok(joined.to_string())
}

/// True when the directive asks for a version different from the one compiled
/// into this binary. The server is the source of truth, so any difference
/// (upgrade or downgrade) converges the agent toward the server.
pub fn update_needed(directive: &AgentUpdateDirective) -> bool {
    directive.version != env!("CARGO_PKG_VERSION")
        && !is_semver_downgrade(env!("CARGO_PKG_VERSION"), &directive.version)
}

fn numeric_semver(version: &str) -> Option<(u64, u64, u64)> {
    let core = version
        .strip_prefix('v')
        .unwrap_or(version)
        .split(['-', '+'])
        .next()?;
    let mut parts = core.split('.');
    let result = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    (parts.next().is_none()).then_some(result)
}

fn is_semver_downgrade(current: &str, target: &str) -> bool {
    matches!((numeric_semver(current), numeric_semver(target)), (Some(current), Some(target)) if target < current)
}

fn directive_matches_platform(directive: &AgentUpdateDirective) -> bool {
    let os_matches = directive.os.eq_ignore_ascii_case(std::env::consts::OS);
    let arch_matches = if std::env::consts::OS == "macos" {
        matches!(directive.arch.as_str(), "aarch64" | "arm64")
            && std::env::consts::ARCH == "aarch64"
    } else {
        matches!(directive.arch.as_str(), "x86_64" | "amd64") && std::env::consts::ARCH == "x86_64"
    };
    os_matches && arch_matches
}

pub fn build_update_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(CHUNK_IDLE_TIMEOUT)
        .timeout(SELF_UPDATE_DEADLINE)
        .build()
        .context("build agent self-update HTTP client")
}

async fn download_binary(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    max_bytes: usize,
    first_byte_timeout: Duration,
    chunk_idle_timeout: Duration,
) -> Result<Vec<u8>> {
    let mut request = client.get(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .context("agent binary download failed")?
        .error_for_status()
        .context("agent binary download returned error status")?;

    if let Some(content_length) = response.content_length()
        && content_length > max_bytes as u64
    {
        bail!("agent binary content length {content_length} exceeds {max_bytes}-byte limit");
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut stream = response.bytes_stream();
    let mut first_chunk = true;

    loop {
        let deadline = if first_chunk {
            first_byte_timeout
        } else {
            chunk_idle_timeout
        };
        let next = timeout(deadline, stream.next()).await.map_err(|_| {
            if first_chunk {
                anyhow!("agent binary first byte exceeded {deadline:?}")
            } else {
                anyhow!("agent binary download stalled for {deadline:?}")
            }
        })?;

        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.context("read agent binary body")?;
        let new_len = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("agent binary size overflow"))?;
        if new_len > max_bytes {
            bail!("agent binary exceeded {max_bytes}-byte limit while streaming");
        }
        bytes.extend_from_slice(&chunk);
        first_chunk = false;
    }

    Ok(bytes)
}

/// Download, verify, install, and re-exec the advertised binary. On success this
/// function does not return (the process image is replaced). It returns `Ok(())`
/// only when no update was needed; any failure leaves the live binary untouched.
pub async fn maybe_update(
    client: &reqwest::Client,
    target_base: &str,
    token: Option<&str>,
    directive: &AgentUpdateDirective,
) -> Result<()> {
    if !update_needed(directive) {
        return Ok(());
    }
    if !directive_matches_platform(directive) {
        bail!(
            "agent update platform mismatch: directive {}/{} does not match {}/{}",
            directive.os,
            directive.arch,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }

    let current = env!("CARGO_PKG_VERSION");
    let exe = std::env::current_exe().context("resolve current_exe")?;
    ensure_binary_still_present(&exe)?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current_exe has no parent dir"))?
        .to_path_buf();
    let _lifecycle_lock =
        crate::setup::heartbeat_agent_env::acquire_heartbeat_agent_lifecycle_lock()
            .context("acquire shared heartbeat-agent lifecycle lock")?;
    prune_update_artifacts(&dir)?;

    tracing::warn!(
        from = current,
        to = %directive.version,
        "agent behind server; downloading update"
    );

    if directive.format != "binary" {
        bail!("unsupported agent update format '{}'", directive.format);
    }

    let expected_sha256 = match directive.sha256.as_deref() {
        Some(sha256) => sha256.to_string(),
        None => {
            let checksum_path = directive.checksum_path.as_deref().ok_or_else(|| {
                anyhow!("server update directive omitted both sha256 and checksum_path")
            })?;
            let checksum_url = join_url(target_base, checksum_path)?;
            let checksum_bytes = download_binary(
                client,
                &checksum_url,
                token,
                4096,
                FIRST_BYTE_TIMEOUT,
                CHUNK_IDLE_TIMEOUT,
            )
            .await
            .context("download agent binary checksum")?;
            let checksum = std::str::from_utf8(&checksum_bytes)
                .context("agent binary checksum is not UTF-8")?
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("agent binary checksum response is empty"))?;
            if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("agent binary checksum response is not a SHA-256 digest");
            }
            checksum.to_ascii_lowercase()
        }
    };

    // 1. Download over the authenticated channel with explicit size and idle limits.
    let url = join_url(target_base, &directive.path)?;
    let bytes = download_binary(
        client,
        &url,
        token,
        MAX_AGENT_BINARY_BYTES,
        FIRST_BYTE_TIMEOUT,
        CHUNK_IDLE_TIMEOUT,
    )
    .await?;

    // 2. Verify integrity before touching disk near the live path.
    let got = sha256_hex(&bytes);
    if !got.eq_ignore_ascii_case(&expected_sha256) {
        bail!(
            "agent binary sha256 mismatch: expected {}, got {got}",
            expected_sha256
        );
    }

    // 3. Stage into the same directory (atomic rename requires same filesystem).
    let tmp_suffix = if cfg!(windows) { ".tmp.exe" } else { ".tmp" };
    ensure_disk_capacity(&dir, bytes.len().saturating_mul(2))?;
    let tmp = unique_staging_path(&dir, &directive.version, tmp_suffix);
    write_staged_exclusive(&tmp, &bytes)?;
    set_executable(&tmp)?;

    // 4. Pre-swap validation: the new binary must run and self-report the
    //    advertised version. Guards against corrupt/incompatible downloads.
    if let Err(error) = validate_binary(&tmp, &directive.version) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.context("staged agent binary failed validation; not installed"));
    }

    // 5. Keep a rollback copy of the current binary, then atomically swap.
    let bak = backup_current_binary(&exe, &dir, current)?;

    // Record the in-flight update before the swap so a boot-crash is recoverable.
    write_marker(
        &exe,
        &UpdateMarker {
            target: directive.version.clone(),
            bak: bak.clone(),
            attempts: 0,
        },
    )?;

    tracing::warn!(
        from = current,
        to = %directive.version,
        "agent binary updated; re-executing"
    );
    install_and_restart(&tmp, &exe, Some(&bak))
}

/// On Linux, `current_exe()` resolves through `/proc/self/exe`. If the file at
/// that path was replaced out from under the running process (e.g. a
/// concurrent rebuild rewrote the exact path this process was exec'd from),
/// the kernel appends " (deleted)" to the resolved path once the original
/// dentry is unlinked, and any filesystem op against it fails with ENOENT.
/// Detect that up front and bail with a clear diagnosis instead of a cryptic
/// ENOENT three steps later out of `backup_current_binary`.
fn ensure_binary_still_present(exe: &Path) -> Result<()> {
    if !exe.exists() {
        bail!(
            "current binary no longer exists at {exe:?} (likely replaced by something \
             other than self-update, e.g. a concurrent rebuild); skipping this update cycle"
        );
    }
    Ok(())
}

fn unique_staging_path(dir: &Path, version: &str, suffix: &str) -> PathBuf {
    dir.join(format!(
        ".cortex-update-{version}-{}-{}{suffix}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

fn write_staged_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create staged binary {path:?}"))?;
    file.write_all(bytes)
        .with_context(|| format!("write staged binary {path:?}"))?;
    file.sync_all()
        .with_context(|| format!("fsync staged binary {path:?}"))?;
    Ok(())
}

#[cfg(unix)]
fn ensure_disk_capacity(dir: &Path, required: usize) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(dir.as_os_str().as_bytes()).context("update directory contains NUL")?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect free space for agent update");
    }
    let stats = unsafe { stats.assume_init() };
    let available = u128::from(stats.f_bavail) * u128::from(stats.f_frsize);
    if available < required as u128 {
        bail!(
            "insufficient disk for agent update: need {required} bytes for stage and backup, have {available}"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_disk_capacity(_dir: &Path, _required: usize) -> Result<()> {
    Ok(())
}

fn prune_update_artifacts(dir: &Path) -> Result<()> {
    let mut backups = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read update directory {dir:?}"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".cortex-update-")
            && (name.ends_with(".tmp") || name.ends_with(".tmp.exe"))
        {
            let _ = std::fs::remove_file(entry.path());
        } else if name.starts_with("cortex.bak-") {
            backups.push((entry.metadata()?.modified().ok(), entry.path()));
        }
    }
    backups.sort_by_key(|(modified, _)| *modified);
    let remove_count = backups.len().saturating_sub(RETAIN_BACKUPS);
    for (_, path) in backups.into_iter().take(remove_count) {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn backup_current_binary(exe: &Path, dir: &Path, current: &str) -> Result<PathBuf> {
    let base = unique_backup_path_base(dir, current);
    for attempt in 0..100 {
        let bak = if attempt == 0 {
            base.clone()
        } else {
            dir.join(format!(
                "{}-{attempt}",
                base.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("cortex.bak")
            ))
        };
        match std::fs::hard_link(exe, &bak).or_else(|_| std::fs::copy(exe, &bak).map(|_| ())) {
            Ok(()) => return Ok(bak),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("back up current binary to {bak:?}"));
            }
        }
    }
    bail!("could not allocate a unique backup path for agent self-update")
}

fn unique_backup_path_base(dir: &Path, current: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    dir.join(format!("cortex.bak-{current}-{pid}-{now}"))
}

/// Confirm a just-installed update is healthy, or roll back if it never settled.
///
/// Called once at agent startup, before the heartbeat loop. If a marker shows
/// the running binary matches the intended target, it bumps the restart counter;
/// once `MAX_ATTEMPTS` restarts pass without [`confirm_update_success`] clearing
/// the marker (i.e. no successful heartbeat), it restores the `.bak` and re-execs.
pub fn confirm_or_rollback() -> Result<()> {
    let exe = std::env::current_exe().context("resolve current_exe")?;
    let path = marker_path(&exe);
    let Some(mut marker) = read_marker(&path) else {
        return Ok(());
    };

    let current = env!("CARGO_PKG_VERSION");
    if marker.target != current {
        // Running binary is not the one the marker tracked (e.g. manual change);
        // the marker is stale — drop it without acting.
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }

    if marker.attempts >= MAX_ATTEMPTS {
        tracing::error!(
            target = %marker.target,
            attempts = marker.attempts,
            "agent update never confirmed healthy; rolling back"
        );
        if marker.bak.exists() {
            return install_and_restart(&marker.bak, &exe, None);
        }
        // No backup to restore — give up on rollback but clear the marker so we
        // stop looping; the operator must intervene.
        let _ = std::fs::remove_file(&path);
        bail!(
            "agent update unhealthy but no rollback binary at {:?}",
            marker.bak
        );
    }

    marker.attempts += 1;
    write_marker(&exe, &marker)?;
    Ok(())
}

/// Clear the in-flight update marker after the agent's first successful
/// heartbeat, finalizing the update. Also prunes the retained `.bak`.
pub fn confirm_update_success() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let path = marker_path(&exe);
    if let Some(marker) = read_marker(&path) {
        tracing::info!(version = %marker.target, "agent update confirmed healthy");
        let _ = std::fs::remove_file(&marker.bak);
        let _ = std::fs::remove_file(&path);
    }
}

fn validate_binary(path: &Path, expected_version: &str) -> Result<()> {
    let output = crate::env::command(path)
        .arg("--version")
        .output()
        .context("run --version on staged binary")?;
    if !output.status.success() {
        bail!("staged binary --version exited with {}", output.status);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.split_whitespace().last() != Some(expected_version) {
        bail!(
            "staged binary reported '{}', expected version {expected_version}",
            stdout.trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).context("chmod staged binary")
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn install_and_restart(staged: &Path, exe: &Path, _fallback: Option<&Path>) -> Result<()> {
    use std::os::unix::process::CommandExt;
    std::fs::rename(staged, exe).with_context(|| format!("swap new binary into {exe:?}"))?;
    if let Some(parent) = exe.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("fsync agent binary directory {parent:?}"))?;
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // `exec` only returns on failure.
    let error = crate::env::command(exe).args(args).exec();
    Err(anyhow!("re-exec of {exe:?} failed: {error}"))
}

#[cfg(any(windows, test))]
fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(any(windows, test))]
fn windows_quote_arg(value: &str) -> String {
    if !value.is_empty()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'"')
    {
        return value.to_string();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
        }
        backslashes = 0;
        quoted.push(ch);
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(any(windows, test))]
fn windows_command_line(args: &[std::ffi::OsString]) -> String {
    args.iter()
        .map(|arg| windows_quote_arg(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(windows, test))]
fn windows_swap_script(
    pid: u32,
    staged: &Path,
    exe: &Path,
    fallback: Option<&Path>,
    args: &[std::ffi::OsString],
) -> String {
    let staged = powershell_literal(&staged.to_string_lossy());
    let exe = powershell_literal(&exe.to_string_lossy());
    let args = powershell_literal(&windows_command_line(args));
    let status = powershell_literal(&exe_path_with_suffix(exe.as_str(), ".handoff.log"));
    let fallback = fallback
        .map(|path| powershell_literal(&path.to_string_lossy()))
        .unwrap_or_else(|| "$null".to_string());
    format!(
        "$ErrorActionPreference='Stop';$status={status};$fallback={fallback};$start={{$task=Get-ScheduledTask -TaskName 'CortexHeartbeatAgent' -ErrorAction SilentlyContinue;if($task){{for($i=0;$i -lt 100 -and $task.State -eq 'Running';$i++){{Start-Sleep -Milliseconds 100;$task=Get-ScheduledTask -TaskName 'CortexHeartbeatAgent'}};if($task.State -eq 'Running'){{throw 'CortexHeartbeatAgent task did not become restartable'}};for($i=0;$i -lt 100 -and $task.State -ne 'Running';$i++){{try{{Start-ScheduledTask -TaskName 'CortexHeartbeatAgent' -ErrorAction Stop}}catch{{}};Start-Sleep -Milliseconds 100;$task=Get-ScheduledTask -TaskName 'CortexHeartbeatAgent'}};if($task.State -ne 'Running'){{throw 'CortexHeartbeatAgent task did not enter Running state'}}}}else{{$psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName={exe};$psi.UseShellExecute=$false;$psi.Arguments={args};[void][Diagnostics.Process]::Start($psi)}}}};try{{$p=[Diagnostics.Process]::GetProcessById({pid});$p.WaitForExit()}}catch [ArgumentException]{{}};try{{Move-Item -LiteralPath {staged} -Destination {exe} -Force;& $start;Set-Content -LiteralPath $status -Value 'swap_started' -Encoding Ascii}}catch{{$message=$_.Exception.ToString();Set-Content -LiteralPath $status -Value $message -Encoding UTF8;if($fallback -and (Test-Path -LiteralPath $fallback)){{Copy-Item -LiteralPath $fallback -Destination {exe} -Force;& $start}}else{{throw}}}}"
    )
}

#[cfg(any(windows, test))]
fn exe_path_with_suffix(quoted_exe: &str, suffix: &str) -> String {
    let raw = quoted_exe
        .strip_prefix('\'')
        .and_then(|v| v.strip_suffix('\''))
        .unwrap_or(quoted_exe);
    format!("{raw}{suffix}")
}

#[cfg(windows)]
fn install_and_restart(staged: &Path, exe: &Path, fallback: Option<&Path>) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let script = windows_swap_script(std::process::id(), staged, exe, fallback, &args);
    crate::env::command("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("spawn Windows agent update handoff")?;
    std::process::exit(0)
}

#[cfg(not(any(unix, windows)))]
fn install_and_restart(_staged: &Path, _exe: &Path, _fallback: Option<&Path>) -> Result<()> {
    bail!("agent self-update is unsupported on this platform")
}

fn write_marker(exe: &Path, marker: &UpdateMarker) -> Result<()> {
    let path = marker_path(exe);
    let json = serde_json::to_string(marker).context("serialize update marker")?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create update marker {tmp:?}"))?;
        file.write_all(json.as_bytes())
            .context("write update marker")?;
        file.sync_all().context("fsync update marker")?;
        std::fs::rename(&tmp, &path).with_context(|| format!("publish update marker {path:?}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn read_marker(path: &Path) -> Option<UpdateMarker> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[cfg(test)]
#[path = "self_update_tests.rs"]
mod tests;
