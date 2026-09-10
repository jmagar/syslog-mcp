use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const LIFECYCLE_LOCK_NAME: &str = "heartbeat-agent.lifecycle.lock";
pub(crate) struct AgentLifecycleLock {
    file: fs::File,
}
pub(crate) fn acquire_heartbeat_agent_lifecycle_lock() -> io::Result<AgentLifecycleLock> {
    let home = super::cortex_home_dir()?;
    fs::create_dir_all(&home)?;
    let path = home.join(LIFECYCLE_LOCK_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "another heartbeat-agent lifecycle operation is active",
            ));
        }
    }
    Ok(AgentLifecycleLock { file })
}

pub(crate) fn heartbeat_agent_lifecycle_lock_held() -> io::Result<bool> {
    let path = super::cortex_home_dir()?.join(LIFECYCLE_LOCK_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            return Ok(false);
        }
        match io::Error::last_os_error().kind() {
            ErrorKind::WouldBlock => Ok(true),
            _ => Err(io::Error::last_os_error()),
        }
    }
    #[cfg(not(unix))]
    Ok(false)
}
impl Drop for AgentLifecycleLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

pub const RECOGNIZED_KEYS: &[&str] = &[
    "CORTEX_HEARTBEAT_TARGET",
    "CORTEX_HEARTBEAT_TOKEN",
    "CORTEX_URL",
    "CORTEX_AGENT_DOCKER",
    "CORTEX_AGENT_DOCKER_URL",
    "CORTEX_AGENT_JOURNALD",
    "CORTEX_AGENT_SYSLOG_FILE",
    "CORTEX_AGENT_FILE_TAILS",
    "CORTEX_SYSLOG_TARGET",
    "CORTEX_AGENT_AI_TRANSCRIPT_FORWARD",
    "CORTEX_AGENT_AI_TRANSCRIPTS",
    "CORTEX_AGENT_AI_TRANSCRIPT_CHECKPOINT",
    "CORTEX_AGENT_COMMAND_FORWARD",
    "CORTEX_AGENT_COMMAND_SPOOL",
    "CORTEX_AGENT_SHELL_HISTORY_FORWARD",
    "CORTEX_AGENT_SHELL_HISTORY_CHECKPOINT",
    "CORTEX_AGENT_AUTO_UPDATE",
    "CORTEX_AGENT_ALLOW_TRUSTED_OVERLAY_HTTP",
    "RUST_LOG",
];

pub fn parse_agent_env(raw: &str) -> io::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| invalid(index, "missing '='"))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err(invalid(index, "invalid key name"));
        }
        if values.contains_key(key) {
            return Err(invalid(index, "duplicate recognized key"));
        }
        let recognized = RECOGNIZED_KEYS.contains(&key);
        let denied = key == "CORTEX_API_TOKEN"
            || key == "CORTEX_REST_TOKEN"
            || key.starts_with("LD_")
            || key.starts_with("DYLD_")
            || key.contains("PROXY")
            || key.contains("TLS")
            || key.contains("CERT")
            || (!recognized
                && (key.contains("TOKEN") || key.contains("SECRET") || key.contains("PASSWORD")));
        if denied {
            return Err(invalid(index, &format!("key {key} is not permitted")));
        }
        if !recognized {
            tracing::warn!(key, "unknown heartbeat-agent environment key ignored");
            continue;
        }
        let value = parse_value(raw_value).map_err(|why| invalid(index, why))?;
        if value.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(invalid(index, "control character in value"));
        }
        values.insert(key.to_string(), value);
    }
    Ok(values)
}

fn parse_value(raw: &str) -> Result<String, &'static str> {
    if raw.starts_with('"') || raw.starts_with('\'') {
        let quote = raw.as_bytes()[0] as char;
        if raw.len() < 2 || !raw.ends_with(quote) {
            return Err("malformed quoting");
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.contains(quote) {
            return Err("embedded quote is unsupported");
        }
        Ok(inner.to_string())
    } else if raw.contains('"') || raw.contains('\'') {
        Err("malformed quoting")
    } else {
        Ok(raw.trim().to_string())
    }
}

fn invalid(index: usize, why: &str) -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        format!("heartbeat env line {}: {why}", index + 1),
    )
}

pub fn load_private_agent_env(path: &Path) -> io::Result<BTreeMap<String, String>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "heartbeat env must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "heartbeat env owner differs from current user",
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "heartbeat env mode must be 0600 or narrower",
            ));
        }
    }
    parse_agent_env(&fs::read_to_string(path)?)
}

pub fn atomic_private_write(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        let meta = fs::symlink_metadata(parent)?;
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "parent must be an owned non-symlink directory",
            ));
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        if let Ok(target) = fs::symlink_metadata(path)
            && (target.file_type().is_symlink() || target.uid() != unsafe { libc::geteuid() })
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "target must be owned and not a symlink",
            ));
        }
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing filename"))?
        .to_string_lossy();
    let mut temp: Option<(PathBuf, fs::File)> = None;
    for nonce in 0..128u32 {
        let candidate = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        match opts.open(&candidate) {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let (tmp, mut file) = temp.ok_or_else(|| {
        io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate atomic temp file",
        )
    })?;
    let result = (|| {
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn atomic_checkpoint_write(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Ok(previous) = fs::read(path) {
        atomic_private_write(&path.with_extension("json.bak"), &previous, 0o600)?;
    }
    atomic_private_write(path, content, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    #[test]
    fn parser_rejects_duplicate_and_secret_unknown() {
        assert!(parse_agent_env("RUST_LOG=x\nRUST_LOG=y\n").is_err());
        assert!(parse_agent_env("OTHER_TOKEN=x\n").is_err());
        assert_eq!(
            parse_agent_env("RUST_LOG='warn'\nUNKNOWN=x\n").unwrap()["RUST_LOG"],
            "warn"
        );
    }

    #[test]
    fn trusted_overlay_http_opt_in_is_recognized() {
        let parsed = parse_agent_env("CORTEX_AGENT_ALLOW_TRUSTED_OVERLAY_HTTP=true\n").unwrap();
        assert_eq!(parsed["CORTEX_AGENT_ALLOW_TRUSTED_OVERLAY_HTTP"], "true");
    }
    #[cfg(unix)]
    #[test]
    fn private_loader_rejects_broad_mode_and_symlink() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.env");
        fs::write(&p, "RUST_LOG=warn\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_private_agent_env(&p).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_private_agent_env(&p).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_mode_and_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x/env");
        atomic_private_write(&p, b"one", 0o600).unwrap();
        atomic_private_write(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn lifecycle_probe_distinguishes_persistent_file_from_active_lock() {
        let d = tempfile::tempdir().unwrap();
        let previous = crate::env::var_os("CORTEX_HOME");
        crate::env::set_test_var("CORTEX_HOME", d.path());
        let lock = acquire_heartbeat_agent_lifecycle_lock().unwrap();
        assert!(heartbeat_agent_lifecycle_lock_held().unwrap());
        drop(lock);
        assert!(!heartbeat_agent_lifecycle_lock_held().unwrap());
        match previous {
            Some(value) => crate::env::set_test_var("CORTEX_HOME", value),
            None => crate::env::remove_test_var("CORTEX_HOME"),
        }
    }
}
