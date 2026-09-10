use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::heartbeat_agent_env::atomic_private_write;

pub(crate) const LABEL: &str = "ai.dinglebear.cortex-heartbeat-agent";
pub(crate) const LEGACY_LABEL: &str = "ai.dinglebear.cortex-transcript-forwarder";

pub(crate) fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}
pub(crate) fn legacy_plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LEGACY_LABEL}.plist"))
}

fn xml(value: &Path) -> String {
    xml_text(&value.to_string_lossy())
}
fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn render_plist(
    binary: &Path,
    env: &Path,
    host_id: &Path,
    stdout: &Path,
    stderr: &Path,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{}</string><string>heartbeat</string><string>agent</string><string>--env-file</string><string>{}</string><string>--host-id-path</string><string>{}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>15</integer><key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        xml(binary),
        xml(env),
        xml(host_id),
        xml(stdout),
        xml(stderr)
    )
}

pub(crate) fn install_plist(path: &Path, content: &str) -> io::Result<()> {
    atomic_private_write(path, content.as_bytes(), 0o600)
}

fn launchctl(uid: u32, args: &[&str]) -> io::Result<Output> {
    let program = std::env::var_os("CORTEX_TEST_LAUNCHCTL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/bin/launchctl"));
    let mut child = Command::new(program)
        .args(args)
        .env("CORTEX_LAUNCHD_UID", uid.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = std::env::var("CORTEX_TEST_COMMAND_DEADLINE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(30));
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "launchctl command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn domain(uid: u32) -> String {
    format!("gui/{uid}")
}

pub(crate) fn bootstrap(uid: u32, plist: &Path) -> io::Result<()> {
    let d = domain(uid);
    let path = plist
        .to_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "non-UTF8 plist path"))?;
    if print(uid, LABEL)?.is_none() {
        let mut last_error = None;
        for attempt in 0..4 {
            let out = launchctl(uid, &["bootstrap", &d, path])?;
            if out.status.success() {
                last_error = None;
                break;
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("already loaded") {
                last_error = None;
                break;
            }
            last_error = Some(io::Error::other(format!(
                "launchctl bootstrap failed: {}",
                stderr.trim()
            )));
            if attempt < 3 {
                std::thread::sleep(Duration::from_millis(250 * (attempt + 1) as u64));
            }
        }
        if let Some(error) = last_error {
            return Err(error);
        }
    }
    let target = format!("{d}/{LABEL}");
    let out = launchctl(uid, &["kickstart", "-k", &target])?;
    if !out.status.success() {
        return Err(io::Error::other("launchctl kickstart failed"));
    }
    Ok(())
}
pub(crate) fn bootout(uid: u32, label: &str) -> io::Result<()> {
    let target = format!("{}/{label}", domain(uid));
    let out = launchctl(uid, &["bootout", &target])?;
    if out.status.success()
        || String::from_utf8_lossy(&out.stderr).contains("Could not find service")
    {
        Ok(())
    } else {
        Err(io::Error::other("launchctl bootout failed"))
    }
}
pub(crate) fn print(uid: u32, label: &str) -> io::Result<Option<String>> {
    let target = format!("{}/{label}", domain(uid));
    let out = launchctl(uid, &["print", &target])?;
    if out.status.success() {
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

pub(crate) fn rotate_log(path: &Path, max: u64) -> io::Result<()> {
    if fs::metadata(path).map(|m| m.len() > max).unwrap_or(false) {
        let old = path.with_extension("log.1");
        let _ = fs::remove_file(&old);
        fs::rename(path, old)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plist_is_deterministic_and_escapes() {
        let p = render_plist(
            Path::new("/a & b/cortex"),
            Path::new("/e<.env"),
            Path::new("/h"),
            Path::new("/o"),
            Path::new("/x"),
        );
        assert_eq!(
            p,
            render_plist(
                Path::new("/a & b/cortex"),
                Path::new("/e<.env"),
                Path::new("/h"),
                Path::new("/o"),
                Path::new("/x")
            )
        );
        assert!(p.contains("/a &amp; b/cortex"));
        assert!(p.contains("/e&lt;.env"));
        assert!(!p.contains("TOKEN"));
    }
}
