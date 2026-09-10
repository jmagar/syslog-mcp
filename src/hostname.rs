//! Single source of truth for resolving this machine's hostname.
//!
//! Cortex stamps `hostname` on every log row, heartbeat, command-log record and
//! transcript event, then groups, filters and correlates on that value. It is an
//! identity, not a label, so resolution has to be deliberate:
//!
//! 1. **`gethostname(2)`** — the kernel's own answer, and the only source that
//!    is actually about *this machine*.
//! 2. **`$HOSTNAME`** — inherited from whatever launched the process, so it can
//!    be stale (a container image baked at build time), deliberately overridden,
//!    or simply absent. Useful as a fallback, wrong as a primary source.
//! 3. **Platform equivalents** — `/proc/sys/kernel/hostname` on Linux (the same
//!    kernel value `gethostname` reports, reachable when the syscall path is
//!    unavailable), `%COMPUTERNAME%` on Windows.
//! 4. **[`UNRESOLVED_HOSTNAME`]** — an explicit sentinel, never a plausible name.

/// Recorded when no source yields a usable hostname.
///
/// This deliberately cannot collide with a real machine identity. `.invalid` is
/// reserved by RFC 2606 and is guaranteed never to resolve, so no fleet host can
/// legitimately report it. The alternatives are worse:
///
/// - `"localhost"` is a name a real machine genuinely reports, and cortex
///   already stores loopback-sourced rows. Using it as the failure sentinel
///   would silently merge every unresolvable host into one identity and mix it
///   with real entries — an unattributed row would look attributed.
/// - `"unknown"` is not reserved either, and reads like data rather than a
///   failure marker when it turns up in a `hosts` listing.
///
/// A row filed under this name is a visible bug report: it says "this host could
/// not identify itself", and it cannot be confused with anything else.
pub(crate) const UNRESOLVED_HOSTNAME: &str = "unresolved-host.invalid";

/// Resolve this machine's hostname, falling back to [`UNRESOLVED_HOSTNAME`].
pub(crate) fn local_hostname() -> String {
    resolve().unwrap_or_else(|| {
        warn_unresolved_hostname();
        UNRESOLVED_HOSTNAME.to_string()
    })
}

/// The ordered resolution chain. `None` means no source produced a usable name.
fn resolve() -> Option<String> {
    #[cfg(unix)]
    {
        syscall_hostname()
            .or_else(|| env_hostname("HOSTNAME"))
            .or_else(proc_hostname)
    }
    #[cfg(not(unix))]
    {
        // Windows has no `gethostname` here; `%COMPUTERNAME%` is the OS-set
        // equivalent and outranks the inheritable `$HOSTNAME` for the same
        // reason the syscall outranks it on unix.
        env_hostname("COMPUTERNAME").or_else(|| env_hostname("HOSTNAME"))
    }
}

/// Accept a candidate only if it can serve as a fleet identity.
///
/// `localhost` is rejected everywhere it appears: it names the loopback
/// interface on every machine, so storing it would collapse distinct hosts into
/// one bucket. Falling through to the next source (and ultimately to
/// [`UNRESOLVED_HOSTNAME`]) keeps that ambiguity out of the database.
fn usable(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("localhost") {
        return None;
    }
    Some(trimmed.to_string())
}

fn env_hostname(key: &str) -> Option<String> {
    crate::env::var(key).ok().as_deref().and_then(usable)
}

#[cfg(unix)]
fn syscall_hostname() -> Option<String> {
    let mut bytes = [0_u8; 256];
    // SAFETY: `bytes` is writable for its full advertised length. gethostname
    // writes at most that many bytes; we find the first NUL (or use the full
    // buffer, for a truncated unterminated name) before validating UTF-8.
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return None;
    }
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).ok().and_then(usable)
}

#[cfg(target_os = "linux")]
fn proc_hostname() -> Option<String> {
    match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(name) => usable(&name),
        Err(error) => {
            tracing::debug!(error = %error, "Linux proc hostname unavailable");
            None
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn proc_hostname() -> Option<String> {
    None
}

/// Warn once per process when the hostname cannot be resolved. Rows filed under
/// the sentinel do not correspond to any fleet host, so correlation queries for
/// the real host silently return nothing — worth one loud line.
fn warn_unresolved_hostname() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            fallback = UNRESOLVED_HOSTNAME,
            "could not resolve a hostname (gethostname failed and no environment \
             or platform source produced one) — recorded rows will be unattributed"
        );
    });
}

#[cfg(test)]
#[path = "hostname_tests.rs"]
mod tests;
