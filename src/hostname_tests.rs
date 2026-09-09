use super::*;

use serial_test::serial;

const SENTINEL: &str = "cortex-hostname-sentinel.invalid";

/// Restores the previous value of a test-overlay env var on drop.
struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = crate::env::var(key).ok();
        crate::env::set_test_var(key, value);
        Self { key, previous }
    }

    fn unset(key: &'static str) -> Self {
        let previous = crate::env::var(key).ok();
        crate::env::remove_test_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => crate::env::set_test_var(self.key, value),
            None => crate::env::remove_test_var(self.key),
        }
    }
}

/// Pins the precedence contract: `$HOSTNAME` is inheritable and may be stale, so
/// the syscall wins whenever it answers. Where the syscall cannot answer, the
/// env var must still be honoured — both halves are asserted so the test proves
/// the ordering on any host it runs on.
#[test]
#[serial]
fn syscall_outranks_the_hostname_env_var() {
    let _guard = EnvGuard::set("HOSTNAME", SENTINEL);

    #[cfg(unix)]
    match syscall_hostname() {
        Some(from_syscall) => assert_eq!(
            local_hostname(),
            from_syscall,
            "gethostname() must win over $HOSTNAME"
        ),
        None => assert_eq!(
            local_hostname(),
            SENTINEL,
            "$HOSTNAME must be used when gethostname() cannot answer"
        ),
    }

    #[cfg(not(unix))]
    {
        let _computer = EnvGuard::unset("COMPUTERNAME");
        assert_eq!(local_hostname(), SENTINEL);
    }
}

#[cfg(not(unix))]
#[test]
#[serial]
fn computername_outranks_the_hostname_env_var() {
    let _computer = EnvGuard::set("COMPUTERNAME", "cortex-computername.invalid");
    let _hostname = EnvGuard::set("HOSTNAME", SENTINEL);

    assert_eq!(local_hostname(), "cortex-computername.invalid");
}

#[test]
#[serial]
fn env_hostname_reads_and_filters_the_env_var() {
    {
        let _guard = EnvGuard::set("HOSTNAME", SENTINEL);
        assert_eq!(env_hostname("HOSTNAME").as_deref(), Some(SENTINEL));
    }
    {
        let _guard = EnvGuard::set("HOSTNAME", "  localhost  ");
        assert_eq!(env_hostname("HOSTNAME"), None);
    }
    {
        let _guard = EnvGuard::unset("HOSTNAME");
        assert_eq!(env_hostname("HOSTNAME"), None);
    }
}

/// `localhost` names the loopback interface on every machine, so accepting it
/// would collapse distinct hosts into one identity.
#[test]
fn usable_rejects_blank_and_loopback_names() {
    assert_eq!(usable(""), None);
    assert_eq!(usable("   "), None);
    assert_eq!(usable("localhost"), None);
    assert_eq!(usable("LocalHost"), None);
    assert_eq!(usable(" localhost\n"), None);

    assert_eq!(usable(" tower \n").as_deref(), Some("tower"));
    // Only the bare loopback name is rejected; real names that merely contain
    // it stay usable.
    assert_eq!(
        usable("localhost.lan").as_deref(),
        Some("localhost.lan"),
        "only the bare loopback name is ambiguous"
    );
}

/// The fallback must be unmistakable: never a name a real machine can report,
/// and never one of the two values this crate used to record.
#[test]
fn unresolved_sentinel_cannot_collide_with_a_real_identity() {
    assert!(
        UNRESOLVED_HOSTNAME.ends_with(".invalid"),
        "the sentinel must sit in the RFC 2606 reserved TLD"
    );
    assert_ne!(UNRESOLVED_HOSTNAME, "localhost");
    assert_ne!(UNRESOLVED_HOSTNAME, "unknown");
}

#[test]
#[serial]
fn local_hostname_never_reports_an_ambiguous_identity() {
    let _guard = EnvGuard::unset("HOSTNAME");

    let resolved = local_hostname();

    assert!(!resolved.is_empty());
    assert_ne!(resolved, "localhost");
    assert_eq!(resolved.trim(), resolved);
}
