//! Process-environment access with a test-only overlay.
//!
//! Rust 2024 makes process-environment mutation unsafe on platforms where
//! libc environment reads can race with writes. Cortex never needs to mutate
//! its own environment in production. Tests exercise env precedence through a
//! Rust map instead of the process environment, removing that unsafe boundary.

use std::ffi::{OsStr, OsString};

#[cfg(any(test, feature = "test-support"))]
use std::collections::{HashMap, HashSet};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{OnceLock, RwLock};

// Binary and library tests share this single map through the `test-support`
// feature. Production builds compile none of the override storage or setters.
#[cfg(any(test, feature = "test-support"))]
static TEST_OVERRIDES: OnceLock<RwLock<HashMap<OsString, Option<OsString>>>> = OnceLock::new();

#[doc(hidden)]
#[inline]
pub fn var<K: AsRef<OsStr>>(key: K) -> Result<String, std::env::VarError> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(value) = test_override(key.as_ref()) {
        return match value {
            Some(value) => value.into_string().map_err(std::env::VarError::NotUnicode),
            None => Err(std::env::VarError::NotPresent),
        };
    }
    std::env::var(key)
}

#[doc(hidden)]
#[inline]
pub fn var_os<K: AsRef<OsStr>>(key: K) -> Option<OsString> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(value) = test_override(key.as_ref()) {
        return value;
    }
    std::env::var_os(key)
}

#[cfg(any(test, feature = "test-support"))]
fn test_override(key: &OsStr) -> Option<Option<OsString>> {
    TEST_OVERRIDES
        .get()?
        .read()
        .expect("test environment overlay lock poisoned")
        .get(key)
        .cloned()
}

/// Set a test-only environment override without mutating the process environment.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn set_test_var<K, V>(key: K, value: V)
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    TEST_OVERRIDES
        .get_or_init(|| RwLock::new(HashMap::new()))
        .write()
        .expect("test environment overlay lock poisoned")
        .insert(
            key.as_ref().to_os_string(),
            Some(value.as_ref().to_os_string()),
        );
}

/// Mask a key from the real process environment for tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn remove_test_var<K: AsRef<OsStr>>(key: K) {
    TEST_OVERRIDES
        .get_or_init(|| RwLock::new(HashMap::new()))
        .write()
        .expect("test environment overlay lock poisoned")
        .insert(key.as_ref().to_os_string(), None);
}

// Program names that must resolve as missing, regardless of what is really on
// `PATH`. See [`mask_test_programs`].
#[cfg(any(test, feature = "test-support"))]
static MASKED_PROGRAMS: OnceLock<RwLock<HashSet<OsString>>> = OnceLock::new();

/// Directory component that cannot exist, so a masked program spawns with the
/// same `ErrorKind::NotFound` a genuinely absent binary would produce. Any path
/// with more than one component bypasses the platform's `PATH` search entirely.
#[cfg(any(test, feature = "test-support"))]
const MASKED_PROGRAM_DIR: &str = "cortex-test-masked-program-does-not-exist";

/// Make specific bare program names resolve as missing until the returned guard
/// is dropped.
///
/// This exists so a test asserting "this command is not installed" does not have
/// to replace `PATH` to say so. The override map is process-global, so replacing
/// `PATH` with a fixture directory takes every *other* test's subprocess spawns
/// down with it — they stop finding `sh`, `git`, and everything else — and under
/// plain `cargo test` those tests run concurrently. Masking states the actual
/// intent instead, and scopes the blast radius to the named programs.
///
/// The mask is still process-global: only mask programs whose spawning tests are
/// serialized against this one.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use = "the mask is lifted when the guard is dropped"]
pub fn mask_test_programs<I, S>(names: I) -> MaskedPrograms
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let names: Vec<OsString> = names
        .into_iter()
        .map(|name| name.as_ref().to_os_string())
        .collect();
    let mut masked = MASKED_PROGRAMS
        .get_or_init(|| RwLock::new(HashSet::new()))
        .write()
        .expect("masked program set lock poisoned");
    for name in &names {
        masked.insert(name.clone());
    }
    drop(masked);
    MaskedPrograms(names)
}

/// Guard returned by [`mask_test_programs`]; lifts the mask on drop.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct MaskedPrograms(Vec<OsString>);

#[cfg(any(test, feature = "test-support"))]
impl Drop for MaskedPrograms {
    fn drop(&mut self) {
        if let Some(masked) = MASKED_PROGRAMS.get() {
            let mut masked = masked.write().expect("masked program set lock poisoned");
            for name in &self.0 {
                masked.remove(name);
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn program_is_masked(program: &OsStr) -> bool {
    MASKED_PROGRAMS.get().is_some_and(|masked| {
        masked
            .read()
            .expect("masked program set lock poisoned")
            .contains(program)
    })
}

/// Resolve an executable when tests mask it or explicitly override `PATH`.
/// Normal test-support builds keep the platform's native command lookup semantics.
#[cfg(any(test, feature = "test-support"))]
fn resolve_test_program(program: &OsStr) -> Option<std::path::PathBuf> {
    let program_path = std::path::Path::new(program);
    if program_path.components().count() != 1 {
        return None;
    }
    if program_is_masked(program) {
        return Some(std::path::Path::new(MASKED_PROGRAM_DIR).join(program));
    }
    let search_path = test_override(OsStr::new("PATH"))??;
    std::env::split_paths(&search_path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(any(test, feature = "test-support"))]
fn test_overrides_snapshot() -> Vec<(OsString, Option<OsString>)> {
    TEST_OVERRIDES
        .get()
        .map(|overrides| {
            overrides
                .read()
                .expect("test environment overlay lock poisoned")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Construct a blocking subprocess command using the real process environment
/// in production and the safe test overlay in test-support builds.
#[doc(hidden)]
#[inline]
pub fn command<P: AsRef<OsStr>>(program: P) -> std::process::Command {
    #[cfg(any(test, feature = "test-support"))]
    {
        let program = program.as_ref();
        let program_path = std::path::Path::new(program);
        let resolved = resolve_test_program(program);
        let mut command = std::process::Command::new(resolved.as_deref().unwrap_or(program_path));
        for (key, value) in test_overrides_snapshot() {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        command
    }

    #[cfg(not(any(test, feature = "test-support")))]
    std::process::Command::new(program)
}

/// Construct an async Tokio subprocess command with the same test overlay
/// semantics as [`command`].
#[doc(hidden)]
#[inline]
pub fn tokio_command<P: AsRef<OsStr>>(program: P) -> tokio::process::Command {
    #[cfg(any(test, feature = "test-support"))]
    {
        let program = program.as_ref();
        let program_path = std::path::Path::new(program);
        let resolved = resolve_test_program(program);
        let mut command = tokio::process::Command::new(resolved.as_deref().unwrap_or(program_path));
        for (key, value) in test_overrides_snapshot() {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        command
    }

    #[cfg(not(any(test, feature = "test-support")))]
    tokio::process::Command::new(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_override_can_set_and_mask_a_key_without_process_mutation() {
        const KEY: &str = "CORTEX_TEST_ENV_OVERLAY_SET_AND_MASK";
        set_test_var(KEY, "overlay-value");
        assert_eq!(var(KEY).as_deref(), Ok("overlay-value"));
        assert_eq!(var_os(KEY).as_deref(), Some(OsStr::new("overlay-value")));

        remove_test_var(KEY);
        assert!(matches!(var(KEY), Err(std::env::VarError::NotPresent)));
        assert!(var_os(KEY).is_none());
    }

    /// Masking must make a program that *is* on `PATH` resolve to something that
    /// cannot be spawned, and must lift cleanly — otherwise it becomes the same
    /// process-global leak that replacing `PATH` was.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn masking_hides_a_resolvable_program_and_lifts_on_drop() {
        // Restore the effective PATH: `remove_test_var` masks the key outright,
        // which would leave every later test in this binary with no PATH at all.
        struct PathGuard(Option<OsString>);
        impl Drop for PathGuard {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(previous) => set_test_var("PATH", previous),
                    None => remove_test_var("PATH"),
                }
            }
        }

        // A name nothing else in this binary spawns, so the process-global mask
        // cannot disturb a concurrently running test.
        const PROGRAM: &str = "cortex-test-mask-probe";

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join(PROGRAM);
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Prepend, never replace: a bare fixture PATH breaks unrelated spawns.
        let mut search_path = vec![dir.path().to_path_buf()];
        if let Some(existing) = var_os("PATH") {
            search_path.extend(std::env::split_paths(&existing));
        }
        let _path = PathGuard(var_os("PATH"));
        set_test_var("PATH", std::env::join_paths(search_path).unwrap());

        assert_eq!(
            resolve_test_program(OsStr::new(PROGRAM)).as_deref(),
            Some(binary.as_path()),
            "the fixture directory should resolve the program before masking"
        );

        {
            let _masked = mask_test_programs([PROGRAM]);
            let resolved = resolve_test_program(OsStr::new(PROGRAM))
                .expect("a masked program still resolves, to a path that cannot exist");
            assert!(
                !resolved.exists(),
                "masking must resolve to an absent path so the spawn fails with \
                 NotFound, exactly as an uninstalled binary does"
            );
        }

        assert_eq!(
            resolve_test_program(OsStr::new(PROGRAM)).as_deref(),
            Some(binary.as_path()),
            "dropping the guard must lift the mask"
        );
    }

    #[test]
    fn unrelated_keys_do_not_interfere() {
        const LEFT: &str = "CORTEX_TEST_ENV_OVERLAY_LEFT";
        const RIGHT: &str = "CORTEX_TEST_ENV_OVERLAY_RIGHT";
        set_test_var(LEFT, "left");
        set_test_var(RIGHT, "right");
        assert_eq!(var(LEFT).as_deref(), Ok("left"));
        assert_eq!(var(RIGHT).as_deref(), Ok("right"));
    }
}
