//! AI transcript roots the host-local sessions watcher observes.
//!
//! `cortex sessions watch` resolves its watch targets exactly once, at startup,
//! from the roots that already exist (`ai_watch::discovery::watch_targets`), and
//! it refuses to start when none exist. A root created after the service starts
//! is therefore never watched until the service restarts. The install path
//! creates every missing root up front so a provider installed later writes
//! into a directory the watcher is already observing.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{PhaseTimer, SetupPhase, SetupStatus};

/// Transcript roots the sessions watch service is expected to observe.
///
/// Keep in sync with the `BindReadOnlyPaths` list in `ai_watch_service_unit`.
pub(crate) fn sessions_watch_transcript_roots(user_home: &Path) -> [PathBuf; 5] {
    [
        user_home.join(".claude/projects"),
        user_home.join(".codex/sessions"),
        user_home.join(".gemini/tmp"),
        user_home.join(".gemini/antigravity/brain"),
        user_home.join(".gemini/antigravity-cli/brain"),
    ]
}

/// Create every missing transcript root as a private (0700) directory.
///
/// Existing roots, and anything at a root path that is not a plain missing
/// entry, are left untouched: ownership and permission problems on existing
/// roots are reported by [`transcript_root_permissions_phase`], never repaired
/// here.
pub(crate) fn ensure_transcript_roots_phase(user_home: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("ai-transcript-roots");
    let mut created = Vec::new();
    let mut failures = Vec::new();
    for root in sessions_watch_transcript_roots(user_home) {
        match std::fs::symlink_metadata(&root) {
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                failures.push(format!("{}: {error}", root.display()));
                continue;
            }
        }
        match create_private_dir_all(&root) {
            Ok(()) => created.push(root.display().to_string()),
            Err(error) => failures.push(format!("create {}: {error}", root.display())),
        }
    }
    if !failures.is_empty() {
        return timer.finish(SetupStatus::Error, failures.join("; "));
    }
    if created.is_empty() {
        timer.finish(SetupStatus::Ok, "all AI transcript roots already exist")
    } else {
        timer.finish(
            SetupStatus::Ok,
            format!(
                "created missing AI transcript roots: {}",
                created.join(", ")
            ),
        )
    }
}

fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Recursive DirBuilder applies the mode to every directory it creates
        // (including a missing `~/.gemini` parent) and never alters existing ones.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

pub(crate) fn transcript_root_permissions_phase(user_home: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("ai-transcript-root-permissions");
    let failures: Vec<String> = sessions_watch_transcript_roots(user_home)
        .iter()
        .filter_map(|root| transcript_root_permission_error(root))
        .collect();
    if failures.is_empty() {
        timer.finish(
            SetupStatus::Ok,
            "AI transcript roots are owned/readable/writable",
        )
    } else {
        timer.finish(SetupStatus::Error, failures.join("; "))
    }
}

fn transcript_root_permission_error(root: &Path) -> Option<String> {
    let metadata = match std::fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => return Some(format!("{}: {error}", root.display())),
    };
    if !metadata.is_dir() {
        return Some(format!("{} is not a directory", root.display()));
    }
    if std::fs::read_dir(root).is_err() {
        return Some(format!("{} is not readable", root.display()));
    }
    let probe = root.join(format!(".cortex-write-check-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
        }
        Err(error) => return Some(format!("{} is not writable: {error}", root.display())),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Some(format!(
                "{} owner uid {} != current uid {}",
                root.display(),
                metadata.uid(),
                current_uid
            ));
        }
    }
    None
}

#[cfg(test)]
#[path = "transcript_roots_tests.rs"]
mod tests;
