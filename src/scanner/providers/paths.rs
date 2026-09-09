//! Safe local discovery roots for transcript-backed providers.

use std::path::{Path, PathBuf};

use super::Provider;

/// Classify a structurally valid transcript path outside the configured home.
/// This supports explicitly-mounted agent roots without broadening discovery;
/// callers must still use the scanner's supported-file predicate first.
pub fn provider_for_transcript_layout(path: &Path) -> Option<Provider> {
    let has_segment = |expected: &str| {
        path.components()
            .any(|component| component.as_os_str() == std::ffi::OsStr::new(expected))
    };

    if has_segment(".codex")
        && (has_segment("sessions") || has_segment("archived_sessions") || has_segment("worktrees"))
    {
        Some(Provider::Codex)
    } else if has_segment(".claude") && has_segment("projects") {
        Some(Provider::Claude)
    } else if has_segment(".gemini") && has_segment("tmp") {
        Some(Provider::Gemini)
    } else if has_segment(".gemini")
        && (has_segment("antigravity") || has_segment("antigravity-cli"))
        && has_segment("brain")
        && path.file_name().and_then(|name| name.to_str()) == Some("transcript.jsonl")
    {
        Some(Provider::Antigravity)
    } else {
        None
    }
}

/// Safe roots that the JSON transcript scanner may recursively inspect.
///
pub(crate) fn transcript_roots() -> Vec<PathBuf> {
    let Some(home) = crate::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };

    let mut roots = vec![
        home.join(".claude/projects"),
        home.join(".gemini/tmp"),
        home.join(".gemini/antigravity/brain"),
        home.join(".gemini/antigravity-cli/brain"),
    ];
    for codex_home in codex_homes(&home) {
        roots.extend([
            codex_home.join("sessions"),
            codex_home.join("archived_sessions"),
            codex_home.join("worktrees"),
        ]);
    }
    roots.sort();
    roots.dedup();
    roots
}

pub(crate) fn is_known_transcript_root(path: &Path) -> bool {
    let canonical = canonical_or_self(path.to_path_buf());
    transcript_roots().iter().any(|root| {
        let root = canonical_or_self(root.clone());
        canonical == root || canonical.starts_with(root)
    })
}

pub(crate) fn provider_for_path(path: &Path) -> Option<Provider> {
    // Scanner sources are canonicalized before persistence. Normalize the
    // provider roots too: macOS commonly aliases `/var` to `/private/var`,
    // and a lexical starts_with check would otherwise hide real sources from
    // the health projection.
    let home = crate::env::var_os("HOME").map(PathBuf::from)?;
    let homes = path_variants(home);
    if homes
        .iter()
        .any(|home| path.starts_with(home.join(".claude/projects")))
    {
        return Some(Provider::Claude);
    }
    if homes.iter().flat_map(|home| codex_homes(home)).any(|root| {
        path.starts_with(root.join("sessions"))
            || path.starts_with(root.join("archived_sessions"))
            || path.starts_with(root.join("worktrees"))
    }) {
        return Some(Provider::Codex);
    }
    if homes
        .iter()
        .any(|home| path.starts_with(home.join(".gemini/tmp")))
    {
        return Some(Provider::Gemini);
    }
    homes
        .iter()
        .any(|home| {
            path.starts_with(home.join(".gemini/antigravity"))
                || path.starts_with(home.join(".gemini/antigravity-cli"))
        })
        .then_some(Provider::Antigravity)
}

fn path_variants(path: PathBuf) -> Vec<PathBuf> {
    let mut variants = vec![path.clone(), canonical_or_self(path)];
    variants.sort();
    variants.dedup();
    variants
}

fn codex_homes(home: &Path) -> Vec<PathBuf> {
    let default = home.join(".codex");
    let mut homes = path_variants(default);
    if let Some(configured) = crate::env::var_os("CODEX_HOME") {
        let configured = PathBuf::from(configured);
        if configured.is_absolute() {
            homes.extend(path_variants(configured));
        }
    }
    homes.sort();
    homes.dedup();
    homes
}

fn canonical_or_self(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
}
