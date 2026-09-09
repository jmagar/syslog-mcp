use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use super::{WatchOptions, target::WatchTarget};
use crate::scanner;

const MAX_WATCH_DIRS: usize = 8192;

pub(super) fn watch_targets(options: &WatchOptions) -> Result<Vec<WatchTarget>> {
    if let Some(path) = &options.path {
        let canonical = scanner::validate_transcript_scan_path(path)?;
        if canonical.is_file() {
            let parent = canonical.parent().map(Path::to_path_buf).ok_or_else(|| {
                anyhow::anyhow!("transcript file has no parent: {}", canonical.display())
            })?;
            return Ok(vec![WatchTarget::File {
                path: canonical,
                parent,
            }]);
        }
        return Ok(vec![WatchTarget::Directory(canonical)]);
    }

    scanner::default_transcript_roots()
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| scanner::validate_transcript_scan_path(&path).map(WatchTarget::Directory))
        .collect()
}

pub(super) fn watch_directory_tree(
    watcher: &mut RecommendedWatcher,
    root: &Path,
    watched_dirs: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let dirs = collect_watch_dirs(root)?;
    for dir in dirs {
        if watched_dirs.contains(&dir) {
            continue;
        }
        if watched_dirs.len() >= MAX_WATCH_DIRS {
            anyhow::bail!(
                "AI transcript watcher directory budget exceeded ({MAX_WATCH_DIRS}); use a narrower --path or raise system inotify limits"
            );
        }
        match watcher.watch(&dir, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched_dirs.insert(dir);
            }
            Err(error) => anyhow::bail!(
                "failed to watch AI transcript directory {}: {error}",
                dir.display()
            ),
        }
    }
    Ok(())
}

pub(super) fn collect_watch_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    if root.is_file() {
        if let Some(parent) = root.parent() {
            collect_watch_dirs_inner(parent, &mut dirs, true)?;
        }
    } else {
        collect_watch_dirs_inner(root, &mut dirs, true)?;
    }
    Ok(dirs)
}

fn collect_watch_dirs_inner(path: &Path, dirs: &mut Vec<PathBuf>, is_root: bool) -> Result<()> {
    if dirs.len() >= MAX_WATCH_DIRS {
        anyhow::bail!(
            "AI transcript watcher directory budget exceeded ({MAX_WATCH_DIRS}) while scanning {}",
            path.display()
        );
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            if is_root && !is_transient_watch_error(&error) {
                anyhow::bail!(
                    "failed to inspect AI transcript watch path {}: {error}",
                    path.display()
                );
            }
            tracing::warn!(path = %path.display(), error = %error, "skipping unreadable AI transcript watch path");
            return Ok(());
        }
    };
    if metadata.file_type().is_symlink() || metadata.is_file() || !metadata.is_dir() {
        return Ok(());
    }
    if !scanner::should_descend_transcript_dir(path) {
        return Ok(());
    }

    let read_dir = match std::fs::read_dir(path) {
        Ok(read_dir) => read_dir,
        Err(error) => {
            if is_root && !is_transient_watch_error(&error) {
                anyhow::bail!(
                    "failed to read AI transcript watch directory {}: {error}",
                    path.display()
                );
            }
            tracing::warn!(path = %path.display(), error = %error, "skipping unreadable AI transcript watch directory");
            return Ok(());
        }
    };
    dirs.push(path.to_path_buf());
    let mut entries = Vec::new();
    for entry in read_dir {
        match entry {
            Ok(entry) => entries.push(entry.path()),
            Err(error) => {
                tracing::warn!(path = %path.display(), error = %error, "skipping unreadable AI transcript watch directory entry");
            }
        }
    }
    entries.sort();
    for entry in entries {
        collect_watch_dirs_inner(&entry, dirs, false)?;
    }
    Ok(())
}

fn is_transient_watch_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Other
    )
}

pub(super) fn event_path_allowed(path: &Path, targets: &[WatchTarget]) -> bool {
    let canonical = canonicalize_allow_missing(path).unwrap_or_else(|error| {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "AI transcript event path canonicalization failed; using original path"
        );
        path.to_path_buf()
    });
    canonical_path_allowed(&canonical, targets)
}

pub(super) fn event_path_allowed_missing_ok(path: &Path, targets: &[WatchTarget]) -> bool {
    let canonical = canonicalize_allow_missing(path).unwrap_or_else(|_| path.to_path_buf());
    canonical_path_allowed(&canonical, targets)
}

/// Canonicalize the longest existing ancestor, then restore a missing suffix.
/// This keeps platform aliases (notably macOS `/var` -> `/private/var`)
/// consistent even for remove events whose leaf no longer exists.
fn canonicalize_allow_missing(path: &Path) -> std::io::Result<PathBuf> {
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = ancestor.file_name() else {
                    return Err(error);
                };
                suffix.push(name.to_os_string());
                let Some(parent) = ancestor.parent() else {
                    return Err(error);
                };
                ancestor = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

fn canonical_path_allowed(canonical: &Path, targets: &[WatchTarget]) -> bool {
    targets.iter().any(|target| match target {
        WatchTarget::Directory(root) => canonical.starts_with(root),
        WatchTarget::File { path, .. } => canonical == path,
    })
}
