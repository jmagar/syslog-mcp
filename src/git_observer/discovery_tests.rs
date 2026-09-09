use super::{DiscoveryOptions, DiscoveryWarning, DiscoveryWarningKind, discover_repositories};
use crate::git_observer::test_support::{GitFixture, git_available};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

fn marker(repository: &Path) {
    fs::create_dir_all(repository.join(".git")).unwrap();
}

fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap()
}

fn beneath_canonical_root(root: &Path, relative: impl AsRef<Path>) -> PathBuf {
    canonical(root).join(relative)
}

fn options(max_depth: usize, max_repositories: usize) -> DiscoveryOptions {
    DiscoveryOptions {
        max_depth,
        max_repositories,
    }
}

#[test]
fn real_git_fixture_discovers_main_and_linked_worktrees_from_git_dir_and_files() {
    if !git_available() {
        eprintln!("skipping discovery fixture: git executable is unavailable");
        return;
    }
    let fixture = GitFixture::build().unwrap();
    let result = discover_repositories(&[fixture.root().to_path_buf()], options(2, 10));
    let mut expected = vec![
        canonical(fixture.repository()),
        canonical(fixture.linked_worktree()),
        canonical(fixture.detached_worktree()),
    ];
    expected.sort();
    assert_eq!(result.repositories, expected);
    assert!(result.warnings.is_empty());
    assert!(fixture.repository().join(".git").is_dir());
    assert!(fixture.linked_worktree().join(".git").is_file());
    assert!(fixture.detached_worktree().join(".git").is_file());
}

#[cfg(unix)]
#[test]
fn explicit_symlink_root_is_canonicalized_but_nested_symlink_is_skipped() {
    use std::os::unix::fs::symlink;

    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    let real_root = outer.path().join("real-root");
    let external = outer.path().join("external/repository");
    fs::create_dir_all(&root).unwrap();
    let root = canonical(&root);
    marker(&real_root.join("repository"));
    marker(&external);
    symlink(&real_root, outer.path().join("root-link")).unwrap();
    symlink(&external, root.join("nested-link")).unwrap();

    let result = discover_repositories(
        &[
            outer.path().join("root-link"),
            real_root.clone(),
            root.clone(),
        ],
        options(3, 10),
    );
    assert_eq!(
        result.repositories,
        vec![canonical(&real_root.join("repository"))]
    );
    assert_eq!(
        result.warnings,
        vec![DiscoveryWarning {
            kind: DiscoveryWarningKind::SymlinkSkipped,
            path: beneath_canonical_root(&root, "nested-link"),
        }]
    );
}

#[test]
fn ignored_directories_are_never_descended_into() {
    let dir = tempfile::tempdir().unwrap();
    let root = canonical(dir.path());
    marker(&root.join("visible"));
    marker(&root.join("outer-repo"));
    marker(&root.join("outer-repo/.git/hidden"));
    for ignored in ["target", "node_modules", "cache", ".cache"] {
        marker(&root.join(ignored).join("hidden"));
    }

    let result = discover_repositories(std::slice::from_ref(&root), options(5, 20));
    assert_eq!(
        result.repositories,
        vec![
            canonical(&root.join("outer-repo")),
            canonical(&root.join("visible")),
        ]
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn depth_limit_is_inclusive_and_reports_each_untraversed_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = canonical(dir.path());
    marker(&root.join("one/two/accepted"));
    marker(&root.join("one/two/too-deep/repository"));
    marker(&root.join("other/middle/also-too-deep/repository"));

    let result = discover_repositories(std::slice::from_ref(&root), options(3, 20));
    assert_eq!(
        result.repositories,
        vec![canonical(&root.join("one/two/accepted"))]
    );
    assert_eq!(
        result.warnings,
        vec![
            DiscoveryWarning {
                kind: DiscoveryWarningKind::DepthLimitReached { max_depth: 3 },
                path: beneath_canonical_root(&root, "one/two/too-deep"),
            },
            DiscoveryWarning {
                kind: DiscoveryWarningKind::DepthLimitReached { max_depth: 3 },
                path: beneath_canonical_root(&root, "other/middle/also-too-deep"),
            },
        ]
    );
}

#[test]
fn repository_cap_returns_deterministic_prefix_and_one_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = canonical(dir.path());
    for name in ["c-repo", "a-repo", "b-repo"] {
        marker(&root.join(name));
    }

    let result = discover_repositories(std::slice::from_ref(&root), options(2, 2));
    assert_eq!(
        result.repositories,
        vec![
            canonical(&root.join("a-repo")),
            canonical(&root.join("b-repo"))
        ]
    );
    assert_eq!(
        result.warnings,
        vec![DiscoveryWarning {
            kind: DiscoveryWarningKind::RepositoryLimitReached { limit: 2 },
            path: root,
        }]
    );
}

#[test]
fn duplicate_and_missing_roots_are_reported_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let repository = dir.path().join("repository");
    marker(&repository);
    let missing = dir.path().join("missing");

    let result = discover_repositories(
        &[
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            missing.clone(),
        ],
        options(2, 10),
    );
    assert_eq!(result.repositories, vec![canonical(&repository)]);
    assert_eq!(
        result.warnings,
        vec![DiscoveryWarning {
            kind: DiscoveryWarningKind::RootUnavailable {
                error_kind: ErrorKind::NotFound,
            },
            path: missing,
        }]
    );
}

#[cfg(unix)]
#[test]
fn permission_denied_directory_becomes_warning_without_losing_other_repositories() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = canonical(dir.path());
    marker(&root.join("visible"));
    let blocked = root.join("blocked");
    marker(&blocked.join("hidden"));
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&blocked).is_ok() {
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipping permission fixture: process can read mode-000 directories");
        return;
    }

    let result = discover_repositories(std::slice::from_ref(&root), options(4, 10));
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result.repositories, vec![canonical(&root.join("visible"))]);
    assert_eq!(
        result.warnings,
        vec![DiscoveryWarning {
            kind: DiscoveryWarningKind::ReadDirectoryFailed {
                error_kind: ErrorKind::PermissionDenied,
            },
            path: beneath_canonical_root(&root, "blocked"),
        }]
    );
}

#[cfg(unix)]
#[test]
fn symlinked_git_marker_is_not_accepted_as_repository() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = canonical(dir.path());
    let repository = root.join("repository");
    fs::create_dir_all(&repository).unwrap();
    let real_git = root.join("real-git");
    fs::create_dir_all(&real_git).unwrap();
    symlink(&real_git, repository.join(".git")).unwrap();

    let result = discover_repositories(std::slice::from_ref(&root), options(2, 10));
    assert!(result.repositories.is_empty());
    assert_eq!(
        result.warnings,
        vec![DiscoveryWarning {
            kind: DiscoveryWarningKind::SymlinkSkipped,
            path: beneath_canonical_root(&root, "repository/.git"),
        }]
    );
}
