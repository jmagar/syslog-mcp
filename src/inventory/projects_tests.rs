use super::*;

struct EnvGuard {
    name: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = crate::env::var(name).ok();
        crate::env::set_test_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => {
                crate::env::set_test_var(self.name, value);
            }
            None => {
                crate::env::remove_test_var(self.name);
            }
        }
    }
}

#[cfg(unix)]
fn executable_file(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

#[test]
fn parses_ahead_and_behind_counts() {
    let (ahead, behind) = parse_ahead_behind("## main...origin/main [ahead 2, behind 3]\n M x");
    assert_eq!(ahead, Some(2));
    assert_eq!(behind, Some(3));
}

#[test]
fn parse_ahead_behind_handles_one_sided_and_plain_branch_status() {
    assert_eq!(
        parse_ahead_behind("## main...origin/main [ahead 7]\n"),
        (Some(7), None)
    );
    assert_eq!(
        parse_ahead_behind("## main...origin/main [behind 4]\n"),
        (None, Some(4))
    );
    assert_eq!(parse_ahead_behind(" M src/lib.rs\n"), (None, None));
}

#[test]
fn discovery_does_not_walk_ignored_dirs() {
    assert!(is_ignored_dir(Path::new("node_modules")));
    assert!(is_ignored_dir(Path::new("target")));
}

#[test]
fn discovery_stops_at_repo_root_and_does_not_report_nested_git_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("nested/.git")).unwrap();

    let mut repos = Vec::new();
    discover_repos(dir.path(), 0, &mut repos);

    assert_eq!(repos, vec![repo]);
}

#[test]
fn discovery_respects_max_depth() {
    let dir = tempfile::tempdir().unwrap();
    let too_deep = dir.path().join("a/b/c/d/repo");
    std::fs::create_dir_all(too_deep.join(".git")).unwrap();

    let mut repos = Vec::new();
    discover_repos(dir.path(), 0, &mut repos);

    assert!(repos.is_empty());
}

#[tokio::test]
async fn collect_warns_when_project_roots_are_empty() {
    let out = collect(&[], std::time::Duration::from_millis(1)).await;

    assert!(out.projects.is_empty());
    assert!(
        out.warnings
            .iter()
            .any(|warning| warning.contains("PROJECT_ROOTS not set"))
    );
}

#[test]
fn discovery_is_sorted_and_skips_symlinked_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let z_repo = dir.path().join("z-repo");
    let a_repo = dir.path().join("a-repo");
    std::fs::create_dir_all(z_repo.join(".git")).unwrap();
    std::fs::create_dir_all(a_repo.join(".git")).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join(".git")).unwrap();
        symlink(&real, dir.path().join("link-repo")).unwrap();
    }

    let mut repos = Vec::new();
    discover_repos(dir.path(), 0, &mut repos);
    let names = repos
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect::<Vec<_>>();

    #[cfg(unix)]
    assert_eq!(names, vec!["a-repo", "real", "z-repo"]);
    #[cfg(not(unix))]
    assert_eq!(names, vec!["a-repo", "z-repo"]);
    assert!(!names.contains(&"link-repo"));
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn repo_summary_maps_git_porcelain_to_project_repo() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    executable_file(
        &bin_dir.join("git"),
        r#"#!/bin/sh
shift # -C
shift # repo path
case "$*" in
  "branch --show-current") printf 'main\n'; exit 0 ;;
  "rev-parse --short HEAD") printf 'abc1234\n'; exit 0 ;;
  "status --porcelain=v1 --branch") printf '## main...origin/main [ahead 2, behind 1]\n M src/lib.rs\n'; exit 0 ;;
  "worktree list --porcelain") printf 'worktree /home/me/repo\nHEAD abc1234\nworktree /home/me/repo-alt\nHEAD def5678\n'; exit 0 ;;
  *) printf 'unexpected git args: %s\n' "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);

    let summary = repo_summary(&repo, std::time::Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(summary.path, repo.display().to_string());
    assert_eq!(summary.branch.as_deref(), Some("main"));
    assert_eq!(summary.head.as_deref(), Some("abc1234"));
    assert!(summary.dirty);
    assert_eq!(summary.ahead, Some(2));
    assert_eq!(summary.behind, Some(1));
    assert_eq!(
        summary.worktrees,
        vec!["/home/me/repo".to_string(), "/home/me/repo-alt".to_string()]
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn collect_discovers_repos_and_warns_on_failed_git_status() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let good = dir.path().join("good");
    let bad = dir.path().join("bad");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(good.join(".git")).unwrap();
    std::fs::create_dir_all(bad.join(".git")).unwrap();
    executable_file(
        &bin_dir.join("git"),
        r#"#!/bin/sh
repo="$2"
shift
shift
case "$repo:$*" in
  *"/bad:status --porcelain=v1 --branch") printf 'bad status\n' >&2; exit 2 ;;
  *":branch --show-current") printf 'main\n'; exit 0 ;;
  *":rev-parse --short HEAD") printf 'abc1234\n'; exit 0 ;;
  *":status --porcelain=v1 --branch") printf '## main...origin/main\n'; exit 0 ;;
  *":worktree list --porcelain") printf 'worktree %s\n' "$repo"; exit 0 ;;
  *) printf 'unexpected git args: %s %s\n' "$repo" "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);

    let output = collect(
        &[dir.path().to_path_buf()],
        std::time::Duration::from_secs(5),
    )
    .await;

    assert_eq!(output.projects.len(), 1);
    assert_eq!(output.projects[0].path, good.display().to_string());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains(&bad.display().to_string()))
    );
}
