//! Deterministic real-Git fixtures for Git observer tests.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const FIXTURE_NAME: &str = "Cortex Fixture";
const FIXTURE_EMAIL: &str = "fixture@example.invalid";
const ROOT_TIME: &str = "2026-01-02T03:04:05Z";
const FEATURE_TIME: &str = "2026-01-02T03:05:05Z";
const MAIN_TIME: &str = "2026-01-02T03:06:05Z";
const RESET_TIME: &str = "2026-01-02T03:07:05Z";
const REBASE_TIME: &str = "2026-01-02T03:08:05Z";

fn canonical_timestamp(value: String) -> Result<String> {
    DateTime::parse_from_rfc3339(&value)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .with_context(|| format!("fixture commit timestamp was not RFC 3339: {value}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitFixtureCommits {
    pub root: String,
    pub main: String,
    pub feature: String,
    pub reset_discarded: String,
    pub reset_head: String,
    pub rebase_original: String,
    pub rebased: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitMetadata {
    pub sha: String,
    pub parents: String,
    pub subject: String,
    pub authored_at: String,
    pub committed_at: String,
}

#[derive(Debug)]
pub(crate) struct GitFixture {
    _temp: TempDir,
    root: PathBuf,
    repository: PathBuf,
    linked_worktree: PathBuf,
    detached_worktree: PathBuf,
    home: PathBuf,
    xdg_config_home: PathBuf,
    pub commits: GitFixtureCommits,
}

pub(crate) fn git_available() -> bool {
    crate::env::command("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn configure(command: &mut Command, home: &Path, xdg_config_home: &Path) {
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg_config_home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
        .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_EDITOR", ":")
        .env("GIT_SEQUENCE_EDITOR", ":")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR");
}

fn command(
    cwd: &Path,
    home: &Path,
    xdg_config_home: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<Output> {
    let mut process = crate::env::command("git");
    process
        .current_dir(cwd)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .args(args);
    configure(&mut process, home, xdg_config_home);
    for (key, value) in extra_env {
        process.env(key, value);
    }
    process
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))
}

fn checked(
    cwd: &Path,
    home: &Path,
    xdg_config_home: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<Output> {
    let output = command(cwd, home, xdg_config_home, args, extra_env)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git {} failed with {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }
    Ok(output)
}

fn text(output: Output, operation: &str) -> Result<String> {
    let value = String::from_utf8(output.stdout)
        .with_context(|| format!("{operation} output was not UTF-8"))?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn rev_parse(repo: &Path, home: &Path, xdg: &Path, revision: &str) -> Result<String> {
    text(
        checked(repo, home, xdg, &["rev-parse", revision], &[])?,
        "git rev-parse",
    )
}

fn commit(repo: &Path, home: &Path, xdg: &Path, timestamp: &str, subject: &str) -> Result<String> {
    checked(repo, home, xdg, &["add", "."], &[])?;
    checked(
        repo,
        home,
        xdg,
        &["commit", "-m", subject],
        &[
            ("GIT_AUTHOR_DATE", timestamp),
            ("GIT_COMMITTER_DATE", timestamp),
        ],
    )?;
    rev_parse(repo, home, xdg, "HEAD")
}

impl GitFixture {
    pub(crate) fn build() -> Result<Self> {
        if !git_available() {
            bail!("git executable is unavailable");
        }
        let temp = tempfile::Builder::new()
            .prefix("cortex-git-fixture-")
            .tempdir()
            .context("create Git fixture directory")?;
        let root = temp
            .path()
            .canonicalize()
            .context("canonicalize fixture root")?;
        let home = root.join("home");
        let xdg_config_home = root.join("xdg");
        let repository = root.join("repo");
        let linked_worktree = root.join("linked");
        let detached_worktree = root.join("detached");
        fs::create_dir_all(&home).context("create fixture HOME")?;
        fs::create_dir_all(&xdg_config_home).context("create fixture XDG config home")?;

        let repo_string = repository.to_str().context("fixture repo must be UTF-8")?;
        checked(
            &root,
            &home,
            &xdg_config_home,
            &["init", "--initial-branch=main", repo_string],
            &[],
        )?;

        fs::write(repository.join("root.txt"), b"root\n").context("write root fixture file")?;
        let root_commit = commit(
            &repository,
            &home,
            &xdg_config_home,
            ROOT_TIME,
            "fixture root",
        )?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["branch", "feature"],
            &[],
        )?;

        fs::write(repository.join("main.txt"), b"main\n").context("write main fixture file")?;
        let main_commit = commit(
            &repository,
            &home,
            &xdg_config_home,
            MAIN_TIME,
            "fixture main",
        )?;

        let linked_string = linked_worktree
            .to_str()
            .context("linked worktree path must be UTF-8")?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["worktree", "add", linked_string, "feature"],
            &[],
        )?;
        fs::write(linked_worktree.join("feature.txt"), b"feature\n")
            .context("write feature fixture file")?;
        let feature_commit = commit(
            &linked_worktree,
            &home,
            &xdg_config_home,
            FEATURE_TIME,
            "fixture feature",
        )?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &[
                "worktree",
                "lock",
                "--reason",
                "fixture lock",
                linked_string,
            ],
            &[],
        )?;

        let detached_string = detached_worktree
            .to_str()
            .context("detached worktree path must be UTF-8")?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["worktree", "add", "--detach", detached_string, &root_commit],
            &[],
        )?;

        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["switch", "-c", "reset-state", &root_commit],
            &[],
        )?;
        fs::write(repository.join("discarded.txt"), b"discarded\n")
            .context("write reset fixture file")?;
        let reset_discarded = commit(
            &repository,
            &home,
            &xdg_config_home,
            RESET_TIME,
            "fixture discarded",
        )?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["reset", "--hard", &root_commit],
            &[],
        )?;
        let reset_head = rev_parse(&repository, &home, &xdg_config_home, "HEAD")?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["switch", "main"],
            &[],
        )?;

        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["switch", "-c", "rebase-state", &root_commit],
            &[],
        )?;
        fs::write(repository.join("rebase.txt"), b"rebase\n")
            .context("write rebase fixture file")?;
        let rebase_original = commit(
            &repository,
            &home,
            &xdg_config_home,
            REBASE_TIME,
            "fixture rebase original",
        )?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["rebase", "--committer-date-is-author-date", "main"],
            &[("GIT_COMMITTER_DATE", REBASE_TIME)],
        )?;
        let rebased = rev_parse(&repository, &home, &xdg_config_home, "HEAD")?;
        checked(
            &repository,
            &home,
            &xdg_config_home,
            &["switch", "main"],
            &[],
        )?;

        Ok(Self {
            _temp: temp,
            root,
            repository,
            linked_worktree,
            detached_worktree,
            home,
            xdg_config_home,
            commits: GitFixtureCommits {
                root: root_commit,
                main: main_commit,
                feature: feature_commit,
                reset_discarded,
                reset_head,
                rebase_original,
                rebased,
            },
        })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn repository(&self) -> &Path {
        &self.repository
    }
    pub(crate) fn linked_worktree(&self) -> &Path {
        &self.linked_worktree
    }
    pub(crate) fn detached_worktree(&self) -> &Path {
        &self.detached_worktree
    }
    pub(crate) fn home(&self) -> &Path {
        &self.home
    }
    pub(crate) fn xdg_config_home(&self) -> &Path {
        &self.xdg_config_home
    }

    pub(crate) fn git_bytes(&self, cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
        Ok(checked(cwd, &self.home, &self.xdg_config_home, args, &[])?.stdout)
    }

    pub(crate) fn git_text(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        text(
            checked(cwd, &self.home, &self.xdg_config_home, args, &[])?,
            "git command",
        )
    }

    pub(crate) fn branch_head(&self, branch: &str) -> Result<String> {
        self.git_text(
            &self.repository,
            &["rev-parse", &format!("refs/heads/{branch}")],
        )
    }

    pub(crate) fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let output = command(
            &self.repository,
            &self.home,
            &self.xdg_config_home,
            &["merge-base", "--is-ancestor", ancestor, descendant],
            &[],
        )?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => bail!(
                "git merge-base --is-ancestor failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }
    }

    pub(crate) fn commit_metadata(&self, sha: &str) -> Result<CommitMetadata> {
        let output = self.git_bytes(
            &self.repository,
            &["show", "-s", "--format=%H%x00%P%x00%s%x00%aI%x00%cI", sha],
        )?;
        let value = output.strip_suffix(b"\n").unwrap_or(&output);
        let fields: Vec<&[u8]> = value.split(|byte| *byte == 0).collect();
        if fields.len() != 5 {
            bail!("unexpected commit metadata field count: {}", fields.len());
        }
        let mut strings = fields.into_iter().map(|field| {
            String::from_utf8(field.to_vec()).context("commit metadata was not UTF-8")
        });
        Ok(CommitMetadata {
            sha: strings.next().expect("five fields")?,
            parents: strings.next().expect("five fields")?,
            subject: strings.next().expect("five fields")?,
            authored_at: canonical_timestamp(strings.next().expect("five fields")?)?,
            committed_at: canonical_timestamp(strings.next().expect("five fields")?)?,
        })
    }
}

#[cfg(test)]
#[path = "test_support_tests.rs"]
mod tests;
