use super::{
    COMMIT_SHOW_FORMAT, CommitParseErrorKind, CommitParseOptions, commit_show_arguments,
    parse_commit_show,
};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const AUTHOR_NAME: &str = "Cortex Fixture";
const AUTHOR_EMAIL: &str = "Fixture@Example.INVALID";
const ROOT_TIME: &str = "2026-01-02T03:04:05Z";
const FEATURE_TIME: &str = "2026-01-02T03:05:05Z";
const CONTENT_TIME: &str = "2026-01-02T03:06:05Z";
const MERGE_TIME: &str = "2026-01-02T03:07:05Z";

struct CommitFixture {
    _temp: TempDir,
    repository: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    root: String,
    feature: String,
    content: String,
    merge: String,
}

fn configure(command: &mut Command, home: &Path, xdg: &Path) {
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_AUTHOR_NAME", AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", AUTHOR_EMAIL)
        .env("GIT_COMMITTER_NAME", AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", AUTHOR_EMAIL)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_EDITOR", ":")
        .env("GIT_SEQUENCE_EDITOR", ":")
        .env("LC_ALL", "C.UTF-8");
}

fn git(cwd: &Path, home: &Path, xdg: &Path, args: &[OsString], timestamp: Option<&str>) -> Vec<u8> {
    let mut command = crate::env::command("git");
    configure(&mut command, home, xdg);
    command
        .current_dir(cwd)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .args(args);
    if let Some(timestamp) = timestamp {
        command
            .env("GIT_AUTHOR_DATE", timestamp)
            .env("GIT_COMMITTER_DATE", timestamp);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn rev_parse(repository: &Path, home: &Path, xdg: &Path, value: &str) -> String {
    String::from_utf8(git(
        repository,
        home,
        xdg,
        &strings(&["rev-parse", value]),
        None,
    ))
    .unwrap()
    .trim()
    .to_string()
}

impl CommitFixture {
    fn build() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cortex-commit-fixture-")
            .tempdir()
            .unwrap();
        let root_dir = temp.path().canonicalize().unwrap();
        let home = root_dir.join("home");
        let xdg = root_dir.join("xdg");
        let repository = root_dir.join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&xdg).unwrap();
        let repo_arg = repository.to_str().unwrap();
        git(
            &root_dir,
            &home,
            &xdg,
            &strings(&["init", "--initial-branch=main", repo_arg]),
            None,
        );

        fs::write(
            repository.join("rename-me.txt"),
            b"rename me
",
        )
        .unwrap();
        git(&repository, &home, &xdg, &strings(&["add", "-A"]), None);
        git(
            &repository,
            &home,
            &xdg,
            &strings(&["commit", "-m", "root subject"]),
            Some(ROOT_TIME),
        );
        let root = rev_parse(&repository, &home, &xdg, "HEAD");

        git(
            &repository,
            &home,
            &xdg,
            &strings(&["switch", "-c", "feature"]),
            None,
        );
        fs::write(
            repository.join("feature.txt"),
            b"feature
",
        )
        .unwrap();
        git(&repository, &home, &xdg, &strings(&["add", "-A"]), None);
        git(
            &repository,
            &home,
            &xdg,
            &strings(&["commit", "-m", "feature subject"]),
            Some(FEATURE_TIME),
        );
        let feature = rev_parse(&repository, &home, &xdg, "HEAD");

        git(
            &repository,
            &home,
            &xdg,
            &strings(&["switch", "main"]),
            None,
        );
        fs::rename(
            repository.join("rename-me.txt"),
            repository.join("renamed.txt"),
        )
        .unwrap();
        fs::write(repository.join("blob.bin"), [0, 1, 2, 3, 4]).unwrap();
        git(&repository, &home, &xdg, &strings(&["add", "-A"]), None);
        git(
            &repository,
            &home,
            &xdg,
            &strings(&["commit", "-m", "content subject"]),
            Some(CONTENT_TIME),
        );
        let content = rev_parse(&repository, &home, &xdg, "HEAD");

        git(
            &repository,
            &home,
            &xdg,
            &strings(&["merge", "--no-ff", "feature", "-m", "merge subject"]),
            Some(MERGE_TIME),
        );
        let merge = rev_parse(&repository, &home, &xdg, "HEAD");

        Self {
            _temp: temp,
            repository,
            home,
            xdg,
            root,
            feature,
            content,
            merge,
        }
    }

    fn show(&self, shas: &[&str], max_commits: usize) -> Vec<u8> {
        let shas = shas
            .iter()
            .map(|sha| (*sha).to_string())
            .collect::<Vec<_>>();
        let args = commit_show_arguments(&shas, max_commits).unwrap();
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        git(&self.repository, &self.home, &self.xdg, &args, None)
    }
}

fn options() -> CommitParseOptions {
    CommitParseOptions {
        max_input_bytes: 1024 * 1024,
        max_commits: 16,
        max_paths_per_commit: 32,
        store_changed_paths: true,
        store_author_name: true,
        store_author_email_hash: true,
    }
}

#[test]
fn real_git_batch_parses_merge_binary_and_rename_exactly() {
    let fixture = CommitFixture::build();
    let raw = fixture.show(&[&fixture.root, &fixture.content, &fixture.merge], 16);
    let commits = parse_commit_show(&raw, options()).unwrap();
    assert_eq!(
        commits
            .iter()
            .map(|commit| commit.sha.as_str())
            .collect::<Vec<_>>(),
        vec![
            fixture.root.as_str(),
            fixture.content.as_str(),
            fixture.merge.as_str(),
        ]
    );

    let root = &commits[0];
    assert!(root.parent_shas.is_empty());
    assert_eq!(root.subject, "root subject");
    assert_eq!(root.authored_at, ROOT_TIME);
    assert_eq!(root.committed_at, ROOT_TIME);
    assert_eq!(root.changed_files, 1);
    assert_eq!(root.insertions, 1);
    assert_eq!(root.deletions, 0);

    let content = &commits[1];
    assert_eq!(content.parent_shas, vec![fixture.root.clone()]);
    assert_eq!(content.subject, "content subject");
    assert_eq!(content.authored_at, CONTENT_TIME);
    assert_eq!(content.binary_files, 1);
    assert_eq!(content.changed_files, 2);
    let rename = content
        .changed_paths
        .iter()
        .find(|change| change.path == b"renamed.txt")
        .unwrap();
    assert_eq!(
        rename.previous_path.as_deref(),
        Some(b"rename-me.txt".as_slice())
    );
    assert_eq!(rename.insertions, Some(0));
    assert_eq!(rename.deletions, Some(0));
    let binary = content
        .changed_paths
        .iter()
        .find(|change| change.path == b"blob.bin")
        .unwrap();
    assert!(binary.binary);
    assert_eq!(binary.insertions, None);
    assert_eq!(binary.deletions, None);
    let merge = &commits[2];
    assert_eq!(
        merge.parent_shas,
        vec![fixture.content.clone(), fixture.feature.clone()]
    );
    assert_eq!(merge.subject, "merge subject");
    assert_eq!(merge.authored_at, MERGE_TIME);
    assert_eq!(merge.changed_files, 1);
    assert_eq!(merge.changed_paths[0].path, b"feature.txt");

    let expected_hash = format!("{:x}", Sha256::digest(b"fixture@example.invalid"));
    assert!(commits.iter().all(|commit| {
        commit.author_name.as_deref() == Some(AUTHOR_NAME)
            && commit.author_email_hash.as_deref() == Some(expected_hash.as_str())
    }));
    assert!(!format!("{commits:?}").contains(AUTHOR_EMAIL));
}

#[test]
fn non_utf8_path_bytes_are_preserved_without_filesystem_round_trip() {
    let mut raw = Vec::new();
    for field in [
        b"CORTEX_COMMIT_V1".as_slice(),
        b"0123456789012345678901234567890123456789",
        b"",
        b"Cortex Fixture",
        b"fixture@example.invalid",
        b"2026-01-02T03:04:05Z",
        b"2026-01-02T03:04:05Z",
        b"byte path subject",
        b"",
    ] {
        raw.extend_from_slice(field);
        raw.push(0);
    }
    let path = b"non-utf8-"
        .iter()
        .copied()
        .chain([255])
        .chain(b".txt".iter().copied())
        .collect::<Vec<_>>();
    let mut numstat = b"\n1\t2\t".to_vec();
    numstat.extend_from_slice(&path);
    raw.extend_from_slice(&numstat);
    raw.push(0);

    let commits = parse_commit_show(&raw, options()).unwrap();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].changed_files, 1);
    assert_eq!(commits[0].insertions, 1);
    assert_eq!(commits[0].deletions, 2);
    assert_eq!(commits[0].changed_paths[0].path, path);
}

#[test]
fn privacy_options_drop_names_email_hashes_and_paths_but_keep_counts() {
    let fixture = CommitFixture::build();
    let raw = fixture.show(&[&fixture.content], 4);
    let commits = parse_commit_show(
        &raw,
        CommitParseOptions {
            store_changed_paths: false,
            store_author_name: false,
            store_author_email_hash: false,
            ..options()
        },
    )
    .unwrap();
    let commit = &commits[0];
    assert_eq!(commit.author_name, None);
    assert_eq!(commit.author_email_hash, None);
    assert!(commit.changed_paths.is_empty());
    assert!(!commit.paths_truncated);
    assert_eq!(commit.changed_files, 2);
    assert_eq!(commit.binary_files, 1);
}

#[test]
fn path_storage_cap_truncates_paths_without_losing_aggregate_counts() {
    let fixture = CommitFixture::build();
    let raw = fixture.show(&[&fixture.content], 4);
    let commits = parse_commit_show(
        &raw,
        CommitParseOptions {
            max_paths_per_commit: 1,
            ..options()
        },
    )
    .unwrap();
    let commit = &commits[0];
    assert_eq!(commit.changed_paths.len(), 1);
    assert!(commit.paths_truncated);
    assert_eq!(commit.changed_files, 2);
    assert_eq!(commit.binary_files, 1);
}

#[test]
fn parser_and_command_builder_enforce_bounds_and_machine_only_options() {
    let fixture = CommitFixture::build();
    let raw = fixture.show(&[&fixture.root, &fixture.content], 4);
    let error = parse_commit_show(
        &raw,
        CommitParseOptions {
            max_commits: 1,
            ..options()
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, CommitParseErrorKind::TooManyCommits { max: 1 });

    let error = parse_commit_show(
        &raw,
        CommitParseOptions {
            max_input_bytes: raw.len() - 1,
            ..options()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error.kind,
        CommitParseErrorKind::InputTooLong { .. }
    ));

    let args = commit_show_arguments(&[fixture.root.clone(), fixture.content.clone()], 2).unwrap();
    assert_eq!(args[0], "show");
    assert!(args.contains(&"--no-walk=unsorted".to_string()));
    assert!(args.contains(&"--diff-merges=first-parent".to_string()));
    assert!(args.contains(&"--find-renames".to_string()));
    assert!(args.contains(&"--numstat".to_string()));
    assert!(args.contains(&"-z".to_string()));
    assert!(args.contains(&format!("--format={COMMIT_SHOW_FORMAT}")));
    assert!(!args.iter().any(|arg| arg == "-p" || arg == "--patch"));

    let error = commit_show_arguments(&["not-an-object-id".to_string()], 2).unwrap_err();
    assert_eq!(error.kind, CommitParseErrorKind::InvalidRequestedObjectId);
    let error =
        commit_show_arguments(&[fixture.root.clone(), fixture.content.clone()], 1).unwrap_err();
    assert_eq!(error.kind, CommitParseErrorKind::TooManyCommits { max: 1 });
}

#[test]
fn malformed_errors_are_bounded_and_never_echo_path_bytes() {
    let fixture = CommitFixture::build();
    let mut raw = fixture.show(&[&fixture.root], 2);
    raw.pop();
    let error = parse_commit_show(&raw, options()).unwrap_err();
    assert_eq!(error.kind, CommitParseErrorKind::MissingTerminator);

    let mut malformed = Vec::new();
    for field in [
        b"CORTEX_COMMIT_V1".as_slice(),
        b"0123456789012345678901234567890123456789",
        b"",
        b"Fixture",
        b"fixture@example.invalid",
        b"2026-01-02T03:04:05Z",
        b"2026-01-02T03:04:05Z",
        b"subject",
        b"",
        b"
nope	0	super-secret-path",
    ] {
        malformed.extend_from_slice(field);
        malformed.push(0);
    }
    let error = parse_commit_show(&malformed, options()).unwrap_err();
    assert_eq!(error.kind, CommitParseErrorKind::InvalidNumstat);
    assert!(!error.to_string().contains("super-secret-path"));
    assert!(error.to_string().len() < 160);
}
