use super::*;

const ROOTS: [&str; 5] = [
    ".claude/projects",
    ".codex/sessions",
    ".gemini/tmp",
    ".gemini/antigravity/brain",
    ".gemini/antigravity-cli/brain",
];

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn fresh_home_roots_are_created_and_pass_permission_check() {
    let home = tempfile::tempdir().unwrap();

    let ensure = ensure_transcript_roots_phase(home.path());
    let permissions = transcript_root_permissions_phase(home.path());

    assert_eq!(ensure.status, SetupStatus::Ok, "{}", ensure.detail);
    for root in ROOTS {
        assert!(home.path().join(root).is_dir(), "{root} not created");
        assert!(ensure.detail.contains(root), "{root} missing from detail");
    }
    assert_eq!(
        permissions.status,
        SetupStatus::Ok,
        "{}",
        permissions.detail
    );
    #[cfg(unix)]
    {
        assert_eq!(mode(&home.path().join(".gemini")), 0o700);
        assert_eq!(
            mode(&home.path().join(".gemini/antigravity-cli/brain")),
            0o700
        );
    }
}

#[test]
fn ensure_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        ensure_transcript_roots_phase(home.path()).status,
        SetupStatus::Ok
    );

    let second = ensure_transcript_roots_phase(home.path());

    assert_eq!(second.status, SetupStatus::Ok);
    assert_eq!(second.detail, "all AI transcript roots already exist");
}

#[cfg(unix)]
#[test]
fn subset_present_creates_only_missing_roots_and_leaves_existing_untouched() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let claude = home.path().join(".claude/projects");
    let codex = home.path().join(".codex/sessions");
    for root in [&claude, &codex] {
        std::fs::create_dir_all(root).unwrap();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(root.join("keep.jsonl"), "{}\n").unwrap();
    }

    let ensure = ensure_transcript_roots_phase(home.path());

    assert_eq!(ensure.status, SetupStatus::Ok, "{}", ensure.detail);
    assert!(!ensure.detail.contains(".claude/projects"));
    assert!(!ensure.detail.contains(".codex/sessions"));
    for root in [
        ".gemini/tmp",
        ".gemini/antigravity/brain",
        ".gemini/antigravity-cli/brain",
    ] {
        assert!(ensure.detail.contains(root), "{root} missing from detail");
        assert_eq!(mode(&home.path().join(root)), 0o700);
    }
    for root in [&claude, &codex] {
        assert_eq!(mode(root), 0o750, "existing root mode changed");
        assert!(root.join("keep.jsonl").is_file());
    }
    assert_eq!(
        transcript_root_permissions_phase(home.path()).status,
        SetupStatus::Ok
    );
}

#[test]
fn existing_non_directory_root_is_left_alone_and_still_flagged() {
    let home = tempfile::tempdir().unwrap();
    let codex_dir = home.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::write(codex_dir.join("sessions"), "not a directory").unwrap();

    let ensure = ensure_transcript_roots_phase(home.path());
    let permissions = transcript_root_permissions_phase(home.path());

    assert_eq!(ensure.status, SetupStatus::Ok, "{}", ensure.detail);
    assert!(!ensure.detail.contains(".codex/sessions"));
    assert!(codex_dir.join("sessions").is_file());
    assert_eq!(permissions.status, SetupStatus::Error);
    assert!(
        permissions
            .detail
            .contains(".codex/sessions is not a directory"),
        "{}",
        permissions.detail
    );
}

#[cfg(unix)]
#[test]
fn existing_unwritable_root_is_not_repaired_and_still_flagged() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        // Root bypasses directory permission bits, so the probe cannot fail.
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let brain = home.path().join(".gemini/antigravity/brain");
    std::fs::create_dir_all(&brain).unwrap();
    std::fs::set_permissions(&brain, std::fs::Permissions::from_mode(0o500)).unwrap();

    let ensure = ensure_transcript_roots_phase(home.path());
    let permissions = transcript_root_permissions_phase(home.path());
    let brain_mode = mode(&brain);
    std::fs::set_permissions(&brain, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(ensure.status, SetupStatus::Ok, "{}", ensure.detail);
    assert_eq!(brain_mode, 0o500, "ensure must not repair existing roots");
    assert_eq!(permissions.status, SetupStatus::Error);
    assert!(
        permissions
            .detail
            .contains(".gemini/antigravity/brain is not writable"),
        "{}",
        permissions.detail
    );
    assert!(!permissions.detail.contains(".claude/projects"));
}

#[test]
fn permission_check_without_ensure_still_reports_missing_roots() {
    let home = tempfile::tempdir().unwrap();

    let permissions = transcript_root_permissions_phase(home.path());

    assert_eq!(permissions.status, SetupStatus::Error);
    for root in ROOTS {
        assert!(permissions.detail.contains(root), "{root} missing");
    }
}

#[test]
fn a_root_that_cannot_be_created_fails_the_phase_without_blocking_the_rest() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join(".gemini"), "not a directory").unwrap();

    let ensure = ensure_transcript_roots_phase(home.path());

    assert_eq!(ensure.status, SetupStatus::Error, "{}", ensure.detail);
    for root in [
        ".gemini/tmp",
        ".gemini/antigravity/brain",
        ".gemini/antigravity-cli/brain",
    ] {
        assert!(
            ensure.detail.contains(root),
            "{root} missing from {}",
            ensure.detail
        );
    }
    assert!(home.path().join(".claude/projects").is_dir());
    assert!(home.path().join(".codex/sessions").is_dir());
    assert!(
        home.path().join(".gemini").is_file(),
        "the blocking file is left alone"
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_at_a_root_is_left_alone_and_still_flagged() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".codex")).unwrap();
    let link = home.path().join(".codex/sessions");
    let target = home.path().join("nowhere");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let ensure = ensure_transcript_roots_phase(home.path());
    let permissions = transcript_root_permissions_phase(home.path());

    assert_eq!(ensure.status, SetupStatus::Ok, "{}", ensure.detail);
    assert!(!ensure.detail.contains(".codex/sessions"));
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!target.exists(), "ensure must not create through a symlink");
    assert_eq!(permissions.status, SetupStatus::Error);
    assert!(
        permissions.detail.contains(".codex/sessions"),
        "{}",
        permissions.detail
    );
}
