use super::*;

const KEY_A: [u8; KEY_LEN] = [7; KEY_LEN];
const KEY_B: [u8; KEY_LEN] = [9; KEY_LEN];

/// The pre-fix value: 16 hex chars of an unkeyed SHA-256 over the token.
fn legacy_unkeyed(token: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", Sha256::digest(token.as_bytes()))[..16].to_string()
}

/// `contracts/integration-profile.schema.json` pins `credential_generation`
/// to a string of 1..=128 chars; the published format is 16 lowercase hex.
fn assert_contract_format(value: &str) {
    assert_eq!(value.len(), GENERATION_HEX_LEN, "{value}");
    assert!((1..=128).contains(&value.len()));
    assert!(
        value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "not lowercase hex: {value}"
    );
}

fn config_with_token(dir: &Path, token: Option<&str>) -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.storage.db_path = dir.join("cortex.db");
    config.api.api_token = crate::config::Secret(token.map(str::to_string));
    config
}

#[test]
fn deterministic_for_same_token_and_key() {
    assert_eq!(
        credential_generation(&KEY_A, "secret"),
        credential_generation(&KEY_A, "secret")
    );
}

#[test]
fn changes_when_token_changes() {
    assert_ne!(
        credential_generation(&KEY_A, "secret"),
        credential_generation(&KEY_A, "secret2")
    );
}

#[test]
fn changes_when_key_changes() {
    assert_ne!(
        credential_generation(&KEY_A, "secret"),
        credential_generation(&KEY_B, "secret")
    );
}

#[test]
fn differs_from_legacy_unkeyed_sha256_prefix() {
    for token in ["secret", "hunter2", "password", &"a".repeat(64)] {
        assert_ne!(credential_generation(&KEY_A, token), legacy_unkeyed(token));
    }
}

#[test]
fn is_domain_separated_from_a_plain_hmac_of_the_token() {
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY_A).unwrap();
    mac.update(b"secret");
    let plain = hex::encode(&mac.finalize().into_bytes()[..GENERATION_HEX_LEN / 2]);
    assert_ne!(credential_generation(&KEY_A, "secret"), plain);
}

#[test]
fn matches_contracted_format() {
    for token in ["", "secret", "ünïcode-tøken", &"x".repeat(4096)] {
        assert_contract_format(&credential_generation(&KEY_A, token));
    }
}

#[test]
fn key_file_is_created_private_and_stable_across_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    let first = load_or_create_key(&path).unwrap();
    let second = load_or_create_key(&path).unwrap();
    assert_eq!(first, second);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text, format!("{}\n", hex::encode(first)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn corrupt_key_file_fails_closed_instead_of_regenerating() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    std::fs::write(&path, "not-a-hex-key\n").unwrap();
    let error = load_or_create_key(&path).unwrap_err().to_string();
    assert!(error.contains("corrupt"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "not-a-hex-key\n");
}

#[test]
fn short_key_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    std::fs::write(&path, hex::encode([1_u8; 16])).unwrap();
    assert!(load_or_create_key(&path).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_key_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere.key");
    std::fs::write(&target, format!("{}\n", hex::encode(KEY_A))).unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(load_or_create_key(&path).is_err());
}

#[cfg(unix)]
#[test]
fn lax_key_file_permissions_are_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    std::fs::write(&path, format!("{}\n", hex::encode(KEY_A))).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(load_or_create_key(&path).unwrap(), KEY_A);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn creation_publishes_atomically_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    let key = load_or_create_key(&path).unwrap();
    assert_eq!(dir_entries(dir.path()), vec![KEY_FILE_NAME.to_string()]);
    assert_eq!(load_or_create_key(&path).unwrap(), key);
}

#[test]
fn losing_the_creation_race_adopts_the_winners_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    let winner = format!("{}\n", hex::encode(KEY_A));
    std::fs::write(&path, &winner).unwrap();

    // The no-clobber publish refuses to replace the winner...
    let error = publish_private_new(&path, b"loser\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    // ...and the create path falls through to loading the winner's key.
    assert_eq!(create_key(&path).unwrap(), KEY_A);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), winner);
    assert_eq!(dir_entries(dir.path()), vec![KEY_FILE_NAME.to_string()]);
}

#[cfg(unix)]
#[test]
fn unreadable_key_file_fails_closed_without_regenerating() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root bypasses file permission checks");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    let original = format!("{}\n", hex::encode(KEY_A));
    std::fs::write(&path, &original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = format!("{:#}", load_or_create_key(&path).unwrap_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(error.contains("open credential-generation key"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert_eq!(dir_entries(dir.path()), vec![KEY_FILE_NAME.to_string()]);
}

#[test]
fn directory_at_key_path_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(KEY_FILE_NAME);
    std::fs::create_dir(&path).unwrap();
    assert!(load_or_create_key(&path).is_err());
    assert!(path.is_dir(), "the directory must be left untouched");
    assert_eq!(dir_entries(dir.path()), vec![KEY_FILE_NAME.to_string()]);
}

#[test]
fn resolve_without_token_reports_none_and_writes_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_token(dir.path(), None);
    assert_eq!(resolve(&config).unwrap(), "none");
    assert!(!dir.path().join(KEY_FILE_NAME).exists());
}

#[test]
fn resolve_is_stable_across_restarts_and_keyed_by_the_persisted_secret() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_token(dir.path(), Some("secret"));
    let first = resolve(&config).unwrap();
    assert_contract_format(&first);
    assert_eq!(resolve(&config).unwrap(), first, "must survive a restart");
    assert_ne!(first, legacy_unkeyed("secret"));

    let key_path = key_path_for_db(&config.storage.db_path);
    let key = load_or_create_key(&key_path).unwrap();
    assert_eq!(first, credential_generation(&key, "secret"));

    std::fs::remove_file(&key_path).unwrap();
    assert_ne!(
        resolve(&config).unwrap(),
        first,
        "a new server secret yields a new generation"
    );
}

#[test]
fn integration_profile_publishes_the_keyed_generation() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_token(dir.path(), Some("secret"));
    let profile = crate::api::resolved_integration_profile(&config).unwrap();
    let published = profile["auth"]["credential_generation"].as_str().unwrap();
    assert_eq!(published, resolve(&config).unwrap());
    assert_ne!(published, legacy_unkeyed("secret"));
}
