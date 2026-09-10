//! Keyed credential-rotation fingerprint for the integration profile.
//!
//! `auth.credential_generation` must change whenever `CORTEX_API_TOKEN`
//! changes (so integrations know to re-trust) while revealing nothing about
//! the token. An unkeyed digest of the token is offline-brute-forceable for a
//! low-entropy operator-chosen token, so the value is an HMAC-SHA256 over a
//! fixed purpose label and the token, keyed by a server-held secret.
//!
//! The key is dedicated to this purpose and persisted in the data directory
//! (`<DATA_DIR>/integration-credential.key`). It is deliberately not the
//! stream cursor key: that key is random per process on loopback when unset
//! and is rotated via `CORTEX_CURSOR_PREVIOUS_KEYS`, either of which would
//! change the fingerprint without a token change and force every integration
//! to re-trust. A missing key file is generated once; an unreadable or corrupt
//! one fails startup rather than silently regenerating (or falling back to an
//! unkeyed digest).

use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// File name of the persisted key, relative to the data directory.
pub(crate) const KEY_FILE_NAME: &str = "integration-credential.key";
/// Domain-separation label: the key is only ever used under this purpose.
const PURPOSE: &[u8] = b"cortex.integration-profile.credential_generation.v1";
const KEY_LEN: usize = 32;
/// Published length (lowercase hex). Unchanged from the previous format; the
/// contract (`contracts/integration-profile.schema.json`) allows 1..=128 chars.
pub(crate) const GENERATION_HEX_LEN: usize = 16;
const MAX_KEY_FILE_BYTES: u64 = 256;

/// Resolve `auth.credential_generation` for the configured API token.
///
/// Returns `"none"` without touching the filesystem when no token is set.
pub(crate) fn resolve(config: &crate::config::Config) -> Result<String> {
    let Some(token) = config.api.api_token.as_deref() else {
        return Ok("none".to_string());
    };
    let key = load_or_create_key(&key_path_for_db(&config.storage.db_path))?;
    Ok(credential_generation(&key, token))
}

pub(crate) fn key_path_for_db(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(KEY_FILE_NAME)
}

/// HMAC-SHA256(key, PURPOSE || 0x00 || token), truncated to
/// [`GENERATION_HEX_LEN`] lowercase hex characters.
pub(crate) fn credential_generation(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(PURPOSE);
    mac.update(&[0]);
    mac.update(token.as_bytes());
    let digest = mac.finalize().into_bytes();
    hex::encode(&digest[..GENERATION_HEX_LEN / 2])
}

pub(crate) fn load_or_create_key(path: &Path) -> Result<[u8; KEY_LEN]> {
    match read_key(path)? {
        Some(key) => Ok(key),
        None => create_key(path),
    }
}

/// Generate and publish a fresh key without ever clobbering an existing one.
/// If another process published first, its key is authoritative.
fn create_key(path: &Path) -> Result<[u8; KEY_LEN]> {
    let mut key = [0_u8; KEY_LEN];
    getrandom::fill(&mut key)
        .map_err(|error| anyhow!("generate credential-generation key: {error}"))?;
    match publish_private_new(path, format!("{}\n", hex::encode(key)).as_bytes()) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "generated integration credential-generation key");
            Ok(key)
        }
        // Lost a creation race: the winner's key is authoritative.
        Err(error) if error.kind() == ErrorKind::AlreadyExists => read_key(path)?
            .ok_or_else(|| anyhow!("credential-generation key `{}` vanished", path.display())),
        Err(error) => Err(error)
            .with_context(|| format!("create credential-generation key `{}`", path.display())),
    }
}

fn read_key(path: &Path) -> Result<Option<[u8; KEY_LEN]>> {
    let file = match open_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("open credential-generation key `{}`", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("stat credential-generation key `{}`", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_FILE_BYTES {
        bail!(
            "credential-generation key `{}` is not a small regular file",
            path.display()
        );
    }
    restrict_permissions(path, &file, &metadata)?;
    let mut text = String::new();
    file.take(MAX_KEY_FILE_BYTES)
        .read_to_string(&mut text)
        .with_context(|| format!("read credential-generation key `{}`", path.display()))?;
    let key = hex::decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; KEY_LEN]>::try_from(bytes).ok())
        .ok_or_else(|| {
            anyhow!(
                "credential-generation key `{}` is corrupt; delete it to generate a new one \
                 (integrations will see a new auth.credential_generation and must re-trust)",
                path.display()
            )
        })?;
    Ok(Some(key))
}

fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Atomically publish `contents` at `path`, failing with `AlreadyExists`
/// instead of overwriting.
///
/// The contents are written and synced to a private temp file in the same
/// directory, then hard-linked into place: `link(2)` never replaces an
/// existing entry, so a concurrent winner is never clobbered, and a racing
/// reader sees either no file or the complete key, never a partial one. The
/// temp name is removed on every path.
fn publish_private_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = temp_path_for(path)?;
    write_private_new(&tmp, contents)?;
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => sync_dir(dir),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(error),
        // Filesystems without hard links (EPERM/ENOTSUP): fall back to a direct
        // exclusive create. Still no-clobber, just not atomic for readers; a
        // reader that races a partial write fails closed as "corrupt".
        Err(error) => {
            tracing::debug!(%error, "hard link unavailable; creating credential key in place");
            write_private_new(path, contents)?;
            sync_dir(dir)
        }
    }
}

fn temp_path_for(path: &Path) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
    let name = format!(
        ".{KEY_FILE_NAME}.{}.{}.tmp",
        std::process::id(),
        hex::encode(nonce)
    );
    Ok(path.with_file_name(name))
}

/// Exclusive `0600` create (never following a symlink) plus write and fsync.
fn write_private_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    if written.is_err() {
        // Do not leave a partial key behind: the next start would fail closed on it.
        let _ = std::fs::remove_file(path);
    }
    written
}

/// Persist the new directory entry so a crash cannot lose a published key.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(
    path: &Path,
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 `{}`", path.display()))?;
        tracing::warn!(
            path = %path.display(),
            previous_mode = format!("{mode:o}"),
            "Tightened credential-generation key permissions to 0600"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_: &Path, _: &std::fs::File, _: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "credential_generation_tests.rs"]
mod tests;
