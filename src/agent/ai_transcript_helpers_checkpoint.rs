//! Durable transcript-forwarder checkpoint and parse-warning state.

use super::*;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(in crate::agent::ai_transcript) struct Checkpoint {
    /// Canonical path string -> lines already forwarded.
    pub(in crate::agent::ai_transcript) files: HashMap<String, usize>,
    /// Bounded source-prefix fingerprints. A changed prefix resets that
    /// file's local cursor; receipt IDs keep the replay safe.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) fingerprints: HashMap<String, String>,
    /// Seekable cursors for append-only JSONL sources. Older checkpoints omit
    /// this map and take the legacy line/fingerprint path once to migrate.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) jsonl_positions: HashMap<String, JsonlPosition>,
    /// Per-root discovery cursors. Discovery is intentionally bounded, so a
    /// busy provider tree cannot permanently hide its later transcript files.
    /// The cursor only moves after the scan is either durably checkpointed or
    /// has nothing to submit; a failed network delivery always retries the
    /// same discovery window.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) discovery_cursors: HashMap<String, String>,
    /// In-process record of malformed Gemini transcripts, keyed by canonical
    /// path. Deliberately not persisted: a restart should re-warn rather than
    /// inherit suppression from a previous process.
    ///
    /// Suppression is bounded in both directions. Warning on every poll cycle
    /// floods journald, but warning only once per content revision lets a file
    /// that goes malformed and then stops changing — a truncated write, a
    /// crashed session, on-disk corruption — go silent for the lifetime of the
    /// agent while its data is never forwarded. So a warning repeats when the
    /// content changes *or* when [`GEMINI_REWARN_INTERVAL`] has elapsed.
    #[serde(skip)]
    pub(in crate::agent::ai_transcript) gemini_parse_failures: HashMap<String, GeminiParseFailure>,
    /// This process's hash state for each transcript's acknowledged prefix,
    /// keyed by canonical path. See [`VerifiedPrefix`].
    ///
    /// Deliberately not persisted. A prefix this process never read is a
    /// prefix this process cannot vouch for: the agent may have been down
    /// while the file was rewritten, so every tracked file is read back from
    /// byte 0 once after start and then at least every
    /// [`DEEP_VERIFY_INTERVAL`].
    #[serde(skip)]
    pub(in crate::agent::ai_transcript) verified_prefixes: HashMap<String, VerifiedPrefix>,
    /// When absent transcripts were last swept out of the persisted maps.
    /// Also not persisted: a fresh process sweeps on its first save.
    #[serde(skip)]
    pub(in crate::agent::ai_transcript) last_pruned: Option<Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::agent::ai_transcript) struct JsonlPosition {
    pub(in crate::agent::ai_transcript) line: usize,
    pub(in crate::agent::ai_transcript) byte_offset: u64,
    pub(in crate::agent::ai_transcript) source_epoch: String,
    pub(in crate::agent::ai_transcript) prefix_guard: String,
    /// Exact SHA-256 digest of every acknowledged byte, `[0, byte_offset)`.
    /// Compared by reading the prefix back — see [`verify_jsonl_position`]
    /// for when that happens.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) prefix_digest: Option<String>,
    /// File size when this cursor was persisted. A later larger size is the
    /// normal append case; a same-size file whose modification time moved
    /// may have been rewritten in place, so it forces a read of the prefix.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) observed_len: u64,
    /// Nanoseconds since the Unix epoch for the persisted file modification.
    /// A missing legacy value makes a same-size file ambiguous, which forces
    /// a read of the prefix; the field is rewritten on the next save.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) modified_ns: Option<u64>,
}

/// How long this process may go without reading a transcript's acknowledged
/// prefix back from byte 0 and comparing it with the digest on record.
///
/// This bounds how late a rewrite of the unsampled middle of history is
/// detected. The digest itself always covers every acknowledged byte (see
/// [`VerifiedPrefix`]), so the interval is a delay, not a region that goes
/// unchecked. Re-reading each tracked transcript once an hour costs seconds
/// per hour even for a multi-GiB tree.
const DEEP_VERIFY_INTERVAL: Duration = Duration::from_secs(3600);

/// How often the persisted checkpoint is swept for transcripts that no
/// longer exist. Each sweep is roughly one `try_exists` per checkpoint key,
/// so it is cheap but not free enough to repeat on every poll.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// This process's proof of one transcript's acknowledged prefix.
///
/// `hasher` is SHA-256 state over exactly `[0, through)` and `digest` is its
/// finalized value — the `prefix_digest` persisted for the position at
/// `through`. Holding the state rather than only the digest is what lets an
/// append extend the proof by hashing just the appended bytes, so the
/// persisted digest always covers every acknowledged byte while the steady
/// state never re-reads history.
#[derive(Debug, Clone)]
pub(in crate::agent::ai_transcript) struct VerifiedPrefix {
    /// When this process last hashed the prefix from byte 0, either
    /// confirming the digest on record or establishing it after a replay.
    pub(in crate::agent::ai_transcript) deep_verified_at: Instant,
    pub(in crate::agent::ai_transcript) through: u64,
    pub(in crate::agent::ai_transcript) digest: String,
    pub(in crate::agent::ai_transcript) hasher: Sha256,
}

/// A cursor to persist, and the hash state that vouches for it.
///
/// The state is adopted only once the cursor is durably saved. Until then
/// the checkpoint still names the previous position, and the state for
/// *that* position is what the next cycle must check against.
pub(in crate::agent::ai_transcript) struct JsonlUpdate {
    pub(in crate::agent::ai_transcript) position: JsonlPosition,
    pub(in crate::agent::ai_transcript) verified: VerifiedPrefix,
}

/// The outcome of checking a persisted cursor against its transcript.
#[derive(Debug)]
pub(in crate::agent::ai_transcript) enum PrefixCheck {
    /// The cursor stands. `hasher` covers exactly `[0, position.byte_offset)`;
    /// `deep` records whether this check read the prefix back to prove it.
    Accepted { hasher: Sha256, deep: bool },
    /// The cursor no longer describes the file, for the stated reason. The
    /// caller replays the file from the start.
    Rejected(&'static str),
}

/// Where to resume a JSONL transcript.
pub(in crate::agent::ai_transcript) struct JsonlResume {
    pub(in crate::agent::ai_transcript) line: usize,
    pub(in crate::agent::ai_transcript) byte_offset: u64,
    /// SHA-256 state over exactly `[0, byte_offset)`, for the caller to extend
    /// across whatever this cycle acknowledges.
    pub(in crate::agent::ai_transcript) hasher: Sha256,
}

/// Resolve the seekable cursor for `key`, if there is one.
///
/// `Ok(None)` means this checkpoint has no seekable position for the file
/// and the caller must take the legacy line/fingerprint migration path. A
/// resume at line 0 / offset 0 means the cursor existed and was rejected:
/// replay the file from the start. `Err` means the file could not be checked
/// at all — an I/O failure, which is not evidence of a rewrite — so the
/// caller should keep the cursor and try again next cycle rather than replay.
pub(in crate::agent::ai_transcript) fn resume_jsonl_position(
    path: &Path,
    checkpoint: &mut Checkpoint,
    key: &str,
    now: Instant,
) -> Result<Option<JsonlResume>> {
    let Some(position) = checkpoint.jsonl_positions.get(key).cloned() else {
        return Ok(None);
    };
    Ok(Some(
        match verify_jsonl_position(path, &position, checkpoint, key, now)? {
            PrefixCheck::Accepted { hasher, deep } => {
                if deep {
                    tracing::debug!(
                        path = %path.display(),
                        acknowledged_bytes = position.byte_offset,
                        reason_code = "transcript_prefix_read_back",
                        "ai transcript forwarder re-verified acknowledged history"
                    );
                }
                JsonlResume {
                    line: position.line,
                    byte_offset: position.byte_offset,
                    hasher,
                }
            }
            PrefixCheck::Rejected(cause) => {
                tracing::warn!(
                    path = %path.display(),
                    cause,
                    acknowledged_bytes = position.byte_offset,
                    reason_code = "transcript_cursor_rejected",
                    "ai transcript forwarder can no longer trust its cursor; replaying the file from the start"
                );
                JsonlResume {
                    line: 0,
                    byte_offset: 0,
                    hasher: Sha256::new(),
                }
            }
        },
    ))
}

/// Decide whether `position` still describes `path`, reading the prefix back
/// only when this process cannot already vouch for it.
///
/// The bounded signals, checked every cycle at a cost independent of the
/// prefix, are the length (truncation), the source epoch (replacement), and
/// the sampled guard windows over the first and last 4 KiB of the prefix
/// (edge rewrites). Any of those rejects the cursor on the cycle it happens.
///
/// Past them, the cursor is accepted without reading history only when this
/// process holds [`VerifiedPrefix`] state for exactly this position — same
/// offset, same digest — that it read from byte 0 within the last
/// [`DEEP_VERIFY_INTERVAL`], and the file is not the same size with a moved
/// modification time (an in-place rewrite the sampled windows may straddle).
/// Otherwise the whole prefix is hashed and compared: after a restart, when a
/// re-read falls due, in that ambiguous same-size case, and whenever the
/// persisted position is not the one this process last recorded.
///
/// Because the digest covers every acknowledged byte, a rewrite confined to
/// the unsampled middle of history and combined with an append is caught by
/// the next such read: within [`DEEP_VERIFY_INTERVAL`], or at the next
/// restart. `Err` is an I/O failure while checking, not evidence either way.
pub(in crate::agent::ai_transcript) fn verify_jsonl_position(
    path: &Path,
    position: &JsonlPosition,
    checkpoint: &mut Checkpoint,
    key: &str,
    now: Instant,
) -> Result<PrefixCheck> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to stat transcript {}", path.display()))?;
    let len = metadata.len();
    if len < position.byte_offset || len < position.observed_len {
        return Ok(PrefixCheck::Rejected("truncated"));
    }
    let Some(expected) = position.prefix_digest.as_ref() else {
        return Ok(PrefixCheck::Rejected("no_prefix_digest"));
    };
    if position.observed_len == 0 {
        return Ok(PrefixCheck::Rejected("no_observed_len"));
    }
    if source_epoch(path) != position.source_epoch {
        return Ok(PrefixCheck::Rejected("replaced"));
    }
    if jsonl_prefix_guard(path, position.byte_offset)? != position.prefix_guard {
        return Ok(PrefixCheck::Rejected("edge_rewritten"));
    }
    let appended = len > position.observed_len;
    let untouched = !appended
        && position.modified_ns.is_some()
        && file_modified_ns(&metadata) == position.modified_ns;
    if (appended || untouched)
        && let Some(verified) = checkpoint.verified_prefixes.get(key)
        && verified.through == position.byte_offset
        && &verified.digest == expected
        && now.duration_since(verified.deep_verified_at) < DEEP_VERIFY_INTERVAL
    {
        return Ok(PrefixCheck::Accepted {
            hasher: verified.hasher.clone(),
            deep: false,
        });
    }
    let hasher = jsonl_prefix_hasher(path, position.byte_offset)?;
    if &finish_digest(&hasher) != expected {
        checkpoint.verified_prefixes.remove(key);
        return Ok(PrefixCheck::Rejected("prefix_rewritten"));
    }
    checkpoint.verified_prefixes.insert(
        key.to_string(),
        VerifiedPrefix {
            deep_verified_at: now,
            through: position.byte_offset,
            digest: expected.clone(),
            hasher: hasher.clone(),
        },
    );
    Ok(PrefixCheck::Accepted { hasher, deep: true })
}

/// Build the cursor to persist once this cycle has read `path` through
/// `acknowledged`, at line `line`.
///
/// `hasher` is SHA-256 state over `[0, from)`: the resumed cursor's state, or
/// fresh state with `from == 0` after a rejection or on first sight. Only
/// `[from, acknowledged)` is read, so an append-only cycle hashes what it
/// appended and nothing else, while the resulting digest still covers every
/// acknowledged byte. A read from byte 0 counts as a deep verification.
pub(in crate::agent::ai_transcript) fn acknowledge_jsonl_prefix(
    path: &Path,
    checkpoint: &Checkpoint,
    key: &str,
    (mut hasher, from): (Sha256, u64),
    acknowledged: u64,
    line: usize,
    now: Instant,
) -> Result<JsonlUpdate> {
    let prefix_guard =
        jsonl_prefix_guard(path, acknowledged).context("failed to guard acknowledged prefix")?;
    extend_prefix_hash(path, &mut hasher, from, acknowledged)
        .context("failed to hash acknowledged prefix")?;
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to stat transcript {}", path.display()))?;
    let digest = finish_digest(&hasher);
    let deep_verified_at = match checkpoint.verified_prefixes.get(key) {
        Some(verified) if from > 0 && verified.through == from => verified.deep_verified_at,
        _ => now,
    };
    Ok(JsonlUpdate {
        position: JsonlPosition {
            line,
            byte_offset: acknowledged,
            source_epoch: source_epoch(path),
            prefix_guard,
            prefix_digest: Some(digest.clone()),
            observed_len: metadata.len(),
            modified_ns: file_modified_ns(&metadata),
        },
        verified: VerifiedPrefix {
            deep_verified_at,
            through: acknowledged,
            digest,
            hasher,
        },
    })
}

/// How long a persistently malformed Gemini transcript stays quiet between
/// warnings. Long enough not to be noise, short enough that an operator
/// scanning a day of logs cannot miss it.
pub(in crate::agent::ai_transcript) const GEMINI_REWARN_INTERVAL: Duration =
    Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub(in crate::agent::ai_transcript) struct GeminiParseFailure {
    pub(in crate::agent::ai_transcript) fingerprint: u64,
    pub(in crate::agent::ai_transcript) last_warned: Instant,
}

pub(in crate::agent::ai_transcript) fn load_checkpoint(path: &Path) -> Result<Checkpoint> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode checkpoint file {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Checkpoint::default()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read checkpoint file {}", path.display()))
        }
    }
}

pub(in crate::agent::ai_transcript) fn save_checkpoint(
    path: &Path,
    checkpoint: &Checkpoint,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create checkpoint dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec(checkpoint)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).context("failed to generate checkpoint temp-file nonce")?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let tmp_path = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut file = options.open(&tmp_path).with_context(|| {
            format!(
                "failed to create checkpoint temp file {}",
                tmp_path.display()
            )
        })?;
        file.write_all(&bytes).with_context(|| {
            format!(
                "failed to write checkpoint temp file {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!("failed to sync checkpoint temp file {}", tmp_path.display())
        })?;
        drop(file);
        fs::rename(&tmp_path, path).with_context(|| {
            format!(
                "failed to atomically replace checkpoint file {}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .with_context(|| format!("failed to open checkpoint dir {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("failed to sync checkpoint dir {}", parent.display()))?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(primary_error) => match fs::remove_file(&tmp_path) {
            Ok(()) => Err(primary_error),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                Err(primary_error)
            }
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "{primary_error:#}; failed to clean checkpoint temp file {}: {cleanup_error}",
                tmp_path.display()
            )),
        },
    }
}

/// Apply cursor updates, persist them atomically, and roll them back in memory
/// when persistence fails. This preserves retry semantics without cloning the
/// potentially large historical checkpoint on every poll. The hash state that
/// vouches for each new JSONL cursor is adopted only after the save succeeds.
/// The absent-transcript sweep ([`prune_absent_entries`]) runs first and is
/// not rolled back.
pub(in crate::agent::ai_transcript) fn save_checkpoint_updates(
    path: &Path,
    checkpoint: &mut Checkpoint,
    roots: &[PathBuf],
    files: HashMap<String, usize>,
    fingerprints: HashMap<String, String>,
    jsonl_updates: HashMap<String, JsonlUpdate>,
    discovery_cursors: HashMap<String, String>,
) -> Result<()> {
    prune_absent_entries(checkpoint, roots, Instant::now());
    let mut verified = Vec::with_capacity(jsonl_updates.len());
    let jsonl_positions = jsonl_updates
        .into_iter()
        .map(|(key, update)| {
            verified.push((key.clone(), update.verified));
            (key, update.position)
        })
        .collect();
    let old_files = apply_updates(&mut checkpoint.files, files);
    let old_fingerprints = apply_updates(&mut checkpoint.fingerprints, fingerprints);
    let old_jsonl_positions = apply_updates(&mut checkpoint.jsonl_positions, jsonl_positions);
    let old_discovery = apply_updates(&mut checkpoint.discovery_cursors, discovery_cursors);
    if let Err(error) = save_checkpoint(path, checkpoint) {
        restore_updates(&mut checkpoint.files, old_files);
        restore_updates(&mut checkpoint.fingerprints, old_fingerprints);
        restore_updates(&mut checkpoint.jsonl_positions, old_jsonl_positions);
        restore_updates(&mut checkpoint.discovery_cursors, old_discovery);
        return Err(error);
    }
    checkpoint.verified_prefixes.extend(verified);
    Ok(())
}

/// Forget transcripts that no longer exist on disk.
///
/// Absence is the only admissible reason to forget a file. "The bounded
/// discovery window did not reach it this cycle" is not: discovery rotates
/// through large trees, so on any given scan most tracked files are simply
/// unvisited, and dropping those would replay them from zero forever.
///
/// A path only counts as absent when it lives under a root that currently
/// exists. An unmounted or transiently unavailable home would otherwise
/// report every one of its transcripts as gone and discard the entire cursor
/// set in a single sweep. `try_exists` errors (permissions, I/O) keep the
/// entry too — only a definite `Ok(false)` drops one.
///
/// Sweeping before the save means a failed save leaves the dropped entries
/// dropped in memory while the on-disk file still lists them. That is
/// harmless: they name files that do not exist, and the next successful save
/// removes them again.
fn prune_absent_entries(checkpoint: &mut Checkpoint, roots: &[PathBuf], now: Instant) {
    if checkpoint
        .last_pruned
        .is_some_and(|last| now.duration_since(last) < PRUNE_INTERVAL)
    {
        return;
    }
    let live: Vec<&PathBuf> = roots
        .iter()
        .filter(|root| root.try_exists().unwrap_or(false))
        .collect();
    if live.is_empty() {
        return;
    }
    checkpoint.last_pruned = Some(now);
    let mut absent: HashSet<String> = HashSet::new();
    for key in checkpoint
        .files
        .keys()
        .chain(checkpoint.fingerprints.keys())
        .chain(checkpoint.jsonl_positions.keys())
    {
        let candidate = Path::new(key);
        if live.iter().any(|root| candidate.starts_with(root))
            && matches!(candidate.try_exists(), Ok(false))
        {
            absent.insert(key.clone());
        }
    }
    if absent.is_empty() {
        return;
    }
    checkpoint.files.retain(|key, _| !absent.contains(key));
    checkpoint
        .fingerprints
        .retain(|key, _| !absent.contains(key));
    checkpoint
        .jsonl_positions
        .retain(|key, _| !absent.contains(key));
    checkpoint
        .verified_prefixes
        .retain(|key, _| !absent.contains(key));
    tracing::info!(
        pruned = absent.len(),
        tracked = checkpoint.files.len(),
        reason_code = "transcript_checkpoint_pruned",
        "ai transcript forwarder dropped checkpoint entries for deleted transcripts"
    );
}

fn apply_updates<V>(
    target: &mut HashMap<String, V>,
    updates: HashMap<String, V>,
) -> Vec<(String, Option<V>)> {
    updates
        .into_iter()
        .map(|(key, value)| {
            let previous = target.insert(key.clone(), value);
            (key, previous)
        })
        .collect()
}

fn restore_updates<V>(target: &mut HashMap<String, V>, previous: Vec<(String, Option<V>)>) {
    for (key, value) in previous {
        match value {
            Some(value) => {
                target.insert(key, value);
            }
            None => {
                target.remove(&key);
            }
        }
    }
}

pub(in crate::agent::ai_transcript) fn gemini_content_fingerprint(raw: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

/// Returns true when this parse failure should be logged: the content changed
/// since the last warning, or the re-warn interval has elapsed. `now` is a
/// parameter so tests can advance the clock without sleeping.
pub(in crate::agent::ai_transcript) fn should_warn_gemini_parse_failure(
    checkpoint: &mut Checkpoint,
    key: &str,
    raw: &str,
    now: Instant,
) -> bool {
    let fingerprint = gemini_content_fingerprint(raw);
    let warn = match checkpoint.gemini_parse_failures.get(key) {
        Some(previous) => {
            previous.fingerprint != fingerprint
                || now.duration_since(previous.last_warned) >= GEMINI_REWARN_INTERVAL
        }
        None => true,
    };
    if warn {
        checkpoint.gemini_parse_failures.insert(
            key.to_string(),
            GeminiParseFailure {
                fingerprint,
                last_warned: now,
            },
        );
    }
    warn
}

/// Drop records for transcripts that no longer exist, so a long-lived agent
/// with rotating sessions does not accumulate entries for deleted files.
pub(in crate::agent::ai_transcript) fn evict_missing_gemini_failures(
    checkpoint: &mut Checkpoint,
    present: &HashSet<String>,
) {
    checkpoint
        .gemini_parse_failures
        .retain(|key, _| present.contains(key));
}
