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
    /// When each transcript's acknowledged prefix was last read back and
    /// hashed byte for byte, keyed by canonical path.
    ///
    /// Deliberately not persisted. A prefix this process never read is a
    /// prefix this process cannot vouch for: the agent may have been down
    /// while the file was rewritten, so every tracked file is deep verified
    /// once after start and then only at [`DEEP_VERIFY_INTERVAL`].
    #[serde(skip)]
    pub(in crate::agent::ai_transcript) prefix_verifications: HashMap<String, Instant>,
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
    /// Exact SHA-256 digest of every acknowledged byte. Growth verifies this
    /// prior prefix before seeking into the append, catching rewrite+append.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) prefix_digest: Option<String>,
    /// File size when this cursor was persisted. A later larger size is the
    /// normal append case; a same-size metadata change is a rewrite.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) observed_len: u64,
    /// Nanoseconds since the Unix epoch for the persisted file modification.
    /// Missing legacy values invalidate once and are rewritten in this form.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) modified_ns: Option<u64>,
    /// Byte offset that [`JsonlPosition::prefix_digest`] actually covers.
    ///
    /// The digest is only recomputed on a cycle that deep verified, so on an
    /// append-only cycle `byte_offset` advances while this does not. Every
    /// checkpoint written before this field existed recorded the digest at
    /// `byte_offset` itself, which is exactly what `None` means here — the
    /// migration needs no rewrite and no reset.
    #[serde(default)]
    pub(in crate::agent::ai_transcript) digest_offset: Option<u64>,
}

/// How long an acknowledged prefix may go without being read back and hashed
/// byte for byte.
///
/// This is the frequency bound on exact rewrite detection. Hashing every
/// tracked transcript once an hour is a rounding error (a 2 GiB tree is
/// seconds of SHA-256 per hour); hashing it every 15 s poll, twice, is the
/// 70-80%-of-a-core bug this replaces.
const DEEP_VERIFY_INTERVAL: Duration = Duration::from_secs(3600);

/// How often the persisted checkpoint is swept for transcripts that no
/// longer exist. Each sweep is one `stat` per tracked path, so it is cheap
/// but not free enough to repeat on every poll.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// What a cursor consultation was actually able to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::agent::ai_transcript) enum PrefixVerification {
    /// Accepted on bounded evidence only: same source epoch, matching
    /// sampled guard windows, and a monotonically grown length. The
    /// acknowledged history was NOT read, so a rewrite confined to the
    /// unsampled middle of the prefix is not detected on this cycle.
    Bounded,
    /// The acknowledged prefix was read back and matched the recorded digest
    /// byte for byte, over the range that digest covers.
    Deep,
}

/// Where to resume a JSONL transcript, and what the caller may reuse.
pub(in crate::agent::ai_transcript) struct JsonlResume {
    pub(in crate::agent::ai_transcript) line: usize,
    pub(in crate::agent::ai_transcript) byte_offset: u64,
    /// The digest to persist again unchanged, with the offset it covers.
    /// `None` means the caller must compute a fresh one — either because
    /// this cycle deep verified (so the digest can be extended to cover
    /// everything acknowledged) or because the cursor was rejected.
    pub(in crate::agent::ai_transcript) carried_digest: Option<(String, u64)>,
}

/// The offset a position's digest covers, honouring the pre-`digest_offset`
/// checkpoint format.
fn digest_offset(position: &JsonlPosition) -> u64 {
    position.digest_offset.unwrap_or(position.byte_offset)
}

/// Resolve the seekable cursor for `key`, if there is one.
///
/// `None` means this checkpoint has no seekable position for the file and
/// the caller must take the legacy line/fingerprint migration path. A
/// returned resume at line 0 / offset 0 means the cursor existed and was
/// rejected: replay the file from the start.
pub(in crate::agent::ai_transcript) fn resume_jsonl_position(
    path: &Path,
    checkpoint: &mut Checkpoint,
    key: &str,
    now: Instant,
) -> Option<JsonlResume> {
    let position = checkpoint.jsonl_positions.get(key)?.clone();
    let Some(verification) = verify_jsonl_position(path, &position, checkpoint, key, now) else {
        return Some(JsonlResume {
            line: 0,
            byte_offset: 0,
            carried_digest: None,
        });
    };
    Some(JsonlResume {
        line: position.line,
        byte_offset: position.byte_offset,
        carried_digest: match verification {
            // Nothing read the history this cycle, so recomputing the digest
            // could only reproduce the value already on record — at a cost
            // proportional to everything ever forwarded. Carry it forward.
            PrefixVerification::Bounded => position
                .prefix_digest
                .clone()
                .map(|digest| (digest, digest_offset(&position))),
            PrefixVerification::Deep => None,
        },
    })
}

/// Decide whether `position` still describes `path`, escalating from bounded
/// signals to an exact prefix hash only when that escalation can tell the
/// caller something the cheap signals cannot.
///
/// The bounded signals are the source epoch (replacement), the sampled guard
/// windows over the first and last 4 KiB of the prefix plus its length
/// (truncation and edge rewrites), and monotonic growth. A deep read happens
/// when:
///
/// * this process has never verified this file — a checkpoint inherited
///   across a restart describes bytes this process has not seen; or
/// * [`DEEP_VERIFY_INTERVAL`] has elapsed since it last did; or
/// * the cheap signals are ambiguous: the file is the same size but its
///   modification time moved, which is precisely the in-place rewrite the
///   sampled windows may straddle.
///
/// The honest consequence, stated plainly: between deep reads, a rewrite of
/// the unsampled middle of the acknowledged prefix combined with an append
/// is NOT detected. You cannot show that history was not rewritten without
/// reading history, so this trades exactness for a bounded detection delay
/// rather than pretending the cheap signals are sufficient.
pub(in crate::agent::ai_transcript) fn verify_jsonl_position(
    path: &Path,
    position: &JsonlPosition,
    checkpoint: &mut Checkpoint,
    key: &str,
    now: Instant,
) -> Option<PrefixVerification> {
    let metadata = path.metadata().ok()?;
    let len = metadata.len();
    if len < position.byte_offset
        || len < position.observed_len
        || position.observed_len == 0
        || position.prefix_digest.is_none()
    {
        return None;
    }
    if source_epoch(path) != position.source_epoch {
        return None;
    }
    if !jsonl_prefix_guard(path, position.byte_offset)
        .is_ok_and(|guard| guard == position.prefix_guard)
    {
        return None;
    }
    let appended = len > position.observed_len;
    let untouched = !appended
        && position.modified_ns.is_some()
        && file_modified_ns(&metadata) == position.modified_ns;
    let ambiguous = !appended && !untouched;
    let due = ambiguous
        || checkpoint
            .prefix_verifications
            .get(key)
            .is_none_or(|last| now.duration_since(*last) >= DEEP_VERIFY_INTERVAL);
    if !due {
        return Some(PrefixVerification::Bounded);
    }
    let expected = position.prefix_digest.as_ref()?;
    if !jsonl_prefix_digest(path, digest_offset(position)).is_ok_and(|actual| &actual == expected) {
        checkpoint.prefix_verifications.remove(key);
        return None;
    }
    checkpoint.prefix_verifications.insert(key.to_string(), now);
    Some(PrefixVerification::Deep)
}

/// Hash the acknowledged prefix through `offset` and record that this
/// process has now seen those bytes. Used when the caller has no digest to
/// carry forward — a new file, a rejected cursor, or a cycle that just deep
/// verified and can therefore extend its coverage to the new offset.
pub(in crate::agent::ai_transcript) fn refresh_prefix_digest(
    path: &Path,
    checkpoint: &mut Checkpoint,
    key: &str,
    offset: u64,
    now: Instant,
) -> Result<(String, u64)> {
    let digest = jsonl_prefix_digest(path, offset)?;
    checkpoint.prefix_verifications.insert(key.to_string(), now);
    Ok((digest, offset))
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
/// potentially large historical checkpoint on every poll.
pub(in crate::agent::ai_transcript) fn save_checkpoint_updates(
    path: &Path,
    checkpoint: &mut Checkpoint,
    roots: &[PathBuf],
    files: HashMap<String, usize>,
    fingerprints: HashMap<String, String>,
    jsonl_positions: HashMap<String, JsonlPosition>,
    discovery_cursors: HashMap<String, String>,
) -> Result<()> {
    prune_absent_entries(checkpoint, roots, Instant::now());
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
        .prefix_verifications
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
