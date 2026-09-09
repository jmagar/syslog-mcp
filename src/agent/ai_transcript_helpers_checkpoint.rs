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
    files: HashMap<String, usize>,
    fingerprints: HashMap<String, String>,
    jsonl_positions: HashMap<String, JsonlPosition>,
    discovery_cursors: HashMap<String, String>,
) -> Result<()> {
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
