//! Bounded durable spool retention and source round-robin helpers.

use super::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;

pub(super) struct LoadedSpool {
    pub(super) spool: SpoolState,
    pub(super) spool_path: PathBuf,
    pub(super) error_code: Option<&'static str>,
}

pub(super) fn load_spool(path: &Path) -> LoadedSpool {
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(spool) => LoadedSpool {
                spool,
                spool_path: path.to_path_buf(),
                error_code: None,
            },
            Err(error) => recover_unreadable_spool(path, error),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LoadedSpool {
            spool: SpoolState::default(),
            spool_path: path.to_path_buf(),
            error_code: None,
        },
        Err(error) => recover_unreadable_spool(path, error),
    }
}

fn recover_unreadable_spool(path: &Path, error: impl std::fmt::Display) -> LoadedSpool {
    // Keep the recovery path stable so a restart continues delivering records
    // accepted after the primary spool became unreadable. A random path here
    // strands the previous process's durable recovery queue on every restart.
    let recovery_path = path.with_extension("recovery");
    let recovery_spool = match fs::read(&recovery_path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(spool) => spool,
            Err(recovery_error) => {
                tracing::error!(
                    recovery_spool = %recovery_path.display(),
                    error = %recovery_error,
                    "syslog recovery spool is unreadable; operator recovery is required"
                );
                return load_or_create_recovery_generation(path, error);
            }
        },
        Err(recovery_error) if recovery_error.kind() == std::io::ErrorKind::NotFound => {
            SpoolState::default()
        }
        Err(recovery_error) => {
            tracing::error!(
                recovery_spool = %recovery_path.display(),
                error = %recovery_error,
                "syslog recovery spool could not be read; operator recovery is required"
            );
            return load_or_create_recovery_generation(path, error);
        }
    };
    tracing::error!(
        spool = %path.display(),
        recovery_spool = %recovery_path.display(),
        error = %error,
        "syslog spool is unreadable; retaining original and starting a separate recovery spool"
    );
    LoadedSpool {
        spool: recovery_spool,
        spool_path: recovery_path,
        error_code: Some("spool_recovery_required"),
    }
}

fn load_or_create_recovery_generation(
    path: &Path,
    primary_error: impl std::fmt::Display,
) -> LoadedSpool {
    let mut generation_number = 2_u32;
    let mut latest_valid = None;
    let (generation, spool) = loop {
        let candidate = path.with_extension(format!("recovery-{generation_number}"));
        match fs::read(&candidate) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(spool) => latest_valid = Some((candidate, spool)),
                Err(error) => {
                    // This existing generation superseded every lower one.
                    // If it cannot be resumed, an older valid generation is
                    // stale and must not become writable again.
                    latest_valid = None;
                    tracing::error!(
                        recovery_spool = %candidate.display(),
                        error = %error,
                        "syslog recovery generation is unreadable; preserving it"
                    );
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                break latest_valid.unwrap_or_else(|| (candidate, SpoolState::default()));
            }
            Err(error) => {
                latest_valid = None;
                tracing::error!(
                    recovery_spool = %candidate.display(),
                    error = %error,
                    "syslog recovery generation could not be read; preserving it"
                );
            }
        }
        generation_number = generation_number
            .checked_add(1)
            .expect("recovery generation space exhausted");
    };
    tracing::error!(
        spool = %path.display(),
        recovery_spool = %generation.display(),
        error = %primary_error,
        "primary and current recovery spools are unreadable; starting a new recovery generation"
    );
    LoadedSpool {
        spool,
        spool_path: generation,
        error_code: Some("spool_recovery_required"),
    }
}

pub(super) fn save_spool(path: &Path, spool: &SpoolState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create syslog spool dir {}", parent.display()))?;
    }
    let temp = path.with_extension(format!("tmp-{}-{}", std::process::id(), random_u64()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut file = options
            .open(&temp)
            .with_context(|| format!("create syslog spool {}", temp.display()))?;
        file.write_all(&serde_json::to_vec(spool)?)
            .with_context(|| format!("write syslog spool {}", temp.display()))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
            .with_context(|| format!("replace syslog spool {}", path.display()))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .with_context(|| format!("open syslog spool dir {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("sync syslog spool dir {}", parent.display()))?;
        }
        Ok(())
    })();
    if let Err(primary_error) = &result
        && let Err(cleanup_error) = fs::remove_file(&temp)
        && cleanup_error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::error!(
            temp = %temp.display(),
            error = %cleanup_error,
            primary_error = format!("{primary_error:#}"),
            "failed to clean up syslog spool temporary file"
        );
    }
    result
}

pub(super) fn evict_source_to_quota(spool: &mut SpoolState, source_key: &str) {
    let cutoff = Utc::now() - chrono::Duration::seconds(MAX_SPOOL_AGE_SECS);
    let mut source_count = 0usize;
    let mut source_bytes = 0usize;
    for record in &spool.records {
        if source_key_of(&record.source_instance).is_some_and(|key| key == source_key) {
            source_count += 1;
            source_bytes = source_bytes.saturating_add(record.line.len());
        }
    }
    let mut retained = VecDeque::with_capacity(spool.records.len());
    let mut evicted = Vec::new();
    while let Some(record) = spool.records.pop_front() {
        let belongs = source_key_of(&record.source_instance).is_some_and(|key| key == source_key);
        let expired = belongs
            && chrono::DateTime::parse_from_rfc3339(&record.observed_at)
                .map(|at| at.with_timezone(&Utc) < cutoff)
                .unwrap_or(true);
        let over_quota = belongs
            && (source_count > MAX_SOURCE_SPOOL_RECORDS || source_bytes > MAX_SOURCE_SPOOL_BYTES);
        if expired || over_quota {
            source_count -= 1;
            source_bytes = source_bytes.saturating_sub(record.line.len());
            evicted.push(record);
        } else {
            retained.push_back(record);
        }
    }
    spool.records = retained;
    record_eviction_gaps(spool, evicted, "local_retention_quota");
}
pub(super) fn evict_aggregate_to_quota(spool: &mut SpoolState) {
    let mut bytes = spool
        .records
        .iter()
        .map(|record| record.line.len())
        .sum::<usize>();
    let mut evicted = Vec::new();
    while spool.records.len() > MAX_SPOOL_RECORDS || bytes > MAX_SPOOL_BYTES {
        let Some(record) = spool.records.pop_front() else {
            break;
        };
        bytes = bytes.saturating_sub(record.line.len());
        evicted.push(record);
    }
    record_eviction_gaps(spool, evicted, "aggregate_retention_quota");
}

fn record_eviction_gaps(
    spool: &mut SpoolState,
    evicted: Vec<SyslogForwardRecord>,
    reason_code: &str,
) {
    let mut windows: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
    for record in evicted {
        spool.evicted_records = spool.evicted_records.saturating_add(1);
        let source_windows = windows.entry(record.source_instance).or_default();
        match source_windows.last_mut() {
            Some((_, to)) if record.sequence == to.saturating_add(1) => *to = record.sequence,
            _ => source_windows.push((record.sequence, record.sequence)),
        }
    }
    for (source_instance, source_windows) in windows {
        for (from_sequence, to_sequence) in source_windows {
            push_gap(
                spool,
                SyslogForwardGap {
                    idempotency_key: delivery_key(
                        &source_instance,
                        spool.source_epoch,
                        to_sequence,
                        "gap",
                    ),
                    source_instance: source_instance.clone(),
                    source_epoch: spool.source_epoch,
                    from_sequence,
                    to_sequence,
                    observed_at: now(),
                    reason_code: reason_code.into(),
                },
            );
        }
    }
}

/// Compact compatible unsent intervals without changing a dispatched gap's
/// identity. At the hard queue bound, retain bounded durable degradation
/// telemetry even though the exact new interval can no longer be stored.
pub(super) fn push_gap(spool: &mut SpoolState, gap: SyslogForwardGap) {
    let dispatched = &spool.dispatched_gap_keys;
    if let Some(existing) = spool.gaps.iter_mut().find(|existing| {
        !dispatched.contains(&existing.idempotency_key)
            && existing.source_instance == gap.source_instance
            && existing.source_epoch == gap.source_epoch
            && existing.reason_code == gap.reason_code
            && gap.from_sequence <= existing.to_sequence.saturating_add(1)
            && existing.from_sequence <= gap.to_sequence.saturating_add(1)
    }) {
        existing.from_sequence = existing.from_sequence.min(gap.from_sequence);
        existing.to_sequence = existing.to_sequence.max(gap.to_sequence);
        existing.observed_at = gap.observed_at;
        existing.idempotency_key = delivery_key(
            &existing.source_instance,
            existing.source_epoch,
            existing.to_sequence,
            "gap",
        );
        return;
    }
    if spool.gaps.len() >= MAX_SPOOL_GAPS {
        spool.gap_overflow_intervals = spool.gap_overflow_intervals.saturating_add(1);
        if should_report_gap_overflow(spool.gap_overflow_intervals) {
            tracing::error!(
                reason_code = "gap_evidence_overflow",
                omitted_intervals = spool.gap_overflow_intervals,
                retained_gaps = spool.gaps.len(),
                max_gaps = MAX_SPOOL_GAPS,
                "syslog forwarding gap evidence exceeded its durable bound"
            );
        }
        return;
    }
    spool.gaps.push_back(gap);
}

pub(super) fn should_report_gap_overflow(omitted_intervals: u64) -> bool {
    omitted_intervals.is_power_of_two()
}

pub(super) fn gap_footprint_bytes(gap: &SyslogForwardGap) -> usize {
    gap.source_instance.len()
        + gap.idempotency_key.len()
        + gap.observed_at.len()
        + gap.reason_code.len()
        + std::mem::size_of::<u64>() * 4
}
pub(super) fn next_source_key(spool: &SpoolState) -> Option<String> {
    let mut sources = BTreeSet::new();
    for record in &spool.records {
        if let Some(source) = source_key_of(&record.source_instance) {
            sources.insert(source.to_string());
        }
    }
    for gap in &spool.gaps {
        if let Some(source) = source_key_of(&gap.source_instance) {
            sources.insert(source.to_string());
        }
    }
    let mut sources = sources.into_iter().collect::<Vec<_>>();
    if sources.is_empty() {
        return None;
    }
    if let Some(last) = spool.last_dispatched_source.as_ref()
        && let Some(position) = sources.iter().position(|source| source == last)
    {
        let len = sources.len();
        sources.rotate_left((position + 1) % len);
    }
    sources.into_iter().next()
}
pub(super) fn source_key_of(source_instance: &str) -> Option<&str> {
    let (_, key) = source_instance.rsplit_once(':')?;
    let digest = key.strip_prefix("source-")?;
    (digest.len() == 24 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(key)
}
