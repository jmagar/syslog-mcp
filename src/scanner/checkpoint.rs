use anyhow::Result;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::db::DbPool;
use std::path::Path;

use crate::scanner::{
    AiDoctorReport, AiIndexingHealth, CheckpointEntry, CheckpointListOptions, FileMetadata,
    ParseErrorEntry, ParseErrorListOptions, PruneCheckpointsOptions, PruneCheckpointsResult,
    SchemaDriftMigration, TranscriptRootStatus,
};

pub struct CheckpointStore<'a> {
    pool: &'a DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMetadata {
    pub file_size: Option<i64>,
    pub file_mtime: Option<i64>,
    pub content_hash: Option<String>,
    pub last_offset: Option<i64>,
    pub last_error: Option<String>,
    /// A scanner-owned identity for the source revision currently represented
    /// by this checkpoint. Legacy checkpoints have no revision and must not
    /// be used for revision-sensitive continuation.
    pub source_revision: Option<String>,
    /// The recovery point represented by `last_offset`.
    pub scan_state: SourceScanState,
}

/// The only scanner recovery states persisted for a transcript source.
///
/// `Boundary` means `last_offset` is a verified record boundary.  A scanner
/// may persist `DiscardUntilNewline` while it is safely skipping an oversized
/// physical record, and must resume that work before parsing more records.
/// `Restart` invalidates continuation and requires a duplicate-safe restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScanState {
    Restart,
    Boundary,
    DiscardUntilNewline,
    Complete,
}

impl SourceScanState {
    const fn as_db_value(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Boundary => "boundary",
            Self::DiscardUntilNewline => "discard_until_newline",
            Self::Complete => "complete",
        }
    }

    fn from_db_value(value: Option<String>) -> Self {
        match value.as_deref() {
            Some("restart") => Self::Restart,
            Some("boundary") => Self::Boundary,
            Some("discard_until_newline") => Self::DiscardUntilNewline,
            // A database created before migration 51 had no state. Its
            // checkpoints were necessarily completed scans, so that is the
            // safe compatibility interpretation. Unknown values restart.
            Some("complete") | None => Self::Complete,
            Some(_) => Self::Restart,
        }
    }
}

impl<'a> CheckpointStore<'a> {
    pub fn new(pool: &'a DbPool) -> Self {
        Self { pool }
    }

    pub fn ensure_source(&self, canonical_path: &str, source_kind: &str) -> Result<i64> {
        let conn = self.pool.get()?;
        if let Some(id) = conn
            .query_row(
                "SELECT id FROM transcript_sources WHERE canonical_path = ?1",
                [canonical_path],
                |row| row.get(0),
            )
            .optional()?
        {
            conn.execute(
                "UPDATE transcript_sources
                 SET source_kind = ?2
                 WHERE id = ?1 AND source_kind != ?2",
                params![id, source_kind],
            )?;
            return Ok(id);
        }
        conn.execute(
            "INSERT INTO transcript_sources (canonical_path, source_kind)
             VALUES (?1, ?2)",
            params![canonical_path, source_kind],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn mark_error(&self, source_id: i64, error: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE transcript_sources
             SET last_error = ?2
             WHERE id = ?1",
            params![source_id, error],
        )?;
        Ok(())
    }

    pub fn record_parse_error(
        &self,
        source_id: i64,
        line_no: i64,
        error: &str,
        record_preview: Option<&str>,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        let record_preview = record_preview.unwrap_or("");
        conn.execute(
            "INSERT OR IGNORE INTO transcript_parse_errors
                 (source_id, line_no, error, record_preview)
             VALUES (?1, ?2, ?3, ?4)",
            params![source_id, line_no, error, record_preview],
        )?;
        Ok(())
    }

    pub fn source_matches_metadata(
        &self,
        source_id: i64,
        file_size: u64,
        file_mtime: Option<i64>,
    ) -> Result<bool> {
        let conn = self.pool.get()?;
        let Some((stored_size, stored_mtime, last_error, scan_state)) = conn
            .query_row(
                "SELECT file_size, file_mtime, last_error, scan_state
                 FROM transcript_sources
                 WHERE id = ?1",
                [source_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(false);
        };

        Ok(last_error.is_none()
            && SourceScanState::from_db_value(scan_state) == SourceScanState::Complete
            && stored_size == Some(file_size as i64)
            && stored_mtime == file_mtime)
    }

    pub fn source_metadata(&self, source_id: i64) -> Result<Option<SourceMetadata>> {
        let conn = self.pool.get()?;
        conn.query_row(
            "SELECT file_size, file_mtime, content_hash, last_offset, last_error,
                    source_revision, scan_state
             FROM transcript_sources
             WHERE id = ?1",
            [source_id],
            |row| {
                Ok(SourceMetadata {
                    file_size: row.get(0)?,
                    file_mtime: row.get(1)?,
                    content_hash: row.get(2)?,
                    last_offset: row.get(3)?,
                    last_error: row.get(4)?,
                    source_revision: row.get(5)?,
                    scan_state: SourceScanState::from_db_value(row.get(6)?),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn reset_source(&self, source_id: i64, canonical_path: &str) -> Result<()> {
        let mut conn = crate::db::write_conn(self.pool)?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM transcript_import_records WHERE source_id = ?1",
            [source_id],
        )?;
        tx.execute(
            "DELETE FROM transcript_parse_errors WHERE source_id = ?1",
            [source_id],
        )?;
        tx.execute(
            "DELETE FROM logs WHERE ai_transcript_path = ?1",
            [canonical_path],
        )?;
        tx.execute(
            "UPDATE hosts
             SET log_count = (SELECT COUNT(*) FROM logs WHERE logs.hostname = hosts.hostname),
                 first_seen = COALESCE((SELECT MIN(received_at) FROM logs WHERE logs.hostname = hosts.hostname), first_seen),
                 last_seen = COALESCE((SELECT MAX(received_at) FROM logs WHERE logs.hostname = hosts.hostname), last_seen)
             WHERE hostname = 'localhost'",
            [],
        )?;
        tx.execute(
            "DELETE FROM hosts WHERE hostname = 'localhost' AND log_count = 0",
            [],
        )?;
        tx.execute(
            "UPDATE transcript_sources
             SET file_size = NULL,
                 file_mtime = NULL,
                 content_hash = NULL,
                 last_offset = 0,
                 source_revision = NULL,
                 scan_state = 'restart',
                 last_indexed_at = NULL,
                 last_error = NULL
             WHERE id = ?1",
            [source_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_checkpoints(
        &self,
        options: &CheckpointListOptions,
    ) -> Result<Vec<CheckpointEntry>> {
        let conn = self.pool.get()?;
        let limit = options.limit.unwrap_or(50).min(500) as usize;
        let query_limit = if options.missing_only { 5000 } else { limit };
        let mut sql = String::from(
            "SELECT s.canonical_path,
                    s.source_kind,
                    s.file_size,
                    s.file_mtime,
                    s.content_hash,
                    s.last_offset,
                    s.last_indexed_at,
                    s.last_error,
                    COUNT(DISTINCT r.id) AS imported_records,
                    COUNT(DISTINCT e.id) AS parse_errors
             FROM transcript_sources s
             LEFT JOIN transcript_import_records r ON r.source_id = s.id
             LEFT JOIN transcript_parse_errors e ON e.source_id = s.id",
        );
        if options.errors_only {
            sql.push_str(" WHERE s.last_error IS NOT NULL");
        }
        sql.push_str(
            " GROUP BY s.id
              ORDER BY
                CASE WHEN s.last_error IS NULL THEN 1 ELSE 0 END,
                COALESCE(s.last_indexed_at, '') DESC,
                s.canonical_path ASC
              LIMIT ?1 OFFSET ?2",
        );

        let mut checkpoints = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([query_limit as i64, offset as i64], |row| {
                let canonical_path: String = row.get(0)?;
                Ok(CheckpointEntry {
                    missing: !Path::new(&canonical_path).exists(),
                    canonical_path,
                    source_kind: row.get(1)?,
                    file_size: row.get(2)?,
                    file_mtime: row.get(3)?,
                    content_hash: row.get(4)?,
                    last_offset: row.get(5)?,
                    last_indexed_at: row.get(6)?,
                    last_error: row.get(7)?,
                    imported_records: row.get(8)?,
                    parse_errors: row.get(9)?,
                })
            })?;
            let batch = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            let batch_len = batch.len();
            if options.missing_only {
                checkpoints.extend(batch.into_iter().filter(|checkpoint| checkpoint.missing));
                checkpoints.truncate(limit);
            } else {
                checkpoints.extend(batch);
            }
            if !options.missing_only || checkpoints.len() >= limit || batch_len < query_limit {
                break;
            }
            offset += query_limit;
        }
        Ok(checkpoints)
    }

    pub fn list_parse_errors(
        &self,
        options: &ParseErrorListOptions,
    ) -> Result<Vec<ParseErrorEntry>> {
        let conn = self.pool.get()?;
        let limit = options.limit.unwrap_or(50).min(500);
        let mut stmt = conn.prepare(
            "SELECT s.canonical_path,
                    s.source_kind,
                    e.line_no,
                    e.error,
                    e.record_preview,
                    e.seen_at
             FROM transcript_parse_errors e
             JOIN transcript_sources s ON s.id = e.source_id
             ORDER BY e.seen_at DESC, s.canonical_path ASC, e.line_no ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok(ParseErrorEntry {
                canonical_path: row.get(0)?,
                source_kind: row.get(1)?,
                line_no: row.get(2)?,
                error: row.get(3)?,
                record_preview: row.get(4)?,
                seen_at: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn prune_checkpoints(
        &self,
        options: &PruneCheckpointsOptions,
    ) -> Result<PruneCheckpointsResult> {
        if !options.missing_only {
            anyhow::bail!("checkpoint pruning requires missing_only=true");
        }
        let checkpoints = self.list_checkpoints(&CheckpointListOptions {
            errors_only: false,
            missing_only: true,
            limit: options.limit,
        })?;
        let paths: Vec<String> = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.canonical_path.clone())
            .collect();
        if options.dry_run || checkpoints.is_empty() {
            return Ok(PruneCheckpointsResult {
                matched: checkpoints.len(),
                pruned: 0,
                dry_run: options.dry_run,
                paths,
            });
        }

        let mut conn = crate::db::write_conn(self.pool)?;
        let tx = conn.transaction()?;
        for checkpoint in &checkpoints {
            let source_id: i64 = tx.query_row(
                "SELECT id FROM transcript_sources WHERE canonical_path = ?1",
                [&checkpoint.canonical_path],
                |row| row.get(0),
            )?;
            tx.execute(
                "DELETE FROM transcript_parse_errors WHERE source_id = ?1",
                [source_id],
            )?;
            tx.execute(
                "DELETE FROM transcript_import_records WHERE source_id = ?1",
                [source_id],
            )?;
            tx.execute("DELETE FROM transcript_sources WHERE id = ?1", [source_id])?;
        }
        tx.commit()?;
        Ok(PruneCheckpointsResult {
            matched: checkpoints.len(),
            pruned: checkpoints.len(),
            dry_run: false,
            paths,
        })
    }

    pub fn doctor(&self, db_path: &Path) -> Result<AiDoctorReport> {
        let conn = self.pool.get()?;
        let schema = crate::db::read_schema_version_info_conn(&conn)?;
        let checkpoint_count =
            conn.query_row("SELECT COUNT(*) FROM transcript_sources", [], |row| {
                row.get(0)
            })?;
        let checkpoint_error_count = conn.query_row(
            "SELECT COUNT(*) FROM transcript_sources WHERE last_error IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let imported_record_count = conn.query_row(
            "SELECT COUNT(*) FROM transcript_import_records",
            [],
            |row| row.get(0),
        )?;
        let parse_error_count =
            conn.query_row("SELECT COUNT(*) FROM transcript_parse_errors", [], |row| {
                row.get(0)
            })?;
        let newest = conn
            .query_row(
                "SELECT canonical_path, last_indexed_at
                 FROM transcript_sources
                 WHERE last_indexed_at IS NOT NULL
                 ORDER BY last_indexed_at DESC
                 LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let mut stmt = conn.prepare("SELECT canonical_path FROM transcript_sources")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut missing_checkpoint_count = 0_i64;
        for row in rows {
            if !Path::new(&row?).exists() {
                missing_checkpoint_count += 1;
            }
        }
        let (claude_root, codex_root, gemini_root) = default_root_statuses();
        Ok(AiDoctorReport {
            db_path: db_path.display().to_string(),
            db_schema_version: schema.version,
            db_last_migration_at: schema.last_migration_at,
            known_schema_version: schema.known_version,
            schema_current: schema.version >= schema.known_version,
            claude_root,
            codex_root,
            gemini_root,
            checkpoint_count,
            checkpoint_error_count,
            missing_checkpoint_count,
            imported_record_count,
            parse_error_count,
            newest_indexed_path: newest.as_ref().map(|(path, _)| path.clone()),
            newest_indexed_at: newest.map(|(_, indexed_at)| indexed_at),
        })
    }

    pub fn indexing_health(&self, process_start_time: Option<&str>) -> Result<AiIndexingHealth> {
        let conn = self.pool.get()?;
        let schema = crate::db::read_schema_version_info_conn(&conn)?;
        let schema_current = schema.version >= schema.known_version;

        let schema_drift_migrations = if let Some(started_at) = process_start_time {
            let mut stmt = conn.prepare(
                "SELECT version, applied_at
                 FROM schema_migrations
                 WHERE applied_at > ?1
                 ORDER BY version ASC",
            )?;
            let rows = stmt.query_map([started_at], |row| {
                Ok(SchemaDriftMigration {
                    version: row.get(0)?,
                    applied_at: row.get(1)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let schema_drift_detected = !schema_drift_migrations.is_empty();

        let last_successful_ingest_at: Option<String> = conn.query_row(
            "SELECT MAX(last_indexed_at)
             FROM transcript_sources
             WHERE last_error IS NULL",
            [],
            |row| row.get(0),
        )?;

        let (recent_failure_count, first_failure_at, last_failure_at): (
            i64,
            Option<String>,
            Option<String>,
        ) = conn.query_row(
            "SELECT COUNT(*), MIN(seen_at), MAX(seen_at)
             FROM transcript_parse_errors
             WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 hour')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let mut stmt = conn.prepare(
            "SELECT canonical_path
             FROM transcript_sources
             WHERE last_error IS NOT NULL
             ORDER BY COALESCE(last_indexed_at, '') DESC, canonical_path ASC
             LIMIT 20",
        )?;
        let affected_paths = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let recent_schema_error_count: i64 = conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM transcript_sources
                 WHERE last_error LIKE '%no such table%'
                    OR last_error LIKE '%schema%')
              + (SELECT COUNT(*) FROM transcript_parse_errors
                 WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 hour')
                   AND (error LIKE '%no such table%' OR error LIKE '%schema%'))",
            [],
            |row| row.get(0),
        )?;

        let mut stale_indicators = Vec::new();
        if !schema_current {
            stale_indicators.push("schema_behind_binary".to_string());
        }
        if schema_drift_detected {
            stale_indicators.push("schema_drift".to_string());
        }
        if recent_failure_count > 0 {
            stale_indicators.push("recent_indexing_failures".to_string());
        }
        if recent_schema_error_count > 0 {
            stale_indicators.push("recent_schema_errors".to_string());
        }

        Ok(AiIndexingHealth {
            db_schema_version: schema.version,
            db_last_migration_at: schema.last_migration_at,
            known_schema_version: schema.known_version,
            schema_current,
            schema_drift_detected,
            schema_drift_migrations,
            last_successful_ingest_at,
            recent_failure_count,
            first_failure_at,
            last_failure_at,
            affected_paths,
            recent_schema_error_count,
            stale_indicators,
            provider_coverage: crate::scanner::providers::runtime_health_conn(&conn)?,
        })
    }
}

fn default_root_statuses() -> (
    TranscriptRootStatus,
    TranscriptRootStatus,
    TranscriptRootStatus,
) {
    let home = crate::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(""));
    let claude = home.join(".claude/projects");
    let codex = home.join(".codex/sessions");
    let gemini = home.join(".gemini/tmp");
    (
        transcript_root_status(&claude),
        transcript_root_status(&codex),
        transcript_root_status(&gemini),
    )
}

fn transcript_root_status(path: &Path) -> TranscriptRootStatus {
    let metadata = std::fs::metadata(path).ok();
    let exists = metadata.is_some();
    let readable = std::fs::read_dir(path).is_ok();
    let writable = can_write_directory(path);
    #[cfg(unix)]
    let (owner_uid, owner_gid, mode, strict_ok) = {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::geteuid() };
        let (owner_uid, owner_gid, mode) = metadata
            .as_ref()
            .map(|metadata| (metadata.uid(), metadata.gid(), metadata.mode() & 0o777))
            .map_or((None, None, None), |(uid, gid, mode)| {
                (Some(uid), Some(gid), Some(mode))
            });
        (
            owner_uid,
            owner_gid,
            mode,
            exists && readable && writable && owner_uid == Some(current_uid),
        )
    };
    #[cfg(not(unix))]
    let (owner_uid, owner_gid, mode, strict_ok) =
        (None, None, None, exists && readable && writable);

    TranscriptRootStatus {
        path: path.display().to_string(),
        exists,
        readable,
        writable,
        owner_uid,
        owner_gid,
        mode,
        strict_ok,
    }
}

fn can_write_directory(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let probe = path.join(format!(".cortex-write-check-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

pub fn claim_imports_in_tx(
    tx: &Transaction<'_>,
    source_id: i64,
    record_keys: &[String],
) -> Result<Vec<bool>> {
    let mut claimed = Vec::with_capacity(record_keys.len());
    if record_keys.is_empty() {
        return Ok(claimed);
    }
    let mut stmt = tx.prepare_cached(
        "INSERT OR IGNORE INTO transcript_import_records (source_id, record_key)
         VALUES (?1, ?2)",
    )?;
    for record_key in record_keys {
        claimed.push(stmt.execute(params![source_id, record_key])? == 1);
    }
    Ok(claimed)
}

/// Persist a checkpoint after a source has been fully scanned.  Completion is
/// the only path that clears accumulated parse errors: partial scans retain
/// their diagnostics for the next bounded pass.
pub fn update_complete_source_metadata_in_tx(
    tx: &Transaction<'_>,
    source_id: i64,
    file_metadata: &FileMetadata,
    source_revision: &str,
) -> Result<()> {
    tx.execute(
        "DELETE FROM transcript_parse_errors WHERE source_id = ?1",
        [source_id],
    )?;
    tx.execute(
        "UPDATE transcript_sources
         SET file_size = ?2,
             file_mtime = ?3,
             content_hash = ?4,
             last_offset = ?5,
             source_revision = ?6,
             scan_state = 'complete',
             last_indexed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             last_error = NULL
         WHERE id = ?1",
        params![
            source_id,
            file_metadata.size as i64,
            file_metadata.mtime,
            file_metadata.content_hash,
            file_metadata.size as i64,
            source_revision,
        ],
    )?;
    Ok(())
}

/// Persist a recoverable bounded-scan checkpoint without pretending that the
/// source is complete. `file_metadata` describes the full observed source,
/// while `last_offset` and `scan_state` describe the exact resumable point.
pub fn update_partial_source_metadata_in_tx(
    tx: &Transaction<'_>,
    source_id: i64,
    file_metadata: &FileMetadata,
    source_revision: &str,
    scan_state: SourceScanState,
    last_offset: u64,
) -> Result<()> {
    if scan_state == SourceScanState::Complete {
        anyhow::bail!("partial source metadata requires a non-complete scan state");
    }
    let last_offset = i64::try_from(last_offset).map_err(|_| {
        anyhow::anyhow!("transcript checkpoint offset exceeds SQLite integer range")
    })?;
    tx.execute(
        "UPDATE transcript_sources
         SET file_size = ?2,
             file_mtime = ?3,
             content_hash = ?4,
             last_offset = ?5,
             source_revision = ?6,
             scan_state = ?7,
             last_indexed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             last_error = NULL
         WHERE id = ?1",
        params![
            source_id,
            file_metadata.size as i64,
            file_metadata.mtime,
            file_metadata.content_hash,
            last_offset,
            source_revision,
            scan_state.as_db_value(),
        ],
    )?;
    Ok(())
}

/// Compatibility shim for callers that completed a scan before explicit scan
/// state existed. New bounded scan paths should call the complete or partial
/// API directly.
#[cfg(test)]
pub fn update_source_metadata_in_tx(
    tx: &Transaction<'_>,
    source_id: i64,
    file_metadata: &FileMetadata,
) -> Result<()> {
    update_complete_source_metadata_in_tx(tx, source_id, file_metadata, &file_metadata.content_hash)
}

#[cfg(test)]
pub fn record_imports_in_tx(
    tx: &Transaction<'_>,
    source_id: i64,
    record_keys: &[String],
    file_metadata: &FileMetadata,
) -> Result<()> {
    let claimed = claim_imports_in_tx(tx, source_id, record_keys)?;
    if claimed.iter().any(|value| *value) || record_keys.is_empty() {
        update_source_metadata_in_tx(tx, source_id, file_metadata)?;
    } else {
        tx.execute(
            "UPDATE transcript_sources
             SET last_error = NULL
             WHERE id = ?1",
            params![source_id],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
