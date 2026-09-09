//! Database operations for the error signature detection subsystem.
//!
//! All functions take a `&r2d2::Pool<SqliteConnectionManager>` (i.e. `&DbPool`)
//! and are intended to be called from inside `tokio::task::spawn_blocking`.
//! They use rusqlite transactions, NOT sqlx.

use anyhow::Result;
use rusqlite::params;

use super::pool::DbPool;

// ---------------------------------------------------------------------------
// Cursor

/// Return the last scanned log ID from `error_scan_cursor`.
pub(crate) fn cursor_get(pool: &DbPool) -> Result<i64> {
    let conn = pool.get()?;
    let id: i64 = conn.query_row(
        "SELECT last_scanned_log_id FROM error_scan_cursor WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(id)
}

/// Advance the cursor to `new_last_id` and record the scan completion time.
pub(crate) fn cursor_advance(conn: &rusqlite::Connection, new_last_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE error_scan_cursor
         SET last_scanned_log_id = ?1,
             last_scan_completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = 1",
        params![new_last_id],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Upsert signature

/// Parameters for `upsert_signature`.
pub(crate) struct UpsertSignatureParams<'a> {
    pub hash: &'a str,
    pub normalizer_version: i64,
    pub template: &'a str,
    pub sample_message: &'a str,
    pub sample_hostname: &'a str,
    pub sample_app_name: Option<&'a str>,
    pub severity: &'a str,
    pub first_seen_at: &'a str,
    pub last_seen_at: &'a str,
    pub delta: i64,
}

/// Upsert a signature into `error_signatures`.
///
/// On INSERT (first time we see this hash+version): write all sample fields.
/// On UPDATE (already exists): advance `last_seen_at` and add `delta` to
/// `total_count`. Sample fields are NEVER overwritten.
pub(crate) fn upsert_signature(
    conn: &rusqlite::Connection,
    p: UpsertSignatureParams<'_>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO error_signatures
             (signature_hash, normalizer_version, template, sample_message,
              sample_hostname, sample_app_name, severity,
              first_seen_at, last_seen_at, total_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(signature_hash, normalizer_version) DO UPDATE SET
             last_seen_at  = CASE WHEN excluded.last_seen_at > last_seen_at
                                  THEN excluded.last_seen_at ELSE last_seen_at END,
             total_count   = total_count + excluded.total_count",
        params![
            p.hash,
            p.normalizer_version,
            p.template,
            p.sample_message,
            p.sample_hostname,
            p.sample_app_name,
            p.severity,
            p.first_seen_at,
            p.last_seen_at,
            p.delta,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Window

/// Insert a window record.  Overlapping windows for the same (hash, ver,
/// start, end) are merged via `ON CONFLICT … DO UPDATE`.
pub(crate) fn insert_window(
    conn: &rusqlite::Connection,
    signature_hash: &str,
    normalizer_version: i64,
    window_start: &str,
    window_end: &str,
    count: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO error_signature_windows
             (signature_hash, normalizer_version, window_start, window_end, count_in_window)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(signature_hash, normalizer_version, window_start, window_end)
         DO UPDATE SET count_in_window = count_in_window + excluded.count_in_window",
        params![
            signature_hash,
            normalizer_version,
            window_start,
            window_end,
            count
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ack / unack

/// Record an ack or unack audit event.
pub(crate) fn record_ack_event(
    conn: &rusqlite::Connection,
    signature_hash: &str,
    normalizer_version: i64,
    event_type: &str, // "ack" | "unack"
    actor: &str,
    notes: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO error_signature_ack_events
             (signature_hash, normalizer_version, event_type, actor, notes)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![signature_hash, normalizer_version, event_type, actor, notes],
    )?;
    Ok(())
}

/// Update the ack projection column on `error_signatures`.
/// Call this after `record_ack_event` inside the same transaction.
pub(crate) fn update_ack_projection(
    conn: &rusqlite::Connection,
    signature_hash: &str,
    normalizer_version: i64,
    acknowledged_at: Option<&str>, // Some → ack, None → clear (unack)
    acknowledged_by: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE error_signatures
         SET acknowledged_at = ?3, acknowledged_by = ?4
         WHERE signature_hash = ?1 AND normalizer_version = ?2",
        params![
            signature_hash,
            normalizer_version,
            acknowledged_at,
            acknowledged_by,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Read queries

/// A row from `error_signatures` joined with a recent-window count.
#[derive(Debug)]
pub(crate) struct SignatureRow {
    pub signature_hash: String,
    pub template: String,
    pub sample_message: String,
    pub sample_hostname: String,
    pub sample_app_name: Option<String>,
    pub severity: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub total_count: i64,
    pub count_last_1h: i64,
    pub acknowledged_at: Option<String>,
}

/// Hard ceiling for a recurring-error comparison.  This is deliberately a
/// source-row cap rather than a response cap: a high-cardinality signature
/// table must not turn an operator comparison into an unbounded aggregation.
pub(crate) const RECURRING_ERROR_CANDIDATE_CAP: usize = 512;
/// Evidence links are provenance hints, not an evidence dump.  Keep a small
/// deterministic page so a caller can explicitly follow up with `graph`.
pub(crate) const RECURRING_ERROR_EVIDENCE_CAP: usize = 4;

/// Canonical, non-display inputs for one recurring-error comparison row.
///
/// Textual samples deliberately stay in this internal row only.  The service
/// boundary scrubs and bounds them before any cache or serialization path.
#[derive(Debug, Clone)]
pub(crate) struct RecurringErrorComparisonRow {
    pub signature_hash: String,
    pub normalizer_version: i64,
    pub template: String,
    pub sample_message: String,
    pub sample_hostname: String,
    pub sample_app_name: Option<String>,
    pub severity: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub total_count: i64,
    pub current_count: i64,
    pub baseline_count: i64,
    pub focal_boundary_windows: i64,
    pub baseline_boundary_windows: i64,
    pub evidence_ids: Vec<i64>,
    pub evidence_truncated: bool,
}

/// Result of comparing signature-window aggregates for adjacent, equally
/// sized windows.  `candidate_window_truncated` means the query saw more
/// canonical signatures than the fixed ranking budget; it never silently
/// implies that a zero delta means no other signature changed.
#[derive(Debug, Clone)]
pub(crate) struct RecurringErrorComparisonResult {
    pub focal_from: String,
    pub focal_to: String,
    pub baseline_from: String,
    pub baseline_to: String,
    pub candidate_rows: usize,
    pub candidate_cap: usize,
    pub candidate_window_truncated: bool,
    pub rows: Vec<RecurringErrorComparisonRow>,
}

/// Typed, canonical inputs for a recurring-error comparison.  Keeping the
/// window and filtering contract together prevents call sites from swapping
/// adjacent focal/baseline bounds or silently growing the query surface.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecurringErrorComparisonParams<'a> {
    pub normalizer_version: i64,
    pub focal_from: &'a str,
    pub focal_to: &'a str,
    pub baseline_from: &'a str,
    pub baseline_to: &'a str,
    pub signature_hash: Option<&'a str>,
    pub include_acknowledged: bool,
    pub limit: usize,
}

/// Return a bounded, deterministic comparison over canonical recurring-error
/// signatures.  Window records that straddle a requested boundary are not
/// counted as if they were exact samples; they are surfaced as explicit
/// boundary markers instead.  This keeps the comparison honest when a scan
/// chunk covered more than one requested time bucket.
pub(crate) fn compare_recurring_errors(
    pool: &DbPool,
    params: RecurringErrorComparisonParams<'_>,
) -> Result<RecurringErrorComparisonResult> {
    let conn = pool.get()?;
    let cap = RECURRING_ERROR_CANDIDATE_CAP;
    let requested_limit = params.limit.clamp(1, 50);
    let signature_filter = if params.signature_hash.is_some() {
        "AND s.signature_hash = ?2"
    } else {
        ""
    };
    let acknowledged_filter = if params.include_acknowledged {
        ""
    } else {
        "AND s.acknowledged_at IS NULL"
    };

    // The stable source order is last-seen DESC then canonical hash/version.
    // We retain cap+1 before ranking so truncation is always visible.
    let sql = format!(
        "WITH candidates AS MATERIALIZED (
             SELECT s.signature_hash, s.normalizer_version, s.template, s.sample_message,
                    s.sample_hostname, s.sample_app_name, s.severity, s.first_seen_at,
                    s.last_seen_at, s.total_count
             FROM error_signatures s
             WHERE s.normalizer_version = ?1 {signature_filter} {acknowledged_filter}
             ORDER BY s.last_seen_at DESC, s.signature_hash ASC, s.normalizer_version ASC
             LIMIT {}
         )
         SELECT
             s.signature_hash, s.normalizer_version, s.template, s.sample_message,
             s.sample_hostname, s.sample_app_name, s.severity, s.first_seen_at,
             s.last_seen_at, s.total_count,
             COALESCE(SUM(CASE WHEN w.window_start >= ?3 AND w.window_end <= ?4
                               THEN w.count_in_window ELSE 0 END), 0) AS current_count,
             COALESCE(SUM(CASE WHEN w.window_start >= ?5 AND w.window_end <= ?6
                               THEN w.count_in_window ELSE 0 END), 0) AS baseline_count,
             COALESCE(SUM(CASE WHEN w.window_start < ?4 AND w.window_end > ?3
                                AND NOT (w.window_start >= ?3 AND w.window_end <= ?4)
                               THEN 1 ELSE 0 END), 0) AS focal_boundary_windows,
             COALESCE(SUM(CASE WHEN w.window_start < ?6 AND w.window_end > ?5
                                AND NOT (w.window_start >= ?5 AND w.window_end <= ?6)
                               THEN 1 ELSE 0 END), 0) AS baseline_boundary_windows
         FROM candidates s
         LEFT JOIN error_signature_windows w
           ON w.signature_hash = s.signature_hash
          AND w.normalizer_version = s.normalizer_version
          AND w.window_end > ?5
          AND w.window_start < ?4
         GROUP BY s.signature_hash, s.normalizer_version
         ORDER BY s.last_seen_at DESC, s.signature_hash ASC, s.normalizer_version ASC",
        cap + 1
    );

    let signature_value = params.signature_hash.unwrap_or_default();
    let mut stmt = conn.prepare(&sql)?;
    let candidates = stmt
        .query_map(
            params![
                params.normalizer_version,
                signature_value,
                params.focal_from,
                params.focal_to,
                params.baseline_from,
                params.baseline_to,
            ],
            |row| {
                Ok(RecurringErrorComparisonRow {
                    signature_hash: row.get(0)?,
                    normalizer_version: row.get(1)?,
                    template: row.get(2)?,
                    sample_message: row.get(3)?,
                    sample_hostname: row.get(4)?,
                    sample_app_name: row.get(5)?,
                    severity: row.get(6)?,
                    first_seen_at: row.get(7)?,
                    last_seen_at: row.get(8)?,
                    total_count: row.get(9)?,
                    current_count: row.get(10)?,
                    baseline_count: row.get(11)?,
                    focal_boundary_windows: row.get(12)?,
                    baseline_boundary_windows: row.get(13)?,
                    evidence_ids: Vec::new(),
                    evidence_truncated: false,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let candidate_window_truncated = candidates.len() > cap;
    let candidate_rows = candidates.len().min(cap);
    let mut rows = candidates.into_iter().take(cap).collect::<Vec<_>>();

    // Rank after the capped source sample.  Higher current count, positive
    // change, severity, and canonical identity give a deterministic answer;
    // never let display/template text decide a tie.
    rows.sort_by(|left, right| {
        let severity = crate::db::severity_to_num(&left.severity)
            .unwrap_or(u8::MAX)
            .cmp(&crate::db::severity_to_num(&right.severity).unwrap_or(u8::MAX));
        right
            .current_count
            .cmp(&left.current_count)
            .then_with(|| {
                (right.current_count - right.baseline_count)
                    .cmp(&(left.current_count - left.baseline_count))
            })
            .then(severity)
            .then_with(|| left.signature_hash.cmp(&right.signature_hash))
            .then_with(|| left.normalizer_version.cmp(&right.normalizer_version))
    });
    rows.truncate(requested_limit);

    if !rows.is_empty() {
        let placeholders = std::iter::repeat_n("?", rows.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT source_signature_hash, id
             FROM (
                 SELECT source_signature_hash, id,
                        ROW_NUMBER() OVER (
                            PARTITION BY source_signature_hash ORDER BY id ASC
                        ) AS evidence_rank
                 FROM graph_relationship_evidence
                 WHERE source_kind = 'error_signature'
                   AND source_signature_hash IN ({placeholders})
             )
             WHERE evidence_rank <= {}\n             ORDER BY source_signature_hash, id",
            RECURRING_ERROR_EVIDENCE_CAP + 1
        );
        let mut evidence_stmt = conn.prepare(&sql)?;
        let mut evidence_by_hash = std::collections::HashMap::<String, Vec<i64>>::new();
        let evidence = evidence_stmt.query_map(
            rusqlite::params_from_iter(rows.iter().map(|row| row.signature_hash.as_str())),
            |item| Ok((item.get::<_, String>(0)?, item.get::<_, i64>(1)?)),
        )?;
        for item in evidence {
            let (hash, id) = item?;
            evidence_by_hash.entry(hash).or_default().push(id);
        }
        for row in &mut rows {
            row.evidence_ids = evidence_by_hash
                .remove(&row.signature_hash)
                .unwrap_or_default();
            row.evidence_truncated = row.evidence_ids.len() > RECURRING_ERROR_EVIDENCE_CAP;
            row.evidence_ids.truncate(RECURRING_ERROR_EVIDENCE_CAP);
        }
    }

    Ok(RecurringErrorComparisonResult {
        focal_from: params.focal_from.to_string(),
        focal_to: params.focal_to.to_string(),
        baseline_from: params.baseline_from.to_string(),
        baseline_to: params.baseline_to.to_string(),
        candidate_rows,
        candidate_cap: cap,
        candidate_window_truncated,
        rows,
    })
}

/// Return a page of unacknowledged (or all, if `include_acknowledged`)
/// signatures for one normalizer version, ordered by `last_seen_at DESC`.
///
/// The operator API identifies signatures by hash only, while ack/unack targets
/// the active normalizer version. Filtering here keeps historical version rows
/// durable without exposing entries the current API cannot act on.
pub(crate) fn read_unaddressed_page(
    pool: &DbPool,
    normalizer_version: i64,
    limit: i64,
    offset: i64,
    include_acknowledged: bool,
) -> Result<Vec<SignatureRow>> {
    let conn = pool.get()?;
    let cutoff_1h = chrono::Utc::now()
        .checked_sub_signed(chrono::TimeDelta::hours(1))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default();

    let filter_clause = if include_acknowledged {
        ""
    } else {
        "AND s.acknowledged_at IS NULL"
    };

    let sql = format!(
        "SELECT
             s.signature_hash,
             s.template,
             s.sample_message,
             s.sample_hostname,
             s.sample_app_name,
             s.severity,
             s.first_seen_at,
             s.last_seen_at,
             s.total_count,
             COALESCE(w.total_1h, 0) AS count_last_1h,
             s.acknowledged_at
         FROM error_signatures s
         LEFT JOIN (
             SELECT signature_hash, normalizer_version, SUM(count_in_window) AS total_1h
             FROM error_signature_windows
             WHERE window_end >= ?1 AND normalizer_version = ?2
             GROUP BY signature_hash, normalizer_version
         ) w USING (signature_hash, normalizer_version)
         WHERE s.normalizer_version = ?2 {filter_clause}
         ORDER BY s.last_seen_at DESC
         LIMIT ?3 OFFSET ?4"
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![cutoff_1h, normalizer_version, limit, offset.max(0)],
        |row| {
            Ok(SignatureRow {
                signature_hash: row.get(0)?,
                template: row.get(1)?,
                sample_message: row.get(2)?,
                sample_hostname: row.get(3)?,
                sample_app_name: row.get(4)?,
                severity: row.get(5)?,
                first_seen_at: row.get(6)?,
                last_seen_at: row.get(7)?,
                total_count: row.get(8)?,
                count_last_1h: row.get(9)?,
                acknowledged_at: row.get(10)?,
            })
        },
    )?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Look up a single signature by hash and normalizer version. Returns `None` if not found.
///
/// The table PK is `(signature_hash, normalizer_version)`, so both parameters are
/// required to uniquely identify a row.
pub(crate) fn read_signature_by_hash(
    pool: &DbPool,
    signature_hash: &str,
    normalizer_version: i64,
) -> Result<Option<SignatureRow>> {
    let conn = pool.get()?;
    let cutoff_1h = chrono::Utc::now()
        .checked_sub_signed(chrono::TimeDelta::hours(1))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default();

    // The `USING (...)` join form is load-bearing for performance (bead q2e8):
    // it lets SQLite push the outer `s.signature_hash = ?1` equality down into
    // the materialized aggregate subquery, so only this hash's windows are summed
    // (PK index seek, sub-ms). Rewriting it to an explicit `ON w.x = s.x` defeats
    // that pushdown and degrades to a full GROUP BY over error_signature_windows
    // (~100x slower at scale). Keep the `USING` form.
    let mut stmt = conn.prepare(
        "SELECT
             s.signature_hash,
             s.template,
             s.sample_message,
             s.sample_hostname,
             s.sample_app_name,
             s.severity,
             s.first_seen_at,
             s.last_seen_at,
             s.total_count,
             COALESCE(w.total_1h, 0) AS count_last_1h,
             s.acknowledged_at
         FROM error_signatures s
         LEFT JOIN (
             SELECT signature_hash, normalizer_version, SUM(count_in_window) AS total_1h
             FROM error_signature_windows
             WHERE window_end >= ?3
             GROUP BY signature_hash, normalizer_version
         ) w USING (signature_hash, normalizer_version)
         WHERE s.signature_hash = ?1 AND s.normalizer_version = ?2
         LIMIT 1",
    )?;

    let mut rows = stmt.query_map(
        params![signature_hash, normalizer_version, cutoff_1h],
        |row| {
            Ok(SignatureRow {
                signature_hash: row.get(0)?,
                template: row.get(1)?,
                sample_message: row.get(2)?,
                sample_hostname: row.get(3)?,
                sample_app_name: row.get(4)?,
                severity: row.get(5)?,
                first_seen_at: row.get(6)?,
                last_seen_at: row.get(7)?,
                total_count: row.get(8)?,
                count_last_1h: row.get(9)?,
                acknowledged_at: row.get(10)?,
            })
        },
    )?;

    rows.next().transpose().map_err(Into::into)
}

#[cfg(test)]
#[path = "error_signatures_tests.rs"]
mod tests;
