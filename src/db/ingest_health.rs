use anyhow::Result;
use rusqlite::params;

use super::pool::DbPool;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IngestSourceKindHealth {
    pub source_kind: String,
    pub last_seen: String,
    pub last_15m: i64,
    pub last_1h: i64,
    pub last_24h: i64,
}

pub fn ingest_source_kind_health(
    pool: &DbPool,
    now: &str,
    cut_15m: &str,
    cut_1h: &str,
    cut_24h: &str,
) -> Result<Vec<IngestSourceKindHealth>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "
        WITH classified AS (
            SELECT
                CASE
                    WHEN ai_transcript_path IS NOT NULL OR source_ip LIKE 'transcript://%' THEN 'transcript'
                    WHEN source_ip LIKE 'docker://%' THEN 'docker-stream'
                    WHEN source_ip LIKE 'docker-event://%' THEN 'docker-event'
                    WHEN source_ip LIKE 'agent-command://%' THEN 'agent-command'
                    WHEN source_ip LIKE 'shell-history://%' THEN 'shell-history'
                    WHEN source_ip LIKE 'file-tail://%' THEN 'file-tail'
                    WHEN source_ip LIKE 'agent-file-tail://%' THEN 'agent-file-tail'
                    ELSE json_extract(metadata_json, '$.source_kind')
                END AS source_kind,
                received_at
            FROM logs
            WHERE received_at >= ?4 AND received_at <= ?1
        )
        SELECT source_kind,
               MAX(received_at),
               SUM(CASE WHEN received_at >= ?2 THEN 1 ELSE 0 END),
               SUM(CASE WHEN received_at >= ?3 THEN 1 ELSE 0 END),
               COUNT(*)
        FROM classified
        WHERE source_kind IS NOT NULL AND source_kind != ''
        GROUP BY source_kind
        ORDER BY source_kind ASC
        ",
    )?;
    let rows = stmt.query_map(params![now, cut_15m, cut_1h, cut_24h], |row| {
        Ok(IngestSourceKindHealth {
            source_kind: row.get(0)?,
            last_seen: row.get(1)?,
            last_15m: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            last_1h: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            last_24h: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
