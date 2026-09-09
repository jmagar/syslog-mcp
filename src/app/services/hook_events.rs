//! `hook_events` read surface — lists already-extracted/backfilled/collected
//! `ai_hook_events` rows. Runtime extraction lives in
//! `crate::scanner::hook_events` (ingest-time) and `super::hook_backfill`
//! (historical backfill); config-inventory collection lives in
//! `crate::hook_config`. This module only wraps `db::list_hook_events` with
//! request/response model conversion, mirroring `super::skill_events`.

use crate::db;

use super::super::models::ListHookEventsRequest;
use super::super::time::parse_optional_timestamp;
use super::{CortexService, ServiceResult};
use crate::app::models::ListHookEventsResponse;

impl CortexService {
    pub async fn list_hook_events(
        &self,
        req: ListHookEventsRequest,
    ) -> ServiceResult<ListHookEventsResponse> {
        let from = parse_optional_timestamp(req.from.as_deref(), "from")?;
        let to = parse_optional_timestamp(req.to.as_deref(), "to")?;
        let params = db::AiHookEventParams {
            hook_event: req.hook_event,
            hook_name: req.hook_name,
            hook_source: req.hook_source,
            status: req.status,
            evidence_kind: req.evidence_kind,
            tool: req.tool,
            project: req.project,
            session_id: req.session_id,
            hostname: req.hostname,
            from,
            to,
            limit: req.limit,
        };
        let result = self
            .run_db("list_hook_events", move |pool| {
                db::list_hook_events(pool, &params)
            })
            .await?;
        Ok(result.into())
    }

    /// Collect a fresh point-in-time hook config/trust-state inventory from
    /// local host files (`~/.claude/settings.json`, `~/.codex/hooks.json`,
    /// `~/.codex/config.toml [hooks.state]`) and persist it via
    /// `crate::hook_config::collect_and_store`. Returns the number of newly
    /// inserted rows. CLI-only in practice — see `cortex assess hooks
    /// --collect-config`'s `CliMode::Http` guard; nothing here itself
    /// refuses a non-local caller, callers are responsible for that guard,
    /// mirroring the LLM-runner CLI-only convention used elsewhere in this
    /// service.
    ///
    /// Uses full millisecond-precision `now()`, so repeated
    /// `--collect-config` runs are NOT deduplicated against each other —
    /// each call inserts a fresh snapshot row per configured hook (no cap
    /// or retention path exists for `ai_hook_events` yet; that's a known,
    /// separately tracked gap). Eng review fix (adversarial re-verify): an
    /// earlier attempt at this truncated the timestamp to the day
    /// boundary to make same-day repeats idempotent via `INSERT OR
    /// IGNORE`, but the unique index's dedupe key has no content-bearing
    /// column (no `trusted_hash`/`hook_command`), so day-truncation also
    /// silently dropped genuine same-day content changes — e.g. a hook's
    /// `trusted_hash` rotating twice in one day would only ever persist
    /// the FIRST value, confirmed by a direct DB test. Losing a real
    /// trust-hash rotation is worse than the storage-growth problem the
    /// truncation was solving, so this reverts to full precision;
    /// deduplication should eventually be content-aware (compare against
    /// the latest existing row per identity) rather than timestamp-based.
    pub async fn collect_hook_config_inventory(&self) -> ServiceResult<usize> {
        let hostname = crate::hostname::local_hostname();
        let timestamp = crate::app::time::rfc3339_z(chrono::Utc::now());
        self.run_db("collect_hook_config_inventory", move |pool| {
            crate::hook_config::collect_and_store(pool, &hostname, &timestamp)
        })
        .await
    }
}
