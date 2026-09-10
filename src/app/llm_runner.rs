//! Shared LLM invocation guard: every LLM-backed assessment feature routes
//! through `LlmRunner::run` (or `LlmRunner::dry_run` for a preview) so
//! concurrency limits, rate limits, circuit breaking, timeouts, size
//! limits, and audit logging are enforced in exactly one place.
//!
//! See `llm_invocations` (migration 37, `src/db/pool.rs`) for the audit
//! schema and `[llm]` in `src/config.rs` for the tunables.
//!
//! Every audit write goes through `crate::db::write_conn`, which takes the
//! process-wide write lock and only then borrows a pooled connection, matching
//! the standing single-writer invariant documented at the top of
//! `src/db/pool.rs` — see the `write_start_row`/`write_finish_row_inner`
//! bodies below.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use crate::assessment::{redact_json_value_strings, redact_secrets};
use crate::config::LlmConfig;
use crate::db::DbPool;

/// Hard cap on the serialized size of `metadata_json`, in bytes. Distinct
/// from (and much smaller than) `LlmConfig.max_output_bytes` — metadata is
/// for small structured tags only, never prompt/evidence content (see the
/// `extra_metadata` contract note in "Locked interfaces for other phases"
/// in the LLM invocation guard plan). Oversized metadata is truncated with
/// an explicit `"truncated": true` marker, never silently stored in full.
const LLM_METADATA_MAX_BYTES: usize = 4096;

/// Who is making this LLM call. Recorded verbatim into
/// `llm_invocations.caller_surface`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmCallerSurface {
    Cli,
    Mcp,
    Rest,
    Background,
    Test,
}

impl LlmCallerSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Mcp => "mcp",
            Self::Rest => "rest",
            Self::Background => "background",
            Self::Test => "test",
        }
    }
}

/// Evidence bundle sizing info recorded into `evidence_counts_json`.
/// Callers build this before invoking `LlmRunner::run` so denials
/// (concurrency/rate-limit/circuit-open/disabled) still get an accurate
/// audit record without needing the LLM call to happen.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LlmEvidenceCounts {
    pub total_incidents: usize,
    pub evidence_bundle_count: usize,
    pub total_anchors: usize,
    pub truncated: bool,
}

/// Everything needed to run (or dry-run) one LLM invocation.
#[derive(Debug, Clone)]
pub struct LlmInvocationSpec {
    pub caller_surface: LlmCallerSurface,
    /// Action name, e.g. "ai_assess", "skill_assess". Used for per-action
    /// concurrency/rate-limit/circuit-breaker/enablement lookups.
    pub action: String,
    pub incident_id: Option<String>,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub evidence_counts: LlmEvidenceCounts,
    pub prompt: String,
    /// Provider identifier, e.g. "gemini-cli".
    pub provider: String,
    pub model: String,
    /// Program invoked, e.g. "gemini".
    pub program: String,
    /// Extra caller-defined metadata merged into `metadata_json`
    /// (host/pid are always added by the runner itself).
    ///
    /// **CONTRACT (do not violate in PR 2-4):** `extra_metadata` is for small
    /// structured tags only (e.g. `{"skill": "frustration-assessment"}`).
    /// It MUST NOT be used to carry prompt text, evidence bundle content, or
    /// any other bulk/sensitive payload — `llm_invocations` is an
    /// operational audit table, not an evidence store, and (per the eng
    /// review security fixes) is scoped `cortex:admin`, not a general
    /// dumping ground. The runner redacts secret-shaped substrings and hard-
    /// caps the serialized size at `LLM_METADATA_MAX_BYTES` (4096 bytes) —
    /// see `build_metadata_json` — so oversized or leaked-looking
    /// `extra_metadata` is truncated/redacted, not silently stored whole.
    pub extra_metadata: serde_json::Value,
}

/// Result of a completed (non-dry-run) invocation.
#[derive(Debug, Clone)]
pub struct LlmInvocationOutcome {
    pub invocation_id: String,
    pub output: String,
    pub duration_ms: i64,
    pub output_bytes: usize,
}

/// Result of a dry-run/preview invocation — no LLM call is made.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LlmDryRunOutcome {
    pub invocation_id: String,
    pub prompt_bytes: usize,
    pub evidence_counts: LlmEvidenceCounts,
    pub would_exceed_prompt_limit: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmRunnerError {
    #[error(
        "LLM invocations are globally disabled ([llm].enabled=false or CORTEX_LLM_ENABLED=false)"
    )]
    Disabled,
    #[error("LLM action '{0}' is disabled ([llm.actions.{0}].enabled=false)")]
    ActionDisabled(String),
    #[error("prompt size {actual} bytes exceeds max_prompt_bytes {limit} bytes")]
    PromptTooLarge { actual: usize, limit: usize },
    #[error("global concurrency limit reached (max_concurrent={0})")]
    ConcurrencyLimited(usize),
    #[error(
        "per-action concurrency limit reached for '{action}' (max_per_action_concurrent={limit})"
    )]
    ActionConcurrencyLimited { action: String, limit: usize },
    #[error("rate limit exceeded for action '{action}': {detail}")]
    RateLimited { action: String, detail: String },
    #[error("circuit open for action '{action}', retry after {retry_after}")]
    CircuitOpen { action: String, retry_after: String },
    #[error("LLM invocation '{0}' timed out after {1}s")]
    Timeout(String, u64),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Per-action sliding-window rate + failure-streak state.
#[derive(Default)]
struct ActionState {
    /// Timestamps (monotonic `Instant`) of invocations started in the
    /// last hour; pruned lazily on each check.
    recent_starts: Vec<Instant>,
    consecutive_failures: u32,
    /// Set when the circuit opens; cleared on the next successful call
    /// after `circuit_open_until` has elapsed.
    circuit_open_until: Option<Instant>,
    /// Per-action concurrency permits, created lazily per action name.
    permits: Option<Arc<Semaphore>>,
}

pub struct LlmRunner {
    pool: Arc<DbPool>,
    config: LlmConfig,
    global_permits: Arc<Semaphore>,
    action_state: Mutex<HashMap<String, ActionState>>,
}

impl LlmRunner {
    /// `pool` is used to write `llm_invocations` audit rows. `config` is the
    /// `[llm]` section of `Config`, and `config.timeout_secs` is now the
    /// SINGLE source of truth for LLM invocation timeouts end to end: Task 6
    /// threads this same value into `GeminiAssessConfig` construction
    /// instead of that struct independently re-reading
    /// `CORTEX_LLM_COMPLETION_TIMEOUT_SECS`, so the outer `LlmRunner::run`
    /// timeout and the inner Gemini-subprocess timeout can never drift
    /// apart.
    pub fn new(pool: Arc<DbPool>, config: LlmConfig) -> Self {
        let global_permits = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            pool,
            config,
            global_permits,
            action_state: Mutex::new(HashMap::new()),
        }
    }

    /// `caller_surface` is required (not just `action`) because the
    /// documented contract for `background_enrichment_enabled` is "checked
    /// whenever `caller_surface == Background`" — the gate must trigger for
    /// ANY action run with `LlmCallerSurface::Background`, not only the
    /// literal action name `"background_enrich"`. The action-name check is
    /// kept as defense in depth: it protects the well-known background
    /// action even if a caller forgets to set `caller_surface` correctly.
    fn action_enabled(&self, action: &str, caller_surface: LlmCallerSurface) -> bool {
        if !self.config.background_enrichment_enabled
            && (caller_surface == LlmCallerSurface::Background || action == "background_enrich")
        {
            return false;
        }
        self.config
            .actions
            .get(action)
            .map(|a| a.enabled)
            .unwrap_or(true)
    }

    /// Byte budget enforced by provider adapters before streaming output.
    pub(crate) fn max_output_bytes(&self) -> usize {
        self.config.max_output_bytes
    }

    /// Resolve the one provider selector captured during configuration loading.
    pub(crate) fn backend(
        &self,
        model: Option<String>,
    ) -> anyhow::Result<crate::llm_backend::LlmBackend> {
        crate::llm_backend::LlmBackend::from_config(model, &self.config)
    }

    /// The same resolved timeout used by the runner and provider subprocess.
    pub fn timeout_secs(&self) -> u64 {
        self.config.timeout_secs
    }

    /// Build the prompt/evidence bundle size report without invoking the LLM.
    /// Still writes an audit row (status "dry_run"). Does NOT consult
    /// concurrency/rate-limit/circuit-breaker state — sizing is always safe
    /// to preview.
    pub async fn dry_run(
        &self,
        spec: &LlmInvocationSpec,
    ) -> Result<LlmDryRunOutcome, LlmRunnerError> {
        let prompt_bytes = spec.prompt.len();
        let would_exceed = prompt_bytes > self.config.max_prompt_bytes;
        let invocation_id = new_invocation_id();
        self.write_start_row(&invocation_id, spec, "dry_run", prompt_bytes)
            .await?;
        self.write_finish_row(&invocation_id, "dry_run", None, 0)
            .await?;
        Ok(LlmDryRunOutcome {
            invocation_id,
            prompt_bytes,
            evidence_counts: spec.evidence_counts.clone(),
            would_exceed_prompt_limit: would_exceed,
        })
    }

    /// Run one LLM invocation end-to-end: enablement checks, concurrency
    /// permits, rate limiting, circuit breaker, size limits, spawn via
    /// `run_fn`, timeout, and audit record start/finish. `run_fn` receives
    /// the validated prompt and must return the raw model output — bounding
    /// output to `max_output_bytes` is NOT required of `run_fn`; the
    /// runner truncates the captured output itself before persisting/
    /// returning it.
    pub async fn run<F, Fut>(
        &self,
        spec: LlmInvocationSpec,
        run_fn: F,
    ) -> Result<LlmInvocationOutcome, LlmRunnerError>
    where
        F: FnOnce(String) -> Fut + Send,
        Fut: std::future::Future<Output = anyhow::Result<String>> + Send,
    {
        let action = spec.action.clone();
        let prompt_bytes = spec.prompt.len();

        // 1. Global kill switch.
        if !self.config.enabled {
            let id = new_invocation_id();
            self.write_start_row(&id, &spec, "disabled", prompt_bytes)
                .await?;
            self.write_finish_row(&id, "disabled", None, 0).await?;
            return Err(LlmRunnerError::Disabled);
        }

        // 2. Per-action enablement (covers background_enrichment_enabled too,
        //    gated on caller_surface == Background per the documented
        //    contract, not just the "background_enrich" action name).
        if !self.action_enabled(&action, spec.caller_surface) {
            let id = new_invocation_id();
            self.write_start_row(&id, &spec, "disabled", prompt_bytes)
                .await?;
            self.write_finish_row(&id, "disabled", None, 0).await?;
            return Err(LlmRunnerError::ActionDisabled(action));
        }

        // 3. Size limit — reject before spawning anything.
        if prompt_bytes > self.config.max_prompt_bytes {
            let id = new_invocation_id();
            self.write_start_row(&id, &spec, "error", prompt_bytes)
                .await?;
            self.write_finish_row(&id, "error", Some("prompt_too_large"), 0)
                .await?;
            return Err(LlmRunnerError::PromptTooLarge {
                actual: prompt_bytes,
                limit: self.config.max_prompt_bytes,
            });
        }

        // 4. Circuit breaker.
        let action_permits = {
            let mut state = self.action_state.lock().await;
            let entry = state.entry(action.clone()).or_default();
            if let Some(open_until) = entry.circuit_open_until {
                if Instant::now() < open_until {
                    drop(state);
                    let id = new_invocation_id();
                    self.write_start_row(&id, &spec, "circuit_open", prompt_bytes)
                        .await?;
                    self.write_finish_row(&id, "circuit_open", Some("circuit_open"), 0)
                        .await?;
                    // `Instant`'s Debug output is opaque/platform-dependent
                    // (not a wall-clock time), so it's not actionable for a
                    // caller trying to know how long to wait. Report the
                    // remaining seconds until the circuit closes instead.
                    // Round UP (not truncate) so a sub-second remainder
                    // never reports "0s" while the circuit is still open.
                    let retry_after_secs = open_until
                        .saturating_duration_since(Instant::now())
                        .as_secs_f64()
                        .ceil() as u64;
                    return Err(LlmRunnerError::CircuitOpen {
                        action: action.clone(),
                        retry_after: format!("{retry_after_secs}s"),
                    });
                }
                entry.circuit_open_until = None;
            }

            // 5. Rate limit (sliding window over recent_starts).
            let now = Instant::now();
            entry
                .recent_starts
                .retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
            let last_minute = entry
                .recent_starts
                .iter()
                .filter(|t| now.duration_since(**t) < Duration::from_secs(60))
                .count() as u32;
            if last_minute >= self.config.max_invocations_per_minute {
                drop(state);
                let id = new_invocation_id();
                self.write_start_row(&id, &spec, "rate_limited", prompt_bytes)
                    .await?;
                self.write_finish_row(&id, "rate_limited", Some("rate_limited_per_minute"), 0)
                    .await?;
                return Err(LlmRunnerError::RateLimited {
                    action: action.clone(),
                    detail: format!(
                        "{last_minute}/{} invocations in the last minute",
                        self.config.max_invocations_per_minute
                    ),
                });
            }
            let last_hour = entry.recent_starts.len() as u32;
            if last_hour >= self.config.max_invocations_per_hour {
                drop(state);
                let id = new_invocation_id();
                self.write_start_row(&id, &spec, "rate_limited", prompt_bytes)
                    .await?;
                self.write_finish_row(&id, "rate_limited", Some("rate_limited_per_hour"), 0)
                    .await?;
                return Err(LlmRunnerError::RateLimited {
                    action: action.clone(),
                    detail: format!(
                        "{last_hour}/{} invocations in the last hour",
                        self.config.max_invocations_per_hour
                    ),
                });
            }
            entry.recent_starts.push(now);

            entry
                .permits
                .get_or_insert_with(|| {
                    Arc::new(Semaphore::new(self.config.max_per_action_concurrent))
                })
                .clone()
        };

        // 6. Concurrency permits (global, then per-action). Acquire
        //    try_acquire (non-blocking): callers get an immediate denial
        //    rather than queuing, matching "max_concurrent=1 means at most
        //    one in flight, others are rejected" from the requirements.
        let _global_permit = match self.global_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let id = new_invocation_id();
                self.write_start_row(&id, &spec, "denied", prompt_bytes)
                    .await?;
                self.write_finish_row(&id, "denied", Some("global_concurrency_limited"), 0)
                    .await?;
                return Err(LlmRunnerError::ConcurrencyLimited(
                    self.config.max_concurrent,
                ));
            }
        };
        let _action_permit = match action_permits.try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let id = new_invocation_id();
                self.write_start_row(&id, &spec, "denied", prompt_bytes)
                    .await?;
                self.write_finish_row(&id, "denied", Some("action_concurrency_limited"), 0)
                    .await?;
                return Err(LlmRunnerError::ActionConcurrencyLimited {
                    action: action.clone(),
                    limit: self.config.max_per_action_concurrent,
                });
            }
        };

        // 7. Run with timeout; record start row now that all guards passed.
        let invocation_id = new_invocation_id();
        self.write_start_row(&invocation_id, &spec, "running", prompt_bytes)
            .await?;
        let start = Instant::now();
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let prompt = spec.prompt.clone();
        let run_result = tokio::time::timeout(timeout, run_fn(prompt)).await;
        let duration_ms = start.elapsed().as_millis() as i64;

        let mut state = self.action_state.lock().await;
        let entry = state.entry(action.clone()).or_default();

        match run_result {
            Ok(Ok(output)) => {
                entry.consecutive_failures = 0;
                let truncated_output = truncate_utf8_bytes(&output, self.config.max_output_bytes);
                let output_bytes = truncated_output.len();
                drop(state);
                // Intentional tradeoff, not an oversight: `run_fn` already
                // succeeded at this point, but the `?` below means a failure
                // to write the finish row (DB pool exhaustion, disk full,
                // write-lock timeout) discards the successful LLM output and
                // returns an error to the caller instead. This favors audit-
                // trail completeness (every invocation that started has a
                // matching finish row, or the caller finds out immediately
                // that the audit trail is broken) over result delivery. A
                // "best-effort audit, always return the result" design was
                // considered and rejected: it would let a caller act on an
                // LLM result with no corresponding audit record, silently
                // undermining the entire point of routing every invocation
                // through `LlmRunner`.
                self.write_finish_row_with_output(
                    &invocation_id,
                    "success",
                    None,
                    duration_ms,
                    output_bytes,
                )
                .await?;
                Ok(LlmInvocationOutcome {
                    invocation_id,
                    output: truncated_output,
                    duration_ms,
                    output_bytes,
                })
            }
            Ok(Err(err)) => {
                entry.consecutive_failures += 1;
                let should_open = entry.consecutive_failures >= self.config.failure_threshold;
                if should_open {
                    entry.circuit_open_until =
                        Some(Instant::now() + Duration::from_secs(self.config.cooldown_secs));
                }
                drop(state);
                // Eng review fix (architecture reviewer): the audit row and
                // the caller-facing error MUST be redacted with the same
                // pass. Previously only the persisted `error` column was
                // sanitized here; the raw `err` was still wrapped and
                // returned to the caller via `LlmRunnerError::Internal`,
                // so a secret-shaped string in (e.g.) Gemini subprocess
                // stderr could reach the CLI/MCP/REST caller directly even
                // though the DB audit trail was clean. Sanitize once and
                // reuse the same redacted text for both the DB write and
                // the returned error.
                let sanitized = sanitize_error(&err);
                self.write_finish_row(&invocation_id, "error", Some(&sanitized), duration_ms)
                    .await?;
                Err(LlmRunnerError::Internal(anyhow::anyhow!(sanitized)))
            }
            Err(_elapsed) => {
                entry.consecutive_failures += 1;
                let should_open = entry.consecutive_failures >= self.config.failure_threshold;
                if should_open {
                    entry.circuit_open_until =
                        Some(Instant::now() + Duration::from_secs(self.config.cooldown_secs));
                }
                drop(state);
                self.write_finish_row(&invocation_id, "timeout", Some("timed out"), duration_ms)
                    .await?;
                Err(LlmRunnerError::Timeout(
                    invocation_id,
                    self.config.timeout_secs,
                ))
            }
        }
    }

    // --- audit writers -----------------------------------------------
    //
    // Eng review fix (CRITICAL — architecture + performance reviewers):
    // every write here MUST hold the process-wide write lock for the
    // duration of the `execute` call. Without it, every audit INSERT/
    // UPDATE races the syslog batch inserter, heartbeat, notifications,
    // and retention maintenance for SQLite's single write lock — the
    // exact hazard the invariant documented at the top of
    // `src/db/pool.rs` exists to prevent. `crate::db::write_conn` takes
    // that lock before it borrows the connection, so a writer queued
    // behind a long write is not also holding one.

    async fn write_start_row(
        &self,
        id: &str,
        spec: &LlmInvocationSpec,
        status: &str,
        prompt_bytes: usize,
    ) -> Result<(), LlmRunnerError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        let caller_surface = spec.caller_surface.as_str().to_string();
        let action = spec.action.clone();
        let provider = spec.provider.clone();
        let model = spec.model.clone();
        let program = spec.program.clone();
        let incident_id = spec.incident_id.clone();
        let ai_tool = spec.ai_tool.clone();
        let ai_project = spec.ai_project.clone();
        let ai_session_id = spec.ai_session_id.clone();
        let evidence_counts_json = serde_json::to_string(&spec.evidence_counts).ok();
        let status = status.to_string();
        let metadata_json = build_metadata_json(&spec.extra_metadata);

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            // Serializes with every other writer in the process — see the
            // module-level invariant note and `src/db/pool.rs`. Both the
            // lock and the connection are scoped to just this INSERT.
            let conn = crate::db::write_conn(&pool)?;
            let params = crate::db::llm_invocations::LlmInvocationInsertParams {
                caller_surface,
                action,
                provider,
                model: Some(model),
                program: Some(program),
                incident_id,
                ai_tool,
                ai_project,
                ai_session_id,
                evidence_counts_json,
                prompt_bytes: Some(prompt_bytes as i64),
                status,
                metadata_json: Some(metadata_json),
            };
            crate::db::llm_invocations::insert_llm_invocation_running(&conn, &id, &params)?;
            Ok(())
        })
        .await
        .map_err(|e| LlmRunnerError::Internal(anyhow::anyhow!("audit write join error: {e}")))?
        .map_err(LlmRunnerError::Internal)
    }

    async fn write_finish_row(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
        duration_ms: i64,
    ) -> Result<(), LlmRunnerError> {
        self.write_finish_row_inner(id, status, error, duration_ms, None)
            .await
    }

    async fn write_finish_row_with_output(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
        duration_ms: i64,
        output_bytes: usize,
    ) -> Result<(), LlmRunnerError> {
        self.write_finish_row_inner(id, status, error, duration_ms, Some(output_bytes))
            .await
    }

    async fn write_finish_row_inner(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
        duration_ms: i64,
        output_bytes: Option<usize>,
    ) -> Result<(), LlmRunnerError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        let status = status.to_string();
        let error = error.map(|e| e.to_string());
        let output_bytes = output_bytes.map(|b| b as i64);

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            // Same lock-then-connection invariant as write_start_row above.
            let conn = crate::db::write_conn(&pool)?;
            crate::db::llm_invocations::finish_llm_invocation(
                &conn,
                &id,
                &status,
                error.as_deref(),
                duration_ms,
                output_bytes,
            )?;
            Ok(())
        })
        .await
        .map_err(|e| LlmRunnerError::Internal(anyhow::anyhow!("audit write join error: {e}")))?
        .map_err(LlmRunnerError::Internal)
    }
}

/// Build the `metadata_json` column value: merge caller-supplied
/// `extra_metadata` with runner-added `host`/`pid`, redact each string
/// LEAF of the JSON tree individually (see `redact_json_value_strings`),
/// then serialize and enforce `LLM_METADATA_MAX_BYTES`.
///
/// Eng review fix (security reviewer V3): `extra_metadata` is
/// caller-supplied and, per the `extra_metadata` contract documented on
/// `LlmInvocationSpec`, MUST NOT carry prompt/evidence content — but
/// nothing stops a future caller (PR 2-4) from doing so by mistake.
/// Redacting + size-capping here is the enforcement backstop: secret-
/// shaped strings never reach the column, and oversized metadata is
/// truncated with an explicit marker rather than silently stored in full.
///
/// Eng review fix (security-sentinel): redacting the WHOLE serialized
/// JSON string (as this used to do) tokenizes on `split_whitespace()`.
/// A secret supplied as a JSON *value* (e.g.
/// `{"token":"sk-realsecret"}`) serializes to a single whitespace-free
/// token like `{"token":"sk-realsecret",...}`, so `looks_secretish`'s
/// `token.starts_with("sk-")` check misses it (the token actually starts
/// with `{`). Walking the `Value` tree and redacting each string leaf
/// BEFORE serialization means `looks_secretish` sees the real token
/// boundaries, so prefix-based checks work correctly. It also guarantees
/// `metadata_json` stays valid JSON — the old blob-redaction approach
/// could in principle replace a token overlapping a quote character with
/// `[REDACTED]` and corrupt the JSON structure.
fn build_metadata_json(extra: &serde_json::Value) -> String {
    let host = hostname_best_effort();
    let pid = std::process::id();
    let mut obj = extra.as_object().cloned().unwrap_or_default();
    obj.insert("host".to_string(), serde_json::json!(host));
    obj.insert("pid".to_string(), serde_json::json!(pid));
    let mut value = serde_json::Value::Object(obj);
    redact_json_value_strings(&mut value);
    let redacted = value.to_string();

    if redacted.len() <= LLM_METADATA_MAX_BYTES {
        return redacted;
    }

    // Oversized even after redaction: truncate to a valid-JSON-ish
    // marker object rather than silently storing a partial/corrupt blob.
    // We deliberately do NOT try to preserve partial structure — an
    // oversized `extra_metadata` is itself a contract violation (see the
    // doc note on `LlmInvocationSpec::extra_metadata`), so the marker
    // calls that out instead of pretending truncation is a normal, silent
    // path.
    serde_json::json!({
        "truncated": true,
        "reason": "extra_metadata exceeded LLM_METADATA_MAX_BYTES",
        "original_bytes": redacted.len(),
        "max_bytes": LLM_METADATA_MAX_BYTES,
        "host": host,
        "pid": pid,
    })
    .to_string()
}

fn hostname_best_effort() -> String {
    crate::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Sanitize an error before persisting: redact FIRST using the same
/// `redact_secrets`/`looks_secretish` heuristic as `src/assessment.rs`
/// (imported, not forked), THEN bound length. Redact-before-truncate is
/// load-bearing: bounding first can split a secret across the truncation
/// boundary and let the surviving half leak into the persisted `error`
/// column.
///
/// The returned string is reused for two purposes, not just persistence:
/// `LlmRunner::run`'s error branch writes it into the audit row's `error`
/// column AND wraps it into the `LlmRunnerError::Internal` returned to the
/// caller. Both sinks share this single sanitized string so a secret-shaped
/// value can't leak through the caller-facing error path while staying
/// clean in the DB (see the call site in `run` for the full rationale).
fn sanitize_error(err: &anyhow::Error) -> String {
    let text = err.to_string();
    let redacted = redact_secrets(&text);
    redacted.chars().take(2048).collect()
}

/// Truncate `s` to at most `max_bytes` BYTES on a valid UTF-8 char
/// boundary. `max_output_bytes` is documented and named as a byte limit,
/// but `.chars().take(n)` (the previous implementation) limits to `n`
/// *characters*, not bytes — for multi-byte UTF-8 output (very common in
/// LLM text: emoji, non-ASCII scripts, smart punctuation) actual byte
/// size could exceed the configured limit by up to ~4x. This walks
/// `char_indices()` and stops at the last boundary whose byte offset is
/// `<= max_bytes`, which is always a valid UTF-8 boundary by construction.
fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = 0;
    for (idx, ch) in s.char_indices() {
        let next_end = idx + ch.len_utf8();
        if next_end > max_bytes {
            break;
        }
        end = next_end;
    }
    s[..end].to_string()
}

/// Stable-across-start/finish invocation id. Timestamp-prefixed for sort
/// order and human debuggability. Uses a simple counter+random suffix
/// instead of a content hash since there is no stable content to hash
/// before the invocation starts.
fn new_invocation_id() -> String {
    let now = chrono::Utc::now();
    let rand_suffix: u32 = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        nanos ^ std::process::id()
    };
    format!(
        "llm-{}-{:08x}",
        now.format("%Y%m%dT%H%M%S%.6f"),
        rand_suffix
    )
}

#[cfg(test)]
#[path = "llm_runner_tests.rs"]
mod tests;
