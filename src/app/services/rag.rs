use super::filters::validate_optional_severity;
use super::*;
use crate::app::RECURRING_ERROR_PRIVACY_POLICY_V1;
use sha2::{Digest, Sha256};

const RECURRING_ERROR_SAFE_TEXT_LIMIT: usize = 512;
const RECURRING_ERROR_BUNDLE_CACHE_CAP: usize = 256;

/// Scrub before truncation so a secret that crosses the display cap cannot
/// leave a surviving suffix.  This is intentionally independent of graph
/// rendering: recurring-error bundles are safe projections in their own right.
fn safe_recurring_error_text(value: &str) -> String {
    let scrubbed = crate::receiver::enrichment::scrub_ai_message(value, None);
    let redacted = crate::assessment::redact_secrets(&scrubbed);
    redacted
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            if lower.contains("/home/")
                || lower.contains("/users/")
                || lower.contains("://") && lower.contains('@')
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token=")
                || lower.contains("api_key")
            {
                "[redacted]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|ch| !ch.is_control())
        .take(RECURRING_ERROR_SAFE_TEXT_LIMIT)
        .collect()
}

fn recurring_error_bundle_id(
    source_key: &str,
    focal_from: &str,
    focal_to: &str,
    evidence_revision: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        "cortex-recurring-error-bundle/v1",
        source_key,
        focal_from,
        focal_to,
        evidence_revision,
        RECURRING_ERROR_PRIVACY_POLICY_V1,
    ] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

impl CortexService {
    /// List recent notification firings.
    pub async fn notifications_recent(
        &self,
        limit: i64,
        rule_id: Option<String>,
        since: Option<String>,
    ) -> ServiceResult<Vec<crate::db::notifications::FiringRow>> {
        self.notifications_recent_checked(NotificationsRecentRequest {
            limit: Some(limit),
            rule_id,
            since,
        })
        .await
    }

    pub async fn notifications_recent_checked(
        &self,
        req: NotificationsRecentRequest,
    ) -> ServiceResult<Vec<crate::db::notifications::FiringRow>> {
        let limit = req.effective_limit();
        self.run_db("notifications_recent", move |pool| {
            let conn = pool.get()?;
            crate::db::notifications::firings_recent(
                &conn,
                limit,
                req.rule_id.as_deref(),
                req.since.as_deref(),
            )
            .map_err(anyhow::Error::from)
        })
        .await
    }

    /// List recent `llm_invocations` audit records (concurrency/rate-limit/
    /// circuit-breaker denials included). Read-only over the audit table
    /// `LlmRunner` writes — no scope gate at the service layer; MCP/REST
    /// callers gate this at their own transport layer (cortex:admin /
    /// X-Cortex-Admin-Token) since it exposes operational kill-switch/
    /// circuit-breaker state, not just log content.
    pub async fn llm_invocations_checked(
        &self,
        req: LlmInvocationsRequest,
    ) -> ServiceResult<Vec<crate::db::llm_invocations::LlmInvocationRow>> {
        let limit = req.effective_limit();
        self.run_db("llm_invocations", move |pool| {
            let conn = pool.get()?;
            crate::db::llm_invocations::list_llm_invocations(
                &conn,
                limit,
                req.since.as_deref(),
                req.action.as_deref(),
                req.status.as_deref(),
            )
            .map_err(anyhow::Error::from)
        })
        .await
    }

    /// Send a test notification via configured Apprise destinations.
    ///
    /// Rate-limited to 10/min per actor using an in-memory counter that resets
    /// after 60s of inactivity per actor.
    pub async fn notifications_test_checked(
        &self,
        body: String,
        actor: impl Into<RequestActor>,
        config: &crate::config::NotificationsConfig,
    ) -> ServiceResult<String> {
        self.notifications_test_with_destinations(
            body,
            actor,
            config.apprise_url.clone(),
            config.apprise_urls.clone(),
        )
        .await
    }

    async fn notifications_test_with_destinations(
        &self,
        body: String,
        actor: impl Into<RequestActor>,
        apprise_url: String,
        apprise_urls: Vec<String>,
    ) -> ServiceResult<String> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        use std::time::Instant;

        const MAX_PER_MIN: u32 = 10;
        let actor = actor.into().display;

        // In-memory rate limiter: actor -> (count, window_start)
        static RATE_LIMITER: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
        let limiter = RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()));

        {
            let mut map = limiter.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            // Evict stale entries (window elapsed) to prevent unbounded map growth.
            map.retain(|_, entry| entry.1.elapsed().as_secs() < 60);
            let entry = map.entry(actor.clone()).or_insert((0, now));
            // Reset window if > 60s has elapsed (belt-and-suspenders after retain)
            if entry.1.elapsed().as_secs() >= 60 {
                *entry = (0, now);
            }
            entry.0 += 1;
            if entry.0 > MAX_PER_MIN {
                return Err(crate::app::ServiceError::InvalidInput(format!(
                    "Rate limit exceeded for actor '{actor}': max {MAX_PER_MIN} test notifications per minute"
                )));
            }
        }

        // Send test notification asynchronously
        let client = crate::notifications::apprise::AppriseClient::new(apprise_url);
        let escaped_body = crate::notifications::apprise::escape_for_notification(&body);
        let result = client
            .notify(
                &apprise_urls,
                "Test Notification",
                &escaped_body,
                crate::notifications::apprise::NotifyType::Info,
            )
            .await;

        match result {
            Ok(resp) => Ok(format!(
                "Test notification sent (status {})",
                resp.status_code
            )),
            Err(e) => Err(crate::app::ServiceError::Internal(anyhow::anyhow!(
                "Apprise delivery failed: {e}"
            ))),
        }
    }

    // -------------------------------------------------------------------------
    // RAG v1 methods
    // -------------------------------------------------------------------------

    pub async fn similar_incidents(
        &self,
        req: SimilarIncidentsRequest,
    ) -> ServiceResult<SimilarIncidentsResponse> {
        let from = parse_optional_timestamp(req.since.as_deref(), "since")?;
        let to = parse_optional_timestamp(req.until.as_deref(), "until")?;
        let severity_min = validate_optional_severity(req.severity_min)?;
        let result = self
            .run_db("similar_incidents", move |pool| {
                db::similar_incidents_clusters(
                    pool,
                    &db::SimilarIncidentsParams {
                        query: req.query,
                        host: req.host,
                        app: req.app,
                        severity_min,
                        since: from,
                        until: to,
                        window_minutes: req.window_minutes,
                        limit: req.limit,
                    },
                )
            })
            .await?;
        Ok(result.into())
    }

    /// Compare one first-pass source family — recurring error signatures —
    /// across adjacent windows.  This is ranking, not causal inference: the
    /// response names its evidence and its open questions explicitly.
    pub async fn compare_recurring_errors(
        &self,
        req: RecurringErrorComparisonRequest,
    ) -> ServiceResult<RecurringErrorComparisonResponse> {
        let focal_to_dt = match req.until.as_deref() {
            Some(value) => parse_required_timestamp(value, "until")?,
            None => chrono::Utc::now(),
        };
        let window_minutes = req.window_minutes.unwrap_or(60).clamp(5, 1_440);
        let focal_from_dt = match req.since.as_deref() {
            Some(value) => parse_required_timestamp(value, "since")?,
            None => focal_to_dt - chrono::Duration::minutes(i64::from(window_minutes)),
        };
        if focal_from_dt >= focal_to_dt {
            return Err(ServiceError::InvalidInput(
                "since must be earlier than until".to_string(),
            ));
        }
        let duration = focal_to_dt - focal_from_dt;
        let baseline_to_dt = focal_from_dt;
        let baseline_from_dt = baseline_to_dt - duration;
        let focal_from = rfc3339_z(focal_from_dt);
        let focal_to = rfc3339_z(focal_to_dt);
        let baseline_from = rfc3339_z(baseline_from_dt);
        let baseline_to = rfc3339_z(baseline_to_dt);
        let requested_limit = req.limit.unwrap_or(10).clamp(1, 50) as usize;
        let signature_hash = req.signature_hash.clone();
        let include_acknowledged = req.include_acknowledged.unwrap_or(false);

        let result = self
            .run_db("compare_recurring_errors", move |pool| {
                crate::db::error_signatures::compare_recurring_errors(
                    pool,
                    crate::db::error_signatures::RecurringErrorComparisonParams {
                        normalizer_version: crate::app::error_detection::NORMALIZER_VERSION,
                        focal_from: &focal_from,
                        focal_to: &focal_to,
                        baseline_from: &baseline_from,
                        baseline_to: &baseline_to,
                        signature_hash: signature_hash.as_deref(),
                        include_acknowledged,
                        limit: requested_limit,
                    },
                )
            })
            .await?;

        let crate::db::error_signatures::RecurringErrorComparisonResult {
            focal_from,
            focal_to,
            baseline_from,
            baseline_to,
            candidate_rows,
            candidate_cap,
            candidate_window_truncated,
            rows,
        } = result;

        let comparisons: Vec<RecurringErrorComparisonEntry> = rows
            .into_iter()
            .map(|row| {
                let source_key = format!("{}:{}", row.signature_hash, row.normalizer_version);
                // This revision is intentionally made only of canonical source
                // values and bounded aggregate counts, never display fields.
                let evidence_revision = format!(
                    "v1:{}:{}:{}:{}:{}:{}",
                    source_key,
                    row.last_seen_at,
                    row.total_count,
                    row.current_count,
                    row.baseline_count,
                    row.evidence_ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
                );
                let retention_or_projection_gap = row.focal_boundary_windows > 0
                    || row.baseline_boundary_windows > 0
                    || row.evidence_ids.is_empty();
                let graph_evidence_truncated = row.evidence_truncated;
                let evidence = RecurringErrorEvidenceBundle {
                    bundle_id: recurring_error_bundle_id(
                        &source_key,
                        &focal_from,
                        &focal_to,
                        &evidence_revision,
                    ),
                    schema_version: "cortex-recurring-error-bundle/v1".to_string(),
                    privacy_policy: RECURRING_ERROR_PRIVACY_POLICY_V1.to_string(),
                    source_key: source_key.clone(),
                    evidence_revision,
                    graph_evidence_ids: row.evidence_ids,
                    graph_evidence_truncated,
                    retention_or_projection_gap,
                    focal_boundary_windows: row.focal_boundary_windows,
                    baseline_boundary_windows: row.baseline_boundary_windows,
                };
                let mut open_questions = Vec::new();
                if evidence.retention_or_projection_gap {
                    open_questions.push(
                        "Window coverage or graph provenance is incomplete; compare only the retained, fully-contained aggregate windows.".to_string(),
                    );
                }
                if evidence.graph_evidence_ids.is_empty() {
                    open_questions.push(
                        "No graph provenance row is currently projected for this signature; rebuild or inspect the canonical signature source before drawing a relationship conclusion.".to_string(),
                    );
                }
                let entry = RecurringErrorComparisonEntry {
                    signature_hash: row.signature_hash,
                    normalizer_version: row.normalizer_version,
                    severity: row.severity,
                    focal_count: row.current_count,
                    baseline_count: row.baseline_count,
                    count_delta: row.current_count - row.baseline_count,
                    total_count: row.total_count,
                    first_seen_at: row.first_seen_at,
                    last_seen_at: row.last_seen_at,
                    safe_template: safe_recurring_error_text(&row.template),
                    safe_sample_message: safe_recurring_error_text(&row.sample_message),
                    safe_hostname: safe_recurring_error_text(&row.sample_hostname),
                    safe_app_name: row
                        .sample_app_name
                        .as_deref()
                        .map(safe_recurring_error_text),
                    evidence,
                    next_query: RecurringErrorNextQuery {
                        action: "graph".to_string(),
                        mode: "explain".to_string(),
                        entity_type: "error_signature".to_string(),
                        key: source_key,
                    },
                    explanation: "Ranked by retained focal-window count, then change from the adjacent baseline, severity, and canonical signature key. This evidence supports follow-up, not causation.".to_string(),
                    open_questions,
                };
                // Cache only the already-scrubbed, bounded public projection.
                // The bundle id includes its evidence revision and privacy
                // policy, so a source change or policy change never reuses a
                // stale representation. BTreeMap eviction is deterministic.
                let cache_key = entry.evidence.bundle_id.clone();
                let mut cache = self.recurring_error_bundle_cache.lock();
                if let Some(cached) = cache.get(&cache_key) {
                    return cached.clone();
                }
                cache.insert(cache_key, entry.clone());
                while cache.len() > RECURRING_ERROR_BUNDLE_CACHE_CAP {
                    let oldest_key = cache.keys().next().cloned();
                    if let Some(oldest_key) = oldest_key {
                        cache.remove(&oldest_key);
                    } else {
                        break;
                    }
                }
                entry
            })
            .collect();

        let results_truncated = candidate_window_truncated || candidate_rows > comparisons.len();
        Ok(RecurringErrorComparisonResponse {
            focal_from,
            focal_to,
            baseline_from,
            baseline_to,
            candidate_rows,
            candidate_cap,
            candidate_window_truncated,
            results_truncated,
            privacy_policy: RECURRING_ERROR_PRIVACY_POLICY_V1.to_string(),
            comparisons,
        })
    }

    pub async fn incident_context(
        &self,
        req: IncidentContextRequest,
    ) -> ServiceResult<IncidentContextResponse> {
        let to_dt = match req.until.as_deref() {
            Some(until) => parse_required_timestamp(until, "until")?,
            None => chrono::Utc::now(),
        };
        let from_dt = match req.since.as_deref() {
            Some(since) => parse_required_timestamp(since, "since")?,
            None => to_dt - chrono::Duration::hours(1),
        };
        if from_dt > to_dt {
            return Err(ServiceError::InvalidInput(
                "since must not be later than until".into(),
            ));
        }
        let from = rfc3339_z(from_dt);
        let to = rfc3339_z(to_dt);
        let result = self
            .run_db("incident_context", move |pool| {
                db::incident_context_summary(
                    pool,
                    &db::IncidentContextParams {
                        since: from,
                        until: to,
                        host: req.host,
                        app: req.app,
                        query: req.query,
                        severity_min: req.severity_min,
                        limit: req.limit,
                    },
                )
            })
            .await?;
        Ok(result.into())
    }
}

#[cfg(test)]
#[path = "rag_tests.rs"]
mod rag_tests;
