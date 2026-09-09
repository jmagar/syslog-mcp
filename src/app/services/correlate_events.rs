use super::*;

impl CortexService {
    pub async fn correlate_events(
        &self,
        req: CorrelateEventsRequest,
    ) -> ServiceResult<CorrelateEventsResponse> {
        let window = req.window_minutes.unwrap_or(5).min(60);
        let severity_min = req.severity_min.unwrap_or_else(|| "warning".into());
        let severity_levels = severity_at_or_above(&severity_min)?;

        let (ref_dt, response_reference_time, matched_session) = match req.reference_time {
            Some(rt) => {
                let dt = parse_required_timestamp(&rt, "reference_time")?;
                (dt, rt, None)
            }
            None => {
                if let Some(query) = req.query.clone() {
                    let ai_params = db::SearchAiSessionsParams {
                        query: query.clone(),
                        ai_project: None,
                        ai_tool: None,
                        host: req.host.clone(),
                        app: None,
                        since: None,
                        until: None,
                        limit: Some(1),
                    };
                    let session_result = self
                        .run_db("correlate_session_lookup", move |pool| {
                            db::search_ai_sessions(pool, &ai_params)
                        })
                        .await?;
                    let top = session_result.sessions.into_iter().next().ok_or_else(|| {
                        ServiceError::InvalidInput(format!(
                            "no AI session found matching query {query:?} - provide reference_time explicitly"
                        ))
                    })?;
                    let dt = parse_required_timestamp(&top.first_seen, "reference_time")?;
                    (dt, rfc3339_z(dt), Some(SearchedSessionEntry::from(top)))
                } else {
                    let now = Utc::now();
                    (now, rfc3339_z(now), None)
                }
            }
        };

        let delta = TimeDelta::try_minutes(i64::from(window))
            .ok_or_else(|| ServiceError::InvalidInput("duration overflow".into()))?;
        let from = rfc3339_z(ref_dt - delta);
        let to = rfc3339_z(ref_dt + delta);
        let limit = req.limit.unwrap_or(500).min(999);
        let params = SearchParams {
            query: req.query,
            host: req.host,
            source: req.source,
            source_ip_prefix: None,
            source_ip_prefixes: None,
            severity: None,
            severity_in: Some(severity_levels),
            app: None,
            facility: None,
            exclude_facility: None,
            process_id: None,
            since: Some(from.clone()),
            until: Some(to.clone()),
            received_since: None,
            received_until: None,
            limit: Some(limit + 1),
            ai_tool: None,
            ai_project: None,
            ai_session_id: None,
            event_action: None,
            exclude_ai: false,
        };
        let mut rows = self
            .run_heavy_db("correlate_events", move |pool| {
                db::search_logs(pool, &params)
            })
            .await?;
        let truncated = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let logs: Vec<LogEntry> = rows.into_iter().map(Into::into).collect();
        let hosts = group_by_host(logs);
        let total_events = hosts.iter().map(|h| h.event_count).sum();

        Ok(CorrelateEventsResponse {
            reference_time: response_reference_time,
            window_minutes: window,
            window_from: from,
            window_to: to,
            severity_min,
            total_events,
            truncated,
            hosts_count: hosts.len(),
            hosts,
            matched_session,
        })
    }
}
