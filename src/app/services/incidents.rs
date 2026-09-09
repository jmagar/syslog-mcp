use super::*;

fn service_app_filter(service: &str) -> String {
    service
        .strip_suffix(".service")
        .unwrap_or(service)
        .to_string()
}

fn incident_event_from_log(log: db::LogEntry) -> IncidentEvent {
    let source = if log.ai_tool.is_some()
        || log.facility.as_deref() == Some("transcript")
        || log.source_ip.starts_with("transcript://")
    {
        "transcript"
    } else if log.source_ip.starts_with("docker://") || log.source_ip.starts_with("docker-event://")
    {
        "docker"
    } else {
        "syslog"
    };
    IncidentEvent {
        timestamp: log.timestamp,
        source: source.to_string(),
        host: Some(log.hostname),
        severity: Some(log.severity),
        app: log.app_name,
        message: log.message,
        log_id: Some(log.id),
    }
}

fn incident_event_from_journal(entry: ServiceJournalEntry) -> Option<IncidentEvent> {
    Some(IncidentEvent {
        timestamp: entry.timestamp?,
        source: "service-log".to_string(),
        host: entry.unit,
        severity: entry.priority,
        app: entry.syslog_identifier,
        message: entry.message.unwrap_or_default(),
        log_id: None,
    })
}

fn incident_sort_key(timestamp: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp_micros())
        .unwrap_or(i64::MAX)
}

impl CortexService {
    pub async fn incident(&self, req: IncidentRequest) -> ServiceResult<IncidentResponse> {
        if req.host.is_some() && req.service.is_some() {
            return Err(ServiceError::InvalidInput(
                "host and service cannot be combined: journal entries are always local \
                 and cannot be filtered by remote host"
                    .into(),
            ));
        }
        let around_dt = match req.around.as_deref() {
            Some(around) => parse_required_timestamp(around, "around")?,
            None => chrono::Utc::now(),
        };
        let around = rfc3339_z(around_dt);
        let window = req.minutes.unwrap_or(5).clamp(1, 120);
        let delta = TimeDelta::try_minutes(i64::from(window))
            .ok_or_else(|| ServiceError::InvalidInput("duration overflow".into()))?;
        let from = rfc3339_z(around_dt - delta);
        let to = rfc3339_z(around_dt + delta);
        let limit = req.limit.unwrap_or(500).clamp(1, 2_000);
        let app_name = req.service.as_deref().map(service_app_filter);
        let params = SearchParams {
            query: None,
            host: req.host.clone(),
            source: None,
            source_ip_prefix: None,
            source_ip_prefixes: None,
            severity: None,
            severity_in: None,
            app: app_name,
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
            .run_db("incident.search", move |pool| {
                db::search_logs(pool, &params)
            })
            .await?;
        let mut truncated = rows.len() > limit as usize;
        rows.truncate(limit as usize);

        let mut events: Vec<IncidentEvent> =
            rows.into_iter().map(incident_event_from_log).collect();
        let mut warnings = Vec::new();

        if let Some(service) = req.service {
            match self
                .service_logs(ServiceLogsRequest {
                    service,
                    since: Some(from.clone()),
                    until: Some(to.clone()),
                    tail: Some(limit.saturating_add(1)),
                })
                .await
            {
                Ok(report) => {
                    if report.dropped_lines > 0 {
                        warnings.push(format!(
                            "service_logs: dropped {} malformed journal line(s)",
                            report.dropped_lines
                        ));
                    }
                    let mut dropped_timestamps: usize = 0;
                    for entry in report.entries {
                        match incident_event_from_journal(entry) {
                            Some(event) => events.push(event),
                            None => dropped_timestamps = dropped_timestamps.saturating_add(1),
                        }
                    }
                    if dropped_timestamps > 0 {
                        warnings.push(format!(
                            "service_logs: dropped {dropped_timestamps} entries with unparseable timestamps"
                        ));
                    }
                }
                Err(error) => warnings.push(format!("service_logs: {error}")),
            }
        }

        events.sort_by_key(|event| incident_sort_key(&event.timestamp));
        if events.len() > limit as usize {
            truncated = true;
            events.truncate(limit as usize);
        }

        Ok(IncidentResponse {
            around,
            window_minutes: window,
            window_from: from,
            window_to: to,
            event_count: events.len(),
            truncated,
            warnings,
            events,
        })
    }
}
