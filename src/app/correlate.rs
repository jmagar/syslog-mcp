use std::collections::BTreeMap;

use super::{CorrelatedHost, LogEntry, ServiceError, ServiceResult};
use crate::db;

pub fn severity_at_or_above(severity_min: &str) -> ServiceResult<Vec<String>> {
    let threshold = db::severity_to_num(severity_min).ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "Invalid severity_min '{}'. Must be one of: emerg, alert, crit, err, warning, notice, info, debug",
            severity_min
        ))
    })?;
    Ok(db::SEVERITY_LEVELS[..=threshold as usize]
        .iter()
        .map(|&s| s.to_string())
        .collect())
}

pub(super) fn group_by_host(logs: Vec<LogEntry>) -> Vec<CorrelatedHost> {
    let mut by_host: BTreeMap<String, Vec<LogEntry>> = BTreeMap::new();
    for log in logs {
        by_host.entry(log.hostname.clone()).or_default().push(log);
    }
    by_host
        .into_iter()
        .map(|(hostname, events)| CorrelatedHost {
            hostname,
            event_count: events.len(),
            events,
        })
        .collect()
}
