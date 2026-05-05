use chrono::{DateTime, Utc};

use super::{ServiceError, ServiceResult};

pub fn parse_optional_timestamp(
    raw: Option<&str>,
    field_name: &str,
) -> ServiceResult<Option<String>> {
    raw.map(|s| parse_required_timestamp(s, field_name).map(|dt| dt.to_rfc3339()))
        .transpose()
}

pub(super) fn parse_required_timestamp(
    raw: &str,
    field_name: &str,
) -> ServiceResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map_err(|e| {
            ServiceError::InvalidInput(format!(
                "Invalid {field_name} '{}': {e}. Expected ISO 8601 / RFC3339 format, e.g. '2025-01-15T00:00:00Z'",
                raw
            ))
        })
        .map(|dt| dt.with_timezone(&Utc))
}
