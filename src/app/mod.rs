mod correlate;
mod error;
mod models;
mod service;
mod time;

pub use correlate::severity_at_or_above;
pub use error::{ServiceError, ServiceResult};
pub use models::{
    CorrelateEventsRequest, CorrelateEventsResponse, CorrelatedHost, DbStats, ErrorSummaryEntry,
    GetErrorsRequest, GetErrorsResponse, HostEntry, ListHostsResponse, LogEntry, SearchLogsRequest,
    SearchLogsResponse, TailLogsRequest,
};
pub use service::SyslogService;
pub use time::parse_optional_timestamp;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
