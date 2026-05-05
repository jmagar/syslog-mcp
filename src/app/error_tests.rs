use std::error::Error;

use anyhow::anyhow;

use super::*;

#[test]
fn service_error_display_uses_user_facing_message() {
    assert_eq!(
        ServiceError::InvalidInput("bad timestamp".into()).to_string(),
        "bad timestamp"
    );
    assert_eq!(
        ServiceError::Busy("database worker limit reached".into()).to_string(),
        "database worker limit reached"
    );
}

#[test]
fn anyhow_errors_convert_to_internal_service_errors() {
    let err: ServiceError = anyhow!("database failed").into();

    assert!(matches!(err, ServiceError::Internal(_)));
    assert_eq!(err.to_string(), "database failed");
    assert!(Error::source(&err).is_none());
}
