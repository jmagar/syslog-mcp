use std::fmt;

#[derive(Debug)]
pub enum ServiceError {
    InvalidInput(String),
    Busy(String),
    Internal(anyhow::Error),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) | Self::Busy(msg) => f.write_str(msg),
            Self::Internal(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(err) => err.source(),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for ServiceError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;
