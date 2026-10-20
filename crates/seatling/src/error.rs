use crate::types::StatusCode;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatlingError {
    pub status: StatusCode,
    pub message: String,
}

impl SeatlingError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl fmt::Display for SeatlingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.status, self.message)
    }
}

impl std::error::Error for SeatlingError {}

impl From<SeatlingError> for String {
    fn from(err: SeatlingError) -> Self {
        err.to_string()
    }
}
