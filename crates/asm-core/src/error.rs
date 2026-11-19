//! Core error type. Every fallible core API returns `Result<T>`; the API layer maps
//! `code` to the HTTP status and wire error envelope from `asm_proto`.

use asm_proto::error::ErrorCode;

pub(crate) const REQUEST_UNAVAILABLE: &str = "request could not be completed; check with the manager operator";

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct CoreError {
    pub code: ErrorCode,
    pub message: String,
}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, m)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, m)
    }
    pub fn ambiguous(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Ambiguous, m)
    }
    pub fn exists(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Exists, m)
    }
    pub fn vault_unavailable(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::VaultUnavailable, m)
    }
    pub fn rate_limited(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::RateLimited, m)
    }
    /// Internal failure; details are manager-local, and the API reports a generic 500.
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, m)
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(format!("io: {e}"))
    }
}
impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::internal(format!("database: {e}"))
    }
}
impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::internal(format!("json: {e}"))
    }
}
impl From<asm_proto::ApiError> for CoreError {
    fn from(e: asm_proto::ApiError) -> Self {
        Self::new(e.code, e.message)
    }
}
impl From<CoreError> for asm_proto::ApiError {
    fn from(e: CoreError) -> Self {
        let message = match e.code {
            ErrorCode::VaultUnavailable | ErrorCode::Internal => REQUEST_UNAVAILABLE.to_owned(),
            _ => e.message,
        };
        Self::new(e.code, message)
    }
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;
