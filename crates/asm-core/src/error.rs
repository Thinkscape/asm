//! Core error type. Every fallible core API returns `Result<T>`; the API layer maps
//! `code` to the HTTP status and wire error envelope from `asm_proto`.

use asm_proto::error::ErrorCode;

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
    /// Internal failure; reported to API clients as `vault_unavailable`-free generic 500-ish.
    /// Uses `Invalid` only if nothing better fits; prefer a specific constructor.
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
        Self::new(e.code, e.message)
    }
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;
