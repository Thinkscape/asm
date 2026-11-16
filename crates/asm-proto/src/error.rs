//! API error codes, the `{"error":{…}}` envelope and CLI exit codes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// CLI exit: success.
pub const EXIT_OK: i32 = 0;
/// CLI exit: connection or other failure (also `vault_unavailable`, `rate_limited`, `internal`, lost request).
pub const EXIT_FAILURE: i32 = 1;
/// CLI exit: invalid input.
pub const EXIT_INVALID: i32 = 2;
/// CLI exit: request denied or expired.
pub const EXIT_DENIED: i32 = 3;
/// CLI exit: still pending when `--wait` elapsed.
pub const EXIT_PENDING: i32 = 4;
/// CLI exit: `not_found`, `ambiguous`, `exists`.
pub const EXIT_NOT_FOUND: i32 = 5;
/// CLI exit: unpaired or token rejected.
pub const EXIT_UNAUTHORIZED: i32 = 6;

/// Machine-readable error code of an API error (snake_case on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Invalid,
    NotFound,
    Ambiguous,
    Exists,
    VaultUnavailable,
    RateLimited,
    /// Unexpected server failure (HTTP 500, CLI exit 1).
    Internal,
}

impl ErrorCode {
    /// HTTP status the manager answers with.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Unauthorized => 401,
            ErrorCode::Invalid => 400,
            ErrorCode::NotFound => 404,
            ErrorCode::Ambiguous | ErrorCode::Exists => 409,
            ErrorCode::VaultUnavailable => 503,
            ErrorCode::RateLimited => 429,
            ErrorCode::Internal => 500,
        }
    }

    /// Exit code of the `asm` CLI when the manager returns this error.
    pub fn cli_exit(self) -> i32 {
        match self {
            ErrorCode::Unauthorized => EXIT_UNAUTHORIZED,
            ErrorCode::Invalid => EXIT_INVALID,
            ErrorCode::NotFound | ErrorCode::Ambiguous | ErrorCode::Exists => EXIT_NOT_FOUND,
            ErrorCode::VaultUnavailable | ErrorCode::RateLimited | ErrorCode::Internal => {
                EXIT_FAILURE
            }
        }
    }

    /// Wire spelling (`not_found`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Invalid => "invalid",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Ambiguous => "ambiguous",
            ErrorCode::Exists => "exists",
            ErrorCode::VaultUnavailable => "vault_unavailable",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An API error: `{"code":…,"message":…}` (inside the `error` envelope on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    /// Build an error with any code.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into() }
    }
    /// `unauthorized`.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, message)
    }
    /// `invalid`.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, message)
    }
    /// `not_found`.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    /// `ambiguous`.
    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Ambiguous, message)
    }
    /// `exists`.
    pub fn exists(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Exists, message)
    }
    /// `vault_unavailable`.
    pub fn vault_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::VaultUnavailable, message)
    }
    /// `rate_limited`.
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::RateLimited, message)
    }
    /// `internal`.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// Wrap in the wire envelope `{"error":{…}}`.
    pub fn into_body(self) -> ErrorBody {
        ErrorBody { error: self }
    }

    /// Serialize as the wire envelope `{"error":{…}}`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&ErrorBodyRef { error: self }).expect("ApiError serializes")
    }

    /// Parse a wire envelope `{"error":{…}}`; `None` if the body is not one.
    pub fn from_json(body: &[u8]) -> Option<Self> {
        serde_json::from_slice::<ErrorBody>(body).ok().map(|b| b.error)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// Wire envelope of an error response: `{"error":{"code":…,"message":…}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ApiError,
}

#[derive(Serialize)]
struct ErrorBodyRef<'a> {
    error: &'a ApiError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let e = ApiError::not_found("no such secret");
        let j = e.to_json();
        assert_eq!(j, r#"{"error":{"code":"not_found","message":"no such secret"}}"#);
        assert_eq!(ApiError::from_json(j.as_bytes()), Some(e));
        assert_eq!(ErrorCode::VaultUnavailable.http_status(), 503);
        assert_eq!(ErrorCode::Exists.cli_exit(), 5);
        assert_eq!(ErrorCode::Unauthorized.cli_exit(), 6);
        assert_eq!(ErrorCode::Internal.http_status(), 500);
        assert_eq!(ErrorCode::Internal.cli_exit(), 1);
        assert_eq!(serde_json::to_string(&ErrorCode::Internal).unwrap(), r#""internal""#);
    }
}
