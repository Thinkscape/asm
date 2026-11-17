//! CLI errors: a message for stderr and the process exit code (plan step 3/8).

use asm_proto::error::{
    ApiError, EXIT_DENIED, EXIT_FAILURE, EXIT_INVALID, EXIT_PENDING, EXIT_UNAUTHORIZED, ErrorCode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub exit: i32,
    /// Printed verbatim on stderr.
    pub message: String,
    /// The manager's error code when the error came from the API.
    pub code: Option<ErrorCode>,
    /// The manager could not be reached (network error, or a 5xx without an API error
    /// body); worth retrying while waiting on a request.
    pub transient: bool,
}

impl CliError {
    pub fn new(exit: i32, message: impl Into<String>) -> Self {
        CliError {
            exit,
            message: message.into(),
            code: None,
            transient: false,
        }
    }
    /// Exit 1: the manager could not be reached; retryable.
    pub fn unreachable(message: impl Into<String>) -> Self {
        CliError {
            transient: true,
            ..Self::failure(message)
        }
    }
    /// Exit 1: connection or other failure.
    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(EXIT_FAILURE, format!("error: {}", message.into()))
    }
    /// Exit 2: invalid input.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(EXIT_INVALID, format!("invalid: {}", message.into()))
    }
    /// Exit 6: unpaired or token rejected.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(
            EXIT_UNAUTHORIZED,
            format!("unauthorized: {}", message.into()),
        )
    }
    /// Exit 3: `denied: <reason>`.
    pub fn denied(reason: Option<&str>) -> Self {
        let reason = reason
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .unwrap_or("no reason given");
        Self::new(EXIT_DENIED, format!("denied: {reason}"))
    }
    /// Exit 3: the request expired or was cancelled.
    pub fn ended(message: impl Into<String>) -> Self {
        Self::new(EXIT_DENIED, message)
    }
    /// Exit 4: still pending when `--wait` elapsed.
    pub fn pending() -> Self {
        Self::new(
            EXIT_PENDING,
            "pending: run the same command again to keep waiting",
        )
    }
    /// A shared exec acquisition deadline elapsed between completed acquisitions.
    pub fn acquisition_elapsed() -> Self {
        Self::new(EXIT_PENDING, "credential acquisition deadline elapsed; rerun asm exec")
    }
    /// Exit 1: the manager no longer knows the request (restart).
    pub fn request_lost() -> Self {
        Self::new(EXIT_FAILURE, "request lost; run the command again")
    }
    /// Exit 1: the manager stayed unreachable until the wait ended; `last` is the last
    /// connection error (already prefixed `error: `), `next` what to do about it.
    pub fn lost_contact(last: &str, next: &str) -> Self {
        Self::new(EXIT_FAILURE, format!("{last}\n{next}"))
    }
}

/// `lost_contact` hint for `get`, `update` and `add` (re-running re-attaches).
pub const RERUN_TO_PICK_UP: &str =
    "the request may still be pending on the manager: run the same command again to pick it up";

impl From<ApiError> for CliError {
    fn from(e: ApiError) -> Self {
        CliError {
            code: Some(e.code),
            ..CliError::new(e.code.cli_exit(), format!("{}: {}", e.code, e.message))
        }
    }
}
