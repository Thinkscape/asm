//! Wire types and shared rules for Agents Secrets Manager, used by both the
//! manager (`asm-core`) and the agent CLI (`asm-cli`). Pure Rust, portable.

pub mod crypto;
pub mod error;
pub mod names;
pub mod pairing;
pub mod rules;
pub mod time;
pub mod wire;

pub use error::{ApiError, ErrorBody, ErrorCode};

/// Version of this build (shared by manager and CLI).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
