//! Manager core (macOS only).
uniffi::setup_scaffolding!();

pub(crate) mod broker;
pub mod error;
pub mod ffi;
pub mod generator;
pub mod manager;
pub mod paths;
pub(crate) mod process;
pub mod proxy;
pub mod settings;
pub(crate) mod ssh;
pub mod store;
pub mod tls;
pub mod totp;
pub mod vault;

pub use ffi::{Decision, Manager, ManagerError, ManagerObserver};
pub use manager::StartOptions;
