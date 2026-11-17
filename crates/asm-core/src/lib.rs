//! Manager core (macOS only).
uniffi::setup_scaffolding!();

pub mod error;
pub mod ffi;
pub mod generator;
pub mod manager;
pub mod paths;
pub mod proxy;
pub mod settings;
pub mod store;
pub mod tls;
pub mod vault;

pub use ffi::{Decision, Manager, ManagerError, ManagerObserver};
pub use manager::StartOptions;
