//! Vault providers (plan step 4). Contract types are fixed here; providers live in
//! submodules. Every provider call is synchronous and may block: call it from a plain
//! thread or `tokio::task::spawn_blocking`, never directly inside an async task.

use serde::{Deserialize, Serialize};

use crate::error::Result;

pub mod bitwarden;
pub mod creds;
pub mod env;
pub mod keychain;
pub mod names;
pub mod registry;

pub use asm_proto::wire::SecretKind;

/// One secret as listed by a provider. `key` is the provider's stable id (Bitwarden item id,
/// `.env` key, keychain composite key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub key: String,
    pub name: String,
    pub kind: SecretKind,
    pub fields: Vec<String>,
    pub uri_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "message", rename_all = "snake_case")]
pub enum VaultStatus {
    Ready,
    Locked,
    Error(String),
}

/// Where `add` puts a new secret. `collection_id` is only meaningful for Bitwarden
/// (`None` = personal vault).
#[derive(Debug, Clone, Default)]
pub struct AddTarget {
    pub collection_id: Option<String>,
}

pub trait VaultProvider: Send + Sync {
    fn status(&self) -> VaultStatus;
    fn list(&self) -> Result<Vec<SecretMeta>>;
    /// `(field, value)` pairs in field order.
    fn read(&self, key: &str) -> Result<Vec<(String, String)>>;
    fn update(&self, key: &str, field: &str, value: &str) -> Result<()>;
    fn add(&self, name: &str, value: &str, target: &AddTarget) -> Result<()>;
    /// Provider-specific extra line for the vault row (e.g. ".env: 3 lines skipped"). Default none.
    fn note(&self) -> Option<String> {
        None
    }
    /// Re-sync with the backend (Bitwarden `POST /sync`); no-op elsewhere.
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    /// Stop helper processes (Bitwarden `bw serve`). Called on remove and shutdown.
    fn shutdown(&self) {}
    /// Unlock with the master password (Bitwarden). The password is used once and never
    /// stored; a wrong one returns an error whose message is meant for the operator.
    fn unlock(&self, _master_password: &str) -> Result<()> {
        Err(crate::error::CoreError::invalid(
            "only Bitwarden vaults have a master password",
        ))
    }
    /// Collections exposed for `add` (Bitwarden: the configured collection ids with their
    /// names); empty elsewhere.
    fn collections(&self) -> Result<Vec<CollectionInfo>> {
        Ok(Vec::new())
    }
}

/// Persisted (non-secret) vault configuration, stored as JSON in the `vaults` table.
/// The Bitwarden client secret lives in the keychain via `creds`; the master password is
/// never stored (it only unlocks the running `bw serve`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultConfig {
    Bitwarden(BitwardenConfig),
    EnvFile { path: String },
    Keychain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitwardenConfig {
    pub server_url: String,
    pub email: String,
    pub client_id: String,
    /// Exposed collection ids.
    pub collections: Vec<String>,
    /// Expose items without an organization (personal vault). Default off.
    pub personal: bool,
    /// `None` = default (first existing of /opt/homebrew/bin/bw, /usr/local/bin/bw).
    pub bw_path: Option<String>,
}

/// Stored secret part of a Bitwarden config (keychain, `creds`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenSecrets {
    pub client_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionInfo {
    pub id: String,
    pub name: String,
    pub organization_id: Option<String>,
}
