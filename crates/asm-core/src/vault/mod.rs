//! Vault providers (plan step 4). Contract types are fixed here; providers live in
//! submodules. Every provider call is synchronous and may block: call it from a plain
//! thread or `tokio::task::spawn_blocking`, never directly inside an async task.

use std::collections::BTreeMap;

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
    /// Bitwarden: ids of the exposed collections that hold the item (empty for a
    /// personal item and outside Bitwarden).
    pub collections: Vec<String>,
}

/// Login picker metadata. Only the local manager receives usernames; they are not
/// ordinary catalog fields. A missing or empty username means there is no label.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginMeta {
    pub meta: SecretMeta,
    pub username: Option<String>,
}

impl SecretMeta {
    pub(crate) fn is_password_login(&self) -> bool {
        self.kind == SecretKind::Login && !self.name.is_empty()
            && self.fields.iter().any(|f| f == "password")
    }
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
    /// Exposed password logins, in one provider enumeration. Labels must come
    /// from listing attributes, never from per-item value reads.
    fn list_logins(&self) -> Result<Vec<LoginMeta>> {
        Ok(self.list()?.into_iter().filter(SecretMeta::is_password_login)
            .map(|meta| LoginMeta { meta, username: None }).collect())
    }
    /// `(field, value)` pairs in field order.
    fn read(&self, key: &str) -> Result<Vec<(String, String)>>;
    /// Read a fresh code for an already selected login. Providers with native
    /// authenticators override this to avoid materializing unrelated fields.
    fn read_totp(&self, key: &str) -> Result<zeroize::Zeroizing<String>> {
        use zeroize::{Zeroize, Zeroizing};
        let mut code = None;
        for (field, mut value) in self.read(key)? {
            if field == "totp" && code.is_none() && !value.is_empty() {
                code = Some(Zeroizing::new(value));
            } else {
                value.zeroize();
            }
        }
        code.ok_or_else(|| crate::error::CoreError::not_found("this login has no one-time code"))
    }
    fn update(&self, key: &str, field: &str, value: &str) -> Result<()>;
    fn add(&self, name: &str, value: &str, target: &AddTarget) -> Result<()>;
    /// Rename an exposed item. Only Bitwarden, whose item ids stay put; elsewhere the name
    /// is the provider key that leases and requests refer to.
    fn rename(&self, _key: &str, _new_name: &str) -> Result<()> {
        Err(crate::error::CoreError::invalid("only Bitwarden items can be renamed here"))
    }
    /// Where items named exactly `name` sit that this vault holds but does not expose
    /// (Bitwarden: "collection Secrets", "personal vault"); for the operator only.
    fn hidden_items_named(&self, _name: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    /// Provider-specific extra line for the vault row (e.g. ".env: 3 lines skipped"). Default none.
    fn note(&self) -> Option<String> {
        None
    }
    /// Re-sync with the backend (Bitwarden `POST /sync`); no-op elsewhere.
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    /// Stop helper processes without revoking resumable provider authority.
    fn shutdown(&self) {}
    /// Explicitly retire the provider and discard any resumable authority.
    fn discard(&self) -> Result<()> {
        self.shutdown();
        Ok(())
    }
    /// Current Bitwarden unlock generation, or None when no session is usable.
    /// Must be a local state read: callers may hold manager locks.
    fn bitwarden_session_revision(&self) -> Option<u64> {
        None
    }
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
    /// Every collection the account can see, exposed or not (Bitwarden, needs `Ready`);
    /// empty elsewhere.
    fn all_collections(&self) -> Result<Vec<CollectionInfo>> {
        Ok(Vec::new())
    }
    /// Apply a changed configuration to the running provider without restarting it.
    /// Returns `false` when the change needs a new provider (the default). Bitwarden
    /// applies exposure changes (collections, personal flag, cached names) in place, so
    /// an unlocked vault stays unlocked.
    fn reconfigure(&self, _config: &VaultConfig) -> bool {
        false
    }
}

/// Persisted (non-secret) vault configuration, stored as JSON in the `vaults` table.
/// The Bitwarden client secret lives in the keychain via `creds`; the master password is
/// never stored. Only a verified Bitwarden session key may be retained for restart.
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
    /// Names of the exposed collections (id → name), cached at the last save or connect so
    /// a locked vault can still show them.
    #[serde(default)]
    pub collection_names: BTreeMap<String, String>,
    /// Agents see which exposed collections hold an item (`asm list --json`), and an
    /// approved add reports the collection chosen. Default off.
    #[serde(default)]
    pub share_collection_names: bool,
}

impl BitwardenConfig {
    /// Same account and `bw` binary: only exposure (collections, personal flag, cached
    /// names) may differ, which a running provider can take over in place.
    pub fn same_connection(&self, other: &BitwardenConfig) -> bool {
        self.server_url == other.server_url
            && self.email == other.email
            && self.client_id == other.client_id
            && self.bw_path == other.bw_path
    }
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
