//! The set of configured vaults and their live providers.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use super::bitwarden::BitwardenVault;
use super::env::EnvFileVault;
use super::keychain::KeychainVault;
use super::names::VaultListing;
use super::{
    AddTarget, BitwardenSecrets, SecretMeta, VaultConfig, VaultProvider, VaultStatus, creds,
};
use crate::error::{CoreError, Result};
use crate::paths::DataDirs;

#[derive(Clone)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub config: VaultConfig,
    pub provider: Arc<dyn VaultProvider>,
}

/// A vault that cannot be built (e.g. its credentials are missing from the keychain):
/// listed with an error status so the vault row shows why.
struct UnavailableVault(String);

impl VaultProvider for UnavailableVault {
    fn status(&self) -> VaultStatus {
        VaultStatus::Error(self.0.clone())
    }
    fn list(&self) -> Result<Vec<SecretMeta>> {
        Err(CoreError::vault_unavailable(self.0.clone()))
    }
    fn read(&self, _key: &str) -> Result<Vec<(String, String)>> {
        Err(CoreError::vault_unavailable(self.0.clone()))
    }
    fn update(&self, _key: &str, _field: &str, _value: &str) -> Result<()> {
        Err(CoreError::vault_unavailable(self.0.clone()))
    }
    fn add(&self, _name: &str, _value: &str, _target: &AddTarget) -> Result<()> {
        Err(CoreError::vault_unavailable(self.0.clone()))
    }
}

#[derive(Default)]
pub struct Registry {
    entries: RwLock<Vec<VaultEntry>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a provider from config; Bitwarden reads its secrets from `creds`. A Bitwarden
    /// vault that fails to start is still returned, with status `Error(<message>)`; its
    /// `sync()` retries. May block while `bw` logs in and unlocks.
    pub fn build_provider(
        dirs: &DataDirs,
        id: &str,
        config: &VaultConfig,
    ) -> Result<Arc<dyn VaultProvider>> {
        Ok(match config {
            VaultConfig::EnvFile { path } => Arc::new(EnvFileVault::new(PathBuf::from(path))),
            VaultConfig::Keychain => Arc::new(KeychainVault::new()),
            VaultConfig::Bitwarden(cfg) => {
                let client_secret = creds::get(id, "client_secret")?;
                let master_password = creds::get(id, "master_password")?;
                match (client_secret, master_password) {
                    (Some(client_secret), Some(master_password)) => Arc::new(BitwardenVault::start_or_error(
                        dirs,
                        id,
                        cfg.clone(),
                        BitwardenSecrets { client_secret, master_password },
                    )),
                    _ => Arc::new(UnavailableVault(
                        "client secret or master password missing from the keychain; edit the vault".into(),
                    )),
                }
            }
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<VaultEntry>> {
        self.entries.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<VaultEntry>> {
        self.entries.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Insert, or replace the entry with the same id (shutting down the old provider).
    pub fn insert(&self, e: VaultEntry) {
        let new_provider = e.provider.clone();
        let old = {
            let mut entries = self.write();
            match entries.iter_mut().find(|x| x.id == e.id) {
                Some(slot) => Some(std::mem::replace(slot, e)),
                None => {
                    entries.push(e);
                    None
                }
            }
        };
        // Re-inserting the same provider (e.g. a rename) must not stop it.
        if let Some(old) = old
            && !Arc::ptr_eq(&old.provider, &new_provider)
        {
            old.provider.shutdown();
        }
    }

    /// Remove an entry and shut its provider down.
    pub fn remove(&self, id: &str) -> Option<VaultEntry> {
        let removed = {
            let mut entries = self.write();
            let i = entries.iter().position(|x| x.id == id)?;
            entries.remove(i)
        };
        removed.provider.shutdown();
        Some(removed)
    }

    pub fn get(&self, id: &str) -> Option<VaultEntry> {
        self.read().iter().find(|x| x.id == id).cloned()
    }

    pub fn all(&self) -> Vec<VaultEntry> {
        self.read().clone()
    }

    /// List every vault whose status is Ready; errors per vault go to `warnings` ("<vault>: <msg>").
    pub fn listings(&self) -> (Vec<VaultListing>, Vec<String>) {
        let mut listings = Vec::new();
        let mut warnings = Vec::new();
        for e in self.all() {
            match e.provider.status() {
                VaultStatus::Ready => match e.provider.list() {
                    Ok(secrets) => listings.push(VaultListing {
                        vault_id: e.id,
                        vault_name: e.name,
                        secrets,
                    }),
                    Err(err) => warnings.push(format!("{}: {}", e.name, err.message)),
                },
                VaultStatus::Locked => warnings.push(format!("{}: vault is locked", e.name)),
                VaultStatus::Error(m) => warnings.push(format!("{}: {m}", e.name)),
            }
        }
        (listings, warnings)
    }

    pub fn shutdown_all(&self) {
        for e in self.all() {
            e.provider.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_entry(dir: &std::path::Path, id: &str, name: &str, body: &str) -> VaultEntry {
        let path = dir.join(format!("{id}.env"));
        std::fs::write(&path, body).unwrap();
        let config = VaultConfig::EnvFile {
            path: path.to_string_lossy().into_owned(),
        };
        let dirs = DataDirs::create(&dir.join("data"), Some(&dir.join("tmp"))).unwrap();
        let provider = Registry::build_provider(&dirs, id, &config).unwrap();
        VaultEntry {
            id: id.into(),
            name: name.into(),
            config,
            provider,
        }
    }

    #[test]
    fn listings_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let r = Registry::new();
        r.insert(env_entry(dir.path(), "a", "work", "SOME_APP_TOKEN=1\n"));
        r.insert(env_entry(
            dir.path(),
            "b",
            "home",
            "SOME_APP_TOKEN=2\nOTHER=3\n",
        ));
        let mut broken = env_entry(dir.path(), "c", "gone", "X=1\n");
        std::fs::remove_file(dir.path().join("c.env")).unwrap();
        broken.name = "gone".into();
        r.insert(broken);

        let (ls, warnings) = r.listings();
        assert_eq!(ls.len(), 2);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("gone: "));
        let names = super::super::names::compute_names(&ls);
        let d: Vec<&str> = names.iter().map(|n| n.display.as_str()).collect();
        assert_eq!(
            d,
            ["work/SOME_APP_TOKEN", "home/SOME_APP_TOKEN", "home/OTHER"]
        );

        // Replace "b" with a renamed vault.
        r.insert(env_entry(dir.path(), "b", "personal", "ONLY=1\n"));
        assert_eq!(r.all().len(), 3);
        assert_eq!(r.get("b").unwrap().name, "personal");
        assert!(r.remove("c").is_some());
        assert!(r.remove("c").is_none());
        let (ls, warnings) = r.listings();
        assert!(warnings.is_empty());
        let d: Vec<String> = super::super::names::compute_names(&ls)
            .into_iter()
            .map(|n| n.display)
            .collect();
        assert_eq!(d, ["SOME_APP_TOKEN", "ONLY"]);
        r.shutdown_all();
    }
}
