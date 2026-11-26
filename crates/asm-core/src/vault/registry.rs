//! The set of configured vaults and their live providers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use super::bitwarden::{BitwardenVault, forget_session};
use super::env::EnvFileVault;
use super::keychain::KeychainVault;
use super::names::VaultListing;
use super::{
    AddTarget, BitwardenSecrets, SecretMeta, VaultConfig, VaultProvider, VaultStatus, creds,
};
use crate::error::{CoreError, Result};
use crate::manager::resume::ResumeStore;
use crate::paths::DataDirs;

#[derive(Clone)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub config: VaultConfig,
    pub provider: Arc<dyn VaultProvider>,
}

pub(crate) struct BitwardenSession {
    pub provider: Arc<dyn VaultProvider>,
    pub revision: Option<u64>,
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
    fn unlock(&self, _master_password: &str) -> Result<()> {
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

    pub(crate) fn build_provider_resumable(
        dirs: &DataDirs,
        id: &str,
        config: &VaultConfig,
        resume: Arc<ResumeStore>,
    ) -> Result<Arc<dyn VaultProvider>> {
        Self::build_provider_with(dirs, id, config, Some(resume), creds::get)
    }

    pub fn build_provider(
        dirs: &DataDirs,
        id: &str,
        config: &VaultConfig,
    ) -> Result<Arc<dyn VaultProvider>> {
        Self::build_provider_with(dirs, id, config, None, creds::get)
    }

    /// `build_provider` with the credential lookup `(vault_id, kind)` injected.
    fn build_provider_with(
        dirs: &DataDirs,
        id: &str,
        config: &VaultConfig,
        resume: Option<Arc<ResumeStore>>,
        stored: impl FnOnce(&str, &str) -> Result<Option<String>>,
    ) -> Result<Arc<dyn VaultProvider>> {
        Ok(match config {
            VaultConfig::EnvFile { path } => Arc::new(EnvFileVault::new(PathBuf::from(path))),
            VaultConfig::Keychain => Arc::new(KeychainVault::new()),
            VaultConfig::Bitwarden(cfg) => match stored(id, creds::CLIENT_SECRET)? {
                Some(client_secret) => Arc::new(BitwardenVault::start_with_resume(
                    dirs,
                    id,
                    cfg.clone(),
                    BitwardenSecrets { client_secret },
                    resume,
                )),
                None => {
                    if let Some(resume) = &resume {
                        forget_session(resume, id)?;
                    }
                    Arc::new(UnavailableVault(
                        "client secret missing from the keychain; edit the vault".into(),
                    ))
                }
            },
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

    /// Remove an entry, explicitly retiring its provider.
    pub fn remove(&self, id: &str) -> Result<Option<VaultEntry>> {
        let removed = {
            let mut entries = self.write();
            let Some(i) = entries.iter().position(|x| x.id == id) else {
                return Ok(None);
            };
            entries.remove(i)
        };
        removed.provider.discard()?;
        Ok(Some(removed))
    }

    pub fn get(&self, id: &str) -> Option<VaultEntry> {
        self.read().iter().find(|x| x.id == id).cloned()
    }

    pub fn all(&self) -> Vec<VaultEntry> {
        self.read().clone()
    }

    pub(crate) fn bitwarden_sessions(&self) -> HashMap<String, BitwardenSession> {
        self.read()
            .iter()
            .filter(|entry| matches!(entry.config, VaultConfig::Bitwarden(_)))
            .map(|entry| {
                (
                    entry.id.clone(),
                    BitwardenSession {
                        provider: entry.provider.clone(),
                        revision: entry.provider.bitwarden_session_revision(),
                    },
                )
            })
            .collect()
    }

    /// List discoverable secret names, and the ready vaults whose listing failed (their
    /// names are unknown, not absent). Provider diagnostics stay in the manager.
    pub(crate) fn listings(&self) -> (Vec<VaultListing>, Vec<String>) {
        let (mut listings, mut unlisted) = (Vec::new(), Vec::new());
        for e in self.all() {
            if e.provider.status() != VaultStatus::Ready {
                continue;
            }
            let Ok(secrets) = e.provider.list() else {
                unlisted.push(e.name);
                continue;
            };
            // Unknown collection names are left out, never replaced by their ids.
            let shared_collection_names = match &e.config {
                VaultConfig::Bitwarden(b) if b.share_collection_names => e.provider.collections()
                    .map(|cs| cs.into_iter().map(|c| (c.id, c.name)).collect())
                    .unwrap_or_default(),
                _ => HashMap::new(),
            };
            listings.push(VaultListing { vault_id: e.id, vault_name: e.name, secrets, shared_collection_names });
        }
        (listings, unlisted)
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

        let (ls, unlisted) = r.listings();
        assert!(unlisted.is_empty(), "a vault that is not ready is not unlisted: {unlisted:?}");
        assert_eq!(ls.len(), 2);
        assert!(matches!(r.get("c").unwrap().provider.status(), VaultStatus::Error(_)));
        let names = super::super::names::compute_names(&ls);
        let d: Vec<&str> = names.iter().map(|n| n.display.as_str()).collect();
        assert_eq!(
            d,
            ["work/SOME_APP_TOKEN", "home/SOME_APP_TOKEN", "OTHER"]
        );

        // Replace "b" with a renamed vault.
        r.insert(env_entry(dir.path(), "b", "personal", "ONLY=1\n"));
        assert_eq!(r.all().len(), 3);
        assert_eq!(r.get("b").unwrap().name, "personal");
        assert!(r.remove("c").unwrap().is_some());
        assert!(r.remove("c").unwrap().is_none());
        let (ls, _) = r.listings();
        let d: Vec<String> = super::super::names::compute_names(&ls)
            .into_iter()
            .map(|n| n.display)
            .collect();
        assert_eq!(d, ["SOME_APP_TOKEN", "ONLY"]);
        r.shutdown_all();
    }

    /// No master password is ever looked up or stored: a Bitwarden vault built at start is
    /// Locked (serve up) or Error (serve cannot start), never Ready.
    #[test]
    fn bitwarden_without_master_password_is_never_ready() {
        use super::super::bitwarden::fake_bw;
        let tmp = fake_bw::tempdir();
        let dirs = DataDirs::create(&tmp.path().join("d"), Some(&tmp.path().join("t"))).unwrap();
        let stored = |_: &str, kind: &str| -> Result<Option<String>> {
            assert_eq!(
                kind,
                creds::CLIENT_SECRET,
                "only the client secret is stored"
            );
            Ok(Some("cs".into()))
        };

        let cfg = VaultConfig::Bitwarden(fake_bw::config(&fake_bw::install(tmp.path())));
        let p = Registry::build_provider_with(&dirs, "bw1", &cfg, None, stored).unwrap();
        assert_eq!(p.status(), VaultStatus::Locked);
        p.sync().unwrap();
        assert_eq!(p.status(), VaultStatus::Locked);
        p.shutdown();

        let cfg = VaultConfig::Bitwarden(fake_bw::config("/nonexistent/bw"));
        let p = Registry::build_provider_with(&dirs, "bw2", &cfg, None, stored).unwrap();
        assert!(matches!(p.status(), VaultStatus::Error(_)));

        let p = Registry::build_provider_with(&dirs, "bw3", &cfg, None, |_, _| Ok(None)).unwrap();
        assert!(matches!(p.status(), VaultStatus::Error(_)));
        assert_eq!(
            p.unlock("x").unwrap_err().code,
            asm_proto::ErrorCode::VaultUnavailable
        );
    }
}
