//! Dynamic credential sources. Unlike vaults, generators issue one credential per
//! approved lease and never participate in the static-secret value cache.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use asm_proto::generators::{GenerationGrant, GithubGrant, GithubPermission, GithubRepository};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::store::GeneratorRecord;
use crate::vault::{SecretKind, SecretMeta, VaultStatus, creds};

pub mod github;

pub use github::GithubAppGenerator;

pub const OUTPUT_NAME: &str = asm_proto::generators::GITHUB_TOKEN_NAME;
pub const OUTPUT_ALIAS: &str = asm_proto::generators::GITHUB_TOKEN_ALIAS;
pub const OUTPUT_KEY: &str = "token";
pub const OUTPUT_FIELD: &str = "value";
pub const OUTPUT_HOST: &str = "https://api.github.com";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GeneratorConfig {
    GithubApp(GithubAppConfig),
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct GithubAppConfig {
    pub client_id: String,
    pub installations: Vec<GithubGrant>,
}

impl PartialEq for GithubAppConfig {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id && self.installations == other.installations
            && self.installations.iter().flat_map(|grant| &grant.repositories)
                .eq(other.installations.iter().flat_map(|grant| &grant.repositories))
    }
}

impl GithubAppConfig {
    pub(crate) fn validate_client_id(client_id: &str) -> Result<()> {
        if client_id.is_empty()
            || client_id.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(CoreError::invalid("GitHub client ID is required without whitespace"));
        }
        Ok(())
    }

    fn validate_installations(&self) -> Result<()> {
        if self.installations.is_empty() {
            return Err(CoreError::invalid("select at least one GitHub installation"));
        }
        if self.installations.windows(2).any(|pair| pair[0].installation_id >= pair[1].installation_id) {
            return Err(CoreError::invalid("GitHub installation IDs must be sorted and unique"));
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) -> Result<()> {
        Self::validate_client_id(&self.client_id)?;
        self.installations.sort_unstable_by_key(|grant| grant.installation_id);
        self.validate_installations()?;
        for grant in &mut self.installations {
            grant.canonicalize()?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        Self::validate_client_id(&self.client_id)?;
        self.validate_installations()?;
        for grant in &self.installations {
            grant.validate()?;
        }
        Ok(())
    }

    /// A canonical configuration has one ceiling per installation, sorted by ID.
    pub fn ceiling(&self, installation_id: u64) -> Option<&GithubGrant> {
        self.installations.binary_search_by_key(&installation_id, |grant| grant.installation_id)
            .ok().map(|index| &self.installations[index])
    }
}

impl GeneratorConfig {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::GithubApp(config) => config.validate(),
        }
    }

    pub fn canonicalize(&mut self) -> Result<()> {
        match self {
            Self::GithubApp(config) => config.canonicalize(),
        }
    }

    pub fn ceilings(&self) -> impl Iterator<Item = GenerationGrant> + '_ {
        let Self::GithubApp(config) = self;
        config.installations.iter().cloned().map(GenerationGrant::GithubApp)
    }

    /// Check the exact installation's ceiling without copying any grants.
    pub fn accepts_grant(&self, grant: &GenerationGrant) -> Result<bool> {
        let (Self::GithubApp(config), GenerationGrant::GithubApp(grant)) = (self, grant);
        match config.ceiling(grant.installation_id) {
            Some(ceiling) => Ok(grant.is_subset_of(ceiling)?),
            None => Ok(false),
        }
    }

    /// Repository display names do not change the authority of an issued grant.
    pub fn same_authority(&self, other: &Self) -> bool {
        let (Self::GithubApp(left), Self::GithubApp(right)) = (self, other);
        left.client_id == right.client_id && left.installations == right.installations
    }

    pub fn metadata(&self) -> SecretMeta {
        SecretMeta {
            key: OUTPUT_KEY.into(),
            name: OUTPUT_NAME.into(),
            kind: SecretKind::Single,
            fields: vec![OUTPUT_FIELD.into()],
            uri_hosts: vec![OUTPUT_HOST.into()],
        }
    }
}

/// Source names share the existing vault naming convention and qualification rules.
pub fn validate_name(name: &str) -> Result<()> {
    let count = name.chars().count();
    if count == 0 || count > 64 || name.contains('/') || name.chars().any(char::is_control) {
        return Err(CoreError::invalid("generator names are 1–64 characters without '/'"));
    }
    Ok(())
}

/// Never serialized. The lease cache owns this by Arc, not by cloning token bytes.
pub struct GeneratedCredential {
    pub token: String,
    pub expires_at: i64,
}

impl fmt::Debug for GeneratedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedCredential")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubInstallationAccount {
    pub installation_id: u64,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubInstallation {
    pub installation_id: u64,
    pub account_login: String,
    pub repositories: Vec<GithubRepository>,
    pub permissions: BTreeMap<String, GithubPermission>,
    /// A discovery-token revocation failure, including its provider expiry, never bytes.
    pub warning: Option<String>,
}

#[derive(Clone)]
pub struct GeneratorEntry {
    pub record: GeneratorRecord,
    pub generator: Option<Arc<GithubAppGenerator>>,
    pub unavailable_reason: Option<String>,
}

impl GeneratorEntry {
    pub fn status(&self) -> VaultStatus {
        match &self.generator {
            Some(_) => VaultStatus::Ready,
            None => VaultStatus::Error(self.unavailable_reason.clone().unwrap_or_else(|| {
                "GitHub generator is unavailable; edit the generator".into()
            })),
        }
    }

    pub fn client(&self) -> Result<Arc<GithubAppGenerator>> {
        self.generator.clone().ok_or_else(|| {
            CoreError::vault_unavailable(self.unavailable_reason.clone().unwrap_or_else(|| {
                "GitHub generator is unavailable; edit the generator".into()
            }))
        })
    }
}

#[derive(Default)]
pub struct GeneratorRegistry {
    entries: RwLock<Vec<GeneratorEntry>>,
}

impl GeneratorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load records and keys locally. No GitHub request is made, including on error.
    pub fn load(&self, records: Vec<GeneratorRecord>) {
        self.load_with(records, creds::get);
    }

    /// Injected lookup prevents tests from ever touching the login keychain.
    pub fn load_with(
        &self,
        records: Vec<GeneratorRecord>,
        mut stored: impl FnMut(&str, &str) -> Result<Option<String>>,
    ) {
        let entries = records.into_iter().map(|record| {
            let built = Self::build_generator_with(&record, &mut stored);
            match built {
                Ok(generator) => GeneratorEntry {
                    record,
                    generator: Some(generator),
                    unavailable_reason: None,
                },
                Err(error) => GeneratorEntry {
                    record,
                    generator: None,
                    unavailable_reason: Some(error.message),
                },
            }
        }).collect();
        *self.entries.write().unwrap_or_else(|p| p.into_inner()) = entries;
    }

    pub fn build_generator(record: &GeneratorRecord) -> Result<Arc<GithubAppGenerator>> {
        Self::build_generator_with(record, creds::get)
    }

    pub fn build_generator_with(
        record: &GeneratorRecord,
        stored: impl FnOnce(&str, &str) -> Result<Option<String>>,
    ) -> Result<Arc<GithubAppGenerator>> {
        validate_name(&record.name)?;
        if record.revision == 0 {
            return Err(CoreError::invalid("generator revision must be positive"));
        }
        record.config.validate()?;
        let pem = stored(&record.id, creds::GITHUB_PRIVATE_KEY)
            .map_err(|_| CoreError::vault_unavailable("GitHub private key could not be read from the keychain; edit the generator"))?
            .ok_or_else(|| CoreError::vault_unavailable("GitHub private key missing from the keychain; edit the generator"))?;
        match &record.config {
            GeneratorConfig::GithubApp(config) => {
                Ok(Arc::new(GithubAppGenerator::new(config, &pem)?))
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<GeneratorEntry> {
        self.with_entry(id, GeneratorEntry::clone)
    }

    /// Read an entry without copying its config. The callback runs under the
    /// registry's read lock and must not call into the registry or store.
    pub(crate) fn with_entry<T>(&self, id: &str, f: impl FnOnce(&GeneratorEntry) -> T) -> Option<T> {
        self.entries.read().unwrap_or_else(|p| p.into_inner())
            .iter().find(|entry| entry.record.id == id).map(f)
    }

    pub fn entries(&self) -> Vec<GeneratorEntry> {
        self.entries.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn insert(&self, entry: GeneratorEntry) {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        match entries.iter_mut().find(|old| old.record.id == entry.record.id) {
            Some(old) => *old = entry,
            None => entries.push(entry),
        }
    }

    pub fn remove(&self, id: &str) -> Option<GeneratorEntry> {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        let index = entries.iter().position(|entry| entry.record.id == id)?;
        Some(entries.remove(index))
    }

    /// Caller supplies a sanitized local status, never a credential-store response.
    pub fn mark_unavailable(&self, id: &str, reason: &str) {
        if let Some(entry) = self.entries.write().unwrap_or_else(|p| p.into_inner())
            .iter_mut().find(|entry| entry.record.id == id)
        {
            entry.generator = None;
            entry.unavailable_reason = Some(reason.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> GeneratorRecord {
        GeneratorRecord {
            id: "generator-1".into(), name: "release-bot".into(), revision: 1, position: 0,
            config: GeneratorConfig::GithubApp(GithubAppConfig {
                client_id: "Iv1.test".into(),
                installations: vec![GithubGrant {
                    installation_id: 7,
                    repositories: vec![GithubRepository { id: 42, full_name: "acme/web".into() }],
                    permissions: BTreeMap::from([("metadata".into(), GithubPermission::Read)]),
                }],
            }),
        }
    }

    #[test]
    fn unavailable_records_remain_visible_without_network_or_keychain() {
        let registry = GeneratorRegistry::new();
        registry.load_with(vec![record()], |id, kind| {
            assert_eq!((id, kind), ("generator-1", creds::GITHUB_PRIVATE_KEY));
            Ok(None)
        });
        let entry = registry.get("generator-1").unwrap();
        assert_eq!(entry.record.name, "release-bot");
        assert!(matches!(entry.status(), VaultStatus::Error(_)));
        assert!(entry.client().is_err());
        assert_eq!(entry.record.config.metadata().name, OUTPUT_NAME);
        assert!(registry.remove("generator-1").is_some());
        assert!(registry.entries().is_empty());
    }

    #[test]
    fn credential_lookup_errors_are_sanitized() {
        let error = GeneratorRegistry::build_generator_with(&record(), |_, _| {
            Err(CoreError::internal("PRIVATE-KEY-CONTENT"))
        }).err().unwrap();
        assert!(!error.message.contains("PRIVATE-KEY-CONTENT"));
    }

    #[test]
    fn credential_debug_is_redacted_and_config_contains_no_key() {
        let credential = GeneratedCredential { token: "private-token".into(), expires_at: 123 };
        assert!(!format!("{credential:?}").contains("private-token"));
        let serialized = serde_json::to_string(&record().config).unwrap();
        assert!(serialized.contains("\"type\":\"github_app\""));
        assert!(!serialized.contains("private_key"));
        assert_eq!(serde_json::from_str::<GeneratorConfig>(&serialized).unwrap(), record().config);
    }

    #[test]
    fn github_config_canonicalizes_installations_and_rejects_duplicates() {
        let GeneratorConfig::GithubApp(mut config) = record().config;
        let mut other = config.installations[0].clone();
        other.installation_id = 9;
        other.repositories[0].id = 43;
        config.installations.insert(0, other.clone());
        config.canonicalize().unwrap();
        assert_eq!(config.ceiling(9), Some(&other));
        assert_eq!(config.ceiling(7).unwrap().repositories[0].id, 42);
        assert!(config.ceiling(8).is_none());
        assert!(config.validate().is_ok());
        let provider = GeneratorConfig::GithubApp(config.clone());
        let mut crossed = other.clone();
        crossed.repositories[0].id = 42;
        assert!(!provider.accepts_grant(&GenerationGrant::GithubApp(crossed)).unwrap());
        assert!(provider.accepts_grant(&GenerationGrant::GithubApp(other.clone())).unwrap());

        config.installations.push(other);
        assert!(config.canonicalize().unwrap_err().message.contains("unique"));
        config.installations.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_git_hub_config_cannot_be_saved() {
        let GeneratorConfig::GithubApp(mut config) = record().config;
        config.installations[0].repositories.clear();
        assert!(config.validate().is_err());
        for id in ["", "a b", "a\nb"] {
            assert!(GithubAppConfig::validate_client_id(id).is_err());
        }
        for name in ["", "bad/name", "bad\nname"] {
            assert!(validate_name(name).is_err());
        }
    }
}
