//! Dynamic credential sources. Unlike vaults, generators issue one credential per
//! approved lease and never participate in the static-secret value cache.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use asm_proto::generators::{
    GCLOUD_TOKEN_NAME, GITHUB_TOKEN_NAME, GcloudAccessGrant, GcloudGrant,
    GenerationGrant, GithubGrant, GithubPermission, GithubRepository, validate_gcloud_project_id,
};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::store::GeneratorRecord;
use crate::vault::{VaultStatus, creds};

pub mod gcloud;
pub(crate) mod gcloud_cli;
pub mod github;

pub use gcloud::GcloudGenerator;
use gcloud_cli::GcloudRunner;
pub use github::GithubAppGenerator;

pub const OUTPUT_KEY: &str = "token";
pub const OUTPUT_FIELD: &str = "value";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GeneratorConfig {
    GithubApp(GithubAppConfig),
    Gcloud(GcloudConfig),
    GcloudConnection(GcloudConnectionConfig),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcloudConfig {
    pub sdk_path: String,
    pub account_subject: String,
    pub account_email: String,
    pub project_id: String,
    pub project_number: String,
    pub ceiling: GcloudGrant,
    /// Descriptive evidence for exactly the saved ceiling, ordered by scope URI.
    pub scope_catalog: Vec<GcloudScopeOption>,
}

/// A Google login only. Project and workload permissions belong to separately
/// provisioned profiles; none can be conferred by saving this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcloudConnectionConfig {
    pub sdk_path: String,
    pub account_subject: String,
    pub account_email: String,
}

impl GcloudConnectionConfig {
    pub fn validate(&self) -> Result<()> {
        validate_gcloud_login(&self.sdk_path, &self.account_subject, &self.account_email)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcloudService {
    pub name: String,
    pub title: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcloudScopeOption {
    pub uri: String,
    pub description: String,
    pub services: Vec<GcloudService>,
}

impl GcloudConfig {
    pub fn canonicalize(&mut self) -> Result<()> {
        self.ceiling.canonicalize()?;
        self.scope_catalog.sort_unstable_by(|a, b| a.uri.cmp(&b.uri));
        self.validate()
    }

    /// Validate saved shape without checking the SDK or contacting Google at startup.
    pub fn validate(&self) -> Result<()> {
        validate_gcloud_login(&self.sdk_path, &self.account_subject, &self.account_email)?;
        validate_gcloud_project_id(&self.project_id)?;
        gcloud::validate_unique_id(&self.project_number)
            .map_err(|_| CoreError::invalid("Google Cloud requires a numeric project number"))?;
        gcloud::validate_unique_id(&self.ceiling.service_account_unique_id)?;
        gcloud::validate_account_email(&self.ceiling.service_account_email)?;
        if self.ceiling.project_id.is_some() {
            return Err(CoreError::invalid("the Google Cloud scope ceiling cannot select an issuance project"));
        }
        self.ceiling.validate()?;
        if !self.scope_catalog.iter().map(|option| &option.uri).eq(&self.ceiling.scopes) {
            return Err(CoreError::invalid("each Google OAuth scope must have exactly one saved catalog option"));
        }
        if self.scope_catalog.iter().flat_map(|option| &option.services)
            .any(|service| !is_google_api_host(&service.name))
        {
            return Err(CoreError::invalid("Google OAuth scope catalog contains an invalid API host"));
        }
        Ok(())
    }
}

fn validate_gcloud_login(sdk_path: &str, subject: &str, email: &str) -> Result<()> {
    let path = Path::new(sdk_path);
    if !path.is_absolute()
        || path.file_name().is_none_or(|name| name != "gcloud")
        || sdk_path.chars().any(char::is_control)
    {
        return Err(CoreError::invalid("choose the absolute path to gcloud on the manager Mac"));
    }
    if subject.is_empty()
        || subject.chars().any(|c| c.is_whitespace() || c.is_control())
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
        || email.split_once('@').is_none_or(|(user, domain)| {
            user.is_empty() || domain.is_empty() || domain.contains('@')
        })
    {
        return Err(CoreError::invalid("Google Cloud requires a verified Google account identity"));
    }
    Ok(())
}

fn is_google_api_host(name: &str) -> bool {
    (name == "googleapis.com" || name.ends_with(".googleapis.com"))
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63
                && !label.starts_with('-') && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl GeneratorConfig {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::GithubApp(config) => config.validate(),
            Self::Gcloud(config) => config.validate(),
            Self::GcloudConnection(config) => config.validate(),
        }
    }

    pub fn canonicalize(&mut self) -> Result<()> {
        match self {
            Self::GithubApp(config) => config.canonicalize(),
            Self::Gcloud(config) => config.canonicalize(),
            Self::GcloudConnection(config) => config.validate(),
        }
    }

    pub fn ceilings(&self) -> impl Iterator<Item = GenerationGrant> + '_ {
        let (github, google) = match self {
            Self::GithubApp(config) => (config.installations.as_slice(), None),
            Self::Gcloud(config) => (&[][..], Some(GenerationGrant::Gcloud(config.ceiling.clone()))),
            Self::GcloudConnection(_) => (&[][..], Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection))),
        };
        github.iter().cloned().map(GenerationGrant::GithubApp).chain(google)
    }

    /// Check a canonical grant without copying either provider's ceiling.
    pub fn accepts_grant(&self, grant: &GenerationGrant) -> Result<bool> {
        match (self, grant) {
            (Self::GithubApp(config), GenerationGrant::GithubApp(grant)) => match config.ceiling(grant.installation_id) {
                Some(ceiling) => Ok(grant.is_subset_of(ceiling)?),
                None => Ok(false),
            },
            (Self::Gcloud(config), GenerationGrant::Gcloud(grant)) => Ok(grant.is_subset_of(&config.ceiling)?),
            // This is only a shape/provider check. The manager must also verify
            // the exact durable profile against the generator, subject and grant.
            (Self::GcloudConnection(_), GenerationGrant::GcloudAccess(grant @ GcloudAccessGrant::Issued { .. })) => {
                grant.validate()?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn output_name(&self) -> &'static str {
        match self {
            Self::GithubApp(_) => GITHUB_TOKEN_NAME,
            Self::Gcloud(_) | Self::GcloudConnection(_) => GCLOUD_TOKEN_NAME,
        }
    }

    pub fn provider_label(&self) -> &'static str {
        match self {
            Self::GithubApp(_) => "GitHub App",
            Self::Gcloud(_) | Self::GcloudConnection(_) => "Google Cloud",
        }
    }

    pub fn credential_kind(&self) -> &'static str {
        match self {
            Self::GithubApp(_) => creds::GITHUB_PRIVATE_KEY,
            Self::Gcloud(_) | Self::GcloudConnection(_) => creds::GCLOUD_ADC,
        }
    }

    /// Display labels do not change issued authority. A managed connection's
    /// verified operator email is also an IAM principal, not just a label.
    pub fn same_authority(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GithubApp(left), Self::GithubApp(right)) => {
                left.client_id == right.client_id && left.installations == right.installations
            }
            (Self::Gcloud(left), Self::Gcloud(right)) => {
                left.sdk_path == right.sdk_path
                    && left.account_subject == right.account_subject
                    && left.project_id == right.project_id
                    && left.project_number == right.project_number
                    && left.ceiling == right.ceiling
            }
            (Self::GcloudConnection(left), Self::GcloudConnection(right)) => {
                left.sdk_path == right.sdk_path && left.account_subject == right.account_subject
                    && left.account_email == right.account_email
            }
            _ => false,
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

pub enum GeneratorClient {
    GithubApp(GithubAppGenerator),
    Gcloud(GcloudGenerator),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcome {
    Revoked,
    Unsupported,
}

impl GeneratorClient {
    pub(crate) fn new(config: &GeneratorConfig, material: &str, runner: &GcloudRunner) -> Result<Self> {
        match config {
            GeneratorConfig::GithubApp(config) => Ok(Self::GithubApp(GithubAppGenerator::new(config, material)?)),
            GeneratorConfig::Gcloud(config) => Ok(Self::Gcloud(GcloudGenerator::new(config, material, runner.clone())?)),
            GeneratorConfig::GcloudConnection(config) => Ok(Self::Gcloud(GcloudGenerator::new_connection(config, material, runner.clone())?)),
        }
    }

    /// Verify the adapter was built for the recorded provider configuration.
    pub fn matches_config(&self, config: &GeneratorConfig) -> bool {
        match (self, config) {
            (Self::GithubApp(client), GeneratorConfig::GithubApp(config)) => client.matches_config(config),
            (Self::Gcloud(client), GeneratorConfig::Gcloud(config)) => client.matches_legacy(config),
            (Self::Gcloud(client), GeneratorConfig::GcloudConnection(config)) => client.matches_connection(config),
            _ => false,
        }
    }

    pub(crate) fn issue(&self, grant: &GenerationGrant) -> Result<GeneratedCredential> {
        match (self, grant) {
            (Self::GithubApp(client), GenerationGrant::GithubApp(grant)) => client.issue(grant),
            (Self::Gcloud(client), GenerationGrant::Gcloud(grant)) => client.issue(grant),
            (Self::Gcloud(client), GenerationGrant::GcloudAccess(grant)) => client.issue_access(grant),
            _ => Err(CoreError::invalid("the grant belongs to a different generator provider")),
        }
    }

    pub fn revoke(&self, token: &str) -> Result<RevocationOutcome> {
        match self {
            Self::GithubApp(client) => client.revoke(token).map(|()| RevocationOutcome::Revoked),
            Self::Gcloud(_) => Ok(RevocationOutcome::Unsupported),
        }
    }

    pub fn revoke_with_timeout(&self, token: &str, timeout: Duration) -> Result<RevocationOutcome> {
        match self {
            Self::GithubApp(client) => client.revoke_with_timeout(token, timeout)
                .map(|()| RevocationOutcome::Revoked),
            Self::Gcloud(_) => Ok(RevocationOutcome::Unsupported),
        }
    }
}

#[derive(Clone)]
pub struct GeneratorEntry {
    pub record: GeneratorRecord,
    pub generator: Option<Arc<GeneratorClient>>,
    pub unavailable_reason: Option<String>,
}

impl GeneratorEntry {
    pub fn status(&self) -> VaultStatus {
        match &self.generator {
            Some(_) => VaultStatus::Ready,
            None => VaultStatus::Error(self.unavailable_message()),
        }
    }

    pub fn client(&self) -> Result<Arc<GeneratorClient>> {
        self.generator.clone().ok_or_else(|| CoreError::vault_unavailable(self.unavailable_message()))
    }

    fn unavailable_message(&self) -> String {
        self.unavailable_reason.clone().unwrap_or_else(|| match &self.record.config {
            GeneratorConfig::GithubApp(_) => "GitHub generator is unavailable; edit the generator".into(),
            GeneratorConfig::Gcloud(_) | GeneratorConfig::GcloudConnection(_) => {
                "Google Cloud generator is unavailable; sign in again".into()
            }
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

    /// Load local keychain material without starting the SDK or contacting a provider.
    pub(crate) fn load(&self, records: Vec<GeneratorRecord>, runner: &GcloudRunner) {
        self.load_with(records, runner, creds::get);
    }

    /// Injected lookup prevents tests from ever touching the login keychain.
    pub(crate) fn load_with(
        &self,
        records: Vec<GeneratorRecord>,
        runner: &GcloudRunner,
        mut stored: impl FnMut(&str, &str) -> Result<Option<String>>,
    ) {
        let entries = records.into_iter().map(|record| {
            let built = Self::build_generator_with(&record, runner, &mut stored);
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

    pub(crate) fn build_generator_with(
        record: &GeneratorRecord,
        runner: &GcloudRunner,
        stored: impl FnOnce(&str, &str) -> Result<Option<String>>,
    ) -> Result<Arc<GeneratorClient>> {
        validate_name(&record.name)?;
        if record.revision == 0 {
            return Err(CoreError::invalid("generator revision must be positive"));
        }
        record.config.validate()?;
        let (unreadable, missing) = match &record.config {
            GeneratorConfig::GithubApp(_) => (
                "GitHub private key could not be read from the keychain; edit the generator",
                "GitHub private key missing from the keychain; edit the generator",
            ),
            GeneratorConfig::Gcloud(_) | GeneratorConfig::GcloudConnection(_) => (
                "Google Cloud credentials could not be read from the keychain; sign in again",
                "Google Cloud credentials missing from the keychain; sign in again",
            ),
        };
        let material = stored(&record.id, record.config.credential_kind())
            .map_err(|_| CoreError::vault_unavailable(unreadable))?
            .ok_or_else(|| CoreError::vault_unavailable(missing))?;
        Ok(Arc::new(GeneratorClient::new(&record.config, &material, runner)?))
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

    const RUN_SCOPE: &str = "https://www.googleapis.com/auth/run.readonly";
    const STORAGE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
    const ADC: &str = r#"{"type":"authorized_user","client_id":"fixture-client","client_secret":"fixture-secret","refresh_token":"fixture-refresh"}"#;

    fn runner(dir: &tempfile::TempDir) -> GcloudRunner {
        GcloudRunner::new(dir.path().join("gcloud")).unwrap()
    }

    fn google_record() -> GeneratorRecord {
        let option = |uri: &str, host: &str| GcloudScopeOption {
            uri: uri.into(),
            description: "Read project resources".into(),
            services: vec![GcloudService { name: host.into(), title: "Fixture API".into(), enabled: true }],
        };
        GeneratorRecord {
            id: "generator-google".into(), name: "google".into(), revision: 1, position: 1,
            config: GeneratorConfig::Gcloud(GcloudConfig {
                sdk_path: "/nonexistent-sdk/bin/gcloud".into(),
                account_subject: "109876543210987654321".into(),
                account_email: "operator@example.com".into(),
                project_id: "test-project".into(),
                project_number: "123456789012".into(),
                ceiling: GcloudGrant {
                    service_account_unique_id: "123456789012345678901".into(),
                    service_account_email: "token-issuer@test-project.iam.gserviceaccount.com".into(),
                    scopes: vec![STORAGE_SCOPE.into(), RUN_SCOPE.into()],
                    project_id: None,
                },
                scope_catalog: vec![
                    option(STORAGE_SCOPE, "storage.googleapis.com"),
                    option(RUN_SCOPE, "run.googleapis.com"),
                ],
            }),
            require_exact_scope_match: false,
        }
    }

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
            require_exact_scope_match: false,
        }
    }

    #[test]
    fn unavailable_records_remain_visible_without_network_or_keychain() {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner(&dir);
        let registry = GeneratorRegistry::new();
        registry.load_with(vec![record(), google_record()], &runner, |id, kind| {
            match id {
                "generator-1" => assert_eq!(kind, creds::GITHUB_PRIVATE_KEY),
                "generator-google" => assert_eq!(kind, creds::GCLOUD_ADC),
                _ => panic!("unexpected credential lookup"),
            }
            Ok(None)
        });
        let entry = registry.get("generator-1").unwrap();
        assert_eq!(entry.record.name, "release-bot");
        assert!(matches!(entry.status(), VaultStatus::Error(_)));
        assert!(entry.client().is_err());
        assert_eq!(entry.record.config.output_name(), GITHUB_TOKEN_NAME);
        assert!(registry.remove("generator-1").is_some());
        let entry = registry.remove("generator-google").unwrap();
        assert!(entry.client().err().unwrap().message.contains("sign in again"));
        assert_eq!(entry.record.config.output_name(), GCLOUD_TOKEN_NAME);
        assert!(registry.entries().is_empty());
    }

    #[test]
    fn credential_lookup_errors_are_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner(&dir);
        for record in [record(), google_record()] {
            let error = GeneratorRegistry::build_generator_with(&record, &runner, |_, _| {
                Err(CoreError::internal("PRIVATE-KEYCHAIN-CONTENT"))
            }).err().unwrap();
            assert!(!error.message.contains("PRIVATE-KEYCHAIN-CONTENT"));
        }
        let error = GeneratorRegistry::build_generator_with(&google_record(), &runner, |_, _| {
            Ok(Some(r#"{"type":"external_account","client_secret":"PRIVATE-ADC-CONTENT"}"#.into()))
        }).err().unwrap();
        assert!(!error.message.contains("PRIVATE-ADC-CONTENT"));
        let error = GeneratorRegistry::build_generator_with(&record(), &runner, |_, _| {
            Ok(Some("PRIVATE-PEM-CONTENT".into()))
        }).err().unwrap();
        assert!(!error.message.contains("PRIVATE-PEM-CONTENT"));
    }

    #[test]
    fn credential_debug_is_redacted_and_config_contains_no_key() {
        let credential = GeneratedCredential { token: "private-token".into(), expires_at: 123 };
        assert!(!format!("{credential:?}").contains("private-token"));
        let serialized = serde_json::to_string(&record().config).unwrap();
        assert!(serialized.contains("\"type\":\"github_app\""));
        assert!(!serialized.contains("private_key"));
        assert_eq!(serde_json::from_str::<GeneratorConfig>(&serialized).unwrap(), record().config);
        let config = google_record().config;
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("\"type\":\"gcloud\""));
        assert!(!serialized.contains("client_secret"));
        assert!(!serialized.contains("refresh_token"));
        assert_eq!(serde_json::from_str::<GeneratorConfig>(&serialized).unwrap(), config);
    }

    #[test]
    fn github_config_canonicalizes_installations_and_rejects_duplicates() {
        let GeneratorConfig::GithubApp(mut config) = record().config else { unreachable!() };
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
        let GeneratorConfig::GithubApp(mut config) = record().config else { unreachable!() };
        config.installations[0].repositories.clear();
        assert!(config.validate().is_err());
        assert!(config.canonicalize().is_err());
        for name in ["", "bad/name", "bad\nname"] {
            assert!(validate_name(name).is_err());
        }
    }

    #[test]
    fn google_config_canonicalizes_exact_catalog_coverage() {
        let GeneratorConfig::Gcloud(mut config) = google_record().config else { unreachable!() };
        config.ceiling.scopes.reverse();
        config.ceiling.scopes.push(RUN_SCOPE.into());
        config.scope_catalog.reverse();
        config.canonicalize().unwrap();
        let mut invalid_number = config.clone();
        invalid_number.project_number = "1".repeat(65);
        assert!(invalid_number.validate().unwrap_err().message.contains("project number"));
        let mut concrete_ceiling = config.clone();
        concrete_ceiling.ceiling.project_id = Some(config.project_id.clone());
        assert!(concrete_ceiling.validate().unwrap_err().message.contains("scope ceiling"));
        assert_eq!(config.ceiling.scopes, [STORAGE_SCOPE, RUN_SCOPE]);

        let mut missing = config.clone();
        missing.scope_catalog.pop();
        assert!(missing.validate().is_err());
        let mut extra = config.clone();
        extra.scope_catalog.push(extra.scope_catalog[0].clone());
        assert!(extra.canonicalize().is_err());
        config.scope_catalog[0].services[0].name = "*.googleapis.com".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn google_authority_excludes_catalog_labels() {
        let original = google_record().config;
        let mut relabeled = original.clone();
        let GeneratorConfig::Gcloud(config) = &mut relabeled else { unreachable!() };
        config.account_email = "operator-new@example.com".into();
        config.ceiling.service_account_email = "token-issuer-new@test-project.iam.gserviceaccount.com".into();
        config.scope_catalog[0].description = "New scope description".into();
        config.scope_catalog[0].services[0].title = "Updated service title".into();
        config.scope_catalog[0].services[0].enabled = false;
        let mut approved = config.ceiling.clone();
        approved.scopes = vec![RUN_SCOPE.into()];
        assert!(original.same_authority(&relabeled));
        let mut different_default = original.clone();
        let GeneratorConfig::Gcloud(config) = &mut different_default else { unreachable!() };
        config.project_id = "another-project".into();
        assert!(!original.same_authority(&different_default));
        let approved = GenerationGrant::Gcloud(approved);
        assert!(original.accepts_grant(&approved).unwrap());
        let github = record().config.ceilings().next().unwrap();
        assert!(!original.accepts_grant(&github).unwrap());
        let GeneratorConfig::Gcloud(config) = &mut relabeled else { unreachable!() };
        config.ceiling.service_account_unique_id = "999999999999999999999".into();
        assert!(!original.same_authority(&relabeled));
        assert!(!relabeled.accepts_grant(&approved).unwrap());
        assert!(!original.same_authority(&record().config));
    }

    #[test]
    fn google_registry_loads_offline_and_dispatches_without_issuing_wrong_provider_grants() {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner(&dir);
        let registry = GeneratorRegistry::new();
        let stored = |id: &str, kind: &str| {
            assert_eq!((id, kind), ("generator-google", creds::GCLOUD_ADC));
            Ok(Some(ADC.into()))
        };
        registry.load_with(vec![google_record()], &runner, stored);
        let entry = registry.get("generator-google").unwrap();
        assert_eq!(entry.status(), VaultStatus::Ready); // The SDK path does not exist.
        let client = entry.client().unwrap();
        assert!(client.matches_config(&entry.record.config));
        assert!(!client.matches_config(&record().config));
        let error = client.issue(&record().config.ceilings().next().unwrap()).unwrap_err();
        assert!(error.message.contains("different generator provider"));
        assert_eq!(client.revoke("fixture-child").unwrap(), RevocationOutcome::Unsupported);
        assert_eq!(client.revoke_with_timeout("fixture-child", Duration::ZERO).unwrap(), RevocationOutcome::Unsupported);
    }

    #[test]
    fn google_connection_persists_only_identity_and_loads_without_running_sdk() {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner(&dir);
        let registry = GeneratorRegistry::new();
        let config: GeneratorConfig = serde_json::from_value(serde_json::json!({
            "type": "gcloud_connection",
            "sdk_path": "/nonexistent-sdk/bin/gcloud",
            "account_subject": "90001",
            "account_email": "operator@example.com"
        })).unwrap();
        assert_eq!(serde_json::to_value(&config).unwrap(), serde_json::json!({
            "type": "gcloud_connection",
            "sdk_path": "/nonexistent-sdk/bin/gcloud",
            "account_subject": "90001",
            "account_email": "operator@example.com"
        }));
        let marker = GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection);
        assert_eq!(config.ceilings().collect::<Vec<_>>(), [marker.clone()]);
        assert!(!config.accepts_grant(&marker).unwrap());
        registry.load_with(vec![GeneratorRecord {
            config, ..google_record()
        }], &runner, |id, kind| {
            assert_eq!((id, kind), ("generator-google", creds::GCLOUD_ADC));
            Ok(Some(ADC.into()))
        });
        let entry = registry.get("generator-google").unwrap();
        let client = entry.client().unwrap();
        assert!(client.matches_config(&entry.record.config));
        assert!(!client.matches_config(&google_record().config));
        assert!(client.issue(&marker).is_err());
    }
}
