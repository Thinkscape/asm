//! UniFFI surface used by the SwiftUI app. Every `Manager` method is synchronous and may
//! block (vault access, proxy reloads): call slow ones off the main thread.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use crate::error::CoreError;
use crate::manager::{Core, StartOptions};

/// Change notifications. Topics: `requests`, `leases`, `hosts`, `vaults`, `proxy`,
/// `generators`, `firewall`, `settings`, `activity`.
/// Called from manager threads; never while the manager holds a lock.
#[uniffi::export(with_foreign)]
pub trait ManagerObserver: Send + Sync {
    fn changed(&self, topic: String);
}

/// The one error type thrown to Swift. `code` is the wire error code (`invalid`,
/// `not_found`, `exists`, `vault_unavailable`, `internal`, …).
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum ManagerError {
    #[error("{message}")]
    Failed { code: String, message: String },
}

impl From<CoreError> for ManagerError {
    fn from(e: CoreError) -> Self {
        ManagerError::Failed {
            code: e.code.as_str().to_string(),
            message: e.message,
        }
    }
}

pub type FfiResult<T> = Result<T, ManagerError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SourceKind {
    Vault,
    Generator,
}

impl From<asm_proto::generators::SourceKind> for SourceKind {
    fn from(kind: asm_proto::generators::SourceKind) -> Self {
        match kind {
            asm_proto::generators::SourceKind::Vault => Self::Vault,
            asm_proto::generators::SourceKind::Generator => Self::Generator,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum GithubPermission {
    Read,
    Write,
    Admin,
}

impl From<asm_proto::generators::GithubPermission> for GithubPermission {
    fn from(level: asm_proto::generators::GithubPermission) -> Self {
        match level {
            asm_proto::generators::GithubPermission::Read => Self::Read,
            asm_proto::generators::GithubPermission::Write => Self::Write,
            asm_proto::generators::GithubPermission::Admin => Self::Admin,
        }
    }
}

impl From<GithubPermission> for asm_proto::generators::GithubPermission {
    fn from(level: GithubPermission) -> Self {
        match level {
            GithubPermission::Read => Self::Read,
            GithubPermission::Write => Self::Write,
            GithubPermission::Admin => Self::Admin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubPermissionEntry {
    pub name: String,
    pub level: GithubPermission,
}

fn permission_entries(
    permissions: std::collections::BTreeMap<String, asm_proto::generators::GithubPermission>,
) -> Vec<GithubPermissionEntry> {
    permissions.into_iter().map(|(name, level)| GithubPermissionEntry {
        name,
        level: level.into(),
    }).collect()
}

fn permission_map(
    entries: Vec<GithubPermissionEntry>,
) -> Result<std::collections::BTreeMap<String, asm_proto::generators::GithubPermission>, CoreError> {
    let mut permissions = std::collections::BTreeMap::new();
    for entry in entries {
        if permissions.insert(entry.name, entry.level.into()).is_some() {
            return Err(CoreError::invalid("duplicate GitHub permission"));
        }
    }
    Ok(permissions)
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubRepository {
    pub id: u64,
    pub full_name: String,
}

impl From<asm_proto::generators::GithubRepository> for GithubRepository {
    fn from(repository: asm_proto::generators::GithubRepository) -> Self {
        Self { id: repository.id, full_name: repository.full_name }
    }
}

impl From<GithubRepository> for asm_proto::generators::GithubRepository {
    fn from(repository: GithubRepository) -> Self {
        Self { id: repository.id, full_name: repository.full_name }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubScopeRequest {
    pub repositories: Option<Vec<String>>,
    pub permissions: Option<Vec<GithubPermissionEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GenerationRequest {
    GithubApp { scope: GithubScopeRequest },
}

impl From<asm_proto::generators::GenerationRequest> for GenerationRequest {
    fn from(request: asm_proto::generators::GenerationRequest) -> Self {
        match request {
            asm_proto::generators::GenerationRequest::GithubApp(scope) => Self::GithubApp {
                scope: GithubScopeRequest {
                    repositories: scope.repositories,
                    permissions: scope.permissions.map(permission_entries),
                },
            },
        }
    }
}

impl TryFrom<GenerationRequest> for asm_proto::generators::GenerationRequest {
    type Error = CoreError;

    fn try_from(request: GenerationRequest) -> Result<Self, Self::Error> {
        let mut request = match request {
            GenerationRequest::GithubApp { scope } => Self::GithubApp(
                asm_proto::generators::GithubScopeRequest {
                    repositories: scope.repositories,
                    permissions: scope.permissions.map(permission_map).transpose()?,
                },
            ),
        };
        request.canonicalize()?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubGrant {
    pub installation_id: u64,
    pub repositories: Vec<GithubRepository>,
    pub permissions: Vec<GithubPermissionEntry>,
}

impl From<asm_proto::generators::GithubGrant> for GithubGrant {
    fn from(grant: asm_proto::generators::GithubGrant) -> Self {
        Self {
            installation_id: grant.installation_id,
            repositories: grant.repositories.into_iter().map(Into::into).collect(),
            permissions: permission_entries(grant.permissions),
        }
    }
}

impl GithubGrant {
    // Discovery drafts can contain an installation ID with no repositories yet.
    fn into_protocol(self) -> Result<asm_proto::generators::GithubGrant, CoreError> {
        Ok(asm_proto::generators::GithubGrant {
            installation_id: self.installation_id,
            repositories: self.repositories.into_iter().map(Into::into).collect(),
            permissions: permission_map(self.permissions)?,
        })
    }
}

impl TryFrom<GithubGrant> for asm_proto::generators::GithubGrant {
    type Error = CoreError;

    fn try_from(grant: GithubGrant) -> Result<Self, Self::Error> {
        let mut grant = grant.into_protocol()?;
        grant.canonicalize()?;
        Ok(grant)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GenerationGrant {
    GithubApp { scope: GithubGrant },
}

impl From<asm_proto::generators::GenerationGrant> for GenerationGrant {
    fn from(grant: asm_proto::generators::GenerationGrant) -> Self {
        match grant {
            asm_proto::generators::GenerationGrant::GithubApp(scope) => Self::GithubApp { scope: scope.into() },
        }
    }
}

impl TryFrom<GenerationGrant> for asm_proto::generators::GenerationGrant {
    type Error = CoreError;

    fn try_from(grant: GenerationGrant) -> Result<Self, Self::Error> {
        match grant {
            GenerationGrant::GithubApp { scope } => Ok(Self::GithubApp(scope.try_into()?)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GenerationChoice {
    pub generator_id: String,
    pub name: String,
    pub revision: u64,
    pub ceiling: GenerationGrant,
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

impl From<asm_proto::generators::GenerationChoice> for GenerationChoice {
    fn from(choice: asm_proto::generators::GenerationChoice) -> Self {
        Self {
            generator_id: choice.generator_id, name: choice.name, revision: choice.revision,
            ceiling: choice.ceiling.into(), available: choice.available,
            unavailable_reason: choice.unavailable_reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GenerationSelection {
    pub generator_id: String,
    pub generator_revision: u64,
    pub grant: GenerationGrant,
}

impl From<asm_proto::generators::GenerationSelection> for GenerationSelection {
    fn from(selection: asm_proto::generators::GenerationSelection) -> Self {
        Self {
            generator_id: selection.generator_id, generator_revision: selection.generator_revision,
            grant: selection.grant.into(),
        }
    }
}

impl TryFrom<GenerationSelection> for asm_proto::generators::GenerationSelection {
    type Error = CoreError;

    fn try_from(selection: GenerationSelection) -> Result<Self, Self::Error> {
        let selection = Self {
            generator_id: selection.generator_id, generator_revision: selection.generator_revision,
            grant: selection.grant.try_into()?,
        };
        selection.validate()?;
        Ok(selection)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorApprovalChoice {
    pub choice: GenerationChoice,
    pub suggested_hosts: Vec<HostPatternCheck>,
    pub scope_issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubAppConfig {
    pub client_id: String,
    pub installations: Vec<GithubGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorConfig {
    GithubApp { config: GithubAppConfig },
}

impl From<crate::generator::GeneratorConfig> for GeneratorConfig {
    fn from(config: crate::generator::GeneratorConfig) -> Self {
        match config {
            crate::generator::GeneratorConfig::GithubApp(config) => Self::GithubApp {
                config: GithubAppConfig {
                    client_id: config.client_id,
                    installations: config.installations.into_iter().map(Into::into).collect(),
                },
            },
        }
    }
}

impl TryFrom<GeneratorConfig> for crate::generator::GeneratorConfig {
    type Error = CoreError;

    fn try_from(config: GeneratorConfig) -> Result<Self, Self::Error> {
        match config {
            GeneratorConfig::GithubApp { config } => {
                let mut ids = std::collections::BTreeSet::new();
                let installations = config.installations.into_iter().map(|grant| {
                    if !ids.insert(grant.installation_id) {
                        return Err(CoreError::invalid("duplicate GitHub installation ID"));
                    }
                    grant.into_protocol()
                }).collect::<Result<_, _>>()?;
                Ok(Self::GithubApp(crate::generator::GithubAppConfig {
                    client_id: config.client_id, installations,
                }))
            }
        }
    }
}

/// Only an operator's transient draft contains a root signing key.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorDraft {
    pub id: Option<String>,
    pub name: String,
    pub config: GeneratorConfig,
    pub private_key_pem: String,
}

impl std::fmt::Debug for GeneratorDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratorDraft")
            .field("id", &self.id).field("name", &self.name).field("config", &self.config)
            .field("private_key_pem", &"[REDACTED]").finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorInfo {
    pub id: String,
    pub name: String,
    pub config: GeneratorConfig,
    pub revision: u64,
    pub status: VaultStatus,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubInstallationAccount {
    pub installation_id: u64,
    pub account: String,
}

impl From<crate::generator::GithubInstallationAccount> for GithubInstallationAccount {
    fn from(account: crate::generator::GithubInstallationAccount) -> Self {
        Self { installation_id: account.installation_id, account: account.account }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GithubInstallation {
    pub installation_id: u64,
    pub account_login: String,
    pub repositories: Vec<GithubRepository>,
    pub permissions: Vec<GithubPermissionEntry>,
    pub warning: Option<String>,
}

impl From<crate::generator::GithubInstallation> for GithubInstallation {
    fn from(installation: crate::generator::GithubInstallation) -> Self {
        Self {
            installation_id: installation.installation_id, account_login: installation.account_login,
            repositories: installation.repositories.into_iter().map(Into::into).collect(),
            permissions: permission_entries(installation.permissions), warning: installation.warning,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LeaseMode {
    Sentinel,
    Raw,
}

impl From<LeaseMode> for asm_proto::wire::LeaseMode {
    fn from(m: LeaseMode) -> Self {
        match m {
            LeaseMode::Sentinel => Self::Sentinel,
            LeaseMode::Raw => Self::Raw,
        }
    }
}
impl From<asm_proto::wire::LeaseMode> for LeaseMode {
    fn from(m: asm_proto::wire::LeaseMode) -> Self {
        match m {
            asm_proto::wire::LeaseMode::Sentinel => Self::Sentinel,
            asm_proto::wire::LeaseMode::Raw => Self::Raw,
        }
    }
}

/// The operator's decision on a pending request.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Decision {
    /// `""` = no reason.
    Deny { reason: String },
    /// `name`: the host's friendly name; trimmed, `""` = the reported hostname, at most 64
    /// characters, no control or bidi characters (else `invalid`, request stays pending).
    /// Ignored when the request re-pairs a host (`repair.kind == "same_install"`, the name
    /// is kept) or replaces one (`same_machine` with `replace`, the old name carries over).
    /// `replace`: for `repair.kind == "same_machine"` only: revoke the host it looks like
    /// (and its leases) and give the new host its name; `false` = a separate host.
    ApprovePair { name: String, replace: bool },
    /// `duration_secs: None` = unlimited; `hosts` for sentinel leases (`["*"]` = any host).
    ApproveGet {
        mode: LeaseMode,
        duration_secs: Option<u64>,
        hosts: Vec<String>,
        generation: Option<GenerationSelection>,
    },
    /// `update`: `vault_id` must be the secret's vault. `add`: the chosen target vault and,
    /// for Bitwarden, collection (`None` = personal vault).
    ApproveWrite {
        vault_id: String,
        collection_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecretKind {
    Login,
    Single,
    Multi,
}

impl From<asm_proto::wire::SecretKind> for SecretKind {
    fn from(k: asm_proto::wire::SecretKind) -> Self {
        match k {
            asm_proto::wire::SecretKind::Login => Self::Login,
            asm_proto::wire::SecretKind::Single => Self::Single,
            asm_proto::wire::SecretKind::Multi => Self::Multi,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub kernel: String,
    pub arch: String,
    pub username: String,
    pub addresses: Vec<String>,
    pub asm_version: String,
    pub container: bool,
}

impl From<asm_proto::wire::HostInfo> for HostInfo {
    fn from(h: asm_proto::wire::HostInfo) -> Self {
        Self {
            hostname: h.hostname,
            os: h.os,
            os_version: h.os_version,
            kernel: h.kernel,
            arch: h.arch,
            username: h.username,
            addresses: h.addresses,
            asm_version: h.asm_version,
            container: h.container,
        }
    }
}

/// A normalised host pattern and whether it is broad (flagged in the popup).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostPatternCheck {
    pub normalized: String,
    pub broad: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CollectionInfo {
    pub id: String,
    pub name: String,
    pub organization_id: Option<String>,
}

impl From<crate::vault::CollectionInfo> for CollectionInfo {
    fn from(c: crate::vault::CollectionInfo) -> Self {
        Self {
            id: c.id,
            name: c.name,
            organization_id: c.organization_id,
        }
    }
}

/// One row of the edit sheet's collection picker (`Manager::vault_collections`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CollectionChoice {
    pub id: String,
    /// The collection's name; the cached name (or the id) while the vault is not ready.
    pub name: String,
    pub organization_id: Option<String>,
    /// Currently exposed by the vault.
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultKind {
    Bitwarden,
    EnvFile,
    Keychain,
}

/// A vault that can receive an `add`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AddTarget {
    pub vault_id: String,
    pub vault_name: String,
    pub kind: VaultKind,
    /// Bitwarden: exposed collections to pick from.
    pub collections: Vec<CollectionInfo>,
    /// Bitwarden: the personal vault may be chosen (`collection_id: None`).
    pub personal_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RequestDetail {
    Pair {
        host_info: HostInfo,
        observed_address: String,
        /// Verification code as shown by the CLI, e.g. `123 456`.
        code: String,
        /// The request looks like an existing host pairing again; `None` = a new machine.
        repair: Option<RepairInfo>,
    },
    Get {
        name: String,
        vault_id: Option<String>,
        vault_name: String,
        kind: SecretKind,
        fields: Vec<String>,
        reason: String,
        raw_requested: bool,
        requested_hosts: Vec<String>,
        /// Pre-filled host list (never `*` or broad patterns).
        initial_hosts: Vec<HostPatternCheck>,
        /// Offered but not pre-filled.
        suggested_hosts: Vec<HostPatternCheck>,
        default_duration_secs: Option<u64>,
        /// A generated target remains generated even if all candidates disappear.
        is_generated: bool,
        generator_choices: Vec<GeneratorApprovalChoice>,
        requested_generation: Option<GenerationRequest>,
        sentinel_required: bool,
        has_substitutable_fields: bool,
    },
    Update {
        name: String,
        vault_id: String,
        vault_name: String,
        field: String,
        old_value: String,
        new_value: String,
    },
    Add {
        name: String,
        value: String,
        targets: Vec<AddTarget>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RequestKind {
    Pair,
    Get,
    Update,
    Add,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingRequest {
    pub id: String,
    pub kind: RequestKind,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    /// `None` for pairing requests.
    pub host_id: Option<String>,
    /// The host's current friendly name; for pairing requests the reported hostname.
    pub host_label: String,
    /// Host info of the requesting host (for pairing: the info it sent).
    pub host_info: Option<HostInfo>,
    pub agent: String,
    /// Address the request came from as the manager saw it (pairing: the observed address).
    pub address: String,
    /// One-line summary for the menu (`kind`-specific).
    pub summary: String,
    /// Last failed approval attempt that left the request pending.
    pub error: Option<String>,
    pub detail: RequestDetail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RequestOutcome {
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecentRequest {
    pub id: String,
    pub kind: RequestKind,
    pub summary: String,
    /// The host's current friendly name (pairing requests: the name chosen, or the hostname).
    pub host_label: String,
    pub outcome: RequestOutcome,
    pub deny_reason: Option<String>,
    pub resolved_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Snapshot {
    /// Oldest first.
    pub pending: Vec<PendingRequest>,
    /// Last 10 resolved, newest first.
    pub recent: Vec<RecentRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultStatus {
    Ready,
    Locked,
    Error { message: String },
}

impl From<crate::vault::VaultStatus> for VaultStatus {
    fn from(s: crate::vault::VaultStatus) -> Self {
        match s {
            crate::vault::VaultStatus::Ready => Self::Ready,
            crate::vault::VaultStatus::Locked => Self::Locked,
            crate::vault::VaultStatus::Error(message) => Self::Error { message },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultConfig {
    Bitwarden {
        server_url: String,
        email: String,
        client_id: String,
        collection_ids: Vec<String>,
        expose_personal: bool,
        /// `None` = default `bw` path.
        bw_path: Option<String>,
    },
    EnvFile {
        path: String,
    },
    Keychain,
}

impl From<crate::vault::VaultConfig> for VaultConfig {
    fn from(c: crate::vault::VaultConfig) -> Self {
        match c {
            crate::vault::VaultConfig::Bitwarden(b) => Self::Bitwarden {
                server_url: b.server_url,
                email: b.email,
                client_id: b.client_id,
                collection_ids: b.collections,
                expose_personal: b.personal,
                bw_path: b.bw_path,
            },
            crate::vault::VaultConfig::EnvFile { path } => Self::EnvFile { path },
            crate::vault::VaultConfig::Keychain => Self::Keychain,
        }
    }
}

impl From<VaultConfig> for crate::vault::VaultConfig {
    fn from(c: VaultConfig) -> Self {
        match c {
            VaultConfig::Bitwarden {
                server_url,
                email,
                client_id,
                collection_ids,
                expose_personal,
                bw_path,
            } => Self::Bitwarden(crate::vault::BitwardenConfig {
                server_url,
                email,
                client_id,
                collections: collection_ids,
                personal: expose_personal,
                bw_path: bw_path.filter(|p| !p.trim().is_empty()),
                collection_names: Default::default(),
            }),
            VaultConfig::EnvFile { path } => Self::EnvFile { path },
            VaultConfig::Keychain => Self::Keychain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub kind: VaultKind,
    pub status: VaultStatus,
    /// `None` when the vault cannot be listed.
    pub secret_count: Option<u32>,
    /// Provider note, e.g. ".env: 3 lines skipped".
    pub note: Option<String>,
    pub config: VaultConfig,
}

/// Vault editor contents. `id: None` creates a vault. For Bitwarden, an empty
/// `client_secret` keeps the stored one (required for new vaults). `master_password` is
/// never stored: when non-empty, `save_vault` uses it once to unlock (a new vault that
/// cannot be unlocked is not kept); empty = leave the vault Locked. `bitwarden_connect`
/// requires it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultDraft {
    pub id: Option<String>,
    pub name: String,
    pub config: VaultConfig,
    pub client_secret: String,
    pub master_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgentSeen {
    pub agent: String,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostRecord {
    pub host_id: String,
    /// Friendly name (the reported hostname unless the operator chose another).
    pub name: String,
    pub info: HostInfo,
    pub observed_address: String,
    pub agents: Vec<AgentSeen>,
    pub paired_at: SystemTime,
    pub last_seen: Option<SystemTime>,
    pub active_leases: u32,
    /// Other active hosts claiming the same machine (a forgeable hint): likely duplicates.
    pub machine_hint_matches: u32,
}

/// The existing host a pairing request relates to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RepairInfo {
    pub host_id: String,
    /// The host's friendly name.
    pub host_name: String,
    pub paired_at: SystemTime,
    /// `"same_install"`: the CLI proved it holds the host's current token; approving gives
    /// the same host record a new token (name, leases and history kept).
    /// `"same_machine"`: only the machine-id hint matches (anyone can claim it); show
    /// "Looks like <host_name>" and a "Replace <host_name>" toggle (default on).
    pub kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PairingCodeStatus {
    Active,
    Expired,
    UsedUp,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingCodeInfo {
    pub id: String,
    pub label: String,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub uses: u32,
    pub max_uses: Option<u32>,
    pub status: PairingCodeStatus,
    /// Normalised CIDR ranges the pairing host's address must be in; `[]` = any address.
    pub allowed_networks: Vec<String>,
}

/// A newly generated pairing code; `code` is shown once and never stored.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedPairingCode {
    pub info: PairingCodeInfo,
    pub code: String,
    /// `asm pair <host>:<port> <code>`
    pub command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LeaseStatus {
    Active,
    Expired,
    Revoked,
}

impl From<asm_proto::wire::LeaseStatus> for LeaseStatus {
    fn from(s: asm_proto::wire::LeaseStatus) -> Self {
        match s {
            asm_proto::wire::LeaseStatus::Active => Self::Active,
            asm_proto::wire::LeaseStatus::Expired => Self::Expired,
            asm_proto::wire::LeaseStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub host_id: String,
    /// The host's friendly name.
    pub host_label: String,
    /// The host's reported hostname.
    pub hostname: String,
    pub vault_id: String,
    pub vault_name: String,
    pub name: String,
    pub mode: LeaseMode,
    /// `[]` for raw leases; `["*"]` = any host.
    pub hosts: Vec<String>,
    pub fields: Vec<String>,
    pub reason: String,
    pub agent: String,
    pub created_at: SystemTime,
    /// `None` = unlimited.
    pub expires_at: Option<SystemTime>,
    pub status: LeaseStatus,
    /// Active lease whose material or proxy publication is unavailable; local substitution fails closed.
    pub suspended: bool,
    /// A raw value has been delivered. Generated provider revocation is best effort.
    pub raw_delivered: bool,
    pub source_kind: SourceKind,
    pub generation: Option<GenerationSelection>,
    pub generator_name: Option<String>,
    pub credential_expires_at: Option<SystemTime>,
    pub credential_version: Option<u64>,
    pub suspension_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProxySettings {
    pub bind_address: String,
    pub port: u16,
    /// Hostnames/addresses agents use to reach the proxy, preferred first.
    pub hints: Vec<String>,
    pub http_port: u16,
    pub https_port: u16,
    pub management_port: u16,
    pub metrics_port: u16,
    pub max_request_body_bytes: u64,
    pub allow_plain_http: bool,
}

/// Proxy health as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ProxyState {
    Running,
    /// Just spawned and not healthy yet, or restarting after a failure for under 5 s.
    Starting,
    /// Not running for at least 5 s (crash loop, start failure, stopped); `reason` is the
    /// most relevant cause, e.g. `port 7416 is in use by python3 (pid 123)`.
    Down {
        reason: String,
        since: SystemTime,
    },
    /// Running, but `/healthz` has failed for more than 10 s.
    Unhealthy {
        since: SystemTime,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProxyStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub healthy: bool,
    pub state: ProxyState,
    /// Failed exits/starts since the proxy was last healthy.
    pub consecutive_failures: u32,
    pub last_reload: Option<SystemTime>,
    pub ca_path: String,
    pub ca_expiry: Option<SystemTime>,
    pub ca_pem: Option<String>,
    /// Cause of the last failure; cleared once the proxy is healthy.
    pub error: Option<String>,
    /// Sentinel fields currently substituted.
    pub active_entries: u32,
    pub suspended_leases: u32,
}

/// What the macOS Application Firewall does to incoming connections for one executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FirewallState {
    Allowed,
    Blocked,
    /// "Block all incoming connections" is on.
    BlockAll,
    FirewallOff,
    /// No rule yet (macOS asks the first time another machine connects), or the firewall
    /// could not be read.
    Unknown,
}

/// Whether other machines can reach one listener.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ListenerReach {
    /// Bound to a non-loopback address (`0.0.0.0`, `::`, an interface address): meant
    /// for other machines. `false` = one-machine setup, the firewall is not involved.
    pub intent_remote: bool,
    pub state: FirewallState,
    /// `intent_remote` and `state` is `Blocked` or `BlockAll`: warn.
    pub blocked: bool,
    pub bind_address: String,
    /// The executable the firewall rule names (for the fix command).
    pub executable: String,
}

/// Firewall reach of the proxy (iron-proxy) and the manager API (this app). Observer
/// topic `firewall`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallStatus {
    pub proxy: ListenerReach,
    pub api: ListenerReach,
    /// `None` until the first check has finished.
    pub checked_at: Option<SystemTime>,
    /// Informational.
    pub stealth_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneralSettings {
    pub api_bind_address: String,
    pub api_port: u16,
    /// `None` = unlimited.
    pub default_lease_secs: Option<u64>,
    pub pending_lifetime_secs: u64,
    /// Default `bw` binary (`None` = first of /opt/homebrew/bin/bw, /usr/local/bin/bw).
    pub bw_path: Option<String>,
    /// Read-only.
    pub version: String,
    /// Read-only: SHA-256 of the manager API certificate (hex).
    pub cert_sha256: String,
    /// Read-only: address the API listener is bound to now.
    pub listening_on: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DurationOption {
    pub label: String,
    /// `None` = unlimited.
    pub secs: Option<u64>,
}

/// Filter for [`Manager::list_activity`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActivityQuery {
    /// `"requests"`, `"leases"`, `"proxy"`, `"pairing"`, `"vaults"`; empty = all.
    pub categories: Vec<String>,
    /// Only rows of this host.
    pub host_id: Option<String>,
    /// Case-insensitive (ASCII) substring of the summary, secret or host label; "" = all.
    pub search: String,
    /// Rows older than this id (paging); `None` = newest.
    pub before_id: Option<i64>,
    /// Page size; 0 = 200, at most 1000.
    pub limit: u32,
}

/// One activity log row. Never holds secret values.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActivityEntry {
    pub id: i64,
    pub at: SystemTime,
    pub category: String,
    /// Per category, e.g. requests: `requested`, `approved`, `reused`, `denied`, `failed`,
    /// `expired`, `cancelled`; leases: `created`, `revoked`, `expired`, `suspended`,
    /// `resumed`; proxy: `substitution`, `rejected`, `started`, `restarted`, `crashed`
    /// (once per distinct cause per outage), `start_failed`, `reload_failed`, `down`,
    /// `unhealthy`, `recovered` (with the downtime), `orphan_killed`, `firewall_blocked`,
    /// `firewall_allowed` (macOS Firewall started or stopped blocking a listener meant for
    /// other machines; `detail.listener` is `proxy` or `api`); pairing: `requested`, `approved`, `denied`,
    /// `expired`, `paired_with_code`, `repaired`, `repaired_with_code`, `replaced`,
    /// `renamed`, `revoked`; vaults: `added`, `edited`,
    /// `removed`, `unlocked`, `unlock_failed`, `unavailable`, `available`.
    pub kind: String,
    pub host_id: Option<String>,
    /// The host's current friendly name; "" without a host.
    pub host_label: String,
    /// Secret display name (lease name, requested secret).
    pub secret: Option<String>,
    pub summary: String,
    /// JSON object text; `lease_id` is set when a lease is known.
    pub detail: Option<String>,
}

/// Lease duration choices for the popup, in display order.
#[uniffi::export]
pub fn lease_durations() -> Vec<DurationOption> {
    asm_proto::wire::LEASE_DURATIONS
        .iter()
        .map(|(label, secs)| DurationOption {
            label: (*label).to_string(),
            secs: *secs,
        })
        .collect()
}

/// Validate and normalise a host pattern with the same rule the manager applies.
#[uniffi::export]
pub fn check_host_pattern(pattern: String) -> FfiResult<HostPatternCheck> {
    let normalized = asm_proto::rules::normalize_host_pattern(&pattern).map_err(CoreError::from)?;
    let broad = asm_proto::rules::is_broad(&normalized);
    Ok(HostPatternCheck { normalized, broad })
}

/// The Mac's own names and addresses, as suggestions for proxy hostname hints.
#[uniffi::export]
pub fn hint_suggestions() -> Vec<String> {
    crate::manager::netinfo::local_names()
}

/// The networks this Mac is attached to (`192.168.1.0/24`, `100.64.0.0/10` for
/// Tailscale, `fd12:3456::/64`), as suggestions for pairing-code networks.
#[uniffi::export]
pub fn subnet_suggestions() -> Vec<String> {
    crate::manager::netinfo::local_subnets()
}

/// Validate and normalise one pairing-code network entry (`10.1.2.3/8` → `10.0.0.0/8`,
/// a bare address → `/32` or `/128`); `invalid` names the entry.
#[uniffi::export]
pub fn check_network(entry: String) -> FfiResult<String> {
    Ok(crate::manager::netinfo::check_network(&entry)?)
}

/// See [`enable_debug_overrides`].
static DEBUG_OVERRIDES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(cfg!(debug_assertions));

/// Honour debug overrides (`ASM_DEBUG_*` environment variables, e.g.
/// `ASM_DEBUG_FIREWALL_LISTAPPS`), as debug builds of the core always do. Debug builds of
/// the app call it before `Manager::start`; release builds never do.
#[uniffi::export]
pub fn enable_debug_overrides() {
    DEBUG_OVERRIDES.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn debug_overrides_enabled() -> bool {
    DEBUG_OVERRIDES.load(std::sync::atomic::Ordering::Relaxed)
}

/// The running manager.
#[derive(uniffi::Object)]
pub struct Manager {
    core: Arc<Core>,
}

impl Manager {
    /// Start with extra options (tests: values root, settings overrides). Not exported.
    pub fn start_with(
        data_dir: PathBuf,
        bin_dir: PathBuf,
        observer: Arc<dyn ManagerObserver>,
        options: StartOptions,
    ) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Self {
            core: Core::start(data_dir, bin_dir, observer, options)?,
        }))
    }

    /// Internal core, for tests.
    pub fn core(&self) -> &Arc<Core> {
        &self.core
    }
}

#[uniffi::export]
impl Manager {
    /// Open the data dir, load vaults, start the proxy and the HTTPS API.
    /// `bin_dir` holds the `iron-proxy` binary.
    #[uniffi::constructor]
    pub fn start(
        data_dir: String,
        bin_dir: String,
        observer: Arc<dyn ManagerObserver>,
    ) -> FfiResult<Arc<Self>> {
        Self::start_with(
            data_dir.into(),
            bin_dir.into(),
            observer,
            StartOptions::default(),
        )
    }

    pub fn snapshot(&self) -> Snapshot {
        self.core.snapshot()
    }

    pub fn resolve_request(&self, id: String, decision: Decision) -> FfiResult<()> {
        Ok(self.core.resolve_request(&id, decision)?)
    }

    pub fn list_vaults(&self) -> Vec<VaultInfo> {
        self.core.list_vaults()
    }

    pub fn save_vault(&self, draft: VaultDraft) -> FfiResult<VaultInfo> {
        Ok(self.core.save_vault(draft)?)
    }

    pub fn remove_vault(&self, id: String) -> FfiResult<()> {
        Ok(self.core.remove_vault(&id)?)
    }

    pub fn list_generators(&self) -> Vec<GeneratorInfo> {
        self.core.list_generators()
    }

    pub fn save_generator(&self, draft: GeneratorDraft) -> FfiResult<GeneratorInfo> {
        Ok(self.core.save_generator(draft)?)
    }

    pub fn remove_generator(&self, id: String) -> FfiResult<()> {
        Ok(self.core.remove_generator(&id)?)
    }

    pub fn github_connect(&self, draft: GeneratorDraft) -> FfiResult<GithubInstallation> {
        Ok(self.core.github_connect(draft)?)
    }

    pub fn github_list_installations(&self, draft: GeneratorDraft) -> FfiResult<Vec<GithubInstallationAccount>> {
        Ok(self.core.github_list_installations(draft)?)
    }

    /// "Connect" in the Bitwarden sheet: log in with the draft and list collections.
    pub fn bitwarden_connect(&self, draft: VaultDraft) -> FfiResult<Vec<CollectionInfo>> {
        Ok(self.core.bitwarden_connect(draft)?)
    }

    /// Collections for editing a Bitwarden vault, without a password. Ready: every
    /// collection the running `bw serve` sees (`enabled` = exposed now), plus exposed ones
    /// it no longer lists. Locked or failed: only the exposed collections, with the names
    /// cached at the last save or connect (the id when none is cached).
    pub fn vault_collections(&self, vault_id: String) -> FfiResult<Vec<CollectionChoice>> {
        Ok(self.core.vault_collections(&vault_id)?)
    }

    pub fn sync_vault(&self, id: String) -> FfiResult<()> {
        Ok(self.core.sync_vault(&id)?)
    }

    /// Unlock a Locked Bitwarden vault. The password is used once and never stored; a
    /// wrong one throws with a message for the operator.
    pub fn unlock_vault(&self, vault_id: String, master_password: String) -> FfiResult<()> {
        Ok(self.core.unlock_vault(&vault_id, &master_password)?)
    }

    pub fn list_hosts(&self) -> Vec<HostRecord> {
        self.core.list_hosts()
    }

    pub fn revoke_host(&self, host_id: String) -> FfiResult<()> {
        Ok(self.core.revoke_host(&host_id)?)
    }

    /// Set a host's friendly name (rules of `Decision::ApprovePair`; `""` = its hostname).
    pub fn rename_host(&self, host_id: String, name: String) -> FfiResult<()> {
        Ok(self.core.rename_host(&host_id, &name)?)
    }

    /// `expiry_secs: None` = never; `max_uses: None` = unlimited; `allowed_networks`:
    /// CIDR ranges or addresses the pairing host's observed address must be in (`[]` =
    /// any); an invalid entry → `invalid` naming it.
    pub fn create_pairing_code(
        &self,
        label: String,
        expiry_secs: Option<u64>,
        max_uses: Option<u32>,
        allowed_networks: Vec<String>,
    ) -> FfiResult<CreatedPairingCode> {
        Ok(self
            .core
            .create_pairing_code(&label, expiry_secs, max_uses, &allowed_networks)?)
    }

    pub fn list_pairing_codes(&self) -> Vec<PairingCodeInfo> {
        self.core.list_pairing_codes()
    }

    pub fn revoke_pairing_code(&self, id: String) -> FfiResult<()> {
        Ok(self.core.revoke_pairing_code(&id)?)
    }

    pub fn list_leases(&self) -> Vec<LeaseInfo> {
        self.core.list_leases()
    }

    pub fn revoke_lease(&self, lease_id: String) -> FfiResult<()> {
        Ok(self.core.revoke_lease(&lease_id)?)
    }

    pub fn proxy_settings(&self) -> ProxySettings {
        self.core.proxy_settings()
    }

    /// Listen changes restart the proxy; on failure the previous settings stay and this throws.
    pub fn set_proxy_settings(&self, settings: ProxySettings) -> FfiResult<()> {
        Ok(self.core.set_proxy_settings(settings)?)
    }

    pub fn proxy_status(&self) -> ProxyStatus {
        self.core.proxy_status()
    }

    pub fn restart_proxy(&self) -> FfiResult<()> {
        Ok(self.core.restart_proxy()?)
    }

    pub fn proxy_log_tail(&self, lines: u32) -> Vec<String> {
        self.core.proxy.log_tail(lines as usize)
    }

    /// macOS Firewall reach of the proxy and the API from the last check (checked at
    /// start, every 60 s, on wake and after listener changes).
    pub fn firewall_status(&self) -> FirewallStatus {
        self.core.firewall_status()
    }

    /// Check the firewall now (runs `socketfilterfw`; blocking) and return the result.
    pub fn check_firewall(&self) -> FirewallStatus {
        self.core.check_firewall();
        self.core.firewall_status()
    }

    /// Activity log, newest first (see [`ActivityQuery`]).
    pub fn list_activity(&self, query: ActivityQuery) -> Vec<ActivityEntry> {
        self.core.list_activity(query)
    }

    /// Id of the activity row recording how a resolved request (pairing or secret
    /// request, e.g. a `Snapshot.recent` entry) ended; `None` once pruned or unknown.
    pub fn activity_row_for_request(&self, request_id: String) -> Option<i64> {
        self.core.activity_row_for_request(&request_id)
    }

    pub fn general_settings(&self) -> GeneralSettings {
        self.core.general_settings()
    }

    /// Changing the API address rebinds at once; throws (old listener kept) when it cannot bind.
    pub fn set_general_settings(&self, settings: GeneralSettings) -> FfiResult<()> {
        Ok(self.core.set_general_settings(settings)?)
    }

    /// Forward `NSWorkspace.didWakeNotification`.
    pub fn on_wake(&self) {
        self.core.on_wake()
    }

    /// Stop the API, the proxy (deleting value files) and vault helpers.
    pub fn shutdown(&self) {
        self.core.shutdown()
    }
}

#[cfg(test)]
mod generator_ffi_tests {
    use super::*;

    #[test]
    fn duplicate_permission_vectors_are_rejected() {
        let duplicate = vec![
            GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read },
            GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read },
        ];
        let config = GeneratorConfig::GithubApp {
            config: GithubAppConfig {
                client_id: "Iv1.test".into(),
                installations: vec![GithubGrant { installation_id: 1, repositories: vec![], permissions: duplicate }],
            },
        };
        assert!(crate::generator::GeneratorConfig::try_from(config).is_err());
    }

    #[test]
    fn duplicate_installation_ids_are_rejected() {
        let grant = GithubGrant {
            installation_id: 1,
            repositories: vec![GithubRepository { id: 7, full_name: "acme/web".into() }],
            permissions: vec![GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read }],
        };
        let config = GeneratorConfig::GithubApp {
            config: GithubAppConfig { client_id: "Iv1.test".into(), installations: vec![grant.clone(), grant] },
        };
        assert!(crate::generator::GeneratorConfig::try_from(config).is_err());
    }

    #[test]
    fn app_discovery_draft_can_have_no_installations() {
        let config = GeneratorConfig::GithubApp {
            config: GithubAppConfig { client_id: "Iv1.test".into(), installations: vec![] },
        };
        let core = crate::generator::GeneratorConfig::try_from(config.clone()).unwrap();
        assert_eq!(GeneratorConfig::from(core), config);
    }

    #[test]
    fn github_config_round_trips_distinct_installation_ceilings() {
        let config = GeneratorConfig::GithubApp {
            config: GithubAppConfig {
                client_id: "Iv1.test".into(),
                installations: vec![
                    GithubGrant {
                        installation_id: 1,
                        repositories: vec![GithubRepository { id: 7, full_name: "acme/web".into() }],
                        permissions: vec![GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read }],
                    },
                    GithubGrant {
                        installation_id: 2,
                        repositories: vec![GithubRepository { id: 8, full_name: "other/ops".into() }],
                        permissions: vec![
                            GithubPermissionEntry { name: "contents".into(), level: GithubPermission::Write },
                            GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read },
                        ],
                    },
                ],
            },
        };
        let core = crate::generator::GeneratorConfig::try_from(config.clone()).unwrap();
        assert_eq!(GeneratorConfig::from(core), config);
    }

    #[test]
    fn connection_draft_can_have_an_empty_ceiling_and_redacts_its_key() {
        let draft = GeneratorDraft {
            id: None,
            name: "test".into(),
            config: GeneratorConfig::GithubApp {
                config: GithubAppConfig {
                    client_id: "Iv1.test".into(),
                    installations: vec![GithubGrant {
                        installation_id: 1, repositories: vec![],
                        permissions: vec![GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read }],
                    }],
                },
            },
            private_key_pem: "PRIVATE_FIXTURE_DO_NOT_DISCLOSE".into(),
        };
        assert!(!format!("{draft:?}").contains(&draft.private_key_pem));
        assert!(crate::generator::GeneratorConfig::try_from(draft.config).is_ok());
    }

    #[test]
    fn generator_selection_rejects_missing_identity() {
        let selection = GenerationSelection {
            generator_id: String::new(),
            generator_revision: 0,
            grant: GenerationGrant::GithubApp {
                scope: GithubGrant {
                    installation_id: 1,
                    repositories: vec![GithubRepository { id: 7, full_name: "acme/web".into() }],
                    permissions: vec![GithubPermissionEntry { name: "metadata".into(), level: GithubPermission::Read }],
                },
            },
        };
        assert!(asm_proto::generators::GenerationSelection::try_from(selection).is_err());
    }
}
