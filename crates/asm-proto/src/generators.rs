//! Generated-credential grants shared by the manager and CLI. These records
//! describe authority; they never contain credentials or provider signing keys.

use crate::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum remaining provider lifetime for cache reuse and an exec launch.
pub const CREDENTIAL_REFRESH_MARGIN_SECS: i64 = 600;
/// GitHub's logical output and its interchangeable request alias.
pub const GITHUB_TOKEN_NAME: &str = "GH_TOKEN";
pub const GITHUB_TOKEN_ALIAS: &str = "GITHUB_TOKEN";
/// Google Cloud CLI's bearer-token override.
pub const GCLOUD_TOKEN_NAME: &str = "CLOUDSDK_AUTH_ACCESS_TOKEN";
pub const GITHUB_TOKEN_NAMES: &[&str] = &[GITHUB_TOKEN_NAME, GITHUB_TOKEN_ALIAS];
pub const GCLOUD_TOKEN_NAMES: &[&str] = &[GCLOUD_TOKEN_NAME];
/// GitHub accepts at most 500 explicit repositories in an installation token.
pub const MAX_GITHUB_REPOSITORIES: usize = 500;

/// All spellings of a generated output, with the canonical name first.
pub fn generated_output_names(name: &str) -> Option<&'static [&'static str]> {
    match name {
        GITHUB_TOKEN_NAME | GITHUB_TOKEN_ALIAS => Some(GITHUB_TOKEN_NAMES),
        GCLOUD_TOKEN_NAME => Some(GCLOUD_TOKEN_NAMES),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    #[default]
    Vault,
    Generator,
}

/// Ordering is also the permission subset ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubPermission {
    Read,
    Write,
    Admin,
}

impl GithubPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubRepository {
    pub id: u64,
    /// Display only. Grant identity is the immutable repository ID.
    pub full_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubScopeRequest {
    /// Full owner/name pairs. Required for a new generated GitHub lease.
    pub repositories: Option<Vec<String>>,
    /// Omission grants only GitHub's mandatory metadata:read permission.
    pub permissions: Option<BTreeMap<String, GithubPermission>>,
}

/// OAuth scope selector for legacy generators bound to a service account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcloudScopeRequest {
    /// None preserves the historical wire format, not managed access.
    pub scopes: Option<Vec<String>>,
}

/// The only project-level Google access profiles a paired host may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GcloudPermission {
    #[serde(rename = "storage=read")]
    StorageRead,
    #[serde(rename = "storage=create")]
    StorageCreate,
    #[serde(rename = "compute=read")]
    ComputeRead,
    #[serde(rename = "run=read")]
    RunRead,
    #[serde(rename = "logs=read")]
    LogsRead,
    #[serde(rename = "bigquery=metadata-read")]
    BigqueryMetadataRead,
}

impl GcloudPermission {
    /// Parse a host claim, never a role name or raw scope URI.
    pub fn from_claim(claim: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|permission| permission.claim() == claim)
    }
    pub const ALL: [Self; 6] = [
        Self::StorageRead, Self::StorageCreate, Self::ComputeRead, Self::RunRead,
        Self::LogsRead, Self::BigqueryMetadataRead,
    ];

    pub fn claim(self) -> &'static str {
        match self {
            Self::StorageRead => "storage=read",
            Self::StorageCreate => "storage=create",
            Self::ComputeRead => "compute=read",
            Self::RunRead => "run=read",
            Self::LogsRead => "logs=read",
            Self::BigqueryMetadataRead => "bigquery=metadata-read",
        }
    }

    pub fn role(self) -> &'static str {
        match self {
            Self::StorageRead => "roles/storage.objectViewer",
            Self::StorageCreate => "roles/storage.objectCreator",
            Self::ComputeRead => "roles/compute.viewer",
            Self::RunRead => "roles/run.viewer",
            Self::LogsRead => "roles/logging.viewer",
            Self::BigqueryMetadataRead => "roles/bigquery.metadataViewer",
        }
    }

    /// The role is the authorization boundary; the OAuth scope is not a
    /// substitute for the role (e.g. storage=create uses a read/write scope).
    pub fn scope(self) -> &'static str {
        match self {
            Self::StorageRead => "https://www.googleapis.com/auth/devstorage.read_only",
            Self::StorageCreate => "https://www.googleapis.com/auth/devstorage.read_write",
            Self::ComputeRead => "https://www.googleapis.com/auth/compute.readonly",
            Self::RunRead => "https://www.googleapis.com/auth/run.readonly",
            Self::LogsRead => "https://www.googleapis.com/auth/logging.read",
            Self::BigqueryMetadataRead => "https://www.googleapis.com/auth/bigquery.readonly",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcloudAccessRequest {
    pub project_id: String,
    /// Nonempty, sorted and deduplicated in enum order.
    pub permissions: Vec<GcloudPermission>,
}

impl GcloudAccessRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        validate_gcloud_project_id(&self.project_id)?;
        if self.permissions.is_empty() {
            return Err(ApiError::invalid("at least one Google Cloud permission claim is required"));
        }
        if self.permissions.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ApiError::invalid("Google Cloud permission claims must be sorted and unique"));
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        self.permissions.sort_unstable();
        self.permissions.dedup();
        self.validate()
    }

    pub fn scopes(&self) -> Vec<String> {
        let mut scopes: Vec<_> = self.permissions.iter().map(|permission| permission.scope().to_owned()).collect();
        scopes.sort_unstable();
        scopes.dedup();
        scopes
    }
}

/// A managed connection alone grants no access. Pending claims describe what
/// the host asked for; only an issued profile can back a credential or lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum GcloudAccessGrant {
    Connection,
    Requested { access: GcloudAccessRequest },
    Issued {
        access: GcloudAccessRequest,
        service_account_unique_id: String,
        service_account_email: String,
    },
}

impl GcloudAccessGrant {
    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::Connection => Ok(()),
            Self::Requested { access } => access.validate(),
            Self::Issued { access, service_account_unique_id, service_account_email } => {
                validate_gcloud_service_account(service_account_unique_id, service_account_email)?;
                access.validate()
            }
        }
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        match self {
            Self::Connection => Ok(()),
            Self::Requested { access } => access.canonicalize(),
            Self::Issued { access, service_account_unique_id, service_account_email } => {
                validate_gcloud_service_account(service_account_unique_id, service_account_email)?;
                access.canonicalize()
            }
        }
    }

    fn is_subset_of(&self, ceiling: &Self) -> Result<bool, ApiError> {
        self.validate()?;
        ceiling.validate()?;
        Ok(matches!((self, ceiling), (
            Self::Issued { access, service_account_unique_id, .. },
            Self::Issued { access: maximum, service_account_unique_id: id, .. },
        ) if access == maximum && service_account_unique_id == id))
    }

    fn covers_request(&self, request: &GcloudAccessRequest) -> Result<bool, ApiError> {
        self.validate()?;
        request.validate()?;
        Ok(matches!(self, Self::Requested { access } | Self::Issued { access, .. } if access == request))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "scope", rename_all = "snake_case")]
pub enum GenerationRequest {
    GithubApp(GithubScopeRequest),
    Gcloud(GcloudScopeRequest),
    GcloudAccess(GcloudAccessRequest),
}

/// Canonical grants have 1–500 positive repository IDs, sorted and deduplicated,
/// and mandatory metadata:read. Call canonicalize at untrusted input seams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubGrant {
    pub installation_id: u64,
    pub repositories: Vec<GithubRepository>,
    pub permissions: BTreeMap<String, GithubPermission>,
}

impl PartialEq for GithubGrant {
    fn eq(&self, other: &Self) -> bool {
        self.installation_id == other.installation_id
            && self.permissions == other.permissions
            && self.repositories.iter().map(|r| r.id).eq(other.repositories.iter().map(|r| r.id))
    }
}

impl Eq for GithubGrant {}

/// Canonical scopes are nonempty, sorted, and unique. The immutable numeric
/// service account ID identifies the authority; the email is display only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcloudGrant {
    pub service_account_unique_id: String,
    pub service_account_email: String,
    pub scopes: Vec<String>,
    /// Issuance/quota project, not a resource boundary. None in configured
    /// ceilings and in legacy grants that used the generator's saved default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
}

impl PartialEq for GcloudGrant {
    fn eq(&self, other: &Self) -> bool {
        self.service_account_unique_id == other.service_account_unique_id
            && self.scopes == other.scopes
            && self.project_id == other.project_id
    }
}

impl Eq for GcloudGrant {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "scope", rename_all = "snake_case")]
pub enum GenerationGrant {
    GithubApp(GithubGrant),
    Gcloud(GcloudGrant),
    GcloudAccess(GcloudAccessGrant),
}

/// An operator's approval candidate, not a public wire type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationChoice {
    pub generator_id: String,
    pub name: String,
    pub revision: u64,
    pub ceiling: GenerationGrant,
    /// Operational readiness, not whether a particular requested scope fits.
    pub available: bool,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationSelection {
    pub generator_id: String,
    pub generator_revision: u64,
    pub grant: GenerationGrant,
}

/// Validate a full owner/name and produce its case-insensitive matching key.
/// Returned GitHub display names need not be replaced with this matching key.
pub fn normalize_repository_name(name: &str) -> Result<String, ApiError> {
    Ok(validate_repository_name(name)?.to_ascii_lowercase())
}

fn validate_repository_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    let mut segments = name.split('/');
    let valid_segment = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    if !segments.next().is_some_and(valid_segment)
        || !segments.next().is_some_and(valid_segment)
        || segments.next().is_some()
    {
        return Err(ApiError::invalid("GitHub repositories must be full ASCII owner/name pairs"));
    }
    Ok(name)
}

fn validate_permissions(permissions: &BTreeMap<String, GithubPermission>) -> Result<(), ApiError> {
    for (name, level) in permissions {
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ApiError::invalid("GitHub permission names must be nonempty lowercase ASCII letters, digits or underscores"));
        }
        if name == "metadata" && *level != GithubPermission::Read {
            return Err(ApiError::invalid("GitHub metadata permission must be read"));
        }
    }
    Ok(())
}

fn canonicalize_permissions(permissions: &mut BTreeMap<String, GithubPermission>) -> Result<(), ApiError> {
    validate_permissions(permissions)?;
    if !permissions.contains_key("metadata") {
        permissions.insert("metadata".into(), GithubPermission::Read);
    }
    Ok(())
}

impl GithubScopeRequest {
    /// Syntax validation does not resolve names against any configured app.
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(repositories) = &self.repositories {
            if repositories.is_empty() {
                return Err(ApiError::invalid("at least one GitHub repository must be requested"));
            }
            for name in repositories {
                validate_repository_name(name)?;
            }
        }
        if let Some(permissions) = &self.permissions {
            validate_permissions(permissions)?;
        }
        Ok(())
    }

    /// Repository omission is preserved for validation by the request target.
    /// Omitted and empty permissions both mean mandatory metadata:read.
    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        if let Some(repositories) = &mut self.repositories {
            if repositories.is_empty() {
                return Err(ApiError::invalid("at least one GitHub repository must be requested"));
            }
            for name in repositories.iter_mut() {
                validate_repository_name(name)?;
                let leading = name.len() - name.trim_start().len();
                let end = name.trim_end().len();
                name.truncate(end);
                name.replace_range(..leading, "");
                name.make_ascii_lowercase();
            }
            repositories.sort_unstable();
            repositories.dedup();
            if repositories.len() > MAX_GITHUB_REPOSITORIES {
                return Err(ApiError::invalid("at most 500 GitHub repositories can be requested"));
            }
        }
        canonicalize_permissions(self.permissions.get_or_insert_with(BTreeMap::new))?;
        Ok(())
    }
}

impl GithubGrant {
    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        if self.installation_id == 0 {
            return Err(ApiError::invalid("GitHub installation ID must be positive"));
        }
        for repository in &self.repositories {
            if repository.id == 0 {
                return Err(ApiError::invalid("GitHub repository IDs must be positive"));
            }
            validate_repository_name(&repository.full_name)?;
        }
        // The display-name tiebreaker makes duplicate-ID normalization deterministic.
        self.repositories.sort_unstable_by(|a, b| a.id.cmp(&b.id).then_with(|| a.full_name.cmp(&b.full_name)));
        self.repositories.dedup_by_key(|r| r.id);
        if !(1..=MAX_GITHUB_REPOSITORIES).contains(&self.repositories.len()) {
            return Err(ApiError::invalid("a GitHub grant must select 1–500 repositories"));
        }
        canonicalize_permissions(&mut self.permissions)
    }

    /// Validate canonical shape without changing authority or allocating a copy.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.installation_id == 0
            || !(1..=MAX_GITHUB_REPOSITORIES).contains(&self.repositories.len())
            || self.repositories.first().is_some_and(|r| r.id == 0)
            || self.repositories.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(ApiError::invalid("GitHub grant requires a positive installation ID and 1–500 sorted unique positive repository IDs"));
        }
        for repository in &self.repositories {
            validate_repository_name(&repository.full_name)?;
        }
        validate_permissions(&self.permissions)?;
        if self.permissions.get("metadata") != Some(&GithubPermission::Read) {
            return Err(ApiError::invalid("GitHub grant requires metadata:read"));
        }
        Ok(())
    }

    /// Both operands must be canonical. Display-name changes do not affect scope.
    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool, ApiError> {
        self.validate()?;
        ceiling.validate()?;
        Ok(self.installation_id == ceiling.installation_id
            && self.repositories.iter().all(|r| ceiling.repositories.binary_search_by_key(&r.id, |c| c.id).is_ok())
            && self.permissions.iter().all(|(name, level)| ceiling.permissions.get(name).is_some_and(|maximum| level <= maximum)))
    }

    /// Check explicit request dimensions only, resolving names within this grant.
    /// Unknown permission keys are not ignored. None imposes no new restriction.
    pub fn covers_request(&self, request: &GithubScopeRequest) -> Result<bool, ApiError> {
        self.validate()?;
        request.validate()?;
        if let Some(repositories) = &request.repositories {
            for name in repositories {
                if !self.repositories.iter().any(|r| r.full_name.trim().eq_ignore_ascii_case(name.trim())) {
                    return Ok(false);
                }
            }
        }
        if let Some(permissions) = &request.permissions {
            if !permissions.iter().all(|(name, level)| self.permissions.get(name).is_some_and(|approved| level <= approved)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Nonsecret descriptions for both candidate ceilings and selected grants.
    /// Omitted dimensions create no issues; unknown keys remain visible.
    pub fn scope_issues(&self, request: &GithubScopeRequest) -> Result<Vec<String>, ApiError> {
        self.validate()?;
        request.validate()?;
        let mut issues = Vec::new();
        if let Some(repositories) = &request.repositories {
            for name in repositories {
                if !self.repositories.iter().any(|r| r.full_name.trim().eq_ignore_ascii_case(name.trim())) {
                    issues.push(format!("repository {} is outside the selected scope", name.trim()));
                }
            }
        }
        if let Some(permissions) = &request.permissions {
            for (name, level) in permissions {
                if !self.permissions.get(name).is_some_and(|approved| level <= approved) {
                    issues.push(format!("permission {name}:{} is outside the selected scope", level.as_str()));
                }
            }
        }
        Ok(issues)
    }
}

/// Validate a Google Cloud project ID, not a display name or project number.
pub fn validate_gcloud_project_id(value: &str) -> Result<(), ApiError> {
    let bytes = value.as_bytes();
    if !(6..=30).contains(&bytes.len())
        || !bytes[0].is_ascii_lowercase()
        || value.ends_with('-')
        || !bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(ApiError::invalid("Enter a Google Cloud project ID (6 to 30 lowercase letters, digits or hyphens), not its display name or number"));
    }
    Ok(())
}

/// Validate an exact, case-sensitive Google OAuth scope URI. This syntax is
/// also safe to pass as one member of gcloud's comma-delimited scope argument.
pub fn validate_gcloud_scope(scope: &str) -> Result<(), ApiError> {
    const PREFIX: &str = "https://www.googleapis.com/auth/";
    if !scope.strip_prefix(PREFIX).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'-'))
    }) {
        return Err(ApiError::invalid("Google Cloud OAuth scopes must be exact https://www.googleapis.com/auth/ URIs"));
    }
    Ok(())
}

fn validate_gcloud_scopes(scopes: &[String]) -> Result<(), ApiError> {
    if scopes.is_empty() {
        return Err(ApiError::invalid("at least one Google Cloud OAuth scope is required"));
    }
    scopes.iter().try_for_each(|scope| validate_gcloud_scope(scope))
}

impl GcloudScopeRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(scopes) = &self.scopes {
            validate_gcloud_scopes(scopes)?;
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        self.validate()?;
        if let Some(scopes) = &mut self.scopes {
            scopes.sort_unstable();
            scopes.dedup();
        }
        Ok(())
    }
}

fn validate_gcloud_service_account(unique_id: &str, email: &str) -> Result<(), ApiError> {
    if unique_id.is_empty() || !unique_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::invalid("Google Cloud grant requires a numeric service account unique ID"));
    }
    if email.is_empty() || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ApiError::invalid("Google Cloud grant requires a service account email"));
    }
    Ok(())
}

impl GcloudGrant {
    fn validate_shape(&self) -> Result<(), ApiError> {
        validate_gcloud_service_account(&self.service_account_unique_id, &self.service_account_email)?;
        if let Some(project_id) = &self.project_id {
            validate_gcloud_project_id(project_id)?;
        }
        validate_gcloud_scopes(&self.scopes)
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        self.validate_shape()?;
        if self.scopes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ApiError::invalid("Google Cloud grant scopes must be sorted and unique"));
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        self.validate_shape()?;
        self.scopes.sort_unstable();
        self.scopes.dedup();
        Ok(())
    }

    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool, ApiError> {
        self.validate()?;
        ceiling.validate()?;
        Ok(self.service_account_unique_id == ceiling.service_account_unique_id
            && ceiling.project_id.as_ref().is_none_or(|project| self.project_id.as_ref() == Some(project))
            && self.scopes.iter().all(|scope| ceiling.scopes.binary_search(scope).is_ok()))
    }

    pub fn covers_request(&self, request: &GcloudScopeRequest) -> Result<bool, ApiError> {
        self.validate()?;
        request.validate()?;
        Ok(request.scopes.as_ref().is_none_or(|scopes| {
            scopes.iter().all(|scope| self.scopes.binary_search(scope).is_ok())
        }))
    }

    pub fn scope_issues(&self, request: &GcloudScopeRequest) -> Result<Vec<String>, ApiError> {
        self.validate()?;
        request.validate()?;
        Ok(request.scopes.iter().flatten()
            .filter(|scope| self.scopes.binary_search(scope).is_err())
            .map(|scope| format!("Google Cloud OAuth scope {scope} is outside the selected scope"))
            .collect())
    }
}

impl GenerationRequest {
    pub fn output_name(&self) -> &'static str {
        match self {
            Self::GithubApp(_) => GITHUB_TOKEN_NAME,
            Self::Gcloud(_) => GCLOUD_TOKEN_NAME,
            Self::GcloudAccess(_) => GCLOUD_TOKEN_NAME,
        }
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(scope) => scope.canonicalize(),
            Self::Gcloud(scope) => scope.canonicalize(),
            Self::GcloudAccess(access) => access.canonicalize(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(scope) => scope.validate(),
            Self::Gcloud(scope) => scope.validate(),
            Self::GcloudAccess(access) => access.validate(),
        }
    }
}

impl GenerationGrant {
    pub fn output_name(&self) -> &'static str {
        self.output_names()[0]
    }

    /// The first spelling is canonical; subsequent spellings are aliases.
    pub fn output_names(&self) -> &'static [&'static str] {
        match self {
            Self::GithubApp(_) => GITHUB_TOKEN_NAMES,
            Self::Gcloud(_) | Self::GcloudAccess(_) => GCLOUD_TOKEN_NAMES,
        }
    }

    /// Pending and catalog markers cannot authorize a delivered credential.
    pub fn is_issued(&self) -> bool {
        !matches!(self, Self::GcloudAccess(GcloudAccessGrant::Connection | GcloudAccessGrant::Requested { .. }))
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(grant) => grant.canonicalize(),
            Self::Gcloud(grant) => grant.canonicalize(),
            Self::GcloudAccess(grant) => grant.canonicalize(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(grant) => grant.validate(),
            Self::Gcloud(grant) => grant.validate(),
            Self::GcloudAccess(grant) => grant.validate(),
        }
    }

    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool, ApiError> {
        match (self, ceiling) {
            (Self::GithubApp(grant), Self::GithubApp(ceiling)) => grant.is_subset_of(ceiling),
            (Self::Gcloud(grant), Self::Gcloud(ceiling)) => grant.is_subset_of(ceiling),
            (Self::GcloudAccess(grant), Self::GcloudAccess(ceiling)) => grant.is_subset_of(ceiling),
            _ => Ok(false),
        }
    }

    pub fn covers_request(&self, request: &GenerationRequest) -> Result<bool, ApiError> {
        match (self, request) {
            (Self::GithubApp(grant), GenerationRequest::GithubApp(request)) => grant.covers_request(request),
            (Self::Gcloud(grant), GenerationRequest::Gcloud(request)) => grant.covers_request(request),
            (Self::GcloudAccess(grant), GenerationRequest::GcloudAccess(request)) => grant.covers_request(request),
            _ => Ok(false),
        }
    }

    /// Match explicit claim bounds without adding or dropping authority.
    /// Requests must be canonicalized. GitHub requires repository names and
    /// defaults omitted permissions to `metadata:read`; legacy Google OAuth
    /// scopes may be unspecified.
    pub fn matches_request_exactly(&self, request: &GenerationRequest) -> Result<bool, ApiError> {
        match (self, request) {
            (Self::GithubApp(grant), GenerationRequest::GithubApp(scope)) => {
                grant.validate()?;
                scope.validate()?;
                Ok(scope.permissions.as_ref().map_or(grant.permissions.len() == 1, |permissions| permissions == &grant.permissions)
                    && scope.repositories.as_ref().is_some_and(|names| names.len() == grant.repositories.len()
                        && names.iter().all(|name| grant.repositories.iter().any(|repo| repo.full_name.trim().eq_ignore_ascii_case(name)))))
            }
            (Self::Gcloud(grant), GenerationRequest::Gcloud(scope)) => {
                grant.validate()?;
                scope.validate()?;
                Ok(scope.scopes.as_ref().is_none_or(|scopes| scopes == &grant.scopes))
            }
            _ => self.covers_request(request),
        }
    }

    /// The operator may edit claims under the grant-selection capability, but
    /// cannot use that capability alone to change providers or projects.
    pub fn can_select_for(&self, request: &GenerationRequest) -> bool {
        match (self, request) {
            (Self::GithubApp(_), GenerationRequest::GithubApp(_))
            | (Self::Gcloud(_), GenerationRequest::Gcloud(_)) => true,
            (Self::GcloudAccess(GcloudAccessGrant::Requested { access }
                | GcloudAccessGrant::Issued { access, .. }), GenerationRequest::GcloudAccess(request)) =>
                access.project_id == request.project_id,
            _ => false,
        }
    }

    /// A separately negotiated project switch is only for issued managed
    /// Google grants. Changing permissions requires separate authorization.
    pub fn can_switch_project_for(&self, request: &GenerationRequest, permissions_selectable: bool) -> bool {
        matches!((self, request), (
            Self::GcloudAccess(GcloudAccessGrant::Issued { access, .. }),
            GenerationRequest::GcloudAccess(request),
        ) if access.project_id != request.project_id
            && (permissions_selectable || access.permissions == request.permissions))
    }

    pub fn scope_issues(&self, request: &GenerationRequest) -> Result<Vec<String>, ApiError> {
        match (self, request) {
            (Self::GithubApp(grant), GenerationRequest::GithubApp(request)) => grant.scope_issues(request),
            (Self::Gcloud(grant), GenerationRequest::Gcloud(request)) => grant.scope_issues(request),
            (Self::GcloudAccess(grant), GenerationRequest::GcloudAccess(request)) => {
                if grant.covers_request(request)? {
                    Ok(Vec::new())
                } else {
                    Ok(vec!["Google Cloud approval must match the exact requested project and permissions".into()])
                }
            }
            _ => Ok(vec!["requested scope belongs to a different credential provider".into()]),
        }
    }
}

impl GenerationSelection {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.generator_id.is_empty() || self.generator_revision == 0 {
            return Err(ApiError::invalid("generator selection requires an ID and positive revision"));
        }
        if matches!(&self.grant, GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection)) {
            return Err(ApiError::invalid("a Google Cloud connection alone is not a grant selection"));
        }
        self.grant.validate()
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        if self.generator_id.is_empty() || self.generator_revision == 0 {
            return Err(ApiError::invalid("generator selection requires an ID and positive revision"));
        }
        if matches!(&self.grant, GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection)) {
            return Err(ApiError::invalid("a Google Cloud connection alone is not a grant selection"));
        }
        self.grant.canonicalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant() -> GithubGrant {
        GithubGrant {
            installation_id: 42,
            repositories: vec![GithubRepository { id: 7, full_name: "Acme/Web".into() }],
            permissions: BTreeMap::from([("contents".into(), GithubPermission::Write), ("metadata".into(), GithubPermission::Read)]),
        }
    }

    #[test]
    fn repository_requests_normalize_and_default_to_metadata_only() {
        let mut request = GithubScopeRequest {
            repositories: Some(vec![" Acme/Web ".into(), "acme/web".into(), "Other/repo.name".into()]),
            permissions: Some(BTreeMap::new()),
        };
        request.canonicalize().unwrap();
        assert_eq!(request.repositories.unwrap(), ["acme/web", "other/repo.name"]);
        assert_eq!(request.permissions.unwrap(), BTreeMap::from([("metadata".into(), GithubPermission::Read)]));
        let mut omitted = GithubScopeRequest::default();
        omitted.canonicalize().unwrap();
        assert_eq!(omitted.repositories, None);
        assert_eq!(omitted.permissions, Some(BTreeMap::from([("metadata".into(), GithubPermission::Read)])));
        for name in ["", "a", "a/", "/b", "a/b/c", "./repo", "a/..", "a/b c", "ä/b", "a/b@c"] {
            assert!(normalize_repository_name(name).is_err(), "{name:?}");
        }
        assert!(normalize_repository_name(" a_b/c-d.e ").is_ok());
        assert!(GithubScopeRequest { repositories: Some(vec![]), permissions: None }.canonicalize().is_err());
        let mut too_many = GithubScopeRequest {
            repositories: Some((0..=MAX_GITHUB_REPOSITORIES).map(|i| format!("acme/repo-{i}")).collect()),
            permissions: None,
        };
        assert!(too_many.canonicalize().is_err());
    }

    #[test]
    fn grant_identity_is_immutable_and_subsets_never_union_permissions() {
        let ceiling = grant();
        let mut narrowed = ceiling.clone();
        narrowed.repositories[0].full_name = "Renamed/Repository".into();
        assert_eq!(narrowed, ceiling);
        narrowed.permissions.insert("contents".into(), GithubPermission::Read);
        assert!(narrowed.is_subset_of(&ceiling).unwrap());
        assert!(!ceiling.is_subset_of(&narrowed).unwrap());
        narrowed.permissions.insert("issues".into(), GithubPermission::Read);
        assert!(!narrowed.is_subset_of(&ceiling).unwrap());
        narrowed = ceiling.clone();
        narrowed.installation_id += 1;
        assert!(!narrowed.is_subset_of(&ceiling).unwrap());
        narrowed = ceiling.clone();
        narrowed.repositories[0].id += 1;
        assert!(!narrowed.is_subset_of(&ceiling).unwrap());
    }

    #[test]
    fn grants_sort_deduplicate_and_validate_ids_and_permissions() {
        let mut value = grant();
        value.repositories.push(GithubRepository { id: 3, full_name: "Acme/Other".into() });
        value.repositories.push(value.repositories[0].clone());
        value.permissions.remove("metadata");
        value.canonicalize().unwrap();
        value.validate().unwrap();
        assert_eq!(value.repositories.iter().map(|r| r.id).collect::<Vec<_>>(), [3, 7]);
        value.repositories[0].id = 0;
        assert!(value.canonicalize().is_err());
        for key in ["", "Contents", "contents:read", "é"] {
            let mut value = grant();
            value.permissions.insert(key.into(), GithubPermission::Read);
            assert!(value.canonicalize().is_err());
        }
        let mut value = grant();
        value.permissions.insert("metadata".into(), GithubPermission::Write);
        assert!(value.canonicalize().is_err());
        value = grant();
        value.repositories.clear();
        assert!(value.canonicalize().is_err());
        value = grant();
        value.repositories = (1..=501).map(|id| GithubRepository { id, full_name: format!("acme/repo-{id}") }).collect();
        assert!(value.canonicalize().is_err());
    }

    #[test]
    fn explicit_request_coverage_and_permission_order() {
        let value = grant();
        assert!(value.covers_request(&GithubScopeRequest::default()).unwrap());
        let mut request = GithubScopeRequest {
            repositories: Some(vec![" ACME/web ".into()]),
            permissions: Some(BTreeMap::from([("contents".into(), GithubPermission::Read)])),
        };
        assert!(value.covers_request(&request).unwrap());
        request.permissions.as_mut().unwrap().insert("contents".into(), GithubPermission::Admin);
        assert!(!value.covers_request(&request).unwrap());
        request.permissions = Some(BTreeMap::from([("unknown".into(), GithubPermission::Read)]));
        assert!(!value.covers_request(&request).unwrap());
        request.permissions = None;
        request.repositories = Some(vec!["other/repo".into()]);
        assert!(!value.covers_request(&request).unwrap());
        assert!(GithubPermission::Read < GithubPermission::Write);
        assert!(GithubPermission::Write < GithubPermission::Admin);
    }

    #[test]
    fn provider_tags_and_scope_roundtrip() {
        let value = GenerationGrant::GithubApp(grant());
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["provider"], "github_app");
        assert_eq!(json["scope"]["installation_id"], 42);
        assert_eq!(serde_json::from_value::<GenerationGrant>(json).unwrap(), value);
        let request = GenerationRequest::GithubApp(GithubScopeRequest::default());
        assert_eq!(serde_json::to_value(request).unwrap(), json!({"provider":"github_app","scope":{"repositories":null,"permissions":null}}));
        assert!(serde_json::from_value::<GithubPermission>(json!("none")).is_err());
        assert!(serde_json::from_value::<GithubPermission>(json!("READ")).is_err());
        assert_eq!(serde_json::to_value(SourceKind::default()).unwrap(), "vault");
        assert_eq!(CREDENTIAL_REFRESH_MARGIN_SECS, 600);
    }

    #[test]
    fn issue_descriptions_cover_every_unmet_explicit_dimension() {
        let ceiling = GenerationGrant::GithubApp(grant());
        let mut request = GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(vec!["other/repo".into()]),
            permissions: Some(BTreeMap::from([
                ("contents".into(), GithubPermission::Admin),
                ("unknown".into(), GithubPermission::Read),
            ])),
        });
        request.canonicalize().unwrap();
        request.validate().unwrap();
        let issues = ceiling.scope_issues(&request).unwrap();
        assert_eq!(issues.len(), 3);
        assert!(issues.iter().any(|issue| issue.contains("other/repo")));
        assert!(issues.iter().any(|issue| issue.contains("contents:admin")));
        assert!(issues.iter().any(|issue| issue.contains("unknown:read")));
        assert!(!ceiling.covers_request(&request).unwrap());
        assert!(ceiling.scope_issues(&GenerationRequest::GithubApp(GithubScopeRequest::default())).unwrap().is_empty());
    }

    #[test]
    fn selection_validation_and_in_place_request_normalization() {
        let mut selection = GenerationSelection {
            generator_id: "g".into(), generator_revision: 1,
            grant: GenerationGrant::GithubApp(grant()),
        };
        selection.canonicalize().unwrap();
        selection.validate().unwrap();
        assert!(selection.grant.is_subset_of(&selection.grant).unwrap());
        selection.generator_revision = 0;
        assert!(selection.validate().is_err());
        assert!(selection.canonicalize().is_err());
        let mut invalid = grant();
        invalid.installation_id = 0;
        assert!(invalid.canonicalize().is_err());
        let mut request = GithubScopeRequest {
            repositories: Some(vec![" \u{2003}ACME/Web\u{2002} ".into()]),
            permissions: None,
        };
        request.canonicalize().unwrap();
        assert_eq!(request.repositories.unwrap(), ["acme/web"]);
        assert_eq!(request.permissions, Some(BTreeMap::from([("metadata".into(), GithubPermission::Read)])));
    }

    const CLOUD: &str = "https://www.googleapis.com/auth/cloud-platform";
    const STORAGE: &str = "https://www.googleapis.com/auth/devstorage.read_only";

    fn gcloud(scopes: &[&str]) -> GcloudGrant {
        GcloudGrant {
            service_account_unique_id: "123456789012345678901".into(),
            service_account_email: "app@demo-project.iam.gserviceaccount.com".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            project_id: None,
        }
    }

    #[test]
    fn gcloud_scopes_canonicalize_and_roundtrip_without_changing_case() {
        let upper = "https://www.googleapis.com/auth/Devstorage.read_only";
        let mut request = GenerationRequest::Gcloud(GcloudScopeRequest {
            scopes: Some(vec![STORAGE.into(), upper.into(), STORAGE.into()]),
        });
        request.canonicalize().unwrap();
        let wire = json!({"provider":"gcloud","scope":{"scopes":[upper, STORAGE]}});
        assert_eq!(serde_json::to_value(&request).unwrap(), wire);
        assert_eq!(serde_json::from_value::<GenerationRequest>(wire).unwrap(), request);
        assert_eq!(request.output_name(), "CLOUDSDK_AUTH_ACCESS_TOKEN");

        let mut grant = GenerationGrant::Gcloud(gcloud(&[STORAGE, CLOUD, STORAGE]));
        grant.canonicalize().unwrap();
        let wire = json!({"provider":"gcloud","scope":{
            "service_account_unique_id":"123456789012345678901",
            "service_account_email":"app@demo-project.iam.gserviceaccount.com",
            "scopes":[CLOUD, STORAGE]
        }});
        assert_eq!(serde_json::to_value(&grant).unwrap(), wire);
        assert_eq!(serde_json::from_value::<GenerationGrant>(wire).unwrap(), grant);
        assert!(!grant.covers_request(&request).unwrap());
        assert!(grant.scope_issues(&request).unwrap()[0].contains(upper));
    }

    #[test]
    fn gcloud_rejects_explicit_empty_and_invalid_scope_sets() {
        let mut omitted = GcloudScopeRequest::default();
        omitted.canonicalize().unwrap();
        assert_eq!(omitted.scopes, None);
        assert!(gcloud(&[CLOUD]).covers_request(&omitted).unwrap());
        assert!(GcloudScopeRequest { scopes: Some(vec![]) }.canonicalize().is_err());
        assert!(gcloud(&[]).canonicalize().is_err());
        assert!(gcloud(&[STORAGE, CLOUD]).validate().is_err());
        assert!(gcloud(&[CLOUD, CLOUD]).validate().is_err());
        for scope in [
            "", "http://www.googleapis.com/auth/api", "https://example.com/auth/api",
            "https://www.googleapis.com/auth/", "https://www.googleapis.com/auth/a,b",
            "https://www.googleapis.com/auth/^x^y", "https://www.googleapis.com/auth/a%20b",
            "https://www.googleapis.com/auth/a b", "https://www.googleapis.com/auth/a\u{2003}b",
            "https://www.googleapis.com/auth/a\nb", "https://www.googleapis.com/auth/a\u{7f}",
        ] {
            assert!(GcloudScopeRequest { scopes: Some(vec![scope.into()]) }.canonicalize().is_err(), "{scope:?}");
            assert!(gcloud(&[scope]).canonicalize().is_err(), "{scope:?}");
        }
        for id in ["", "name@example.com", "１２３", "123,456"] {
            let mut grant = gcloud(&[CLOUD]);
            grant.service_account_unique_id = id.into();
            assert!(grant.canonicalize().is_err(), "{id:?}");
        }
    }

    #[test]
    fn gcloud_subsets_require_exact_scopes_and_the_same_immutable_identity() {
        let ceiling = gcloud(&[CLOUD, STORAGE]);
        let mut narrower = gcloud(&[STORAGE]);
        assert!(narrower.is_subset_of(&ceiling).unwrap());
        assert!(!ceiling.is_subset_of(&narrower).unwrap());
        assert!(!narrower.is_subset_of(&gcloud(&[CLOUD])).unwrap());

        narrower.service_account_email = "renamed@demo-project.iam.gserviceaccount.com".into();
        assert!(narrower.is_subset_of(&ceiling).unwrap());
        narrower.service_account_unique_id.push('2');
        assert!(!narrower.is_subset_of(&ceiling).unwrap());

        let grant = GenerationGrant::Gcloud(gcloud(&[CLOUD]));
        let request = GenerationRequest::Gcloud(GcloudScopeRequest { scopes: Some(vec![STORAGE.into()]) });
        assert!(!grant.covers_request(&request).unwrap());
        assert!(grant.scope_issues(&request).unwrap()[0].contains(STORAGE));
    }

    #[test]
    fn gcloud_concrete_project_constraints_require_an_exact_project() {
        let ceiling = gcloud(&[STORAGE]);
        let mut approved = ceiling.clone();
        approved.project_id = Some("quota-project".into());
        let mut other = ceiling.clone();
        other.project_id = Some("other-project".into());
        assert!(approved.is_subset_of(&ceiling).unwrap());
        assert!(approved.is_subset_of(&approved).unwrap());
        assert!(!approved.is_subset_of(&other).unwrap());
        assert!(!ceiling.is_subset_of(&approved).unwrap());
        assert_ne!(approved, other);
        assert_ne!(approved, ceiling);

        let grant = GenerationGrant::Gcloud(approved);
        let wire = serde_json::to_value(&grant).unwrap();
        assert_eq!(wire["scope"]["project_id"], "quota-project");
        assert_eq!(serde_json::from_value::<GenerationGrant>(wire).unwrap(), grant);
        for project_id in ["", "abcde", "123456", "Upper-project", "quota-", "proj_ect",
            "proj/ect", "--project=other", "proj\t ect", "abcdefghijklmnopqrstuvwxyz12345"] {
            let mut invalid = gcloud(&[STORAGE]);
            invalid.project_id = Some(project_id.into());
            assert!(invalid.validate().is_err(), "{project_id:?}");
            assert!(invalid.canonicalize().is_err(), "{project_id:?}");
        }
    }

    #[test]
    fn provider_mismatches_never_cover_or_reinterpret_authority() {
        let github_grant = GenerationGrant::GithubApp(grant());
        let github_request = GenerationRequest::GithubApp(GithubScopeRequest::default());
        let google_grant = GenerationGrant::Gcloud(gcloud(&[CLOUD]));
        let google_request = GenerationRequest::Gcloud(GcloudScopeRequest::default());
        assert!(!github_grant.is_subset_of(&google_grant).unwrap());
        assert!(!google_grant.is_subset_of(&github_grant).unwrap());
        for (grant, request) in [(&github_grant, &google_request), (&google_grant, &github_request)] {
            assert!(!grant.covers_request(request).unwrap());
            assert_eq!(grant.scope_issues(request).unwrap(), ["requested scope belongs to a different credential provider"]);
        }
    }

    #[test]
    fn managed_google_claims_map_to_predefined_roles_and_provider_scopes() {
        for (claim, role, scope) in [
            ("storage=read", "roles/storage.objectViewer", STORAGE),
            ("storage=create", "roles/storage.objectCreator", "https://www.googleapis.com/auth/devstorage.read_write"),
            ("compute=read", "roles/compute.viewer", "https://www.googleapis.com/auth/compute.readonly"),
            ("run=read", "roles/run.viewer", "https://www.googleapis.com/auth/run.readonly"),
            ("logs=read", "roles/logging.viewer", "https://www.googleapis.com/auth/logging.read"),
            ("bigquery=metadata-read", "roles/bigquery.metadataViewer", "https://www.googleapis.com/auth/bigquery.readonly"),
        ] {
            let permission = GcloudPermission::from_claim(claim).unwrap();
            assert_eq!(permission.claim(), claim);
            assert_eq!(permission.role(), role);
            assert_eq!(permission.scope(), scope);
            assert_eq!(serde_json::from_value::<GcloudPermission>(json!(claim)).unwrap(), permission);
            assert_eq!(serde_json::to_value(permission).unwrap(), json!(claim));
        }
        for invalid in [CLOUD, "roles/owner", "storage=write", "Storage=read", "compute=admin", ""] {
            assert!(GcloudPermission::from_claim(invalid).is_none());
            assert!(serde_json::from_value::<GcloudPermission>(json!(invalid)).is_err());
        }
    }

    #[test]
    fn github_operator_selection_can_differ_from_explicit_request_bounds() {
        let mut exact = grant();
        exact.permissions.remove("contents");
        let mut broad = grant();
        broad.repositories.push(GithubRepository { id: 9, full_name: "Acme/Other".into() });
        let request = GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(vec!["acme/web".into()]),
            permissions: None,
        });
        for (candidate, matches) in [(exact, true), (broad, false)] {
            let candidate = GenerationGrant::GithubApp(candidate);
            assert!(candidate.can_select_for(&request));
            assert_eq!(candidate.matches_request_exactly(&request).unwrap(), matches);
        }
    }

    #[test]
    fn managed_google_leases_require_exact_project_claims_and_pinned_identity() {
        let mut access = GcloudAccessRequest {
            project_id: "demo-project".into(),
            permissions: vec![GcloudPermission::ComputeRead, GcloudPermission::StorageRead, GcloudPermission::ComputeRead],
        };
        assert!(access.validate().is_err());
        access.canonicalize().unwrap();
        assert_eq!(access.scopes(), ["https://www.googleapis.com/auth/compute.readonly", STORAGE]);
        let request = GenerationRequest::GcloudAccess(access.clone());
        let wire = json!({"provider":"gcloud_access","scope":{
            "project_id":"demo-project","permissions":["storage=read","compute=read"]
        }});
        assert_eq!(serde_json::to_value(&request).unwrap(), wire);
        assert_eq!(serde_json::from_value::<GenerationRequest>(wire).unwrap(), request);
        let grant = |access, id: &str| GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
            access,
            service_account_unique_id: id.into(),
            service_account_email: "app@demo-project.iam.gserviceaccount.com".into(),
        });
        let issued = grant(access.clone(), "12345");
        let wire = serde_json::to_value(&issued).unwrap();
        assert_eq!(wire["provider"], "gcloud_access");
        assert_eq!(wire["scope"]["state"], "issued");
        assert_eq!(serde_json::from_value::<GenerationGrant>(wire).unwrap(), issued);
        assert!(issued.covers_request(&request).unwrap());
        assert!(issued.matches_request_exactly(&request).unwrap());
        assert!(issued.can_select_for(&request));
        assert!(issued.is_subset_of(&issued).unwrap());
        assert!(!issued.is_subset_of(&grant(access.clone(), "67890")).unwrap());
        assert!(grant(access.clone(), "not-an-id").validate().is_err());
        for other in [
            GcloudAccessRequest { permissions: vec![GcloudPermission::StorageRead], ..access.clone() },
            GcloudAccessRequest { permissions: vec![GcloudPermission::StorageRead, GcloudPermission::ComputeRead, GcloudPermission::RunRead], ..access.clone() },
            GcloudAccessRequest { project_id: "other-project".into(), ..access.clone() },
        ] {
            let different = grant(other.clone(), "12345");
            assert!(!issued.is_subset_of(&different).unwrap());
            assert!(!different.is_subset_of(&issued).unwrap());
            let other_request = GenerationRequest::GcloudAccess(other.clone());
            assert!(!issued.matches_request_exactly(&other_request).unwrap());
            assert_eq!(issued.can_select_for(&other_request), other.project_id == access.project_id);
        }
        let pending = GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: access.clone() });
        let catalog = GenerationGrant::GcloudAccess(GcloudAccessGrant::Connection);
        assert!(pending.covers_request(&request).unwrap());
        assert!(!catalog.covers_request(&request).unwrap());
        for display in [pending, catalog] {
            assert!(!display.is_issued());
            assert!(!display.is_subset_of(&issued).unwrap());
            assert!(!issued.is_subset_of(&display).unwrap());
        }
        let legacy = GenerationGrant::Gcloud(gcloud(&[STORAGE]));
        assert!(!legacy.covers_request(&request).unwrap());
        assert!(!legacy.can_select_for(&request));
        assert!(!issued.is_subset_of(&legacy).unwrap());
        assert!(!issued.covers_request(&GenerationRequest::Gcloud(GcloudScopeRequest::default())).unwrap());
        assert!(GcloudAccessRequest { permissions: vec![], ..access }.validate().is_err());
    }

    #[test]
    fn project_selection_does_not_imply_permission_selection_or_lease_equivalence() {
        let access = GcloudAccessRequest {
            project_id: "demo-project".into(),
            permissions: vec![GcloudPermission::StorageRead],
        };
        let issued = |access| GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
            access,
            service_account_unique_id: "12345".into(),
            service_account_email: "managed@demo-project.iam.gserviceaccount.com".into(),
        });
        let request = GenerationRequest::GcloudAccess(access.clone());
        let exact = issued(access.clone());
        let switched_access = GcloudAccessRequest { project_id: "other-project".into(), ..access };
        let switched = issued(switched_access.clone());
        let switched_and_edited = issued(GcloudAccessRequest {
            permissions: vec![GcloudPermission::ComputeRead],
            ..switched_access.clone()
        });
        let pending = GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: switched_access });
        assert!(!exact.can_switch_project_for(&request, true));
        assert!(switched.can_switch_project_for(&request, false));
        assert!(!switched_and_edited.can_switch_project_for(&request, false));
        assert!(switched_and_edited.can_switch_project_for(&request, true));
        assert!(!pending.can_switch_project_for(&request, true));
        assert!(!switched.can_select_for(&request));
        assert!(!switched.matches_request_exactly(&request).unwrap());
        assert!(!switched.is_subset_of(&exact).unwrap());
    }
}
