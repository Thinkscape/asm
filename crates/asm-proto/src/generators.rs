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
/// GitHub accepts at most 500 explicit repositories in an installation token.
pub const MAX_GITHUB_REPOSITORIES: usize = 500;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "scope", rename_all = "snake_case")]
pub enum GenerationRequest {
    GithubApp(GithubScopeRequest),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "scope", rename_all = "snake_case")]
pub enum GenerationGrant {
    GithubApp(GithubGrant),
}

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

impl GenerationRequest {
    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(scope) => scope.canonicalize(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(scope) => scope.validate(),
        }
    }
}

impl GenerationGrant {
    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(grant) => grant.canonicalize(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::GithubApp(grant) => grant.validate(),
        }
    }

    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool, ApiError> {
        match (self, ceiling) {
            (Self::GithubApp(grant), Self::GithubApp(ceiling)) => grant.is_subset_of(ceiling),
        }
    }

    pub fn covers_request(&self, request: &GenerationRequest) -> Result<bool, ApiError> {
        match (self, request) {
            (Self::GithubApp(grant), GenerationRequest::GithubApp(request)) => grant.covers_request(request),
        }
    }

    pub fn scope_issues(&self, request: &GenerationRequest) -> Result<Vec<String>, ApiError> {
        match (self, request) {
            (Self::GithubApp(grant), GenerationRequest::GithubApp(request)) => grant.scope_issues(request),
        }
    }
}

impl GenerationSelection {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.generator_id.is_empty() || self.generator_revision == 0 {
            return Err(ApiError::invalid("generator selection requires an ID and positive revision"));
        }
        self.grant.validate()
    }

    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        if self.generator_id.is_empty() || self.generator_revision == 0 {
            return Err(ApiError::invalid("generator selection requires an ID and positive revision"));
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
}
