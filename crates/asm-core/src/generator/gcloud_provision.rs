//! The local admin review owns authorization to mutate Google resources. These
//! operations constrain each effect to that review and never adopt by name.

use asm_proto::generators::{GcloudAccessRequest, validate_gcloud_project_id};
use base64::{Engine, engine::general_purpose};
use reqwest::blocking::Response;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};

use super::{
    GcloudHttp, GcloudIdentity, decode, endpoint, failed, identity_text,
    malformed, send, sign_in_again, successful, valid_hostname, validate_unique_id,
};
use crate::error::{CoreError, Result};

const CREATE_ACCOUNT: &str = "Google Cloud profile service account creation";
const GET_ACCOUNT: &str = "Google Cloud profile service account verification";
const DELETE_ACCOUNT: &str = "Google Cloud profile service account deletion";
const GET_PROJECT_POLICY: &str = "Google Cloud project IAM policy verification";
const SET_PROJECT_POLICY: &str = "Google Cloud project IAM policy update";
const GET_ACCOUNT_POLICY: &str = "Google Cloud service account IAM policy verification";
const SET_ACCOUNT_POLICY: &str = "Google Cloud service account IAM policy update";
pub(crate) const TOKEN_CREATOR: &str = "roles/iam.serviceAccountTokenCreator";
const ACCOUNT_RESPONSE: u64 = 64 * 1024;
const POLICY_RESPONSE: u64 = 2 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct ProvisionedAccount {
    pub(crate) unique_id: String,
    pub(crate) email: String,
}

impl GcloudHttp {
    pub(crate) fn create_profile_account(
        &self,
        token: &str,
        project_id: &str,
        account_id: &str,
    ) -> Result<ProvisionedAccount> {
        validate_gcloud_project_id(project_id)?;
        validate_account_id(account_id)?;
        let email = format!("{account_id}@{project_id}.iam.gserviceaccount.com");
        let url = endpoint(&format!("https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"));
        let response = send(
            self.management(Method::POST, url, token, project_id).json(&json!({
                "accountId": account_id,
                "serviceAccount": {"displayName": "ASM access profile"},
            })),
            CREATE_ACCOUNT,
        )?;
        if response.status() == StatusCode::CONFLICT {
            return Err(failed(CREATE_ACCOUNT, "the account name already exists; ASM did not adopt it"));
        }
        let account: ProfileAccountResponse = decode(
            authorized(response, CREATE_ACCOUNT, "iam.serviceAccounts.create")?,
            CREATE_ACCOUNT,
            ACCOUNT_RESPONSE,
        )?;
        account.checked(project_id, &email, &account.unique_id, CREATE_ACCOUNT)?;
        Ok(ProvisionedAccount {
            unique_id: account.unique_id,
            email: account.email,
        })
    }

    pub(crate) fn verify_profile_account(
        &self,
        token: &str,
        project_id: &str,
        unique_id: &str,
        email: &str,
    ) -> Result<()> {
        self.verify_pinned_account(token, PinnedAccount::new(project_id, unique_id, email)?)
    }

    /// Only the manager's journal may supply this target. Once deletion or
    /// absence is confirmed, prune only project-policy entries whose deleted
    /// principal proves the same immutable ID, never live email principals.
    pub(crate) fn delete_profile_account(
        &self,
        token: &str,
        access: &GcloudAccessRequest,
        unique_id: &str,
        email: &str,
        identity: &GcloudIdentity,
        mut before_write: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        access.validate()?;
        let account = PinnedAccount::new(&access.project_id, unique_id, email)?;
        validate_human(identity)?;
        if self.identity(token)? != *identity {
            return Err(sign_in_again());
        }

        let response = self.get_pinned_account(token, account)?;
        if response.status() == StatusCode::NOT_FOUND {
            confirm_not_found(response, GET_ACCOUNT)?;
        } else {
            let response = authorized(response, GET_ACCOUNT, "iam.serviceAccounts.get")?;
            if response.status() != StatusCode::OK {
                return Err(malformed(GET_ACCOUNT));
            }
            let current: ProfileAccountResponse = decode(response, GET_ACCOUNT, ACCOUNT_RESPONSE)?;
            // Disabled accounts cannot issue, but are still safe to delete.
            current.check_identity(account.project_id, account.email, account.unique_id, GET_ACCOUNT)?;
            let request = self.management(Method::DELETE, account.url(""), token, account.project_id);
            before_write()?;
            let response = send(request, DELETE_ACCOUNT)?;
            if response.status() == StatusCode::NOT_FOUND {
                confirm_not_found(response, DELETE_ACCOUNT)?;
            } else {
                let response = authorized(response, DELETE_ACCOUNT, "iam.serviceAccounts.delete")?;
                // IAM documents HTTP 200 with an empty JSON object. Anything
                // else leaves the operation pending for an explicit retry.
                if response.status() != StatusCode::OK
                    || !decode::<Map<String, Value>>(response, DELETE_ACCOUNT, ACCOUNT_RESPONSE)?.is_empty()
                {
                    return Err(malformed(DELETE_ACCOUNT));
                }
            }
        }

        let target = PolicyTarget::Project(account.project_id);
        let mut policy = self.read_profile_policy(token, target)?;
        let member = format!("deleted:serviceAccount:{}?uid={}", account.email, account.unique_id);
        if !policy.remove_deleted_profile_member(access, &member) {
            return Ok(());
        }
        if self.identity(token)? != *identity {
            return Err(sign_in_again());
        }
        let applied = self.write_profile_policy(token, target, policy, before_write)?;
        if applied.bindings.iter().any(|binding| {
            binding.profile_role(access) && binding.members.iter().any(|candidate| candidate == &member)
        }) {
            return Err(failed(SET_PROJECT_POLICY, "Google did not confirm removal of the deleted profile principal"));
        }
        Ok(())
    }

    pub(crate) fn apply_profile_project_roles(
        &self,
        token: &str,
        access: &GcloudAccessRequest,
        unique_id: &str,
        email: &str,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        access.validate()?;
        let account = PinnedAccount::new(&access.project_id, unique_id, email)?;
        let member = format!("serviceAccount:{email}");
        let target = PolicyTarget::Project(account.project_id);
        let mut policy = self.read_profile_policy(token, target)?;
        let found = policy.project_roles(access, account, &member)?;
        // Check the immutable ID after reading the policy, as close as possible
        // to the write. IAM allow-policy membership itself is written by email.
        self.verify_pinned_account(token, account)?;
        if all_project_roles_found(access, found) {
            return Ok(());
        }
        for (index, permission) in access.permissions.iter().enumerate() {
            if found & (1 << index) == 0 {
                policy.add_member(permission.role(), &member);
            }
        }
        let applied = self.write_profile_policy(token, target, policy, before_write)?;
        require_project_roles(&applied, access, account, &member)
    }

    pub(crate) fn apply_profile_token_creator(
        &self,
        token: &str,
        project_id: &str,
        unique_id: &str,
        email: &str,
        identity: &GcloudIdentity,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let account = PinnedAccount::new(project_id, unique_id, email)?;
        let member = human_member(identity)?;
        let target = PolicyTarget::Account(account);
        let mut policy = self.read_profile_policy(token, target)?;
        let present = policy.token_creator(&member)?;
        self.verify_pinned_account(token, account)?;
        if present {
            return Ok(());
        }
        policy.add_member(TOKEN_CREATOR, &member);
        if self.identity(token)? != *identity {
            return Err(sign_in_again());
        }
        let applied = self.write_profile_policy(token, target, policy, before_write)?;
        require_token_creator(&applied, &member)
    }

    pub(crate) fn verify_profile_project_roles(
        &self,
        token: &str,
        access: &GcloudAccessRequest,
        unique_id: &str,
        email: &str,
    ) -> Result<()> {
        access.validate()?;
        let account = PinnedAccount::new(&access.project_id, unique_id, email)?;
        self.verify_pinned_account(token, account)?;
        self.check_project_roles(token, access, account)
    }

    pub(crate) fn verify_profile_token_creator(
        &self,
        token: &str,
        project_id: &str,
        unique_id: &str,
        email: &str,
        identity: &GcloudIdentity,
    ) -> Result<()> {
        let account = PinnedAccount::new(project_id, unique_id, email)?;
        let member = human_member(identity)?;
        self.verify_pinned_account(token, account)?;
        self.check_token_creator(token, account, &member)
    }

    /// Verify direct IAM bindings and pinned account identity, not effective
    /// permissions through inheritance, groups, principal sets, or other resources.
    /// `identity` must already have been verified from this same parent token.
    pub(crate) fn verify_profile_ready(
        &self,
        token: &str,
        access: &GcloudAccessRequest,
        unique_id: &str,
        email: &str,
        identity: &GcloudIdentity,
    ) -> Result<()> {
        access.validate()?;
        let account = PinnedAccount::new(&access.project_id, unique_id, email)?;
        let member = human_member(identity)?;
        self.verify_pinned_account(token, account)?;
        self.check_project_roles(token, access, account)?;
        self.check_token_creator(token, account, &member)
    }

    fn get_pinned_account(&self, token: &str, account: PinnedAccount<'_>) -> Result<Response> {
        send(
            self.management(Method::GET, account.url(""), token, account.project_id),
            GET_ACCOUNT,
        )
    }

    fn verify_pinned_account(&self, token: &str, account: PinnedAccount<'_>) -> Result<()> {
        let response = self.get_pinned_account(token, account)?;
        let current: ProfileAccountResponse = decode(
            authorized(response, GET_ACCOUNT, "iam.serviceAccounts.get")?,
            GET_ACCOUNT,
            ACCOUNT_RESPONSE,
        )?;
        current.checked(account.project_id, account.email, account.unique_id, GET_ACCOUNT)
    }

    fn check_project_roles(
        &self,
        token: &str,
        access: &GcloudAccessRequest,
        account: PinnedAccount<'_>,
    ) -> Result<()> {
        let policy = self.read_profile_policy(token, PolicyTarget::Project(account.project_id))?;
        require_project_roles(&policy, access, account, &format!("serviceAccount:{}", account.email))
    }

    fn check_token_creator(&self, token: &str, account: PinnedAccount<'_>, member: &str) -> Result<()> {
        let policy = self.read_profile_policy(token, PolicyTarget::Account(account))?;
        require_token_creator(&policy, member)
    }

    fn read_profile_policy(&self, token: &str, target: PolicyTarget<'_>) -> Result<IamPolicy> {
        let mut url = target.url(":getIamPolicy");
        let (operation, permission, request) = match target {
            PolicyTarget::Project(project) => (
                GET_PROJECT_POLICY,
                "resourcemanager.projects.getIamPolicy",
                self.management(Method::POST, url, token, project)
                    .json(&json!({"options": {"requestedPolicyVersion": 3}})),
            ),
            PolicyTarget::Account(account) => {
                // Unlike Resource Manager, IAM v1 expects a query and no body. Google's
                // front end answers a bodyless POST without Content-Length with HTTP 411.
                url.query_pairs_mut().append_pair("options.requestedPolicyVersion", "3");
                (
                    GET_ACCOUNT_POLICY,
                    "iam.serviceAccounts.getIamPolicy",
                    self.management(Method::POST, url, token, account.project_id)
                        .header(reqwest::header::CONTENT_LENGTH, 0),
                )
            }
        };
        parse_policy(send(request, operation)?, operation, permission)
    }

    fn write_profile_policy(
        &self,
        token: &str,
        target: PolicyTarget<'_>,
        mut policy: IamPolicy,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<IamPolicy> {
        let (operation, permission) = match target {
            PolicyTarget::Project(_) => (SET_PROJECT_POLICY, "resourcemanager.projects.setIamPolicy"),
            PolicyTarget::Account(_) => (SET_ACCOUNT_POLICY, "iam.serviceAccounts.setIamPolicy"),
        };
        policy.version = Some(3);
        let request = self.management(Method::POST, target.url(":setIamPolicy"), token, target.project())
            .json(&SetPolicy { policy: &policy, update_mask: "bindings,etag" });
        before_write()?;
        let response = send(request, operation)?;
        if matches!(response.status(), StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED) {
            return Err(failed(operation, "the IAM policy changed concurrently; no retry was attempted"));
        }
        parse_policy(response, operation, permission)
    }
}

fn validate_account_id(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        Ok(())
    } else {
        Err(CoreError::invalid("Invalid planned Google Cloud service account ID"))
    }
}

#[derive(Clone, Copy)]
struct PinnedAccount<'a> {
    project_id: &'a str,
    unique_id: &'a str,
    email: &'a str,
}

impl<'a> PinnedAccount<'a> {
    fn new(project_id: &'a str, unique_id: &'a str, email: &'a str) -> Result<Self> {
        validate_gcloud_project_id(project_id)?;
        validate_unique_id(unique_id)?;
        let (account_id, domain) = email.split_once('@')
            .ok_or_else(|| CoreError::invalid("Invalid Google Cloud profile service account email"))?;
        if domain.strip_suffix(".iam.gserviceaccount.com") != Some(project_id) {
            return Err(CoreError::invalid("The profile service account must belong to the approved Google Cloud project"));
        }
        validate_account_id(account_id)?;
        Ok(Self { project_id, unique_id, email })
    }

    fn url(self, suffix: &str) -> Url {
        endpoint(&format!("https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}{suffix}", self.project_id, self.unique_id))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileAccountResponse {
    name: String,
    project_id: String,
    unique_id: String,
    email: String,
    #[serde(default)]
    disabled: bool,
}

impl ProfileAccountResponse {
    fn checked(&self, project: &str, email: &str, unique_id: &str, operation: &str) -> Result<()> {
        self.check_identity(project, email, unique_id, operation)?;
        if self.disabled {
            return Err(failed(operation, "the profile service account is disabled"));
        }
        Ok(())
    }

    fn check_identity(&self, project: &str, email: &str, unique_id: &str, operation: &str) -> Result<()> {
        let resource = self.name.strip_prefix("projects/").and_then(|s| s.split_once("/serviceAccounts/"));
        if self.project_id != project || self.email != email || self.unique_id != unique_id
            || validate_unique_id(&self.unique_id).is_err()
            || !resource.is_some_and(|(p, id)| p == project && (id == email || id == unique_id))
        {
            return Err(failed(operation, "Google did not confirm the planned service account identity"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PolicyTarget<'a> {
    Project(&'a str),
    Account(PinnedAccount<'a>),
}

impl<'a> PolicyTarget<'a> {
    fn project(self) -> &'a str {
        match self {
            Self::Project(project) => project,
            Self::Account(account) => account.project_id,
        }
    }

    fn url(self, suffix: &str) -> Url {
        match self {
            Self::Project(project) => endpoint(&format!("https://cloudresourcemanager.googleapis.com/v3/projects/{project}{suffix}")),
            Self::Account(account) => account.url(suffix),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetPolicy<'a> {
    policy: &'a IamPolicy,
    update_mask: &'static str,
}

#[derive(Deserialize, Serialize)]
struct IamPolicy {
    version: Option<u8>,
    etag: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bindings: Vec<IamBinding>,
    // Send audit configuration and unrecognized fields back unmodified. The
    // update mask also limits which top-level fields Google may change.
    #[serde(flatten)]
    other: Map<String, Value>,
}

#[derive(Deserialize, Serialize)]
struct IamBinding {
    role: String,
    members: Vec<String>,
    #[serde(default, deserialize_with = "condition_present", skip_serializing_if = "Option::is_none")]
    condition: Option<IamCondition>,
    #[serde(flatten)]
    other: Map<String, Value>,
}

impl IamBinding {
    fn conditional(&self) -> bool {
        self.condition.is_some()
    }

    fn profile_role(&self, access: &GcloudAccessRequest) -> bool {
        !self.conditional() && access.permissions.iter().any(|permission| permission.role() == self.role)
    }
}

#[derive(Deserialize, Serialize)]
struct IamCondition {
    expression: String,
    #[serde(flatten)]
    other: Map<String, Value>,
}

fn condition_present<'de, D: Deserializer<'de>>(decoder: D) -> std::result::Result<Option<IamCondition>, D::Error> {
    IamCondition::deserialize(decoder).map(Some)
}

impl IamPolicy {
    fn validate(&self, operation: &str) -> Result<()> {
        let mut etag_bytes = [0; 256];
        let valid_etag = [
            &general_purpose::STANDARD,
            &general_purpose::STANDARD_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::URL_SAFE_NO_PAD,
        ].iter().any(|engine| engine.decode_slice(&self.etag, &mut etag_bytes).is_ok_and(|n| n > 0));
        // Google may return version 1 (or omit version/bindings for an empty
        // policy) when version 3 was requested but there are no conditions.
        if !valid_etag || !matches!(self.version, None | Some(0 | 1 | 3))
            || self.other.get("auditConfigs").is_some_and(|v| !v.is_array())
            || self.bindings.iter().any(|binding| {
                !identity_text(&binding.role) || binding.role.contains("_withcond_")
                    || binding.members.is_empty() || binding.members.iter().any(|member| {
                        member.is_empty() || member.trim() != member || member.chars().any(char::is_control)
                    }) || binding.condition.as_ref().is_some_and(|condition| {
                        self.version != Some(3) || condition.expression.trim().is_empty()
                    })
            })
        {
            return Err(malformed(operation));
        }
        Ok(())
    }

    fn project_roles(&self, access: &GcloudAccessRequest, account: PinnedAccount<'_>, member: &str) -> Result<u64> {
        let drift = || failed(GET_PROJECT_POLICY, "the profile service account has an unexpected, duplicate, or conditional direct project binding");
        let mut found = 0u64;
        for binding in &self.bindings {
            let mut exact = false;
            for candidate in &binding.members {
                if candidate.eq_ignore_ascii_case(member) {
                    if candidate != member || exact {
                        return Err(drift());
                    }
                    exact = true;
                } else if candidate.strip_prefix("deleted:").and_then(|p| p.split_once("?uid="))
                    .is_some_and(|(principal, id)| principal.eq_ignore_ascii_case(member) && id == account.unique_id)
                {
                    return Err(drift());
                }
            }
            if !exact { continue; }
            let index = access.permissions.iter().position(|permission| permission.role() == binding.role)
                .ok_or_else(drift)?;
            let bit = 1u64.checked_shl(index as u32).ok_or_else(drift)?;
            if binding.conditional() || found & bit != 0 {
                return Err(drift());
            }
            found |= bit;
        }
        Ok(found)
    }

    fn remove_deleted_profile_member(&mut self, access: &GcloudAccessRequest, member: &str) -> bool {
        let mut changed = false;
        self.bindings.retain_mut(|binding| {
            if binding.profile_role(access) {
                let previous = binding.members.len();
                binding.members.retain(|candidate| candidate != member);
                changed |= previous != binding.members.len();
            }
            !binding.members.is_empty()
        });
        changed
    }

    fn token_creator(&self, member: &str) -> Result<bool> {
        let mut found = false;
        for binding in self.bindings.iter().filter(|binding| binding.role == TOKEN_CREATOR) {
            for candidate in &binding.members {
                if candidate.eq_ignore_ascii_case(member) {
                    if candidate != member || found || binding.conditional() {
                        return Err(failed(GET_ACCOUNT_POLICY, "the verified Google account has an unexpected, duplicate, or conditional Token Creator binding"));
                    }
                    found = true;
                }
            }
        }
        Ok(found)
    }

    fn add_member(&mut self, role: &str, member: &str) {
        if let Some(binding) = self.bindings.iter_mut().find(|b| b.role == role && !b.conditional()) {
            binding.members.push(member.to_owned());
        } else {
            self.bindings.push(IamBinding {
                role: role.to_owned(),
                members: vec![member.to_owned()],
                condition: None,
                other: Map::new(),
            });
        }
    }
}

fn all_project_roles_found(access: &GcloudAccessRequest, found: u64) -> bool {
    found.count_ones() as usize == access.permissions.len()
}

fn require_project_roles(policy: &IamPolicy, access: &GcloudAccessRequest, account: PinnedAccount<'_>, member: &str) -> Result<()> {
    if all_project_roles_found(access, policy.project_roles(access, account, member)?) {
        Ok(())
    } else {
        Err(failed(GET_PROJECT_POLICY, "the profile service account is missing an approved direct project binding"))
    }
}

fn require_token_creator(policy: &IamPolicy, member: &str) -> Result<()> {
    if policy.token_creator(member)? {
        Ok(())
    } else {
        Err(failed(GET_ACCOUNT_POLICY, "the verified Google account is missing the approved Token Creator binding"))
    }
}

fn validate_human(identity: &GcloudIdentity) -> Result<()> {
    if !identity_text(&identity.subject) || identity.email.len() > 254
        || !identity.email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && valid_hostname(domain) && !domain.ends_with(".gserviceaccount.com")
                && local.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
        })
    {
        return Err(CoreError::invalid("Invalid verified Google account identity for a profile"));
    }
    Ok(())
}

fn human_member(identity: &GcloudIdentity) -> Result<String> {
    validate_human(identity)?;
    Ok(format!("user:{}", identity.email))
}

fn confirm_not_found(response: Response, operation: &str) -> Result<()> {
    #[derive(Deserialize)]
    struct ResponseBody {
        error: GoogleError,
    }
    #[derive(Deserialize)]
    struct GoogleError {
        code: u16,
        status: String,
        message: String,
    }

    // A generic HTTP 404 (e.g. an intermediary page) is not evidence of
    // absence. The authenticated project-qualified IAM endpoint must also
    // return its structured NOT_FOUND error, never parsed for display text.
    let body: ResponseBody = decode(response, operation, ACCOUNT_RESPONSE)?;
    if body.error.code != 404 || body.error.status != "NOT_FOUND" || body.error.message.trim().is_empty() {
        return Err(malformed(operation));
    }
    Ok(())
}

fn authorized(response: Response, operation: &str, permission: &str) -> Result<Response> {
    if response.status() == StatusCode::FORBIDDEN {
        return Err(failed(operation, &format!("requires {permission} and serviceusage.services.use on the selected project; check that its APIs are enabled")));
    }
    successful(response, operation, true)
}

fn parse_policy(response: Response, operation: &str, permission: &str) -> Result<IamPolicy> {
    let policy: IamPolicy = decode(authorized(response, operation, permission)?, operation, POLICY_RESPONSE)?;
    policy.validate(operation)?;
    Ok(policy)
}

#[cfg(test)]
#[path = "gcloud_provision_tests.rs"]
mod tests;
