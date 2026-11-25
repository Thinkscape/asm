//! Google management requests use an isolated operator credential. Only a scoped,
//! verified impersonated credential is eligible for lease delivery.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asm_proto::generators::{GcloudAccessGrant, GcloudGrant, validate_gcloud_project_id};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::gcloud_cli::{AuthorizedUser, GcloudRunner};
use super::{GcloudConfig, GcloudConnectionConfig, GeneratedCredential};
use crate::error::{CoreError, Result};

#[path = "gcloud_provision.rs"]
pub(crate) mod provision;

const IDENTITY: &str = "Google account verification";
const PREFLIGHT: &str = "Google Cloud impersonation preflight";
const TOKENINFO: &str = "Google access token verification";
const PROJECT_SEARCH: &str = "Google Cloud project discovery";
const IMPERSONATE_PERMISSION: &str = "iam.serviceAccounts.getAccessToken";
const SMALL_RESPONSE: u64 = 64 * 1024;
/// Google error bodies are small; anything larger is not parsed for a message.
const ERROR_RESPONSE: u64 = 16 * 1024;
const ERROR_MESSAGE_CHARS: usize = 500;
const PROJECTS_PAGE_SIZE: usize = 100;
const PROJECTS_MAX_PAGES: usize = 100;
const PROJECTS_TIMEOUT: Duration = Duration::from_secs(30);
const PROJECTS_MAX_TOKEN_BYTES: usize = 4096;

pub(crate) const GCLOUD_SIGN_IN_REQUIRED: &str = "Google authorization expired or was revoked; sign in again";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcloudIdentity {
    pub subject: String,
    pub email: String,
}

pub(crate) struct GcloudHttp {
    client: Client,
    test_endpoint: Option<Url>,
}

pub struct GcloudGenerator {
    sdk_path: PathBuf,
    account_subject: String,
    legacy: Option<LegacyTarget>,
    adc: AuthorizedUser,
    runner: GcloudRunner,
    http: GcloudHttp,
}

struct LegacyTarget {
    project_id: String,
    ceiling: GcloudGrant,
}

impl GcloudGenerator {
    pub(crate) fn new(config: &GcloudConfig, adc_json: &str, runner: GcloudRunner) -> Result<Self> {
        Self::from_legacy(config, adc_json, runner, GcloudHttp::new()?)
    }

    pub(crate) fn new_connection(config: &GcloudConnectionConfig, adc_json: &str, runner: GcloudRunner) -> Result<Self> {
        Self::from_connection(config, adc_json, runner, GcloudHttp::new()?)
    }

    /// Explicit loopback-only test transport, never read from FFI, saved
    /// configuration, or the environment. The production runner is unchanged.
    #[doc(hidden)]
    pub fn with_endpoint_for_tests(
        config: &GcloudConfig,
        adc_json: &str,
        workspace_root: &Path,
        endpoint: Url,
    ) -> Result<Self> {
        Self::from_legacy(
            config,
            adc_json,
            GcloudRunner::new(workspace_root.to_owned())?,
            GcloudHttp::with_test_endpoint(endpoint)?,
        )
    }

    #[doc(hidden)]
    pub fn connection_with_endpoint_for_tests(
        config: &GcloudConnectionConfig,
        adc_json: &str,
        workspace_root: &Path,
        endpoint: Url,
    ) -> Result<Self> {
        Self::from_connection(
            config,
            adc_json,
            GcloudRunner::new(workspace_root.to_owned())?,
            GcloudHttp::with_test_endpoint(endpoint)?,
        )
    }

    fn from_legacy(config: &GcloudConfig, adc_json: &str, runner: GcloudRunner, http: GcloudHttp) -> Result<Self> {
        config.validate()?;
        Self::construct(&config.sdk_path, &config.account_subject, Some(LegacyTarget {
            project_id: config.project_id.clone(),
            ceiling: config.ceiling.clone(),
        }), adc_json, runner, http)
    }

    fn from_connection(config: &GcloudConnectionConfig, adc_json: &str, runner: GcloudRunner, http: GcloudHttp) -> Result<Self> {
        config.validate()?;
        Self::construct(&config.sdk_path, &config.account_subject, None, adc_json, runner, http)
    }

    fn construct(
        sdk_path: &str,
        account_subject: &str,
        legacy: Option<LegacyTarget>,
        adc_json: &str,
        runner: GcloudRunner,
        http: GcloudHttp,
    ) -> Result<Self> {
        Ok(Self {
            sdk_path: PathBuf::from(sdk_path),
            account_subject: account_subject.to_owned(),
            legacy,
            adc: AuthorizedUser::parse(adc_json)?,
            runner,
            http,
        })
    }

    pub(super) fn matches_legacy(&self, config: &GcloudConfig) -> bool {
        self.sdk_path == Path::new(&config.sdk_path)
            && self.account_subject == config.account_subject
            && self.legacy.as_ref().is_some_and(|legacy| {
                legacy.project_id == config.project_id && legacy.ceiling == config.ceiling
            })
    }

    pub(super) fn matches_connection(&self, config: &GcloudConnectionConfig) -> bool {
        self.sdk_path == Path::new(&config.sdk_path)
            && self.account_subject == config.account_subject && self.legacy.is_none()
    }

    pub(crate) fn verified_parent(&self, http: &GcloudHttp) -> Result<(String, GcloudIdentity)> {
        let token = self.runner.parent_token(&self.sdk_path, &self.adc)?;
        let identity = http.identity(&token)?;
        if identity.subject != self.account_subject { return Err(sign_in_again()); }
        Ok((token, identity))
    }

    pub fn issue(&self, grant: &GcloudGrant) -> Result<GeneratedCredential> {
        let legacy = self.legacy.as_ref()
            .ok_or_else(|| CoreError::invalid("Google connection requires an issued access profile"))?;
        if !grant.is_subset_of(&legacy.ceiling)? {
            return Err(CoreError::invalid("Google grant is outside the saved service account or scope ceiling"));
        }
        self.mint(grant.project_id.as_deref().unwrap_or(&legacy.project_id),
            &legacy.ceiling.service_account_unique_id, &grant.scopes)
    }

    /// The manager verifies the issued lease's durable profile before calling.
    /// A connection marker or a merely requested claim is not mint authority.
    pub(super) fn issue_access(&self, grant: &GcloudAccessGrant) -> Result<GeneratedCredential> {
        if self.legacy.is_some() {
            return Err(CoreError::invalid("legacy Google generators cannot issue managed access"));
        }
        let GcloudAccessGrant::Issued { access, service_account_unique_id, service_account_email } = grant else {
            return Err(CoreError::invalid("Google connection requires an issued access profile"));
        };
        grant.validate()?;
        validate_unique_id(service_account_unique_id)?;
        validate_account_email(service_account_email)?;
        self.mint(&access.project_id, service_account_unique_id, &access.scopes())
    }

    fn mint(&self, project_id: &str, unique_id: &str, scopes: &[String]) -> Result<GeneratedCredential> {
        let token = self.runner.child_token(
            &self.sdk_path,
            &self.adc,
            project_id,
            unique_id,
            scopes,
        )?;
        let expires_at = self.http.verify_child(&token, scopes)?;
        Ok(GeneratedCredential { token, expires_at })
    }
}

pub(crate) fn sign_in_again() -> CoreError {
    CoreError::unauthorized(GCLOUD_SIGN_IN_REQUIRED)
}

pub(crate) fn validate_unique_id(value: &str) -> Result<()> {
    if !value.is_empty() && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_digit()) && value.bytes().any(|b| b != b'0')
    {
        Ok(())
    } else {
        Err(CoreError::invalid("Google service account unique ID must be all decimal digits"))
    }
}

pub(crate) fn validate_account_email(value: &str) -> Result<()> {
    if value.len() <= 254 && value.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && local.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            && domain.ends_with(".gserviceaccount.com")
            && valid_hostname(domain)
    }) {
        Ok(())
    } else {
        Err(CoreError::invalid("Enter the full Google Cloud service account email address"))
    }
}

fn valid_hostname(host: &str) -> bool {
    host.len() <= 253 && host.split('.').all(|label| {
        let b = label.as_bytes();
        !b.is_empty() && b.len() <= 63 && b[0] != b'-' && b[b.len() - 1] != b'-'
            && b.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}

fn failed(operation: &str, detail: &str) -> CoreError {
    CoreError::vault_unavailable(format!("{operation} failed ({detail})"))
}

fn malformed(operation: &str) -> CoreError {
    failed(operation, "malformed or incomplete Google response")
}

fn send(request: RequestBuilder, operation: &str) -> Result<Response> {
    request.send().map_err(|error| {
        let detail = if error.is_timeout() {
            "network error: timed out"
        } else if error.is_connect() {
            "network error: could not connect"
        } else {
            "network error"
        };
        failed(operation, detail)
    })
}

/// A failed Google call, with Google's own explanation appended when its error
/// body has one. Operator diagnostics only: `VaultUnavailable` messages never
/// reach manager API clients (see `asm_proto::ApiError::from`). `sent` is the
/// credential the request carried; a message echoing it is dropped.
fn rejected(response: Response, operation: &str, detail: &str, sent: &str) -> CoreError {
    match google_message(response, sent) {
        Some(message) => failed(operation, &format!("{detail}; Google: {message}")),
        None => failed(operation, detail),
    }
}

/// `error.status: error.message` (API errors) or `error: error_description`
/// (OAuth errors), flattened to one line and capped.
fn google_message(response: Response, sent: &str) -> Option<String> {
    let mut bytes = Vec::new();
    response.take(ERROR_RESPONSE).read_to_end(&mut bytes).ok()?;
    let body: Value = serde_json::from_slice(&bytes).ok()?;
    let text = match body.get("error")? {
        Value::Object(error) => {
            let message = error.get("message").and_then(Value::as_str)?;
            match error.get("status").and_then(Value::as_str) {
                Some(status) => format!("{status}: {message}"),
                None => message.to_owned(),
            }
        }
        Value::String(code) => match body.get("error_description").and_then(Value::as_str) {
            Some(description) => format!("{code}: {description}"),
            None => code.clone(),
        },
        _ => return None,
    };
    if !sent.is_empty() && text.contains(sent) {
        return None;
    }
    let text: String = text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(ERROR_MESSAGE_CHARS)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn successful(response: Response, operation: &str, authenticated: bool, sent: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if authenticated && status == StatusCode::UNAUTHORIZED {
        return Err(sign_in_again());
    }
    if authenticated && status == StatusCode::FORBIDDEN {
        let detail = match operation {
            PREFLIGHT => "requires serviceusage.services.use on the selected project and iam.serviceAccounts.getAccessToken on the service account; check that the IAM API is enabled",
            PROJECT_SEARCH => "requires resourcemanager.projects.get to see a project; check that the Resource Manager API is enabled",
            _ => "permission denied",
        };
        return Err(rejected(response, operation, detail, sent));
    }
    Err(rejected(response, operation, &format!("HTTP {}", status.as_u16()), sent))
}

fn decode<T: DeserializeOwned>(response: Response, operation: &str, limit: u64) -> Result<T> {
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(failed(operation, "Google response is too large"));
    }
    let mut bytes = Vec::new();
    response.take(limit + 1).read_to_end(&mut bytes)
        .map_err(|_| failed(operation, "could not read Google response"))?;
    if bytes.len() as u64 > limit {
        return Err(failed(operation, "Google response is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| malformed(operation))
}

fn now() -> Result<i64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .ok_or_else(|| failed(TOKENINFO, "invalid local clock"))
}

impl GcloudHttp {
    pub(crate) fn new() -> Result<Self> {
        Self::construct(None)
    }

    pub(crate) fn with_test_endpoint(endpoint: Url) -> Result<Self> {
        if endpoint.scheme() != "http"
            || !endpoint.host_str().is_some_and(|host| {
                host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            })
            || endpoint.path() != "/" || endpoint.query().is_some() || endpoint.fragment().is_some()
            || !endpoint.username().is_empty() || endpoint.password().is_some()
        {
            return Err(CoreError::invalid("invalid isolated Google test endpoint"));
        }
        Self::construct(Some(endpoint))
    }

    fn construct(test_endpoint: Option<Url>) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(test_endpoint.is_none())
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build().map_err(|_| failed("Google Cloud connection", "HTTP client unavailable"))?;
        Ok(Self { client, test_endpoint })
    }

    fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let url = if let Some(endpoint) = &self.test_endpoint {
            let mut endpoint = endpoint.clone();
            endpoint.set_path(url.path());
            endpoint.set_query(url.query());
            endpoint
        } else {
            url
        };
        self.client.request(method, url).header(reqwest::header::ACCEPT, "application/json")
    }

    fn management(&self, method: Method, url: Url, token: &str, project: &str) -> RequestBuilder {
        self.request(method, url).bearer_auth(token).header("x-goog-user-project", project)
    }

    pub(crate) fn identity(&self, token: &str) -> Result<GcloudIdentity> {
        let url = endpoint("https://openidconnect.googleapis.com/v1/userinfo");
        let response = send(self.request(Method::GET, url).bearer_auth(token), IDENTITY)?;
        let user: UserInfo = decode(successful(response, IDENTITY, true, token)?, IDENTITY, SMALL_RESPONSE)?;
        if !user.email_verified {
            return Err(failed(IDENTITY, "Google account email is not verified"));
        }
        if !identity_text(&user.sub) || !identity_text(&user.email)
            || !user.email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && !domain.is_empty() && !domain.contains('@')
            })
        {
            return Err(malformed(IDENTITY));
        }
        Ok(GcloudIdentity { subject: user.sub, email: user.email })
    }

    /// Search across the signed-in user's visibility, not a caller-selected quota
    /// project. The returned IDs only establish what Google reported as active;
    /// they do not establish permission to change any project's IAM.
    pub(crate) fn active_projects(&self, token: &str) -> Result<Vec<String>> {
        let deadline = Instant::now() + PROJECTS_TIMEOUT;
        let mut seen_tokens = HashSet::new();
        let mut projects = BTreeMap::new();
        let page_size = PROJECTS_PAGE_SIZE.to_string();
        let mut base = endpoint("https://cloudresourcemanager.googleapis.com/v3/projects:search");
        base.query_pairs_mut().extend_pairs([
            ("query", "state:ACTIVE"),
            ("pageSize", page_size.as_str()),
            ("fields", "projects(projectId,state),nextPageToken"),
        ]);
        let mut url = base.clone();
        for _ in 0..PROJECTS_MAX_PAGES {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(failed(PROJECT_SEARCH, "project search timed out"));
            }
            let request = self.request(Method::GET, url).bearer_auth(token).timeout(remaining);
            let response = send(request, PROJECT_SEARCH)?;
            let page: SearchProjectsPage = decode(
                successful(response, PROJECT_SEARCH, true, token)?, PROJECT_SEARCH, SMALL_RESPONSE,
            )?;
            if page.projects.len() > PROJECTS_PAGE_SIZE {
                return Err(malformed(PROJECT_SEARCH));
            }
            for project in page.projects {
                validate_gcloud_project_id(&project.project_id).map_err(|_| malformed(PROJECT_SEARCH))?;
                if projects.insert(project.project_id, project.state).is_some_and(|previous| previous != project.state) {
                    return Err(malformed(PROJECT_SEARCH));
                }
            }
            let cursor = page.next_page_token;
            if cursor.is_empty() {
                return Ok(projects.into_iter()
                    .filter_map(|(id, state)| (state == ProjectState::Active).then_some(id))
                    .collect());
            }
            if cursor.len() > PROJECTS_MAX_TOKEN_BYTES || !identity_text(&cursor) {
                return Err(malformed(PROJECT_SEARCH));
            }
            url = base.clone();
            url.query_pairs_mut().append_pair("pageToken", &cursor);
            if !seen_tokens.insert(cursor) {
                return Err(failed(PROJECT_SEARCH, "Google returned a repeated page token"));
            }
        }
        Err(failed(PROJECT_SEARCH, "Google project search exceeded the page limit"))
    }

    pub(crate) fn preflight(&self, token: &str, project_id: &str, unique_id: &str) -> Result<()> {
        validate_gcloud_project_id(project_id)?;
        validate_unique_id(unique_id)?;
        let url = endpoint(&format!("https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{unique_id}:testIamPermissions"));
        let request = self.management(Method::POST, url, token, project_id)
            .json(&json!({ "permissions": [IMPERSONATE_PERMISSION] }));
        let response = send(request, PREFLIGHT)?;
        let result: TestPermissions = decode(successful(response, PREFLIGHT, true, token)?, PREFLIGHT, SMALL_RESPONSE)?;
        if !result.permissions.iter().any(|permission| permission == IMPERSONATE_PERMISSION) {
            return Err(failed(PREFLIGHT, "ask an administrator to grant iam.serviceAccounts.getAccessToken on this service account (commonly Service Account Token Creator)"));
        }
        Ok(())
    }

    fn verify_child(&self, token: &str, approved: &[String]) -> Result<i64> {
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(failed(TOKENINFO, "malformed access token"));
        }
        let url = endpoint("https://www.googleapis.com/oauth2/v1/tokeninfo");
        let request = self.request(Method::POST, url).form(&[("access_token", token)]);
        let before = now()?;
        let response = send(request, TOKENINFO)?;
        let info: TokenInfo = decode(successful(response, TOKENINFO, false, token)?, TOKENINFO, SMALL_RESPONSE)?;
        let mut reported: Vec<_> = info.scope.split(' ').collect();
        reported.sort_unstable();
        reported.dedup();
        if !reported.into_iter().eq(approved.iter().map(String::as_str)) {
            return Err(failed(TOKENINFO, "Google returned scopes different from the approved scopes"));
        }
        if !(1..=3660).contains(&info.expires_in) {
            return Err(failed(TOKENINFO, "invalid credential expiry"));
        }
        let expires_at = before.checked_add(info.expires_in - 1)
            .ok_or_else(|| failed(TOKENINFO, "invalid credential expiry"))?;
        if expires_at <= now()? {
            return Err(failed(TOKENINFO, "credential already expired"));
        }
        Ok(expires_at)
    }
}

fn endpoint(url: &str) -> Url {
    Url::parse(url).expect("locally constructed Google API endpoint")
}

fn identity_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: String,
    email_verified: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchProjectsPage {
    #[serde(default)]
    projects: Vec<SearchProject>,
    #[serde(default)]
    next_page_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchProject {
    project_id: String,
    state: ProjectState,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProjectState {
    Active,
    DeleteRequested,
    StateUnspecified,
}

#[derive(Deserialize)]
struct TestPermissions {
    #[serde(default)]
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct TokenInfo {
    scope: String,
    expires_in: i64,
}

#[cfg(test)]
#[path = "gcloud_tests.rs"]
mod tests;
