//! GitHub.com installation credentials. Root credentials are never sent through
//! the substitution proxy, and every agent token is checked against its full grant.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asm_proto::generators::{GithubGrant, GithubPermission, GithubRepository, normalize_repository_name};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use jwt_sha2::Sha256;
use reqwest::blocking::{Client, ClientBuilder, RequestBuilder, Response};
use reqwest::{Method, Url};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::{GeneratedCredential, GithubAppConfig, GithubInstallation, GithubInstallationAccount};
use crate::error::{CoreError, Result};

const API_BASE: &str = "https://api.github.com/";
const API_VERSION: &str = "2026-03-10";
const GENERATE: &str = "GitHub token generation";
const CONNECT: &str = "GitHub installation connection";
const LIST_INSTALLATIONS: &str = "GitHub installation discovery";
const DISCOVER: &str = "GitHub repository discovery";
const REVOKE: &str = "GitHub token revocation";
const LISTING_CHANGED: &str = "GitHub repository listing changed or was incomplete; reconnect";
const OUTSIDE_SCOPE: &str = "GitHub returned a token outside the approved scope";
const PER_PAGE: usize = 100;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Concrete adapter, not a VaultProvider. The parsed signer and HTTP client are
/// reused for this live configuration; neither its root key nor JWT is persisted.
pub struct GithubAppGenerator {
    config: GithubAppConfig,
    signer: SigningKey<Sha256>,
    client: Client,
    base_url: Url,
}

#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    repository_ids: RepositoryIds<'a>,
    permissions: &'a BTreeMap<String, GithubPermission>,
}

struct RepositoryIds<'a>(&'a [GithubRepository]);

impl Serialize for RepositoryIds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|repository| repository.id))
    }
}

#[derive(Serialize)]
struct DiscoveryRequest {
    permissions: DiscoveryPermissions,
}

#[derive(Serialize)]
struct DiscoveryPermissions {
    metadata: GithubPermission,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn failed(operation: &str, detail: &str) -> CoreError {
    CoreError::vault_unavailable(format!("{operation} failed ({detail})"))
}

fn scope_error() -> CoreError {
    CoreError::vault_unavailable(OUTSIDE_SCOPE)
}

fn signing_key(pem: &str) -> Result<SigningKey<Sha256>> {
    let invalid = || CoreError::invalid("GitHub private key must be a valid RSA PEM key of at least 2048 bits");
    // jsonwebtoken accepts both GitHub's PKCS#1 keys and PKCS#8 PEM, normalizing
    // them to PKCS#1 DER. Retain the actual parsed key, not just the DER buffer:
    // jsonwebtoken::encode would parse that buffer again for every signature.
    let encoded = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|_| invalid())?;
    let mut key = rsa::PrivateKey::from_pkcs1_der(encoded.as_bytes()).map_err(|_| invalid())?;
    key.validate().map_err(|_| invalid())?;
    if key.n().bit_width() < 2048 {
        return Err(invalid());
    }
    key.precompute().map_err(|_| invalid())?;
    Ok(SigningKey::new(key))
}

/// Pure local validation; no credential-store access and no network request.
pub fn validate_private_key(pem: &str) -> Result<()> {
    signing_key(pem).map(|_| ())
}

impl GithubAppGenerator {
    /// Fixed GitHub.com endpoint and private, non-proxied transport.
    pub fn new(config: &GithubAppConfig, pem: &str) -> Result<Self> {
        config.validate()?;
        Self::direct(config.clone(), pem)
    }

    pub(crate) fn for_discovery(client_id: String, pem: &str) -> Result<Self> {
        GithubAppConfig::validate_client_id(&client_id)?;
        Self::direct(GithubAppConfig { client_id, installations: Vec::new() }, pem)
    }

    fn direct(config: GithubAppConfig, pem: &str) -> Result<Self> {
        Self::construct(config, pem, Self::client_builder().https_only(true)
            .build().map_err(|_| failed(CONNECT, "HTTP client unavailable"))?,
            Url::parse(API_BASE).expect("constant GitHub API URL"))
    }

    fn client_builder() -> ClientBuilder {
        // reqwest's rustls-no-provider mode does not infer ring from Cargo
        // features. Direct construction must work before Core::start, too.
        // An existing provider wins; concurrent installation is idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(TOTAL_TIMEOUT)
    }

    /// Rust-only isolated-test seam. Never used by stored configuration, FFI or
    /// environment variables. Callers control this injected transport explicitly.
    #[doc(hidden)]
    pub fn with_client_for_tests(
        config: &GithubAppConfig,
        pem: &str,
        client: Client,
        base_url: Url,
    ) -> Result<Self> {
        if !matches!(base_url.scheme(), "http" | "https")
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(CoreError::invalid("invalid isolated GitHub test endpoint"));
        }
        config.validate()?;
        Self::construct(config.clone(), pem, client, base_url)
    }

    fn construct(config: GithubAppConfig, pem: &str, client: Client, base_url: Url) -> Result<Self> {
        Ok(Self { config, signer: signing_key(pem)?, client, base_url })
    }

    pub(crate) fn matches_config(&self, config: &GithubAppConfig) -> bool {
        &self.config == config
    }

    fn jwt(&self) -> Result<String> {
        let now = now();
        let header = serde_json::to_vec(&Header::new(Algorithm::RS256))
            .map_err(|_| failed(CONNECT, "JWT encoding error"))?;
        let claims = serde_json::to_vec(&Claims {
            iat: now - 60,
            exp: now + 600,
            iss: &self.config.client_id,
        }).map_err(|_| failed(CONNECT, "JWT encoding error"))?;
        let mut message = URL_SAFE_NO_PAD.encode(header);
        message.push('.');
        URL_SAFE_NO_PAD.encode_string(claims, &mut message);
        let signature = self.signer.try_sign(message.as_bytes())
            .map_err(|_| failed(CONNECT, "JWT signing error"))?;
        message.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.to_bytes(), &mut message);
        Ok(message)
    }

    fn request(&self, method: Method, path: &str, bearer: &str) -> RequestBuilder {
        let url = self.base_url.join(path).expect("locally constructed GitHub path");
        self.client.request(method, url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header(reqwest::header::USER_AGENT, concat!("asm/", env!("CARGO_PKG_VERSION")))
            .bearer_auth(bearer)
    }

    fn send(request: RequestBuilder, operation: &str) -> Result<Response> {
        let response = request.send().map_err(|_| failed(operation, "network error"))?;
        if !response.status().is_success() {
            return Err(failed(operation, &format!("HTTP {}", response.status().as_u16())));
        }
        Ok(response)
    }

    fn json(request: RequestBuilder, operation: &str) -> Result<Value> {
        Self::send(request, operation)?.json().map_err(|_| failed(operation, "invalid response"))
    }

    fn create_token(&self, installation_id: u64, jwt: &str, body: &impl Serialize, operation: &str) -> Result<Value> {
        Self::json(self.request(Method::POST,
            &format!("app/installations/{installation_id}/access_tokens"), jwt)
            .json(body), operation)
    }

    /// The app JWT lists installation accounts without minting an installation token.
    pub fn list_installations(&self) -> Result<Vec<GithubInstallationAccount>> {
        let jwt = self.jwt()?;
        let malformed = || failed(LIST_INSTALLATIONS, "invalid installation listing");
        let mut accounts = Vec::new();
        let mut seen = BTreeSet::new();
        let mut page = 1u64;
        loop {
            let response = Self::send(self.request(Method::GET,
                &format!("app/installations?per_page={PER_PAGE}&page={page}"), &jwt), LIST_INSTALLATIONS)?;
            // Use Link only as a pagination hint; never send a JWT to a URL
            // supplied by a response.
            let has_next = response.headers().get_all(reqwest::header::LINK).iter()
                .filter_map(|header| header.to_str().ok())
                .flat_map(|header| header.split(','))
                .any(|link| link.split(';').skip(1).any(|param| param.trim() == "rel=\"next\""));
            let items: Vec<Value> = response.json().map_err(|_| malformed())?;
            if items.len() > PER_PAGE || (items.is_empty() && has_next) {
                return Err(malformed());
            }
            let count = items.len();
            for item in items {
                let (installation_id, account) = installation_account(&item).ok_or_else(malformed)?;
                if !seen.insert(installation_id) {
                    return Err(malformed());
                }
                accounts.push(GithubInstallationAccount { installation_id, account: account.to_owned() });
            }
            if count < PER_PAGE && !has_next {
                accounts.sort_unstable_by_key(|account| account.installation_id);
                return Ok(accounts);
            }
            page = page.checked_add(1).ok_or_else(malformed)?;
        }
    }

    /// Verify the installation and discover current stable repository IDs. The
    /// metadata-only discovery token is never returned, cached or persisted.
    pub fn connect(&self, installation_id: u64) -> Result<GithubInstallation> {
        if installation_id == 0 {
            return Err(CoreError::invalid("GitHub installation ID must be positive"));
        }
        self.connect_with_app_jwt(installation_id, &self.jwt()?)
    }

    fn connect_with_app_jwt(&self, installation_id: u64, jwt: &str) -> Result<GithubInstallation> {
        let installation = Self::json(self.request(Method::GET,
            &format!("app/installations/{installation_id}"), jwt), CONNECT)?;
        let malformed = || failed(CONNECT, "invalid installation response");
        let (returned_id, account_login) = installation_account(&installation).ok_or_else(malformed)?;
        if returned_id != installation_id {
            return Err(malformed());
        }
        // A missing suspension field is not proof that an installation is active.
        match installation.get("suspended_at") {
            Some(Value::Null) => {}
            Some(_) => return Err(failed(CONNECT, "installation is suspended")),
            None => return Err(malformed()),
        }
        let account_login = account_login.to_owned();
        let permissions = permissions(installation.get("permissions")).map_err(|_| malformed())?;
        let mut response = self.create_token(installation_id, jwt, &DiscoveryRequest {
            permissions: DiscoveryPermissions { metadata: GithubPermission::Read },
        }, DISCOVER)?;
        let token = take_token(&mut response).ok_or_else(|| failed(DISCOVER, "invalid token response"))?;
        let expires_at = expiry(response.get("expires_at"));
        let discovered = (|| {
            let expires_at = expires_at.filter(|expiry| *expiry > now())
                .ok_or_else(|| failed(DISCOVER, "invalid token expiry"))?;
            // This response must explicitly prove metadata-only access; unlike
            // ordinary scope comparison an omitted metadata map is insufficient.
            if !response.get("permissions").and_then(Value::as_object).is_some_and(|map| {
                map.len() == 1 && map.get("metadata").and_then(Value::as_str) == Some("read")
            }) {
                return Err(failed(DISCOVER, "discovery token permissions were not metadata-only"));
            }
            let repositories = self.repositories(&token)?;
            if expires_at <= now() {
                return Err(failed(DISCOVER, "token expired during discovery"));
            }
            Ok(GithubInstallation {
                installation_id,
                account_login,
                repositories,
                permissions,
                warning: None,
            })
        })();
        let cleanup = self.revoke(&token);
        match (discovered, cleanup) {
            (Ok(mut installation), Err(error)) => {
                installation.warning = Some(cleanup_warning(&error, expires_at));
                Ok(installation)
            }
            (Err(mut error), Err(cleanup)) => {
                error.message.push_str("; ");
                error.message.push_str(&cleanup_warning(&cleanup, expires_at));
                Err(error)
            }
            (result, _) => result,
        }
    }

    /// Verify the configured ID/name pairs and permission ceilings with this
    /// exact app key before saving an authority change.
    pub(crate) fn verify_installations(&self) -> Result<Option<String>> {
        let jwt = self.jwt()?;
        let mut warnings = Vec::new();
        let verified = (|| {
            for ceiling in &self.config.installations {
                let id = ceiling.installation_id;
                let installation = self.connect_with_app_jwt(id, &jwt).map_err(|mut error| {
                    error.message = format!("GitHub installation {id}: {}", error.message);
                    error
                })?;
                if let Some(warning) = installation.warning {
                    warnings.push(format!("GitHub installation {id}: {warning}"));
                }
                for repo in &ceiling.repositories {
                    let matches = installation.repositories.binary_search_by_key(&repo.id, |actual| actual.id)
                        .is_ok_and(|index| repo.full_name.trim()
                            .eq_ignore_ascii_case(installation.repositories[index].full_name.trim()));
                    if !matches {
                        return Err(CoreError::invalid(format!(
                            "GitHub repository ID {} and name do not match installation {id}; reconnect", repo.id)));
                    }
                }
                for (name, level) in &ceiling.permissions {
                    if !installation.permissions.get(name).is_some_and(|maximum| level <= maximum) {
                        return Err(CoreError::invalid(format!(
                            "GitHub permission {name}:{} exceeds installation {id}'s permissions; reconnect", level.as_str())));
                    }
                }
            }
            Ok(())
        })();
        let warning = (!warnings.is_empty()).then(|| warnings.join("; "));
        match verified {
            Ok(()) => Ok(warning),
            Err(mut error) => {
                if let Some(warning) = warning {
                    error.message.push_str("; ");
                    error.message.push_str(&warning);
                }
                Err(error)
            }
        }
    }

    /// Mint exactly the approved immutable grant. Never retry with restrictions
    /// omitted, accept a narrower response, or publish unverifiable credentials.
    pub fn issue(&self, grant: &GithubGrant) -> Result<GeneratedCredential> {
        let ceiling = self.config.ceiling(grant.installation_id)
            .ok_or_else(|| CoreError::invalid("GitHub installation is not configured for this generator"))?;
        if !grant.is_subset_of(ceiling)? {
            return Err(CoreError::invalid("GitHub grant exceeds this generator's ceiling"));
        }
        let mut response = self.create_token(grant.installation_id, &self.jwt()?, &TokenRequest {
            repository_ids: RepositoryIds(&grant.repositories),
            permissions: &grant.permissions,
        }, GENERATE)?;
        let token = take_token(&mut response).ok_or_else(|| failed(GENERATE, "invalid token response"))?;
        let expires_at = expiry(response.get("expires_at"));
        let checked = (|| {
            let expires_at = expires_at.filter(|expiry| *expiry > now())
                .ok_or_else(|| failed(GENERATE, "invalid token expiry"))?;
            let returned_permissions = permissions(response.get("permissions")).map_err(|_| scope_error())?;
            if returned_permissions != grant.permissions {
                return Err(scope_error());
            }
            let repositories = match response.get("repositories") {
                None => self.repositories(&token)?,
                Some(value) => {
                    let repositories = parse_repositories(value).map_err(|_| scope_error())?;
                    if repositories.iter().any(|repository| {
                        grant.repositories.binary_search_by_key(&repository.id, |approved| approved.id).is_err()
                    }) {
                        return Err(scope_error());
                    }
                    if repositories.len() == grant.repositories.len() {
                        repositories
                    } else {
                        self.repositories(&token)?
                    }
                }
            };
            if repositories.len() != grant.repositories.len()
                || !repositories.iter().map(|r| r.id).eq(grant.repositories.iter().map(|r| r.id))
            {
                return Err(scope_error());
            }
            if expires_at <= now() {
                return Err(failed(GENERATE, "token expired during verification"));
            }
            Ok(expires_at)
        })();
        match checked {
            Ok(expires_at) => Ok(GeneratedCredential { token, expires_at }),
            Err(mut error) => {
                if let Err(cleanup) = self.revoke(&token) {
                    error.message.push_str("; ");
                    error.message.push_str(&cleanup_warning(&cleanup, expires_at));
                }
                Err(error)
            }
        }
    }

    /// All pages are constructed locally; Link headers cannot redirect bearer
    /// credentials or mask an inconsistent/incomplete listing.
    fn repositories(&self, token: &str) -> Result<Vec<GithubRepository>> {
        let mut repositories = Vec::new();
        let mut seen = BTreeSet::new();
        let mut expected = None;
        let mut page = 1u64;
        loop {
            let changed = || CoreError::vault_unavailable(LISTING_CHANGED);
            let value: Value = Self::send(self.request(Method::GET,
                &format!("installation/repositories?per_page={PER_PAGE}&page={page}"), token), DISCOVER)?
                .json().map_err(|_| changed())?;
            let total = value.get("total_count").and_then(Value::as_u64).ok_or_else(changed)?;
            let count = usize::try_from(total).map_err(|_| changed())?;
            if expected.is_some_and(|expected| expected != count) {
                return Err(changed());
            }
            expected = Some(count);
            let items = parse_repositories(value.get("repositories").ok_or_else(changed)?)
                .map_err(|_| changed())?;
            if items.len() > PER_PAGE || (items.is_empty() && repositories.len() != count) {
                return Err(changed());
            }
            for repository in items {
                if !seen.insert(repository.id) {
                    return Err(changed());
                }
                repositories.push(repository);
            }
            if repositories.len() > count {
                return Err(changed());
            }
            if repositories.len() == count {
                repositories.sort_by_key(|repository| repository.id);
                return Ok(repositories);
            }
            page = page.checked_add(1).ok_or_else(changed)?;
        }
    }

    pub fn revoke(&self, token: &str) -> Result<()> {
        self.revoke_with_timeout(token, TOTAL_TIMEOUT)
    }

    /// Shutdown passes the shared deadline's remaining time, not N full request
    /// timeouts. A zero budget performs no network operation.
    pub fn revoke_with_timeout(&self, token: &str, timeout: Duration) -> Result<()> {
        if timeout.is_zero() {
            return Err(failed(REVOKE, "deadline elapsed"));
        }
        Self::send(self.request(Method::DELETE, "installation/token", token)
            .timeout(timeout.min(TOTAL_TIMEOUT)), REVOKE).map(|_| ())
    }
}

fn installation_account(value: &Value) -> Option<(u64, &str)> {
    let id = value.get("id")?.as_u64().filter(|id| *id > 0)?;
    let account = value.get("account")?.get("login")?.as_str()
        .filter(|login| !login.is_empty() && !login.chars().any(|c| c.is_whitespace() || c.is_control()))?;
    Some((id, account))
}

fn take_token(response: &mut Value) -> Option<String> {
    match response.as_object_mut()?.remove("token")? {
        Value::String(token) if !token.is_empty() => Some(token),
        _ => None,
    }
}

fn expiry(value: Option<&Value>) -> Option<i64> {
    asm_proto::time::parse_unix(value?.as_str()?)
}

fn cleanup_warning(error: &CoreError, expiry: Option<i64>) -> String {
    let expiry = expiry.map(asm_proto::time::fmt_unix).unwrap_or_else(|| "unknown".into());
    format!("{}; token provider expiry: {expiry}", error.message)
}

fn permissions(value: Option<&Value>) -> Result<BTreeMap<String, GithubPermission>> {
    let object = value.and_then(Value::as_object).ok_or_else(scope_error)?;
    let mut permissions = BTreeMap::new();
    for (name, level) in object {
        if name.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(scope_error());
        }
        let level = match level.as_str() {
            Some("read") => GithubPermission::Read,
            Some("write") => GithubPermission::Write,
            Some("admin") => GithubPermission::Admin,
            _ => return Err(scope_error()),
        };
        if name == "metadata" && level != GithubPermission::Read {
            return Err(scope_error());
        }
        permissions.insert(name.clone(), level);
    }
    permissions.entry("metadata".into()).or_insert(GithubPermission::Read);
    Ok(permissions)
}

fn parse_repositories(value: &Value) -> Result<Vec<GithubRepository>> {
    let items = value.as_array().ok_or_else(scope_error)?;
    let mut repositories = Vec::with_capacity(items.len());
    for item in items {
        let id = item.get("id").and_then(Value::as_u64).filter(|id| *id > 0).ok_or_else(scope_error)?;
        let full_name = item.get("full_name").and_then(Value::as_str).ok_or_else(scope_error)?;
        normalize_repository_name(full_name).map_err(|_| scope_error())?;
        repositories.push(GithubRepository { id, full_name: full_name.into() });
    }
    repositories.sort_by_key(|repository| repository.id);
    if repositories.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(scope_error());
    }
    Ok(repositories)
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn test_pem() -> &'static str {
    tests::test_pem()
}
