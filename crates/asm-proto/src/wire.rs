//! Serde types of the manager API (`/v1/...`). Ids are UUIDv4 strings; times are
//! RFC 3339 UTC strings, `None`/`null` meaning unlimited.

use crate::error::ApiError;
use crate::generators::{GenerationRequest, GenerationSelection, SourceKind};
use crate::rules::{parse_login_url, validate_agent_text};
use crate::ssh::{SshAccess, SshResult};
use serde::{Deserialize, Serialize};

/// Path prefix of every endpoint.
pub const API_PREFIX: &str = "/v1";
/// `name` reported by `GET /v1/health`.
pub const MANAGER_NAME: &str = "asm-manager";
/// Default manager API port.
pub const DEFAULT_API_PORT: u16 = 7411;
/// Default proxy port (HTTP proxy, CONNECT and SOCKS5).
pub const DEFAULT_PROXY_PORT: u16 = 7412;
/// Upper bound the manager applies to `?wait=` long polls, in seconds.
pub const MAX_POLL_WAIT_SECS: u64 = 25;
/// Scope-aware generated-credential requests and durable credential versions.
pub const CAPABILITY_GENERATED_CREDENTIALS_V1: &str = "generated_credentials_v1";
/// Explicit repository and permission bounds for generated GitHub requests.
pub const CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1: &str = "github_explicit_scope_v1";
/// Exact project and predefined permission claims for managed Google access.
pub const CAPABILITY_GCLOUD_ACCESS_V1: &str = "gcloud_access_v1";
/// Field authorization, catalog aliases and per-field substitution metadata.
pub const CAPABILITY_SECRET_FIELDS_V1: &str = "secret_fields_v1";
/// A fresh approval can explicitly select a different grant from the request.
pub const CAPABILITY_OPERATOR_SELECTED_GRANT_V1: &str = "operator_selected_grant_v1";
/// A fresh managed Google Cloud approval can select a different project.
pub const CAPABILITY_OPERATOR_SELECTED_PROJECT_V1: &str = "operator_selected_project_v1";
/// An unpinned generated request can reuse an existing, possibly broader grant.
pub const CAPABILITY_BROADER_LEASE_REUSE_V1: &str = "broader_lease_reuse_v1";
/// Single-use login grants (`asm get --login-url`).
pub const CAPABILITY_LOGIN_GRANT_V1: &str = "login_grant_v1";
/// Operator-assisted sign-in handing over a browser storage state (`asm login`).
pub const CAPABILITY_LOGIN_BROKER_V1: &str = "login_broker_v1";
/// SSH targets, SSH leases with per-host access and `/v1/ssh/*`.
pub const CAPABILITY_SSH_LEASES_V2: &str = "ssh_leases_v2";
/// `asm add --vault/--collection`: a suggested destination the operator can preselect.
pub const CAPABILITY_ADD_DESTINATION_V1: &str = "add_destination_v1";
/// Longest suggested vault or collection name in an `add` request.
pub const MAX_DESTINATION_HINT_CHARS: usize = 128;
/// Lease duration choices: label and seconds (`None` = unlimited).
pub const LEASE_DURATIONS: &[(&str, Option<u64>)] = &[
    ("5 min", Some(300)),
    ("15 min", Some(900)),
    ("1 h", Some(3600)),
    ("12 h", Some(43_200)),
    ("24 h", Some(86_400)),
    ("3 days", Some(259_200)),
    ("7 days", Some(604_800)),
    ("30 days", Some(2_592_000)),
    ("1 year", Some(31_536_000)),
    ("unlimited", None),
];
/// Default lease duration in seconds (1 hour).
pub const DEFAULT_LEASE_SECS: u64 = 3600;

/// `GET /health` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl HealthResponse {
    /// Check the pinned manager before sending a request it might misunderstand.
    pub fn require_capability(&self, capability: &str) -> Result<(), ApiError> {
        if !self.capabilities.iter().any(|c| c == capability) {
            return Err(ApiError::invalid(format!(
                "manager does not support {capability}; upgrade the manager"
            )));
        }
        Ok(())
    }
}

/// Facts about the agent machine, sent when pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl HostInfo {
    /// Reject control and bidi characters in every string (`invalid`).
    pub fn validate(&self) -> Result<(), ApiError> {
        for (what, v) in [
            ("hostname", &self.hostname),
            ("os", &self.os),
            ("os_version", &self.os_version),
            ("kernel", &self.kernel),
            ("arch", &self.arch),
            ("username", &self.username),
            ("asm_version", &self.asm_version),
        ] {
            validate_agent_text(what, v)?;
        }
        self.addresses
            .iter()
            .try_for_each(|a| validate_agent_text("address", a))
    }
}

/// `POST /pair` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// Hex of `SHA-256(client_nonce)` (64 characters).
    pub client_commit: String,
    pub host_info: HostInfo,
    /// Unattended pairing code `asm-<secret>-<fp>`, or `None` for interactive pairing.
    pub pairing_code: Option<String>,
    /// Proof of an existing pairing with this manager (the stored `host.json`); sent only to
    /// the certificate pinned there. A valid proof re-pairs the same host record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<PairProof>,
    /// [`machine_hint`] of this machine; a hint only, anyone can claim any value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_hint: Option<String>,
}

/// The host id and token of an earlier pairing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairProof {
    pub host_id: String,
    pub token: String,
}

impl std::fmt::Debug for PairProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairProof")
            .field("host_id", &self.host_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Lowercase hex SHA-256 of `asm-machine-v1:` + the platform machine id.
pub fn machine_hint(machine_id: &str) -> String {
    crate::crypto::sha256_hex(format!("asm-machine-v1:{machine_id}"))
}

impl PairRequest {
    /// Host info strings, and `machine_hint` must be 64 lowercase hex digits (`invalid`).
    pub fn validate(&self) -> Result<(), ApiError> {
        self.host_info.validate()?;
        if let Some(h) = &self.machine_hint
            && !(h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(ApiError::new(
                crate::error::ErrorCode::Invalid,
                "machine_hint must be 64 lowercase hex digits",
            ));
        }
        Ok(())
    }
}

/// `POST /pair/{pair_id}/reveal` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealRequest {
    pub poll_token: String,
    /// Hex of the 16-byte client nonce (32 characters).
    pub client_nonce: String,
}

/// Query of `GET /pair/{pair_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairPollQuery {
    pub poll_token: String,
    #[serde(default)]
    pub wait: Option<u64>,
}

/// Query of long-poll endpoints such as `GET /requests/{id}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitQuery {
    #[serde(default)]
    pub wait: Option<u64>,
}

/// Response of every pairing endpoint, tagged by `status`:
/// `POST /pair` → `AwaitingReveal` (no code) or `Approved` (valid code);
/// `POST /pair/{id}/reveal` → `Pending`;
/// `GET /pair/{id}` → `Pending`, `Denied`, `Expired` or `Approved` (once).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairResponse {
    AwaitingReveal {
        pair_id: String,
        poll_token: String,
        /// Hex of the 16-byte server nonce (32 characters).
        server_nonce: String,
    },
    Pending {
        #[serde(default)]
        deny_reason: Option<String>,
        /// When the pairing request expires unanswered (RFC 3339); absent from older managers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<String>,
    },
    Denied {
        #[serde(default)]
        deny_reason: Option<String>,
    },
    Expired {
        #[serde(default)]
        deny_reason: Option<String>,
    },
    Approved {
        host_id: String,
        token: String,
    },
}

/// Kind of a vault secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Login,
    Single,
    Multi,
}

/// Lease mode: a sentinel substituted by the proxy, or the raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Sentinel,
    Raw,
}

/// A request preference is distinct from the operator's final lease mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestedMode {
    #[default]
    Default,
    Raw,
    Sentinel,
}

impl RequestedMode {
    pub fn from_flags(raw: bool, sentinel: bool) -> Result<Self, ApiError> {
        match (raw, sentinel) {
            (false, false) => Ok(Self::Default),
            (true, false) => Ok(Self::Raw),
            (false, true) => Ok(Self::Sentinel),
            (true, true) => Err(ApiError::invalid("raw and sentinel are mutually exclusive")),
        }
    }

    /// Resolve the delivery mode for an unpinned generated request.
    /// An exact existing lease can keep its original mode and host restrictions.
    pub fn for_new_generated(self, hosts: &[String]) -> Result<Self, ApiError> {
        if self == Self::Sentinel {
            return Err(ApiError::invalid("generated credentials require raw delivery; remove --sentinel"));
        }
        if !hosts.is_empty() {
            return Err(ApiError::invalid("generated credentials are raw and cannot be restricted to hosts; remove --hosts"));
        }
        Ok(Self::Raw)
    }
}

/// Lease status, derived from the wall clock and revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseStatus {
    Active,
    Expired,
    Revoked,
}

/// The calling host's active lease on a secret, as listed by `GET /secrets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseBrief {
    pub lease_id: String,
    pub mode: LeaseMode,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub generation: Option<GenerationSelection>,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default)]
    pub credential_version: Option<u64>,
    #[serde(default)]
    pub generator_name: Option<String>,
}

/// One entry of `GET /secrets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub vault: String,
    pub kind: SecretKind,
    pub fields: Vec<String>,
    pub lease: Option<LeaseBrief>,
    #[serde(default)]
    pub source_kind: SourceKind,
    #[serde(default)]
    pub generators: Vec<GeneratorOption>,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The vault item's own name when it differs from the listed name (a duplicate shown
    /// as `name~<hash>`): a bare lookup of it is ambiguous instead of unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_name: Option<String>,
    /// Names of the Bitwarden collections that hold the item, when its vault shares them
    /// with agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<String>,
}

/// Public generator identity; readiness and ceilings stay in the manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorOption {
    pub generator_id: String,
    pub name: String,
    // A write-only compatibility marker. `false` omits the field on re-serialization.
    #[serde(rename = "available", skip_deserializing, skip_serializing_if = "std::ops::Not::not")]
    include_legacy_availability: bool,
}

impl GeneratorOption {
    /// Advertise an addressable generator to HTTP clients. Legacy clients require
    /// `available: true`; it does not report the provider's readiness.
    pub fn listed(generator_id: String, name: String) -> Self {
        Self { generator_id, name, include_legacy_availability: true }
    }
}

/// `GET /secrets` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsResponse {
    pub secrets: Vec<SecretEntry>,
}

/// The exact HTTPS form action a login grant is valid for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginScope {
    /// Canonical `https://host[:port]<path>[?query]` (see [`crate::rules::parse_login_url`]).
    pub url: String,
}

/// `POST /requests` body, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RequestBody {
    Get {
        name: String,
        /// Set for new generated requests for compatibility with older managers.
        /// For static requests this is a preference, not a delivery guarantee.
        #[serde(default)]
        raw: bool,
        /// Require sentinel delivery. Not permitted for new generated requests.
        #[serde(default)]
        sentinel: bool,
        /// None selects all current fields; Some is an exact authorization set.
        #[serde(default)]
        fields: Option<Vec<String>>,
        #[serde(default)]
        generation: Option<GenerationRequest>,
        #[serde(default)]
        refresh: bool,
        #[serde(default)]
        new_lease: bool,
        #[serde(default)]
        lease_id: Option<String>,
        /// Conditional force rotation against an observed durable version.
        #[serde(default)]
        refresh_from_version: Option<u64>,
        #[serde(default)]
        client_capabilities: Vec<String>,
        /// Proxy destination restrictions, not applicable to new generated requests.
        #[serde(default)]
        hosts: Vec<String>,
        /// A single-use login grant for this form action; `name` may then be empty,
        /// meaning "infer the vault login from the URL's host".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        login: Option<LoginScope>,
        reason: String,
        #[serde(default)]
        agent: String,
    },
    Update {
        name: String,
        #[serde(default)]
        field: Option<String>,
        value: String,
        #[serde(default)]
        agent: String,
    },
    Add {
        name: String,
        value: String,
        #[serde(default)]
        agent: String,
        /// Suggested destination vault (by name); the operator decides. Needs
        /// [`CAPABILITY_ADD_DESTINATION_V1`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// Suggested Bitwarden collection (by name) in `vault`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        collection: Option<String>,
    },
    /// Operator-assisted sign-in: the manager fills a browser on the Mac and hands
    /// the agent the resulting storage state. An empty `name` means "infer".
    Login {
        name: String,
        url: String,
        reason: String,
        #[serde(default)]
        extra_fill_origins: Vec<String>,
        #[serde(default)]
        agent: String,
        #[serde(default)]
        client_capabilities: Vec<String>,
    },
    /// SSH access to enrolled targets (`kind: "ssh"`).
    Ssh {
        targets: Vec<String>,
        access: SshAccess,
        #[serde(default)]
        grants: Vec<String>,
        /// For access as a user: which user.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default)]
        new_lease: bool,
        reason: String,
        #[serde(default)]
        agent: String,
    },
    /// Extend an active SSH lease of the calling host.
    #[serde(rename = "ssh_extend")]
    SshExtend {
        lease_id: String,
        reason: String,
        #[serde(default)]
        agent: String,
    },
}

impl RequestBody {
    /// The request kind.
    pub fn kind(&self) -> RequestKind {
        match self {
            RequestBody::Get { .. } => RequestKind::Get,
            RequestBody::Update { .. } => RequestKind::Update,
            RequestBody::Add { .. } => RequestKind::Add,
            RequestBody::Login { .. } => RequestKind::Login,
            RequestBody::Ssh { .. } | RequestBody::SshExtend { .. } => RequestKind::Ssh,
        }
    }

    /// The secret name the request is about.
    pub fn name(&self) -> &str {
        match self {
            RequestBody::Get { name, .. }
            | RequestBody::Update { name, .. }
            | RequestBody::Add { name, .. }
            | RequestBody::Login { name, .. } => name,
            RequestBody::Ssh { .. } | RequestBody::SshExtend { .. } => "ssh",
        }
    }

    /// The agent label.
    pub fn agent(&self) -> &str {
        match self {
            RequestBody::Get { agent, .. }
            | RequestBody::Update { agent, .. }
            | RequestBody::Add { agent, .. }
            | RequestBody::Login { agent, .. }
            | RequestBody::Ssh { agent, .. }
            | RequestBody::SshExtend { agent, .. } => agent,
        }
    }

    /// Canonicalize shared get syntax before target lookup. Source-specific
    /// authority checks (including unknown fields) still belong to the manager.
    pub fn canonicalize(&mut self) -> Result<(), ApiError> {
        if let Self::Get {
            raw, sentinel, fields, generation, refresh, new_lease, lease_id,
            refresh_from_version, hosts, login, ..
        } = self
        {
            if let Some(login) = login {
                let conflicts = [
                    ("raw", *raw),
                    ("fields", fields.is_some()),
                    ("hosts", !hosts.is_empty()),
                    ("generation", generation.is_some()),
                    ("lease_id", lease_id.is_some()),
                    ("refresh", *refresh),
                    ("new_lease", *new_lease),
                ];
                if let Some((flag, _)) = conflicts.iter().find(|(_, set)| *set) {
                    return Err(ApiError::invalid(format!("a login grant does not take {flag}")));
                }
                login.url = parse_login_url(&login.url)?.canonical_url();
            }
            RequestedMode::from_flags(*raw, *sentinel)?;
            if *new_lease && (lease_id.is_some() || *refresh) {
                return Err(ApiError::invalid("new_lease conflicts with lease_id and refresh"));
            }
            if lease_id.as_ref().is_some_and(|id| id.is_empty()) {
                return Err(ApiError::invalid("lease_id must not be empty"));
            }
            if let Some(version) = refresh_from_version {
                if !*refresh || lease_id.is_none() || *version == 0 {
                    return Err(ApiError::invalid("refresh_from_version requires refresh, lease_id and a positive version"));
                }
            }
            if let Some(fields) = fields {
                if fields.is_empty() || fields.iter().any(String::is_empty) {
                    return Err(ApiError::invalid("fields must be a nonempty list of exact field names"));
                }
                fields.sort_unstable();
                fields.dedup();
            }
            if let Some(generation) = generation {
                generation.canonicalize()?;
            }
        }
        if let Self::Ssh { targets, access, grants, user, .. } = self {
            if targets.is_empty() || targets.len() > crate::ssh::MAX_TARGETS {
                return Err(ApiError::invalid(format!("name 1–{} SSH targets", crate::ssh::MAX_TARGETS)));
            }
            for target in targets.iter() {
                crate::ssh::validate_target_name(target)?;
            }
            targets.sort_unstable();
            targets.dedup();
            crate::ssh::validate_access(*access, grants, user.as_deref())?;
            grants.sort_unstable();
            grants.dedup();
        }
        if let Self::SshExtend { lease_id, .. } = self
            && !crate::crypto::is_uuid(lease_id)
        {
            return Err(ApiError::invalid("lease_id must be an SSH lease id"));
        }
        if let Self::Add { vault, collection, .. } = self {
            for (what, hint) in [("vault", &mut *vault), ("collection", &mut *collection)] {
                if let Some(text) = hint.take() {
                    let text = text.trim();
                    validate_agent_text(what, text)?;
                    let n = text.chars().count();
                    if n == 0 || n > MAX_DESTINATION_HINT_CHARS {
                        return Err(ApiError::invalid(format!("{what} must be 1–{MAX_DESTINATION_HINT_CHARS} characters")));
                    }
                    *hint = Some(text.to_owned());
                }
            }
            if collection.is_some() && vault.is_none() {
                return Err(ApiError::invalid("a collection needs its vault"));
            }
        }
        Ok(())
    }

    /// Whether the client understands a grant selected by the operator.
    pub fn supports_operator_selected_grant(&self) -> bool {
        matches!(self, Self::Get { client_capabilities, .. } if
            client_capabilities.iter().any(|c| c == CAPABILITY_OPERATOR_SELECTED_GRANT_V1))
    }

    /// Whether this unpinned managed Google request permits project selection.
    pub fn supports_operator_selected_project(&self) -> bool {
        matches!(self, Self::Get {
            generation: Some(GenerationRequest::GcloudAccess(_)), lease_id: None, client_capabilities, ..
        } if client_capabilities.iter().any(|c| c == CAPABILITY_OPERATOR_SELECTED_PROJECT_V1))
    }

    /// Whether an automatic reuse may return more than the requested scope.
    pub fn supports_broader_lease_reuse(&self) -> bool {
        matches!(self, Self::Get {
            generation: Some(_), lease_id: None, new_lease: false, client_capabilities, ..
        } if client_capabilities.iter().any(|c| c == CAPABILITY_BROADER_LEASE_REUSE_V1))
    }

    /// Negotiate only features that change request meaning, not arbitrary
    /// unknown JSON fields. Legacy static whole-item requests remain accepted.
    pub fn validate_get_capabilities(&self, source: SourceKind) -> Result<(), ApiError> {
        if let Self::Get { fields, generation, sentinel, login, client_capabilities, .. } = self {
            let require = |capability| {
                if client_capabilities.iter().any(|c| c == capability) {
                    Ok(())
                } else {
                    Err(ApiError::invalid(format!("request requires {capability}; upgrade the CLI")))
                }
            };
            if source == SourceKind::Generator {
                require(CAPABILITY_GENERATED_CREDENTIALS_V1)?;
                if matches!(generation, Some(GenerationRequest::GithubApp(_))) {
                    require(CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1)?;
                }
                if matches!(generation, Some(GenerationRequest::GcloudAccess(_))) {
                    require(CAPABILITY_GCLOUD_ACCESS_V1)?;
                }
            }
            if fields.is_some() || *sentinel {
                require(CAPABILITY_SECRET_FIELDS_V1)?;
            }
            if login.is_some() {
                require(CAPABILITY_LOGIN_GRANT_V1)?;
            }
        }
        Ok(())
    }
}

/// Kind of a host request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Get,
    Update,
    Add,
    Login,
    Ssh,
}

/// Request lifecycle state: `pending` → one terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

impl RequestStatus {
    /// Every status except `pending` is terminal.
    pub fn is_terminal(self) -> bool {
        self != RequestStatus::Pending
    }
}

/// State of a host request (`POST /requests`, `GET`/`DELETE /requests/{id}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestState {
    pub request_id: String,
    pub kind: RequestKind,
    pub status: RequestStatus,
    pub deny_reason: Option<String>,
    pub result: Option<RequestResult>,
    /// While pending: when the request expires unanswered (RFC 3339); `null` once
    /// resolved. Absent from older managers.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// The manager's pending-request lifetime in seconds (always set while pending);
    /// 0 = unknown (older manager).
    #[serde(default)]
    pub pending_lifetime_secs: u64,
}

/// Result of an approved request: `GetResult` for `get`, `WriteResult` for `update`/`add`,
/// `SshResult` for `ssh` (last: its JSON has none of the other variants' required keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestResult {
    Get(GetResult),
    Write(WriteResult),
    Ssh(SshResult),
}

/// Result of an approved `get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetResult {
    pub lease_id: String,
    pub mode: LeaseMode,
    /// Approved host patterns; `["*"]` = any host; empty for raw leases.
    pub hosts: Vec<String>,
    pub expires_at: Option<String>,
    pub files: Vec<ResultFile>,
    #[serde(default)]
    pub generation: Option<GenerationSelection>,
    /// This fresh request was resolved by explicit operator selection, not
    /// by reusing or renewing an existing authorization. A changed managed
    /// Google project is carried in `generation` and also requires the
    /// project-selection capability; this marker is not sufficient on its own.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub operator_selected_grant: bool,
    /// An existing generated lease was reused with a grant covering the request.
    /// Never set on fresh operator approvals or pinned deliveries.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub broader_lease_reuse: bool,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default)]
    pub credential_version: Option<u64>,
    #[serde(default)]
    pub generator_name: Option<String>,
    /// Set on login grants: the form action the password sentinel is valid for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginScope>,
}

impl GetResult {
    /// Validate generated delivery metadata before publishing values locally.
    /// Authorization/provider freshness is checked separately against the clock.
    pub fn validate(&self) -> Result<(), ApiError> {
        match &self.generation {
            Some(selection) => {
                if self.broader_lease_reuse && (self.operator_selected_grant || self.mode != LeaseMode::Raw) {
                    return Err(ApiError::invalid("broader lease reuse requires existing raw authorization"));
                }
                selection.validate()?;
                if !selection.grant.is_issued() {
                    return Err(ApiError::invalid("generated result requires an issued grant"));
                }
                if self.credential_version.is_none_or(|version| version == 0)
                    || self.credential_expires_at.as_deref().and_then(crate::time::parse_unix).is_none()
                {
                    return Err(ApiError::invalid("generated result requires a positive credential version and provider expiry"));
                }
            }
            None if self.operator_selected_grant || self.broader_lease_reuse || self.credential_version.is_some() || self.credential_expires_at.is_some() || self.generator_name.is_some() => {
                return Err(ApiError::invalid("credential metadata requires a generation selection"));
            }
            None => {}
        }
        Ok(())
    }
}

/// One file of a `get` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultFile {
    pub field: String,
    /// `[<vault>/]<name>[.<field>]`; check with [`crate::rules::check_relative_path`].
    pub relative_path: String,
    /// Sentinel, raw value, or the plain username.
    pub content: String,
    /// Absent on older managers; in sentinel mode this is not evidence of raw delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substituted: Option<bool>,
}

/// Result of an approved `update` or `add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteResult {
    pub name: String,
    pub vault: String,
    /// `add`: the source-qualified spelling of the new secret (`<vault>/<name>`), when the
    /// manager could check that it names exactly that secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    /// `add`: the Bitwarden collection the operator chose, when the vault shares
    /// collection names with agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
}

/// One entry of `GET /leases`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub name: String,
    pub mode: LeaseMode,
    pub hosts: Vec<String>,
    pub expires_at: Option<String>,
    pub status: LeaseStatus,
    #[serde(default)]
    pub source_kind: SourceKind,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub generation: Option<GenerationSelection>,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default)]
    pub credential_version: Option<u64>,
    #[serde(default)]
    pub generator_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginScope>,
}

/// `GET /leases` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasesResponse {
    pub leases: Vec<LeaseInfo>,
}

/// `GET /proxy-info` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub port: u16,
    /// Hostnames/addresses under which agents can reach the proxy, preferred first.
    pub hints: Vec<String>,
    /// Lowercase hex SHA-256 of the proxy CA certificate (DER).
    pub ca_sha256: String,
    /// The macOS Firewall on the manager's Mac blocks incoming connections to the proxy
    /// while it listens for other machines. Absent from older managers and before the
    /// manager's first check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_blocks_proxy: Option<bool>,
    /// The proxy requires per-host credentials (`host_id` /
    /// [`crate::crypto::proxy_password`] of the token hash).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_auth: bool,
    /// PEM of the asm browser CA; absent from managers without browser logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_ca_pem: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, json, to_value};

    #[test]
    fn pair_responses() {
        let r: PairResponse = from_str(r#"{"status":"pending"}"#).unwrap();
        assert_eq!(
            r,
            PairResponse::Pending {
                deny_reason: None,
                expires_at: None
            }
        );
        let r = PairResponse::Pending {
            deny_reason: None,
            expires_at: Some("2026-11-16T12:00:00Z".into()),
        };
        assert_eq!(
            to_value(&r).unwrap(),
            json!({"status":"pending","deny_reason":null,"expires_at":"2026-11-16T12:00:00Z"})
        );
        assert_eq!(
            to_value(PairResponse::Pending {
                deny_reason: None,
                expires_at: None
            })
            .unwrap(),
            json!({"status":"pending","deny_reason":null}),
            "older CLIs see the same pending answer as before"
        );
        let r = PairResponse::AwaitingReveal {
            pair_id: "p".into(),
            poll_token: "t".into(),
            server_nonce: "00".into(),
        };
        assert_eq!(
            to_value(&r).unwrap(),
            json!({"status":"awaiting_reveal","pair_id":"p","poll_token":"t","server_nonce":"00"})
        );
        let r: PairResponse = from_str(r#"{"status":"denied","deny_reason":"no"}"#).unwrap();
        assert_eq!(
            r,
            PairResponse::Denied {
                deny_reason: Some("no".into())
            }
        );
        let r: PairResponse =
            from_str(r#"{"status":"approved","host_id":"h","token":"t"}"#).unwrap();
        assert!(matches!(r, PairResponse::Approved { .. }));
    }

    #[test]
    fn request_bodies() {
        let b: RequestBody = from_str(
            r#"{"kind":"get","name":"X","raw":false,"hosts":["a.com"],"reason":"r","agent":"claude"}"#,
        )
        .unwrap();
        assert_eq!(b.kind(), RequestKind::Get);
        assert_eq!(b.name(), "X");
        let b = RequestBody::Update {
            name: "X".into(),
            field: None,
            value: "v".into(),
            agent: "".into(),
        };
        assert_eq!(
            to_value(&b).unwrap(),
            json!({"kind":"update","name":"X","field":null,"value":"v","agent":""})
        );
        let b: RequestBody = from_str(r#"{"kind":"add","name":"X","value":"v"}"#).unwrap();
        assert_eq!(b.agent(), "");
    }

    #[test]
    fn request_states() {
        let get = json!({"request_id":"r","kind":"get","status":"approved","deny_reason":null,
            "result":{"lease_id":"l","mode":"sentinel","hosts":["a.com"],"expires_at":null,
                      "files":[{"field":"value","relative_path":"X","content":"asm_x","substituted":false}],
                      "generation":null,"credential_expires_at":null,"credential_version":null,"generator_name":null},
            "expires_at":null,"pending_lifetime_secs":600});
        let s: RequestState = serde_json::from_value(get.clone()).unwrap();
        assert!(matches!(
            s.result,
            Some(RequestResult::Get(GetResult {
                mode: LeaseMode::Sentinel,
                ..
            }))
        ));
        assert_eq!(to_value(&s).unwrap(), get);
        let write = json!({"request_id":"r","kind":"add","status":"approved","deny_reason":null,
            "result":{"name":"X","vault":"v"}});
        let s: RequestState = serde_json::from_value(write).unwrap();
        assert!(matches!(s.result, Some(RequestResult::Write(_))));
        // An older manager sends neither expiry field.
        let pending: RequestState =
            from_str(r#"{"request_id":"r","kind":"update","status":"pending","deny_reason":null,"result":null}"#)
                .unwrap();
        assert!(!pending.status.is_terminal());
        assert_eq!(
            (pending.expires_at, pending.pending_lifetime_secs),
            (None, 0)
        );
        let pending: RequestState = from_str(
            r#"{"request_id":"r","kind":"get","status":"pending","deny_reason":null,"result":null,
                "expires_at":"2026-11-16T12:10:00Z","pending_lifetime_secs":600}"#,
        )
        .unwrap();
        assert_eq!(pending.expires_at.as_deref(), Some("2026-11-16T12:10:00Z"));
        assert_eq!(pending.pending_lifetime_secs, 600);
    }

    #[test]
    fn ssh_requests_and_results() {
        let mut b: RequestBody = from_str(
            r#"{"kind":"ssh","targets":["web","db","web"],"access":"restricted","grants":["restart:a.service","logs:a.service","logs:a.service"],"reason":"r"}"#,
        )
        .unwrap();
        assert_eq!(b.kind(), RequestKind::Ssh);
        b.canonicalize().unwrap();
        let RequestBody::Ssh { targets, grants, new_lease, .. } = &b else { panic!("not ssh") };
        assert_eq!(targets, &["db", "web"]);
        assert_eq!(grants, &["logs:a.service", "restart:a.service"]);
        assert!(!new_lease);
        let mut privileged_with_grants: RequestBody = from_str(
            r#"{"kind":"ssh","targets":["web"],"access":"privileged","grants":["logs:a.service"],"reason":"r"}"#,
        )
        .unwrap();
        assert!(privileged_with_grants.canonicalize().is_err());
        let mut restricted_without: RequestBody =
            from_str(r#"{"kind":"ssh","targets":["web"],"access":"restricted","reason":"r"}"#).unwrap();
        assert!(restricted_without.canonicalize().is_err());
        let mut no_targets: RequestBody =
            from_str(r#"{"kind":"ssh","targets":[],"access":"privileged","reason":"r"}"#).unwrap();
        assert!(no_targets.canonicalize().is_err());
        let mut as_user: RequestBody =
            from_str(r#"{"kind":"ssh","targets":["web"],"access":"user","user":"deploy","reason":"r"}"#).unwrap();
        as_user.canonicalize().unwrap();
        assert!(matches!(&as_user, RequestBody::Ssh { user: Some(u), .. } if u == "deploy"));
        for (json, message) in [
            (r#"{"kind":"ssh","targets":["web"],"access":"user","reason":"r"}"#, "access as a user needs the user's name"),
            (r#"{"kind":"ssh","targets":["web"],"access":"privileged","user":"deploy","reason":"r"}"#,
                "a user applies only to access as a user"),
            (r#"{"kind":"ssh","targets":["web"],"access":"user","user":"deploy","grants":["logs:a.service"],"reason":"r"}"#,
                "grants apply only to restricted access"),
            (r#"{"kind":"ssh","targets":["web"],"access":"user","user":"asm-ops","reason":"r"}"#,
                "logins starting with asm- are reserved for asm's accounts"),
        ] {
            let mut b: RequestBody = from_str(json).unwrap();
            assert_eq!(b.canonicalize().unwrap_err().message, message, "{json}");
        }

        let ssh = json!({"request_id":"r","kind":"ssh","status":"approved","deny_reason":null,
            "result":{"lease_id":"l","expires_at":"2026-11-16T12:10:00Z",
                "targets":[{"name":"web","target_id":"0a1b2c3d","login":"asm-priv","hostname":"web.example",
                    "port":22,"host_keys":["ssh-ed25519 AAAA"],"access":"privileged",
                    "certificate":"ssh-ed25519-cert-v01@openssh.com AAAA asm-lease-l"},
                    {"name":"db","target_id":"0a1b2c3e","login":"asm-ops","hostname":"db.example",
                    "port":2222,"host_keys":["ssh-ed25519 BBBB"],"access":"restricted","grants":["logs:pg.service"],
                    "certificate":"ssh-ed25519-cert-v01@openssh.com BBBB asm-lease-l"},
                    {"name":"app","target_id":"0a1b2c3f","login":"asm-priv","hostname":"app.example",
                    "port":22,"host_keys":["ssh-ed25519 CCCC"],"access":"user","user":"deploy",
                    "certificate":"ssh-ed25519-cert-v01@openssh.com CCCC asm-lease-l"}]},
            "expires_at":null,"pending_lifetime_secs":600});
        let s: RequestState = serde_json::from_value(ssh.clone()).unwrap();
        let Some(RequestResult::Ssh(r)) = &s.result else { panic!("not an SSH result") };
        let access: Vec<_> = r.targets.iter().map(|t| (t.access, t.grants.len(), t.user.as_deref())).collect();
        assert_eq!(access, [(SshAccess::Privileged, 0, None), (SshAccess::Restricted, 1, None),
            (SshAccess::User, 0, Some("deploy"))]);
        assert_eq!(to_value(&s).unwrap(), ssh);
    }

    #[test]
    fn ssh_extend_requests() {
        let json = r#"{"kind":"ssh_extend","lease_id":"0f8fad5b-d9cb-469f-a165-70867728950e","reason":"more time","agent":"a"}"#;
        let mut b: RequestBody = from_str(json).unwrap();
        assert_eq!(b.kind(), RequestKind::Ssh);
        assert_eq!(b.agent(), "a");
        b.canonicalize().unwrap();
        assert_eq!(to_value(&b).unwrap(), serde_json::from_str::<serde_json::Value>(json).unwrap());
        let mut bad: RequestBody =
            from_str(r#"{"kind":"ssh_extend","lease_id":"not-a-lease","reason":"r"}"#).unwrap();
        assert_eq!(bad.canonicalize().unwrap_err().message, "lease_id must be an SSH lease id");
    }

    #[test]
    fn secrets_and_leases() {
        let s = SecretsResponse {
            secrets: vec![SecretEntry {
                name: "GitHub".into(),
                vault: "work".into(),
                kind: SecretKind::Login,
                fields: vec!["username".into(), "password".into()],
                lease: Some(LeaseBrief {
                    lease_id: "l".into(),
                    mode: LeaseMode::Raw,
                    expires_at: None,
                    generation: None,
                    credential_expires_at: None,
                    credential_version: None,
                    generator_name: None,
                }),
                source_kind: SourceKind::Vault,
                generators: vec![],
                aliases: vec![],
                item_name: None,
                collections: vec![],
            }],
        };
        let v = to_value(&s).unwrap();
        assert_eq!(v["secrets"][0]["kind"], "login");
        assert_eq!(v["secrets"][0]["lease"]["mode"], "raw");
        let l: LeasesResponse = from_str(
            r#"{"leases":[{"lease_id":"l","name":"n","mode":"sentinel","hosts":["*"],"expires_at":"2026-11-16T12:00:00Z","status":"revoked"}]}"#,
        )
        .unwrap();
        assert_eq!(l.leases[0].status, LeaseStatus::Revoked);
    }

    #[test]
    fn catalog_decoding_drops_legacy_status_from_display() {
        let public = json!({"secrets":[{
            "name":"GH_TOKEN", "vault":"bot", "kind":"single", "fields":["value"], "lease":null,
            "source_kind":"generator", "aliases":["GITHUB_TOKEN"],
            "generators":[{"generator_id":"bot-id", "name":"bot"}]
        }]});
        for available in [true, false] {
            let mut legacy = public.clone();
            legacy["warnings"] = json!(["vault is locked"]);
            legacy["secrets"][0]["generators"][0]["available"] = json!(available);
            legacy["secrets"][0]["generators"][0]["unavailable_reason"] = json!("private diagnostics");

            let decoded: SecretsResponse = serde_json::from_value(legacy).unwrap();
            assert_eq!(to_value(&decoded).unwrap(), public);
            assert_eq!(serde_json::from_value::<SecretsResponse>(public.clone()).unwrap(), decoded);
        }
    }

    #[test]
    fn host_info_validation() {
        let mut h = HostInfo {
            hostname: "nuk1".into(),
            ..Default::default()
        };
        assert!(h.validate().is_ok());
        h.username = "evil\u{202E}".into();
        assert!(h.validate().is_err());
    }

    #[test]
    fn pair_request_optional_fields() {
        // Requests of older CLIs (no `previous`, no `machine_hint`) still parse.
        let r: PairRequest = from_str(
            r#"{"client_commit":"00","host_info":{"hostname":"h","os":"","os_version":"","kernel":"","arch":"","username":"","addresses":[],"asm_version":"","container":false},"pairing_code":null}"#,
        )
        .unwrap();
        assert_eq!((r.previous.as_ref(), r.machine_hint.as_ref()), (None, None));
        let v = to_value(&r).unwrap();
        assert!(v.get("previous").is_none() && v.get("machine_hint").is_none());
        assert!(r.validate().is_ok());

        let hint = machine_hint("4c4c4544-0042");
        assert_eq!(hint.len(), 64);
        let mut r = PairRequest {
            previous: Some(PairProof {
                host_id: "h1".into(),
                token: "secret-token".into(),
            }),
            machine_hint: Some(hint),
            ..r
        };
        assert!(r.validate().is_ok());
        assert!(!format!("{r:?}").contains("secret-token"));
        r.machine_hint = Some("ABC".into());
        assert!(r.validate().is_err());
    }

    #[test]
    fn proxy_info_firewall_field_is_optional() {
        let old: ProxyInfo = from_str(r#"{"port":7412,"hints":["mac"],"ca_sha256":"ab"}"#).unwrap();
        assert_eq!(old.firewall_blocks_proxy, None);
        assert_eq!(
            to_value(&old).unwrap(),
            json!({"port":7412,"hints":["mac"],"ca_sha256":"ab"})
        );
        let new = ProxyInfo {
            firewall_blocks_proxy: Some(true),
            ..old
        };
        assert_eq!(
            to_value(&new).unwrap(),
            json!({"port":7412,"hints":["mac"],"ca_sha256":"ab","firewall_blocks_proxy":true})
        );
    }

    #[test]
    fn old_static_wire_records_default_to_no_generation() {
        let health: HealthResponse = from_str(r#"{"name":"asm-manager","version":"old"}"#).unwrap();
        assert!(health.capabilities.is_empty());
        let entry: SecretEntry = from_str(r#"{"name":"X","vault":"work","kind":"single","fields":["value"],"lease":null}"#).unwrap();
        assert_eq!(entry.source_kind, SourceKind::Vault);
        assert!(entry.generators.is_empty() && entry.aliases.is_empty());
        let brief: LeaseBrief = from_str(r#"{"lease_id":"l","mode":"sentinel","expires_at":null}"#).unwrap();
        assert_eq!((brief.generation, brief.credential_expires_at, brief.credential_version, brief.generator_name), (None, None, None, None));
        let lease: LeaseInfo = from_str(r#"{"lease_id":"l","name":"X","mode":"sentinel","hosts":["*"],"expires_at":null,"status":"active"}"#).unwrap();
        assert_eq!(lease.source_kind, SourceKind::Vault);
        assert!(lease.fields.is_empty());
        assert_eq!((lease.generation, lease.credential_expires_at, lease.credential_version, lease.generator_name), (None, None, None, None));
        let result: GetResult = from_str(r#"{"lease_id":"l","mode":"sentinel","hosts":["*"],"expires_at":null,"files":[{"field":"value","relative_path":"X","content":"asm_fixture"}]}"#).unwrap();
        assert_eq!(result.files[0].substituted, None);
        assert_eq!((result.generation.as_ref(), result.credential_expires_at.as_ref(), result.credential_version, result.generator_name.as_ref()), (None, None, None, None));
        result.validate().unwrap();
    }

    fn get_body(extra: serde_json::Value) -> RequestBody {
        let mut value = json!({"kind":"get","name":"GH_TOKEN","reason":"Read repository"});
        value.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn get_fields_and_scope_canonicalize_without_guessing_field_names() {
        let mut body = get_body(json!({
            "fields":["password","Username","password"],
            "generation":{"provider":"github_app","scope":{"repositories":[" Acme/Web ","acme/web"],"permissions":{}}}
        }));
        body.canonicalize().unwrap();
        let RequestBody::Get { fields, generation, .. } = body else { panic!() };
        assert_eq!(fields.unwrap(), ["Username", "password"]);
        let Some(GenerationRequest::GithubApp(scope)) = generation else { panic!() };
        assert_eq!(scope.repositories.unwrap(), ["acme/web"]);
        assert_eq!(scope.permissions.unwrap().get("metadata"), Some(&crate::generators::GithubPermission::Read));
        for fields in [json!([]), json!([""])] {
            assert!(get_body(json!({"fields":fields})).canonicalize().is_err());
        }
        let mut exact = get_body(json!({"fields":[" value "]}));
        exact.canonicalize().unwrap();
        let RequestBody::Get { fields, .. } = exact else { panic!() };
        assert_eq!(fields.unwrap(), [" value "], "field names are exact and never trimmed");
    }

    #[test]
    fn gcloud_get_scope_is_canonicalized_at_the_request_seam() {
        let storage = "https://www.googleapis.com/auth/devstorage.read_only";
        let cloud = "https://www.googleapis.com/auth/cloud-platform";
        let mut body = get_body(json!({
            "name":"CLOUDSDK_AUTH_ACCESS_TOKEN",
            "generation":{"provider":"gcloud","scope":{"scopes":[storage, cloud, storage]}}
        }));
        body.canonicalize().unwrap();
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["name"], "CLOUDSDK_AUTH_ACCESS_TOKEN");
        assert_eq!(value["generation"], json!({"provider":"gcloud","scope":{"scopes":[cloud, storage]}}));
        assert_eq!(serde_json::from_value::<RequestBody>(value).unwrap(), body);
        assert!(get_body(json!({
            "generation":{"provider":"gcloud","scope":{"scopes":[]}}
        })).canonicalize().is_err());
    }

    #[test]
    fn get_flag_and_conditional_refresh_conflicts_fail_locally() {
        for extra in [
            json!({"raw":true,"sentinel":true}),
            json!({"new_lease":true,"lease_id":"l"}),
            json!({"new_lease":true,"refresh":true}),
            json!({"lease_id":""}),
            json!({"refresh_from_version":1}),
            json!({"refresh":true,"refresh_from_version":1}),
            json!({"lease_id":"l","refresh_from_version":1}),
            json!({"lease_id":"l","refresh":true,"refresh_from_version":0}),
        ] {
            assert!(get_body(extra.clone()).canonicalize().is_err(), "{extra}");
        }
        get_body(json!({"lease_id":"l","refresh":true,"refresh_from_version":9})).canonicalize().unwrap();
        get_body(json!({"refresh":true})).canonicalize().unwrap();
        let mut old = get_body(json!({"unknown_future_field":true}));
        old.canonicalize().unwrap();
        let RequestBody::Get { sentinel, fields, generation, refresh, new_lease, lease_id, refresh_from_version, client_capabilities, .. } = old else { panic!() };
        assert!(!sentinel && !refresh && !new_lease);
        assert_eq!((fields, generation, lease_id, refresh_from_version), (None, None, None, None));
        assert!(client_capabilities.is_empty());
    }

    #[test]
    fn login_grants_canonicalize_the_url_and_reject_other_get_flags() {
        let mut body = get_body(json!({"name":"","login":{"url":"https://Example.com:443/session?return_to=%2F"}}));
        body.canonicalize().unwrap();
        let RequestBody::Get { name, login, .. } = &body else { panic!() };
        assert_eq!((name.as_str(), login.as_ref().unwrap().url.as_str()), ("", "https://example.com/session?return_to=%2F"));
        assert!(body.validate_get_capabilities(SourceKind::Vault).unwrap_err().message.contains(CAPABILITY_LOGIN_GRANT_V1));
        let RequestBody::Get { client_capabilities, .. } = &mut body else { panic!() };
        client_capabilities.push(CAPABILITY_LOGIN_GRANT_V1.into());
        body.validate_get_capabilities(SourceKind::Vault).unwrap();
        for (flag, extra) in [
            ("raw", json!({"raw":true})),
            ("fields", json!({"fields":["password"]})),
            ("hosts", json!({"hosts":["example.com"]})),
            ("generation", json!({"generation":{"provider":"github_app","scope":{"repositories":["acme/web"],"permissions":{}}}})),
            ("lease_id", json!({"lease_id":"l"})),
            ("refresh", json!({"refresh":true})),
            ("new_lease", json!({"new_lease":true})),
        ] {
            let mut extra = extra;
            extra["login"] = json!({"url":"https://example.com/session"});
            let err = get_body(extra).canonicalize().unwrap_err();
            assert!(err.message.contains(flag), "{flag}: {}", err.message);
        }
        assert!(get_body(json!({"login":{"url":"http://example.com/session"}})).canonicalize().is_err());
        let plain = serde_json::to_value(get_body(json!({}))).unwrap();
        assert!(plain.get("login").is_none(), "absent login is not serialized for older managers");
    }

    #[test]
    fn login_wire_fields_are_optional() {
        let info: ProxyInfo = from_str(r#"{"port":7412,"hints":["mac"],"ca_sha256":"ab"}"#).unwrap();
        assert_eq!((info.proxy_auth, info.browser_ca_pem.as_deref()), (false, None));
        let with = ProxyInfo { proxy_auth: true, browser_ca_pem: Some("PEM".into()), ..info };
        assert_eq!(
            to_value(&with).unwrap(),
            json!({"port":7412,"hints":["mac"],"ca_sha256":"ab","proxy_auth":true,"browser_ca_pem":"PEM"})
        );
        let login: RequestBody = from_str(r#"{"kind":"login","name":"","url":"https://example.com/login","reason":"r"}"#).unwrap();
        assert_eq!(login.kind(), RequestKind::Login);
        let RequestBody::Login { extra_fill_origins, client_capabilities, .. } = login else { panic!() };
        assert!(extra_fill_origins.is_empty() && client_capabilities.is_empty());
    }

    #[test]
    fn new_generated_modes_require_raw_without_host_restrictions() {
        assert_eq!(RequestedMode::Default.for_new_generated(&[]).unwrap(), RequestedMode::Raw);
        assert_eq!(RequestedMode::Raw.for_new_generated(&[]).unwrap(), RequestedMode::Raw);
        assert!(RequestedMode::Sentinel.for_new_generated(&[]).unwrap_err().message.contains("--sentinel"));
        assert!(RequestedMode::Default.for_new_generated(&["api.github.com".into()]).unwrap_err()
            .message.contains("--hosts"));
    }

    #[test]
    fn capability_checks_are_targeted_and_do_not_break_legacy_static_requests() {
        let old = get_body(json!({}));
        assert!(!old.supports_operator_selected_grant());
        old.validate_get_capabilities(SourceKind::Vault).unwrap();
        assert!(old.validate_get_capabilities(SourceKind::Generator).is_err());
        for extra in [json!({"fields":["value"]}), json!({"sentinel":true})] {
            assert!(get_body(extra).validate_get_capabilities(SourceKind::Vault).is_err());
        }
        let capable = get_body(json!({
            "lease_id":"known","sentinel":true,"fields":["value"],
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1,CAPABILITY_SECRET_FIELDS_V1,"future"]
        }));
        capable.validate_get_capabilities(SourceKind::Generator).unwrap();
        assert!(!capable.supports_operator_selected_grant());
        let selectable = get_body(json!({
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1,CAPABILITY_OPERATOR_SELECTED_GRANT_V1]
        }));
        assert!(selectable.supports_operator_selected_grant());
        selectable.validate_get_capabilities(SourceKind::Generator).unwrap();
        let health = HealthResponse { name: MANAGER_NAME.into(), version: "new".into(), capabilities: vec![CAPABILITY_SECRET_FIELDS_V1.into()] };
        health.require_capability(CAPABILITY_SECRET_FIELDS_V1).unwrap();
        let error = health.require_capability(CAPABILITY_GENERATED_CREDENTIALS_V1).unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::Invalid);
        assert!(error.message.contains("upgrade the manager"));
        let legacy_github = get_body(json!({
            "generation":{"provider":"github_app","scope":{"repositories":["acme/repo"]}},
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1]
        }));
        assert!(legacy_github.validate_get_capabilities(SourceKind::Generator).unwrap_err()
            .message.contains(CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1));
        let scoped_github = get_body(json!({
            "generation":{"provider":"github_app","scope":{"repositories":["acme/repo"]}},
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1,CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1]
        }));
        scoped_github.validate_get_capabilities(SourceKind::Generator).unwrap();
        let pinned = get_body(json!({"lease_id":"known","client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1]}));
        pinned.validate_get_capabilities(SourceKind::Generator).unwrap();
    }

    #[test]
    fn managed_google_requests_negotiate_their_own_capability() {
        let request = |capabilities| get_body(json!({
            "generation":{"provider":"gcloud_access","scope":{"project_id":"demo-project","permissions":["storage=read"]}},
            "client_capabilities":capabilities
        }));
        assert!(request(vec![CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1])
            .validate_get_capabilities(SourceKind::Generator).unwrap_err().message.contains(CAPABILITY_GCLOUD_ACCESS_V1));
        request(vec![CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GCLOUD_ACCESS_V1])
            .validate_get_capabilities(SourceKind::Generator).unwrap();
    }

    #[test]
    fn project_selection_is_an_independent_opt_in_for_unpinned_managed_google() {
        let mut body = get_body(json!({
            "generation":{"provider":"gcloud_access","scope":{"project_id":"demo-project","permissions":["storage=read"]}},
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1,CAPABILITY_GCLOUD_ACCESS_V1,CAPABILITY_OPERATOR_SELECTED_GRANT_V1]
        }));
        assert!(!body.supports_operator_selected_project());
        let RequestBody::Get { client_capabilities, .. } = &mut body else { panic!() };
        client_capabilities.retain(|capability| capability != CAPABILITY_OPERATOR_SELECTED_GRANT_V1);
        client_capabilities.push(CAPABILITY_OPERATOR_SELECTED_PROJECT_V1.into());
        assert!(body.supports_operator_selected_project());
        assert!(!body.supports_operator_selected_grant());

        let mut value = to_value(&body).unwrap();
        value["lease_id"] = json!("known");
        let pinned: RequestBody = serde_json::from_value(value.clone()).unwrap();
        assert!(!pinned.supports_operator_selected_project());
        value["lease_id"] = serde_json::Value::Null;
        for generation in [json!(null), json!({"provider":"gcloud","scope":{"scopes":null}})] {
            value["generation"] = generation;
            let other: RequestBody = serde_json::from_value(value.clone()).unwrap();
            assert!(!other.supports_operator_selected_project());
        }
    }

    #[test]
    fn broader_reuse_requires_an_opted_in_unpinned_generated_request() {
        let mut value = json!({"generation":{"provider":"github_app","scope":{"repositories":["acme/web"]}}});
        assert!(!get_body(value.clone()).supports_broader_lease_reuse());
        value["client_capabilities"] = json!([CAPABILITY_BROADER_LEASE_REUSE_V1]);
        assert!(get_body(value.clone()).supports_broader_lease_reuse());
        for (field, changed) in [("lease_id", json!("pinned")), ("new_lease", json!(true)), ("generation", json!(null))] {
            let mut other = value.clone();
            other[field] = changed;
            assert!(!get_body(other).supports_broader_lease_reuse());
        }
    }

    #[test]
    fn generated_results_require_durable_version_and_parseable_provider_expiry() {
        let mut value = json!({
            "lease_id":"l","mode":"raw","hosts":[],"expires_at":"2026-11-18T00:00:00Z",
            "files":[{"field":"value","relative_path":"GITHUB_TOKEN","content":"fixture","substituted":false}],
            "generation":{"generator_id":"g","generator_revision":1,"grant":{"provider":"github_app","scope":{
                "installation_id":42,"repositories":[{"id":7,"full_name":"acme/web"}],"permissions":{"metadata":"read"}
            }}},
            "credential_expires_at":"2026-11-17T13:00:00Z","credential_version":1,"generator_name":"review-bot"
        });
        let result: GetResult = serde_json::from_value(value.clone()).unwrap();
        assert!(!result.operator_selected_grant);
        result.validate().unwrap();
        assert_eq!(to_value(&result).unwrap(), value);
        let mut reused = result.clone();
        assert!(!reused.broader_lease_reuse);
        reused.broader_lease_reuse = true;
        reused.validate().unwrap();
        assert_eq!(to_value(&reused).unwrap()["broader_lease_reuse"], true);
        reused.operator_selected_grant = true;
        assert!(reused.validate().is_err());
        {
            let mut approved = value.clone();
            approved["operator_selected_grant"] = json!(true);
            let result: GetResult = serde_json::from_value(approved.clone()).unwrap();
            result.validate().unwrap();
            assert!(result.operator_selected_grant);
            assert_eq!(to_value(&result).unwrap(), approved);
            for key in ["generation", "credential_expires_at", "credential_version", "generator_name"] {
                approved[key] = json!(null);
            }
            assert!(serde_json::from_value::<GetResult>(approved).unwrap().validate().is_err());
        }
        for version in [json!(null), json!(0)] {
            value["credential_version"] = version;
            assert!(serde_json::from_value::<GetResult>(value.clone()).unwrap().validate().is_err());
        }
        value["credential_version"] = json!(2);
        for expiry in [json!(null), json!("not a time")] {
            value["credential_expires_at"] = expiry;
            assert!(serde_json::from_value::<GetResult>(value.clone()).unwrap().validate().is_err());
        }
        value["generation"] = json!(null);
        assert!(serde_json::from_value::<GetResult>(value).unwrap().validate().is_err());
    }

    #[test]
    fn generated_results_cannot_deliver_a_google_connection_or_pending_choice() {
        let access = json!({"project_id":"demo-project","permissions":["storage=read"]});
        for scope in [
            json!({"state":"connection"}),
            json!({"state":"requested","access":access}),
            json!({"state":"issued","access":access,"service_account_unique_id":"123456","service_account_email":"managed@demo-project.iam.gserviceaccount.com"}),
        ] {
            let result: GetResult = serde_json::from_value(json!({
                "lease_id":"l","mode":"raw","hosts":[],"expires_at":null,
                "files":[{"field":"value","relative_path":"CLOUDSDK_AUTH_ACCESS_TOKEN","content":"fixture"}],
                "generation":{"generator_id":"g","generator_revision":1,"grant":{"provider":"gcloud_access","scope":scope}},
                "credential_expires_at":"2026-11-17T13:00:00Z","credential_version":1
            })).unwrap();
            assert_eq!(result.validate().is_ok(), scope["state"] == "issued");
        }
    }
}
