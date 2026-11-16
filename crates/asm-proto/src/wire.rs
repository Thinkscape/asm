//! Serde types of the manager API (`/v1/...`). Ids are UUIDv4 strings; times are
//! RFC 3339 UTC strings, `None`/`null` meaning unlimited.

use crate::error::ApiError;
use crate::rules::validate_agent_text;
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
/// Lease duration choices: label and seconds (`None` = unlimited).
pub const LEASE_DURATIONS: &[(&str, Option<u64>)] = &[
    ("5 min", Some(300)),
    ("15 min", Some(900)),
    ("1 h", Some(3600)),
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
        self.addresses.iter().try_for_each(|a| validate_agent_text("address", a))
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
}

/// One entry of `GET /secrets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub vault: String,
    pub kind: SecretKind,
    pub fields: Vec<String>,
    pub lease: Option<LeaseBrief>,
}

/// `GET /secrets` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsResponse {
    pub secrets: Vec<SecretEntry>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `POST /requests` body, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RequestBody {
    Get {
        name: String,
        #[serde(default)]
        raw: bool,
        #[serde(default)]
        hosts: Vec<String>,
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
    },
}

impl RequestBody {
    /// The request kind.
    pub fn kind(&self) -> RequestKind {
        match self {
            RequestBody::Get { .. } => RequestKind::Get,
            RequestBody::Update { .. } => RequestKind::Update,
            RequestBody::Add { .. } => RequestKind::Add,
        }
    }

    /// The secret name the request is about.
    pub fn name(&self) -> &str {
        match self {
            RequestBody::Get { name, .. } | RequestBody::Update { name, .. } | RequestBody::Add { name, .. } => name,
        }
    }

    /// The agent label.
    pub fn agent(&self) -> &str {
        match self {
            RequestBody::Get { agent, .. } | RequestBody::Update { agent, .. } | RequestBody::Add { agent, .. } => {
                agent
            }
        }
    }
}

/// Kind of a host request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Get,
    Update,
    Add,
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
}

/// Result of an approved request: `GetResult` for `get`, `WriteResult` for `update`/`add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestResult {
    Get(GetResult),
    Write(WriteResult),
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
}

/// One file of a `get` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultFile {
    pub field: String,
    /// `[<vault>/]<name>[.<field>]`; check with [`crate::rules::check_relative_path`].
    pub relative_path: String,
    /// Sentinel, raw value, or the plain username.
    pub content: String,
}

/// Result of an approved `update` or `add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteResult {
    pub name: String,
    pub vault: String,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, json, to_value};

    #[test]
    fn pair_responses() {
        let r: PairResponse = from_str(r#"{"status":"pending"}"#).unwrap();
        assert_eq!(r, PairResponse::Pending { deny_reason: None });
        let r = PairResponse::AwaitingReveal { pair_id: "p".into(), poll_token: "t".into(), server_nonce: "00".into() };
        assert_eq!(
            to_value(&r).unwrap(),
            json!({"status":"awaiting_reveal","pair_id":"p","poll_token":"t","server_nonce":"00"})
        );
        let r: PairResponse = from_str(r#"{"status":"denied","deny_reason":"no"}"#).unwrap();
        assert_eq!(r, PairResponse::Denied { deny_reason: Some("no".into()) });
        let r: PairResponse = from_str(r#"{"status":"approved","host_id":"h","token":"t"}"#).unwrap();
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
        let b = RequestBody::Update { name: "X".into(), field: None, value: "v".into(), agent: "".into() };
        assert_eq!(to_value(&b).unwrap(), json!({"kind":"update","name":"X","field":null,"value":"v","agent":""}));
        let b: RequestBody = from_str(r#"{"kind":"add","name":"X","value":"v"}"#).unwrap();
        assert_eq!(b.agent(), "");
    }

    #[test]
    fn request_states() {
        let get = json!({"request_id":"r","kind":"get","status":"approved","deny_reason":null,
            "result":{"lease_id":"l","mode":"sentinel","hosts":["a.com"],"expires_at":null,
                      "files":[{"field":"value","relative_path":"X","content":"asm_x"}]}});
        let s: RequestState = serde_json::from_value(get.clone()).unwrap();
        assert!(matches!(s.result, Some(RequestResult::Get(GetResult { mode: LeaseMode::Sentinel, .. }))));
        assert_eq!(to_value(&s).unwrap(), get);
        let write = json!({"request_id":"r","kind":"add","status":"approved","deny_reason":null,
            "result":{"name":"X","vault":"v"}});
        let s: RequestState = serde_json::from_value(write).unwrap();
        assert!(matches!(s.result, Some(RequestResult::Write(_))));
        let pending: RequestState =
            from_str(r#"{"request_id":"r","kind":"update","status":"pending","deny_reason":null,"result":null}"#)
                .unwrap();
        assert!(!pending.status.is_terminal());
    }

    #[test]
    fn secrets_and_leases() {
        let s = SecretsResponse {
            secrets: vec![SecretEntry {
                name: "GitHub".into(),
                vault: "work".into(),
                kind: SecretKind::Login,
                fields: vec!["username".into(), "password".into()],
                lease: Some(LeaseBrief { lease_id: "l".into(), mode: LeaseMode::Raw, expires_at: None }),
            }],
            warnings: vec![],
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
    fn host_info_validation() {
        let mut h = HostInfo { hostname: "nuk1".into(), ..Default::default() };
        assert!(h.validate().is_ok());
        h.username = "evil\u{202E}".into();
        assert!(h.validate().is_err());
    }
}
