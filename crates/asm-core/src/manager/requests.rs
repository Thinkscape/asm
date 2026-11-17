//! Host requests (`get`, `update`, `add`) and the shared pending list (which also holds
//! revealed pairing requests). Pending requests, including the values of `update`/`add`,
//! live in memory only; every state change happens under `Core::book`.

use std::collections::HashMap;

use asm_proto::crypto::{new_uuid_v4, sha256};
use asm_proto::generators::{
    GenerationChoice, GenerationRequest, GenerationSelection, SourceKind,
};
use asm_proto::rules::{
    is_broad, new_sentinel, normalize_host_pattern, normalize_host_patterns, relative_paths,
    validate_agent_text, validate_reason, validate_secret_value,
};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{
    GetResult, HostInfo, LeaseMode, RequestBody, RequestKind, RequestResult, RequestState,
    RequestStatus, ResultFile, SecretKind, WriteResult,
};

use super::pairing::{PairAttempt, PairState, Repair};
use super::{
    Core, TOPIC_LEASES, TOPIC_REQUESTS, TOPIC_VAULTS, activity, lock, to_system_time,
};
use crate::error::{CoreError, Result};
use crate::ffi;
use crate::proxy::ProxyEntry;
use crate::store::{HistoryRecord, HostRecord, LeaseField, LeaseRecord};
use crate::vault::names::NamedSecret;
use crate::vault::{AddTarget, CollectionInfo, VaultConfig, VaultStatus};

/// Resolved host requests stay pollable this long.
const DONE_KEEP_SECS: i64 = 3600;
/// Unrevealed pairing attempts expire after this long.
pub const REVEAL_SECS: i64 = 60;

#[derive(Default)]
pub struct Book {
    pub(crate) pending: Vec<Pending>,
    pub(crate) done: HashMap<String, Done>,
    pub(crate) pairs: HashMap<String, PairAttempt>,
}

pub(crate) struct Done {
    pub(crate) host_id: String,
    pub(crate) state: RequestState,
    pub(crate) at: i64,
    pub(crate) generated: Option<GeneratedDelivery>,
}

#[derive(Clone)]
pub(crate) struct GeneratedDelivery {
    pub lease_id: String,
    pub credential_version: u64,
    pub consumed: bool,
}

/// A secret as resolved when the request was made.
#[derive(Debug, Clone)]
pub(crate) struct SecretRef {
    pub vault_id: String,
    pub vault_name: String,
    pub key: String,
    pub kind: SecretKind,
    pub fields: Vec<String>,
    pub display: String,
    /// Name inside the vault after duplicate suffixes (`display` without the vault prefix).
    pub base: String,
    pub prefixed: bool,
}

impl SecretRef {
    fn from_named(n: &NamedSecret) -> Self {
        let base = if n.prefixed {
            n.display
                .split_once('/')
                .map(|(_, b)| b.to_string())
                .unwrap_or_else(|| n.display.clone())
        } else {
            n.display.clone()
        };
        Self {
            vault_id: n.vault_id.clone(),
            vault_name: n.vault_name.clone(),
            key: n.meta.key.clone(),
            kind: n.meta.kind,
            fields: n.meta.fields.clone(),
            display: n.display.clone(),
            base,
            prefixed: n.prefixed,
        }
    }
}

pub(crate) use asm_proto::wire::RequestedMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GeneratorTarget {
    pub requested_name: String,
    pub output_name: String,
    pub pinned_generator_id: Option<String>,
    pub candidates: Vec<GenerationChoice>,
    pub requested_generation: Option<GenerationRequest>,
}

#[derive(Debug, Clone)]
pub(crate) enum GetTarget {
    Vault(SecretRef),
    Generated(GeneratorTarget),
}

impl GetTarget {
    pub(crate) fn display(&self) -> &str {
        match self {
            Self::Vault(s) => &s.display,
            Self::Generated(g) => &g.requested_name,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GetDetail {
    pub target: GetTarget,
    pub mode: RequestedMode,
    pub wanted_fields: Vec<String>,
    pub requested_hosts: Vec<String>,
    pub reason: String,
    pub initial: Vec<String>,
    pub suggestions: Vec<String>,
}

impl GetDetail {
    pub(crate) fn has_substitutable_fields(&self) -> bool {
        self.wanted_fields.iter().any(|f| substitutes(f))
    }
}

pub(crate) fn substitutes(field: &str) -> bool {
    field != "username"
}

#[derive(Debug, Clone)]
pub(crate) struct UpdateDetail {
    pub secret: SecretRef,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AddTargetData {
    pub vault_id: String,
    pub vault_name: String,
    pub kind: ffi::VaultKind,
    pub collections: Vec<CollectionInfo>,
    pub personal_allowed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct AddDetail {
    pub name: String,
    pub value: String,
    pub targets: Vec<AddTargetData>,
}

#[derive(Debug, Clone)]
pub(crate) enum Detail {
    Pair {
        info: HostInfo,
        address: String,
        code: String,
        /// The machine hint the CLI claimed (forgeable).
        machine_hint: Option<String>,
        /// The existing host this request relates to, if any.
        repair: Option<Repair>,
    },
    Get(GetDetail),
    Update(UpdateDetail),
    Add(AddDetail),
}

#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub id: String,
    pub created: i64,
    pub expires: i64,
    /// `None` for pairing requests.
    pub host_id: Option<String>,
    pub host_label: String,
    pub host_info: Option<HostInfo>,
    pub agent: String,
    /// Address the request came from (TCP peer of the manager API).
    pub address: String,
    /// The operator's decision is being carried out (vault access); not expirable/cancellable.
    pub resolving: bool,
    pub error: Option<String>,
    pub detail: Detail,
}

impl Pending {
    pub(crate) fn kind_str(&self) -> &'static str {
        match self.detail {
            Detail::Pair { .. } => "pair",
            Detail::Get(_) => "get",
            Detail::Update(_) => "update",
            Detail::Add(_) => "add",
        }
    }

    fn wire_kind(&self) -> RequestKind {
        match self.detail {
            Detail::Update(_) => RequestKind::Update,
            Detail::Add(_) => RequestKind::Add,
            _ => RequestKind::Get,
        }
    }

    pub(crate) fn summary(&self) -> String {
        match &self.detail {
            Detail::Pair { info, .. } => format!("pair {}", info.hostname),
            Detail::Get(g) => format!(
                "get {}{}",
                g.target.display(),
                if g.mode == RequestedMode::Raw { " (raw)" } else { "" }
            ),
            Detail::Update(u) => format!("update {} ({})", u.secret.display, u.field),
            Detail::Add(a) => format!("add {}", a.name),
        }
    }

    /// Lifetime this request was given, in seconds.
    fn lifetime_secs(&self) -> u64 {
        (self.expires - self.created).max(0) as u64
    }

    fn state(&self) -> RequestState {
        RequestState {
            request_id: self.id.clone(),
            kind: self.wire_kind(),
            status: RequestStatus::Pending,
            deny_reason: None,
            result: None,
            expires_at: Some(fmt_unix(self.expires)),
            pending_lifetime_secs: self.lifetime_secs(),
        }
    }

    /// The terminal state this request ended in (no expiry any more).
    pub(crate) fn ended_state(&self, status: RequestStatus) -> RequestState {
        RequestState {
            status,
            expires_at: None,
            ..self.state()
        }
    }

    pub(crate) fn history(&self, status: RequestStatus, deny_reason: Option<String>, t: i64) -> HistoryRecord {
        HistoryRecord {
            id: self.id.clone(),
            kind: self.kind_str().to_string(),
            host_id: self.host_id.clone(),
            host_label: self.host_label.clone(),
            summary: self.summary(),
            status: status_str(status).to_string(),
            deny_reason,
            created_at: self.created,
            resolved_at: t,
        }
    }
}

pub(crate) fn status_str(s: RequestStatus) -> &'static str {
    match s {
        RequestStatus::Pending => "pending",
        RequestStatus::Approved => "approved",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
        RequestStatus::Cancelled => "cancelled",
    }
}

/// Why an approval did not go through.
pub(crate) enum Fail {
    /// The decision cannot be carried out as given; the request stays pending.
    Keep(CoreError),
    /// The request becomes denied with this reason (e.g. `vault unavailable: …`).
    Deny(String),
}

impl From<CoreError> for Fail {
    fn from(e: CoreError) -> Self {
        Fail::Keep(e)
    }
}

impl From<asm_proto::ApiError> for Fail {
    fn from(e: asm_proto::ApiError) -> Self { Self::Keep(e.into()) }
}

/// Host part of a URI-ish string (`https://a.b:443/x`, `a.b`, `a.b:8080`) as a pattern.
fn uri_host(s: &str) -> Option<String> {
    let s = s.trim();
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    normalize_host_pattern(host).ok()
}

/// Initial (pre-filled) host list and suggestions for the `get` popup.
pub(crate) fn host_candidates(
    requested: &[String],
    remembered: &[String],
    uri: &[String],
) -> (Vec<String>, Vec<String>) {
    let base: &[String] = if !requested.is_empty() {
        requested
    } else if !remembered.is_empty() {
        remembered
    } else {
        uri
    };
    let mut initial: Vec<String> = Vec::new();
    for p in base {
        if p != "*" && !is_broad(p) && !initial.contains(p) {
            initial.push(p.clone());
        }
    }
    let mut suggestions: Vec<String> = Vec::new();
    for p in requested.iter().chain(remembered).chain(uri) {
        if !initial.contains(p) && !suggestions.contains(p) {
            suggestions.push(p.clone());
        }
    }
    (initial, suggestions)
}

fn hash_hex(v: &str) -> [u8; 32] {
    sha256(v.as_bytes())
}

fn is_env_key(name: &str) -> bool {
    let mut c = name.chars();
    matches!(c.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && c.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

impl Core {
    fn record_history(&self, rows: &[HistoryRecord]) {
        for r in rows {
            if let Err(e) = self.store.insert_history(r) {
                log::error!("request history: {}", e.message);
            }
        }
    }

    /// Expire pending requests and unrevealed pairing attempts; prune old resolved ones.
    pub fn expire_requests(&self, t: i64) {
        let mut rows = Vec::new();
        let mut changed = false;
        {
            let _authority = lock(&self.authorization);
            let mut b = lock(&self.book);
            let (expired, keep): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut b.pending)
                .into_iter()
                .partition(|p| p.expires <= t && (!p.resolving || matches!(&p.detail,
                    Detail::Get(GetDetail { target: GetTarget::Generated(_), .. }))));
            b.pending = keep;
            for p in expired {
                changed = true;
                rows.push(p.history(RequestStatus::Expired, None, t));
                self.log(activity::ended(&p, "expired", None));
                match (&p.detail, &p.host_id) {
                    (Detail::Pair { .. }, _) => {
                        if let Some(a) = b.pairs.get_mut(&p.id) {
                            a.state = PairState::Expired;
                            a.ended = Some(t);
                        }
                    }
                    (_, Some(host_id)) => {
                        let state = p.ended_state(RequestStatus::Expired);
                        b.done.insert(
                            p.id.clone(),
                            Done {
                                host_id: host_id.clone(),
                                state,
                                at: t,
                                generated: None,
                            },
                        );
                    }
                    _ => {}
                }
            }
            for a in b.pairs.values_mut() {
                if matches!(a.state, PairState::AwaitingReveal) && a.expires <= t {
                    a.state = PairState::Expired;
                    a.ended = Some(t);
                    changed = true;
                }
            }
            b.done.retain(|_, d| d.at + DONE_KEEP_SECS > t);
            b.pairs
                .retain(|_, a| a.ended.is_none_or(|e| e + DONE_KEEP_SECS > t));
        }
        self.record_history(&rows);
        if changed {
            self.bump();
            if !rows.is_empty() {
                self.notify(TOPIC_REQUESTS);
            }
        }
    }

    /// Resolve a secret name for a host's request; a miss while some vault is not ready →
    /// `vault_unavailable`. A name that no current name resolves (ambiguous or not found)
    /// but that equals the name recorded on one of the host's active leases resolves to
    /// that lease's secret: names becoming vault-prefixed (or getting a `~hash`) must not
    /// break the names an agent already holds leases under.
    pub(crate) fn find_secret(&self, host_id: &str, query: &str) -> Result<NamedSecret> {
        let catalog = self.secret_catalog()?;
        let names = &catalog.static_entries;
        let e = match catalog.resolve(query) {
            Ok(super::catalog::CatalogMatch::Vault(named)) => return Ok(named),
            Ok(super::catalog::CatalogMatch::Generated(_)) => return Err(CoreError::invalid("generated secrets cannot be updated")),
            Err(e) => e,
        };
        if catalog.generated.iter().any(|g| g.static_collisions.iter().any(|n| n == query)) {
            return Err(e);
        }
        if let Some((source, leaf)) = query.rsplit_once('/')
            && matches!(leaf, "GH_TOKEN" | "GITHUB_TOKEN")
            && self.store.leases_of_host(host_id)?.iter().any(|lease|
                lease.source_kind == SourceKind::Generator && lease.vault_name == source) {
            return Err(e);
        }
        if !matches!(
            e.code,
            asm_proto::ErrorCode::NotFound | asm_proto::ErrorCode::Ambiguous
        ) {
            return Err(e);
        }
        if let Some(n) = self.leased_secret(host_id, query, &names)? {
            return Ok(n);
        }
        if e.code != asm_proto::ErrorCode::NotFound {
            return Err(e);
        }
        let unavailable: Vec<String> = self
            .registry
            .all()
            .into_iter()
            .filter(|v| v.provider.status() != VaultStatus::Ready)
            .map(|v| v.name)
            .collect();
        let relevant = match query.split_once('/') {
            Some((vault, _)) => unavailable.iter().any(|u| u == vault),
            None => !unavailable.is_empty(),
        };
        if relevant {
            Err(CoreError::vault_unavailable(format!(
                "{query:?} was not found in the available vaults; unavailable: {}",
                unavailable.join(", ")
            )))
        } else {
            Err(e)
        }
    }

    /// The current entry of the secret behind the host's most recent active lease whose
    /// recorded name is exactly `query`.
    fn leased_secret(
        &self,
        host_id: &str,
        query: &str,
        names: &[NamedSecret],
    ) -> Result<Option<NamedSecret>> {
        let t = self.generation_now();
        let mut leases: Vec<LeaseRecord> = self
            .store
            .leases_of_host(host_id)?
            .into_iter()
            .filter(|l| l.source_kind == SourceKind::Vault && l.name == query && l.is_active(t))
            .collect();
        leases.sort_by_key(|l| std::cmp::Reverse(l.created_at));
        Ok(leases.iter().find_map(|l| {
            names
                .iter()
                .find(|n| n.vault_id == l.vault_id && n.meta.key == l.secret_key)
                .cloned()
        }))
    }

    /// `POST /requests` from `address` (the TCP peer). Returns the state; `approved` only
    /// for the existing-lease shortcut.
    pub fn create_request(
        &self,
        host: &HostRecord,
        address: &str,
        mut body: RequestBody,
    ) -> Result<RequestState> {
        body.canonicalize()?;
        let agent = body.agent().trim().to_string();
        validate_agent_text("agent", &agent)?;
        if agent.chars().count() > 128 {
            return Err(CoreError::invalid("agent label is too long"));
        }
        let t = self.generation_now();
        if !agent.is_empty() {
            self.store.upsert_agent(&host.id, &agent, t)?;
            self.notify(super::TOPIC_HOSTS);
        }
        self.expire_requests(t);
        match body {
            body @ RequestBody::Get { .. } => self.create_get(host, &agent, address, body),
            RequestBody::Update {
                name, field, value, ..
            } => self.create_update(host, &agent, address, &name, field, value),
            RequestBody::Add { name, value, .. } => {
                self.create_add(host, &agent, address, name, value)
            }
        }
    }

    pub(crate) fn new_pending(
        &self,
        host: &HostRecord,
        agent: &str,
        address: &str,
        detail: Detail,
    ) -> Pending {
        let t = self.generation_now();
        let lifetime = self.settings().request_lifetime_secs.max(1) as i64;
        Pending {
            id: new_uuid_v4(),
            created: t,
            expires: t + lifetime,
            host_id: Some(host.id.clone()),
            host_label: host.label().to_string(),
            host_info: Some(host.info.clone()),
            agent: agent.to_string(),
            address: address.to_string(),
            resolving: false,
            error: None,
            detail,
        }
    }

    /// Push a pending request unless an equal one of the same host exists (re-attach).
    pub(crate) fn push_pending(&self, p: Pending, same: impl Fn(&Pending) -> bool) -> RequestState {
        let state = {
            let mut b = lock(&self.book);
            if let Some(existing) = b.pending.iter().find(|q| q.host_id == p.host_id && same(q)) {
                return existing.state();
            }
            self.log(activity::requested(&p));
            let s = p.state();
            b.pending.push(p);
            s
        };
        self.bump();
        self.notify(TOPIC_REQUESTS);
        state
    }

    fn create_get(
        &self,
        host: &HostRecord,
        agent: &str,
        address: &str,
        body: RequestBody,
    ) -> Result<RequestState> {
        let RequestBody::Get {
            name, raw, sentinel, hosts, reason, fields, generation, refresh, new_lease,
            lease_id, refresh_from_version, ..
        } = &body else { unreachable!() };
        let mode = if *raw { RequestedMode::Raw } else if *sentinel {
            RequestedMode::Sentinel
        } else { RequestedMode::Default };
        let reason = validate_reason(reason)?;
        let requested = normalize_host_patterns(hosts)?;
        if let Some(id) = lease_id {
            body.validate_get_capabilities(SourceKind::Generator)?;
            return self.generated_pinned_get(host, agent, name, id, mode, &requested,
                fields.as_deref(), generation.as_ref(), *refresh, *refresh_from_version, &reason);
        }
        let catalog = self.secret_catalog()?;
        let resolved = match catalog.resolve(name) {
            Ok(target) => target,
            Err(e) if matches!(e.code, asm_proto::ErrorCode::NotFound | asm_proto::ErrorCode::Ambiguous) => {
                if catalog.generated.iter().any(|g| g.static_collisions.iter().any(|n| n == name)) {
                    return Err(e);
                }
                super::catalog::CatalogMatch::Vault(self.find_secret(&host.id, name)?)
            }
            Err(e) => return Err(e),
        };
        match resolved {
            super::catalog::CatalogMatch::Generated(super::catalog::CatalogGeneratedTarget {
                requested_name, output_name, pinned_generator_id, candidates,
            }) => {
                body.validate_get_capabilities(SourceKind::Generator)?;
                let target = GeneratorTarget {
                    requested_name, output_name, pinned_generator_id, candidates,
                    requested_generation: generation.clone(),
                };
                let wanted_fields = select_fields(&["value".to_string()], fields.as_deref())?;
                self.create_generated_get(host, agent, address, target, mode, wanted_fields,
                    requested, reason, *new_lease, *refresh, *refresh_from_version)
            }
            super::catalog::CatalogMatch::Vault(named) => {
                body.validate_get_capabilities(SourceKind::Vault)?;
                if generation.is_some() || *refresh || *new_lease || refresh_from_version.is_some() {
                    return Err(CoreError::invalid("generator options require a generated secret"));
                }
                let secret = SecretRef::from_named(&named);
                let wanted_fields = select_fields(&secret.fields, fields.as_deref())?;
                if mode != RequestedMode::Raw
                    && let Some(state) = self.get_shortcut(host, agent, &secret,
                        &wanted_fields, &requested, &reason)? {
                    return Ok(state);
                }
                let remembered = self.store.secret_hosts(&secret.vault_id, &secret.key)?;
                let uri: Vec<String> = named.meta.uri_hosts.iter().filter_map(|u| uri_host(u)).collect();
                let (initial, suggestions) = host_candidates(&requested, &remembered, &uri);
                let detail = GetDetail {
                    target: GetTarget::Vault(secret), mode, wanted_fields,
                    requested_hosts: requested, reason, initial, suggestions,
                };
                let p = self.new_pending(host, agent, address, Detail::Get(detail.clone()));
                Ok(self.push_pending(p, |q| match (&q.detail, &detail.target) {
                    (Detail::Get(g), GetTarget::Vault(s)) => matches!(&g.target,
                        GetTarget::Vault(other) if other.vault_id == s.vault_id && other.key == s.key)
                        && g.mode == detail.mode && g.wanted_fields == detail.wanted_fields
                        && g.requested_hosts == detail.requested_hosts && g.reason == detail.reason,
                    _ => false,
                }))
            }
        }
    }

    /// Existing active sentinel lease covering the request → approved without a popup.
    fn get_shortcut(
        &self,
        host: &HostRecord,
        agent: &str,
        secret: &SecretRef,
        wanted_fields: &[String],
        requested: &[String],
        reason: &str,
    ) -> Result<Option<RequestState>> {
        let t = self.generation_now();
        let mut candidates: Vec<LeaseRecord> = self
            .store
            .leases_of_host(&host.id)?
            .into_iter()
            .filter(|l| {
                l.source_kind == SourceKind::Vault
                    && wanted_fields.iter().all(|f| l.fields.iter().any(|lf| &lf.field == f))
                    &&
                l.is_active(t)
                    && l.mode == LeaseMode::Sentinel
                    && l.vault_id == secret.vault_id
                    && l.secret_key == secret.key
                    && (requested.is_empty()
                        || wanted_fields.iter().all(|f| !substitutes(f))
                        || l.hosts == ["*"]
                        || requested.iter().all(|r| l.hosts.contains(r)))
            })
            .collect();
        // Longest-lived first (unlimited first).
        candidates.sort_by_key(|l| std::cmp::Reverse(l.expires_at.unwrap_or(i64::MAX)));
        let Some(lease) = candidates.into_iter().next() else {
            return Ok(None);
        };

        let needs_values = lease.fields.iter().any(|f| wanted_fields.contains(&f.field) && f.sentinel.is_none());
        let values = if needs_values {
            let entry = self
                .registry
                .get(&lease.vault_id)
                .ok_or_else(|| CoreError::vault_unavailable("vault was removed"))?;
            entry
                .provider
                .read(&lease.secret_key)
                .map_err(|e| CoreError::vault_unavailable(e.message))?
        } else {
            Vec::new()
        };
        let mut files = Vec::new();
        for f in lease.fields.iter().filter(|f| wanted_fields.contains(&f.field)) {
            let content = match &f.sentinel {
                Some(s) => s.clone(),
                None => values
                    .iter()
                    .find(|(n, _)| n == &f.field)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| {
                        CoreError::vault_unavailable(format!(
                            "field {:?} is no longer in the vault",
                            f.field
                        ))
                    })?,
            };
            files.push(ResultFile {
                field: f.field.clone(),
                relative_path: f.path.clone(),
                content,
                substituted: f.sentinel.is_some(),
            });
        }
        if lease.fields.iter().any(|f| wanted_fields.contains(&f.field) && f.sentinel.is_some())
            && (self.suspended().contains_key(&lease.id) || lock(&self.proxy_state).dirty) {
            self.reconcile_proxy_with(true, |_| {})?;
            if self.suspended().contains_key(&lease.id) {
                return Err(CoreError::vault_unavailable("lease is suspended because its vault is unavailable"));
            }
        }
        let id = new_uuid_v4();
        let state = RequestState {
            request_id: id.clone(),
            kind: RequestKind::Get,
            status: RequestStatus::Approved,
            deny_reason: None,
            result: Some(RequestResult::Get(GetResult {
                lease_id: lease.id.clone(),
                mode: LeaseMode::Sentinel,
                hosts: lease.hosts.clone(),
                expires_at: lease.expires_at.map(fmt_unix),
                files,
                generation: None,
                credential_expires_at: None,
                credential_version: None,
                generator_name: None,
            })),
            expires_at: None,
            pending_lifetime_secs: self.settings().request_lifetime_secs.max(1),
        };
        lock(&self.book).done.insert(
            id.clone(),
            Done {
                host_id: host.id.clone(),
                state: state.clone(),
                at: t,
                generated: None,
            },
        );
        self.log(
            activity::Event::new(
                activity::Category::Requests,
                "reused",
                format!("get {} served from an existing lease", secret.display),
            )
            .host(Some(&host.id))
            // The lease's recorded name, like its other rows (names may have been prefixed since).
            .secret(&lease.name)
            .detail(serde_json::json!({
                "request_id": id,
                "request": "get",
                "agent": agent,
                "vault": secret.vault_name,
                "requested_hosts": requested,
                "reason": reason,
                "lease_id": lease.id,
                "lease_hosts": lease.hosts,
                "expires_at": lease.expires_at.map(fmt_unix),
            })),
        );
        self.record_history(&[HistoryRecord {
            id,
            kind: "get".into(),
            host_id: Some(host.id.clone()),
            host_label: host.label().to_string(),
            summary: format!("get {} (existing lease)", secret.display),
            status: "approved".into(),
            deny_reason: None,
            created_at: t,
            resolved_at: t,
        }]);
        self.notify(TOPIC_REQUESTS);
        Ok(Some(state))
    }

    fn create_update(
        &self,
        host: &HostRecord,
        agent: &str,
        address: &str,
        name: &str,
        field: Option<String>,
        value: String,
    ) -> Result<RequestState> {
        validate_secret_value(&value)?;
        if matches!(self.secret_catalog()?.resolve(name), Ok(super::catalog::CatalogMatch::Generated(_))) {
            return Err(CoreError::invalid("generated secrets cannot be updated"));
        }
        let named = self.find_secret(&host.id, name)?;
        let secret = SecretRef::from_named(&named);
        let field = match field
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
        {
            Some(f) => {
                validate_agent_text("field", &f)?;
                f
            }
            None => match secret.kind {
                SecretKind::Login => "password".to_string(),
                SecretKind::Single if secret.fields.len() == 1 => secret.fields[0].clone(),
                _ => {
                    return Err(CoreError::invalid(format!(
                        "{} has several fields ({}); choose one with --field",
                        secret.display,
                        secret.fields.join(", ")
                    )));
                }
            },
        };
        let known = secret.fields.contains(&field)
            || (secret.kind == SecretKind::Login && (field == "password" || field == "username"));
        if !known {
            return Err(CoreError::invalid(format!(
                "{} has no field {field:?}; fields: {}",
                secret.display,
                secret.fields.join(", ")
            )));
        }
        let hash = hash_hex(&value);
        // Re-attach before reading the vault again.
        {
            let b = lock(&self.book);
            if let Some(q) = b.pending.iter().find(|q| {
                q.host_id.as_deref() == Some(&host.id)
                    && matches!(&q.detail, Detail::Update(u) if u.secret.vault_id == secret.vault_id
                        && u.secret.key == secret.key && u.field == field && hash_hex(&u.new_value) == hash)
            }) {
                return Ok(q.state());
            }
        }
        let entry = self
            .registry
            .get(&secret.vault_id)
            .ok_or_else(|| CoreError::vault_unavailable("vault was removed"))?;
        let old_value = entry
            .provider
            .read(&secret.key)
            .map_err(|e| CoreError::vault_unavailable(e.message))?
            .into_iter()
            .find(|(f, _)| f == &field)
            .map(|(_, v)| v)
            .unwrap_or_default();
        let detail = UpdateDetail {
            secret,
            field,
            old_value,
            new_value: value,
        };
        let p = self.new_pending(host, agent, address, Detail::Update(detail.clone()));
        Ok(self.push_pending(p, |q| {
            matches!(&q.detail, Detail::Update(u) if u.secret.vault_id == detail.secret.vault_id
                && u.secret.key == detail.secret.key && u.field == detail.field
                && hash_hex(&u.new_value) == hash)
        }))
    }

    /// Vaults that can receive `add <name>` (plan step 4 table).
    pub(crate) fn add_targets(&self, name: &str) -> Vec<AddTargetData> {
        let mut out = Vec::new();
        for v in self.registry.all() {
            if v.provider.status() != VaultStatus::Ready {
                continue;
            }
            match &v.config {
                VaultConfig::Bitwarden(b) => {
                    if b.collections.is_empty() && !b.personal {
                        continue;
                    }
                    let known = v.provider.collections().unwrap_or_default();
                    let collections = b
                        .collections
                        .iter()
                        .map(|id| {
                            known
                                .iter()
                                .find(|c| &c.id == id)
                                .cloned()
                                .unwrap_or_else(|| CollectionInfo {
                                    id: id.clone(),
                                    name: b
                                        .collection_names
                                        .get(id)
                                        .cloned()
                                        .unwrap_or_else(|| id.clone()),
                                    organization_id: None,
                                })
                        })
                        .collect();
                    out.push(AddTargetData {
                        vault_id: v.id.clone(),
                        vault_name: v.name.clone(),
                        kind: ffi::VaultKind::Bitwarden,
                        collections,
                        personal_allowed: b.personal,
                    });
                }
                VaultConfig::EnvFile { .. } => {
                    if is_env_key(name) {
                        out.push(AddTargetData {
                            vault_id: v.id.clone(),
                            vault_name: v.name.clone(),
                            kind: ffi::VaultKind::EnvFile,
                            collections: Vec::new(),
                            personal_allowed: false,
                        });
                    }
                }
                VaultConfig::Keychain => out.push(AddTargetData {
                    vault_id: v.id.clone(),
                    vault_name: v.name.clone(),
                    kind: ffi::VaultKind::Keychain,
                    collections: Vec::new(),
                    personal_allowed: false,
                }),
            }
        }
        out
    }

    fn create_add(
        &self,
        host: &HostRecord,
        agent: &str,
        address: &str,
        name: String,
        value: String,
    ) -> Result<RequestState> {
        validate_secret_value(&value)?;
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 256 {
            return Err(CoreError::invalid("name must be 1–256 characters"));
        }
        if name.contains('/') {
            return Err(CoreError::invalid("name must not contain '/'"));
        }
        validate_agent_text("name", &name)?;
        if self.secret_catalog()?.has_base_name(&name) {
            return Err(CoreError::exists(format!(
                "a secret named {name:?} already exists; use asm update"
            )));
        }
        let targets = self.add_targets(&name);
        if targets.is_empty() {
            return Err(CoreError::vault_unavailable(format!(
                "no available vault can store a secret named {name:?}"
            )));
        }
        let hash = hash_hex(&value);
        let detail = AddDetail {
            name,
            value,
            targets,
        };
        let p = self.new_pending(host, agent, address, Detail::Add(detail.clone()));
        Ok(self.push_pending(p, |q| {
            matches!(&q.detail, Detail::Add(a) if a.name == detail.name && hash_hex(&a.value) == hash)
        }))
    }

    /// `GET /requests/{id}`: the request's state. A raw result is returned once, then dropped.
    pub fn request_state(&self, host_id: &str, id: &str) -> Result<RequestState> {
        self.expire_requests(self.generation_now());
        let marker = {
            let mut book = lock(&self.book);
            if let Some(pending) = book.pending.iter().find(|p| p.id == id && p.host_id.as_deref() == Some(host_id)) {
                return Ok(pending.state());
            }
            let done = book.done.get_mut(id).filter(|d| d.host_id == host_id)
                .ok_or_else(|| CoreError::not_found("no such request"))?;
            if let Some(marker) = &done.generated { marker.clone() } else {
                let state = done.state.clone();
                if matches!(&done.state.result, Some(RequestResult::Get(g)) if g.mode == LeaseMode::Raw) {
                    done.state.result = None;
                }
                return Ok(state);
            }
        };
        let outcome = (|| -> Result<RequestState> {
            let authority = lock(&self.authorization);
            let mode = self.check_generated_delivery(&marker.lease_id, marker.credential_version)?;
            if mode == LeaseMode::Sentinel && lock(&self.proxy_state).dirty {
                self.publish_proxy_locked(&authority).map_err(|_|
                    CoreError::vault_unavailable("generated credential publication failed; run asm get to retry"))?;
            }
            let result = self.validate_generated_delivery(&marker.lease_id, marker.credential_version)?;
            let mut book = lock(&self.book);
            let done = book.done.get_mut(id).filter(|d| d.host_id == host_id)
                .ok_or_else(|| CoreError::not_found("no such request"))?;
            let delivery = done.generated.as_mut().filter(|d| d.lease_id == marker.lease_id
                && d.credential_version == marker.credential_version)
                .ok_or_else(|| CoreError::vault_unavailable("generated credential is no longer available; run asm get again"))?;
            if result.mode == LeaseMode::Raw && delivery.consumed {
                return Err(CoreError::vault_unavailable("generated credential is no longer available; run asm get again"));
            }
            if result.mode == LeaseMode::Raw { delivery.consumed = true; }
            let mut state = done.state.clone();
            state.result = Some(RequestResult::Get(result));
            Ok(state)
        })();
        self.notify_proxy_changed();
        outcome
    }

    /// `DELETE /requests/{id}`.
    pub fn cancel_request(&self, host_id: &str, id: &str) -> Result<RequestState> {
        let t = self.generation_now();
        self.expire_requests(t);
        let (state, row) = {
            let _authority = lock(&self.authorization);
            let mut b = lock(&self.book);
            let pos = b
                .pending
                .iter()
                .position(|p| p.id == id && p.host_id.as_deref() == Some(host_id));
            match pos {
                Some(i) if !b.pending[i].resolving || matches!(&b.pending[i].detail,
                    Detail::Get(GetDetail { target: GetTarget::Generated(_), .. })) => {
                    let p = b.pending.remove(i);
                    let state = p.ended_state(RequestStatus::Cancelled);
                    b.done.insert(
                        p.id.clone(),
                        Done {
                            host_id: host_id.to_string(),
                            state: state.clone(),
                            at: t,
                            generated: None,
                        },
                    );
                    self.log(activity::ended(&p, "cancelled", None));
                    (state, Some(p.history(RequestStatus::Cancelled, None, t)))
                }
                Some(i) => (b.pending[i].state(), None),
                None => match b.done.get_mut(id).filter(|d| d.host_id == host_id) {
                    Some(d) => {
                        if let Some(delivery) = d.generated.as_mut() { delivery.consumed = true; }
                        if matches!(&d.state.result, Some(RequestResult::Get(g)) if g.mode == LeaseMode::Raw) {
                            d.state.result = None;
                        }
                        (d.state.clone(), None)
                    }
                    None => return Err(CoreError::not_found("no such request")),
                },
            }
        };
        if let Some(row) = row {
            self.record_history(&[row]);
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
        Ok(state)
    }

    /// Cancel every pending request of a host (host revoked).
    pub(crate) fn cancel_host_requests(&self, host_id: &str) {
        let t = self.generation_now();
        let rows: Vec<HistoryRecord> = {
            let _authority = lock(&self.authorization);
            let mut b = lock(&self.book);
            let (gone, keep): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut b.pending)
                .into_iter()
                .partition(|p| p.host_id.as_deref() == Some(host_id));
            b.pending = keep;
            gone.iter()
                .map(|p| {
                    let state = p.ended_state(RequestStatus::Cancelled);
                    b.done.insert(
                        p.id.clone(),
                        Done {
                            host_id: host_id.to_string(),
                            state,
                            at: t,
                            generated: None,
                        },
                    );
                    self.log(activity::ended(p, "cancelled", Some("host revoked")));
                    p.history(RequestStatus::Cancelled, Some("host revoked".into()), t)
                })
                .collect()
        };
        if !rows.is_empty() {
            self.record_history(&rows);
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
    }

    // ---- resolution ----

    /// Carry out the operator's decision on a pending request.
    pub fn resolve_request(&self, id: &str, decision: ffi::Decision) -> Result<()> {
        let t = self.generation_now();
        self.expire_requests(t);
        // Phase 1: claim the request.
        let p = {
            let mut b = lock(&self.book);
            let Some(i) = b.pending.iter().position(|p| p.id == id) else {
                return Err(CoreError::not_found("this request is no longer pending"));
            };
            if b.pending[i].resolving {
                return Err(CoreError::invalid("this request is already being resolved"));
            }
            let ok = matches!(
                (&b.pending[i].detail, &decision),
                (_, ffi::Decision::Deny { .. })
                    | (Detail::Pair { .. }, ffi::Decision::ApprovePair { .. })
                    | (Detail::Get(_), ffi::Decision::ApproveGet { .. })
                    | (Detail::Update(_), ffi::Decision::ApproveWrite { .. })
                    | (Detail::Add(_), ffi::Decision::ApproveWrite { .. })
            );
            if !ok {
                return Err(CoreError::invalid(
                    "this decision does not fit the request kind",
                ));
            }
            if let ffi::Decision::Deny { reason } = &decision {
                let reason = Some(reason.trim().to_string()).filter(|r| !r.is_empty());
                let p = b.pending.remove(i);
                drop(b);
                self.finish(p, Err(reason), t, false);
                return Ok(());
            }
            b.pending[i].resolving = true;
            b.pending[i].clone()
        };

        // Phase 2: do the work without holding the book.
        let outcome: std::result::Result<Option<RequestResult>, Fail> = match (&p.detail, decision)
        {
            (Detail::Pair { .. }, ffi::Decision::ApprovePair { name, replace }) => {
                self.approve_pair(&p, &name, replace).map(|_| None)
            }
            (
                Detail::Get(g),
                ffi::Decision::ApproveGet {
                    mode,
                    duration_secs,
                    hosts,
                    generation,
                },
            ) => match generation.map(GenerationSelection::try_from).transpose() {
                Ok(selection) => self.approve_get(&p, g, mode.into(), duration_secs, hosts, selection)
                    .map(|r| Some(RequestResult::Get(r))),
                Err(error) => Err(Fail::Keep(error)),
            },
            (Detail::Update(u), ffi::Decision::ApproveWrite { vault_id, .. }) => self
                .approve_update(u, &vault_id)
                .map(|r| Some(RequestResult::Write(r))),
            (
                Detail::Add(a),
                ffi::Decision::ApproveWrite {
                    vault_id,
                    collection_id,
                },
            ) => self
                .approve_add(a, &vault_id, collection_id)
                .map(|r| Some(RequestResult::Write(r))),
            _ => Err(Fail::Keep(CoreError::invalid(
                "this decision does not fit the request kind",
            ))),
        };

        // Phase 3: record the outcome.
        let t = self.generation_now();
        match outcome {
            Ok(result) => {
                let p = self.take_pending(id);
                if let Some(p) = p {
                    self.finish(p, Ok(result), t, false);
                }
                Ok(())
            }
            Err(Fail::Keep(e)) => {
                {
                    let mut b = lock(&self.book);
                    if let Some(q) = b.pending.iter_mut().find(|q| q.id == id) {
                        q.resolving = false;
                        q.error = Some(e.message.clone());
                    }
                }
                self.notify(TOPIC_REQUESTS);
                Err(e)
            }
            Err(Fail::Deny(reason)) => {
                if let Some(p) = self.take_pending(id) {
                    self.finish(p, Err(Some(reason.clone())), t, true);
                }
                Err(CoreError::vault_unavailable(reason))
            }
        }
    }

    fn take_pending(&self, id: &str) -> Option<Pending> {
        let mut b = lock(&self.book);
        let i = b.pending.iter().position(|p| p.id == id)?;
        Some(b.pending.remove(i))
    }

    /// Move a removed pending request to its terminal state. `Ok(result)` = approved,
    /// `Err(reason)` = denied (`failed`: by a vault failure while approving).
    pub(crate) fn finish(
        &self,
        p: Pending,
        outcome: std::result::Result<Option<RequestResult>, Option<String>>,
        t: i64,
        failed: bool,
    ) {
        let event = match &outcome {
            Ok(r) => activity::approved(&p, r.as_ref(), t),
            Err(reason) => activity::ended(
                &p,
                if failed { "failed" } else { "denied" },
                reason.as_deref(),
            ),
        };
        self.log(event);
        let (status, deny_reason, result) = match outcome {
            Ok(r) => (RequestStatus::Approved, None, r),
            Err(reason) => (RequestStatus::Denied, reason, None),
        };
        {
            let mut b = lock(&self.book);
            match (&p.detail, &p.host_id) {
                (Detail::Pair { .. }, _) => {
                    if let Some(a) = b.pairs.get_mut(&p.id) {
                        if status == RequestStatus::Denied {
                            a.state = PairState::Denied(deny_reason.clone());
                        }
                        a.ended = Some(t);
                    }
                }
                (_, Some(host_id)) => {
                    let mut state = p.ended_state(status);
                    state.deny_reason = deny_reason.clone();
                    state.result = result;
                    b.done.insert(
                        p.id.clone(),
                        Done {
                            host_id: host_id.clone(),
                            state,
                            at: t,
                            generated: None,
                        },
                    );
                }
                _ => {}
            }
        }
        self.record_history(&[p.history(status, deny_reason, t)]);
        self.bump();
        self.notify(TOPIC_REQUESTS);
    }

    fn approve_get(
        &self,
        p: &Pending,
        g: &GetDetail,
        mode: LeaseMode,
        duration_secs: Option<u64>,
        hosts: Vec<String>,
        generation: Option<GenerationSelection>,
    ) -> std::result::Result<GetResult, Fail> {
        if g.mode == RequestedMode::Sentinel && mode == LeaseMode::Raw {
            return Err(Fail::Keep(CoreError::invalid("this request requires sentinel delivery")));
        }
        if let GetTarget::Generated(target) = &g.target {
            return self.approve_generated_get(p, g, target, mode, duration_secs, hosts, generation);
        }
        if generation.is_some() {
            return Err(Fail::Keep(CoreError::invalid("static secrets cannot select a generator")));
        }
        let hosts = match mode {
            LeaseMode::Raw => Vec::new(),
            LeaseMode::Sentinel => {
                let h = normalize_host_patterns(&hosts).map_err(CoreError::from)?;
                if h.is_empty() && g.has_substitutable_fields() {
                    return Err(Fail::Keep(CoreError::invalid(
                        "choose at least one host, or Any host",
                    )));
                }
                if h.iter().any(|x| x == "*") {
                    vec!["*".to_string()]
                } else {
                    h
                }
            }
        };
        let GetTarget::Vault(s) = &g.target else { unreachable!() };
        let entry = self
            .registry
            .get(&s.vault_id)
            .ok_or_else(|| Fail::Deny("vault unavailable: vault was removed".into()))?;
        let mut values = entry
            .provider
            .read(&s.key)
            .map_err(|e| Fail::Deny(format!("vault unavailable: {}", e.message)))?;
        for field in &g.wanted_fields {
            if !values.iter().any(|(f, _)| f == field) {
                return Err(Fail::Keep(CoreError::vault_unavailable("an approved field is no longer available")));
            }
        }
        values.retain(|(f, _)| g.wanted_fields.contains(f));
        if values.is_empty() {
            return Err(Fail::Deny(
                "vault unavailable: the secret has no fields".into(),
            ));
        }
        let field_names: Vec<&str> = values.iter().map(|(f, _)| f.as_str()).collect();
        let paths = relative_paths(
            s.prefixed.then_some(s.vault_name.as_str()),
            &s.base,
            s.kind,
            &field_names,
        );
        let lease_id = new_uuid_v4();
        let t = self.generation_now();
        let mut files = Vec::new();
        let mut fields = Vec::new();
        let mut entries = Vec::new();
        for (index, ((field, value), path)) in values.iter().zip(paths).enumerate() {
            let sentinel = (mode == LeaseMode::Sentinel && substitutes(field)).then(new_sentinel);
            if let Some(sv) = &sentinel {
                entries.push(ProxyEntry {
                    lease_id: lease_id.clone(),
                    index,
                    sentinel: sv.clone(),
                    value: value.clone(),
                    hosts: hosts.clone(),
                });
            }
            files.push(ResultFile {
                field: field.clone(),
                relative_path: path.clone(),
                content: sentinel.clone().unwrap_or_else(|| value.clone()),
                substituted: sentinel.is_some(),
            });
            fields.push(LeaseField {
                field: field.clone(),
                sentinel,
                path,
            });
        }
        let expires_at = duration_secs.map(|d| t.saturating_add(d.min(i64::MAX as u64) as i64));
        let lease = LeaseRecord {
            id: lease_id.clone(),
            host_id: p.host_id.clone().unwrap_or_default(),
            vault_id: s.vault_id.clone(),
            vault_name: s.vault_name.clone(),
            secret_key: s.key.clone(),
            name: s.display.clone(),
            mode,
            fields,
            hosts: hosts.clone(),
            reason: g.reason.clone(),
            agent: p.agent.clone(),
            created_at: t,
            expires_at,
            revoked_at: None,
            source_kind: SourceKind::Vault,
            generation: None,
            generator_revision: None,
            credential_expires_at: None,
            approval_order: None,
            credential_version: 0,
            requested_generation: None,
        };
        self.store.insert_lease(&lease)?;
        self.log_lease_created(&lease);
        if mode == LeaseMode::Sentinel && g.has_substitutable_fields() {
            self.store
                .replace_secret_hosts(&s.vault_id, &s.key, &hosts)?;
            self.sync_proxy_with(false, |st| {
                st.dirty = true;
                st.entries.insert(lease_id.clone(), entries);
            });
        }
        lock(&self.last_active).insert(lease_id.clone());
        self.notify(TOPIC_LEASES);
        Ok(GetResult {
            lease_id,
            mode,
            hosts,
            expires_at: expires_at.map(fmt_unix),
            files,
            generation: None,
            credential_expires_at: None,
            credential_version: None,
            generator_name: None,
        })
    }

    fn approve_update(
        &self,
        u: &UpdateDetail,
        vault_id: &str,
    ) -> std::result::Result<WriteResult, Fail> {
        let s = &u.secret;
        if vault_id != s.vault_id {
            return Err(Fail::Keep(CoreError::invalid(
                "an update is written to the secret's own vault",
            )));
        }
        let entry = self
            .registry
            .get(&s.vault_id)
            .ok_or_else(|| Fail::Deny("vault unavailable: vault was removed".into()))?;
        entry
            .provider
            .update(&s.key, &u.field, &u.new_value)
            .map_err(|e| Fail::Deny(format!("vault unavailable: {}", e.message)))?;
        let t = self.generation_now();
        let leases: Vec<LeaseRecord> = self
            .store
            .active_leases(t)
            .map_err(Fail::Keep)?
            .into_iter()
            .filter(|l| l.source_kind == SourceKind::Vault && l.vault_id == s.vault_id && l.secret_key == s.key)
            .collect();
        for l in leases.iter().filter(|l| l.mode == LeaseMode::Raw) {
            match self.store.revoke_lease(&l.id, t) {
                Ok(true) => self.log_lease_revoked(l, "secret updated"),
                Ok(false) => {}
                Err(e) => log::error!("revoke raw lease after update: {}", e.message),
            }
        }
        let sentinel: Vec<&LeaseRecord> = leases
            .iter()
            .filter(|l| l.mode == LeaseMode::Sentinel)
            .collect();
        self.sync_proxy_with(false, |st| {
            st.dirty = true;
            for l in &sentinel {
                if let Some(es) = st.entries.get_mut(&l.id) {
                    for e in es.iter_mut() {
                        if l.fields.get(e.index).is_some_and(|f| f.field == u.field) {
                            e.value = u.new_value.clone();
                        }
                    }
                }
            }
        });
        if !leases.is_empty() {
            self.notify(TOPIC_LEASES);
        }
        self.notify(TOPIC_VAULTS);
        Ok(WriteResult {
            name: s.display.clone(),
            vault: s.vault_name.clone(),
        })
    }

    fn approve_add(
        &self,
        a: &AddDetail,
        vault_id: &str,
        collection_id: Option<String>,
    ) -> std::result::Result<WriteResult, Fail> {
        let Some(target) = a.targets.iter().find(|t| t.vault_id == vault_id) else {
            return Err(Fail::Keep(CoreError::invalid(
                "choose one of the offered vaults",
            )));
        };
        let collection_id = match target.kind {
            ffi::VaultKind::Bitwarden => match collection_id {
                Some(c) if target.collections.iter().any(|x| x.id == c) => Some(c),
                None if target.personal_allowed => None,
                _ => {
                    return Err(Fail::Keep(CoreError::invalid(
                        "choose one of the offered collections",
                    )));
                }
            },
            _ => None,
        };
        if self.secret_catalog()?.has_base_name(&a.name) {
            return Err(Fail::Deny(format!(
                "a secret named {:?} already exists",
                a.name
            )));
        }
        let entry = self
            .registry
            .get(vault_id)
            .ok_or_else(|| Fail::Deny("vault unavailable: vault was removed".into()))?;
        entry
            .provider
            .add(&a.name, &a.value, &AddTarget { collection_id })
            .map_err(|e| Fail::Deny(format!("vault unavailable: {}", e.message)))?;
        self.notify(TOPIC_VAULTS);
        Ok(WriteResult {
            name: a.name.clone(),
            vault: target.vault_name.clone(),
        })
    }

    // ---- snapshot ----

    pub fn snapshot(&self) -> ffi::Snapshot {
        self.expire_requests(self.generation_now());
        let default_duration = self.settings().lease_default_secs;
        let pending: Vec<Pending> = lock(&self.book).pending.clone();
        // Labels follow renames: look up the host's current name.
        let mut names = self.host_names();
        let pending = pending
            .into_iter()
            .map(|mut p| {
                if let Some((label, _)) = p.host_id.as_deref().and_then(|id| names.get(id)) {
                    p.host_label = label.clone();
                }
                pending_to_ffi(self, p, default_duration)
            })
            .collect();
        let recent = self
            .store
            .recent_history(10)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|h| {
                let outcome = match h.status.as_str() {
                    "approved" => ffi::RequestOutcome::Approved,
                    "denied" => ffi::RequestOutcome::Denied,
                    "expired" => ffi::RequestOutcome::Expired,
                    "cancelled" => ffi::RequestOutcome::Cancelled,
                    _ => return None,
                };
                Some(ffi::RecentRequest {
                    id: h.id,
                    kind: kind_from_str(&h.kind),
                    summary: h.summary,
                    host_label: h
                        .host_id
                        .as_deref()
                        .and_then(|id| names.get(id))
                        .map(|(label, _)| label.clone())
                        .unwrap_or(h.host_label),
                    outcome,
                    deny_reason: h.deny_reason,
                    resolved_at: to_system_time(h.resolved_at),
                })
            })
            .collect();
        ffi::Snapshot { pending, recent }
    }
}

fn select_fields(available: &[String], wanted: Option<&[String]>) -> Result<Vec<String>> {
    let mut fields = wanted.unwrap_or(available).to_vec();
    if fields.is_empty() || fields.iter().any(|f| !available.contains(f)) {
        return Err(CoreError::invalid(format!("choose fields from: {}", available.join(", "))));
    }
    fields.sort();
    fields.dedup();
    Ok(fields)
}

fn kind_from_str(s: &str) -> ffi::RequestKind {
    match s {
        "pair" => ffi::RequestKind::Pair,
        "update" => ffi::RequestKind::Update,
        "add" => ffi::RequestKind::Add,
        _ => ffi::RequestKind::Get,
    }
}

fn pattern_check(p: &str) -> ffi::HostPatternCheck {
    ffi::HostPatternCheck {
        normalized: p.to_string(),
        broad: is_broad(p),
    }
}

fn pending_to_ffi(core: &Core, p: Pending, default_duration: Option<u64>) -> ffi::PendingRequest {
    let summary = p.summary();
    let kind = kind_from_str(p.kind_str());
    let detail = match p.detail {
        Detail::Pair {
            info,
            address,
            code,
            repair,
            ..
        } => ffi::RequestDetail::Pair {
            host_info: info.into(),
            observed_address: address,
            code,
            repair: repair.map(|r| ffi::RepairInfo {
                kind: r.kind().to_string(),
                host_id: r.host_id,
                host_name: r.host_name,
                paired_at: to_system_time(r.paired_at),
            }),
        },
        Detail::Get(g) => {
            let has_substitutable_fields = g.has_substitutable_fields();
            let (name, vault_id, vault_name, kind, generator_choices, requested_generation) = match &g.target {
                GetTarget::Vault(s) => (s.display.clone(), Some(s.vault_id.clone()), s.vault_name.clone(),
                    s.kind, Vec::new(), None),
                GetTarget::Generated(target) => (
                    target.requested_name.clone(), target.pinned_generator_id.clone(), "GitHub App".into(),
                    SecretKind::Single, target.candidates.iter().map(|choice| ffi::GeneratorApprovalChoice {
                        choice: choice.clone().into(),
                        suggested_hosts: {
                            let remembered = core.store.secret_hosts(&choice.generator_id, "token").unwrap_or_default();
                            let (initial, suggestions) = host_candidates(&g.requested_hosts, &remembered, &["api.github.com".into()]);
                            initial.iter().chain(&suggestions).map(|h| pattern_check(h)).collect()
                        },
                        scope_issues: target.requested_generation.as_ref().map(|request|
                            choice.ceiling.scope_issues(request).unwrap_or_else(|e| vec![e.message])).unwrap_or_default(),
                    }).collect(), target.requested_generation.clone().map(Into::into)),
            };
            ffi::RequestDetail::Get {
                name, vault_id, vault_name, kind: kind.into(), fields: g.wanted_fields,
                reason: g.reason, raw_requested: g.mode == RequestedMode::Raw
                    || (g.mode == RequestedMode::Default && matches!(g.target, GetTarget::Generated(_))),
                sentinel_required: g.mode == RequestedMode::Sentinel, has_substitutable_fields,
                generator_choices, requested_generation,
                requested_hosts: g.requested_hosts,
                initial_hosts: g.initial.iter().map(|h| pattern_check(h)).collect(),
                suggested_hosts: g.suggestions.iter().map(|h| pattern_check(h)).collect(),
                default_duration_secs: default_duration,
            }
        },
        Detail::Update(u) => ffi::RequestDetail::Update {
            name: u.secret.display,
            vault_id: u.secret.vault_id,
            vault_name: u.secret.vault_name,
            field: u.field,
            old_value: u.old_value,
            new_value: u.new_value,
        },
        Detail::Add(a) => ffi::RequestDetail::Add {
            name: a.name,
            value: a.value,
            targets: a
                .targets
                .into_iter()
                .map(|t| ffi::AddTarget {
                    vault_id: t.vault_id,
                    vault_name: t.vault_name,
                    kind: t.kind,
                    collections: t.collections.into_iter().map(Into::into).collect(),
                    personal_allowed: t.personal_allowed,
                })
                .collect(),
        },
    };
    ffi::PendingRequest {
        id: p.id,
        kind,
        created_at: to_system_time(p.created),
        expires_at: to_system_time(p.expires),
        host_id: p.host_id,
        host_label: p.host_label,
        host_info: p.host_info.map(Into::into),
        agent: p.agent,
        address: p.address,
        summary,
        error: p.error,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn host_list_initial_value() {
        // Requested hosts win; broad and `*` are only suggested.
        let (i, s) = host_candidates(
            &v(&["api.github.com", "*", "*github.com"]),
            &v(&["old.example.com"]),
            &v(&["github.com"]),
        );
        assert_eq!(i, v(&["api.github.com"]));
        assert_eq!(s, v(&["*", "*github.com", "old.example.com", "github.com"]));
        // Then remembered hosts.
        let (i, _) = host_candidates(&[], &v(&["old.example.com"]), &v(&["github.com"]));
        assert_eq!(i, v(&["old.example.com"]));
        // Then URI hosts.
        let (i, s) = host_candidates(&[], &[], &v(&["github.com"]));
        assert_eq!(i, v(&["github.com"]));
        assert!(s.is_empty());
    }

    #[test]
    fn uri_hosts() {
        assert_eq!(
            uri_host("https://user@API.github.com:443/login?x=1").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(uri_host("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            uri_host("http://[::1]:8080/"),
            None,
            "IPv6 literals are not valid patterns"
        );
        assert_eq!(uri_host("androidapp://"), None);
    }

    #[test]
    fn env_keys() {
        assert!(is_env_key("DEMO_TOKEN"));
        assert!(is_env_key("_x1"));
        assert!(!is_env_key("1X"));
        assert!(!is_env_key("my-key"));
        assert!(!is_env_key(""));
    }
}
