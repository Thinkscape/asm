//! Host requests (`get`, `update`, `add`) and the shared request book. Each request
//! is sealed as one durable row, and transitions commit before changing the live book.

use std::borrow::Cow;
use std::collections::HashMap;

use asm_proto::crypto::{new_uuid_v4, sha256};
use asm_proto::generators::{
    GcloudAccessGrant, GcloudAccessRequest, GenerationChoice, GenerationGrant, GenerationRequest,
    GenerationSelection, SourceKind,
};
use asm_proto::rules::{
    is_broad, new_sentinel, normalize_host_pattern, normalize_host_patterns, parse_https_url, parse_login_url,
    relative_paths, validate_agent_text, validate_reason, validate_secret_value,
};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{
    BrowserLoginMode, BrowserLoginRequest, GetResult, HostInfo, LeaseMode, LoginScope, RequestBody, RequestKind,
    RequestResult, RequestState, RequestStatus, ResultFile, SecretKind, WriteResult,
};
use serde::{Deserialize, Serialize};

use super::catalog::CatalogMatch;
use super::generation::GeneratedApproval;
use super::pairing::{PairAttempt, PairState, Repair};
use super::resume::SealedResume;
use super::{
    Core, TOPIC_LEASES, TOPIC_REQUESTS, TOPIC_VAULTS, activity, lock, to_system_time,
};
use crate::broker::{self, SessionSpec, fill};
use crate::error::{CoreError, REQUEST_UNAVAILABLE, Result};
use crate::ffi;
use crate::proxy::{LoginBinding, ProxyEntry};
use crate::store::{HistoryRecord, HostRecord, LeaseField, LeaseRecord};
use crate::vault::names::NamedSecret;
use crate::vault::{AddTarget, CollectionInfo, VaultConfig, VaultStatus, registry::VaultEntry};
use zeroize::Zeroizing;

/// Resolved host requests stay pollable this long.
const DONE_KEEP_SECS: i64 = 3600;
/// Longest login grant; also how long its site stays routed through asm.
const LOGIN_MAX_SECS: u64 = 3600;
/// Default lifetime of a storage state handed over by the login broker.
const BROKER_DEFAULT_SECS: u64 = 3600;
/// Most extra origins the login broker may fill besides the requested site.
const MAX_EXTRA_FILL_ORIGINS: usize = 5;
/// Longest URL `asm login` opens.
const MAX_LOGIN_URL_BYTES: usize = 2048;
/// The broker exports its storage state as this one file.
const STORAGE_STATE_FIELD: &str = "storage-state";
/// Bound the sealed pending row and its eventual delivery transaction.
const MAX_GITHUB_CALLERS: usize = 64;
/// Unrevealed pairing attempts expire after this long.
pub const REVEAL_SECS: i64 = 60;

const BOOK_NAMESPACE: &str = "request-book-v1";
const INTERRUPTED: &str = "Approval was interrupted. Verify whether the operation completed before deciding again.";
const LEGACY_LOGIN: &str = "This browser login requires a new account selection. Upgrade the CLI and request it again.";

#[derive(Default)]
pub struct Book {
    pub(crate) pending: Vec<Pending>,
    pub(crate) done: HashMap<String, Done>,
    pub(crate) pairs: HashMap<String, PairAttempt>,
}

impl Book {
    /// Only host polling and cancellation accept delivery IDs. Operator decisions use `Pending::id`.
    pub(super) fn pending_for_caller(&self, host_id: &str, id: &str) -> Option<&Pending> {
        self.pending.iter().find(|p| p.host_id.as_deref() == Some(host_id)
            && (p.id == id || p.attached_ids.iter().any(|attached| attached == id)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Done {
    pub(crate) host_id: String,
    pub(crate) state: RequestState,
    pub(crate) at: i64,
    pub(crate) generated: Option<GeneratedDelivery>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GeneratedDelivery {
    pub lease_id: String,
    pub credential_version: u64,
    pub consumed: bool,
    pub operator_selected_grant: bool,
}

/// One upsert atomically replaces a request's prior state. A revealed pairing
/// attempt and its popup are stored together; neither can outlive the other.
#[derive(Serialize, Deserialize)]
enum BookRow<'a> {
    Pending(Cow<'a, Pending>),
    Done(Cow<'a, Done>),
    Pair {
        attempt: Cow<'a, PairAttempt>,
        pending: Option<Cow<'a, Pending>>,
    },
}

/// A secret as resolved when the request was made.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GeneratorTarget {
    pub requested_name: String,
    pub output_name: String,
    pub pinned_generator_id: Option<String>,
    pub candidates: Vec<GenerationChoice>,
    pub requested_generation: Option<GenerationRequest>,
    pub operator_selected_grant: bool,
    pub operator_selected_gcloud_project: bool,
}

impl GeneratorTarget {
    pub(super) fn allows_reviewed_gcloud_access(&self, selected: &GcloudAccessRequest) -> bool {
        let Some(GenerationRequest::GcloudAccess(requested)) = &self.requested_generation else {
            return false;
        };
        (selected.project_id == requested.project_id || self.operator_selected_gcloud_project)
            && (selected.permissions == requested.permissions || self.operator_selected_grant)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GetDetail {
    pub target: GetTarget,
    pub mode: RequestedMode,
    pub wanted_fields: Vec<String>,
    pub requested_hosts: Vec<String>,
    pub reason: String,
    pub initial: Vec<String>,
    pub suggestions: Vec<String>,
    /// Decode v1 pending rows only; they are denied on restore, never approved as ordinary gets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginScope>,
}

impl GetDetail {
    pub(crate) fn has_substitutable_fields(&self) -> bool {
        self.wanted_fields.iter().any(|f| substitutes(f))
    }
}

/// Whether a sentinel lease delivers `field` as a sentinel (else as its plain value).
pub(crate) fn substitutes(field: &str) -> bool {
    !matches!(field, "username" | "totp")
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct UpdateDetail {
    pub secret: SecretRef,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AddDetail {
    pub name: String,
    pub value: String,
}

/// No vault item is attached to a pending browser request, even when only one matches.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LoginDetail {
    pub mode: BrowserLoginMode,
    pub site: Option<String>,
    pub account: Option<String>,
    /// Exact credential endpoint (grant) or sign-in page (broker).
    pub url: String,
    /// Empty for grants; for brokers the export origin first, then allowed extras.
    pub fill_origins: Vec<String>,
    pub reason: String,
}

impl LoginDetail {
    /// `(host, port)` of the URL; it was checked when the request was made.
    fn target(&self) -> Result<(String, u16)> {
        Ok(parse_https_url(&self.url)?)
    }
}

struct VaultDelivery<'a> {
    wanted_fields: &'a [String],
    reason: &'a str,
    mode: LeaseMode,
    duration_secs: Option<u64>,
    hosts: Vec<String>,
    login: Option<(LoginScope, LoginBinding)>,
}

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(rename = "BrowserLogin")]
    Login(LoginDetail),
    /// V1 selected an item before approval. Keep only the marker to retire the row.
    #[serde(rename = "Login")]
    LegacyLogin {},
    Ssh(SshDetail),
    SshExtend(SshExtendDetail),
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SshDetailTarget {
    pub target_id: String,
    pub name: String,
    /// The target revision the request was checked against.
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SshDetail {
    pub targets: Vec<SshDetailTarget>,
    pub access: asm_proto::ssh::SshAccess,
    pub grants: Vec<String>,
    /// For access as a user: which user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SshExtendDetail {
    pub lease_id: String,
    pub reason: String,
    /// The lease's target names, for summaries.
    pub names: Vec<String>,
}

impl SshDetail {
    /// The same targets, access, grants and user (the request re-attaches instead of
    /// creating a second approval).
    pub(crate) fn same_request(&self, other: &Self) -> bool {
        self.access == other.access && self.grants == other.grants && self.user == other.user
            && self.targets.iter().map(|t| &t.target_id).eq(other.targets.iter().map(|t| &t.target_id))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Pending {
    pub id: String,
    /// Additional one-shot delivery IDs for this GitHub approval; `id` serves the first caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attached_ids: Vec<String>,
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
            Detail::Login(_) | Detail::LegacyLogin {} => "login",
            Detail::Ssh(_) | Detail::SshExtend(_) => "ssh",
        }
    }

    fn wire_kind(&self) -> RequestKind {
        match self.detail {
            Detail::Update(_) => RequestKind::Update,
            Detail::Add(_) => RequestKind::Add,
            Detail::Login(LoginDetail { mode: BrowserLoginMode::Grant, .. }) => RequestKind::Get,
            Detail::Login(_) | Detail::LegacyLogin {} => RequestKind::Login,
            Detail::Ssh(_) | Detail::SshExtend(_) => RequestKind::Ssh,
            Detail::Pair { .. } | Detail::Get(_) => RequestKind::Get,
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
            Detail::Login(l) => format!("{} {}", match l.mode {
                BrowserLoginMode::Grant => "login grant for",
                BrowserLoginMode::Broker => "sign in to",
            }, l.url),
            Detail::LegacyLogin {} => "legacy browser login".to_owned(),
            Detail::Ssh(s) => format!(
                "ssh {} ({})",
                s.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", "),
                super::ssh::access_summary(s.access, &s.grants, s.user.as_deref())
            ),
            Detail::SshExtend(e) => format!("extend ssh lease on {}", e.names.join(", ")),
        }
    }

    /// Lifetime this request was given, in seconds.
    fn lifetime_secs(&self) -> u64 {
        (self.expires - self.created).max(0) as u64
    }

    pub(super) fn state_for(&self, id: &str, status: RequestStatus) -> RequestState {
        RequestState {
            request_id: id.to_owned(),
            kind: self.wire_kind(),
            status,
            deny_reason: None,
            result: None,
            expires_at: (status == RequestStatus::Pending).then(|| fmt_unix(self.expires)),
            pending_lifetime_secs: self.lifetime_secs(),
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
    /// The request becomes denied. This diagnostic is retained only on the manager.
    Deny(String),
    /// The request becomes denied with this reason, which the agent also receives.
    Refuse(String),
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

fn accepts_add(vault: &VaultEntry, name: &str) -> bool {
    vault.provider.status() == VaultStatus::Ready && match &vault.config {
        VaultConfig::Bitwarden(config) => config.personal || !config.collections.is_empty(),
        VaultConfig::EnvFile { .. } => is_env_key(name),
        VaultConfig::Keychain => true,
    }
}

impl Core {
    pub(super) fn seal_pending(&self, pending: &Pending) -> Result<SealedResume> {
        self.resume.seal(BOOK_NAMESPACE, &pending.id, &BookRow::Pending(Cow::Borrowed(pending)))
    }

    pub(super) fn seal_done(&self, id: &str, done: &Done) -> Result<SealedResume> {
        self.resume.seal(BOOK_NAMESPACE, id, &BookRow::Done(Cow::Borrowed(done)))
    }

    pub(super) fn seal_pair(&self, attempt: &PairAttempt, pending: Option<&Pending>) -> Result<SealedResume> {
        self.resume.seal(BOOK_NAMESPACE, &attempt.id, &BookRow::Pair {
            attempt: Cow::Borrowed(attempt),
            pending: pending.map(Cow::Borrowed),
        })
    }

    pub(super) fn save_pending_locked(&self, book: &mut Book, pending: Pending) -> Result<()> {
        let row = if matches!(&pending.detail, Detail::Pair { .. }) {
            let attempt = book.pairs.get(&pending.id)
                .ok_or_else(|| CoreError::internal("pairing request is missing its attempt"))?;
            self.seal_pair(attempt, Some(&pending))?
        } else {
            self.seal_pending(&pending)?
        };
        self.store.commit_request_book(&[row], None)?;
        Self::apply_pending_locked(book, pending);
        Ok(())
    }

    /// Caller owns the live host pending row under authorization and book locks.
    pub(super) fn mark_request_resolving(&self, pending: &mut Pending) -> Result<()> {
        if pending.resolving || matches!(&pending.detail, Detail::Pair { .. }) {
            return Err(CoreError::invalid("this request cannot be claimed"));
        }
        pending.resolving = true;
        let result = self.seal_pending(pending)
            .and_then(|row| self.store.commit_request_book(&[row], None));
        if result.is_err() {
            pending.resolving = false;
        }
        result
    }

    pub(super) fn apply_pending_locked(book: &mut Book, pending: Pending) {
        if let Some(existing) = book.pending.iter_mut().find(|p| p.id == pending.id) {
            *existing = pending;
        } else {
            book.pending.push(pending);
        }
    }

    pub(super) fn apply_done_locked(book: &mut Book, id: String, done: Done) {
        Self::remove_pending_locked(book, &id);
        book.done.insert(id, done);
    }

    pub(super) fn remove_pending_locked(book: &mut Book, id: &str) {
        if let Some(index) = book.pending.iter().position(|p| p.id == id) {
            book.pending.remove(index);
        }
    }

    pub(super) fn insert_done_locked(
        &self, book: &mut Book, id: String, done: Done, history: Option<HistoryRecord>,
    ) -> Result<()> {
        let row = self.seal_done(&id, &done)?;
        self.store.commit_request_book(&[row], history.as_ref())?;
        Self::apply_done_locked(book, id, done);
        Ok(())
    }

    /// Commit the canonical rows and every caller's value-free terminal row together. Read
    /// membership from the live book: another caller may have joined during provider I/O.
    pub(super) fn complete_pending_locked<const N: usize>(
        &self, book: &mut Book, mut done: Done, primary_rows: [SealedResume; N],
        commit: impl FnOnce(&[SealedResume]) -> Result<()>,
    ) -> Result<()> {
        let index = book.pending.iter().position(|p| p.id == done.state.request_id)
            .ok_or_else(|| CoreError::internal("cannot complete a missing pending request"))?;
        let attached = &book.pending[index].attached_ids;
        if attached.is_empty() {
            commit(&primary_rows)?;
        } else {
            let mut rows = Vec::with_capacity(N + attached.len());
            rows.extend(primary_rows);
            for id in attached {
                done.state.request_id.clone_from(id);
                rows.push(self.seal_done(id, &done)?);
            }
            commit(&rows)?;
        }
        let pending = book.pending.remove(index);
        for id in pending.attached_ids {
            done.state.request_id.clone_from(&id);
            book.done.insert(id, done.clone());
        }
        done.state.request_id.clone_from(&pending.id);
        book.done.insert(pending.id, done);
        Ok(())
    }

    pub(super) fn delete_book_row(&self, id: &str) -> Result<()> {
        self.resume.remove(BOOK_NAMESPACE, id)
    }

    pub(super) fn save_pair_locked(
        &self, book: &mut Book, attempt: PairAttempt, pending: Option<Pending>, history: Option<&HistoryRecord>,
    ) -> Result<()> {
        let row = self.seal_pair(&attempt, pending.as_ref())?;
        self.store.commit_request_book(&[row], history)?;
        if let Some(pending) = pending {
            Self::apply_pending_locked(book, pending);
        } else {
            Self::remove_pending_locked(book, &attempt.id);
        }
        book.pairs.insert(attempt.id.clone(), attempt);
        Ok(())
    }

    /// Load before serving requests. A claimed operation may have reached its external
    /// provider, so never replay it or mistake a process exit for an operator denial.
    pub(super) fn restore_request_book(&self, t: i64) -> Result<()> {
        let mut book = Book::default();
        for (id, row) in self.resume.list::<BookRow<'static>>(BOOK_NAMESPACE)? {
            match row {
                BookRow::Pending(p) if p.id == id && !matches!(&p.detail, Detail::Pair { .. }) => {
                    book.pending.push(p.into_owned());
                }
                BookRow::Done(d) if d.state.request_id == id && d.state.status.is_terminal() => {
                    if let Some(delivery) = &d.generated
                        && self.store.get_lease(&delivery.lease_id)?.is_none() {
                        // Managed account retirement deletes its leases. A crash
                        // after retirement must not recover their delivery rows.
                        self.delete_book_row(&id)?;
                        continue;
                    }
                    book.done.insert(id, d.into_owned());
                }
                BookRow::Pair { attempt, pending } if attempt.id == id
                    && matches!(&attempt.state, PairState::Pending) == pending.is_some()
                    && pending.as_ref().is_none_or(|p| p.id == id && matches!(&p.detail, Detail::Pair { .. })) =>
                {
                    book.pairs.insert(id, attempt.into_owned());
                    if let Some(p) = pending {
                        book.pending.push(p.into_owned());
                    }
                }
                _ => return Err(CoreError::internal("request continuity state is inconsistent")),
            }
        }
        book.pending.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        let _authority = lock(&self.authorization);
        for index in (0..book.pending.len()).rev() {
            let p = &book.pending[index];
            if matches!(&p.detail, Detail::LegacyLogin {} | Detail::Get(GetDetail { login: Some(_), .. })) {
                let id = p.id.clone();
                self.end_pending_locked(&mut book, &id, RequestStatus::Denied, Some(LEGACY_LOGIN.into()), None, t, false)?;
                continue;
            }
            let revoked = p.host_id.as_deref().map(|id| self.host_is_active(id)).transpose()? == Some(false);
            if revoked || p.expires <= t {
                let id = p.id.clone();
                let (status, reason, ended_at) = if revoked {
                    (RequestStatus::Cancelled, Some("host revoked".into()), t)
                } else {
                    (RequestStatus::Expired, None, p.expires)
                };
                self.end_pending_locked(&mut book, &id, status, reason, None, ended_at, false)?;
                continue;
            }
            let reconciled = if let Detail::Get(GetDetail { target: GetTarget::Generated(target), .. }) = &p.detail {
                let mut current = target.clone();
                self.reconcile_generator_target(&mut current, true);
                (current != *target).then_some(current)
            } else {
                None
            };
            if reconciled.as_ref().is_some_and(|target| target.candidates.is_empty()) {
                let id = p.id.clone();
                self.finish_locked(&mut book, &id, Err(Some("no offered generators remain".into())), t, true)?;
            } else if p.resolving || reconciled.is_some() {
                let mut pending = p.clone();
                if pending.resolving {
                    pending.resolving = false;
                    pending.error = Some(INTERRUPTED.into());
                }
                if let Some(target) = reconciled
                    && let Detail::Get(GetDetail { target: GetTarget::Generated(current), .. }) = &mut pending.detail {
                    *current = target;
                }
                self.save_pending_locked(&mut book, pending)?;
            }
        }
        *lock(&self.book) = book;
        drop(_authority);
        self.expire_requests(t)
    }

    pub(crate) fn host_is_active(&self, host_id: &str) -> Result<bool> {
        Ok(self.store.get_host(host_id)?.is_some_and(|h| h.revoked_at.is_none()))
    }

    pub(super) fn require_active_host(&self, host_id: &str) -> Result<()> {
        if !self.host_is_active(host_id)? {
            return Err(CoreError::unauthorized("host was revoked"));
        }
        Ok(())
    }

    fn require_request_host(&self, host_id: &str, proof: Option<&[u8; 32]>) -> Result<()> {
        match proof {
            Some(hash) if self.store.host_by_proof(host_id, hash)?.is_none() => {
                Err(CoreError::unauthorized("token rejected; run asm pair"))
            }
            Some(_) => Ok(()),
            None => self.require_active_host(host_id),
        }
    }

    /// Recheck the authority of a static terminal GET immediately before any
    /// cached files (including unsubstituted ones) leave the manager.
    fn check_static_delivery(&self, host_id: &str, result: &GetResult) -> Result<()> {
        self.store.get_lease(&result.lease_id)?.filter(|lease| lease.host_id == host_id
            && lease.source_kind == SourceKind::Vault && lease.mode == result.mode
            && lease.is_active(self.generation_now()))
            .ok_or_else(|| CoreError::vault_unavailable("lease ended; run asm get again"))?;
        Ok(())
    }

    /// Expire pending requests and unrevealed pairing attempts; prune old resolved ones.
    pub fn expire_requests(&self, t: i64) -> Result<()> {
        let (mut changed, mut pending_changed) = (false, false);
        {
            let _authority = lock(&self.authorization);
            let mut book = lock(&self.book);
            for index in (0..book.pending.len()).rev() {
                let p = &book.pending[index];
                if p.expires <= t && (!p.resolving || matches!(&p.detail,
                    Detail::Get(GetDetail { target: GetTarget::Generated(_), .. }))) {
                    let (id, expires) = (p.id.clone(), p.expires);
                    self.end_pending_locked(&mut book, &id, RequestStatus::Expired, None, None, expires, false)?;
                    pending_changed = true;
                }
            }
            let ended_pairs: Vec<_> = book.pairs.values().filter(|a|
                matches!(a.state, PairState::AwaitingReveal) && a.expires <= t).cloned().collect();
            for mut attempt in ended_pairs {
                attempt.state = PairState::Expired;
                attempt.ended = Some(attempt.expires);
                self.save_pair_locked(&mut book, attempt, None, None)?;
                changed = true;
            }
            let stale_done: Vec<_> = book.done.iter().filter(|(_, d)| d.at + DONE_KEEP_SECS <= t)
                .map(|(id, _)| id.clone()).collect();
            let stale_pairs: Vec<_> = book.pairs.iter().filter(|(_, a)| a.ended.is_some_and(|e| e + DONE_KEEP_SECS <= t))
                .map(|(id, _)| id.clone()).collect();
            for id in stale_done {
                self.delete_book_row(&id)?;
                book.done.remove(&id);
            }
            for id in stale_pairs {
                self.delete_book_row(&id)?;
                book.pairs.remove(&id);
            }
        }
        if changed || pending_changed {
            self.bump();
        }
        if pending_changed {
            self.notify(TOPIC_REQUESTS);
        }
        Ok(())
    }

    /// Resolve only against the catalog and this host's existing leases. An unavailable
    /// provider must not turn an ordinary miss into a different client-visible error.
    fn resolve_request_secret(&self, host_id: &str, query: &str) -> Result<CatalogMatch> {
        let catalog = self.secret_catalog()?;
        let e = match catalog.resolve(query) {
            Err(e) if matches!(e.code, asm_proto::ErrorCode::NotFound | asm_proto::ErrorCode::Ambiguous) => e,
            resolved => return resolved,
        };
        if catalog.generated.iter().any(|g| g.static_collisions.iter().any(|n| n == query)) {
            return Err(e);
        }
        if let Some((source, leaf)) = query.rsplit_once('/')
            && let Some(output) = asm_proto::names::canonical_generated_output(leaf)
            && self.store.leases_of_host(host_id)?.iter().any(|lease|
                lease.source_kind == SourceKind::Generator && lease.vault_name == source
                && lease.generation.as_ref().is_some_and(|grant| grant.output_name() == output)) {
            return Err(e);
        }
        self.leased_secret(host_id, query, &catalog.static_entries)?.map(CatalogMatch::Vault).ok_or(e)
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
        self.require_active_host(&host.id)?;
        if !agent.is_empty() {
            self.store.upsert_agent(&host.id, &agent, t)?;
            self.notify(super::TOPIC_HOSTS);
        }
        self.expire_requests(t)?;
        match body {
            body @ RequestBody::Get { .. } => self.create_get(host, &agent, address, body),
            RequestBody::Update {
                name, field, value, ..
            } => self.create_update(host, &agent, address, &name, field, value),
            RequestBody::Add { name, value, .. } => {
                self.create_add(host, &agent, address, name, value)
            }
            RequestBody::Login { .. } => Err(CoreError::invalid(LEGACY_LOGIN)),
            RequestBody::BrowserLogin(login) => self.create_login(host, &agent, address, login),
            body @ RequestBody::Ssh { .. } => self.create_ssh(host, &agent, address, body),
            body @ RequestBody::SshExtend { .. } => self.create_ssh_extend(host, &agent, address, body),
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
            attached_ids: Vec::new(),
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
    pub(crate) fn push_pending(&self, p: Pending, same: impl Fn(&Pending) -> bool) -> Result<RequestState> {
        self.push_matching_pending(p, |current, _| same(current))
    }

    fn push_matching_pending(&self, p: Pending, same: impl Fn(&Pending, &Pending) -> bool) -> Result<RequestState> {
        let authority = lock(&self.authorization);
        let (state, inserted) = self.attach_pending(p, same)?;
        drop(authority);
        if inserted {
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
        Ok(state)
    }

    /// Caller holds authorization (the generated path also checks its offered revisions).
    pub(crate) fn attach_pending(&self, p: Pending, same: impl Fn(&Pending, &Pending) -> bool) -> Result<(RequestState, bool)> {
        if let Some(host_id) = p.host_id.as_deref() {
            self.require_active_host(host_id)?;
        }
        let mut b = lock(&self.book);
        if let Some(existing) = b.pending.iter_mut().find(|q| q.host_id == p.host_id && same(q, &p)) {
            if !matches!(&p.detail, Detail::Get(GetDetail { target: GetTarget::Generated(target), .. })
                if target.output_name == asm_proto::generators::GITHUB_TOKEN_NAME) {
                return Ok((existing.state_for(&existing.id, RequestStatus::Pending), false));
            }
            if existing.attached_ids.len() >= MAX_GITHUB_CALLERS - 1 {
                return Err(CoreError::rate_limited("too many callers waiting for this GitHub approval"));
            }
            let state = existing.state_for(&p.id, RequestStatus::Pending);
            existing.attached_ids.push(p.id);
            if let Err(error) = self.seal_pending(existing)
                .and_then(|row| self.store.commit_request_book(&[row], None)) {
                existing.attached_ids.pop();
                return Err(error);
            }
            return Ok((state, false));
        }
        let event = activity::requested(&p);
        let state = p.state_for(&p.id, RequestStatus::Pending);
        self.save_pending_locked(&mut b, p)?;
        self.log(event);
        Ok((state, true))
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
            lease_id, refresh_from_version, login, ..
        } = &body else { unreachable!() };
        let mode = if *raw { RequestedMode::Raw } else if *sentinel {
            RequestedMode::Sentinel
        } else { RequestedMode::Default };
        let reason = validate_reason(reason)?;
        if login.is_some() {
            return Err(CoreError::invalid(LEGACY_LOGIN));
        }
        let requested = normalize_host_patterns(hosts)?;
        if let Some(id) = lease_id {
            body.validate_get_capabilities(SourceKind::Generator)?;
            return self.generated_pinned_get(host, agent, name, id, mode, &requested,
                fields.as_deref(), generation.as_ref(), *refresh, *refresh_from_version, &reason);
        }
        match self.resolve_request_secret(&host.id, name)? {
            CatalogMatch::Generated(super::catalog::CatalogGeneratedTarget {
                requested_name, output_name, pinned_generator_id, candidates,
            }) => {
                body.validate_get_capabilities(SourceKind::Generator)?;
                if generation.as_ref().is_some_and(|request| request.output_name() != output_name) {
                    return Err(CoreError::invalid("requested scope provider does not match the generated output"));
                }
                let target = GeneratorTarget {
                    requested_name, output_name, pinned_generator_id, candidates,
                    requested_generation: generation.clone(),
                    operator_selected_grant: body.supports_operator_selected_grant(),
                    operator_selected_gcloud_project: body.supports_operator_selected_project(),
                };
                let wanted_fields = select_fields(&["value".to_string()], fields.as_deref())?;
                self.create_generated_get(host, agent, address, target, mode, wanted_fields,
                    requested, reason, *new_lease, *refresh, *refresh_from_version, body.supports_broader_lease_reuse())
            }
            CatalogMatch::Vault(named) => {
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
                    requested_hosts: requested, reason, initial, suggestions, login: None,
                };
                self.push_vault_get(host, agent, address, detail)
            }
        }
    }

    fn create_login(
        &self, host: &HostRecord, agent: &str, address: &str, request: BrowserLoginRequest,
    ) -> Result<RequestState> {
        let BrowserLoginRequest { mode, url, site, account, reason, extra_fill_origins, .. } = request;
        let (url, fill_origins) = match mode {
            BrowserLoginMode::Grant => (url, Vec::new()),
            BrowserLoginMode::Broker => {
                let url = url.trim();
                if url.len() > MAX_LOGIN_URL_BYTES || url.bytes().any(|b| !b.is_ascii_graphic()) {
                    return Err(CoreError::invalid(format!(
                        "URL must be printable ASCII without spaces, at most {MAX_LOGIN_URL_BYTES} bytes")));
                }
                let (host, port) = parse_https_url(url)?;
                let origin = fill::origin(&host, port);
                if extra_fill_origins.len() > MAX_EXTRA_FILL_ORIGINS {
                    return Err(CoreError::invalid(format!("at most {MAX_EXTRA_FILL_ORIGINS} extra fill origins")));
                }
                let mut origins = Vec::with_capacity(extra_fill_origins.len() + 1);
                origins.push(origin);
                for extra in extra_fill_origins {
                    let extra = fill::parse_fill_origin(&extra)?;
                    if !origins.contains(&extra) {
                        origins.push(extra);
                    }
                }
                origins[1..].sort_unstable();
                let suffix = url[8..].find(['/', '?', '#']).map_or("", |i| &url[8 + i..]);
                let url = format!("{}{}{suffix}", origins[0], if suffix.starts_with('/') { "" } else { "/" });
                (url, origins)
            }
        };
        let detail = LoginDetail { mode, url, site, account, fill_origins, reason: validate_reason(&reason)? };
        let pending = self.new_pending(host, agent, address, Detail::Login(detail));
        self.push_matching_pending(pending, |q, p| q.agent == p.agent
            && matches!((&q.detail, &p.detail), (Detail::Login(a), Detail::Login(b)) if a == b))
    }

    /// Queue a vault GET, re-attaching to an equal pending request of the same host.
    fn push_vault_get(&self, host: &HostRecord, agent: &str, address: &str, detail: GetDetail) -> Result<RequestState> {
        let p = self.new_pending(host, agent, address, Detail::Get(detail.clone()));
        self.push_pending(p, |q| match (&q.detail, &detail.target) {
            (Detail::Get(g), GetTarget::Vault(s)) => matches!(&g.target,
                GetTarget::Vault(other) if other.vault_id == s.vault_id && other.key == s.key)
                && g.mode == detail.mode && g.wanted_fields == detail.wanted_fields
                && g.requested_hosts == detail.requested_hosts && g.reason == detail.reason
                && g.login == detail.login,
            _ => false,
        })
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
                    // Only the dedicated lease-bound OTP endpoint may reuse a browser grant.
                    && l.login.is_none()
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
                substituted: Some(f.sentinel.is_some()),
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
                operator_selected_grant: false,
                broader_lease_reuse: false,
                credential_expires_at: None,
                credential_version: None,
                generator_name: None,
                login: None,
            })),
            expires_at: None,
            pending_lifetime_secs: self.settings().request_lifetime_secs.max(1),
        };
        let history = HistoryRecord {
            id: id.clone(),
            kind: "get".into(),
            host_id: Some(host.id.clone()),
            host_label: host.label().to_string(),
            summary: format!("get {} (existing lease)", secret.display),
            status: "approved".into(),
            deny_reason: None,
            created_at: t,
            resolved_at: t,
        };
        {
            let _authority = lock(&self.authorization);
            self.require_active_host(&host.id)?;
            let Some(RequestResult::Get(result)) = &state.result else { unreachable!() };
            self.check_static_delivery(&host.id, result)?;
            self.insert_done_locked(&mut lock(&self.book), id.clone(), Done {
                host_id: host.id.clone(),
                state: state.clone(),
                at: t,
                generated: None,
            }, Some(history))?;
        }
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
        let CatalogMatch::Vault(named) = self.resolve_request_secret(&host.id, name)? else {
            return Err(CoreError::invalid("generated secrets cannot be updated"));
        };
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
        if field == "totp" {
            return Err(CoreError::invalid(
                "totp is generated from the item's authenticator key and cannot be updated",
            ));
        }
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
                return Ok(q.state_for(&q.id, RequestStatus::Pending));
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
        self.push_pending(p, |q| {
            matches!(&q.detail, Detail::Update(u) if u.secret.vault_id == detail.secret.vault_id
                && u.secret.key == detail.secret.key && u.field == detail.field
                && hash_hex(&u.new_value) == hash)
        })
    }

    /// Current writable destinations, for the manager's approval view only.
    fn add_targets(&self, name: &str) -> Vec<ffi::AddTarget> {
        self.registry.all().into_iter().filter(|v| accepts_add(v, name)).map(|v| {
            let (kind, collections, personal_allowed) = match &v.config {
                VaultConfig::Bitwarden(b) => {
                    let known = v.provider.collections().unwrap_or_default();
                    let collections = b.collections.iter().map(|id| {
                        known.iter().find(|c| &c.id == id).cloned().unwrap_or_else(|| CollectionInfo {
                            id: id.clone(),
                            name: b.collection_names.get(id).cloned().unwrap_or_else(|| id.clone()),
                            organization_id: None,
                        }).into()
                    }).collect();
                    (ffi::VaultKind::Bitwarden, collections, b.personal)
                }
                VaultConfig::EnvFile { .. } => (ffi::VaultKind::EnvFile, Vec::new(), false),
                VaultConfig::Keychain => (ffi::VaultKind::Keychain, Vec::new(), false),
            };
            ffi::AddTarget { vault_id: v.id, vault_name: v.name, kind, collections, personal_allowed }
        }).collect()
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
        // Accept the request without probing writable targets. Only the operator sees
        // which destinations, if any, can receive the value.
        let hash = hash_hex(&value);
        let detail = AddDetail { name, value };
        let p = self.new_pending(host, agent, address, Detail::Add(detail.clone()));
        self.push_pending(p, |q| {
            matches!(&q.detail, Detail::Add(a) if a.name == detail.name && hash_hex(&a.value) == hash)
        })
    }

    /// `GET /requests/{id}`: the request's state. A raw result is returned once, then dropped.
    pub fn request_state(&self, host_id: &str, id: &str) -> Result<RequestState> {
        self.request_state_with_proof(host_id, id, None)
    }

    pub(super) fn request_state_with_proof(
        &self, host_id: &str, id: &str, proof: Option<&[u8; 32]>,
    ) -> Result<RequestState> {
        self.expire_requests(self.generation_now())?;
        let outcome = (|| {
            let authority = lock(&self.authorization);
            self.require_request_host(host_id, proof)?;
            let book = lock(&self.book);
            if let Some(pending) = book.pending_for_caller(host_id, id) {
                return Ok(pending.state_for(id, RequestStatus::Pending));
            }
            let done = book.done.get(id).filter(|d| d.host_id == host_id)
                .ok_or_else(|| CoreError::not_found("no such request"))?;
            if let Some(delivery) = &done.generated {
                let unavailable = || CoreError::vault_unavailable(
                    "generated credential is no longer available; run asm get again");
                if delivery.consumed {
                    return Err(unavailable());
                }
                let delivery = delivery.clone();
                // Generated authorization may take its cache and publication locks.
                // The authority lock keeps cancellation and revocation out throughout.
                drop(book);
                let mode = self.check_generated_delivery(&delivery.lease_id, delivery.credential_version)?;
                if mode == LeaseMode::Sentinel && lock(&self.proxy_state).dirty {
                    self.publish_proxy_locked(&authority).map_err(|_|
                        CoreError::vault_unavailable("generated credential publication failed; run asm get to retry"))?;
                }
                let mut result = self.validate_generated_delivery(&delivery.lease_id, delivery.credential_version)?;
                result.operator_selected_grant = delivery.operator_selected_grant;
                let mut book = lock(&self.book);
                let done = book.done.get(id).ok_or_else(unavailable)?;
                let mut state = done.state.clone();
                if mode == LeaseMode::Raw {
                    let mut retained = done.clone();
                    retained.generated.as_mut().ok_or_else(unavailable)?.consumed = true;
                    self.insert_done_locked(&mut book, id.to_owned(), retained, None)?;
                }
                state.result = Some(RequestResult::Get(result));
                return Ok(state);
            }

            if let Some(RequestResult::Get(result)) = &done.state.result {
                self.check_static_delivery(host_id, result)?;
                if result.mode == LeaseMode::Sentinel
                    && result.files.iter().any(|f| f.substituted == Some(true)) {
                    let lease_id = result.lease_id.clone();
                    drop(book);
                    if lock(&self.proxy_state).dirty {
                        self.publish_proxy_locked(&authority)?;
                    }
                    if !lock(&self.proxy_state).entries.contains_key(&lease_id) {
                        return Err(CoreError::vault_unavailable("lease is suspended because its vault is unavailable"));
                    }
                    return Ok(lock(&self.book).done.get(id)
                        .ok_or_else(|| CoreError::not_found("no such request"))?.state.clone());
                }
                if result.mode == LeaseMode::Raw {
                    let mut book = book;
                    let done = book.done.get_mut(id).expect("same locked row");
                    let delivery = done.state.result.take();
                    let committed = self.seal_done(id, done)
                        .and_then(|row| self.store.commit_request_book(&[row], None));
                    if let Err(e) = committed {
                        done.state.result = delivery;
                        return Err(e);
                    }
                    return Ok(RequestState { result: delivery, ..done.state.clone() });
                }
            }
            Ok(done.state.clone())
        })();
        self.notify_proxy_changed();
        outcome
    }

    /// `DELETE /requests/{id}`.
    pub fn cancel_request(&self, host_id: &str, id: &str) -> Result<RequestState> {
        self.cancel_request_with_proof(host_id, id, None)
    }

    pub(super) fn cancel_request_with_proof(
        &self, host_id: &str, id: &str, proof: Option<&[u8; 32]>,
    ) -> Result<RequestState> {
        let t = self.generation_now();
        self.expire_requests(t)?;
        let (state, changed, broker_session) = {
            let _authority = lock(&self.authorization);
            self.require_request_host(host_id, proof)?;
            let mut book = lock(&self.book);
            if let Some(p) = book.pending_for_caller(host_id, id) {
                // A running sign-in ends with its request; any other claimed request
                // may already have reached its provider.
                let broker_session = matches!(&p.detail, Detail::Login(_)) && self.broker.is_live(&p.id);
                if p.resolving && !broker_session
                    && !matches!(&p.detail, Detail::Get(GetDetail { target: GetTarget::Generated(_), .. })) {
                    return Ok(p.state_for(id, RequestStatus::Pending));
                }
                let state = p.state_for(id, RequestStatus::Cancelled);
                let approval_id = p.id.clone();
                self.end_pending_locked(&mut book, &approval_id, RequestStatus::Cancelled, None, None, t, false)?;
                (state, true, broker_session.then_some(approval_id))
            } else {
                let done = book.done.get_mut(id).filter(|d| d.host_id == host_id)
                    .ok_or_else(|| CoreError::not_found("no such request"))?;
                let result = if matches!(&done.state.result, Some(RequestResult::Get(_))) {
                    done.state.result.take()
                } else {
                    None
                };
                let newly_consumed = done.generated.as_mut().is_some_and(|d|
                    !std::mem::replace(&mut d.consumed, true));
                if result.is_some() || newly_consumed {
                    let committed = self.seal_done(id, done)
                        .and_then(|row| self.store.commit_request_book(&[row], None));
                    if let Err(e) = committed {
                        if result.is_some() {
                            done.state.result = result;
                        }
                        if newly_consumed {
                            done.generated.as_mut().expect("delivery just marked consumed").consumed = false;
                        }
                        return Err(e);
                    }
                }
                (done.state.clone(), false, None)
            }
        };
        if let Some(id) = broker_session {
            self.broker.cancel(&id, broker::DENY_CANCELLED);
        }
        if changed {
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
        Ok(state)
    }

    /// Cancel every pending request of a host (host revoked). An approved sign-in whose
    /// browser is open is denied with the broker's own text, and its browser closed.
    pub(crate) fn cancel_host_requests(&self, host_id: &str) -> Result<()> {
        let t = self.generation_now();
        let mut changed = false;
        let mut sessions = Vec::new();
        {
            let _authority = lock(&self.authorization);
            let mut book = lock(&self.book);
            for index in (0..book.pending.len()).rev() {
                let p = &book.pending[index];
                if p.host_id.as_deref() == Some(host_id) {
                    let id = p.id.clone();
                    let (status, reason) = if matches!(&p.detail, Detail::Login(_)) && self.broker.is_live(&id) {
                        sessions.push(id.clone());
                        (RequestStatus::Denied, broker::DENY_REVOKED)
                    } else {
                        (RequestStatus::Cancelled, "host revoked")
                    };
                    self.end_pending_locked(&mut book, &id, status, Some(reason.into()), None, t, false)?;
                    changed = true;
                }
            }
        }
        for id in sessions {
            self.broker.cancel(&id, broker::DENY_REVOKED);
        }
        if changed {
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
        Ok(())
    }

    // ---- resolution ----

    /// Carry out the operator's decision on a pending request.
    pub fn resolve_request(&self, id: &str, decision: ffi::Decision) -> Result<()> {
        let t = self.generation_now();
        self.expire_requests(t)?;
        // Phase 1: claim the request.
        let p = {
            // Serialize claiming/denial with the cloud-write and final delivery gates.
            let authority = lock(&self.authorization);
            let mut b = lock(&self.book);
            let Some(i) = b.pending.iter().position(|p| p.id == id) else {
                return Err(CoreError::not_found("this request is no longer pending"));
            };
            let deniable_managed_get = matches!(&decision, ffi::Decision::Deny { .. }) && matches!(&b.pending[i].detail,
                Detail::Get(GetDetail { target: GetTarget::Generated(GeneratorTarget {
                    requested_generation: Some(GenerationRequest::GcloudAccess(_)), ..
                }), .. }));
            if b.pending[i].resolving && !deniable_managed_get {
                return Err(CoreError::invalid("this request is already being resolved"));
            }
            let ok = matches!(
                (&b.pending[i].detail, &decision),
                (_, ffi::Decision::Deny { .. })
                    | (Detail::Pair { .. }, ffi::Decision::ApprovePair { .. })
                    | (Detail::Get(_), ffi::Decision::ApproveGet { .. })
                    | (Detail::Update(_), ffi::Decision::ApproveWrite { .. })
                    | (Detail::Add(_), ffi::Decision::ApproveWrite { .. })
                    | (Detail::Login(_), ffi::Decision::ApproveLogin { .. })
                    | (Detail::Ssh(_), ffi::Decision::ApproveSsh { .. })
                    | (Detail::SshExtend(_), ffi::Decision::ApproveSshExtend { .. })
            );
            if !ok {
                return Err(CoreError::invalid(
                    "this decision does not fit the request kind",
                ));
            }
            if let ffi::Decision::Deny { reason } = &decision {
                let reason = Some(reason.trim().to_string()).filter(|r| !r.is_empty());
                self.finish_locked(&mut b, id, Err(reason), t, false)?;
                drop(b);
                drop(authority);
                self.notify_request_ended();
                return Ok(());
            }
            if let Some(host_id) = b.pending[i].host_id.as_deref() {
                self.require_active_host(host_id)?;
            }
            if matches!(&b.pending[i].detail, Detail::Pair { .. }) {
                let mut pending = b.pending[i].clone();
                pending.resolving = true;
                self.save_pending_locked(&mut b, pending.clone())?;
                pending
            } else {
                self.mark_request_resolving(&mut b.pending[i])?;
                b.pending[i].clone()
            }
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
                    .map(|_| None),
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
            (Detail::Login(l), ffi::Decision::ApproveLogin { selection, duration_secs, fill_origins }) => self
                .approve_login(&p, l, &selection, duration_secs, &fill_origins)
                .map(|()| None),
            (Detail::Ssh(d), ffi::Decision::ApproveSsh { targets, duration_secs }) => self
                .approve_ssh(&p, d, super::ssh::SshApproval { targets, duration_secs })
                .map(|_| None),
            (Detail::SshExtend(d), ffi::Decision::ApproveSshExtend { duration_secs }) => self
                .approve_ssh_extend(&p, d, duration_secs)
                .map(|_| None),
            _ => Err(Fail::Keep(CoreError::invalid(
                "this decision does not fit the request kind",
            ))),
        };

        // Phase 3: record the outcome.
        let t = self.generation_now();
        match outcome {
            // Pairing and GET approvals already committed atomically with their
            // delivery authority. A vault write cannot share that transaction. An
            // approved sign-in stays pending until its browser session ends.
            Ok(None) => Ok(()),
            Ok(Some(result)) => {
                let changed = {
                    let _authority = lock(&self.authorization);
                    self.finish_locked(&mut lock(&self.book), id, Ok(Some(result)), t, false)?
                };
                if !changed {
                    return Err(CoreError::vault_unavailable(
                        "request ended during the write; verify the vault before trying again"));
                }
                self.notify_request_ended();
                Ok(())
            }
            Err(Fail::Keep(e)) => {
                self.keep_request_pending(id, &e)?;
                Err(e)
            }
            Err(Fail::Deny(reason)) => {
                let changed = {
                    let _authority = lock(&self.authorization);
                    self.finish_locked(&mut lock(&self.book), id, Err(Some(reason.clone())), t, true)?
                };
                if changed {
                    self.notify_request_ended();
                }
                Err(CoreError::vault_unavailable(reason))
            }
            Err(Fail::Refuse(reason)) => {
                let changed = {
                    let _authority = lock(&self.authorization);
                    self.finish_locked(&mut lock(&self.book), id, Err(Some(reason.clone())), t, false)?
                };
                if changed {
                    self.notify_request_ended();
                }
                Err(CoreError::invalid(reason))
            }
        }
    }

    pub(super) fn keep_request_pending(&self, id: &str, error: &CoreError) -> Result<()> {
        let mut book = lock(&self.book);
        if let Some(p) = book.pending.iter().find(|p| p.id == id) {
            let mut pending = p.clone();
            pending.resolving = false;
            pending.error = Some(error.message.clone());
            self.save_pending_locked(&mut book, pending)?;
        }
        drop(book);
        self.notify(TOPIC_REQUESTS);
        Ok(())
    }

    pub(super) fn notify_request_ended(&self) {
        self.bump();
        self.notify(TOPIC_REQUESTS);
    }

    /// Move the pending request to a terminal state without an intermediate gap.
    /// `failed` means an internal denial reason must stay on the manager.
    pub(super) fn finish_locked(
        &self, book: &mut Book, id: &str,
        outcome: std::result::Result<Option<RequestResult>, Option<String>>,
        t: i64, failed: bool,
    ) -> Result<bool> {
        let (status, reason, result) = match outcome {
            Ok(result) => (RequestStatus::Approved, None, result),
            Err(reason) => (RequestStatus::Denied, reason, None),
        };
        self.end_pending_locked(book, id, status, reason, result, t, failed)
    }

    fn end_pending_locked(
        &self, book: &mut Book, id: &str, status: RequestStatus, reason: Option<String>,
        result: Option<RequestResult>, t: i64, failed: bool,
    ) -> Result<bool> {
        let Some(p) = book.pending.iter().find(|p| p.id == id) else { return Ok(false) };
        let event = if status == RequestStatus::Approved {
            activity::approved(p, result.as_ref(), t)
        } else {
            activity::ended(p, if failed { "failed" } else { status_str(status) }, reason.as_deref())
        };
        let history = p.history(status, reason.clone(), t);
        if matches!(&p.detail, Detail::Pair { .. }) {
            let mut attempt = book.pairs.get(id).cloned()
                .ok_or_else(|| CoreError::internal("pairing request is missing its attempt"))?;
            attempt.state = match status {
                RequestStatus::Denied => PairState::Denied(reason),
                RequestStatus::Expired => PairState::Expired,
                _ => return Err(CoreError::internal("invalid pairing outcome")),
            };
            attempt.ended = Some(t);
            self.save_pair_locked(book, attempt, None, Some(&history))?;
        } else {
            let host_id = p.host_id.clone().ok_or_else(|| CoreError::internal("request is missing its host"))?;
            let mut state = p.state_for(id, status);
            state.deny_reason = if failed { Some(REQUEST_UNAVAILABLE.into()) } else { reason };
            state.result = result;
            let done = Done { host_id, state, at: t, generated: None };
            let row = self.seal_done(id, &done)?;
            self.complete_pending_locked(book, done, [row], |rows|
                self.store.commit_request_book(rows, Some(&history)))?;
        }
        self.log(event);
        Ok(true)
    }

    fn approve_get(
        &self,
        p: &Pending,
        g: &GetDetail,
        mode: LeaseMode,
        duration_secs: Option<u64>,
        hosts: Vec<String>,
        generation: Option<GenerationSelection>,
    ) -> std::result::Result<(), Fail> {
        if matches!(&g.target, GetTarget::Generated(_)) {
            let selection = generation.ok_or_else(|| CoreError::invalid("choose a generator and grant"))?;
            let approval = GeneratedApproval::new(g, mode, duration_secs, &hosts)?;
            return self.approve_generated_get(p, g, approval, selection, None).map(|_| ());
        }
        let GetTarget::Vault(s) = &g.target else { unreachable!() };
        if g.mode == RequestedMode::Sentinel && mode == LeaseMode::Raw {
            return Err(Fail::Keep(CoreError::invalid("this request requires sentinel delivery")));
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
        let delivery = VaultDelivery { wanted_fields: &g.wanted_fields, reason: &g.reason,
            mode, duration_secs, hosts, login: None };
        let entry = self
            .registry
            .get(&s.vault_id)
            .ok_or_else(|| Fail::Deny("vault unavailable: vault was removed".into()))?;
        let values = entry
            .provider
            .read(&s.key)
            .map_err(|e| Fail::Deny(format!("vault unavailable: {}", e.message)))?;
        self.deliver_vault(p, s, values, delivery)
    }

    fn deliver_vault(
        &self, p: &Pending, s: &SecretRef, mut values: super::Values, delivery: VaultDelivery<'_>,
    ) -> std::result::Result<(), Fail> {
        let VaultDelivery { wanted_fields, reason, mode, duration_secs, hosts, login } = delivery;
        let host_id = p.host_id.clone().unwrap_or_default();
        for field in wanted_fields {
            if !values.iter().any(|(f, _)| f == field) {
                return Err(Fail::Keep(CoreError::vault_unavailable("an approved field is no longer available")));
            }
        }
        values.retain(|(f, _)| wanted_fields.contains(f));
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
                    login: login.as_ref().map(|(_, binding)| binding.clone()),
                });
            }
            files.push(ResultFile {
                field: field.clone(),
                relative_path: path.clone(),
                content: sentinel.clone().unwrap_or_else(|| value.clone()),
                substituted: Some(sentinel.is_some()),
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
            host_id,
            vault_id: s.vault_id.clone(),
            vault_name: s.vault_name.clone(),
            secret_key: s.key.clone(),
            name: s.display.clone(),
            mode,
            fields,
            hosts: hosts.clone(),
            reason: reason.into(),
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
            login: login.as_ref().map(|(scope, _)| scope.clone()),
        };
        let result = RequestResult::Get(GetResult {
            lease_id,
            mode,
            hosts,
            expires_at: expires_at.map(fmt_unix),
            files,
            generation: None,
            operator_selected_grant: false,
            broader_lease_reuse: false,
            credential_expires_at: None,
            credential_version: None,
            generator_name: None,
            login: login.map(|(scope, _)| scope),
        });
        let event = activity::approved(p, Some(&result), t);
        let mut state = p.state_for(&p.id, RequestStatus::Approved);
        state.result = Some(result);
        let done = Done { host_id: lease.host_id.clone(), state, at: t, generated: None };
        let history = p.history(RequestStatus::Approved, None, t);
        let row = self.seal_done(&p.id, &done)?;
        let publication = {
            let authority = lock(&self.authorization);
            self.require_active_host(&lease.host_id)?;
            let mut book = lock(&self.book);
            if !book.pending.iter().any(|q| q.id == p.id && q.resolving && q.expires > self.generation_now()) {
                return Err(Fail::Keep(CoreError::vault_unavailable("request ended before its lease was approved")));
            }
            // A login grant's host is not a remembered host choice for the item.
            if !entries.is_empty() && lease.login.is_none() {
                self.store.replace_secret_hosts(&s.vault_id, &s.key, &lease.hosts)?;
            }
            self.store.insert_lease_with_request(&lease, &[row], &history)?;
            Self::apply_done_locked(&mut book, p.id.clone(), done);
            drop(book);
            if entries.is_empty() {
                Ok(())
            } else {
                {
                    let mut proxy = lock(&self.proxy_state);
                    proxy.dirty = true;
                    proxy.entries.insert(lease.id.clone(), entries);
                }
                self.publish_proxy_locked(&authority)
            }
        };
        lock(&self.last_active).insert(lease.id.clone());
        self.log_lease_created(&lease);
        self.log(event);
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        self.notify_request_ended();
        // Approval is already durable. Polling refuses to release the sentinel until
        // the proxy publishes the lease; a publication error must not re-open approval.
        publication.map_err(Fail::Keep)
    }

    fn approve_login(
        &self, p: &Pending, l: &LoginDetail, selection: &ffi::LoginChoice,
        duration_secs: Option<u64>, fill_origins: &[String],
    ) -> std::result::Result<(), Fail> {
        let vault = self.registry.get(&selection.vault_id)
            .ok_or_else(|| CoreError::vault_unavailable("the selected vault was removed"))?;
        let named = self.resolve_login_choice(selection)?;
        let mut secret = SecretRef::from_named(&named);
        if l.mode == BrowserLoginMode::Grant {
            if !fill_origins.is_empty() {
                return Err(CoreError::invalid("a login grant does not allow extra fill origins").into());
            }
            if !duration_secs.is_some_and(|d| (1..=LOGIN_MAX_SECS).contains(&d)) {
                return Err(CoreError::invalid("choose a login grant duration of at most 1 hour").into());
            }
            let target = parse_login_url(&l.url)?;
            secret.fields.retain(|f| matches!(f.as_str(), "username" | "password" | "totp"));
            let binding = LoginBinding { port: target.port, target: target.target, owner: p.host_id.clone().unwrap_or_default() };
            let delivery = VaultDelivery { wanted_fields: &secret.fields, reason: &l.reason, mode: LeaseMode::Sentinel,
                hosts: vec![target.host], duration_secs, login: Some((LoginScope { url: l.url.clone() }, binding)) };
            return self.deliver_vault(p, &secret, self.read_selected_login(&vault, selection)?, delivery);
        }
        let export_origin = l.fill_origins.first().cloned()
            .ok_or_else(|| CoreError::internal("sign-in request without an origin"))?;
        let mut approved = vec![export_origin.clone()];
        for o in fill_origins {
            if !l.fill_origins.contains(o) {
                return Err(Fail::Keep(CoreError::invalid(format!("{o} is not a fill origin of this request"))));
            }
            if !approved.contains(o) {
                approved.push(o.clone());
            }
        }
        if duration_secs == Some(0) {
            return Err(Fail::Keep(CoreError::invalid("choose how long the session stays valid")));
        }
        let (export_host, _) = l.target()?;
        if self.broker.chrome().is_none() {
            return Err(Fail::Refuse(broker::NO_CHROME.into()));
        }
        let values = self.read_selected_login(&vault, selection)?;
        let (mut username, mut password) = (None, None);
        for (field, value) in values {
            // Every value read is zeroized when dropped, used or not.
            let value = Zeroizing::new(value);
            match field.as_str() {
                "username" => username = Some(value),
                "password" => password = Some(value),
                _ => {}
            }
        }
        let password = password
            .ok_or_else(|| Fail::Keep(CoreError::vault_unavailable("an approved field is no longer available")))?;
        let event = activity::broker_started(p, &approved);
        let spec = SessionSpec {
            request_id: p.id.clone(),
            host_id: p.host_id.clone().unwrap_or_default(),
            host_label: p.host_label.clone(),
            account: l.account.clone(),
            url: l.url.clone(),
            export_host,
            export_origin,
            fill_origins: approved,
            username,
            password,
            secret,
            lease_secs: duration_secs.unwrap_or(BROKER_DEFAULT_SECS),
        };
        self.broker.start(spec, self.generation_now()).map_err(Fail::Refuse)?;
        self.log(event);
        self.notify(TOPIC_REQUESTS);
        Ok(())
    }

    fn read_selected_login(&self, vault: &VaultEntry, choice: &ffi::LoginChoice) -> Result<super::Values> {
        let mut values = vault.provider.read(&choice.key)
            .map_err(|e| CoreError::vault_unavailable(e.message))?;
        let username = values.iter().find(|(f, _)| f == "username")
            .map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
        if username != choice.username.as_deref()
            || values.iter().any(|(f, _)| f == "totp") != choice.has_totp
            || !self.registry.get(&choice.vault_id).is_some_and(|current| current.name == choice.vault_name
                && std::sync::Arc::ptr_eq(&current.provider, &vault.provider)) {
            for (_, value) in &mut values { zeroize::Zeroize::zeroize(value); }
            return Err(CoreError::vault_unavailable("the selected login changed; review it again"));
        }
        Ok(values)
    }

    /// End an approved sign-in: hand the storage state over, or deny. A request that
    /// already ended (cancelled by its host, host revoked) is left as it is.
    pub(crate) fn broker_finished(&self, request_id: &str, secret: &SecretRef, outcome: broker::Outcome) {
        let result = match outcome {
            broker::Outcome::Deny(reason) => self.broker_deny(request_id, reason),
            broker::Outcome::HandOver { state, lease_secs } => {
                let handed = self.broker_hand_over(request_id, secret, &state, lease_secs);
                if let Err(e) = &handed {
                    log::error!("sign-in {request_id}: hand-over failed: {}", e.message);
                }
                handed.or_else(|_| self.broker_deny(request_id, "the sign-in could not be handed over"))
            }
        };
        if let Err(e) = result {
            log::error!("sign-in {request_id}: {}", e.message);
        }
    }

    fn broker_deny(&self, id: &str, reason: &str) -> Result<()> {
        let t = self.generation_now();
        let changed = {
            let _authority = lock(&self.authorization);
            self.finish_locked(&mut lock(&self.book), id, Err(Some(reason.to_owned())), t, false)?
        };
        if changed {
            self.notify_request_ended();
        }
        Ok(())
    }

    /// Deliver the storage state once, as a raw lease of the login item.
    fn broker_hand_over(&self, id: &str, s: &SecretRef, state: &str, lease_secs: u64) -> Result<()> {
        let Some(p) = lock(&self.book).pending.iter().find(|p| p.id == id).cloned() else { return Ok(()) };
        let Detail::Login(l) = &p.detail else {
            return Err(CoreError::internal("a sign-in ended on a request of another kind"));
        };
        let path = relative_paths(s.prefixed.then_some(s.vault_name.as_str()), &s.base, s.kind, &[STORAGE_STATE_FIELD])
            .remove(0);
        let t = self.generation_now();
        let expires_at = Some(t.saturating_add(lease_secs.min(i64::MAX as u64) as i64));
        let lease = LeaseRecord {
            id: new_uuid_v4(),
            host_id: p.host_id.clone().unwrap_or_default(),
            vault_id: s.vault_id.clone(),
            vault_name: s.vault_name.clone(),
            secret_key: s.key.clone(),
            name: s.display.clone(),
            mode: LeaseMode::Raw,
            fields: vec![LeaseField { field: STORAGE_STATE_FIELD.into(), sentinel: None, path: path.clone() }],
            hosts: Vec::new(),
            reason: l.reason.clone(),
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
            login: None,
        };
        let result = RequestResult::Get(GetResult {
            lease_id: lease.id.clone(),
            mode: LeaseMode::Raw,
            hosts: Vec::new(),
            expires_at: expires_at.map(fmt_unix),
            files: vec![ResultFile {
                field: STORAGE_STATE_FIELD.into(),
                relative_path: path,
                content: state.to_owned(),
                substituted: Some(false),
            }],
            generation: None,
            operator_selected_grant: false,
            broader_lease_reuse: false,
            credential_expires_at: None,
            credential_version: None,
            generator_name: None,
            login: None,
        });
        let event = activity::approved(&p, Some(&result), t);
        let mut request_state = p.state_for(&p.id, RequestStatus::Approved);
        request_state.result = Some(result);
        let done = Done { host_id: lease.host_id.clone(), state: request_state, at: t, generated: None };
        let history = p.history(RequestStatus::Approved, None, t);
        {
            let _authority = lock(&self.authorization);
            if !self.host_is_active(&lease.host_id)? {
                return Ok(());
            }
            let mut book = lock(&self.book);
            if !book.pending.iter().any(|q| q.id == p.id) {
                return Ok(());
            }
            let row = self.seal_done(&p.id, &done)?;
            self.complete_pending_locked(&mut book, done, [row], |rows|
                self.store.insert_lease_with_request(&lease, rows, &history))?;
        }
        lock(&self.last_active).insert(lease.id.clone());
        self.log_lease_created(&lease);
        self.log(event);
        self.notify(TOPIC_LEASES);
        self.notify_request_ended();
        Ok(())
    }

    /// The operator's "Hand over session".
    pub fn broker_handover(&self, request_id: &str) -> Result<()> {
        if !self.broker.hand_over(request_id) {
            return Err(CoreError::not_found("this sign-in is no longer running"));
        }
        self.notify(TOPIC_REQUESTS);
        Ok(())
    }

    /// The operator's "Cancel": the request is denied with "sign-in cancelled".
    pub fn broker_cancel(&self, request_id: &str) -> Result<()> {
        if !self.broker.cancel(request_id, broker::DENY_CANCELLED) {
            return Err(CoreError::not_found("this sign-in is no longer running"));
        }
        self.notify(TOPIC_REQUESTS);
        Ok(())
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
        let leases: Vec<LeaseRecord> = {
            let _authority = lock(&self.authorization);
            let leases: Vec<LeaseRecord> = self.store.active_leases(t)?
                .into_iter()
                .filter(|l| l.source_kind == SourceKind::Vault && l.vault_id == s.vault_id && l.secret_key == s.key)
                .collect();
            for l in leases.iter().filter(|l| l.mode == LeaseMode::Raw) {
                if self.store.revoke_lease(&l.id, t)? {
                    self.log_lease_revoked(l, "secret updated");
                }
            }
            leases
        };
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
        let entry = self.registry.get(vault_id).filter(|v| accepts_add(v, &a.name))
            .ok_or_else(|| Fail::Keep(CoreError::invalid("choose an available vault")))?;
        let collection_id = match &entry.config {
            VaultConfig::Bitwarden(config) => match collection_id {
                Some(c) if config.collections.contains(&c) => Some(c),
                None if config.personal => None,
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
        entry
            .provider
            .add(&a.name, &a.value, &AddTarget { collection_id })
            .map_err(|e| Fail::Deny(format!("vault unavailable: {}", e.message)))?;
        self.notify(TOPIC_VAULTS);
        Ok(WriteResult {
            name: a.name.clone(),
            vault: entry.name,
        })
    }

    // ---- snapshot ----

    pub fn snapshot(&self) -> ffi::Snapshot {
        if let Err(e) = self.expire_requests(self.generation_now()) {
            log::error!("request expiration: {}", e.message);
        }
        let default_duration = self.settings().lease_default_secs;
        // An approved sign-in stays pending for its host while its browser runs; the
        // operator sees it as a broker session instead.
        let mut pending: Vec<Pending> = lock(&self.book).pending.clone();
        let mut broker_sessions = self.broker.sessions();
        pending.retain(|p| !broker_sessions.iter().any(|s| s.request_id == p.id));
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
        let pending_hosts: HashMap<String, String> = lock(&self.book).pending.iter()
            .filter_map(|p| Some((p.id.clone(), p.host_id.clone()?))).collect();
        for s in &mut broker_sessions {
            if let Some((label, _)) = pending_hosts.get(&s.request_id).and_then(|id| names.get(id)) {
                s.host_label = label.clone();
            }
        }
        let broker_sessions = broker_sessions.into_iter().map(|s| ffi::BrokerSessionInfo {
            request_id: s.request_id, url: s.url, account: s.account, host_label: s.host_label,
            started_at: to_system_time(s.started_at), status: s.status,
        }).collect();
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
        ffi::Snapshot { pending, recent, broker_sessions }
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
        "login" => ffi::RequestKind::Login,
        "ssh" => ffi::RequestKind::Ssh,
        _ => ffi::RequestKind::Get,
    }
}

fn pattern_check(p: &str) -> ffi::HostPatternCheck {
    ffi::HostPatternCheck {
        normalized: p.to_string(),
        broad: is_broad(p),
    }
}

fn approval_choice(
    core: &Core,
    target: &GeneratorTarget,
    choice: &GenerationChoice,
) -> ffi::GeneratorApprovalChoice {
    let mut scope_catalog = Vec::new();
    let mut default_project_id = None;
    let mut gcloud_ready = None;
    let _authority = matches!(&choice.ceiling, GenerationGrant::GcloudAccess(_))
        .then(|| lock(&core.authorization));
    // Never describe a pending grant using metadata from a replacement revision.
    if let Some(entry) = core.generators.get(&choice.generator_id)
        && entry.record.revision == choice.revision
    {
        if let GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access }) = &choice.ceiling {
            gcloud_ready = core.ready_gcloud_access_locked(&entry.record, access).ok().map(Into::into);
        }
        if let crate::generator::GeneratorConfig::Gcloud(config) = entry.record.config {
            default_project_id = Some(config.project_id);
            scope_catalog.extend(config.scope_catalog.into_iter().map(Into::<ffi::GcloudScopeOption>::into));
        }
    }
    ffi::GeneratorApprovalChoice {
        choice: choice.clone().into(), scope_catalog, default_project_id, gcloud_ready,
        scope_issues: target.requested_generation.as_ref().map(|request|
            choice.ceiling.scope_issues(request).unwrap_or_else(|e| vec![e.message])).unwrap_or_default(),
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
                GetTarget::Generated(target) => {
                    let label = target.candidates.first()
                        .and_then(|choice| core.generators.get(&choice.generator_id))
                        .map(|entry| entry.record.config.provider_label())
                        .unwrap_or("Generator");
                    (target.requested_name.clone(), target.pinned_generator_id.clone(), label.into(),
                        SecretKind::Single, target.candidates.iter().map(|choice|
                            approval_choice(core, target, choice)
                        ).collect(), target.requested_generation.clone().map(Into::into))
                }
            };
            ffi::RequestDetail::Get {
                is_generated: matches!(g.target, GetTarget::Generated(_)),
                name, vault_id, vault_name, kind: kind.into(), fields: g.wanted_fields,
                reason: g.reason, raw_requested: g.mode == RequestedMode::Raw
                    || (g.mode == RequestedMode::Default && matches!(g.target, GetTarget::Generated(_))),
                sentinel_required: g.mode == RequestedMode::Sentinel,
                has_substitutable_fields,
                generator_choices, requested_generation,
                operator_selected_grant: matches!(&g.target, GetTarget::Generated(target) if target.operator_selected_grant),
                operator_selected_gcloud_project: matches!(&g.target, GetTarget::Generated(target)
                    if target.operator_selected_gcloud_project),
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
            targets: core.add_targets(&a.name),
            name: a.name,
            value: a.value,
        },
        Detail::Login(l) => ffi::RequestDetail::Login {
            site: l.site,
            account: l.account,
            broker: l.mode == BrowserLoginMode::Broker,
            url: l.url,
            fill_origins: l.fill_origins,
            reason: l.reason,
        },
        Detail::LegacyLogin {} => unreachable!("legacy pending logins are retired on restore"),
        Detail::Ssh(s) => core.ssh_approval_detail(&s, default_duration),
        Detail::SshExtend(e) => core.ssh_extend_approval_detail(&e, default_duration),
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
#[path = "login_broker_tests.rs"]
mod login_broker_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use asm_proto::crypto::hex_encode;
    use asm_proto::pairing::{client_commit, new_nonce};
    use asm_proto::wire::{PairRequest, PairResponse, RevealRequest};
    use serde_json::json;

    struct Quiet;

    impl ffi::ManagerObserver for Quiet {
        fn changed(&self, _: String) {}
    }

    pub(super) fn open_manager(tmp: &tempfile::TempDir) -> Arc<Core> {
        let data = tmp.path().join("data");
        let dirs = crate::paths::DataDirs::create(&data, Some(tmp.path())).unwrap();
        if !dirs.proxy.join("ca.crt").exists() {
            std::fs::write(dirs.proxy.join("ca.crt"), "isolated existing ca").unwrap();
            std::fs::write(dirs.proxy.join("ca.key"), "isolated existing key").unwrap();
        }
        Core::start(data, tmp.path().join("no-proxy-binary"), Arc::new(Quiet), super::super::StartOptions {
            values_root: Some(tmp.path().to_owned()),
            resume_key: Some([42; 32]),
            settings: vec![
                (crate::settings::API_BIND.into(), json!("127.0.0.1")),
                (crate::settings::API_PORT.into(), json!(0)),
            ],
        }).unwrap()
    }

    fn reopen(core: Arc<Core>, tmp: &tempfile::TempDir) -> Arc<Core> {
        core.shutdown();
        drop(core);
        open_manager(tmp)
    }

    pub(super) fn request_host(core: &Core) -> HostRecord {
        request_host_with_proof(core, &[1; 32])
    }

    fn request_host_with_proof(core: &Core, proof: &[u8; 32]) -> HostRecord {
        let host = HostRecord {
            id: new_uuid_v4(),
            info: HostInfo { hostname: "request-host".into(), ..Default::default() },
            name: String::new(),
            address: "127.0.0.1".into(),
            paired_at: core.generation_now(),
            last_seen: None,
            revoked_at: None,
            machine_hint: None,
        };
        core.store.insert_host(&host, proof).unwrap();
        host
    }

    fn request_add(core: &Core, host: &HostRecord, name: &str, value: &str) -> RequestState {
        core.create_request(host, "127.0.0.1", RequestBody::Add {
            name: name.into(), value: value.into(), agent: String::new(),
        }).unwrap()
    }

    #[test]
    fn interrupted_write_keeps_its_id_deadline_and_value_without_replaying() {
        const PROPOSAL: &str = "isolated-proposed-value-not-in-sqlite";
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let output = tmp.path().join("secrets.env");
        std::fs::write(&output, "EXISTING=value\n").unwrap();
        let vault = core.save_vault(ffi::VaultDraft {
            id: None, name: "test".into(),
            config: ffi::VaultConfig::EnvFile { path: output.to_string_lossy().into_owned() },
            client_secret: String::new(), master_password: String::new(),
        }).unwrap();
        let host = request_host(&core);
        let pending = request_add(&core, &host, "PROPOSED", PROPOSAL);
        {
            let _authorization = lock(&core.authorization);
            let mut book = lock(&core.book);
            let p = book.pending.iter_mut().find(|p| p.id == pending.request_id).unwrap();
            // Simulate the exact durable boundary before the provider is called.
            core.mark_request_resolving(p).unwrap();
        }
        for path in [core.dirs.db(), core.dirs.db().with_extension("db-wal")] {
            if let Ok(bytes) = std::fs::read(path) {
                assert!(!bytes.windows(PROPOSAL.len()).any(|w| w == PROPOSAL.as_bytes()));
            }
        }

        core = reopen(core, &tmp);
        assert_eq!(core.request_state(&host.id, &pending.request_id).unwrap(), pending);
        assert_eq!(request_add(&core, &host, "PROPOSED", PROPOSAL), pending);
        let snapshot = core.snapshot();
        assert_eq!(snapshot.pending[0].error.as_deref(), Some(INTERRUPTED));
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "EXISTING=value\n");

        core.resolve_request(&pending.request_id, ffi::Decision::ApproveWrite {
            vault_id: vault.id, collection_id: None,
        }).unwrap();
        core = reopen(core, &tmp);
        let terminal = core.request_state(&host.id, &pending.request_id).unwrap();
        assert_eq!(terminal.status, RequestStatus::Approved);
        assert!(matches!(terminal.result, Some(RequestResult::Write(_))));
        assert_eq!(core.snapshot().recent[0].id, pending.request_id);
        assert!(std::fs::read_to_string(&output).unwrap().contains(PROPOSAL));
        core.shutdown();
    }

    #[test]
    fn terminal_decisions_and_host_revocation_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let host = request_host(&core);
        let denied = request_add(&core, &host, "DENIED", "test").request_id;
        core.resolve_request(&denied, ffi::Decision::Deny { reason: "explicit denial".into() }).unwrap();
        let cancelled = request_add(&core, &host, "CANCELLED", "test").request_id;
        core.cancel_request(&host.id, &cancelled).unwrap();
        let expired = {
            let mut pending = core.new_pending(&host, "", "127.0.0.1", Detail::Add(AddDetail {
                name: "EXPIRED".into(), value: "test".into(),
            }));
            pending.created -= 10;
            pending.expires = core.generation_now() - 1;
            let id = pending.id.clone();
            core.save_pending_locked(&mut lock(&core.book), pending).unwrap();
            id
        };
        core = reopen(core, &tmp);
        let state = core.request_state(&host.id, &denied).unwrap();
        assert_eq!(state.status, RequestStatus::Denied);
        assert_eq!(state.deny_reason.as_deref(), Some("explicit denial"));
        assert_eq!(core.request_state(&host.id, &cancelled).unwrap().status, RequestStatus::Cancelled);
        assert_eq!(core.request_state(&host.id, &expired).unwrap().status, RequestStatus::Expired);
        assert!(core.snapshot().pending.is_empty());

        let revoked = request_add(&core, &host, "REVOKED", "test").request_id;
        // Simulate stopping after the authoritative host row changed, before
        // cancelling the requests that belonged to it.
        assert!(core.store.revoke_host(&host.id, core.generation_now()).unwrap());
        core = reopen(core, &tmp);
        assert!(core.snapshot().pending.is_empty());
        assert!(core.request_state(&host.id, &revoked).is_err());
        assert!(core.snapshot().recent.iter().any(|r| r.id == revoked && r.outcome == ffi::RequestOutcome::Cancelled));
        core.shutdown();
    }

    #[test]
    fn raw_delivery_commits_once_and_checks_live_lease_and_host_proof() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let env = tmp.path().join("secrets.env");
        std::fs::write(&env, "DEMO_TOKEN=isolated-static-value\n").unwrap();
        core.save_vault(ffi::VaultDraft {
            id: None, name: "test".into(),
            config: ffi::VaultConfig::EnvFile { path: env.to_string_lossy().into_owned() },
            client_secret: String::new(), master_password: String::new(),
        }).unwrap();
        let host = request_host(&core);
        let approve = |core: &Core, reason: &str| {
            let body = serde_json::from_value(json!({
                "kind": "get", "name": "DEMO_TOKEN", "raw": true, "reason": reason,
            })).unwrap();
            let r = core.create_request(&host, "127.0.0.1", body).unwrap();
            core.resolve_request(&r.request_id, ffi::Decision::ApproveGet {
                mode: ffi::LeaseMode::Raw, duration_secs: None, hosts: Vec::new(), generation: None,
            }).unwrap();
            r.request_id
        };
        let deliver = approve(&core, "consume after restart");
        let revoked = approve(&core, "revoke before poll");
        let leases = core.store.leases_of_host(&host.id).unwrap();
        let lease = leases.iter().find(|l| l.reason == "revoke before poll").unwrap();
        core.revoke_lease(&lease.id).unwrap();
        assert!(core.store.rotate_host_token(&host, &[1; 32], &[2; 32]).unwrap());
        // No credential can leave the manager if its consume mark cannot commit.
        core.resume.close().unwrap();
        assert!(core.request_state_with_proof(&host.id, &deliver, Some(&[2; 32])).is_err());

        core = reopen(core, &tmp);
        assert_eq!(core.request_state_with_proof(&host.id, &deliver, Some(&[1; 32])).unwrap_err().code,
            asm_proto::ErrorCode::Unauthorized);
        assert!(core.request_state_with_proof(&host.id, &revoked, Some(&[2; 32])).is_err());
        let approved = core.request_state_with_proof(&host.id, &deliver, Some(&[2; 32])).unwrap();
        let Some(RequestResult::Get(result)) = approved.result else { panic!("missing recovered delivery") };
        assert_eq!(result.files[0].content, "isolated-static-value");

        core = reopen(core, &tmp);
        assert!(core.request_state_with_proof(&host.id, &deliver, Some(&[2; 32])).unwrap().result.is_none());
        assert!(core.request_state_with_proof(&host.id, &revoked, Some(&[2; 32])).is_err());
        core.shutdown();
    }

    fn start_pair(core: &Core, name: &str, ip: &str) -> (String, RevealRequest) {
        let nonce = new_nonce();
        let PairResponse::AwaitingReveal { pair_id, poll_token, .. } = core.pair_start(PairRequest {
            client_commit: hex_encode(&client_commit(&nonce)),
            host_info: HostInfo { hostname: name.into(), ..Default::default() },
            pairing_code: None, previous: None, machine_hint: None,
        }, ip).unwrap() else { panic!("missing pairing attempt") };
        (pair_id, RevealRequest {
            poll_token, client_nonce: hex_encode(&nonce),
        })
    }

    #[test]
    fn pairing_can_reveal_and_claim_the_same_attempt_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let (pair_id, request) = start_pair(&core, "pair-host", "127.0.0.1");
        core = reopen(core, &tmp);
        let reveal = |core: &Core| core.pair_reveal(&pair_id, request.clone()).unwrap();
        let PairResponse::Pending { expires_at, .. } = reveal(&core) else { panic!("pair did not reveal") };
        core = reopen(core, &tmp);
        assert_eq!(core.snapshot().pending[0].id, pair_id);
        let PairResponse::Pending { expires_at: recovered, .. } = reveal(&core) else { panic!("pair lost reveal") };
        assert_eq!(recovered, expires_at);
        core.resolve_request(&pair_id, ffi::Decision::ApprovePair { name: "paired".into(), replace: false }).unwrap();
        core = reopen(core, &tmp);
        assert!(core.pair_poll(&pair_id, "wrong").is_err());
        let PairResponse::Approved { host_id, token } = core.pair_poll(&pair_id, &request.poll_token).unwrap()
            else { panic!("pair did not recover its approval") };
        assert!(core.store.host_by_proof(&host_id, &sha256(token.as_bytes())).unwrap().is_some());
        core = reopen(core, &tmp);
        assert_eq!(core.pair_poll(&pair_id, &request.poll_token).unwrap_err().code, asm_proto::ErrorCode::NotFound);
        assert!(core.snapshot().recent.iter().any(|r| r.id == pair_id && r.outcome == ffi::RequestOutcome::Approved));
        core.shutdown();
    }

    #[test]
    fn pairing_denial_expiry_and_host_revocation_are_final_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let (denied, deny_req) = start_pair(&core, "deny-pair", "127.0.0.1");
        core.pair_reveal(&denied, deny_req.clone()).unwrap();
        core.resolve_request(&denied, ffi::Decision::Deny { reason: "not this host".into() }).unwrap();

        let (revoked, revoke_req) = start_pair(&core, "revoke-pair", "127.0.0.1");
        core.pair_reveal(&revoked, revoke_req.clone()).unwrap();
        core.resolve_request(&revoked, ffi::Decision::ApprovePair { name: "".into(), replace: false }).unwrap();
        let host = core.store.list_hosts().unwrap().into_iter().find(|h| h.info.hostname == "revoke-pair").unwrap();
        core.revoke_host(&host.id).unwrap();

        let (expired, expire_req) = start_pair(&core, "expire-pair", "127.0.0.1");
        core.expire_requests(core.generation_now() + REVEAL_SECS).unwrap();
        core = reopen(core, &tmp);
        assert!(core.snapshot().pending.is_empty());
        assert!(core.pair_reveal(&denied, deny_req.clone()).is_err());
        assert!(matches!(core.pair_poll(&denied, &deny_req.poll_token).unwrap(),
            PairResponse::Denied { deny_reason: Some(reason) } if reason == "not this host"));
        assert!(matches!(core.pair_poll(&expired, &expire_req.poll_token).unwrap(), PairResponse::Expired { .. }));
        assert_eq!(core.pair_poll(&revoked, &revoke_req.poll_token).unwrap_err().code, asm_proto::ErrorCode::NotFound);
        core.shutdown();
    }

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

    /// Login items for grant tests; every read yields a new one-time code.
    pub(super) struct Logins(pub(super) std::sync::atomic::AtomicU64);

    impl crate::vault::VaultProvider for Logins {
        fn status(&self) -> VaultStatus {
            VaultStatus::Ready
        }
        fn list(&self) -> Result<Vec<crate::vault::SecretMeta>> {
            let item = |key: &str, kind, fields: &[&str], hosts: &[&str]| crate::vault::SecretMeta {
                key: key.into(), name: key.into(), kind,
                fields: fields.iter().map(|f| f.to_string()).collect(),
                uri_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            };
            let login = |key: &str, hosts: &[&str]| item(key, SecretKind::Login, &["username", "password"], hosts);
            Ok(vec![
                item("Herokuapp", SecretKind::Login, &["username", "password", "totp"], &["the-internet.herokuapp.com"]),
                login("SharedA", &["shared.test"]),
                login("SharedB", &["shared.test"]),
                login("ChangedUser", &["shared.test"]),
                login("Exact", &["sso.exact.test"]),
                login("Parent", &["exact.test", "parent.test"]),
                item("Note", SecretKind::Single, &["notes"], &["note.test"]),
            ])
        }
        fn list_logins(&self) -> Result<Vec<crate::vault::LoginMeta>> {
            Ok(self.list()?.into_iter().filter(|m| m.kind == SecretKind::Login).map(|meta| {
                crate::vault::LoginMeta { meta, username: Some("tomsmith".into()) }
            }).collect())
        }
        fn read(&self, key: &str) -> Result<Vec<(String, String)>> {
            if key == "Note" {
                return Ok(vec![("notes".into(), "n".into())]);
            }
            let username = if key == "ChangedUser" { "another-user" } else { "tomsmith" };
            let mut values = vec![("username".into(), username.into()), ("password".into(), "SuperSecretPassword!".into())];
            if key == "Herokuapp" {
                let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                values.push(("totp".into(), format!("{n:06}")));
            }
            Ok(values)
        }
        fn update(&self, _: &str, _: &str, _: &str) -> Result<()> {
            Err(CoreError::invalid("read-only"))
        }
        fn add(&self, _: &str, _: &str, _: &AddTarget) -> Result<()> {
            Err(CoreError::invalid("read-only"))
        }
    }

    /// A manager whose proxy is an inert child, so login grants publish. Reopening the
    /// same `tmp` restarts on the same data directory.
    fn open_login_manager(tmp: &tempfile::TempDir) -> Arc<Core> {
        open_login_manager_with(tmp, &[])
    }

    fn open_login_manager_with(tmp: &tempfile::TempDir, extra: &[(&str, serde_json::Value)]) -> Arc<Core> {
        use std::os::unix::fs::PermissionsExt;
        let data = tmp.path().join("data");
        let dirs = crate::paths::DataDirs::create(&data, Some(tmp.path())).unwrap();
        if !dirs.proxy.join("ca.crt").exists() {
            std::fs::write(dirs.proxy.join("ca.crt"), "isolated existing ca").unwrap();
            std::fs::write(dirs.proxy.join("ca.key"), "isolated existing key").unwrap();
        }
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("iron-proxy"), "#!/bin/sh\nexec /bin/sleep 60\n").unwrap();
        std::fs::set_permissions(bin.join("iron-proxy"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let listeners: Vec<_> = (0..5).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let ports: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap().port()).collect();
        drop(listeners);
        let mut settings = vec![
            (crate::settings::API_BIND.into(), json!("127.0.0.1")),
            (crate::settings::API_PORT.into(), json!(0)),
            (crate::settings::PROXY_BIND.into(), json!("127.0.0.1")),
            (crate::settings::PROXY_PORT.into(), json!(ports[0])),
            (crate::settings::PROXY_HTTP_PORT.into(), json!(ports[1])),
            (crate::settings::PROXY_HTTPS_PORT.into(), json!(ports[2])),
            (crate::settings::PROXY_MGMT_PORT.into(), json!(ports[3])),
            (crate::settings::PROXY_METRICS_PORT.into(), json!(ports[4])),
        ];
        settings.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        let core = Core::start(data, bin, Arc::new(Quiet), super::super::StartOptions {
            values_root: Some(tmp.path().to_owned()),
            resume_key: Some([42; 32]),
            settings,
        }).unwrap();
        core.registry.insert(VaultEntry {
            id: "logins".into(), name: "Logins".into(),
            config: VaultConfig::EnvFile { path: "/unused".into() },
            provider: Arc::new(Logins(std::sync::atomic::AtomicU64::new(0))),
        });
        core
    }

    fn login_body(url: &str) -> RequestBody {
        RequestBody::BrowserLogin(BrowserLoginRequest {
            mode: BrowserLoginMode::Grant, url: url.into(), site: None, account: None,
            reason: "sign in".into(), extra_fill_origins: Vec::new(), agent: String::new(),
            client_capabilities: vec![asm_proto::wire::CAPABILITY_BROWSER_LOGIN_V2.into()],
        })
    }

    pub(super) fn choice(core: &Core, key: &str) -> ffi::LoginChoice {
        core.login_choices().unwrap().items.into_iter().find(|c| c.key == key).unwrap()
    }

    #[test]
    fn browser_intents_reattach_only_within_requester_account_and_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager(&tmp);
        let host = request_host(&core);
        let other = request_host_with_proof(&core, &[2; 32]);
        let RequestBody::BrowserLogin(base) = login_body(LOGIN_URL) else { unreachable!() };
        let submit = |host: &HostRecord, intent| core.create_request(host, "127.0.0.1", RequestBody::BrowserLogin(intent)).unwrap();
        let pending = submit(&host, base.clone());
        assert_eq!(pending.kind, RequestKind::Get);
        assert_eq!(submit(&host, base.clone()), pending);
        assert_ne!(submit(&other, base.clone()).request_id, pending.request_id);
        for different in [
            BrowserLoginRequest { url: format!("{LOGIN_URL}?p=2"), ..base.clone() },
            BrowserLoginRequest { account: Some("personal".into()), ..base.clone() },
            BrowserLoginRequest { account: Some("work".into()), ..base.clone() },
            BrowserLoginRequest { site: Some("https://app.test".into()), ..base.clone() },
            BrowserLoginRequest { agent: "another".into(), ..base.clone() },
            BrowserLoginRequest { reason: "different task".into(), ..base.clone() },
            BrowserLoginRequest { mode: BrowserLoginMode::Broker, ..base.clone() },
        ] {
            let distinct = submit(&host, different.clone());
            assert_ne!(distinct.request_id, pending.request_id);
            assert_eq!(submit(&host, different), distinct);
        }
        assert_eq!(core.snapshot().pending.len(), 9);
        for url in ["https://nothing.test/session", "https://sso.exact.test/session", "https://shared.test/session"] {
            let state = core.create_request(&host, "127.0.0.1", login_body(url)).unwrap();
            assert_eq!(state.status, RequestStatus::Pending);
        }
        for name in ["", "SharedA"] {
            for body in [json!({"kind":"get","name":name,"reason":"why","login":{"url":LOGIN_URL}}),
                         json!({"kind":"login","name":name,"reason":"why","url":LOGIN_URL})] {
                let error = core.create_request(&host, "127.0.0.1", serde_json::from_value(body).unwrap()).unwrap_err();
                assert!(error.message.to_lowercase().contains("upgrade"));
            }
        }
        core.shutdown();
    }

    #[test]
    fn restart_retires_both_shapes_of_preselection_but_reattaches_v2_intent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_manager(&tmp);
        let host = request_host(&core);
        let new_request = core.create_request(&host, "127.0.0.1", login_body(LOGIN_URL)).unwrap();
        let secret = json!({ "vault_id":"vault", "vault_name":"Vault", "key":"old-key", "kind":"login",
            "fields":["username","password"], "display":"old title", "base":"old title", "prefixed":false });
        let mut old_ids = Vec::new();
        for detail in [
            json!({ "Login": { "secret":secret, "url":LOGIN_URL, "fill_origins":[], "reason":"sign in" }}),
            json!({ "Get": { "target":{"Vault":secret}, "mode":"Default", "wanted_fields":["username","password"],
                "requested_hosts":[], "reason":"sign in", "initial":[], "suggestions":[], "login":{"url":LOGIN_URL} }}),
        ] {
            let id = new_uuid_v4();
            let p = lock(&core.book).pending[0].clone();
            let mut legacy = serde_json::to_value(p).unwrap();
            legacy["id"] = json!(id);
            legacy["detail"] = detail;
            let row = core.resume.seal(BOOK_NAMESPACE, &id, &json!({ "Pending": legacy })).unwrap();
            core.store.commit_request_book(&[row], None).unwrap();
            old_ids.push(id);
        }
        core = reopen(core, &tmp);
        assert_eq!(core.snapshot().pending.len(), 1);
        assert_eq!(core.create_request(&host, "127.0.0.1", login_body(LOGIN_URL)).unwrap(), new_request);
        for id in old_ids {
            let state = core.request_state(&host.id, &id).unwrap();
            assert_eq!((state.status, state.deny_reason.as_deref()), (RequestStatus::Denied, Some(LEGACY_LOGIN)));
        }
        core.shutdown();
    }

    #[test]
    fn unavailable_renamed_or_changed_account_requires_new_review() {
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager(&tmp);
        let host = request_host(&core);
        let pending = core.create_request(&host, "127.0.0.1", login_body(LOGIN_URL)).unwrap();
        let original = choice(&core, "SharedB");
        let approve = |selection| core.resolve_request(&pending.request_id, ffi::Decision::ApproveLogin {
            selection, duration_secs: Some(900), fill_origins: Vec::new(),
        });
        let mut vault = core.registry.remove("logins").unwrap().unwrap();
        assert!(approve(original.clone()).is_err(), "removed since display");
        vault.name = "Renamed".into();
        core.registry.insert(vault);
        assert!(approve(original).is_err(), "same stable key but displayed vault changed");
        assert!(approve(choice(&core, "ChangedUser")).is_err(), "username changed between list and read");
        assert!(core.store.leases_of_host(&host.id).unwrap().is_empty());
        assert_eq!(core.request_state(&host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);
        approve(choice(&core, "SharedB")).unwrap();
        let leases = core.store.leases_of_host(&host.id).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!((leases[0].secret_key.as_str(), leases[0].vault_name.as_str()), ("SharedB", "Renamed"));
        assert_eq!(leases[0].hosts, ["the-internet.herokuapp.com"], "saved hosts never broaden authority");
        assert!(core.login_totp(&host.id, &[1; 32], &leases[0].id).is_err(), "no authenticator on the approved item");
        core.shutdown();
    }

    #[test]
    fn only_selected_login_can_issue_a_grant_and_generic_get_never_reuses_it() {
        const URL: &str = "https://the-internet.herokuapp.com/authenticate";
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager(&tmp);
        let host = request_host(&core);
        let pending = core.create_request(&host, "127.0.0.1", login_body(URL)).unwrap();
        let p = core.snapshot().pending.pop().unwrap();
        assert_eq!(p.detail, ffi::RequestDetail::Login { url: URL.into(), site: None, account: None,
            fill_origins: Vec::new(), reason: "sign in".into(), broker: false });
        assert!(core.resolve_request(&pending.request_id, ffi::Decision::ApproveGet {
            mode: ffi::LeaseMode::Raw, duration_secs: Some(900), hosts: Vec::new(), generation: None,
        }).is_err());
        let selection = choice(&core, "Herokuapp");
        let approve = |selection, duration_secs, fill_origins| core.resolve_request(&pending.request_id,
            ffi::Decision::ApproveLogin { selection, duration_secs, fill_origins });
        let mut stale = selection.clone();
        stale.title.push_str(" (renamed)");
        assert!(approve(stale, Some(900), Vec::new()).is_err());
        for duration in [None, Some(0), Some(3601)] {
            assert!(approve(selection.clone(), duration, Vec::new()).is_err());
        }
        assert!(approve(selection.clone(), Some(900), vec!["https://another.test".into()]).is_err());
        assert_eq!(core.request_state(&host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);

        approve(selection, Some(900), Vec::new()).unwrap();
        let state = core.request_state(&host.id, &pending.request_id).unwrap();
        let Some(RequestResult::Get(result)) = state.result else { panic!("missing login grant") };
        assert_eq!(result.login, Some(LoginScope { url: URL.into() }));
        assert_eq!(result.hosts, ["the-internet.herokuapp.com"]);
        let file = |f: &str| result.files.iter().find(|x| x.field == f).unwrap();
        assert_eq!((file("username").content.as_str(), file("username").substituted), ("tomsmith", Some(false)));
        assert!(asm_proto::rules::is_sentinel(&file("password").content));
        assert_eq!(file("password").substituted, Some(true));
        assert_eq!(file("totp").substituted, Some(false));
        let first_code = file("totp").content.clone();
        let lease = core.store.get_lease(&result.lease_id).unwrap().unwrap();
        assert_eq!(lease.login, result.login);
        let expires = lease.expires_at.unwrap();
        {
            let proxy = lock(&core.proxy_state);
            let entries = &proxy.entries[&lease.id];
            assert_eq!(entries.len(), 1, "only the password is substituted");
            assert_eq!(entries[0].login, Some(LoginBinding {
                port: 443, target: "/authenticate".into(), owner: host.id.clone(),
            }));
            assert_eq!(proxy.routes, [crate::proxy::BrowserRoute {
                host: "the-internet.herokuapp.com".into(), port: 443, until: expires,
            }]);
        }
        assert!(core.store.secret_hosts("logins", "Herokuapp").unwrap().is_empty(), "no remembered hosts");
        let config = std::fs::read_to_string(core.dirs.proxy.join("iron-proxy.yaml")).unwrap();
        assert!(config.contains(&format!(
            "browser_hosts: [{{host: \"the-internet.herokuapp.com\", port: 443, until: {expires}}}]")), "{config}");
        assert!(config.contains("target: \"/authenticate\""), "{config}");

        let get = |fields: serde_json::Value| core.create_request(&host, "127.0.0.1", serde_json::from_value(json!({
            "kind": "get", "name": "Herokuapp", "fields": fields, "reason": "otp",
            "client_capabilities": ["secret_fields_v1"],
        })).unwrap()).unwrap();
        assert_eq!(get(json!(["totp"])).status, RequestStatus::Pending);
        assert_eq!(get(json!(["username"])).status, RequestStatus::Pending);
        let reused = core.login_totp(&host.id, &[1; 32], &lease.id).unwrap();
        assert_eq!(reused.lease_id, lease.id);
        assert_eq!(reused.files.len(), 1);
        assert_eq!((reused.files[0].field.as_str(), reused.files[0].substituted), ("totp", Some(false)));
        assert_eq!(reused.files[0].relative_path, file("totp").relative_path);
        assert_eq!(reused.login, result.login);
        let other = request_host_with_proof(&core, &[2; 32]);
        assert!(core.login_totp(&other.id, &[2; 32], &lease.id).is_err());
        assert!(core.login_totp(&host.id, &[2; 32], &lease.id).is_err());
        assert_ne!(reused.files[0].content, first_code, "a fresh code");
        assert_eq!(get(json!(["password"])).status, RequestStatus::Pending, "the password sentinel is never redelivered");
        assert_eq!(get(json!(["password", "username"])).status, RequestStatus::Pending);
        core.revoke_lease(&lease.id).unwrap();
        assert!(core.login_totp(&host.id, &[1; 32], &lease.id).is_err());
        core.shutdown();
    }

    #[test]
    fn proxy_credentials_follow_host_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let core = open_manager(&tmp);
        let path = core.dirs.proxy.join("proxy-auth");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "", "written at startup");
        let host = request_host(&core);
        core.sync_proxy_auth();
        let password = asm_proto::crypto::proxy_password(&[1; 32]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(),
            format!("{}:{}\n", host.id, asm_proto::crypto::sha256_hex(password)));
        core.revoke_host(&host.id).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        core.shutdown();
    }

    const LOGIN_URL: &str = "https://the-internet.herokuapp.com/authenticate";

    /// Approve a login grant for [`LOGIN_URL`] lasting `secs`; returns its lease.
    fn approve_login(core: &Core, host: &HostRecord, secs: u64) -> LeaseRecord {
        let pending = core.create_request(host, "127.0.0.1", login_body(LOGIN_URL)).unwrap();
        core.resolve_request(&pending.request_id, ffi::Decision::ApproveLogin {
            selection: choice(core, "Herokuapp"), duration_secs: Some(secs), fill_origins: Vec::new(),
        }).unwrap();
        let Some(RequestResult::Get(result)) = core.request_state(&host.id, &pending.request_id).unwrap().result
            else { panic!("missing login grant") };
        core.store.get_lease(&result.lease_id).unwrap().unwrap()
    }

    fn proxy_config(core: &Core) -> String {
        std::fs::read_to_string(core.dirs.proxy.join("iron-proxy.yaml")).unwrap()
    }

    #[test]
    fn restart_republishes_login_entries_routes_and_keeps_their_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let mut core = open_login_manager(&tmp);
        let host = request_host(&core);
        let lease = approve_login(&core, &host, 900);
        let expires = lease.expires_at.unwrap();
        // `password` is field 1 of username, password, totp.
        let claims = core.dirs.proxy.join("login-claims");
        let claim = claims.join(format!("{}.1.claim", lease.id));
        let claim_line = format!("claim_file: \"{}\"", claim.display());
        let route = format!("browser_hosts: [{{host: \"the-internet.herokuapp.com\", port: 443, until: {expires}}}]");
        let config = proxy_config(&core);
        assert!(config.contains(&claim_line) && config.contains(&route), "{config}");
        // The proxy claimed the sentinel; another claim belongs to a lease that is gone.
        std::fs::write(&claim, "2026-11-23T00:00:00Z").unwrap();
        let stale = claims.join("deleted-lease.1.claim");
        std::fs::write(&stale, "2026-11-23T00:00:00Z").unwrap();

        core.shutdown();
        drop(core);
        std::fs::remove_file(tmp.path().join("data/proxy/iron-proxy.yaml")).unwrap();
        core = open_login_manager(&tmp);
        assert!(claim.exists(), "the claim of a live lease survives the restart");
        assert!(!stale.exists(), "claims of vanished leases are pruned");
        assert!(proxy_config(&core).contains(&route), "the route is published at start");
        // The test vault is in-memory only, so the lease's values return with it.
        core.sync_proxy(true);
        {
            let proxy = lock(&core.proxy_state);
            assert_eq!(proxy.entries[&lease.id][0].login, Some(LoginBinding {
                port: 443, target: "/authenticate".into(), owner: host.id.clone(),
            }));
        }
        let config = proxy_config(&core);
        assert!(config.contains("login: {port: 443, target: \"/authenticate\"") && config.contains(&claim_line)
            && config.contains(&route), "{config}");
        core.shutdown();
    }

    #[test]
    fn expiry_drops_the_login_entry_and_route() {
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager(&tmp);
        let host = request_host(&core);
        let lease = approve_login(&core, &host, 1);
        assert!(proxy_config(&core).contains("login: {port: 443"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while core.generation_now() < lease.expires_at.unwrap() {
            assert!(std::time::Instant::now() < deadline, "lease did not expire");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(core.login_totp(&host.id, &[1; 32], &lease.id).is_err());
        core.sync_proxy(false);
        {
            let proxy = lock(&core.proxy_state);
            assert!(!proxy.entries.contains_key(&lease.id));
            assert!(proxy.routes.is_empty());
        }
        let config = proxy_config(&core);
        assert!(config.contains("browser_hosts: []") && !config.contains("login: {"), "{config}");
        let sentinel = lease.fields.iter().find_map(|f| f.sentinel.clone()).unwrap();
        assert!(config.contains(&format!("{{proxy_value: \"{sentinel}\", ended: true}}")), "{config}");
        core.shutdown();
    }

    #[test]
    fn totp_updates_are_refused_before_a_popup() {
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager(&tmp);
        let host = request_host(&core);
        let body = serde_json::from_value(json!({
            "kind": "update", "name": "Herokuapp", "field": "totp", "value": "123456",
        })).unwrap();
        assert_eq!(core.create_request(&host, "127.0.0.1", body).unwrap_err().message,
            "totp is generated from the item's authenticator key and cannot be updated");
        assert!(core.snapshot().pending.is_empty());
        core.shutdown();
    }

    #[test]
    fn pairing_updates_proxy_credentials_and_require_auth_toggles_the_auth_file() {
        use asm_proto::crypto::{proxy_password, sha256, sha256_hex};
        let tmp = tempfile::tempdir().unwrap();
        let core = open_login_manager_with(&tmp, &[(crate::settings::PROXY_REQUIRE_AUTH, json!(true))]);
        let path = core.dirs.proxy.join("proxy-auth");
        let auth_line = format!("  auth_file: \"{}\"\n", path.display());
        assert!(proxy_config(&core).contains(&auth_line));
        let line = |id: &str, token: &str| format!("{id}:{}", sha256_hex(proxy_password(&sha256(token.as_bytes()))));
        let lines = || std::fs::read_to_string(&path).unwrap().lines().map(str::to_owned).collect::<Vec<_>>();
        let code = core.create_pairing_code("ci", Some(3600), None, &[]).unwrap().code;
        let code_pair = |previous: Option<asm_proto::wire::PairProof>| {
            let PairResponse::Approved { host_id, token } = core.pair_start(PairRequest {
                client_commit: hex_encode(&client_commit(&new_nonce())),
                host_info: HostInfo { hostname: "code-host".into(), ..Default::default() },
                pairing_code: Some(code.clone()), previous, machine_hint: None,
            }, "127.0.0.1").unwrap() else { panic!("pairing code rejected") };
            (host_id, token)
        };

        let (code_host, code_token) = code_pair(None);
        assert_eq!(lines(), [line(&code_host, &code_token)]);

        let (pair_id, reveal) = start_pair(&core, "approved-host", "127.0.0.1");
        core.pair_reveal(&pair_id, reveal.clone()).unwrap();
        core.resolve_request(&pair_id, ffi::Decision::ApprovePair { name: "approved".into(), replace: false }).unwrap();
        let PairResponse::Approved { host_id, token } = core.pair_poll(&pair_id, &reveal.poll_token).unwrap()
            else { panic!("pairing not approved") };
        assert_eq!(lines(), [line(&code_host, &code_token), line(&host_id, &token)]);

        let (rotated, new_token) = code_pair(Some(asm_proto::wire::PairProof {
            host_id: code_host.clone(), token: code_token.clone(),
        }));
        assert_eq!(rotated, code_host, "the proven host keeps its id");
        assert_eq!(lines(), [line(&code_host, &new_token), line(&host_id, &token)]);

        let mut settings = core.proxy_settings();
        settings.require_auth = false;
        core.set_proxy_settings(settings).unwrap();
        assert!(!crate::settings::Settings::load(&core.store).unwrap().proxy.require_auth);
        let config = proxy_config(&core);
        assert!(!config.contains("auth_file"), "{config}");
        core.shutdown();
    }
}
