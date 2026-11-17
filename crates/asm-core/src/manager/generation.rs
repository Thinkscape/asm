//! Generated grants have durable authority and versions, but never durable token bytes.
//! Lock order is issuance → authorization → short store/cache/proxy/book operations.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use asm_proto::crypto::new_uuid_v4;
use asm_proto::generators::{
    CREDENTIAL_REFRESH_MARGIN_SECS, GenerationGrant, GenerationRequest, GenerationSelection,
    GithubGrant, SourceKind,
};
use asm_proto::rules::{new_sentinel, normalize_host_patterns};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{GetResult, LeaseMode, RequestKind, RequestResult, RequestState, RequestStatus, ResultFile};

use super::activity::{Category, Event};
use super::requests::{Detail, Done, Fail, GeneratedDelivery, GeneratorTarget, GetDetail, GetTarget, Pending, RequestedMode, host_candidates};
use super::{Core, TOPIC_GENERATORS, TOPIC_LEASES, TOPIC_REQUESTS, lock};
use crate::error::{CoreError, Result};
use crate::ffi;
use crate::generator::{GeneratedCredential, GeneratorConfig, GeneratorEntry, GithubAppGenerator};
use crate::store::{GeneratorRecord, HostRecord, LeaseField, LeaseRecord};
use crate::vault::creds;

pub(crate) struct CachedLease {
    pub current: Arc<GeneratedCredential>,
    pub version: u64,
    retired: Vec<Arc<GeneratedCredential>>,
    client: Arc<GithubAppGenerator>,
}

impl CachedLease {
    fn prune(&mut self, now: i64) {
        self.retired.retain(|c| c.expires_at > now);
    }

    fn fresh(&self, now: i64) -> bool {
        self.current.expires_at.saturating_sub(now) > CREDENTIAL_REFRESH_MARGIN_SECS
    }
}

pub(crate) struct Revocation {
    lease_id: String,
    generator_id: String,
    credential: Arc<GeneratedCredential>,
    client: Arc<GithubAppGenerator>,
}

struct RetiredLease {
    tokens: Vec<Arc<GeneratedCredential>>,
    client: Arc<GithubAppGenerator>,
}

pub(crate) struct GenerationState {
    pub cached: HashMap<String, CachedLease>,
    retired_only: HashMap<String, RetiredLease>,
    issuance: HashMap<String, Arc<Mutex<()>>>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    shutting_down: bool,
    shutdown_tokens: Vec<Revocation>,
}

impl GenerationState {
    pub(crate) fn new(clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self { cached: HashMap::new(), retired_only: HashMap::new(), issuance: HashMap::new(), clock,
            shutting_down: false, shutdown_tokens: Vec::new() }
    }

    pub(crate) fn next_expiry(&self, now: i64) -> Option<i64> {
        self.cached.values().filter_map(|c| (c.current.expires_at > now).then_some(c.current.expires_at)).min()
    }

    fn take(&mut self, lease: &LeaseRecord, now: i64) -> Vec<Revocation> {
        self.issuance.remove(&lease.id);
        let mut tokens: Vec<Revocation> = self.cached.remove(&lease.id).map_or_else(Vec::new, |cached| {
            std::iter::once(cached.current).chain(cached.retired)
                .filter(|c| c.expires_at > now)
                .map(|credential| Revocation { lease_id: lease.id.clone(), generator_id: lease.vault_id.clone(),
                    credential, client: cached.client.clone() }).collect()
        });
        if let Some(retired) = self.retired_only.remove(&lease.id) {
            tokens.extend(retired.tokens.into_iter().filter(|c| c.expires_at > now).map(|credential|
                Revocation { lease_id: lease.id.clone(), generator_id: lease.vault_id.clone(),
                    credential, client: retired.client.clone() }));
        }
        tokens
    }
}

fn github(grant: &GenerationGrant) -> &GithubGrant {
    match grant { GenerationGrant::GithubApp(g) => g }
}

fn canonical_name(name: &str) -> Option<String> {
    let (prefix, leaf) = name.rsplit_once('/').map_or((None, name), |(p, l)| (Some(p), l));
    if !matches!(leaf, "GH_TOKEN" | "GITHUB_TOKEN") { return None; }
    Some(prefix.map_or_else(|| "GH_TOKEN".into(), |p| format!("{p}/GH_TOKEN")))
}

fn hosts_cover(lease: &LeaseRecord, requested: &[String]) -> bool {
    lease.mode == LeaseMode::Raw || requested.is_empty() || lease.hosts == ["*"]
        || requested.iter().all(|r| lease.hosts.contains(r))
}

fn accepts_mode(requested: RequestedMode, mode: LeaseMode) -> bool {
    match requested {
        RequestedMode::Default => true,
        RequestedMode::Raw => mode == LeaseMode::Raw,
        RequestedMode::Sentinel => mode == LeaseMode::Sentinel,
    }
}

fn request_compatible(lease: &LeaseRecord, requested: Option<&GenerationRequest>) -> bool {
    requested.is_none() || requested == lease.requested_generation.as_ref()
        || lease.generation.as_ref().is_some_and(|grant| requested.is_some_and(|r| grant.covers_request(r).unwrap_or(false)))
}

impl Core {
    pub(crate) fn generation_now(&self) -> i64 {
        let clock = lock(&self.generation).clock.clone();
        clock()
    }

    fn generator_event(&self, kind: &'static str, lease: &LeaseRecord, status: Option<&str>) {
        self.log(Event::new(Category::Generators, kind, format!("generator {}: {kind}", lease.vault_name))
            .host(Some(&lease.host_id)).secret(&lease.name).detail(serde_json::json!({
                "generator_id": lease.vault_id, "generator_revision": lease.generator_revision,
                "lease_id": lease.id, "grant": lease.generation,
                "expires_at": lease.expires_at.map(fmt_unix),
                "credential_expires_at": lease.credential_expires_at.map(fmt_unix),
                "credential_version": lease.credential_version, "status": status,
            })));
    }

    fn authorized_generator(&self, lease: &LeaseRecord, now: i64) -> Result<GeneratorEntry> {
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        if lease.source_kind != SourceKind::Generator || !lease.is_active(now) {
            return Err(CoreError::invalid("lease ended; request a new lease without --lease"));
        }
        self.store.get_host(&lease.host_id)?.filter(|h| h.revoked_at.is_none())
            .ok_or_else(|| CoreError::unauthorized("host was revoked"))?;
        let entry = self.generators.get(&lease.vault_id)
            .ok_or_else(|| CoreError::vault_unavailable("generator was removed"))?;
        if Some(entry.record.revision) != lease.generator_revision {
            return Err(CoreError::vault_unavailable("generator authorization changed"));
        }
        let GeneratorConfig::GithubApp(config) = &entry.record.config;
        let grant = lease.generation.as_ref().ok_or_else(|| CoreError::vault_unavailable("generated lease has no grant"))?;
        if !github(grant).is_subset_of(&config.ceiling)? {
            return Err(CoreError::vault_unavailable("generator authorization changed"));
        }
        entry.client()?;
        Ok(entry)
    }

    pub(crate) fn create_generated_get(
        &self, host: &HostRecord, agent: &str, address: &str, target: GeneratorTarget,
        mode: RequestedMode, wanted_fields: Vec<String>, requested: Vec<String>, reason: String,
        new_lease: bool, refresh: bool, refresh_from_version: Option<u64>,
    ) -> Result<RequestState> {
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        if !new_lease {
            let latest = self.store.leases_of_host(&host.id)?.into_iter()
                .filter(|l| l.source_kind == SourceKind::Generator && l.agent == agent
                    && accepts_mode(mode, l.mode)
                    && l.name == target.requested_name
                    && target.pinned_generator_id.as_ref().is_none_or(|id| id == &l.vault_id))
                .max_by_key(|l| l.approval_order.unwrap_or(0));
            if let Some(lease) = latest {
                let now = self.generation_now();
                if lease.is_active(now) && hosts_cover(&lease, &requested)
                    && wanted_fields.iter().all(|f| lease.fields.iter().any(|lf| &lf.field == f))
                    && request_compatible(&lease, target.requested_generation.as_ref())
                    && self.generators.get(&lease.vault_id).is_some_and(|g| Some(g.record.revision) == lease.generator_revision) {
                    let result = self.materialize_generated(&lease.id, refresh, refresh_from_version)?;
                    return self.generated_shortcut(host, result);
                }
            }
        }
        let (initial, suggestions) = host_candidates(&requested, &[], &["api.github.com".into()]);
        let detail = GetDetail { target: GetTarget::Generated(target), mode, wanted_fields,
            requested_hosts: requested, reason, initial, suggestions };
        let p = self.new_pending(host, agent, address, Detail::Get(detail.clone()));
        Ok(self.push_pending(p, |q| q.agent == agent && matches!(&q.detail, Detail::Get(g)
            if matches!((&g.target, &detail.target), (GetTarget::Generated(a), GetTarget::Generated(b)) if a == b)
                && g.mode == detail.mode && g.wanted_fields == detail.wanted_fields
                && g.requested_hosts == detail.requested_hosts && g.reason == detail.reason)))
    }

    pub(crate) fn generated_pinned_get(
        &self, host: &HostRecord, _agent: &str, name: &str, id: &str, mode: RequestedMode,
        requested: &[String], fields: Option<&[String]>, generation: Option<&GenerationRequest>,
        refresh: bool, refresh_from_version: Option<u64>, _reason: &str,
    ) -> Result<RequestState> {
        let lease = self.store.get_lease(id)?.filter(|l| l.host_id == host.id)
            .ok_or_else(|| CoreError::not_found("no such lease"))?;
        if lease.source_kind != SourceKind::Generator {
            return Err(CoreError::invalid("--lease requires a generated lease"));
        }
        let requested_name = canonical_name(name).ok_or_else(|| CoreError::invalid("name does not match this lease"))?;
        let current_name = self.generators.get(&lease.vault_id).map(|g| format!("{}/GH_TOKEN", g.record.name));
        if requested_name != lease.name && current_name.as_deref() != Some(&requested_name) {
            return Err(CoreError::invalid("name does not match this lease"));
        }
        if !lease.is_active(self.generation_now()) {
            return Ok(RequestState { request_id: new_uuid_v4(), kind: RequestKind::Get,
                status: RequestStatus::Denied, deny_reason: Some("lease ended; request a new lease without --lease".into()),
                result: None, expires_at: None, pending_lifetime_secs: 0 });
        }
        if !accepts_mode(mode, lease.mode) || !hosts_cover(&lease, requested)
            || fields.is_some_and(|fs| fs.iter().any(|f| !lease.fields.iter().any(|lf| &lf.field == f)))
            || !request_compatible(&lease, generation) {
            return Err(CoreError::invalid("request does not fit this lease"));
        }
        let result = self.materialize_generated(id, refresh, refresh_from_version)?;
        self.generated_shortcut(host, result)
    }

    fn generated_shortcut(&self, host: &HostRecord, result: GetResult) -> Result<RequestState> {
        let authority = lock(&self.authorization);
        let lease_id = result.lease_id.clone();
        let version = result.credential_version.unwrap_or(0);
        let consumed = result.mode == LeaseMode::Raw;
        let metadata = self.with_generated_delivery(&lease_id, version, true, Self::generated_metadata)?;
        let id = new_uuid_v4();
        let retained = RequestState { request_id: id.clone(), kind: RequestKind::Get,
            status: RequestStatus::Approved, deny_reason: None, result: Some(RequestResult::Get(metadata)),
            expires_at: None, pending_lifetime_secs: self.settings().request_lifetime_secs.max(1) };
        let state = RequestState { result: Some(RequestResult::Get(result)), ..retained.clone() };
        lock(&self.book).done.insert(id, Done { host_id: host.id.clone(), state: retained,
            at: self.generation_now(), generated: Some(GeneratedDelivery { lease_id,
                credential_version: version, consumed }) });
        drop(authority);
        Ok(state)
    }

    fn generated_metadata(lease: &LeaseRecord, cached: &CachedLease) -> GetResult {
        GetResult {
            lease_id: lease.id.clone(), mode: lease.mode, hosts: lease.hosts.clone(),
            expires_at: lease.expires_at.map(fmt_unix),
            generation: lease.generation.clone().map(|grant| GenerationSelection {
                generator_id: lease.vault_id.clone(), generator_revision: lease.generator_revision.unwrap_or(0), grant }),
            generator_name: Some(lease.vault_name.clone()),
            credential_expires_at: Some(fmt_unix(cached.current.expires_at)), credential_version: Some(cached.version),
            files: Vec::new(),
        }
    }

    fn generated_result(&self, lease: &LeaseRecord, cached: &CachedLease) -> GetResult {
        let mut result = Self::generated_metadata(lease, cached);
        result.files = lease.fields.iter().map(|f| ResultFile { field: f.field.clone(), relative_path: f.path.clone(),
            substituted: f.sentinel.is_some(), content: f.sentinel.clone().unwrap_or_else(|| cached.current.token.clone()) }).collect();
        result
    }

    pub(crate) fn validate_generated_delivery(&self, id: &str, version: u64) -> Result<GetResult> {
        self.with_generated_delivery(id, version, true, |lease, cached| self.generated_result(lease, cached))
    }

    pub(crate) fn check_generated_delivery(&self, id: &str, version: u64) -> Result<LeaseMode> {
        self.with_generated_delivery(id, version, false, |lease, _| lease.mode)
    }

    fn with_generated_delivery<T>(
        &self, id: &str, version: u64, require_published: bool, deliver: impl FnOnce(&LeaseRecord, &CachedLease) -> T,
    ) -> Result<T> {
        let unavailable = || CoreError::vault_unavailable("generated credential is no longer available; run asm get again");
        let now = self.generation_now();
        let lease = self.store.get_lease(id)?.ok_or_else(unavailable)?;
        self.authorized_generator(&lease, now).map_err(|_| unavailable())?;
        let dirty = require_published && lease.mode == LeaseMode::Sentinel && lock(&self.proxy_state).dirty;
        let generation = lock(&self.generation);
        let cached = generation.cached.get(id).filter(|c| c.version == version
            && lease.credential_version == version && c.current.expires_at > now).ok_or_else(unavailable)?;
        if dirty { return Err(unavailable()); }
        Ok(deliver(&lease, cached))
    }

    fn materialize_generated(&self, id: &str, refresh: bool, refresh_from_version: Option<u64>) -> Result<GetResult> {
        let (issuance, observed) = {
            let _authority = lock(&self.authorization);
            let lease = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            self.authorized_generator(&lease, self.generation_now())?;
            if refresh_from_version.is_some_and(|v| v == 0 || v > lease.credential_version) {
                return Err(CoreError::invalid("refresh version is not an observed credential version"));
            }
            let mut generation = lock(&self.generation);
            let issuance = generation.issuance.entry(id.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))).clone();
            (issuance, refresh_from_version.unwrap_or(lease.credential_version))
        };
        let _issuing = lock(&issuance);
        let (lease, client, force) = {
            let authority = lock(&self.authorization);
            let lease = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            let entry = self.authorized_generator(&lease, self.generation_now())?;
            let now = self.generation_now();
            let force = refresh && lease.credential_version <= observed;
            let mut generation = lock(&self.generation);
            if let Some(cached) = generation.cached.get_mut(id) {
                cached.prune(now);
                if !force && cached.fresh(now) {
                    drop(generation);
                    if lease.mode == LeaseMode::Sentinel {
                        let result = self.publish_proxy_locked(&authority);
                        drop(authority);
                        self.notify_proxy_changed();
                        result?;
                        let _authority = lock(&self.authorization);
                        return self.validate_generated_delivery(id, lease.credential_version);
                    }
                    return self.validate_generated_delivery(id, lease.credential_version);
                }
                if !force && cached.current.expires_at > now && cached.retired.len() >= 2 {
                    return Err(CoreError::rate_limited("too many live generated credentials; wait for an earlier token to expire"));
                }
            }
            (lease, entry.client()?, force)
        };
        let credential = Arc::new(client.issue(github(lease.generation.as_ref().ok_or_else(|| CoreError::vault_unavailable("generated lease has no grant"))?))
            .map_err(|e| { self.generator_event("generation_failed", &lease, Some(&e.message)); CoreError::vault_unavailable(e.message) })?);
        let mut revoke = Vec::new();
        let outcome = (|| {
            let authority = lock(&self.authorization);
            let mut current = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            self.authorized_generator(&current, self.generation_now())?;
            if current.generation != lease.generation || current.credential_version != lease.credential_version {
                return Err(CoreError::vault_unavailable("generator authorization changed during issuance"));
            }
            if credential.expires_at <= self.generation_now() {
                return Err(CoreError::vault_unavailable("GitHub returned an expired credential"));
            }
            let version = self.store.update_generated_credential(id, lease.credential_version, credential.expires_at)?;
            current.credential_version = version;
            current.credential_expires_at = Some(credential.expires_at);
            let mut generation = lock(&self.generation);
            let mut retired = Vec::new();
            if let Some(previous) = generation.retired_only.remove(id) {
                if force {
                    let now = (generation.clock)();
                    revoke.extend(previous.tokens.into_iter().filter(|c| c.expires_at > now)
                        .map(|credential| Revocation { lease_id: id.into(), generator_id: lease.vault_id.clone(),
                            credential, client: previous.client.clone() }));
                } else {
                    retired = previous.tokens;
                }
            }
            if let Some(previous) = generation.cached.remove(id) {
                if force {
                    revoke.extend(std::iter::once(previous.current).chain(previous.retired).filter(|c| c.expires_at > self.generation_now_unlocked(&generation))
                        .map(|c| Revocation { lease_id: id.into(), generator_id: lease.vault_id.clone(), credential: c, client: previous.client.clone() }));
                } else {
                    retired.extend(previous.retired);
                    if previous.current.expires_at > (generation.clock)() { retired.push(previous.current); }
                    retired.retain(|c| c.expires_at > (generation.clock)());
                }
            }
            generation.cached.insert(id.into(), CachedLease { current: credential.clone(), version, retired, client: client.clone() });
            drop(generation);
            self.lease_wake.notify_one();
            let published = if current.mode == LeaseMode::Sentinel {
                self.publish_proxy_locked(&authority)
            } else {
                lock(&self.proxy_state).resume(&current);
                Ok(())
            };
            if published.is_err() {
                lock(&self.proxy_state).suspended.insert(id.into(), "credential publication failed; run asm get to retry".into());
                return Err(CoreError::vault_unavailable("generated credential publication failed; run asm get to retry"));
            }
            let result = self.validate_generated_delivery(id, version)?;
            self.generator_event("refreshed", &current, None);
            Ok(result)
        })();
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        if outcome.is_err() {
            let installed = lock(&self.generation).cached.get(id).is_some_and(|c| Arc::ptr_eq(&c.current, &credential));
            if !installed { revoke.push(Revocation { lease_id: id.into(), generator_id: lease.vault_id.clone(), credential, client }); }
        }
        self.revoke_tokens(revoke, None);
        outcome
    }

    fn generation_now_unlocked(&self, generation: &GenerationState) -> i64 { (generation.clock)() }

    pub(crate) fn approve_generated_get(
        &self, pending: &Pending, detail: &GetDetail, target: &GeneratorTarget, mode: LeaseMode,
        duration: Option<u64>, hosts: Vec<String>, selection: Option<GenerationSelection>,
    ) -> Result<GetResult, Fail> {
        if duration == Some(0) { return Err(CoreError::invalid("generated leases must have a positive duration").into()); }
        let mut selection = selection.ok_or_else(|| CoreError::invalid("choose a GitHub App and grant"))?;
        selection.grant.canonicalize()?;
        let hosts = if mode == LeaseMode::Raw { Vec::new() } else {
            let hosts = normalize_host_patterns(&hosts)?;
            if hosts.is_empty() { return Err(CoreError::invalid("choose at least one host, or Any host").into()); }
            if hosts.iter().any(|h| h == "*") { vec!["*".into()] } else { hosts }
        };
        let (lease, client) = {
            let _authority = lock(&self.authorization);
            self.check_pending_generation(pending, &selection)?;
            let offered = target.candidates.iter().find(|c| c.generator_id == selection.generator_id
                && c.revision == selection.generator_revision).ok_or_else(|| CoreError::invalid("choose one of the offered GitHub Apps"))?;
            let entry = self.generators.get(&selection.generator_id).ok_or_else(|| CoreError::invalid("generator was removed"))?;
            let GeneratorConfig::GithubApp(config) = &entry.record.config;
            if entry.record.revision != selection.generator_revision || !offered.available
                || !github(&selection.grant).is_subset_of(&config.ceiling)? {
                return Err(CoreError::invalid("grant does not fit the selected GitHub App").into());
            }
            let now = self.generation_now();
            let order = self.store.reserve_generator_approval_order()?;
            let lease = LeaseRecord { id: new_uuid_v4(), host_id: pending.host_id.clone().unwrap_or_default(),
                vault_id: entry.record.id.clone(), vault_name: entry.record.name.clone(), secret_key: "token".into(),
                name: canonical_name(&target.requested_name).ok_or_else(|| CoreError::invalid("invalid generated name"))?,
                mode, fields: detail.wanted_fields.iter().map(|field| LeaseField { field: field.clone(),
                    sentinel: (mode == LeaseMode::Sentinel).then(new_sentinel), path: target.requested_name.clone() }).collect(),
                hosts: hosts.clone(), reason: detail.reason.clone(), agent: pending.agent.clone(), created_at: now,
                expires_at: duration.map(|d| now.saturating_add(d.min(i64::MAX as u64) as i64)), revoked_at: None,
                source_kind: SourceKind::Generator, generation: Some(selection.grant.clone()),
                generator_revision: Some(selection.generator_revision), credential_expires_at: None,
                approval_order: Some(order), credential_version: 1, requested_generation: target.requested_generation.clone() };
            (lease, entry.client()?)
        };
        let credential = Arc::new(client.issue(github(&selection.grant)).map_err(|e| {
            self.generator_event("generation_failed", &lease, Some(&e.message));
            Fail::Keep(CoreError::vault_unavailable(e.message))
        })?);
        let mut lease = lease;
        lease.credential_expires_at = Some(credential.expires_at);
        let outcome = (|| -> Result<GetResult> {
            let authority = lock(&self.authorization);
            self.check_pending_generation(pending, &selection)?;
            if !lease.is_active(self.generation_now()) || credential.expires_at <= self.generation_now() {
                return Err(CoreError::vault_unavailable("approval expired during token generation"));
            }
            self.authorized_generator(&lease, self.generation_now())?;
            self.store.insert_lease(&lease)?;
            lock(&self.generation).cached.insert(lease.id.clone(), CachedLease {
                current: credential.clone(), version: 1, retired: Vec::new(), client: client.clone() });
            if mode == LeaseMode::Sentinel && let Err(e) = self.publish_proxy_locked(&authority) {
                let _ = self.store.revoke_lease(&lease.id, self.generation_now());
                lock(&self.generation).cached.remove(&lease.id);
                let mut state = lock(&self.proxy_state);
                state.entries.remove(&lease.id);
                state.suspended.remove(&lease.id);
                state.dirty = true;
                drop(state);
                let _ = self.publish_proxy_locked(&authority);
                return Err(e);
            }
            let result = self.with_generated_delivery(&lease.id, 1, true, Self::generated_metadata)?;
            let mut book = lock(&self.book);
            let index = book.pending.iter().position(|p| p.id == pending.id && p.resolving)
                .ok_or_else(|| CoreError::vault_unavailable("request was cancelled during token generation"))?;
            book.pending.remove(index);
            let mut state = pending.ended_state(RequestStatus::Approved);
            state.result = Some(RequestResult::Get(result.clone()));
            book.done.insert(pending.id.clone(), Done { host_id: lease.host_id.clone(), state,
                at: self.generation_now(), generated: Some(GeneratedDelivery { lease_id: lease.id.clone(), credential_version: 1, consumed: false }) });
            drop(book);
            lock(&self.last_active).insert(lease.id.clone());
            Ok(result)
        })();
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        match outcome {
            Ok(result) => {
                if mode == LeaseMode::Sentinel { let _ = self.store.replace_secret_hosts(&lease.vault_id, "token", &hosts); }
                self.log_lease_created(&lease);
                self.generator_event("issued", &lease, None);
                self.complete_generated_pending(pending, &result);
                Ok(result)
            }
            Err(e) => {
                let mut revoked = Vec::new();
                {
                    let authority = lock(&self.authorization);
                    if self.store.get_lease(&lease.id).ok().flatten().is_some() {
                        if let Err(error) = self.store.revoke_lease(&lease.id, self.generation_now()) {
                            log::error!("failed approval rollback: {}", error.message);
                        }
                        revoked.extend(self.evict_generated_locked(&lease, &authority));
                        let _ = self.publish_proxy_locked(&authority);
                    }
                }
                if !revoked.iter().any(|r| Arc::ptr_eq(&r.credential, &credential)) {
                    revoked.push(Revocation { lease_id: lease.id, generator_id: lease.vault_id, credential, client });
                }
                self.notify_proxy_changed();
                self.revoke_tokens(revoked, None);
                Err(Fail::Keep(e))
            }
        }
    }

    fn check_pending_generation(&self, pending: &Pending, selection: &GenerationSelection) -> Result<()> {
        let now = self.generation_now();
        if lock(&self.generation).shutting_down { return Err(CoreError::vault_unavailable("manager is shutting down")); }
        let book = lock(&self.book);
        let current = book.pending.iter().find(|p| p.id == pending.id && p.host_id == pending.host_id
            && p.resolving && p.expires > now).ok_or_else(|| CoreError::vault_unavailable("request ended during token generation"))?;
        let Detail::Get(GetDetail { target: GetTarget::Generated(target), .. }) = &current.detail else {
            return Err(CoreError::invalid("request no longer offers this generator"));
        };
        if !target.candidates.iter().any(|c| c.generator_id == selection.generator_id && c.revision == selection.generator_revision) {
            return Err(CoreError::invalid("request no longer offers this generator"));
        }
        drop(book);
        self.store.get_host(pending.host_id.as_deref().unwrap_or_default())?.filter(|h| h.revoked_at.is_none())
            .ok_or_else(|| CoreError::unauthorized("host was revoked"))?;
        let entry = self.generators.get(&selection.generator_id).ok_or_else(|| CoreError::invalid("generator was removed"))?;
        let GeneratorConfig::GithubApp(config) = &entry.record.config;
        if entry.record.revision != selection.generator_revision
            || !github(&selection.grant).is_subset_of(&config.ceiling)? {
            return Err(CoreError::invalid("generator authorization changed"));
        }
        Ok(())
    }

    fn complete_generated_pending(&self, pending: &Pending, result: &GetResult) {
        self.log(super::activity::approved(pending, Some(&RequestResult::Get(result.clone())), self.generation_now()));
        if let Err(e) = self.store.insert_history(&pending.history(RequestStatus::Approved, None, self.generation_now())) {
            log::error!("request history: {}", e.message);
        }
        self.bump();
        self.notify(TOPIC_REQUESTS);
    }

    pub(crate) fn evict_generated_locked(&self, lease: &LeaseRecord, _guard: &MutexGuard<'_, ()>) -> Vec<Revocation> {
        let now = self.generation_now();
        let tokens = lock(&self.generation).take(lease, now);
        let mut state = lock(&self.proxy_state);
        state.entries.remove(&lease.id);
        state.suspended.remove(&lease.id);
        state.dirty = true;
        self.lease_wake.notify_one();
        tokens
    }

    pub(crate) fn revoke_tokens(&self, tokens: Vec<Revocation>, deadline: Option<Instant>) {
        for token in tokens {
            let result = match deadline {
                Some(deadline) => deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
                    .ok_or_else(|| CoreError::vault_unavailable("shutdown revocation deadline elapsed"))
                    .and_then(|remaining| token.client.revoke_with_timeout(&token.credential.token, remaining)),
                None => token.client.revoke(&token.credential.token),
            };
            if let Err(e) = result {
                self.log(Event::new(Category::Generators, "revocation_failed", "GitHub token revocation failed")
                    .detail(serde_json::json!({ "lease_id": token.lease_id, "generator_id": token.generator_id,
                        "credential_expires_at": fmt_unix(token.credential.expires_at), "status": e.message })));
            }
        }
    }

    pub(crate) fn sweep_generated_at(&self, now: i64) {
        let mut tokens = Vec::new();
        let mut changed = false;
        let result = (|| -> Result<()> {
            let authority = lock(&self.authorization);
            for lease in self.store.list_leases()?.into_iter().filter(|l| l.source_kind == SourceKind::Generator) {
                let expired = lock(&self.generation).cached.get(&lease.id).is_some_and(|c| c.current.expires_at <= now);
                if !lease.is_active(now) {
                    tokens.extend(self.evict_generated_locked(&lease, &authority));
                } else if expired {
                    let mut generation = lock(&self.generation);
                    if let Some(mut cached) = generation.cached.remove(&lease.id) {
                        cached.prune(now);
                        if !cached.retired.is_empty() {
                            generation.retired_only.insert(lease.id.clone(), RetiredLease {
                                tokens: cached.retired, client: cached.client });
                        }
                    }
                    drop(generation);
                    let mut state = lock(&self.proxy_state);
                    state.dirty |= state.entries.remove(&lease.id).is_some();
                    changed = true;
                    state.suspended.insert(lease.id.clone(), "credential expired; run asm get to refresh".into());
                    self.lease_wake.notify_one();
                } else {
                    let mut generation = lock(&self.generation);
                    if let Some(cached) = generation.cached.get_mut(&lease.id) { cached.prune(now); }
                    if let Some(retired) = generation.retired_only.get_mut(&lease.id) {
                        retired.tokens.retain(|c| c.expires_at > now);
                        if retired.tokens.is_empty() { generation.retired_only.remove(&lease.id); }
                    }
                }
            }
            if lock(&self.proxy_state).dirty { self.publish_proxy_locked(&authority)?; }
            Ok(())
        })();
        if let Err(e) = result { log::error!("generated expiry: {}", e.message); }
        self.notify_proxy_changed();
        if changed { self.notify(TOPIC_LEASES); }
        self.revoke_tokens(tokens, None);
    }

    pub(crate) fn begin_generation_shutdown(&self) {
        let authority = lock(&self.authorization);
        lock(&self.generation).shutting_down = true;
        if let Ok(leases) = self.store.list_leases() {
            let mut tokens = Vec::new();
            for lease in leases.iter().filter(|l| l.source_kind == SourceKind::Generator) {
                tokens.extend(self.evict_generated_locked(lease, &authority));
            }
            lock(&self.generation).shutdown_tokens.extend(tokens);
        }
    }

    pub(crate) fn finish_generation_shutdown(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let queue = Mutex::new(VecDeque::from(std::mem::take(&mut lock(&self.generation).shutdown_tokens)));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let queue = &queue;
                scope.spawn(move || loop {
                    let Some(token) = lock(queue).pop_front() else { break; };
                    self.revoke_tokens(vec![token], Some(deadline));
                });
            }
        });
    }
}

impl Core {
    fn generator_info(&self, entry: &GeneratorEntry, warning: Option<String>) -> ffi::GeneratorInfo {
        ffi::GeneratorInfo { id: entry.record.id.clone(), name: entry.record.name.clone(),
            config: entry.record.config.clone().into(), revision: entry.record.revision,
            status: entry.status().into(), warning }
    }

    pub fn list_generators(&self) -> Vec<ffi::GeneratorInfo> {
        self.generators.entries().iter().map(|entry| self.generator_info(entry, None)).collect()
    }

    pub fn github_connect(&self, draft: ffi::GeneratorDraft) -> Result<ffi::GithubInstallation> {
        let config: GeneratorConfig = draft.config.try_into()?;
        let GeneratorConfig::GithubApp(config) = config;
        let pem = if draft.private_key_pem.is_empty() {
            creds::get(draft.id.as_deref().ok_or_else(|| CoreError::invalid("choose a private key PEM file"))?,
                creds::GITHUB_PRIVATE_KEY)?.ok_or_else(|| CoreError::invalid("choose a private key PEM file"))?
        } else { draft.private_key_pem };
        Ok(GithubAppGenerator::new(&config, &pem)?.connect()?.into())
    }

    pub fn save_generator(&self, draft: ffi::GeneratorDraft) -> Result<ffi::GeneratorInfo> {
        self.save_generator_with(draft,
            |id| creds::get(id, creds::GITHUB_PRIVATE_KEY),
            creds::set_github_private_key,
            |id| creds::delete(id, creds::GITHUB_PRIVATE_KEY))
    }

    fn save_generator_with(
        &self, draft: ffi::GeneratorDraft,
        get_key: impl Fn(&str) -> Result<Option<String>>,
        put_key: impl Fn(&str, &str) -> Result<()>,
        delete_key: impl Fn(&str) -> Result<()>,
    ) -> Result<ffi::GeneratorInfo> {
        let name = draft.name.trim().to_string();
        crate::generator::validate_name(&name)?;
        let mut config: GeneratorConfig = draft.config.try_into()?;
        let GeneratorConfig::GithubApp(github) = &mut config;
        github.ceiling.canonicalize()?;
        config.validate()?;
        let mut tokens = Vec::new();
        let (entry, ended) = {
            let authority = lock(&self.authorization);
            if lock(&self.generation).shutting_down {
                return Err(CoreError::vault_unavailable("manager is shutting down"));
            }
            let previous = match draft.id.as_deref() {
                Some(id) => Some(self.store.get_generator(id)?.ok_or_else(|| CoreError::not_found("no such generator"))?),
                None => None,
            };
            let id = previous.as_ref().map(|r| r.id.clone()).unwrap_or_else(new_uuid_v4);
            let old_pem = get_key(&id)?;
            let key_changed = !draft.private_key_pem.is_empty()
                && old_pem.as_deref() != Some(draft.private_key_pem.as_str());
            let pem = if draft.private_key_pem.is_empty() {
                old_pem.as_deref().ok_or_else(|| CoreError::invalid("choose a private key PEM file"))?
            } else { &draft.private_key_pem };
            let authority_changed = previous.as_ref().is_some_and(|r| r.config != config) || key_changed;
            let reusable = (!authority_changed).then(|| self.generators.get(&id).and_then(|e| e.generator)).flatten();
            let client = match reusable {
                Some(client) => client,
                None => {
                    let GeneratorConfig::GithubApp(github) = &config;
                    Arc::new(GithubAppGenerator::new(github, pem)?)
                }
            };
            let revision = match previous.as_ref() {
                Some(r) if authority_changed => r.revision.checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64).ok_or_else(|| CoreError::invalid("generator revision overflow"))?,
                Some(r) => r.revision,
                None => 1,
            };
            let position = previous.as_ref().map(|r| r.position).unwrap_or(
                self.store.list_generators()?.iter().map(|r| r.position).max().unwrap_or(0).saturating_add(1));
            let record = GeneratorRecord { id: id.clone(), name, config, revision, position };
            if key_changed || previous.is_none() {
                put_key(&id, pem)?;
            }
            if let Err(error) = self.store.upsert_generator(&record) {
                let rollback = if key_changed || previous.is_none() {
                    match old_pem.as_deref() {
                        Some(old) => put_key(&id, old),
                        None => delete_key(&id),
                    }
                } else { Ok(()) };
                if rollback.is_err() && previous.is_some() {
                    self.generators.mark_unavailable(&id, "private key rollback failed; reconnect this generator");
                    for lease in self.store.list_leases()?.into_iter().filter(|l|
                        l.source_kind == SourceKind::Generator && l.vault_id == id) {
                        tokens.extend(self.evict_generated_locked(&lease, &authority));
                    }
                    let _ = self.refresh_generator_candidates_locked(&authority);
                }
                drop(authority);
                self.revoke_tokens(tokens, None);
                self.sync_proxy(false);
                self.notify(TOPIC_GENERATORS);
                self.notify(TOPIC_REQUESTS);
                return Err(error);
            }
            let entry = GeneratorEntry { record, generator: Some(client), unavailable_reason: None };
            self.generators.insert(entry.clone());
            if authority_changed {
                for lease in self.store.list_leases()?.into_iter().filter(|l|
                    l.source_kind == SourceKind::Generator && l.vault_id == id) {
                    if lease.is_active(self.generation_now()) && self.store.revoke_lease(&lease.id, self.generation_now())? {
                        self.log_lease_revoked(&lease, "generator authorization changed");
                    }
                    tokens.extend(self.evict_generated_locked(&lease, &authority));
                }
            }
            let ended = self.refresh_generator_candidates_locked(&authority);
            self.log(Event::new(Category::Generators, if previous.is_some() { "edited" } else { "created" },
                format!("generator {} saved", entry.record.name)).detail(serde_json::json!({
                    "generator_id": id, "name": entry.record.name, "revision": entry.record.revision,
                    "config": entry.record.config,
                })));
            (entry, ended)
        };
        self.revoke_tokens(tokens, None);
        for pending in ended { self.finish(pending, Err(Some("no offered generators remain".into())), self.generation_now(), false); }
        self.sync_proxy(false);
        self.notify(TOPIC_GENERATORS);
        self.notify(TOPIC_REQUESTS);
        self.notify(TOPIC_LEASES);
        let catalog = self.secret_catalog()?;
        let mut qualified = Vec::new();
        for group in &catalog.generated {
            if group.static_collisions.is_empty() { continue; }
            qualified.extend(catalog.static_entries.iter().filter(|s|
                group.static_collisions.contains(&s.meta.name)).map(|s| s.display.clone()));
            for choice in &group.choices {
                qualified.extend(group.static_collisions.iter().map(|name| format!("{}/{name}", choice.name)));
            }
        }
        qualified.sort();
        qualified.dedup();
        let warning = (!qualified.is_empty()).then(|| format!("Secret name collision; use qualified choices: {}", qualified.join(", ")));
        Ok(self.generator_info(&entry, warning))
    }

    pub fn remove_generator(&self, id: &str) -> Result<()> {
        self.remove_generator_with(id, |id| creds::delete(id, creds::GITHUB_PRIVATE_KEY))
    }

    fn remove_generator_with(&self, id: &str, delete_key: impl Fn(&str) -> Result<()>) -> Result<()> {
        let mut tokens = Vec::new();
        let ended = {
            let authority = lock(&self.authorization);
            let record = self.store.get_generator(id)?.ok_or_else(|| CoreError::not_found("no such generator"))?;
            self.store.delete_generator(id)?;
            self.generators.remove(id);
            for lease in self.store.list_leases()?.into_iter().filter(|l|
                l.source_kind == SourceKind::Generator && l.vault_id == id) {
                if lease.is_active(self.generation_now()) && self.store.revoke_lease(&lease.id, self.generation_now())? {
                    self.log_lease_revoked(&lease, "generator removed");
                }
                tokens.extend(self.evict_generated_locked(&lease, &authority));
            }
            let ended = self.refresh_generator_candidates_locked(&authority);
            self.log(Event::new(Category::Generators, "removed", format!("generator {} removed", record.name))
                .detail(serde_json::json!({ "generator_id": id, "name": record.name, "revision": record.revision })));
            ended
        };
        if let Err(e) = delete_key(id) { log::warn!("generator credential cleanup: {}", e.message); }
        self.revoke_tokens(tokens, None);
        for pending in ended { self.finish(pending, Err(Some("no offered generators remain".into())), self.generation_now(), false); }
        self.sync_proxy(false);
        self.notify(TOPIC_GENERATORS);
        self.notify(TOPIC_REQUESTS);
        self.notify(TOPIC_LEASES);
        Ok(())
    }

    fn refresh_generator_candidates_locked(&self, _authority: &MutexGuard<'_, ()>) -> Vec<Pending> {
        let mut book = lock(&self.book);
        for pending in &mut book.pending {
            let Detail::Get(GetDetail { target: GetTarget::Generated(target), .. }) = &mut pending.detail else { continue; };
            target.candidates.retain_mut(|candidate| {
                let Some(entry) = self.generators.get(&candidate.generator_id) else { return false; };
                let GeneratorConfig::GithubApp(config) = &entry.record.config;
                candidate.name = entry.record.name;
                candidate.revision = entry.record.revision;
                candidate.ceiling = GenerationGrant::GithubApp(config.ceiling.clone());
                candidate.available = entry.generator.is_some();
                candidate.unavailable_reason = entry.unavailable_reason;
                true
            });
        }
        let (ended, keep) = std::mem::take(&mut book.pending).into_iter().partition(|p|
            matches!(&p.detail, Detail::Get(GetDetail { target: GetTarget::Generated(target), .. }) if target.candidates.is_empty()));
        book.pending = keep;
        ended
    }

    /// Rust-only isolation seam: configuration remains durable, credentials do not.
    /// Callers inject a real local HTTP client; no provider operation is simulated.
    pub fn install_generator_client(&self, record: GeneratorRecord, client: Arc<GithubAppGenerator>) -> Result<()> {
        record.config.validate()?;
        let authority = lock(&self.authorization);
        if lock(&self.generation).shutting_down { return Err(CoreError::vault_unavailable("manager is shutting down")); }
        if self.store.get_generator(&record.id)?.is_some() {
            return Err(CoreError::exists("generator is already configured"));
        }
        self.store.upsert_generator(&record)?;
        self.generators.insert(GeneratorEntry { record, generator: Some(client), unavailable_reason: None });
        drop(authority);
        self.notify(TOPIC_GENERATORS);
        Ok(())
    }
}

#[cfg(test)]
#[path = "generation_tests.rs"]
mod tests;
