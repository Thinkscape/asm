//! Generated grants and issued credentials survive restart without another provider call.
//! Lock order is issuance → authorization → short store/cache/proxy/book operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use asm_proto::crypto::{new_uuid_v4, sha256};
use asm_proto::generators::{
    CREDENTIAL_REFRESH_MARGIN_SECS, GITHUB_TOKEN_NAME, GcloudAccessGrant,
    GenerationGrant, GenerationRequest, GenerationSelection, GithubGrant, GithubRepository,
    GithubScopeRequest, SourceKind,
};
use asm_proto::names::canonical_generated_output;
use asm_proto::time::fmt_unix;
use asm_proto::wire::{GetResult, LeaseMode, RequestKind, RequestResult, RequestState, RequestStatus, ResultFile};
use serde::{Deserialize, Serialize};

use super::activity::{Category, Event};
use super::gcloud_profiles::ReviewedGcloudProfile;
use super::requests::{Detail, Done, Fail, GeneratedDelivery, GeneratorTarget, GetDetail, GetTarget, Pending, RequestedMode};
use super::resume::SealedResume;
use super::{Core, TOPIC_GENERATORS, TOPIC_LEASES, TOPIC_REQUESTS, lock};
use crate::error::{CoreError, Result};
use crate::ffi;
use crate::generator::gcloud::GCLOUD_SIGN_IN_REQUIRED;
use crate::generator::{GeneratedCredential, GeneratorClient, GeneratorConfig, GeneratorEntry, GithubAppGenerator, RevocationOutcome};
use crate::store::{GeneratorRecord, HostRecord, LeaseField, LeaseRecord};
use crate::vault::creds;

const GENERATED_RESUME: &str = "generated-credentials-v1";

/// One authenticated snapshot per lease. The fingerprint binds all delivery-relevant
/// lease fields; the credential high-water mark is matched separately on restore.
#[derive(Serialize, Deserialize)]
struct SavedCredentials<T> {
    authority: [u8; 32],
    version: u64,
    current: Option<SavedToken<T>>,
    retired: Vec<SavedToken<T>>,
}

#[derive(Serialize, Deserialize)]
struct SavedToken<T> {
    version: u64,
    token: T,
    expires_at: i64,
}

impl<'a> SavedToken<&'a str> {
    fn new(version: u64, credential: &'a GeneratedCredential) -> Self {
        Self { version, token: &credential.token, expires_at: credential.expires_at }
    }
}

impl SavedToken<String> {
    fn into_credential(self) -> Arc<GeneratedCredential> {
        Arc::new(GeneratedCredential { token: self.token, expires_at: self.expires_at })
    }

    fn valid(&self, lease: &LeaseRecord) -> bool {
        self.version > 0 && self.version <= lease.credential_version
            && self.expires_at > 0 && !self.token.is_empty()
            && (self.version != lease.credential_version || Some(self.expires_at) == lease.credential_expires_at)
    }
}

fn lease_authority(lease: &LeaseRecord) -> Result<[u8; 32]> {
    Ok(sha256(serde_json::to_vec(&(
        &lease.id, &lease.host_id, &lease.vault_id, &lease.generator_revision,
        &lease.generation, &lease.requested_generation, lease.mode, &lease.fields, &lease.hosts,
        lease.created_at, lease.expires_at, lease.approval_order,
    ))?))
}

struct RetiredCredential {
    version: u64,
    credential: Arc<GeneratedCredential>,
}

impl RetiredCredential {
    fn saved(&self) -> SavedToken<&str> {
        SavedToken::new(self.version, &self.credential)
    }
}

pub(crate) struct CachedLease {
    pub current: Arc<GeneratedCredential>,
    pub version: u64,
    retired: Vec<RetiredCredential>,
    client: Arc<GeneratorClient>,
}

impl CachedLease {
    fn fresh(&self, now: i64) -> bool {
        self.current.expires_at.saturating_sub(now) > CREDENTIAL_REFRESH_MARGIN_SECS
    }
}

pub(crate) struct Revocation {
    lease_id: String,
    generator_id: String,
    credential: Arc<GeneratedCredential>,
    client: Arc<GeneratorClient>,
}

impl Revocation {
    fn new(lease: &LeaseRecord, credential: Arc<GeneratedCredential>, client: &Arc<GeneratorClient>) -> Self {
        Self { lease_id: lease.id.clone(), generator_id: lease.vault_id.clone(), credential, client: client.clone() }
    }

    fn queue(
        jobs: &mut Vec<Self>, lease: &LeaseRecord, client: &Arc<GeneratorClient>,
        credentials: impl IntoIterator<Item = Arc<GeneratedCredential>>, now: i64,
    ) {
        let gcloud = matches!(client.as_ref(), GeneratorClient::Gcloud(_));
        jobs.extend(credentials.into_iter().filter(|c| gcloud || c.expires_at > now)
            .map(|credential| Self::new(lease, credential, client)));
    }

    fn prune_retired(
        jobs: &mut Vec<Self>, lease: &LeaseRecord, client: &Arc<GeneratorClient>,
        retired: &mut Vec<RetiredCredential>, now: i64,
    ) {
        let gcloud = matches!(client.as_ref(), GeneratorClient::Gcloud(_));
        retired.retain(|r| {
            if r.credential.expires_at > now { return true; }
            if gcloud { jobs.push(Self::new(lease, r.credential.clone(), client)); }
            false
        });
    }
}

struct RetiredLease {
    tokens: Vec<RetiredCredential>,
    client: Arc<GeneratorClient>,
}

pub(crate) struct GenerationState {
    pub cached: HashMap<String, CachedLease>,
    retired_only: HashMap<String, RetiredLease>,
    issuance: HashMap<String, Arc<Mutex<()>>>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub(super) shutting_down: bool,
}

impl GenerationState {
    pub(crate) fn new(clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self { cached: HashMap::new(), retired_only: HashMap::new(), issuance: HashMap::new(), clock,
            shutting_down: false }
    }

    pub(crate) fn next_expiry(&self, now: i64) -> Option<i64> {
        self.cached.values().flat_map(|c| std::iter::once(&c.current)
            .chain(c.retired.iter().map(|r| &r.credential)))
            .chain(self.retired_only.values().flat_map(|r| r.tokens.iter().map(|t| &t.credential)))
            .map(|c| c.expires_at).filter(|&expiry| expiry > now).min()
    }

    fn take(&mut self, lease: &LeaseRecord, now: i64) -> Vec<Revocation> {
        self.issuance.remove(&lease.id);
        let mut tokens = Vec::new();
        if let Some(cached) = self.cached.remove(&lease.id) {
            Revocation::queue(&mut tokens, lease, &cached.client,
                std::iter::once(cached.current).chain(cached.retired.into_iter().map(|r| r.credential)), now);
        }
        if let Some(retired) = self.retired_only.remove(&lease.id) {
            Revocation::queue(&mut tokens, lease, &retired.client, retired.tokens.into_iter().map(|r| r.credential), now);
        }
        tokens
    }
}

fn canonical_name(name: &str) -> Option<String> {
    let (prefix, leaf) = name.rsplit_once('/').map_or((None, name), |(p, l)| (Some(p), l));
    let output = canonical_generated_output(leaf)?;
    Some(prefix.map_or_else(|| output.into(), |p| format!("{p}/{output}")))
}

fn gcloud_grant_uid(grant: &GenerationGrant) -> Option<&str> {
    match grant {
        GenerationGrant::Gcloud(grant) => Some(&grant.service_account_unique_id),
        GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { service_account_unique_id, .. }) =>
            Some(service_account_unique_id),
        _ => None,
    }
}

/// A generated get's validated delivery settings.
#[derive(PartialEq, Eq)]
pub(super) struct GeneratedApproval {
    duration: Option<u64>,
    name: String,
}

impl GeneratedApproval {
    pub(super) fn new(detail: &GetDetail, mode: LeaseMode, duration: Option<u64>, hosts: &[String]) -> Result<Self> {
        let GetTarget::Generated(target) = &detail.target else {
            return Err(CoreError::invalid("request no longer offers this generator"));
        };
        detail.mode.for_new_generated(&detail.requested_hosts)?;
        if mode != LeaseMode::Raw || !hosts.is_empty() {
            return Err(CoreError::invalid("generated credentials require raw delivery without proxy hosts"));
        }
        if duration == Some(0) {
            return Err(CoreError::invalid("generated leases must have a positive duration"));
        }
        let name = canonical_name(&target.requested_name).ok_or_else(|| CoreError::invalid("invalid generated name"))?;
        Ok(Self { duration, name })
    }
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

fn legacy_gcloud_request_compatible(lease: &LeaseRecord, requested: Option<&GenerationRequest>) -> bool {
    let Some(GenerationGrant::Gcloud(grant)) = lease.generation.as_ref() else { return false; };
    match requested {
        None => true,
        // Reuse the grant the operator made, not the scope preference it replaced.
        Some(GenerationRequest::Gcloud(request)) => request.scopes.as_ref() == Some(&grant.scopes),
        _ => false,
    }
}

fn gcloud_access_matches(lease: &LeaseRecord, request: &GenerationRequest) -> bool {
    // The original request documents the decision; only the issued profile
    // can satisfy an explicit fresh request or a pinned renewal.
    matches!((lease.generation.as_ref(), request),
        (Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { access, .. })),
            GenerationRequest::GcloudAccess(requested)) if access == requested)
}

fn explicit_github_scope(request: Option<&GenerationRequest>) -> Result<&GithubScopeRequest> {
    match request {
        Some(GenerationRequest::GithubApp(scope)) if scope.repositories.as_ref().is_some_and(|names| !names.is_empty()) => Ok(scope),
        _ => Err(CoreError::invalid("generated GitHub credentials require an explicit --repositories list of owner/repo names")),
    }
}

fn configured_github_repository<'a>(ceiling: &'a GithubGrant, name: &str) -> Option<&'a GithubRepository> {
    let mut matches = ceiling.repositories.iter().filter(|repo| repo.full_name.trim().eq_ignore_ascii_case(name));
    let repo = matches.next()?;
    matches.next().is_none().then_some(repo)
}

/// Resolve against one installation only. Request syntax has already been canonicalized.
fn resolve_github_grant(scope: &GithubScopeRequest, ceiling: &GithubGrant) -> Option<GithubGrant> {
    let permissions = scope.permissions.as_ref()?;
    if !permissions.iter().all(|(name, level)| ceiling.permissions.get(name).is_some_and(|max| level <= max)) {
        return None;
    }
    let names = scope.repositories.as_ref()?;
    let mut repositories = Vec::with_capacity(names.len());
    for name in names {
        repositories.push(configured_github_repository(ceiling, name)?.clone());
    }
    repositories.sort_unstable_by_key(|repo| repo.id);
    Some(GithubGrant { installation_id: ceiling.installation_id, repositories, permissions: permissions.clone() })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeMatch { Exact, Broader }

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseReuse { StrictOrPinned, Ranked(ScopeMatch) }

/// Resolve every requested repository in one current installation by immutable ID.
fn github_scope_match(scope: &GithubScopeRequest, grant: &GithubGrant, ceiling: &GithubGrant) -> Option<ScopeMatch> {
    let permissions = scope.permissions.as_ref()?;
    let names = scope.repositories.as_ref()?;
    if grant.installation_id != ceiling.installation_id
        || !permissions.iter().all(|(key, level)| grant.permissions.get(key).is_some_and(|issued| issued >= level))
        || !names.iter().all(|name| configured_github_repository(ceiling, name).is_some_and(|repo|
            grant.repositories.binary_search_by_key(&repo.id, |approved| approved.id).is_ok()))
    {
        return None;
    }
    Some(if permissions == &grant.permissions && names.len() == grant.repositories.len() {
        ScopeMatch::Exact
    } else {
        ScopeMatch::Broader
    })
}

/// Rank authorization duration, not the independently renewable provider token.
fn reuse_rank(lease: &LeaseRecord) -> (i64, usize, Option<u64>) {
    let breadth = match lease.generation.as_ref() {
        Some(GenerationGrant::GithubApp(grant)) => grant.repositories.len()
            * grant.permissions.values().map(|level| match level {
                asm_proto::generators::GithubPermission::Read => 1,
                asm_proto::generators::GithubPermission::Write => 2,
                asm_proto::generators::GithubPermission::Admin => 3,
            }).sum::<usize>(),
        Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { access, .. })) => access.permissions.len(),
        Some(GenerationGrant::Gcloud(grant)) => grant.scopes.len(),
        _ => 0,
    };
    (lease.expires_at.unwrap_or(i64::MAX), breadth, lease.approval_order)
}

fn same_generated_get(left: &GeneratorTarget, right: &GeneratorTarget) -> bool {
    if left.operator_selected_grant != right.operator_selected_grant
        || left.operator_selected_gcloud_project != right.operator_selected_gcloud_project
    {
        return false;
    }
    if left.output_name == right.output_name && (left.output_name == GITHUB_TOKEN_NAME
        || matches!(&left.requested_generation, Some(GenerationRequest::GcloudAccess(_)))) {
        // Catalog edits can add choices, but cannot create a parallel approval
        // for the same request while an already offered choice is being issued.
        left.pinned_generator_id == right.pinned_generator_id
            && (left.pinned_generator_id.is_some() || left.requested_name == right.requested_name)
            && left.requested_generation == right.requested_generation
    } else {
        left == right
    }
}

impl Core {
    pub(crate) fn generation_now(&self) -> i64 {
        let clock = lock(&self.generation).clock.clone();
        clock()
    }

    /// Rebind the authenticated snapshots to today's local authority. Startup
    /// publishes the resulting sentinel entries together with the static ones.
    pub(super) fn restore_generated(&self) -> Result<()> {
        let _authority = lock(&self.authorization);
        let now = self.generation_now();
        for (id, mut saved) in self.resume.list::<SavedCredentials<String>>(GENERATED_RESUME)? {
            let Some(lease) = self.store.get_lease(&id)? else {
                self.resume.remove(GENERATED_RESUME, &id)?;
                continue;
            };
            let valid = saved.authority == lease_authority(&lease)?
                && saved.version == lease.credential_version
                && saved.current.as_ref().is_none_or(|c| c.version == saved.version && c.valid(&lease))
                && saved.retired.iter().all(|r| r.valid(&lease)
                    && (saved.current.is_none() || r.version < saved.version))
                && saved.retired.windows(2).all(|rs| rs[0].version < rs[1].version);
            if !valid {
                self.resume.remove(GENERATED_RESUME, &id)?;
                continue;
            }
            let client = match self.with_generator_authority(&lease, now, |entry| Ok(
                entry.generator.as_ref().filter(|client| client.matches_config(&entry.record.config)).cloned()
            )) {
                Ok(client) => client,
                Err(e) if e.code == asm_proto::ErrorCode::Internal => return Err(e),
                Err(_) => {
                    self.resume.remove(GENERATED_RESUME, &id)?;
                    continue;
                }
            };

            let current_expired = saved.current.as_ref().is_some_and(|c| c.expires_at <= now);
            if current_expired { saved.current = None; }
            let before = saved.retired.len();
            saved.retired.retain(|r| r.expires_at > now);
            if saved.current.is_none() && saved.retired.is_empty() {
                self.resume.remove(GENERATED_RESUME, &id)?;
                continue;
            }
            if current_expired || saved.retired.len() != before {
                self.resume.put(GENERATED_RESUME, &id, &saved)?;
            }
            // A temporary client/keychain error is not an authority revocation.
            // Keep the still-live snapshot but never publish it without a client.
            let Some(client) = client else { continue; };
            let retired = saved.retired.into_iter().map(|token| RetiredCredential {
                version: token.version, credential: token.into_credential(),
            }).collect();
            let mut generation = lock(&self.generation);
            if let Some(current) = saved.current {
                generation.cached.insert(id, CachedLease {
                    current: current.into_credential(), version: saved.version, retired, client,
                });
            } else {
                generation.retired_only.insert(id, RetiredLease { tokens: retired, client });
            }
        }
        Ok(())
    }

    fn seal_generated<'a>(
        &self, lease: &LeaseRecord, current: SavedToken<&'a str>,
        retired: impl Iterator<Item = SavedToken<&'a str>>,
    ) -> Result<SealedResume> {
        self.resume.seal(GENERATED_RESUME, &lease.id, &SavedCredentials {
            authority: lease_authority(lease)?, version: lease.credential_version,
            current: Some(current), retired: retired.collect(),
        })
    }

    /// Persist expiry/suspension changes before another process can restore this cache.
    fn persist_pruned_generated(&self, lease: &LeaseRecord, generation: &GenerationState) -> Result<()> {
        let (current, retired) = if let Some(cached) = generation.cached.get(&lease.id) {
            (Some(SavedToken::new(cached.version, &cached.current)), cached.retired.as_slice())
        } else if let Some(retired) = generation.retired_only.get(&lease.id) {
            (None, retired.tokens.as_slice())
        } else {
            return self.resume.remove(GENERATED_RESUME, &lease.id);
        };
        self.resume.put(GENERATED_RESUME, &lease.id, &SavedCredentials {
            authority: lease_authority(lease)?, version: lease.credential_version,
            current, retired: retired.iter().map(RetiredCredential::saved).collect(),
        })
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

    fn authorized_generator(&self, lease: &LeaseRecord, now: i64) -> Result<Arc<GeneratorClient>> {
        self.with_generator_authority(lease, now, GeneratorEntry::client)
    }

    fn with_generator_authority<T>(
        &self, lease: &LeaseRecord, now: i64, select: impl FnOnce(&GeneratorEntry) -> Result<T>,
    ) -> Result<T> {
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        if lease.source_kind != SourceKind::Generator || !lease.is_active(now) {
            return Err(CoreError::invalid("lease ended; request a new lease without --lease"));
        }
        self.store.get_host(&lease.host_id)?.filter(|h| h.revoked_at.is_none())
            .ok_or_else(|| CoreError::unauthorized("host was revoked"))?;
        let grant = lease.generation.as_ref().ok_or_else(|| CoreError::vault_unavailable("generated lease has no grant"))?;
        if let GenerationGrant::GcloudAccess(grant) = grant {
            let GcloudAccessGrant::Issued { access, .. } = grant else {
                return Err(CoreError::vault_unavailable("generated lease has no issued grant"));
            };
            // Release the registry read lock before checking durable authority.
            let entry = self.generators.get(&lease.vault_id)
                .ok_or_else(|| CoreError::vault_unavailable("generator was removed"))?;
            if Some(entry.record.revision) != lease.generator_revision
                || !matches!(lease.requested_generation.as_ref(), Some(GenerationRequest::GcloudAccess(_)))
                || !matches!(&entry.record.config, GeneratorConfig::GcloudConnection(_))
                || self.ready_gcloud_access_locked(&entry.record, access)? != *grant
            {
                return Err(CoreError::vault_unavailable("Google Cloud access profile authorization changed"));
            }
            return select(&entry);
        }
        if let Some(uid) = gcloud_grant_uid(grant) {
            self.check_gcloud_account_not_retired(uid)?;
        }
        self.generators.with_entry(&lease.vault_id, |entry| {
            if Some(entry.record.revision) != lease.generator_revision || !entry.record.config.accepts_grant(grant)? {
                return Err(CoreError::vault_unavailable("generator authorization changed"));
            }
            select(entry)
        }).ok_or_else(|| CoreError::vault_unavailable("generator was removed"))?
    }

    fn issue_for_lease(
        &self, lease: &LeaseRecord, client: &Arc<GeneratorClient>, before_google_issue: impl FnOnce() -> Result<()>,
    ) -> Result<GeneratedCredential> {
        let grant = lease.generation.as_ref()
            .ok_or_else(|| CoreError::vault_unavailable("generated lease has no grant"))?;
        let issue = || {
            if let GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
                access, service_account_unique_id, service_account_email,
            }) = grant {
                let entry = self.generators.get(&lease.vault_id)
                    .ok_or_else(|| CoreError::vault_unavailable("generator was removed"))?;
                if Some(entry.record.revision) != lease.generator_revision || !Arc::ptr_eq(&entry.client()?, client) {
                    return Err(CoreError::vault_unavailable("generator authorization changed"));
                }
                let GeneratorConfig::GcloudConnection(config) = &entry.record.config else {
                    return Err(CoreError::vault_unavailable("generator authorization changed"));
                };
                self.with_gcloud_connection_parent(&entry, |http, token, identity| {
                    if identity.subject != config.account_subject || identity.email != config.account_email {
                        return Err(CoreError::unauthorized(GCLOUD_SIGN_IN_REQUIRED));
                    }
                    http.verify_profile_ready(token, access, service_account_unique_id, service_account_email, identity)
                })?;
            }
            let _flight = if let Some(uid) = gcloud_grant_uid(grant) {
                let _authority = lock(&self.authorization);
                let live = self.authorized_generator(lease, self.generation_now())?;
                if !Arc::ptr_eq(&live, client) {
                    return Err(CoreError::vault_unavailable("generator authorization changed"));
                }
                before_google_issue()?;
                Some(self.gcloud_profiles.start_mint(uid)?)
            } else {
                None
            };
            client.issue(grant)
        };
        issue().map_err(|e| {
            if matches!(client.as_ref(), GeneratorClient::Gcloud(_)) && e.code == asm_proto::ErrorCode::Unauthorized
                && let Some(revision) = lease.generator_revision {
                self.mark_gcloud_sign_in_required(&lease.vault_id, revision, client);
            }
            self.generator_event("generation_failed", lease, Some(&e.message));
            CoreError::vault_unavailable(e.message)
        })
    }

    /// Caller holds authorization from candidate reconciliation through selection.
    fn select_generated_lease(
        &self, host: &HostRecord, agent: &str, target: &GeneratorTarget, fields: &[String], supports_broader: bool,
    ) -> Result<Option<(LeaseRecord, LeaseReuse)>> {
        let Some(request) = &target.requested_generation else { return Ok(None); };
        let now = self.generation_now();
        let mut latest_strict = None;
        let mut best = None;
        let mut best_rank = None;
        for lease in self.store.generated_reuse_candidates(&host.id, &target.requested_name)? {
            if target.pinned_generator_id.as_ref().is_some_and(|id| id != &lease.vault_id) {
                continue;
            }
            let Some(grant) = &lease.generation else { continue; };
            let relaxed = supports_broader && self.generators.with_entry(&lease.vault_id,
                |entry| !entry.record.require_exact_scope_match) == Some(true);
            if !relaxed && lease.agent != agent { continue; }
            let active = lease.is_active(now) && fields.iter().all(|f| lease.fields.iter().any(|lf| &lf.field == f));
            if relaxed && !active { continue; }
            let choice = target.candidates.iter().find(|choice| choice.generator_id == lease.vault_id
                && match (grant, &choice.ceiling) {
                    (GenerationGrant::GithubApp(g), GenerationGrant::GithubApp(c)) => g.installation_id == c.installation_id,
                    (GenerationGrant::Gcloud(_), GenerationGrant::Gcloud(_))
                    | (GenerationGrant::GcloudAccess(_), GenerationGrant::GcloudAccess(_)) => true,
                    _ => false,
                });
            let current = choice.is_some_and(|c| Some(c.revision) == lease.generator_revision);
            if relaxed && !current { continue; }
            let scope = match (grant, request) {
                (GenerationGrant::GithubApp(g), GenerationRequest::GithubApp(r)) => choice.and_then(|c| {
                    let GenerationGrant::GithubApp(ceiling) = &c.ceiling else { return None; };
                    github_scope_match(r, g, ceiling)
                }),
                (GenerationGrant::Gcloud(g), GenerationRequest::Gcloud(r)) if r.scopes.as_ref() == Some(&g.scopes) =>
                    Some(ScopeMatch::Exact),
                (GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { access, .. }), GenerationRequest::GcloudAccess(r))
                    if r == access => Some(ScopeMatch::Exact),
                _ if relaxed && grant.covers_lease_reuse_request(request)? => Some(ScopeMatch::Broader),
                _ => None,
            };
            if !relaxed {
                // Strict mode preserves the newest relevant decision, including ended leases.
                // Request history can block an older approval but cannot authorize delivery.
                let relevant = scope == Some(ScopeMatch::Exact) || match request {
                    GenerationRequest::GithubApp(_) => lease.requested_generation.as_ref() == Some(request),
                    GenerationRequest::Gcloud(_) => matches!(grant, GenerationGrant::Gcloud(_)),
                    GenerationRequest::GcloudAccess(_) => false,
                };
                if relevant && latest_strict.as_ref().is_none_or(|(order, _)| lease.approval_order > *order) {
                    let exact = active && current && scope == Some(ScopeMatch::Exact);
                    latest_strict = Some((lease.approval_order, exact.then_some(lease)));
                }
                continue;
            }
            let Some(scope) = scope else { continue; };
            let rank = reuse_rank(&lease);
            if best_rank.is_some_and(|best| rank <= best) { continue; }
            // In particular, a still-unexpired managed lease can have lost its Ready IAM profile.
            match self.authorized_generator(&lease, now) {
                Ok(_) => {}
                Err(e) if e.code == asm_proto::ErrorCode::VaultUnavailable => continue,
                Err(e) => return Err(e),
            }
            best_rank = Some(rank);
            best = Some((lease, LeaseReuse::Ranked(scope)));
        }
        if let Some((_, Some(lease))) = latest_strict
            && best_rank.is_none_or(|rank| reuse_rank(&lease) > rank)
        {
            return Ok(Some((lease, LeaseReuse::StrictOrPinned)));
        }
        Ok(best)
    }

    pub(crate) fn create_generated_get(
        &self, host: &HostRecord, agent: &str, address: &str, mut target: GeneratorTarget,
        mode: RequestedMode, wanted_fields: Vec<String>, requested: Vec<String>, reason: String,
        new_lease: bool, refresh: bool, refresh_from_version: Option<u64>, supports_broader: bool,
    ) -> Result<RequestState> {
        let mode = mode.for_new_generated(&requested)?;
        // Serialize the reuse decision and pending insertion with approval commit.
        let authority = lock(&self.authorization);
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        let github = target.output_name == GITHUB_TOKEN_NAME;
        let managed = matches!(&target.requested_generation, Some(GenerationRequest::GcloudAccess(_)));
        if github {
            explicit_github_scope(target.requested_generation.as_ref())?;
        } else if !managed
            && !matches!(target.requested_generation.as_ref(), Some(GenerationRequest::Gcloud(scope))
                if scope.scopes.as_ref().is_some_and(|scopes| !scopes.is_empty()))
        {
            return Err(CoreError::invalid(
                "Google Cloud connections require --project ID and --permissions; use --gcloud-scope explicitly for legacy generators",
            ));
        }
        self.reconcile_generator_target(&mut target, false);
        if target.candidates.is_empty() {
            let message = if github && target.operator_selected_grant {
                "no configured GitHub App installation covers any requested repository; check the owner/repo names and generator access"
            } else if github {
                "no single configured GitHub App installation covers the requested repositories and permissions; \
                 check the owner/repo names and generator access, split the repositories by installation, or lower --permissions"
            } else if managed {
                "no matching Google Cloud connection for the requested output"
            } else {
                "Google Cloud connections require explicit --project ID and --permissions; --gcloud-scope is legacy only"
            };
            return Err(CoreError::invalid(message));
        }
        if !new_lease && let Some((lease, reuse)) =
            self.select_generated_lease(host, agent, &target, &wanted_fields, supports_broader)?
        {
            drop(authority);
            let result = self.materialize_generated(&lease.id, refresh, refresh_from_version)?;
            let state = self.generated_shortcut(host, result, reuse)?;
            if reuse == LeaseReuse::Ranked(ScopeMatch::Broader) {
                self.log(Event::new(Category::Generators, "broader_lease_reused",
                    format!("Reused {} lease with broader access than requested", lease.name))
                    .host(Some(&host.id)).secret(&lease.name).detail(serde_json::json!({
                        "request_id": state.request_id, "agent": agent, "generator_id": lease.vault_id,
                        "lease_id": lease.id, "requested": target.requested_generation, "grant": lease.generation,
                    })));
            }
            return Ok(state);
        }
        let detail = GetDetail { target: GetTarget::Generated(target), mode, wanted_fields,
            requested_hosts: requested, reason, initial: Vec::new(), suggestions: Vec::new(), login: None };
        let p = self.new_pending(host, agent, address, Detail::Get(detail));
        let (state, inserted) = self.attach_pending(p, |q, p| q.agent == agent
            && matches!((&q.detail, &p.detail), (Detail::Get(g), Detail::Get(detail))
                if matches!((&g.target, &detail.target), (GetTarget::Generated(a), GetTarget::Generated(b)) if same_generated_get(a, b))
                    && g.mode == detail.mode && g.wanted_fields == detail.wanted_fields
                    && g.requested_hosts == detail.requested_hosts && g.reason == detail.reason))?;
        drop(authority);
        if inserted {
            self.bump();
            self.notify(TOPIC_REQUESTS);
        }
        Ok(state)
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
        if requested_name != lease.name && self.generators.with_entry(&lease.vault_id, |g| {
            requested_name.rsplit_once('/') == Some((g.record.name.as_str(), g.record.config.output_name()))
        }) != Some(true) {
            return Err(CoreError::invalid("name does not match this lease"));
        }
        let provider_matches = match (lease.generation.as_ref(), generation) {
            (Some(GenerationGrant::GithubApp(_)), None | Some(GenerationRequest::GithubApp(_))) => true,
            (Some(GenerationGrant::Gcloud(_)), None | Some(GenerationRequest::Gcloud(_))) => true,
            (Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { .. })), Some(GenerationRequest::GcloudAccess(_))) => true,
            (Some(GenerationGrant::GcloudAccess(_)), None) =>
                return Err(CoreError::invalid("this Google Cloud lease requires its exact --project ID and --permissions")),
            _ => false,
        };
        if !provider_matches {
            return Err(CoreError::invalid("the requested scope type does not match this lease"));
        }
        if !lease.is_active(self.generation_now()) {
            return Ok(RequestState { request_id: new_uuid_v4(), kind: RequestKind::Get,
                status: RequestStatus::Denied, deny_reason: Some("lease ended; request a new lease without --lease".into()),
                result: None, expires_at: None, pending_lifetime_secs: 0 });
        }
        let scope_matches = match (lease.generation.as_ref(), generation) {
            (Some(GenerationGrant::GithubApp(grant)), Some(request)) => {
                let scope = explicit_github_scope(Some(request))?;
                self.generators.with_entry(&lease.vault_id, |entry| {
                    let GeneratorConfig::GithubApp(config) = &entry.record.config else { return false; };
                    let Some(ceiling) = config.ceiling(grant.installation_id) else { return false; };
                    github_scope_match(scope, grant, ceiling) == Some(ScopeMatch::Exact)
                }) == Some(true)
            }
            (Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { .. })), Some(request)) =>
                gcloud_access_matches(&lease, request),
            (Some(GenerationGrant::Gcloud(_)), _) => legacy_gcloud_request_compatible(&lease, generation),
            (Some(GenerationGrant::GithubApp(_)), None) => true,
            _ => false,
        };
        if !accepts_mode(mode, lease.mode) || !hosts_cover(&lease, requested)
            || fields.is_some_and(|fs| fs.iter().any(|f| !lease.fields.iter().any(|lf| &lf.field == f)))
            || !scope_matches {
            return Err(CoreError::invalid("request does not fit this lease"));
        }
        let result = self.materialize_generated(id, refresh, refresh_from_version)?;
        self.generated_shortcut(host, result, LeaseReuse::StrictOrPinned)
    }

    fn generated_shortcut(&self, host: &HostRecord, mut result: GetResult, reuse: LeaseReuse) -> Result<RequestState> {
        let authority = lock(&self.authorization);
        if let LeaseReuse::Ranked(scope) = reuse {
            // Materialization releases authorization while renewing. Respect a policy change before delivery.
            if !result.generation.as_ref().is_some_and(|g| self.generators.with_entry(&g.generator_id,
                |entry| !entry.record.require_exact_scope_match) == Some(true))
            {
                return Err(CoreError::invalid("generator lease reuse policy changed; request the token again"));
            }
            result.broader_lease_reuse = scope == ScopeMatch::Broader;
        }
        let lease_id = result.lease_id.clone();
        let version = result.credential_version.unwrap_or(0);
        let consumed = result.mode == LeaseMode::Raw;
        let mut metadata = self.with_generated_delivery(&lease_id, version, true, Self::generated_metadata)?;
        metadata.broader_lease_reuse = result.broader_lease_reuse;
        let id = new_uuid_v4();
        let retained = RequestState { request_id: id.clone(), kind: RequestKind::Get,
            status: RequestStatus::Approved, deny_reason: None, result: Some(RequestResult::Get(metadata)),
            expires_at: None, pending_lifetime_secs: self.settings().request_lifetime_secs.max(1) };
        let state = RequestState { result: Some(RequestResult::Get(result)), ..retained.clone() };
        self.insert_done_locked(&mut lock(&self.book), id, Done { host_id: host.id.clone(), state: retained,
            at: self.generation_now(), generated: Some(GeneratedDelivery { lease_id,
                credential_version: version, consumed, operator_selected_grant: false }) }, None)?;
        drop(authority);
        Ok(state)
    }

    fn generated_metadata(lease: &LeaseRecord, cached: &CachedLease) -> GetResult {
        GetResult {
            lease_id: lease.id.clone(), mode: lease.mode, hosts: lease.hosts.clone(),
            expires_at: lease.expires_at.map(fmt_unix),
            generation: lease.generation.clone().map(|grant| GenerationSelection {
                generator_id: lease.vault_id.clone(), generator_revision: lease.generator_revision.unwrap_or(0), grant }),
            operator_selected_grant: false,
            broader_lease_reuse: false,
            generator_name: Some(lease.vault_name.clone()),
            credential_expires_at: Some(fmt_unix(cached.current.expires_at)), credential_version: Some(cached.version),
            files: Vec::new(),
            login: None,
        }
    }

    fn generated_result(&self, lease: &LeaseRecord, cached: &CachedLease) -> GetResult {
        let mut result = Self::generated_metadata(lease, cached);
        result.files = lease.fields.iter().map(|f| ResultFile { field: f.field.clone(), relative_path: f.path.clone(),
            substituted: Some(f.sentinel.is_some()), content: f.sentinel.clone().unwrap_or_else(|| cached.current.token.clone()) }).collect();
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
        let client = self.authorized_generator(&lease, now).map_err(|_| unavailable())?;
        let dirty = require_published && lease.mode == LeaseMode::Sentinel && lock(&self.proxy_state).dirty;
        let generation = lock(&self.generation);
        let cached = generation.cached.get(id).filter(|c| Arc::ptr_eq(&c.client, &client)
            && c.version == version && lease.credential_version == version && c.current.expires_at > now
            && lease.credential_expires_at == Some(c.current.expires_at)).ok_or_else(unavailable)?;
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
        let (lease, client, recall) = {
            let authority = lock(&self.authorization);
            let lease = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            let now = self.generation_now();
            let client = self.authorized_generator(&lease, now)?;
            let force = refresh && lease.credential_version <= observed;
            let generation = lock(&self.generation);
            if let Some(cached) = generation.cached.get(id) {
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
            }
            // A forced Google refresh cannot recall predecessors, so it
            // cannot bypass the same live-credential limit as ordinary renewal.
            let recall = force && matches!(client.as_ref(), GeneratorClient::GithubApp(_));
            if !recall {
                let live_tokens = if let Some(cached) = generation.cached.get(id) {
                    usize::from(cached.current.expires_at > now)
                        + cached.retired.iter().filter(|r| r.credential.expires_at > now).count()
                } else {
                    generation.retired_only.get(id).map_or(0, |r|
                        r.tokens.iter().filter(|t| t.credential.expires_at > now).count())
                };
                if live_tokens >= 3 {
                    return Err(CoreError::rate_limited("too many live generated credentials; wait for an earlier token to expire"));
                }
            }
            (lease, client, recall)
        };
        let credential = match self.issue_for_lease(&lease, &client, || {
            let live = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            if live != lease {
                return Err(CoreError::vault_unavailable("lease changed during issuance"));
            }
            Ok(())
        }) {
            Ok(credential) => Arc::new(credential),
            Err(error) => {
                if matches!(lease.generation.as_ref(), Some(GenerationGrant::GcloudAccess(_))) {
                    self.suspend_managed_renewal(&lease, &client);
                }
                return Err(error);
            }
        };
        let mut revoke = Vec::new();
        let mut installed = false;
        let outcome = (|| {
            let authority = lock(&self.authorization);
            let mut current = self.store.get_lease(id)?.ok_or_else(|| CoreError::not_found("no such lease"))?;
            let live = self.authorized_generator(&current, self.generation_now())?;
            if !Arc::ptr_eq(&live, &client)
                || current.generation != lease.generation || current.credential_version != lease.credential_version {
                return Err(CoreError::vault_unavailable("generator authorization changed during issuance"));
            }
            let now = self.generation_now();
            if credential.expires_at <= now {
                return Err(CoreError::vault_unavailable("provider returned an expired credential"));
            }
            let version = lease.credential_version.checked_add(1)
                .ok_or_else(|| CoreError::internal("credential version exhausted"))?;
            current.credential_version = version;
            current.credential_expires_at = Some(credential.expires_at);
            let saved = {
                let generation = lock(&self.generation);
                let cached = generation.cached.get(id).filter(|_| !recall);
                let retired = cached.map(|c| c.retired.as_slice()).or_else(||
                    generation.retired_only.get(id).filter(|_| !recall).map(|r| r.tokens.as_slice()))
                    .unwrap_or_default();
                self.seal_generated(&current, SavedToken::new(version, &credential),
                    retired.iter().filter(|r| r.credential.expires_at > now).map(RetiredCredential::saved)
                        .chain(cached.filter(|c| c.current.expires_at > now)
                            .map(|c| SavedToken::new(c.version, &c.current))))?
            };
            self.store.update_generated_credential_with_resume(
                id, lease.credential_version, credential.expires_at, &[saved],
            )?;
            let mut generation = lock(&self.generation);
            let mut retired = Vec::new();
            if let Some(previous) = generation.retired_only.remove(id) {
                if recall {
                    Revocation::queue(&mut revoke, &lease, &previous.client,
                        previous.tokens.into_iter().map(|r| r.credential), now);
                } else {
                    retired = previous.tokens;
                }
            }
            if let Some(previous) = generation.cached.remove(id) {
                if recall {
                    Revocation::queue(&mut revoke, &lease, &previous.client,
                        std::iter::once(previous.current).chain(previous.retired.into_iter().map(|r| r.credential)), now);
                } else {
                    retired.extend(previous.retired);
                    if matches!(client.as_ref(), GeneratorClient::Gcloud(_)) {
                        revoke.push(Revocation::new(&lease, previous.current.clone(), &client));
                    }
                    if previous.current.expires_at > now {
                        retired.push(RetiredCredential { version: previous.version, credential: previous.current });
                    }
                }
            }
            Revocation::prune_retired(&mut revoke, &lease, &client, &mut retired, now);
            generation.cached.insert(id.into(), CachedLease { current: credential.clone(), version, retired, client: client.clone() });
            installed = true;
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
        if outcome.is_err() && !installed {
            revoke.push(Revocation::new(&lease, credential, &client));
        }
        self.revoke_tokens(revoke);
        outcome
    }

    pub(super) fn approve_generated_get(
        &self, pending: &Pending, detail: &GetDetail, approval: GeneratedApproval,
        selection: GenerationSelection, reviewed: Option<&ReviewedGcloudProfile<'_>>,
    ) -> Result<GetResult, Fail> {
        let GetTarget::Generated(target) = &detail.target else {
            return Err(CoreError::invalid("request no longer offers this generator").into());
        };
        let GenerationSelection { generator_id, generator_revision, grant: selector } = selection;
        let GeneratedApproval { duration, name } = approval;
        // All callers hold authorization. An IAM review additionally pins
        // the reviewed client, IAM account and plan expiry at each issuance gate.
        let check_pending = |selector: &GenerationGrant| -> Result<_> {
            let (entry, issued) = self.check_pending_generation(pending, &generator_id, generator_revision, selector, reviewed.is_some())?;
            if let Some(review) = reviewed {
                review.check(self, pending, &entry, issued.as_ref())?;
            }
            Ok((entry, issued))
        };
        let (lease, client, managed_selector) = {
            let _authority = lock(&self.authorization);
            let (entry, issued) = check_pending(&selector)?;
            let (mut grant, managed_selector) = match issued {
                Some(issued) => (GenerationGrant::GcloudAccess(issued), Some(selector)),
                None => (selector, None),
            };
            match (&mut grant, &entry.record.config) {
                (GenerationGrant::Gcloud(grant), GeneratorConfig::Gcloud(config)) => {
                    grant.project_id.get_or_insert_with(|| config.project_id.clone());
                    grant.service_account_email.clone_from(&config.ceiling.service_account_email);
                }
                (GenerationGrant::GithubApp(grant), GeneratorConfig::GithubApp(config)) => {
                    let ceiling = config.ceiling(grant.installation_id)
                        .ok_or_else(|| CoreError::invalid("GitHub installation authorization changed"))?;
                    // Approval supplies IDs; only verified configuration supplies display names.
                    for repo in &mut grant.repositories {
                        let index = ceiling.repositories.binary_search_by_key(&repo.id, |r| r.id)
                            .map_err(|_| CoreError::invalid("GitHub repository authorization changed"))?;
                        repo.full_name.clone_from(&ceiling.repositories[index].full_name);
                    }
                }
                (GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { .. }), GeneratorConfig::GcloudConnection(_)) => {}
                _ => return Err(CoreError::invalid("generator authorization changed").into()),
            }
            let now = self.generation_now();
            let order = self.store.reserve_generator_approval_order()?;
            let lease = LeaseRecord { id: new_uuid_v4(), host_id: pending.host_id.clone().unwrap_or_default(),
                vault_id: entry.record.id.clone(), vault_name: entry.record.name.clone(), secret_key: "token".into(),
                name,
                mode: LeaseMode::Raw, fields: detail.wanted_fields.iter().map(|field| LeaseField {
                    field: field.clone(), sentinel: None, path: target.requested_name.clone(),
                }).collect(),
                hosts: Vec::new(), reason: detail.reason.clone(), agent: pending.agent.clone(), created_at: now,
                expires_at: duration.map(|d| now.saturating_add(d.min(i64::MAX as u64) as i64)), revoked_at: None,
                source_kind: SourceKind::Generator, generation: Some(grant),
                generator_revision: Some(generator_revision), credential_expires_at: None,
                approval_order: Some(order), credential_version: 1, requested_generation: target.requested_generation.clone(),
                login: None };
            (lease, entry.client()?, managed_selector)
        };
        let check_live_entry = |lease: &LeaseRecord| -> Result<_> {
            let grant = lease.generation.as_ref().ok_or_else(|| CoreError::internal("generated lease has no grant"))?;
            let (entry, issued) = check_pending(managed_selector.as_ref().unwrap_or(grant))?;
            if let Some(issued) = issued
                && lease.generation != Some(GenerationGrant::GcloudAccess(issued))
            {
                return Err(CoreError::vault_unavailable("Google Cloud access profile changed during issuance"));
            }
            let live = entry.client()?;
            if !Arc::ptr_eq(&live, &client) {
                return Err(CoreError::vault_unavailable("generator authorization changed during issuance"));
            }
            Ok(())
        };
        let credential = Arc::new(self.issue_for_lease(&lease, &client, || check_live_entry(&lease)).map_err(Fail::Keep)?);
        let mut lease = lease;
        lease.credential_expires_at = Some(credential.expires_at);
        let outcome = (|| -> Result<GetResult> {
            let _authority = lock(&self.authorization);
            check_live_entry(&lease)?;
            let now = self.generation_now();
            if !lease.is_active(now) || credential.expires_at <= now {
                return Err(CoreError::vault_unavailable("approval expired during token generation"));
            }
            let cached = CachedLease {
                current: credential.clone(), version: 1, retired: Vec::new(), client: client.clone(),
            };
            let result = Self::generated_metadata(&lease, &cached);
            let operator_selected_grant = target.operator_selected_grant
                || matches!((&target.requested_generation, &lease.generation),
                    (Some(GenerationRequest::GcloudAccess(requested)),
                    Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { access, .. })))
                    if access.project_id != requested.project_id);
            let mut state = pending.state_for(&pending.id, RequestStatus::Approved);
            state.result = Some(RequestResult::Get(result.clone()));
            let done = Done { host_id: lease.host_id.clone(), state, at: now,
                generated: Some(GeneratedDelivery { lease_id: lease.id.clone(), credential_version: 1,
                    consumed: false, operator_selected_grant }) };
            let sealed = self.seal_generated(&lease, SavedToken::new(1, &credential), std::iter::empty())?;
            let sealed_done = self.seal_done(&pending.id, &done)?;
            let history = pending.history(RequestStatus::Approved, None, now);
            self.complete_pending_locked(&mut lock(&self.book), done, [sealed, sealed_done], |rows|
                self.store.insert_lease_with_request(&lease, rows, &history))?;
            lock(&self.generation).cached.insert(lease.id.clone(), cached);
            lock(&self.last_active).insert(lease.id.clone());
            self.lease_wake.notify_one();
            Ok(result)
        })();
        match outcome {
            Ok(result) => {
                self.notify(TOPIC_LEASES);
                self.log_lease_created(&lease);
                self.generator_event("issued", &lease, None);
                self.complete_generated_pending(pending, &result);
                Ok(result)
            }
            Err(e) => {
                self.revoke_tokens(vec![Revocation::new(&lease, credential, &client)]);
                Err(Fail::Keep(e))
            }
        }
    }

    fn check_pending_generation(
        &self, pending: &Pending, generator_id: &str, revision: u64, grant: &GenerationGrant,
        managed_reviewed: bool,
    ) -> Result<(GeneratorEntry, Option<GcloudAccessGrant>)> {
        let now = self.generation_now();
        if lock(&self.generation).shutting_down { return Err(CoreError::vault_unavailable("manager is shutting down")); }
        let book = lock(&self.book);
        let current = book.pending.iter().find(|p| p.id == pending.id && p.host_id == pending.host_id
            && p.resolving && p.expires == pending.expires && p.expires > now)
            .ok_or_else(|| CoreError::vault_unavailable("request ended during token generation"))?;
        let Detail::Get(GetDetail { target: GetTarget::Generated(target), mode, wanted_fields, .. }) = &current.detail else {
            return Err(CoreError::invalid("request no longer offers this generator"));
        };
        let Detail::Get(GetDetail { target: GetTarget::Generated(original), mode: original_mode, wanted_fields: original_fields, .. }) = &pending.detail else {
            return Err(CoreError::invalid("request no longer offers this generator"));
        };
        let offered = target.requested_generation == original.requested_generation
            && target.operator_selected_grant == original.operator_selected_grant
            && target.operator_selected_gcloud_project == original.operator_selected_gcloud_project
            && target.requested_name == original.requested_name
            && mode == original_mode && wanted_fields == original_fields
            && target.pinned_generator_id == original.pinned_generator_id
            && target.output_name == grant.output_name()
            && target.pinned_generator_id.as_ref().is_none_or(|id| id == generator_id)
            && target.candidates.iter().any(|choice|
                choice.generator_id == generator_id && choice.revision == revision && match grant {
                    GenerationGrant::GithubApp(grant) => {
                        let GenerationGrant::GithubApp(ceiling) = &choice.ceiling else { return false; };
                        original.candidates.iter().any(|snapshot| snapshot.generator_id == generator_id
                            && snapshot.revision == revision && snapshot.ceiling == choice.ceiling)
                            && if target.operator_selected_grant {
                                grant.is_subset_of(ceiling).unwrap_or(false)
                            } else {
                                grant == ceiling
                            }
                    }
                    GenerationGrant::Gcloud(_) => matches!(&choice.ceiling, GenerationGrant::Gcloud(_)),
                    GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access }) => {
                        let Some(GenerationRequest::GcloudAccess(requested)) = &target.requested_generation else {
                            return false;
                        };
                        choice.available
                            && matches!(&choice.ceiling, GenerationGrant::GcloudAccess(
                                GcloudAccessGrant::Requested { access: offered }) if offered == requested)
                            && (access == requested || (managed_reviewed && target.allows_reviewed_gcloud_access(access)))
                    }
                    GenerationGrant::GcloudAccess(_) => false,
                });
        if !offered {
            return Err(CoreError::invalid(if matches!(grant, GenerationGrant::GithubApp(_)) {
                if target.operator_selected_grant {
                    "approval must stay within the offered GitHub installation, repositories and permissions"
                } else {
                    "approval must match an offered GitHub installation and its exact requested repositories and permissions"
                }
            } else if matches!(grant, GenerationGrant::GcloudAccess(_)) {
                "approval must match the offered Google connection; project and permission changes require a reviewed IAM plan and corresponding client support"
            } else {
                "request no longer offers this generator"
            }));
        }
        drop(book);
        self.store.get_host(pending.host_id.as_deref().unwrap_or_default())?.filter(|h| h.revoked_at.is_none())
            .ok_or_else(|| CoreError::unauthorized("host was revoked"))?;
        let entry = self.generators.get(generator_id).ok_or_else(|| CoreError::invalid("generator was removed"))?;
        if entry.record.revision != revision {
            return Err(CoreError::invalid("generator authorization changed"));
        }
        if let GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access }) = grant {
            if !matches!(&entry.record.config, GeneratorConfig::GcloudConnection(_)) {
                return Err(CoreError::invalid("generator authorization changed"));
            }
            // Pending requests are selectors only; durable authority is derived here from the Ready record.
            let issued = self.ready_gcloud_access_locked(&entry.record, access)?;
            return Ok((entry, Some(issued)));
        }
        if !entry.record.config.accepts_grant(grant)? {
            return Err(CoreError::invalid("generator authorization changed"));
        }
        if let Some(uid) = gcloud_grant_uid(grant) {
            self.check_gcloud_account_not_retired(uid)?;
        }
        if let (GenerationGrant::Gcloud(grant), GeneratorConfig::Gcloud(config)) = (grant, &entry.record.config)
            && let Some(project_id) = grant.project_id.as_deref()
            && project_id != config.project_id.as_str()
        {
            self.validate_gcloud_approval_project_locked(&entry.record, project_id)?;
        }
        Ok((entry, None))
    }

    fn complete_generated_pending(&self, pending: &Pending, result: &GetResult) {
        self.log(super::activity::approved(pending, Some(&RequestResult::Get(result.clone())), self.generation_now()));
        self.bump();
        self.notify(TOPIC_REQUESTS);
    }

    /// Stop delivery after a failed verification/renewal, but continue
    /// counting prior Google tokens until their provider expiry.
    fn suspend_managed_renewal(&self, lease: &LeaseRecord, client: &Arc<GeneratorClient>) {
        let authority = lock(&self.authorization);
        let now = self.generation_now();
        let mut generation = lock(&self.generation);
        if generation.shutting_down { return; }
        if !generation.cached.get(&lease.id).is_some_and(|cached|
            cached.version == lease.credential_version && Arc::ptr_eq(&cached.client, client))
        {
            return;
        }
        let CachedLease { current, version, mut retired, .. } = generation.cached.remove(&lease.id).expect("cached lease");
        let mut stopped = vec![Revocation::new(lease, current.clone(), client)];
        if current.expires_at > now { retired.push(RetiredCredential { version, credential: current }); }
        Revocation::prune_retired(&mut stopped, lease, client, &mut retired, now);
        if !retired.is_empty() {
            generation.retired_only.insert(lease.id.clone(), RetiredLease { tokens: retired, client: client.clone() });
        }
        if let Err(error) = self.persist_pruned_generated(lease, &generation) {
            log::error!("persisting generated credential suspension: {}", error.message);
            // If we cannot retain predecessors safely, at least prevent the
            // old credential from being deliverable on a later restart.
            if let Err(error) = self.resume.remove(GENERATED_RESUME, &lease.id) {
                log::error!("removing suspended generated credential: {}", error.message);
            }
        }
        drop(generation);
        {
            let mut proxy = lock(&self.proxy_state);
            proxy.dirty |= proxy.entries.remove(&lease.id).is_some();
            proxy.suspended.insert(lease.id.clone(), "credential renewal failed; run asm get to retry".into());
        }
        self.lease_wake.notify_one();
        if let Err(error) = self.publish_proxy_locked(&authority) {
            log::error!("publishing proxy state after Google renewal failed: {}", error.message);
        }
        drop(authority);
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        self.revoke_tokens(stopped);
    }

    pub(crate) fn evict_generated_locked(&self, lease: &LeaseRecord, _guard: &MutexGuard<'_, ()>) -> Vec<Revocation> {
        if let Err(error) = self.resume.remove(GENERATED_RESUME, &lease.id) {
            log::error!("removing generated credentials: {}", error.message);
        }
        let now = self.generation_now();
        let tokens = lock(&self.generation).take(lease, now);
        let mut state = lock(&self.proxy_state);
        state.dirty |= state.entries.remove(&lease.id).is_some();
        state.suspended.remove(&lease.id);
        state.pending_resumed.remove(&lease.id);
        self.lease_wake.notify_one();
        tokens
    }

    pub(crate) fn revoke_tokens(&self, tokens: Vec<Revocation>) {
        for token in tokens { self.revoke_token(token); }
    }

    fn revoke_token(&self, token: Revocation) {
        let result = token.client.revoke(&token.credential.token);
        let (kind, summary, status) = match result {
            Ok(RevocationOutcome::Revoked) => return,
            Ok(RevocationOutcome::Unsupported) => ("revocation_unsupported",
                "Google access tokens cannot be individually revoked; copies remain usable until credential expiry", None),
            Err(e) => ("revocation_failed", "GitHub token revocation failed", Some(e.message)),
        };
        self.log(Event::new(Category::Generators, kind, summary)
            .detail(serde_json::json!({ "lease_id": token.lease_id, "generator_id": token.generator_id,
                "credential_expires_at": fmt_unix(token.credential.expires_at), "status": status })));
    }

    pub(crate) fn sweep_generated_at(&self, now: i64) {
        let mut tokens = Vec::new();
        let mut changed = false;
        let result = (|| -> Result<()> {
            let authority = lock(&self.authorization);
            if lock(&self.generation).shutting_down { return Ok(()); }
            for lease in self.store.list_leases()?.into_iter().filter(|l| l.source_kind == SourceKind::Generator) {
                let mut generation = lock(&self.generation);
                if !lease.is_active(now) {
                    let known = generation.cached.contains_key(&lease.id) || generation.retired_only.contains_key(&lease.id);
                    drop(generation);
                    if known { tokens.extend(self.evict_generated_locked(&lease, &authority)); }
                    continue;
                }
                let expired = generation.cached.get(&lease.id).is_some_and(|c| c.current.expires_at <= now);
                let mut pruned = false;
                if expired {
                    if let Some(mut cached) = generation.cached.remove(&lease.id) {
                        Revocation::queue(&mut tokens, &lease, &cached.client, [cached.current], now);
                        Revocation::prune_retired(&mut tokens, &lease, &cached.client, &mut cached.retired, now);
                        if !cached.retired.is_empty() {
                            generation.retired_only.insert(lease.id.clone(), RetiredLease {
                                tokens: cached.retired, client: cached.client });
                        }
                    }
                    pruned = true;
                } else {
                    if let Some(cached) = generation.cached.get_mut(&lease.id) {
                        let before = cached.retired.len();
                        Revocation::prune_retired(&mut tokens, &lease, &cached.client, &mut cached.retired, now);
                        pruned = cached.retired.len() != before;
                    } else if let Some(retired) = generation.retired_only.get_mut(&lease.id) {
                        let before = retired.tokens.len();
                        Revocation::prune_retired(&mut tokens, &lease, &retired.client, &mut retired.tokens, now);
                        pruned = retired.tokens.len() != before;
                        if retired.tokens.is_empty() { generation.retired_only.remove(&lease.id); }
                    }
                }
                if pruned && let Err(error) = self.persist_pruned_generated(&lease, &generation) {
                    log::error!("pruning generated credentials: {}", error.message);
                }
                drop(generation);
                if expired {
                    let mut state = lock(&self.proxy_state);
                    state.dirty |= state.entries.remove(&lease.id).is_some();
                    changed = true;
                    state.suspended.insert(lease.id.clone(), "credential expired; run asm get to refresh".into());
                    self.lease_wake.notify_one();
                }
            }
            if lock(&self.proxy_state).dirty { self.publish_proxy_locked(&authority)?; }
            Ok(())
        })();
        if let Err(e) = result { log::error!("generated expiry: {}", e.message); }
        self.notify_proxy_changed();
        if changed { self.notify(TOPIC_LEASES); }
        self.revoke_tokens(tokens);
    }

    pub(crate) fn begin_generation_shutdown(&self) {
        let _authority = lock(&self.authorization);
        // In-flight responses still recheck this fence before installing.
        // Issued credentials remain durable; quit is not operator revocation.
        lock(&self.generation).shutting_down = true;
    }
}

impl Core {
    fn generator_info(&self, entry: &GeneratorEntry, warning: Option<String>) -> ffi::GeneratorInfo {
        ffi::GeneratorInfo { id: entry.record.id.clone(), name: entry.record.name.clone(),
            config: entry.record.config.clone().into(), revision: entry.record.revision,
            status: entry.status().into(), warning, require_exact_scope_match: entry.record.require_exact_scope_match }
    }

    pub fn list_generators(&self) -> Vec<ffi::GeneratorInfo> {
        self.generators.entries().iter().map(|entry| self.generator_info(entry, None)).collect()
    }

    pub fn github_connect(&self, draft: ffi::GeneratorDraft) -> Result<ffi::GithubInstallation> {
        let ffi::GeneratorConfig::GithubApp { config } = draft.config else {
            return Err(CoreError::invalid("choose a GitHub App generator"));
        };
        let [ceiling] = config.installations.as_slice() else {
            return Err(CoreError::invalid("choose exactly one GitHub installation to connect"));
        };
        let installation_id = ceiling.installation_id;
        let pem = Self::github_draft_pem(draft.id.as_deref(), draft.credentials)?;
        Ok(GithubAppGenerator::for_discovery(config.client_id, &pem)?.connect(installation_id)?.into())
    }

    pub fn github_list_installations(&self, draft: ffi::GeneratorDraft) -> Result<Vec<ffi::GithubInstallationAccount>> {
        let ffi::GeneratorConfig::GithubApp { config } = draft.config else {
            return Err(CoreError::invalid("choose a GitHub App generator"));
        };
        let pem = Self::github_draft_pem(draft.id.as_deref(), draft.credentials)?;
        Ok(GithubAppGenerator::for_discovery(config.client_id, &pem)?.list_installations()?.into_iter()
            .map(|account| ffi::GithubInstallationAccount {
                installation_id: account.installation_id,
                account: account.account,
            }).collect())
    }

    fn github_draft_pem(id: Option<&str>, credentials: ffi::GeneratorCredentials) -> Result<String> {
        let missing = || CoreError::invalid("choose a private key PEM file");
        match credentials {
            ffi::GeneratorCredentials::Keep => creds::get(id.ok_or_else(missing)?, creds::GITHUB_PRIVATE_KEY)?
                .ok_or_else(missing),
            ffi::GeneratorCredentials::GithubPrivateKey { pem } => Ok(pem),
            ffi::GeneratorCredentials::GcloudSession { .. } => Err(missing()),
        }
    }

    pub fn save_generator(&self, draft: ffi::GeneratorDraft) -> Result<ffi::GeneratorInfo> {
        self.save_generator_with(draft, creds::get, creds::set, creds::delete)
    }

    fn save_generator_with(
        &self, draft: ffi::GeneratorDraft,
        get_key: impl Fn(&str, &str) -> Result<Option<String>>,
        put_key: impl Fn(&str, &str, &str) -> Result<()>,
        delete_key: impl Fn(&str, &str) -> Result<()>,
    ) -> Result<ffi::GeneratorInfo> {
        self.save_generator_with_github(draft, get_key, put_key, delete_key, GithubAppGenerator::new)
    }

    fn save_generator_with_github(
        &self, draft: ffi::GeneratorDraft,
        get_key: impl Fn(&str, &str) -> Result<Option<String>>,
        put_key: impl Fn(&str, &str, &str) -> Result<()>,
        delete_key: impl Fn(&str, &str) -> Result<()>,
        build_github: impl FnOnce(&crate::generator::GithubAppConfig, &str) -> Result<GithubAppGenerator>,
    ) -> Result<ffi::GeneratorInfo> {
        let name = draft.name.trim().to_string();
        crate::generator::validate_name(&name)?;
        let previous = match draft.id.as_deref() {
            Some(id) => Some(self.store.get_generator(id)?.ok_or_else(|| CoreError::not_found("no such generator"))?),
            None => None,
        };
        let config: GeneratorConfig = draft.config.try_into()?;
        if previous.as_ref().is_some_and(|old| std::mem::discriminant(&old.config) != std::mem::discriminant(&config)) {
            return Err(CoreError::invalid("an existing generator's provider cannot be changed"));
        }
        if previous.is_none() && matches!(&config, GeneratorConfig::Gcloud(_)) {
            return Err(CoreError::invalid("new Google Cloud generators must be sign-in connections"));
        }
        let (mut config, replacement, prepared) = match (config, draft.credentials) {
            (config @ GeneratorConfig::GithubApp(_), ffi::GeneratorCredentials::Keep) => (config, None, None),
            (config @ GeneratorConfig::GithubApp(_), ffi::GeneratorCredentials::GithubPrivateKey { pem }) => {
                (config, Some(pem), None)
            }
            (GeneratorConfig::Gcloud(_) | GeneratorConfig::GcloudConnection(_), ffi::GeneratorCredentials::Keep) => {
                let previous = previous.as_ref()
                    .ok_or_else(|| CoreError::invalid("sign in with Google before saving this generator"))?;
                (previous.config.clone(), None, None)
            }
            (GeneratorConfig::Gcloud(_) | GeneratorConfig::GcloudConnection(_), ffi::GeneratorCredentials::GcloudSession { session_id }) => {
                // A legacy reconnect's preflight must not hold authorization.
                let (config, adc, prepared) = self.prepare_gcloud_save(previous.as_ref(), &session_id)?;
                (config, Some(adc), Some(prepared))
            }
            _ => return Err(CoreError::invalid("credentials do not match the generator provider")),
        };
        config.canonicalize()?;
        let replacement = replacement.as_deref();
        let kind = config.credential_kind();
        let id = previous.as_ref().map(|r| r.id.clone()).unwrap_or_else(new_uuid_v4);
        let mut github_warning = None;
        let mut verified_key = None;
        let mut verified_github = None;
        if let GeneratorConfig::GithubApp(github) = &config {
            let reuse = replacement.is_none()
                && previous.as_ref().is_some_and(|old| old.config == config)
                && self.generators.with_entry(&id, |entry| entry.generator.is_some()) == Some(true);
            if !reuse {
                // Bind the network proof to this exact draft, outside the authorization lock.
                if replacement.is_none() && previous.is_some() {
                    verified_key = get_key(&id, kind)?;
                }
                let pem = replacement.or(verified_key.as_deref()).filter(|pem| !pem.is_empty())
                    .ok_or_else(|| CoreError::invalid("choose a private key PEM file"))?;
                let client = build_github(github, pem)?;
                github_warning = client.verify_installations()?;
                verified_github = Some(client);
            }
        }
        let mut tokens = Vec::new();
        let entry = {
            let authority = lock(&self.authorization);
            if lock(&self.generation).shutting_down {
                return Err(CoreError::vault_unavailable("manager is shutting down"));
            }
            self.gcloud_profiles.check_generator_mutation(&id)?;
            if let Some(previous) = &previous
                && self.store.get_generator(&previous.id)?.as_ref() != Some(previous) {
                return Err(CoreError::invalid("generator changed while saving; reopen the editor and try again"));
            }
            if let Some(prepared) = &prepared {
                self.validate_gcloud_save_locked(prepared)?;
            }
            let old_material = get_key(&id, kind)?;
            if verified_key.is_some() && verified_key != old_material {
                return Err(CoreError::invalid("generator credentials changed while saving; reopen the editor and try again"));
            }
            let key_changed = replacement.is_some_and(|new| old_material.as_deref() != Some(new));
            let material = replacement.or(old_material.as_deref()).filter(|s| !s.is_empty())
                .ok_or_else(|| CoreError::invalid(match &config {
                    GeneratorConfig::GithubApp(_) => "choose a private key PEM file",
                    GeneratorConfig::Gcloud(_) | GeneratorConfig::GcloudConnection(_) => {
                        "sign in with Google before saving this generator"
                    }
                }))?;
            let authority_changed = previous.as_ref().is_some_and(|r|
                prepared.is_some() || !r.config.same_authority(&config)) || key_changed;
            let live = previous.as_ref().and_then(|_| self.generators.get(&id));
            let (generator, unavailable_reason) = match (verified_github, live) {
                (Some(client), _) => (Some(Arc::new(GeneratorClient::GithubApp(client))), None),
                (None, Some(live)) if !authority_changed && live.generator.is_some() => (live.generator, None),
                (None, _) if matches!(&config, GeneratorConfig::GithubApp(_)) => {
                    return Err(CoreError::invalid("generator changed while saving; reopen the editor and try again"));
                }
                (None, Some(live)) if replacement.is_none() && live.generator.is_none() => (None, live.unavailable_reason),
                (None, _) => (Some(Arc::new(GeneratorClient::new(&config, material, &self.gcloud.runner)?)), None),
            };
            let revision = match previous.as_ref() {
                Some(r) if authority_changed => r.revision.checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64).ok_or_else(|| CoreError::invalid("generator revision overflow"))?,
                Some(r) => r.revision,
                None => 1,
            };
            let position = match &previous {
                Some(previous) => previous.position,
                None => self.store.list_generators()?.iter().map(|r| r.position).max().unwrap_or(0).saturating_add(1),
            };
            let affected_leases = if authority_changed && previous.is_some() { self.generator_leases(&id)? } else { Vec::new() };
            let record = GeneratorRecord { id: id.clone(), name, config, revision, position,
                require_exact_scope_match: draft.require_exact_scope_match };
            if key_changed || previous.is_none() {
                put_key(&id, kind, material)?;
            }
            if let Err(error) = self.store.upsert_generator(&record) {
                let rollback = if key_changed || previous.is_none() {
                    match old_material.as_deref() {
                        Some(old) => put_key(&id, kind, old),
                        None => delete_key(&id, kind),
                    }
                } else { Ok(()) };
                if rollback.is_err() && previous.is_some() {
                    // Delete an unrestorable replacement where possible so a restart
                    // cannot pick it up under the previous verified identity.
                    if old_material.is_some() && delete_key(&id, kind).is_err() {
                        log::error!("could not remove unrestored generator credentials from the keychain");
                    }
                    self.generators.mark_unavailable(&id, "credential rollback failed; reconnect this generator");
                    for lease in affected_leases {
                        tokens.extend(self.evict_generated_locked(&lease, &authority));
                    }
                    self.refresh_generator_candidates_locked(&authority);
                }
                drop(authority);
                self.revoke_tokens(tokens);
                self.sync_proxy(false);
                self.notify(TOPIC_GENERATORS);
                self.bump();
                self.notify(TOPIC_REQUESTS);
                self.notify(TOPIC_LEASES);
                return Err(error);
            }
            let entry = GeneratorEntry { record, generator, unavailable_reason };
            self.generators.insert(entry.clone());
            if let Some(prepared) = &prepared {
                self.finish_gcloud_save(prepared);
            }
            for lease in affected_leases {
                tokens.extend(self.end_generator_lease_locked(&lease, "generator authorization changed", &authority));
            }
            self.refresh_generator_candidates_locked(&authority);
            self.log(Event::new(Category::Generators, if previous.is_some() { "edited" } else { "created" },
                format!("generator {} saved", entry.record.name)).detail(serde_json::json!({
                    "generator_id": id, "name": entry.record.name, "revision": entry.record.revision,
                    "config": entry.record.config,
                    "require_exact_scope_match": entry.record.require_exact_scope_match,
                })));
            entry
        };
        if let Some(previous) = &previous
            && let (GeneratorConfig::GcloudConnection(old), GeneratorConfig::GcloudConnection(new)) =
                (&previous.config, &entry.record.config)
            && old.account_email != new.account_email
        {
            self.publish_gcloud_profile_cleanup(previous);
        }
        self.revoke_tokens(tokens);
        self.sync_proxy(false);
        self.notify(TOPIC_GENERATORS);
        self.bump();
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
        let mut warning = github_warning;
        if !qualified.is_empty() {
            let collision = format!("Secret name collision; use qualified choices: {}", qualified.join(", "));
            if let Some(warning) = &mut warning {
                warning.push_str("; ");
                warning.push_str(&collision);
            } else {
                warning = Some(collision);
            }
        }
        Ok(self.generator_info(&entry, warning))
    }

    pub fn remove_generator(&self, id: &str) -> Result<()> {
        self.remove_generator_with(id, creds::delete)
    }

    fn remove_generator_with(&self, id: &str, delete_key: impl Fn(&str, &str) -> Result<()>) -> Result<()> {
        let mut tokens = Vec::new();
        let record = {
            let authority = lock(&self.authorization);
            if lock(&self.generation).shutting_down {
                return Err(CoreError::vault_unavailable("manager is shutting down"));
            }
            let record = self.store.get_generator(id)?.ok_or_else(|| CoreError::not_found("no such generator"))?;
            self.gcloud_profiles.check_generator_mutation(id)?;
            let affected_leases = self.generator_leases(id)?;
            self.store.delete_generator(id)?;
            self.generators.remove(id);
            for lease in affected_leases {
                tokens.extend(self.end_generator_lease_locked(&lease, "generator removed", &authority));
            }
            self.refresh_generator_candidates_locked(&authority);
            self.log(Event::new(Category::Generators, "removed", format!("generator {} removed", record.name))
                .detail(serde_json::json!({ "generator_id": id, "name": record.name, "revision": record.revision })));
            record
        };
        if delete_key(id, record.config.credential_kind()).is_err() {
            log::warn!("could not remove the generator credential from the keychain");
        }
        if matches!(&record.config, GeneratorConfig::GcloudConnection(_)) {
            self.publish_gcloud_profile_cleanup(&record);
        }
        self.revoke_tokens(tokens);
        self.sync_proxy(false);
        self.notify(TOPIC_GENERATORS);
        self.bump();
        self.notify(TOPIC_REQUESTS);
        self.notify(TOPIC_LEASES);
        Ok(())
    }

    fn generator_leases(&self, id: &str) -> Result<Vec<LeaseRecord>> {
        Ok(self.store.list_leases()?.into_iter()
            .filter(|l| l.source_kind == SourceKind::Generator && l.vault_id == id).collect())
    }

    fn end_generator_lease_locked(&self, lease: &LeaseRecord, reason: &str, authority: &MutexGuard<'_, ()>) -> Vec<Revocation> {
        let now = self.generation_now();
        if lease.is_active(now) {
            match self.store.revoke_lease(&lease.id, now) {
                Ok(true) => self.log_lease_revoked(lease, reason),
                Ok(false) => {},
                Err(e) => log::error!("ending generated lease: {}", e.message),
            }
        }
        // Even if the durable update failed, the removed generator or old
        // revision is no longer authorized to deliver anything.
        self.evict_generated_locked(lease, authority)
    }

    pub(crate) fn mark_gcloud_sign_in_required(&self, id: &str, revision: u64, client: &Arc<GeneratorClient>) {
        if !matches!(client.as_ref(), GeneratorClient::Gcloud(_)) { return; }
        let mut tokens = Vec::new();
        {
            let authority = lock(&self.authorization);
            if lock(&self.generation).shutting_down { return; }
            let current = self.generators.with_entry(id, |current| current.record.revision == revision
                && current.generator.as_ref().is_some_and(|active| Arc::ptr_eq(active, client)));
            if current != Some(true) {
                return;
            }
            self.generators.mark_unavailable(id, GCLOUD_SIGN_IN_REQUIRED);
            match self.generator_leases(id) {
                Ok(leases) => for lease in leases {
                    tokens.extend(self.evict_generated_locked(&lease, &authority));
                },
                Err(e) => log::error!("evicting credentials after Google authorization failed: {}", e.message),
            }
            self.refresh_generator_candidates_locked(&authority);
            if let Err(e) = self.publish_proxy_locked(&authority) {
                log::error!("publishing proxy state after Google authorization failed: {}", e.message);
            }
        }
        self.notify_proxy_changed();
        self.revoke_tokens(tokens);
        self.notify(TOPIC_GENERATORS);
        self.bump();
        self.notify(TOPIC_REQUESTS);
        self.notify(TOPIC_LEASES);
    }

    pub(super) fn reconcile_generator_target(&self, target: &mut GeneratorTarget, keep_offered_grant: bool) {
        let request = target.requested_generation.as_ref();
        let operator_selected_grant = target.operator_selected_grant;
        target.candidates.retain_mut(|candidate| {
            self.generators.with_entry(&candidate.generator_id, |entry| {
                let ceiling = match (&entry.record.config, &candidate.ceiling) {
                    (GeneratorConfig::GithubApp(config), GenerationGrant::GithubApp(offered)) => {
                        let Some(GenerationRequest::GithubApp(scope)) = request else { return false; };
                        let Some(ceiling) = config.ceiling(offered.installation_id) else { return false; };
                        if operator_selected_grant {
                            let Some(names) = scope.repositories.as_ref() else { return false; };
                            // Route by at least one unambiguous requested repository, but
                            // offer the actual ceiling. A pending name must not acquire a
                            // different ID after an edit, even before a new review.
                            let mut matched = false;
                            for name in names {
                                let resolved = configured_github_repository(ceiling, name).map(|repo| repo.id);
                                if keep_offered_grant && configured_github_repository(offered, name)
                                    .is_some_and(|old| resolved != Some(old.id))
                                {
                                    return false;
                                }
                                matched |= resolved.is_some();
                            }
                            if !matched { return false; }
                            (offered != ceiling || offered.repositories != ceiling.repositories)
                                .then(|| GenerationGrant::GithubApp(ceiling.clone()))
                        } else {
                            let Some(resolved) = resolve_github_grant(scope, ceiling) else { return false; };
                            if keep_offered_grant && &resolved != offered { return false; }
                            Some(GenerationGrant::GithubApp(resolved))
                        }
                    }
                    (GeneratorConfig::Gcloud(config), GenerationGrant::Gcloud(_))
                        if matches!(request, None | Some(GenerationRequest::Gcloud(_))) =>
                        Some(GenerationGrant::Gcloud(config.ceiling.clone())),
                    (GeneratorConfig::GcloudConnection(_), GenerationGrant::GcloudAccess(grant)) => {
                        let Some(GenerationRequest::GcloudAccess(access)) = request else { return false; };
                        if access.validate().is_err() { return false; }
                        match grant {
                            GcloudAccessGrant::Connection if !keep_offered_grant =>
                                Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: access.clone() })),
                            GcloudAccessGrant::Requested { access: offered } if access == offered => None,
                            _ => return false,
                        }
                    }
                    _ => return false,
                };
                candidate.name.clone_from(&entry.record.name);
                candidate.revision = entry.record.revision;
                if let Some(ceiling) = ceiling { candidate.ceiling = ceiling; }
                candidate.available = entry.generator.is_some();
                candidate.unavailable_reason.clone_from(&entry.unavailable_reason);
                true
            }).unwrap_or(false)
        });
    }

    fn refresh_generator_candidates_locked(&self, _authority: &MutexGuard<'_, ()>) {
        let mut book = lock(&self.book);
        for index in (0..book.pending.len()).rev() {
            let pending = &book.pending[index];
            let Detail::Get(GetDetail { target: GetTarget::Generated(old), .. }) = &pending.detail else { continue; };
            let mut updated = old.clone();
            self.reconcile_generator_target(&mut updated, true);
            let result = if updated.candidates.is_empty() {
                let id = pending.id.clone();
                self.finish_locked(&mut book, &id, Err(Some("no offered generators remain".into())), self.generation_now(), true)
                    .map(|_| ())
            } else if updated != *old || updated.candidates.iter().zip(&old.candidates).any(|(new, old)|
                match (&new.ceiling, &old.ceiling) {
                    (GenerationGrant::GithubApp(new), GenerationGrant::GithubApp(old)) => new.repositories != old.repositories,
                    (GenerationGrant::Gcloud(new), GenerationGrant::Gcloud(old)) => new.service_account_email != old.service_account_email,
                    _ => false,
                })
            {
                let mut pending = pending.clone();
                let Detail::Get(get) = &mut pending.detail else { unreachable!() };
                get.target = GetTarget::Generated(updated);
                self.save_pending_locked(&mut book, pending)
            } else {
                Ok(())
            };
            if let Err(error) = result {
                log::error!("persisting pending generator candidates: {}", error.message);
            }
        }
    }

    /// Rust-only isolation seam: inject a provider with isolated external endpoints.
    /// Callers inject a real provider adapter with isolated external endpoints.
    pub fn install_generator_client(&self, record: GeneratorRecord, client: Arc<GeneratorClient>) -> Result<()> {
        record.config.validate()?;
        if !client.matches_config(&record.config) {
            return Err(CoreError::invalid("generator client does not match the configured provider"));
        }
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
