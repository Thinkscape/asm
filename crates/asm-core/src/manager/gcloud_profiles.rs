//! Local review and approval for durable, exact Google Cloud access profiles.
//! Review is read-only. Approval journals the reviewed resource before
//! creation and never adopts an account found by its name.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, Weak};

use asm_proto::crypto::{hex_encode, new_uuid_v4, random_bytes};
use asm_proto::generators::{
    GCLOUD_TOKEN_NAME, GcloudAccessGrant, GcloudAccessRequest, GenerationGrant, GenerationRequest,
    GenerationSelection,
};
use asm_proto::wire::LeaseMode;
use serde_json::json;

use super::activity::{Category, Event};
use super::generation::GeneratedApproval;
use super::requests::{Detail, Fail, GeneratorTarget, GetDetail, GetTarget, Pending, RequestedMode};
use super::{Core, TOPIC_GCLOUD_ACCOUNTS, lock};
use crate::error::{CoreError, Result};
use crate::ffi::Decision;
use crate::generator::gcloud::{GcloudHttp, GcloudIdentity};
use crate::generator::gcloud::provision::TOKEN_CREATOR;
use crate::generator::{GeneratorClient, GeneratorConfig, GeneratorEntry};
use crate::store::{
    GcloudProfileKey, GcloudProfilePhase, GcloudProfileRecord, GeneratorRecord, gcloud_profile_email,
    validate_profile_admin_email,
};

const PLAN_LIFETIME_SECS: i64 = 2 * 60;
const CLEANUP: &str = "Verify the service account's immutable ID in Google Cloud before cleanup. Remove its project IAM bindings, its Service Account Token Creator grant, and the account if no longer needed.";
const CLEANUP_UNKNOWN: &str = "ASM has no immutable ID for this attempt. Check the Google Cloud creation audit log to establish ownership before removing anything. ASM never adopts an account by name.";

pub(crate) struct GcloudProfilePlan {
    pub plan_id: Option<String>,
    pub expires_at: Option<i64>,
    pub ready: bool,
    pub project_id: String,
    pub service_account_name: String,
    pub service_account_email: String,
    pub service_account_unique_id: Option<String>,
    pub project_roles: Vec<String>,
    pub scopes: Vec<String>,
    pub service_account_role: String,
    pub admin_principal: String,
    pub messages: Vec<String>,
}

struct ProfileContext {
    request_id: String,
    host_id: String,
    request_expires: i64,
    requested_name: String,
    requested_mode: RequestedMode,
    wanted_fields: Vec<String>,
    revision: u64,
    requested_access: GcloudAccessRequest,
    operator_selected_grant: bool,
    operator_selected_gcloud_project: bool,
    key: GcloudProfileKey,
    admin_email: String,
    client: Weak<GeneratorClient>,
}

struct Plan {
    context: ProfileContext,
    delivery: GeneratedApproval,
    expires: i64,
    account_id: String,
    previous: Option<GcloudProfileRecord>,
}

impl Plan {
    fn check_identity(&self, identity: &GcloudIdentity) -> Result<()> {
        self.context.check_identity(identity)
    }

    fn email(&self) -> String {
        gcloud_profile_email(&self.context.key.access.project_id, &self.account_id)
    }
}

struct ProfileDecision {
    mode: LeaseMode,
    duration_secs: Option<u64>,
    hosts: Vec<String>,
    selection: GenerationSelection,
}

impl ProfileDecision {
    fn parse(decision: Decision) -> Result<Self> {
        let Decision::ApproveGet { mode, duration_secs, hosts, generation: Some(selection) } = decision else {
            return Err(CoreError::invalid("Google IAM review requires a complete get approval"));
        };
        let selection = GenerationSelection::try_from(selection)?;
        if !matches!(&selection.grant, GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { .. })) {
            return Err(changed_request());
        }
        if mode == crate::ffi::LeaseMode::Raw && !hosts.is_empty() {
            return Err(CoreError::invalid("raw delivery does not accept destination hosts"));
        }
        Ok(Self { mode: mode.into(), duration_secs, hosts, selection })
    }
}

/// An IAM review pins the exact ready account, including when no writes were needed.
pub(super) struct ReviewedGcloudProfile<'a> {
    plan: &'a Plan,
    issued: GcloudAccessGrant,
}

impl ReviewedGcloudProfile<'_> {
    pub(super) fn check(
        &self, core: &Core, pending: &Pending, entry: &GeneratorEntry, issued: Option<&GcloudAccessGrant>,
    ) -> Result<()> {
        self.plan.context.check_selection(core, pending, entry)?;
        if self.plan.expires <= core.generation_now() {
            return Err(stale_plan());
        }
        if issued != Some(&self.issued) {
            return Err(changed_request());
        }
        Ok(())
    }
}

impl ProfileContext {
    fn check_identity(&self, identity: &GcloudIdentity) -> Result<()> {
        if identity.subject != self.key.account_subject || identity.email != self.admin_email {
            return Err(CoreError::unauthorized("Google account identity changed; sign in again before reviewing IAM provisioning"));
        }
        validate_profile_admin_email(&identity.email)
    }

    fn check_selection(&self, core: &Core, pending: &Pending, entry: &GeneratorEntry) -> Result<Option<i64>> {
        let GeneratorConfig::GcloudConnection(config) = &entry.record.config else {
            return Err(changed_request());
        };
        let (get, target, access) = profile_get(pending)?;
        if pending.id != self.request_id || entry.record.revision != self.revision
            || pending.host_id.as_deref() != Some(self.host_id.as_str()) || pending.expires != self.request_expires
            || target.requested_name != self.requested_name || get.mode != self.requested_mode
            || get.wanted_fields != self.wanted_fields || access != &self.requested_access
            || target.operator_selected_grant != self.operator_selected_grant
            || target.operator_selected_gcloud_project != self.operator_selected_gcloud_project
            || config.account_subject != self.key.account_subject || config.account_email != self.admin_email
            || !Weak::ptr_eq(&Arc::downgrade(&entry.client()?), &self.client)
        {
            return Err(changed_request());
        }
        core.validate_gcloud_selected_project_locked(pending, entry, &self.key.access.project_id)
    }
}

#[derive(Default)]
struct ProfileOperations {
    plans: HashMap<String, Plan>,
    working: HashSet<GcloudProfileKey>,
    deleting: HashMap<String, GcloudProfileKey>,
    minting: HashMap<String, usize>,
    closed: bool,
}

#[derive(Default)]
pub(super) struct GcloudProfiles {
    state: Mutex<ProfileOperations>,
    drained: Condvar,
}

struct ProfileFlight<'a> {
    profiles: &'a GcloudProfiles,
    key: &'a GcloudProfileKey,
}

impl Drop for ProfileFlight<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.profiles.state);
        state.working.remove(self.key);
        self.profiles.drained.notify_all();
    }
}

#[derive(Clone, Copy)]
enum AccountOperation {
    Mint,
    Delete,
}

pub(super) struct AccountFlight<'a> {
    profiles: &'a GcloudProfiles,
    unique_id: &'a str,
    operation: AccountOperation,
}

impl Drop for AccountFlight<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.profiles.state);
        match self.operation {
            AccountOperation::Mint => {
                let count = state.minting.get_mut(self.unique_id).expect("active Google mint");
                *count -= 1;
                if *count == 0 { state.minting.remove(self.unique_id); }
            }
            AccountOperation::Delete => { state.deleting.remove(self.unique_id); }
        }
        self.profiles.drained.notify_all();
    }
}

impl GcloudProfiles {
    fn ensure_available(state: &ProfileOperations, key: &GcloudProfileKey) -> Result<()> {
        if state.closed {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        if state.working.contains(key) || state.deleting.values().any(|active| active == key) {
            return Err(CoreError::vault_unavailable("another Google IAM operation is in progress for these exact claims"));
        }
        Ok(())
    }

    fn publish(&self, now: i64, plan: Plan) -> Result<String> {
        let mut state = lock(&self.state);
        Self::ensure_available(&state, &plan.context.key)?;
        // Reviewing another choice for this request replaces, rather than accumulates,
        // administrative confirmations. None of the retired IDs can be replayed.
        state.plans.retain(|_, p| p.expires > now && p.context.request_id != plan.context.request_id);
        let id = new_uuid_v4();
        state.plans.insert(id.clone(), plan);
        Ok(id)
    }

    fn take(&self, id: &str, now: i64) -> Result<Plan> {
        let mut state = lock(&self.state);
        let plan = state.plans.remove(id).filter(|p| p.expires > now).ok_or_else(stale_plan)?;
        Self::ensure_available(&state, &plan.context.key)?;
        Ok(plan)
    }

    fn start<'a>(&'a self, key: &'a GcloudProfileKey) -> Result<ProfileFlight<'a>> {
        let mut state = lock(&self.state);
        Self::ensure_available(&state, key)?;
        state.working.insert(key.clone());
        Ok(ProfileFlight { profiles: self, key })
    }

    /// Mint and deletion permits are claimed under generation authorization. In-flight
    /// mints already admitted for this UID must finish before deletion may be confirmed.
    pub(super) fn start_mint<'a>(&'a self, unique_id: &'a str) -> Result<AccountFlight<'a>> {
        let mut state = lock(&self.state);
        if state.closed || state.deleting.contains_key(unique_id) {
            return Err(CoreError::vault_unavailable("Google account generation is no longer available"));
        }
        *state.minting.entry(unique_id.into()).or_default() += 1;
        Ok(AccountFlight { profiles: self, unique_id, operation: AccountOperation::Mint })
    }

    fn ensure_delete_available(state: &ProfileOperations, key: &GcloudProfileKey, unique_id: &str) -> Result<()> {
        Self::ensure_available(state, key)?;
        if state.minting.contains_key(unique_id)
            || state.deleting.contains_key(unique_id)
            || state.deleting.values().any(|active| active.generator_id == key.generator_id)
        {
            return Err(CoreError::vault_unavailable("another Google account operation is in progress; try again after it finishes"));
        }
        Ok(())
    }

    pub(super) fn start_delete<'a>(&'a self, key: &GcloudProfileKey, unique_id: &'a str) -> Result<AccountFlight<'a>> {
        let mut state = lock(&self.state);
        Self::ensure_delete_available(&state, key, unique_id)?;
        state.deleting.insert(unique_id.into(), key.clone());
        Ok(AccountFlight { profiles: self, unique_id, operation: AccountOperation::Delete })
    }

    pub(super) fn invalidate_deleted_profile_plans(&self, key: &GcloudProfileKey) {
        lock(&self.state).plans.retain(|_, plan| &plan.context.key != key);
    }

    /// Prevent replacement/removal from racing a cloud write using a pinned client.
    /// Pending intents do not block reconnect once the current attempt has returned.
    pub(super) fn check_generator_mutation(&self, generator_id: &str) -> Result<()> {
        if lock(&self.state).deleting.values().any(|key| key.generator_id == generator_id) {
            return Err(CoreError::vault_unavailable("Google service account deletion is in progress; try again after it finishes"));
        }
        Ok(())
    }

    pub(super) fn shutdown(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        state.plans.clear();
        // Keep the data-dir lock and activity writer alive while an in-flight provider
        // response is journaled. Shutdown has already fenced all further cloud writes.
        drop(self.drained.wait_while(state, |state| {
            !state.working.is_empty() || !state.deleting.is_empty() || !state.minting.is_empty()
        }).unwrap_or_else(|e| e.into_inner()));
    }
}

fn stale_plan() -> CoreError {
    CoreError::invalid("Google IAM plan expired, was discarded, or was already used; review a fresh plan")
}

fn changed_request() -> CoreError {
    CoreError::invalid("the exact Google request, connection, or delivery decision changed; review it again")
}

fn ready_missing() -> CoreError {
    CoreError::vault_unavailable("this exact Google project and permission profile is not ready; review IAM and approve in the manager")
}

fn project_roles(access: &GcloudAccessRequest) -> Vec<String> {
    access.permissions.iter().map(|permission| permission.role().to_owned()).collect()
}

fn account_name(project: &str, email: &str) -> String {
    format!("projects/{project}/serviceAccounts/{email}")
}

pub(super) fn profile_get(pending: &Pending) -> Result<(&GetDetail, &GeneratorTarget, &GcloudAccessRequest)> {
    let Detail::Get(get) = &pending.detail else { return Err(changed_request()) };
    let GetTarget::Generated(target) = &get.target else { return Err(changed_request()) };
    let Some(GenerationRequest::GcloudAccess(access)) = &target.requested_generation else {
        return Err(changed_request());
    };
    Ok((get, target, access))
}

fn resource_error(error: CoreError, email: &str, unique_id: Option<&str>) -> CoreError {
    let instructions = match unique_id {
        Some(id) => format!("Google resource: {email} (immutable ID {id}). {CLEANUP} ASM will not repair recorded bindings automatically."),
        None => format!("Google may have created {email}. {CLEANUP_UNKNOWN} A new review uses a different name."),
    };
    CoreError::new(error.code, format!("{}. {instructions}", error.message.trim_end_matches('.')))
}

impl Core {
    /// Use under generation authorization; only a Ready, locally managed exact tuple
    /// can become issued authority. The mint path separately verifies live Google IAM.
    pub(crate) fn ready_gcloud_access_locked(
        &self, generator: &GeneratorRecord, access: &GcloudAccessRequest,
    ) -> Result<GcloudAccessGrant> {
        let GeneratorConfig::GcloudConnection(config) = &generator.config else {
            return Err(changed_request());
        };
        let profile = self.store.gcloud_profile_for(&generator.id, &config.account_subject, access)?.filter(|profile| {
            profile.phase == GcloudProfilePhase::Ready && profile.admin_email == config.account_email
        }).ok_or_else(ready_missing)?;
        let unique_id = profile.unique_id.ok_or_else(ready_missing)?;
        self.check_gcloud_account_not_retired(&unique_id)?;
        Ok(GcloudAccessGrant::Issued {
            access: access.clone(),
            service_account_unique_id: unique_id,
            service_account_email: gcloud_profile_email(&access.project_id, &profile.account_id),
        })
    }

    /// Administrative review only: read current identity/evidence; do not change either
    /// Google or durable profile state. Paired hosts never call this function.
    pub(crate) fn gcloud_profile_plan(
        &self, request_id: String, decision: Decision,
    ) -> Result<GcloudProfilePlan> {
        let decision = ProfileDecision::parse(decision)?;
        let generator_id = decision.selection.generator_id;
        let revision = decision.selection.generator_revision;
        let GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: selected }) = decision.selection.grant else {
            return Err(changed_request());
        };
        let (context, entry, previous, delivery) = self.with_profile_request(
            &request_id, &generator_id, revision, false, |pending, entry| {
                let GeneratorConfig::GcloudConnection(config) = &entry.record.config else {
                    return Err(changed_request());
                };
                let (get, target, access) = profile_get(pending)?;
                if !target.allows_reviewed_gcloud_access(&selected) {
                    return Err(changed_request());
                }
                self.validate_gcloud_selected_project_locked(pending, entry, &selected.project_id)?;
                let delivery = GeneratedApproval::new(get, decision.mode, decision.duration_secs, &decision.hosts)?;
                let key = GcloudProfileKey {
                    generator_id: generator_id.clone(), account_subject: config.account_subject.clone(), access: selected,
                };
                GcloudProfiles::ensure_available(&lock(&self.gcloud_profiles.state), &key)?;
                let previous = self.store.gcloud_profile(&key)?;
                let context = ProfileContext {
                    request_id: request_id.clone(), host_id: pending.host_id.clone().ok_or_else(changed_request)?,
                    request_expires: pending.expires, requested_name: target.requested_name.clone(),
                    requested_mode: get.mode, wanted_fields: get.wanted_fields.clone(),
                    requested_access: access.clone(), operator_selected_grant: target.operator_selected_grant,
                    operator_selected_gcloud_project: target.operator_selected_gcloud_project,
                    revision, key, admin_email: config.account_email.clone(),
                    client: Arc::downgrade(&entry.client()?),
                };
                Ok((context, entry.clone(), previous, delivery))
            },
        )?;
        let known = previous.as_ref().filter(|p| p.unique_id.is_some());
        let ready = known.is_some_and(|p| p.phase == GcloudProfilePhase::Ready);
        let account_id = known.map_or_else(|| format!("asm-{}", hex_encode(&random_bytes::<12>())), |p| p.account_id.clone());
        let email = gcloud_profile_email(&context.key.access.project_id, &account_id);
        let unique_id = known.and_then(|p| p.unique_id.as_deref());
        let access = &context.key.access;
        self.with_gcloud_connection_parent(&entry, |http, token, identity| {
            context.check_identity(identity)?;
            if let Some((profile, id)) = known.zip(unique_id) {
                Self::verify_recorded_profile(http, token, access, profile, id, &email, identity)
                    .map_err(|e| resource_error(e, &email, Some(id)))?;
            }
            Ok(())
        })?;

        let mut messages = Vec::new();
        if !ready && known.is_some() {
            messages.push("This is a partial attempt. Approval verifies completed steps and applies only the reviewed remaining bindings to the same immutable account. Drift in completed steps stops provisioning.".into());
        } else if let Some(unverified) = previous.as_ref().filter(|p| p.unique_id.is_none()) {
            let old = gcloud_profile_email(&access.project_id, &unverified.account_id);
            messages.push(format!("An earlier creation of {old} did not return a recorded immutable ID. Check that resource and its creation audit logs before cleanup. This review is for a different account; ASM never adopts the old name."));
        }
        let mut review = GcloudProfilePlan {
            plan_id: None, expires_at: None, ready, project_id: access.project_id.clone(),
            service_account_name: account_name(&access.project_id, &email), service_account_email: email,
            service_account_unique_id: unique_id.map(str::to_owned), project_roles: project_roles(access),
            scopes: access.scopes(), service_account_role: TOKEN_CREATOR.into(),
            admin_principal: format!("user:{}", context.admin_email), messages,
        };
        // Build the opaque capability only after all I/O and rechecking the original
        // pending request, client and durable profile snapshot under authorization.
        (review.plan_id, review.expires_at) = self.with_profile_request(&request_id, &generator_id, revision, false, |pending, entry| {
            let project_evidence_expires = context.check_selection(self, pending, entry)?;
            if self.store.gcloud_profile(&context.key)? != previous {
                return Err(changed_request());
            }
            let now = self.generation_now();
            let expires = pending.expires.min(now.saturating_add(PLAN_LIFETIME_SECS))
                .min(project_evidence_expires.unwrap_or(i64::MAX));
            if expires <= now {
                return Err(stale_plan());
            }
            let id = self.gcloud_profiles.publish(now, Plan {
                context, delivery, expires, account_id, previous,
            })?;
            Ok((Some(id), Some(expires)))
        })?;
        Ok(review)
    }

    pub(crate) fn gcloud_cancel_profile(&self, plan_id: String) -> Result<()> {
        lock(&self.gcloud_profiles.state).plans.remove(&plan_id);
        Ok(())
    }

    /// The reviewed Approve action claims the original request before any IAM
    /// write. Denial, cancellation and revocation can still fence later writes
    /// and delivery. No other approval can take over the claimed request.
    pub(crate) fn gcloud_approve_profile(&self, request_id: &str, plan_id: &str, decision: Decision) -> Result<()> {
        let plan = self.gcloud_profiles.take(plan_id, self.generation_now())?;
        if plan.context.request_id != request_id {
            return Err(changed_request());
        }
        let decision = ProfileDecision::parse(decision)?;
        let context = &plan.context;
        let flight = self.gcloud_profiles.start(&context.key)?;
        let (pending, entry, delivery) = self.with_profile_request(request_id, &context.key.generator_id, context.revision, false, |pending, entry| {
            context.check_selection(self, pending, entry)?;
            let (detail, _, _) = profile_get(pending)?;
            let delivery = GeneratedApproval::new(detail, decision.mode, decision.duration_secs, &decision.hosts)?;
            if decision.selection.generator_id != context.key.generator_id
                || decision.selection.generator_revision != context.revision
                || !matches!(&decision.selection.grant, GenerationGrant::GcloudAccess(
                    GcloudAccessGrant::Requested { access }) if access == &context.key.access)
                || delivery != plan.delivery || self.store.gcloud_profile(&context.key)? != plan.previous
            {
                return Err(changed_request());
            }
            if plan.expires <= self.generation_now() {
                return Err(stale_plan());
            }
            pending.resolving = true;
            Ok((pending.clone(), entry.clone(), delivery))
        })?;
        let outcome = (|| {
            let issued = self.with_gcloud_connection_parent(&entry, |http, token, identity| {
                self.provision_reviewed_profile(&plan, http, token, identity)
            })?;
            let (detail, _, _) = profile_get(&pending)?;
            let reviewed = ReviewedGcloudProfile { plan: &plan, issued };
            self.approve_generated_get(&pending, detail, delivery, decision.selection, Some(&reviewed))
                .map(|_| ())
                .map_err(|failure| {
                    let error = match failure {
                        Fail::Keep(error) => error,
                        Fail::Deny(reason) => CoreError::vault_unavailable(reason),
                    };
                    let iam_status = if plan.previous.as_ref().is_some_and(|p| p.phase == GcloudProfilePhase::Ready) {
                        "No Google IAM changes were made."
                    } else {
                        "Google IAM changes remain."
                    };
                    CoreError::new(error.code, format!(
                        "The exact Google IAM profile is ready, but no lease was approved: {}. {iam_status} If this request is still open, review it and explicitly approve again.",
                        error.message.trim_end_matches('.'),
                    ))
                })
        })();
        drop(flight);
        self.notify(TOPIC_GCLOUD_ACCOUNTS);
        if let Err(error) = &outcome {
            self.keep_request_pending(request_id, error);
        }
        outcome
    }

    fn provision_reviewed_profile(
        &self, plan: &Plan, http: &GcloudHttp, token: &str, identity: &GcloudIdentity,
    ) -> Result<GcloudAccessGrant> {
        plan.check_identity(identity)?;
        let context = &plan.context;
        let key = &context.key;
        let access = &key.access;
        let email = plan.email();
        let mut id = plan.previous.as_ref().and_then(|p| p.unique_id.clone());
        let mut attempted = false;
        let result = (|| -> Result<()> {
            self.with_live_profile_plan(plan, |_| {
                if self.store.gcloud_profile(key)? != plan.previous {
                    return Err(changed_request());
                }
                Ok(())
            })?;
            let mut phase = if let Some((previous, unique_id)) = plan.previous.as_ref().zip(id.as_deref()) {
                Self::verify_recorded_profile(http, token, access, previous, unique_id, &email, identity)?;
                previous.phase
            } else {
                self.with_live_profile_plan(plan, |_| {
                    self.store.begin_gcloud_profile(
                        key, &plan.account_id, &context.admin_email, plan.previous.as_ref().map(|p| p.account_id.as_str()),
                    )?;
                    self.log_profile_resource(
                        "gcloud_profile_create", "Google service account creation approved; resource might remain in Google Cloud",
                        context, &email, None, None,
                    );
                    Ok(())
                })?;
                attempted = true;
                let created = http.create_profile_account(token, &access.project_id, &plan.account_id)?;
                if created.email != email {
                    return Err(CoreError::vault_unavailable("Google creation did not return the exact reviewed service account"));
                }
                // A provider response is cleanup evidence, even when revocation/
                // expiry races it. No policy write happens before it is durable.
                id = Some(created.unique_id);
                self.store.record_gcloud_profile_identity(key, &plan.account_id, id.as_deref().ok_or_else(ready_missing)?)?;
                self.notify(TOPIC_GCLOUD_ACCOUNTS);
                GcloudProfilePhase::Created
            };
            let id = id.as_deref().ok_or_else(ready_missing)?;
            if phase == GcloudProfilePhase::Created {
                self.with_live_profile_plan(plan, |_| Ok(()))?;
                http.apply_profile_project_roles(token, access, id, &email, || {
                    plan.check_identity(&http.identity(token)?)?;
                    self.with_live_profile_plan(plan, |_| Ok(()))
                })?;
                self.store.mark_gcloud_profile_project_bound(key, &plan.account_id, id)?;
                self.notify(TOPIC_GCLOUD_ACCOUNTS);
                phase = GcloudProfilePhase::ProjectBound;
            }
            if phase == GcloudProfilePhase::ProjectBound {
                self.with_live_profile_plan(plan, |_| Ok(()))?;
                http.verify_profile_project_roles(token, access, id, &email)?;
                http.apply_profile_token_creator(token, &access.project_id, id, &email, identity, || {
                    self.with_live_profile_plan(plan, |_| Ok(()))
                })?;
                self.store.mark_gcloud_profile_token_creator_bound(key, &plan.account_id, id)?;
                self.notify(TOPIC_GCLOUD_ACCOUNTS);
                phase = GcloudProfilePhase::TokenCreatorBound;
            }
            if phase != GcloudProfilePhase::Ready {
                self.with_live_profile_plan(plan, |_| Ok(()))?;
                http.verify_profile_ready(token, access, id, &email, identity)?;
                plan.check_identity(&http.identity(token)?)?;
                self.with_live_profile_plan(plan, |_| self.store.mark_gcloud_profile_ready(key, &plan.account_id, id))?;
                self.notify(TOPIC_GCLOUD_ACCOUNTS);
                self.log_profile_resource("gcloud_profile_ready", "Exact Google IAM profile ready", context, &email, Some(id), None);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                let id = id.ok_or_else(ready_missing)?;
                Ok(GcloudAccessGrant::Issued { access: access.clone(), service_account_unique_id: id, service_account_email: email })
            }
            Err(error) if attempted || id.is_some() => {
                let error = resource_error(error, &email, id.as_deref());
                self.log_profile_resource("gcloud_profile_paused", "Google IAM provisioning stopped; no lease approved. Verify cloud cleanup or review again", context, &email, id.as_deref(), Some(&error.message));
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_recorded_profile(
        http: &GcloudHttp, token: &str, access: &GcloudAccessRequest, profile: &GcloudProfileRecord,
        id: &str, email: &str, identity: &GcloudIdentity,
    ) -> Result<()> {
        if profile.admin_email != identity.email {
            return Err(CoreError::unauthorized("the verified Google email no longer matches the reviewed IAM principal; use a new connection after reviewing cleanup"));
        }
        match profile.phase {
            GcloudProfilePhase::Creating => Err(ready_missing()),
            GcloudProfilePhase::Created => http.verify_profile_account(token, &access.project_id, id, email),
            GcloudProfilePhase::ProjectBound => http.verify_profile_project_roles(token, access, id, email),
            GcloudProfilePhase::TokenCreatorBound | GcloudProfilePhase::Ready =>
                http.verify_profile_ready(token, access, id, email, identity),
        }
    }

    fn with_live_profile_plan<T>(&self, plan: &Plan, operation: impl FnOnce(&GeneratorEntry) -> Result<T>) -> Result<T> {
        let context = &plan.context;
        self.with_profile_request(&context.request_id, &context.key.generator_id, context.revision, true, |pending, entry| {
            context.check_selection(self, pending, entry)?;
            if plan.expires <= self.generation_now() {
                return Err(stale_plan());
            }
            operation(entry)
        })
    }

    /// Hold authorization and the pending book only for local checks or journal
    /// updates. A write gate that observes a concurrent denial cannot proceed.
    pub(super) fn with_profile_request<T>(
        &self, request_id: &str, generator_id: &str, revision: u64, resolving: bool,
        operation: impl FnOnce(&mut Pending, &GeneratorEntry) -> Result<T>,
    ) -> Result<T> {
        let _authority = lock(&self.authorization);
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        let now = self.generation_now();
        let mut book = lock(&self.book);
        let pending = book.pending.iter_mut().find(|p| p.id == request_id && p.resolving == resolving && p.expires > now)
            .ok_or_else(|| CoreError::invalid("this Google request is no longer open for IAM approval"))?;
        let (_, target, access) = profile_get(pending)?;
        access.validate()?;
        if target.output_name != GCLOUD_TOKEN_NAME
            || target.pinned_generator_id.as_deref().is_some_and(|id| id != generator_id)
            || !target.candidates.iter().any(|c| {
                c.generator_id == generator_id && c.revision == revision && c.available
                    && matches!(&c.ceiling, GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: choice }) if choice == access)
            })
        {
            return Err(changed_request());
        }
        let host_id = pending.host_id.as_deref().ok_or_else(changed_request)?;
        self.store.get_host(host_id)?.filter(|h| h.revoked_at.is_none())
            .ok_or_else(|| CoreError::unauthorized("host was revoked"))?;
        self.generators.with_entry(generator_id, |entry| {
            if entry.record.revision != revision {
                return Err(changed_request());
            }
            operation(pending, entry)
        }).ok_or_else(changed_request)?
    }

    fn log_profile_resource(
        &self, kind: &'static str, summary: &str, context: &ProfileContext, email: &str,
        id: Option<&str>, message: Option<&str>,
    ) {
        self.log(Event::new(Category::Generators, kind, format!("{summary}: {email}"))
            .host(Some(&context.host_id)).detail(json!({
                "request_id": context.request_id, "generator_id": context.key.generator_id,
                "requested_project": context.requested_access.project_id,
                "project": context.key.access.project_id, "service_account_email": email, "service_account_unique_id": id,
                "project_roles": project_roles(&context.key.access), "project_member": format!("serviceAccount:{email}"),
                "service_account_role": TOKEN_CREATOR, "service_account_member": format!("user:{}", context.admin_email),
                "status": message, "cleanup": if id.is_some() { CLEANUP } else { CLEANUP_UNKNOWN },
            })));
    }

    /// Removal or changed verified principal never deletes cloud resources and never
    /// turns formerly managed resources into name-adoptable candidates.
    pub(crate) fn publish_gcloud_profile_cleanup(&self, generator: &GeneratorRecord) {
        let GeneratorConfig::GcloudConnection(config) = &generator.config else { return };
        lock(&self.gcloud_profiles.state).plans.retain(|_, plan| {
            plan.context.key.generator_id != generator.id || plan.context.revision != generator.revision
        });
        match self.store.gcloud_profile_cleanup_resources(&generator.id, &config.account_subject, &config.account_email) {
            Ok(resources) => for (access, account, id) in resources {
                let email = gcloud_profile_email(&access.project_id, &account);
                self.log(Event::new(Category::Generators, "gcloud_profile_cleanup", format!("Google IAM resource may remain after disconnect: {email}"))
                    .detail(json!({ "generator_id": generator.id, "project": access.project_id,
                        "service_account_email": email, "service_account_unique_id": id,
                        "project_roles": project_roles(&access), "project_member": format!("serviceAccount:{email}"),
                        "service_account_role": TOKEN_CREATOR, "service_account_member": format!("user:{}", config.account_email),
                        "cleanup": if id.is_some() { CLEANUP } else { CLEANUP_UNKNOWN },
                    })));
            },
            Err(e) => self.log(Event::new(Category::Generators, "gcloud_profile_cleanup", "Could not read Google IAM cleanup inventory; consult prior provisioning activity and Google Cloud audit logs")
                .detail(json!({ "generator_id": generator.id, "status": e.message }))),
        }
        self.notify(TOPIC_GCLOUD_ACCOUNTS);
    }
}

#[cfg(test)]
#[path = "gcloud_profiles_tests.rs"]
mod tests;
