//! `asm list`, `get`, `update`, `add`: listing secrets and the request/approval flow.

use crate::api::Api;
use crate::error::{CliError, RERUN_TO_PICK_UP};
use crate::files::{FileBinding, SecretsDir};
use crate::state::{self, HostState};
use asm_proto::error::ErrorCode;
use asm_proto::generators::{
    GCLOUD_TOKEN_NAME, GITHUB_TOKEN_ALIAS, GITHUB_TOKEN_NAME, GcloudAccessGrant, GcloudAccessRequest,
    GcloudPermission, GcloudScopeRequest, GenerationGrant, GenerationRequest, GenerationSelection,
    GithubPermission, GithubScopeRequest,
};
use asm_proto::names::{canonical_generated_output, generated_output};
use asm_proto::wire::{
    CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1,
    GetResult, LeaseMode, LeaseStatus, LeasesResponse, MAX_POLL_WAIT_SECS, RequestBody,
    RequestResult, RequestState, RequestStatus, SecretsResponse, WriteResult,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A paired session: host state, API client, and (when usable) the secrets directory
/// after the expiry cleanup every command except `pair` performs.
pub struct Session {
    pub host: HostState,
    pub api: Api,
    pub secrets: Result<SecretsDir, CliError>,
}

impl Session {
    /// Load `host.json` and delete the files of leases past expiry.
    pub fn open() -> Result<Self, CliError> {
        let host = state::require()?;
        let api = Api::for_host(&host)?;
        let secrets = SecretsDir::open_default().and_then(|d| d.remove_expired().map(|()| d));
        Ok(Session { host, api, secrets })
    }

    /// The secrets directory, or its error (fatal for `get`).
    pub fn secrets_dir(&self) -> Result<&SecretsDir, CliError> {
        self.secrets.as_ref().map_err(Clone::clone)
    }

    /// Print a secrets-directory problem as a warning (commands that do not need it).
    pub fn warn_secrets(&self) {
        if let Err(e) = &self.secrets {
            eprintln!("warning: secrets directory: {}", e.message);
        }
    }

    /// `GET /leases`; delete the files of leases no longer reported active, then make
    /// sure a background reaper removes the remaining ones when they end.
    pub fn sync_leases(&self) -> Result<LeasesResponse, CliError> {
        let result = self.api.get("/leases").and_then(|leases: LeasesResponse| {
            if let Ok(dir) = &self.secrets {
                let active: HashSet<String> = leases
                    .leases
                    .iter()
                    .filter(|l| l.status == LeaseStatus::Active)
                    .map(|l| l.lease_id.clone())
                    .collect();
                dir.reconcile(&active)?;
            }
            Ok(leases)
        });
        if let Ok(dir) = &self.secrets {
            crate::reaper::ensure_running(dir);
        }
        result
    }
}

pub fn list(json: bool) -> Result<(), CliError> {
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = s.api.get_bytes("/secrets")?;
    let parsed: SecretsResponse = serde_json::from_slice(&body)
        .map_err(|e| CliError::failure(format!("unexpected answer from the manager: {e}")))?;
    for w in &parsed.warnings {
        eprintln!("warning: {w}");
    }
    let mut out = std::io::stdout().lock();
    if json {
        let _ = out.write_all(&body);
        let _ = out.write_all(b"\n");
    } else {
        let mut printed = HashSet::new();
        for secret in &parsed.secrets {
            for name in std::iter::once(&secret.name).chain(secret.aliases.iter()) {
                if printed.insert(name) {
                    let _ = writeln!(out, "{name}");
                }
            }
        }
    }
    Ok(())
}

/// Parse `--hosts a,b` values (already split on commas) into normalised patterns.
pub(crate) fn parse_hosts(hosts: &[String]) -> Result<Vec<String>, CliError> {
    let raw: Vec<&str> = hosts
        .iter()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .collect();
    Ok(asm_proto::rules::normalize_host_patterns(&raw)?)
}

fn check_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() {
        return Err(CliError::invalid("secret name is empty"));
    }
    asm_proto::rules::validate_agent_text("secret name", name)?;
    Ok(())
}

/// Waited past the manager's expiry before giving up on an unreachable manager.
const EXPIRY_MARGIN: Duration = Duration::from_secs(15);
/// Wait when the manager does not say when a request expires (older managers).
const FALLBACK_WAIT: Duration = Duration::from_secs(600);
/// Longest pause between retries while the manager is unreachable.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// How long, from now, the manager keeps a pending request (plus a margin): from its
/// `expires_at`, bounded by its lifetime (`0` = not sent). A request that is pending
/// cannot already be past its expiry nor outlive its lifetime; such a value means the two
/// clocks differ, and the lifetime is used instead. Neither sent → 600 s.
pub fn pending_window(expires_at: Option<&str>, lifetime_secs: u64, now: i64) -> Duration {
    let left = expires_at
        .and_then(asm_proto::time::parse_unix)
        .map(|e| e - now)
        .filter(|l| *l > 0)
        .map(|l| l as u64);
    let secs = match (left, lifetime_secs) {
        (Some(l), 0) => l,
        (Some(l), max) if l <= max => l,
        (_, 0) => return FALLBACK_WAIT,
        (_, max) => max,
    };
    Duration::from_secs(secs) + EXPIRY_MARGIN
}

/// `"10 minutes"`, `"1 minute"`, `"90 seconds"`.
fn fmt_lifetime(secs: u64) -> String {
    match secs {
        60 => "1 minute".to_owned(),
        s if s % 60 == 0 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

/// Retry pacing while the manager is unreachable: 1 s, doubling, at most 30 s.
pub struct Backoff(Duration);

impl Backoff {
    pub fn new() -> Self {
        Backoff(Duration::from_secs(1))
    }

    pub fn reset(&mut self) {
        self.0 = Duration::from_secs(1);
    }

    /// Sleep before the next attempt, never past `until`; `false` once `until` has passed.
    pub fn wait(&mut self, until: Instant) -> bool {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(self.0.min(left));
        self.0 = (self.0 * 2).min(MAX_BACKOFF);
        true
    }
}

/// Submit without filesystem side effects. One deadline covers POST, polling and backoff.
fn submit(
    api: &Api,
    body: &RequestBody,
    deadline: Option<Instant>,
) -> Result<(RequestResult, bool), CliError> {
    let started = Instant::now();
    let mut state: RequestState = api.post_until("/requests", body, deadline)?;
    if !asm_proto::crypto::is_uuid(&state.request_id) {
        return Err(CliError::failure("the manager sent an invalid request id"));
    }
    let was_pending = state.status == RequestStatus::Pending;
    let lifetime = state.pending_lifetime_secs;
    let expected = started
        + pending_window(
            state.expires_at.as_deref(),
            state.pending_lifetime_secs,
            unix_now(),
        );
    let hard = deadline;
    let retry_until = hard.map_or(expected, |h| h.min(expected));
    let mut backoff = Backoff::new();
    // The last connection error, while the manager is unreachable.
    let mut last_error: Option<String> = None;
    while state.status == RequestStatus::Pending {
        let now = Instant::now();
        let secs = match hard {
            Some(h) if now >= h => {
                return Err(match last_error {
                    Some(msg) => CliError::lost_contact(&msg, RERUN_TO_PICK_UP),
                    None => CliError::pending(),
                });
            }
            Some(h) => {
                (h.duration_since(now).as_secs_f64().ceil() as u64).clamp(1, MAX_POLL_WAIT_SECS)
            }
            None => MAX_POLL_WAIT_SECS,
        };
        let polled = Instant::now();
        match api.get_until::<RequestState>(&format!("/requests/{}?wait={secs}", state.request_id), hard) {
            Ok(s) => {
                if s.request_id != state.request_id {
                    return Err(CliError::failure("the manager returned a decision for a different request"));
                }
                state = s;
                backoff.reset();
                last_error = None;
                if state.status == RequestStatus::Pending {
                    let until = hard.unwrap_or(expected);
                    std::thread::sleep(Duration::from_secs(1).saturating_sub(polled.elapsed()).min(until.saturating_duration_since(Instant::now())));
                }
            }
            Err(e) if e.exit == asm_proto::error::EXIT_PENDING => return Err(CliError::pending()),
            Err(e) if e.code == Some(ErrorCode::NotFound) => return Err(CliError::request_lost()),
            Err(e) if e.transient => {
                if !backoff.wait(retry_until) {
                    return Err(CliError::lost_contact(&e.message, RERUN_TO_PICK_UP));
                }
                last_error = Some(e.message);
            }
            Err(e) => return Err(e),
        }
    }
    match state.status {
        RequestStatus::Approved => state.result.map(|result| (result, was_pending)).ok_or_else(|| {
            CliError::failure("the manager approved the request but sent no result")
        }),
        RequestStatus::Denied => Err(CliError::denied(state.deny_reason.as_deref())),
        RequestStatus::Expired => {
            let lifetime = match state.pending_lifetime_secs {
                0 => lifetime,
                l => l,
            };
            Err(CliError::ended(match lifetime {
                0 => "expired: the request was not answered in time".to_owned(),
                l => format!("expired: no decision within {}", fmt_lifetime(l)),
            }))
        }
        RequestStatus::Cancelled => Err(CliError::ended("cancelled: the request was cancelled")),
        RequestStatus::Pending => unreachable!("loop exits only on a terminal status"),
    }
}

pub(crate) fn submit_get(
    api: &Api, body: &RequestBody, deadline: Option<Instant>, pinned: Option<&GenerationSelection>,
    capabilities: crate::bindings::GetCapabilities,
) -> Result<GetResult, CliError> {
    let (result, was_pending) = submit(api, body, deadline)?;
    let result = match result {
        RequestResult::Get(result) => result,
        RequestResult::Write(_) => return Err(CliError::failure("the manager sent a write result for a get")),
    };
    let RequestBody::Get { fields, generation, sentinel, lease_id, .. } = body else {
        return Err(CliError::failure("invalid get request"));
    };
    let actual: HashSet<&str> = result.files.iter().map(|f| f.field.as_str()).collect();
    if !asm_proto::crypto::is_uuid(&result.lease_id)
        || result.files.is_empty()
        || actual.len() != result.files.len()
        || fields.as_ref().is_some_and(|wanted| wanted.len() != actual.len() || wanted.iter().any(|f| !actual.contains(f.as_str())))
        || lease_id.as_ref().is_some_and(|id| id != &result.lease_id)
        || lease_id.is_some() != pinned.is_some()
        || (*sentinel && result.mode != LeaseMode::Sentinel)
        || (result.mode == LeaseMode::Raw && result.files.iter().any(|f| f.substituted))
    {
        return Err(CliError::failure("the manager sent an inconsistent get result"));
    }
    if result.expires_at.as_deref().is_some_and(|expiry| asm_proto::time::parse_unix(expiry).is_none_or(|t| t <= unix_now())) {
        return Err(CliError::failure("the manager sent an invalid or ended lease"));
    }
    if result.validate().is_err() || (result.generation.is_some()
        && result.credential_expires_at.as_deref().and_then(asm_proto::time::parse_unix).is_none_or(|t| t <= unix_now()))
    {
        return Err(CliError::failure("the manager sent invalid generated credential metadata"));
    }
    if let Some(pinned) = pinned {
        if result.generation.as_ref() != Some(pinned) {
            return Err(CliError::failure("the manager changed the pinned generated credential grant"));
        }
        if result.operator_selected_grant {
            return Err(CliError::failure("the manager returned a fresh approval for a pinned lease"));
        }
        return Ok(result);
    }
    let operator_selected = result.operator_selected_grant
        && capabilities.operator_selected_grant && body.supports_operator_selected_grant();
    // Immediate results may reuse a lease, even when no lease ID was pinned.
    let operator_selected_project = was_pending && result.operator_selected_grant
        && capabilities.operator_selected_project && body.supports_operator_selected_project();
    match (generation, result.generation.as_ref().map(|selection| &selection.grant)) {
        (Some(request), Some(grant)) if grant.matches_request_exactly(request)?
            || (operator_selected && grant.can_select_for(request))
            || (operator_selected_project && grant.can_switch_project_for(request, operator_selected)) => {}
        // Legacy bound Google approvals already allowed edited OAuth scopes
        // before this capability existed. A capable manager must mark edits.
        (Some(GenerationRequest::Gcloud(_)), Some(GenerationGrant::Gcloud(_)))
            if !capabilities.operator_selected_grant => {}
        (Some(GenerationRequest::GcloudAccess(_)), _) => {
            return Err(CliError::failure("the manager did not approve the exact Google Cloud project and permissions or return a negotiated operator selection"));
        }
        (Some(request), Some(grant)) if grant.can_select_for(request) => {
            return Err(CliError::failure("the manager did not approve the exact requested grant or return a negotiated operator selection"));
        }
        (None, None) => {}
        _ => return Err(CliError::failure("the manager sent a result for a different credential source")),
    }
    Ok(result)
}

/// Managed renewal repeats the exact claims from the previously validated
/// lease, so callers need only its ID and never reconstruct authority.
pub(crate) fn replay_managed_claims(pinned: Option<&GenerationSelection>) -> Option<GenerationRequest> {
    match pinned.map(|selection| &selection.grant) {
        Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { access, .. })) =>
            Some(GenerationRequest::GcloudAccess(access.clone())),
        _ => None,
    }
}

pub(crate) fn deadline(wait: Option<u64>) -> Option<Instant> {
    wait.map(|seconds| Instant::now() + Duration::from_secs(seconds))
}

/// Keep at least one second between polls when the manager answers a long poll early.
pub fn pace(started: Instant) {
    if let Some(rest) = Duration::from_secs(1).checked_sub(started.elapsed()) {
        std::thread::sleep(rest);
    }
}

#[derive(Serialize)]
struct JsonFile<'a> {
    field: &'a str,
    relative_path: &'a str,
    path: &'a PathBuf,
}

#[derive(Serialize)]
struct JsonGet<'a> {
    lease_id: &'a str,
    mode: LeaseMode,
    hosts: &'a [String],
    expires_at: &'a Option<String>,
    generation: &'a Option<asm_proto::generators::GenerationSelection>,
    generator_name: &'a Option<String>,
    credential_expires_at: &'a Option<String>,
    credential_version: Option<u64>,
    files: Vec<JsonFile<'a>>,
}

#[derive(clap::Args)]
pub(crate) struct GenerationArgs {
    /// Explicit GitHub owner/repo names; repeat or separate with commas.
    #[arg(long, value_name = "OWNER/REPO", value_delimiter = ',')]
    repositories: Vec<String>,
    /// Google Cloud project ID; conflicts with --repositories and --gcloud-scope.
    /// A compatible manager can let the operator select a different project on fresh approval.
    #[arg(long, value_name = "ID", requires = "permissions", conflicts_with_all = ["repositories", "gcloud_scopes"])]
    project: Option<String>,
    /// GitHub KEY=LEVEL with --repositories, or Google claims (e.g. storage=read) with --project.
    /// Repeat or separate with commas. GitHub defaults to metadata=read; Google claims are required.
    /// A compatible manager can let the operator approve a different set of claims.
    #[arg(long, value_name = "CLAIM", value_delimiter = ',')]
    permissions: Vec<String>,
}

pub(crate) fn github_repositories_required() -> CliError {
    CliError::invalid("generated GitHub credentials require --repositories OWNER/REPO")
}

pub(crate) fn gcloud_access_required() -> CliError {
    CliError::invalid("generated Google Cloud credentials require --project ID --permissions CLAIM (or --gcloud-scope URI for a legacy bound generator)")
}

pub(crate) struct GenerationSelectors {
    pub github: Option<GenerationRequest>,
    pub google: Option<GenerationRequest>,
}

impl GenerationSelectors {
    pub(crate) fn capability(&self) -> Option<&'static str> {
        if matches!(&self.google, Some(GenerationRequest::GcloudAccess(_))) {
            Some(CAPABILITY_GCLOUD_ACCESS_V1)
        } else if self.github.is_some() {
            Some(CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1)
        } else {
            None
        }
    }
}

impl GenerationArgs {
    pub(crate) fn into_selectors(self, gcloud_scopes: Vec<String>) -> Result<GenerationSelectors, CliError> {
        if let Some(project_id) = self.project {
            let mut permissions = Vec::with_capacity(self.permissions.len());
            for claim in &self.permissions {
                let permission = GcloudPermission::from_claim(claim)
                    .ok_or_else(|| CliError::invalid(
                        "unknown Google Cloud permission claim; use storage=read, storage=create, compute=read, run=read, logs=read or bigquery=metadata-read"
                    ))?;
                permissions.push(permission);
            }
            let mut access = GcloudAccessRequest { project_id, permissions };
            access.canonicalize()?;
            return Ok(GenerationSelectors { github: None, google: Some(GenerationRequest::GcloudAccess(access)) });
        }
        let google = if gcloud_scopes.is_empty() {
            None
        } else {
            let mut request = GenerationRequest::Gcloud(GcloudScopeRequest { scopes: Some(gcloud_scopes) });
            request.canonicalize()?;
            Some(request)
        };
        let github = self.github_request()?;
        Ok(GenerationSelectors { github, google })
    }

    fn github_request(self) -> Result<Option<GenerationRequest>, CliError> {
        if self.repositories.is_empty() {
            return if self.permissions.is_empty() { Ok(None) } else { Err(github_repositories_required()) };
        }
        let mut permissions = BTreeMap::new();
        for item in self.permissions {
            let invalid = || CliError::invalid("permissions must be KEY=read|write|admin");
            let (key, level) = item.trim().split_once('=').ok_or_else(invalid)?;
            let level = match level {
                "read" => GithubPermission::Read,
                "write" => GithubPermission::Write,
                "admin" => GithubPermission::Admin,
                _ => return Err(invalid()),
            };
            if permissions.insert(key.to_owned(), level).is_some() {
                return Err(CliError::invalid("duplicate permission key"));
            }
        }
        let mut request = GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(self.repositories),
            permissions: Some(permissions),
        });
        request.canonicalize()?;
        Ok(Some(request))
    }
}

#[derive(clap::Args)]
pub struct GetArgs {
    /// Ask for raw values (the operator may choose sentinel delivery instead).
    #[arg(long, conflicts_with = "sentinel")]
    pub raw: bool,
    /// Forbid disclosure of raw substitutable values.
    #[arg(long, conflicts_with = "raw")]
    pub sentinel: bool,
    #[arg(long, value_delimiter = ',')]
    pub hosts: Vec<String>,
    /// Overall operator/acquisition wait, in seconds.
    #[arg(long)]
    pub wait: Option<u64>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub no_reaper: bool,
    #[command(flatten)]
    generation_args: GenerationArgs,
    /// Explicit OAuth scope URI for a legacy bound Google generator; repeat or separate with commas.
    #[arg(long = "gcloud-scope", value_name = "URI", value_delimiter = ',', conflicts_with_all = ["repositories", "permissions"])]
    pub gcloud_scopes: Vec<String>,
    /// Renew exactly this host-owned generated lease, without rebinding.
    #[arg(long, conflicts_with = "new_lease")]
    pub lease: Option<String>,
    /// Replace a generated token; may disrupt existing consumers.
    #[arg(long, conflicts_with = "new_lease")]
    pub refresh: bool,
    /// Ask for a new generated authorization instead of reusing one.
    #[arg(long, conflicts_with_all = ["lease", "refresh"])]
    pub new_lease: bool,
    /// [DEST=]SOURCE[::FIELD].
    pub name: String,
    /// Why you need access.
    pub reason: String,
}

pub fn get(a: GetArgs) -> Result<(), CliError> {
    let reason = asm_proto::rules::validate_reason(&a.reason)?;
    let hosts = parse_hosts(&a.hosts)?;
    let selectors = a.generation_args.into_selectors(a.gcloud_scopes)?;
    let mut capability = selectors.capability();
    let generation = selectors.github.or(selectors.google);
    let generated_flags = generation.is_some() || a.lease.is_some() || a.refresh || a.new_lease;
    let s = Session::open()?;
    let dir = s.secrets_dir()?;
    crate::bindings::require_capabilities(&s.api, generated_flags, a.sentinel || a.lease.is_some(), capability)?;
    let owned = s.sync_leases()?;
    let mut refresh_from_version = None;
    let mut pinned = None;
    let (binding, request_name, output, fields) = if let Some(id) = &a.lease {
        if !asm_proto::crypto::is_uuid(id) {
            return Err(CliError::invalid("invalid lease id"));
        }
        let binding = asm_proto::bindings::parse_binding(&a.name)?;
        let lease = owned.leases.iter().find(|l| &l.lease_id == id)
            .ok_or_else(|| CliError::from(asm_proto::error::ApiError::new(ErrorCode::NotFound, "lease not found")))?;
        let selection = lease.generation.as_ref()
            .ok_or_else(|| CliError::invalid("--lease requires a generated lease"))?;
        if selection.validate().is_err() || !selection.grant.is_issued() {
            return Err(CliError::failure("the manager sent invalid generated credential metadata"));
        }
        pinned = Some(selection);
        let managed = matches!(&selection.grant, GenerationGrant::GcloudAccess(_));
        if managed {
            capability = Some(CAPABILITY_GCLOUD_ACCESS_V1);
        }
        if let Some(request) = &generation {
            if !selection.grant.matches_request_exactly(request)? {
                let message = if managed || matches!(request, GenerationRequest::GcloudAccess(_)) {
                    "the pinned Google Cloud lease does not match the exact requested project and permissions"
                } else {
                    "the pinned generated lease does not match the exact requested grant"
                };
                return Err(CliError::invalid(message));
            }
        }
        if lease.status != LeaseStatus::Active {
            return Err(CliError::denied(Some("lease ended; request a new lease without --lease")));
        }
        if (a.raw && lease.mode != LeaseMode::Raw) || (a.sentinel && lease.mode != LeaseMode::Sentinel) {
            return Err(CliError::invalid("delivery mode conflicts with the selected lease"));
        }
        let field = binding.field.clone().or_else(|| (binding.destination.is_some() && lease.fields.len() == 1).then(|| lease.fields[0].clone()));
        if binding.destination.is_some() && field.is_none() {
            return Err(CliError::invalid(format!("select a field; available fields: {}", lease.fields.join(", "))));
        }
        if field.as_ref().is_some_and(|f| !lease.fields.contains(f)) {
            return Err(CliError::invalid("the selected field is not authorized by this lease"));
        }
        refresh_from_version = a.refresh.then_some(lease.credential_version)
            .flatten().filter(|v| *v > 0);
        if a.refresh && refresh_from_version.is_none() {
            return Err(CliError::failure("the manager sent invalid generated credential metadata"));
        }
        let name = binding.source.clone();
        (binding, name, Some(selection.grant.output_name()), field.map(|f| vec![f]))
    } else {
        let entries = crate::bindings::catalog(&s.api)?;
        let binding = asm_proto::bindings::parse_get_binding(&a.name, &entries)?;
        let resolved = crate::bindings::resolve(binding.clone(), &entries);
        match resolved {
            Ok(resolved) => {
                let fields = binding.field.clone().or_else(|| binding.destination.as_ref().map(|_| resolved.available_fields[0].clone())).map(|f| vec![f]);
                (binding, resolved.request_name, resolved.generated_output, fields)
            }
            // Whole-item static gets retain the manager's historical leased-name
            // fallback, but a generated spelling (including a hidden colliding
            // alias) must not go through it.
            Err(e) if matches!(e.code, Some(ErrorCode::NotFound | ErrorCode::Ambiguous))
                && binding.destination.is_none() && binding.field.is_none()
                && !generated_flags
                && !canonical_generated_output(&binding.source).is_some_and(|output| {
                    entries.iter().any(|entry| generated_output(entry) == Some(output))
                }) => {
                let name = binding.source.clone();
                (binding, name, None, None)
            }
            Err(e) => return Err(e),
        }
    };
    check_name(&request_name)?;
    let generated = output.is_some();
    if generated_flags && !generated {
        return Err(CliError::invalid("generation options require a generated secret"));
    }
    if let Some(request) = &generation {
        if output != Some(request.output_name()) {
            let message = match request {
                GenerationRequest::GithubApp(_) => "--repositories and --permissions require a generated GitHub secret",
                GenerationRequest::GcloudAccess(_) => "--project and --permissions require a generated Google Cloud secret",
                GenerationRequest::Gcloud(_) => "--gcloud-scope requires a legacy bound Google Cloud secret",
            };
            return Err(CliError::invalid(message));
        }
    } else if pinned.is_none() {
        match output {
            Some(GITHUB_TOKEN_NAME) => return Err(github_repositories_required()),
            Some(GCLOUD_TOKEN_NAME) => return Err(gcloud_access_required()),
            _ => {}
        }
    }
    let capabilities = crate::bindings::require_capabilities(
        &s.api,
        generated,
        fields.is_some() || a.sentinel || (generated && binding.source.ends_with(GITHUB_TOKEN_ALIAS)),
        capability,
    )?;
    let generation = generation.or_else(|| replay_managed_claims(pinned));
    let client_capabilities = capabilities.client_capabilities(generation.as_ref(), pinned.is_some());
    let mut body = RequestBody::Get {
        name: request_name,
        raw: a.raw,
        sentinel: a.sentinel,
        fields,
        generation,
        refresh: a.refresh,
        refresh_from_version,
        new_lease: a.new_lease,
        lease_id: a.lease.clone(),
        client_capabilities,
        hosts,
        reason: reason.clone(),
        agent: crate::hostinfo::agent_label(),
    };
    body.canonicalize()?;
    let result = submit_get(&s.api, &body, deadline(a.wait), pinned, capabilities)
        .map_err(|e| if e.message == CliError::acquisition_elapsed().message { CliError::pending() } else { e })?;
    let views = result.files.iter().map(|f| FileBinding {
        field: f.field.clone(),
        requested_path: binding.destination.clone().unwrap_or_else(|| if generated { binding.source.clone() } else { f.relative_path.clone() }),
    }).collect::<Vec<_>>();
    let stored = if generated || binding.destination.is_some() { dir.store_bindings(&result, &views)? } else { dir.store(&result)? };
    crate::reaper::ensure_running(dir);
    let mut out = std::io::stdout().lock();
    if a.json {
        let j = JsonGet {
            lease_id: &result.lease_id,
            mode: result.mode,
            hosts: &result.hosts,
            expires_at: &result.expires_at,
            generation: &result.generation,
            generator_name: &result.generator_name,
            credential_expires_at: &result.credential_expires_at,
            credential_version: result.credential_version,
            files: stored
                .iter()
                .map(|f| JsonFile {
                    field: &f.field,
                    relative_path: &f.relative_path,
                    path: &f.path,
                })
                .collect(),
        };
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&j).expect("serializes")
        );
    } else {
        let _ = write!(
            out,
            "{}",
            get_block(
                &result,
                &stored.iter().map(|f| f.path.clone()).collect::<Vec<_>>()
            )
        );
    }
    if let Some(selection) = &result.generation {
        let mode = if result.mode == LeaseMode::Sentinel { " --sentinel" } else { "" };
        eprintln!("refresh: asm get --lease {} --refresh{} {} {}", result.lease_id, mode, crate::bindings::shell_quote(&a.name), crate::bindings::shell_quote(&reason));
        if a.refresh {
            match &selection.grant {
                GenerationGrant::GithubApp(_) => eprintln!("warning: explicit refresh can invalidate tokens used by running consumers"),
                GenerationGrant::Gcloud(_) | GenerationGrant::GcloudAccess(_) =>
                    eprintln!("warning: previously released Google tokens may remain usable until credential expiry"),
            }
        }
    }
    Ok(())
}

/// The text block `asm get` prints.
fn get_block(r: &GetResult, paths: &[PathBuf]) -> String {
    let mode = match r.mode {
        LeaseMode::Sentinel => "sentinel",
        LeaseMode::Raw => "raw",
    };
    let hosts = match r.mode {
        LeaseMode::Raw => "none (raw value)".to_owned(),
        LeaseMode::Sentinel => r.hosts.join(","),
    };
    let expires = r.expires_at.as_deref().unwrap_or("never");
    let mut s = format!("mode: {mode}\nhosts: {hosts}\nexpires: {expires}\n");
    if let Some(generation) = &r.generation {
        s.push_str(&format!("lease: {}\ngenerator: {}\ngrant: {}\ncredential expires: {}\ncredential version: {}\n",
            r.lease_id,
            r.generator_name.as_deref().unwrap_or(&generation.generator_id),
            serde_json::to_string(&generation.grant).expect("grant serializes"),
            r.credential_expires_at.as_deref().unwrap_or("unknown"),
            r.credential_version.unwrap_or(0)));
    }
    for p in paths {
        s.push_str(&p.to_string_lossy());
        s.push('\n');
    }
    s
}

fn write_result(r: RequestResult) -> Result<WriteResult, CliError> {
    match r {
        RequestResult::Write(w) => Ok(w),
        RequestResult::Get(_) => Err(CliError::failure(
            "the manager sent a get result for a write",
        )),
    }
}

fn read_value() -> Result<String, CliError> {
    Ok(asm_proto::rules::read_secret_value(
        std::io::stdin().lock(),
    )?)
}

pub fn update(field: Option<String>, wait: Option<u64>, name: String) -> Result<(), CliError> {
    check_name(&name)?;
    let field = field.map(|f| f.trim().to_owned()).filter(|f| !f.is_empty());
    let value = read_value()?;
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = RequestBody::Update {
        name,
        field,
        value,
        agent: crate::hostinfo::agent_label(),
    };
    let (result, _) = submit(&s.api, &body, deadline(wait))?;
    let w = write_result(result)?;
    // Raw leases on this secret were revoked by the update: remove their files.
    if let Err(e) = s.sync_leases() {
        eprintln!("warning: {}", e.message);
    }
    println!("updated {} in {}", w.name, w.vault);
    Ok(())
}

pub fn add(wait: Option<u64>, name: String) -> Result<(), CliError> {
    check_name(&name)?;
    if name.contains('/') {
        return Err(CliError::invalid("a new secret name must not contain '/'"));
    }
    let value = read_value()?;
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = RequestBody::Add {
        name,
        value,
        agent: crate::hostinfo::agent_label(),
    };
    let (result, _) = submit(&s.api, &body, deadline(wait))?;
    let w = write_result(result)?;
    println!("added {} to {}; run asm get to use it", w.name, w.vault);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asm_proto::wire::ResultFile;
    use clap::{Parser, error::ErrorKind};

    const GCLOUD_NAME: &str = "CLOUDSDK_AUTH_ACCESS_TOKEN";
    const CLOUD_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
    const STORAGE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";

    fn parse_get(options: &[&str]) -> Result<GetArgs, clap::Error> {
        let args = ["asm", "get"].into_iter().chain(options.iter().copied()).chain([GCLOUD_NAME, "Read demo data"]);
        let crate::Command::Get(get) = crate::Cli::try_parse_from(args)?.command else { unreachable!() };
        Ok(get)
    }

    #[test]
    fn gcloud_scope_flags_are_repeatable_comma_delimited_and_exact() {
        let both = format!("{STORAGE_SCOPE},{CLOUD_SCOPE}");
        let get = parse_get(&["--gcloud-scope", &both, "--gcloud-scope", STORAGE_SCOPE]).unwrap();
        let generation = get.generation_args.into_selectors(get.gcloud_scopes).unwrap().google.unwrap();
        assert_eq!(serde_json::to_value(generation).unwrap(), serde_json::json!({
            "provider":"gcloud", "scope":{"scopes":[CLOUD_SCOPE, STORAGE_SCOPE]}
        }));
        let get = parse_get(&[]).unwrap();
        let selectors = get.generation_args.into_selectors(get.gcloud_scopes).unwrap();
        assert!(selectors.google.is_none() && selectors.github.is_none());
        for malformed in ["", "openid", "https://www.googleapis.com/auth/a b"] {
            let flag = format!("--gcloud-scope={malformed}");
            assert!(parse_get(&[&flag]).map_or(true, |get| get.generation_args.into_selectors(get.gcloud_scopes).is_err()));
        }
    }

    #[test]
    fn gcloud_scope_flags_conflict_with_both_github_dimensions() {
        for (flag, value) in [
            ("--repositories", "acme/repo"),
            ("--permissions", "contents=read"),
        ] {
            let Err(err) = parse_get(&[flag, value, "--gcloud-scope", STORAGE_SCOPE]) else {
                panic!("{flag} accepted conflicting gcloud scope");
            };
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn managed_google_flags_require_an_exact_selector() {
        let get = parse_get(&[
            "--project", "demo-project", "--permissions", "run=read,storage=read",
            "--permissions", "storage=read",
        ]).unwrap();
        let selectors = get.generation_args.into_selectors(get.gcloud_scopes).unwrap();
        assert!(selectors.github.is_none());
        assert_eq!(serde_json::to_value(selectors.google.unwrap()).unwrap(), serde_json::json!({
            "provider":"gcloud_access","scope":{"project_id":"demo-project","permissions":["storage=read","run=read"]}
        }));
        assert_eq!(parse_get(&["--project", "demo-project"]).err().unwrap().kind(), ErrorKind::MissingRequiredArgument);
        for conflict in [("--repositories", "acme/web"), ("--gcloud-scope", STORAGE_SCOPE)] {
            let error = parse_get(&["--project", "demo-project", "--permissions", "storage=read", conflict.0, conflict.1])
                .err().unwrap();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
        for invalid in ["storage=write", "roles/owner", CLOUD_SCOPE, "Storage=read", "", " storage=read"] {
            let parsed = parse_get(&["--project", "demo-project", "--permissions", invalid]);
            assert!(parsed.map_or(true, |get| get.generation_args.into_selectors(get.gcloud_scopes).is_err()), "{invalid:?}");
        }
    }

    #[test]
    fn obsolete_github_flags_are_not_accepted_by_get_or_exec() {
        for flag in ["--permission", "--github-permission", "--github-repositories"] {
            let value = if flag == "--github-repositories" { "acme/web" } else { "contents=read" };
            let Err(error) = parse_get(&[flag, value]) else {
                panic!("get accepted {flag}");
            };
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
            let Err(error) = crate::Cli::try_parse_from(["asm", "exec", flag, value, "GH_TOKEN", "--", "gh"]) else {
                panic!("exec accepted {flag}");
            };
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn get_block_format() {
        let mut r = GetResult {
            lease_id: "l".into(),
            mode: LeaseMode::Sentinel,
            hosts: vec!["api.github.com".into(), "*.githubusercontent.com".into()],
            expires_at: Some("2026-11-16T12:34:56Z".into()),
            generation: None,
            operator_selected_grant: false,
            credential_expires_at: None,
            credential_version: None,
            generator_name: None,
            files: vec![ResultFile {
                field: "value".into(),
                relative_path: "T".into(),
                content: "x".into(),
                substituted: false,
            }],
        };
        let p = vec![PathBuf::from("/run/user/1000/asm/secrets/GITHUB_TOKEN")];
        assert_eq!(
            get_block(&r, &p),
            "mode: sentinel\nhosts: api.github.com,*.githubusercontent.com\nexpires: 2026-11-16T12:34:56Z\n/run/user/1000/asm/secrets/GITHUB_TOKEN\n"
        );
        r.mode = LeaseMode::Raw;
        r.hosts.clear();
        r.expires_at = None;
        assert_eq!(
            get_block(&r, &[]),
            "mode: raw\nhosts: none (raw value)\nexpires: never\n"
        );
    }

    #[test]
    fn host_parsing() {
        let h =
            parse_hosts(&["API.github.com".into(), " ".into(), "*.example.com".into()]).unwrap();
        assert_eq!(h, vec!["*.example.com", "api.github.com"]);
        assert!(parse_hosts(&["https://x".into()]).is_err());
    }

    #[test]
    fn pending_windows() {
        let now = 1_000_000;
        let at = |s: i64| asm_proto::time::fmt_unix(now + s);
        let m = EXPIRY_MARGIN;
        // The manager's expiry wins when it fits the lifetime (a re-attached request).
        assert_eq!(
            pending_window(Some(&at(300)), 600, now),
            Duration::from_secs(300) + m
        );
        assert_eq!(
            pending_window(Some(&at(600)), 600, now),
            Duration::from_secs(600) + m
        );
        // Clock skew: already past, or longer than the lifetime → the lifetime.
        assert_eq!(
            pending_window(Some(&at(-30)), 600, now),
            Duration::from_secs(600) + m
        );
        assert_eq!(
            pending_window(Some(&at(5000)), 600, now),
            Duration::from_secs(600) + m
        );
        // Only one of them sent.
        assert_eq!(pending_window(None, 120, now), Duration::from_secs(120) + m);
        assert_eq!(
            pending_window(Some(&at(90)), 0, now),
            Duration::from_secs(90) + m
        );
        // Neither (an older manager) → 600 s.
        assert_eq!(pending_window(None, 0, now), FALLBACK_WAIT);
        assert_eq!(pending_window(Some("garbage"), 0, now), FALLBACK_WAIT);
    }

    #[test]
    fn lifetimes() {
        assert_eq!(fmt_lifetime(600), "10 minutes");
        assert_eq!(fmt_lifetime(60), "1 minute");
        assert_eq!(fmt_lifetime(90), "90 seconds");
    }
}
