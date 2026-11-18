//! Browser sign-in sessions own the SDK's temporary credential until Save.
//! Google parent credentials are only used inside manager-side provider calls.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};

use asm_proto::crypto::new_uuid_v4;
use asm_proto::error::ErrorCode;
use asm_proto::generators::validate_gcloud_project_id;

use crate::error::{CoreError, Result};
use crate::generator::gcloud::{GCLOUD_SIGN_IN_REQUIRED, GcloudHttp, GcloudIdentity};
use crate::generator::gcloud_cli::{AuthorizedUser, GcloudRunner, GcloudSdk};
use crate::generator::{GcloudConnectionConfig, GeneratorClient, GeneratorConfig, GeneratorEntry};
use crate::store::GeneratorRecord;

use super::gcloud_profiles::profile_get;
use super::requests::Pending;
use super::{Core, lock, now};

const LOGIN_EXPIRY_SECS: i64 = 30 * 60;
const PROJECT_EVIDENCE_SECS: i64 = 2 * 60;

fn stale_login() -> CoreError {
    CoreError::invalid("Google sign-in was canceled or expired; sign in again")
}

struct Login {
    sdk: PathBuf,
    identity: GcloudIdentity,
    adc: AuthorizedUser,
}

struct Timed<T> {
    value: T,
    expires: i64,
}

impl<T> Timed<T> {
    fn new(value: T, time: i64) -> Self {
        Self { value, expires: time + LOGIN_EXPIRY_SECS }
    }

    fn fresh(&self, time: i64) -> bool {
        time < self.expires
    }
}

enum LoginPhase {
    Pending,
    Finished(Timed<Result<Arc<Login>>>),
    Canceled,
}

struct LoginSession {
    canceled: AtomicBool,
    phase: Mutex<LoginPhase>,
    changed: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
    commands: Mutex<usize>,
    commands_idle: Condvar,
}

struct SessionCommand<'a>(&'a LoginSession);

impl Drop for SessionCommand<'_> {
    fn drop(&mut self) {
        let mut commands = lock(&self.0.commands);
        *commands -= 1;
        if *commands == 0 { self.0.commands_idle.notify_all(); }
    }
}

impl LoginSession {
    fn new() -> Self {
        Self {
            canceled: AtomicBool::new(false),
            phase: Mutex::new(LoginPhase::Pending),
            changed: Condvar::new(),
            worker: Mutex::new(None),
            commands: Mutex::new(0),
            commands_idle: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<Login>, time: i64) {
        let mut phase = lock(&self.phase);
        if matches!(*phase, LoginPhase::Pending) {
            *phase = LoginPhase::Finished(Timed::new(result.map(Arc::new), time));
            self.changed.notify_all();
        }
    }

    fn outcome(phase: &LoginPhase, time: i64) -> Result<Arc<Login>> {
        match phase {
            LoginPhase::Finished(result) if result.fresh(time) => result.value.clone(),
            LoginPhase::Pending => Err(CoreError::invalid("complete Google sign-in in the local browser first")),
            _ => Err(stale_login()),
        }
    }

    fn login(&self, time: i64) -> Result<Arc<Login>> {
        Self::outcome(&lock(&self.phase), time)
    }

    fn parent_token(&self, runner: &GcloudRunner) -> Result<String> {
        let (_command, login) = {
            let mut commands = lock(&self.commands);
            if self.canceled.load(Ordering::Acquire) { return Err(stale_login()); }
            let login = self.login(now())?;
            *commands += 1;
            (SessionCommand(self), login)
        };
        let result = runner.parent_token_for_session(&login.sdk, &login.adc, &self.canceled);
        drop(login);
        if self.canceled.load(Ordering::Acquire) { return Err(stale_login()); }
        result
    }

    fn wait(&self) -> Result<Arc<Login>> {
        let phase = self.changed.wait_while(lock(&self.phase), |phase| {
            matches!(phase, LoginPhase::Pending)
        }).unwrap_or_else(|e| e.into_inner());
        Self::outcome(&phase, now())
    }

    fn expired(&self, time: i64) -> bool {
        matches!(&*lock(&self.phase), LoginPhase::Finished(result) if !result.fresh(time))
    }

    fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        *lock(&self.phase) = LoginPhase::Canceled;
        self.changed.notify_all();
    }

    fn join(&self) {
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
        drop(self.commands_idle.wait_while(lock(&self.commands), |n| *n != 0)
            .unwrap_or_else(|e| e.into_inner()));
    }
}

struct ApprovalProjectSearch {
    attempt: String,
    generator_id: String,
    revision: u64,
    client: Weak<GeneratorClient>,
    expires: i64,
    projects: Option<Vec<String>>,
}

impl ApprovalProjectSearch {
    fn matches(&self, entry: &GeneratorEntry) -> Result<bool> {
        Ok(self.generator_id == entry.record.id
            && self.revision == entry.record.revision
            && self.client.as_ptr() == Arc::as_ptr(&entry.client()?))
    }
}

fn stale_projects() -> CoreError {
    CoreError::invalid("Google project discovery is no longer current; refresh the visible project list")
}

fn require_project_choice(pending: &Pending) -> Result<()> {
    if !profile_get(pending)?.1.operator_selected_gcloud_project {
        return Err(CoreError::invalid("this request does not allow an operator-selected Google Cloud project"));
    }
    Ok(())
}

fn project_evidence_expiry(time: i64, pending: &Pending) -> i64 {
    pending.expires.min(time.saturating_add(PROJECT_EVIDENCE_SECS))
}

#[derive(Default)]
struct SetupState {
    closed: bool,
    sessions: HashMap<String, Arc<LoginSession>>,
    approval_projects: HashMap<String, ApprovalProjectSearch>,
}

impl SetupState {
    fn require_open(&self) -> Result<()> {
        if self.closed { Err(CoreError::vault_unavailable("manager is shutting down")) } else { Ok(()) }
    }

    fn session(&self, id: &str) -> Result<&Arc<LoginSession>> {
        self.require_open()?;
        self.sessions.get(id).ok_or_else(stale_login)
    }

    fn cancel_session(&mut self, id: &str) -> Option<Arc<LoginSession>> {
        let session = self.sessions.remove(id)?;
        session.cancel();
        Some(session)
    }

    fn expire(&mut self, time: i64) -> Vec<Arc<LoginSession>> {
        self.approval_projects.retain(|_, search| search.expires > time);
        let expired: Vec<_> = self.sessions.iter().filter(|(_, s)| s.expired(time)).map(|(id, _)| id.clone()).collect();
        expired.iter().filter_map(|id| self.cancel_session(id)).collect()
    }

    fn close(&mut self) -> Vec<Arc<LoginSession>> {
        self.closed = true;
        self.approval_projects.clear();
        self.sessions.drain().map(|(_, session)| {
            session.cancel();
            session
        }).collect()
    }
}

pub(crate) struct GcloudSetup {
    pub(crate) runner: GcloudRunner,
    http: Mutex<Option<Arc<GcloudHttp>>>,
    state: Mutex<SetupState>,
}

impl GcloudSetup {
    pub(crate) fn new(root: PathBuf) -> Result<Self> {
        Ok(Self {
            runner: GcloudRunner::new(root)?,
            http: Mutex::new(None),
            state: Mutex::new(SetupState::default()),
        })
    }

    fn http(&self) -> Result<Arc<GcloudHttp>> {
        let mut http = lock(&self.http);
        if let Some(http) = http.as_ref() { return Ok(http.clone()); }
        let created = Arc::new(GcloudHttp::new()?);
        *http = Some(created.clone());
        Ok(created)
    }
}

pub(crate) struct PreparedGcloudSave {
    session_id: String,
    session: Arc<LoginSession>,
}

impl Core {
    pub(crate) fn gcloud_check_sdk(&self, path: Option<String>) -> Result<GcloudSdk> {
        lock(&self.gcloud.state).require_open()?;
        self.gcloud.runner.check_sdk(path.as_deref().map(Path::new))
    }

    pub(crate) fn gcloud_begin_login(&self, sdk_path: String) -> Result<String> {
        let sdk_path = PathBuf::from(sdk_path);
        if !sdk_path.is_absolute() {
            return Err(CoreError::invalid("locate gcloud using its absolute installation path"));
        }
        let mut state = lock(&self.gcloud.state);
        state.require_open()?;
        let id = new_uuid_v4();
        let session = Arc::new(LoginSession::new());
        let run_session = session.clone();
        let runner = self.gcloud.runner.clone();
        let http = self.gcloud.http()?;
        let worker = thread::Builder::new().name("asm-gcloud-login".into()).spawn(move || {
            let result = (|| {
                let (sdk, adc) = runner.login(&sdk_path, &run_session.canceled)?;
                if run_session.canceled.load(Ordering::Acquire) { return Err(stale_login()); }
                let token = runner.parent_token_for_session(&sdk.path, &adc, &run_session.canceled)?;
                if run_session.canceled.load(Ordering::Acquire) { return Err(stale_login()); }
                let identity = http.identity(&token)?;
                Ok(Login { sdk: sdk.path, identity, adc })
            })();
            run_session.complete(result, now());
        }).map_err(|_| CoreError::internal("could not start Google sign-in"))?;
        *lock(&session.worker) = Some(worker);
        state.sessions.insert(id.clone(), session);
        Ok(id)
    }

    pub(crate) fn gcloud_finish_login(&self, session_id: &str) -> Result<GcloudIdentity> {
        let session = lock(&self.gcloud.state).session(session_id)?.clone();
        session.wait()?;
        let state = lock(&self.gcloud.state);
        // Cancellation and completion can race between the wait and applying its result.
        if !Arc::ptr_eq(state.session(session_id)?, &session) { return Err(stale_login()); }
        Ok(session.login(now())?.identity.clone())
    }

    pub(crate) fn gcloud_cancel_login(&self, session_id: &str) -> Result<()> {
        let session = {
            let _authorization = lock(&self.authorization);
            lock(&self.gcloud.state).cancel_session(session_id)
        };
        if let Some(session) = session { session.join(); }
        Ok(())
    }

    pub(crate) fn sweep_gcloud_setup(&self, time: i64) {
        let sessions = {
            let _authorization = lock(&self.authorization);
            lock(&self.gcloud.state).expire(time)
        };
        for session in sessions { session.join(); }
    }

    pub(crate) fn shutdown_gcloud_setup(&self) {
        let sessions = {
            let _authorization = lock(&self.authorization);
            lock(&self.gcloud.state).close()
        };
        self.gcloud.runner.shutdown();
        for session in sessions { session.join(); }
    }

    /// Use the isolated SDK parent only after fresh Google userinfo matches this
    /// saved connection. This does network I/O; the caller checks the entry's
    /// revision/client under authorization before and after the operation.
    pub(crate) fn with_gcloud_connection_parent<T>(
        &self,
        entry: &GeneratorEntry,
        operation: impl FnOnce(&GcloudHttp, &str, &GcloudIdentity) -> Result<T>,
    ) -> Result<T> {
        if !matches!(&entry.record.config, GeneratorConfig::GcloudConnection(_)) {
            return Err(CoreError::invalid("this is not a Google Cloud connection"));
        }
        let client = entry.client()?;
        let GeneratorClient::Gcloud(google) = client.as_ref() else {
            return Err(CoreError::internal("invalid Google Cloud generator client"));
        };
        if !client.matches_config(&entry.record.config) {
            return Err(CoreError::internal("Google Cloud client does not match the saved connection"));
        }
        let http = self.gcloud.http()?;
        let result = google.verified_parent(&http)
            .and_then(|(token, identity)| operation(&http, &token, &identity));
        if result.as_ref().is_err_and(|error| {
            error.code == ErrorCode::Unauthorized && error.message == GCLOUD_SIGN_IN_REQUIRED
        }) {
            self.mark_gcloud_sign_in_required(&entry.record.id, entry.record.revision, &client);
        }
        result
    }

    /// Discover project IDs only for the live, offered managed connection.
    /// Every new lookup replaces the request's previous evidence, even if the
    /// lookup fails. An older in-flight lookup cannot restore it.
    pub(crate) fn gcloud_approval_projects(
        &self, request_id: &str, generator_id: &str, revision: u64,
    ) -> Result<Vec<String>> {
        let attempt = new_uuid_v4();
        let entry = self.with_profile_request(request_id, generator_id, revision, false, |pending, entry| {
            require_project_choice(pending)?;
            if !matches!(&entry.record.config, GeneratorConfig::GcloudConnection(_)) {
                return Err(stale_projects());
            }
            let client = entry.client()?;
            let time = self.generation_now();
            let mut state = lock(&self.gcloud.state);
            state.require_open()?;
            state.approval_projects.insert(pending.id.clone(), ApprovalProjectSearch {
                attempt: attempt.clone(), generator_id: generator_id.into(), revision,
                client: Arc::downgrade(&client), expires: project_evidence_expiry(time, pending), projects: None,
            });
            Ok(entry.clone())
        })?;
        let GeneratorConfig::GcloudConnection(config) = &entry.record.config else {
            return Err(stale_projects());
        };
        let projects = self.with_gcloud_connection_parent(&entry, |http, token, identity| {
            if identity.email != config.account_email {
                return Err(CoreError::unauthorized("the verified Google email changed; sign in again before discovering projects"));
            }
            // A search endpoint failure must not mark a verified connection as
            // signed out or prevent review of the exact requested project.
            Ok(http.active_projects(token))
        })??;
        self.with_profile_request(request_id, generator_id, revision, false, |pending, entry| {
            require_project_choice(pending)?;
            let time = self.generation_now();
            let mut state = lock(&self.gcloud.state);
            state.require_open()?;
            let search = state.approval_projects.get_mut(request_id)
                .filter(|search| search.attempt == attempt && search.expires > time)
                .ok_or_else(stale_projects)?;
            if !search.matches(entry)? {
                return Err(stale_projects());
            }
            search.expires = project_evidence_expiry(time, pending);
            search.projects = Some(projects.clone());
            Ok(projects)
        })
    }

    /// The caller has already checked the live pending request and connection
    /// under authorization. A project change requires fresh local evidence;
    /// approving the original is never gated on optional discovery.
    pub(super) fn validate_gcloud_selected_project_locked(
        &self, pending: &Pending, entry: &GeneratorEntry, selected_project: &str,
    ) -> Result<Option<i64>> {
        validate_gcloud_project_id(selected_project)?;
        let (_, _, requested) = profile_get(pending)?;
        if selected_project == requested.project_id {
            return Ok(None);
        }
        require_project_choice(pending)?;
        let time = self.generation_now();
        let state = lock(&self.gcloud.state);
        state.require_open()?;
        let search = state.approval_projects.get(&pending.id)
            .filter(|search| search.expires > time)
            .ok_or_else(stale_projects)?;
        if !search.matches(entry)? {
            return Err(stale_projects());
        }
        let projects = search.projects.as_ref().ok_or_else(stale_projects)?;
        if projects.binary_search_by(|id| id.as_str().cmp(selected_project)).is_err() {
            return Err(CoreError::invalid("this project was not reported active and visible to the selected Google connection"));
        }
        Ok(Some(search.expires))
    }

    /// Legacy scope approvals only use the saved default project. A previously
    /// issued legacy lease can still renew with its stored quota project.
    pub(super) fn validate_gcloud_approval_project_locked(&self, record: &GeneratorRecord, project_id: &str) -> Result<()> {
        validate_gcloud_project_id(project_id)?;
        let GeneratorConfig::Gcloud(config) = &record.config else {
            return Err(CoreError::invalid("this is not a legacy Google Cloud generator"));
        };
        if project_id != config.project_id {
            return Err(CoreError::invalid("legacy Google Cloud approvals use the generator's saved project"));
        }
        Ok(())
    }

    /// The supplied draft never determines identity or legacy authority. The
    /// session was completed by SDK login and verified Google userinfo.
    pub(crate) fn prepare_gcloud_save(
        &self,
        previous: Option<&GeneratorRecord>,
        session_id: &str,
    ) -> Result<(GeneratorConfig, String, PreparedGcloudSave)> {
        let session = lock(&self.gcloud.state).session(session_id)?.clone();
        let login = session.login(now())?;
        let sdk_path = login.sdk.to_str()
            .ok_or_else(|| CoreError::invalid("the resolved gcloud path must be valid UTF-8"))?;
        let identity = &login.identity;
        let config = match previous.map(|record| &record.config) {
            Some(GeneratorConfig::Gcloud(legacy)) => {
                require_same_subject(&legacy.account_subject, identity)?;
                // Never change a legacy service account, project or scope
                // ceiling. Confirm the new login can still use its exact target.
                let http = self.gcloud.http()?;
                let token = session.parent_token(&self.gcloud.runner)?;
                let identity = http.identity(&token)?;
                require_same_subject(&legacy.account_subject, &identity)?;
                http.preflight(&token, &legacy.project_id, &legacy.ceiling.service_account_unique_id)?;
                let mut config = legacy.clone();
                config.sdk_path = sdk_path.to_owned();
                config.account_email = identity.email;
                GeneratorConfig::Gcloud(config)
            }
            Some(GeneratorConfig::GcloudConnection(saved)) => {
                require_same_subject(&saved.account_subject, identity)?;
                connection_config(sdk_path, identity)
            }
            None => connection_config(sdk_path, identity),
            Some(GeneratorConfig::GithubApp(_)) => {
                return Err(CoreError::invalid("an existing generator cannot change provider"));
            }
        };
        config.validate()?;
        let adc = login.adc.to_json()?;
        Ok((config, adc, PreparedGcloudSave {
            session_id: session_id.to_owned(),
            session,
        }))
    }

    /// The caller also compares the current database record to its original
    /// snapshot and holds authorization until committing or abandoning the save.
    pub(crate) fn validate_gcloud_save_locked(&self, prepared: &PreparedGcloudSave) -> Result<()> {
        let state = lock(&self.gcloud.state);
        if !Arc::ptr_eq(state.session(&prepared.session_id)?, &prepared.session) {
            return Err(stale_login());
        }
        prepared.session.login(now())?;
        Ok(())
    }

    /// Consume the completed sign-in session only after a successful commit.
    /// Its worker has finished producing the login; don't join under authorization.
    pub(crate) fn finish_gcloud_save(&self, prepared: &PreparedGcloudSave) {
        lock(&self.gcloud.state).cancel_session(&prepared.session_id);
    }
}

fn require_same_subject(saved_subject: &str, identity: &GcloudIdentity) -> Result<()> {
    if identity.subject != saved_subject {
        return Err(CoreError::invalid("sign in with the Google account already connected to this generator"));
    }
    Ok(())
}

fn connection_config(sdk_path: &str, identity: &GcloudIdentity) -> GeneratorConfig {
    GeneratorConfig::GcloudConnection(GcloudConnectionConfig {
        sdk_path: sdk_path.to_owned(),
        account_subject: identity.subject.clone(),
        account_email: identity.email.clone(),
    })
}

#[cfg(test)]
impl Core {
    pub(crate) fn set_gcloud_setup_endpoint_for_test(&self, endpoint: reqwest::Url) -> Result<()> {
        *lock(&self.gcloud.http) = Some(Arc::new(GcloudHttp::with_test_endpoint(endpoint)?));
        Ok(())
    }

    pub(crate) fn install_gcloud_setup_for_test(
        &self,
        sdk: PathBuf,
        adc_json: &str,
        identity: GcloudIdentity,
    ) -> Result<String> {
        let time = now();
        let id = new_uuid_v4();
        let session = Arc::new(LoginSession::new());
        session.complete(Ok(Login { sdk, identity, adc: AuthorizedUser::parse(adc_json)? }), time);
        lock(&self.gcloud.state).sessions.insert(id.clone(), session);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADC: &str = r#"{"type":"authorized_user","client_id":"test-id","client_secret":"test-client","refresh_token":"test-refresh"}"#;

    fn login() -> Login {
        Login {
            sdk: "/opt/google-cloud-sdk/bin/gcloud".into(),
            identity: GcloudIdentity { subject: "operator-subject".into(), email: "operator@example.com".into() },
            adc: AuthorizedUser::parse(ADC).unwrap(),
        }
    }

    #[test]
    fn cancel_wakes_waiter_and_late_login_cannot_restore_credentials() {
        let mut state = SetupState::default();
        let session = Arc::new(LoginSession::new());
        state.sessions.insert("session".into(), session.clone());
        let waiting = session.clone();
        let waiter = thread::spawn(move || waiting.wait().is_err());
        let removed = state.cancel_session("session").unwrap();
        assert!(Arc::ptr_eq(&session, &removed));
        assert!(session.canceled.load(Ordering::Acquire));
        session.complete(Ok(login()), now());
        assert!(waiter.join().unwrap());
        assert!(session.login(now()).is_err());
        assert!(state.session("session").is_err());
    }

    #[test]
    fn sweep_expires_completed_credentials_and_shutdown_clears_pending_work() {
        let mut state = SetupState::default();
        let finished = Arc::new(LoginSession::new());
        finished.complete(Ok(login()), 100);
        assert!(finished.login(99 + LOGIN_EXPIRY_SECS).is_ok());
        assert!(finished.login(100 + LOGIN_EXPIRY_SECS).is_err());
        let pending = Arc::new(LoginSession::new());
        state.sessions.insert("finished".into(), finished.clone());
        state.sessions.insert("pending".into(), pending.clone());
        assert!(state.expire(99 + LOGIN_EXPIRY_SECS).is_empty());
        assert_eq!(state.expire(100 + LOGIN_EXPIRY_SECS).len(), 1);
        assert!(finished.canceled.load(Ordering::Acquire));
        assert!(!pending.canceled.load(Ordering::Acquire));
        assert_eq!(state.close().len(), 1);
        assert!(pending.canceled.load(Ordering::Acquire));
        assert!(state.sessions.is_empty());
        assert!(state.require_open().is_err());
    }
}
