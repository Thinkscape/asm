//! Login broker (`asm login`): after approval the manager opens a headed Chrome with a
//! throwaway profile on the Mac, fills the approved vault login into sign-in forms of
//! the approved origins (never submitting), and on the operator's hand-over exports the
//! cookies and localStorage valid for the requested site as a Playwright storage state.
//! The password and one-time codes go only to Chrome, over its debugging pipe.

pub(crate) mod cdp;
pub(crate) mod fill;

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use self::cdp::{CALL_TIMEOUT, Cdp, CdpError};
use crate::manager::{Core, lock};

/// A sign-in session ends unanswered after this long.
pub(crate) const SESSION_SECS: u64 = 600;
/// Fill loop period.
const TICK: Duration = Duration::from_millis(500);
/// After `Browser.close`, Chrome is killed if it is still running this long after.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// Chrome's first page and the attach to it.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Written into each profile; names the Chrome to kill after a manager crash.
pub(crate) const PID_FILE: &str = "asm-broker.pid";
/// No new one-time code read sooner than this after a failed one.
const TOTP_RETRY: Duration = Duration::from_secs(5);

pub(crate) const NO_CHROME: &str = "no Chrome or Chromium on the manager Mac";
pub(crate) const DENY_CANCELLED: &str = "sign-in cancelled";
pub(crate) const DENY_TIMED_OUT: &str = "sign-in timed out after 10 minutes";
pub(crate) const DENY_CLOSED: &str = "the sign-in browser closed before hand-over";
pub(crate) const DENY_REVOKED: &str = "the requesting host was revoked";

const CHROME_PATHS: [&str; 3] = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
];

/// The first installed Chrome or Chromium.
pub(crate) fn find_chrome() -> Option<PathBuf> {
    CHROME_PATHS.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// One-time codes are read from the vault when a code field is filled.
pub(crate) struct TotpSource {
    pub vault_id: String,
    pub key: String,
}

/// An approved sign-in.
pub(crate) struct SessionSpec {
    pub request_id: String,
    pub host_id: String,
    pub host_label: String,
    pub url: String,
    pub export_host: String,
    pub export_origin: String,
    pub fill_origins: Vec<String>,
    pub username: Option<Zeroizing<String>>,
    pub password: Zeroizing<String>,
    pub totp: Option<TotpSource>,
    /// Lifetime of the handed-over storage state.
    pub lease_secs: u64,
}

/// How a session ended.
pub(crate) enum Outcome {
    /// The storage state JSON, valid for `lease_secs`.
    HandOver { state: Zeroizing<String>, lease_secs: u64 },
    /// One of the `DENY_*` texts.
    Deny(&'static str),
}

/// A live session, as listed to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionInfo {
    pub request_id: String,
    pub url: String,
    pub host_label: String,
    pub started_at: i64,
    pub status: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Control {
    Run,
    HandOver,
    Cancel(&'static str),
    /// The manager is stopping: kill Chrome, leave the request to the next start.
    Shutdown,
    /// The session decided how it ends; later controls are refused.
    Finished,
}

struct Session {
    info: Mutex<SessionInfo>,
    pid: u32,
    profile: PathBuf,
    /// The control and how many controls were applied so far.
    control: Mutex<(Control, u64)>,
    wake: Condvar,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    #[cfg(test)]
    page: Mutex<Option<(Arc<Cdp>, String)>>,
}

impl Session {
    /// Apply a control; `false` once the session has decided how it ends.
    fn set_control(&self, control: Control) -> bool {
        let mut current = lock(&self.control);
        if current.0 == Control::Finished {
            return false;
        }
        // Ending wins over a hand-over; the first ending wins over later ones.
        if matches!(current.0, Control::Run | Control::HandOver) || control == Control::Shutdown {
            current.0 = control;
        }
        current.1 += 1;
        self.wake.notify_all();
        true
    }

    /// Wait up to `timeout` for a control change; the current control.
    fn wait(&self, timeout: Duration) -> Control {
        let current = lock(&self.control);
        if current.0 != Control::Run {
            return current.0;
        }
        self.wake.wait_timeout(current, timeout).unwrap_or_else(|e| e.into_inner()).0.0
    }

    /// How many controls were applied so far.
    fn generation(&self) -> u64 {
        lock(&self.control).1
    }

    fn resume(&self) {
        let mut current = lock(&self.control);
        if current.0 == Control::HandOver {
            current.0 = Control::Run;
        }
    }

    /// Refuse further controls; the last control before that.
    fn finish(&self) -> Control {
        std::mem::replace(&mut lock(&self.control).0, Control::Finished)
    }
}

pub(crate) struct Broker {
    /// `<data>/broker`: one profile directory per session.
    root: PathBuf,
    core: Weak<Core>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// Tests: the Chrome to run and extra switches (headless, test certificates);
    /// `Some(None)` = no Chrome installed.
    #[cfg(test)]
    pub(crate) chrome_override: Mutex<Option<Option<(PathBuf, Vec<String>)>>>,
    /// Tests: a shorter session timeout.
    #[cfg(test)]
    pub(crate) session_timeout: Mutex<Option<Duration>>,
}

impl Broker {
    pub(crate) fn new(root: PathBuf, core: Weak<Core>) -> Self {
        Self {
            root,
            core,
            sessions: Mutex::new(HashMap::new()),
            #[cfg(test)]
            chrome_override: Mutex::new(None),
            #[cfg(test)]
            session_timeout: Mutex::new(None),
        }
    }

    /// The Chrome to launch, and extra switches.
    pub(crate) fn chrome(&self) -> Option<(PathBuf, Vec<String>)> {
        #[cfg(test)]
        if let Some(o) = lock(&self.chrome_override).clone() {
            return o;
        }
        find_chrome().map(|p| (p, Vec::new()))
    }

    /// Kill Chrome left running by an earlier manager and delete every old profile.
    pub(crate) fn cleanup_leftovers(&self) {
        cleanup_leftovers(&self.root);
    }

    pub(crate) fn is_live(&self, request_id: &str) -> bool {
        lock(&self.sessions).contains_key(request_id)
    }

    pub(crate) fn sessions(&self) -> Vec<SessionInfo> {
        let mut out: Vec<SessionInfo> = lock(&self.sessions).values().map(|s| lock(&s.info).clone()).collect();
        out.sort_by(|a, b| (a.started_at, &a.request_id).cmp(&(b.started_at, &b.request_id)));
        out
    }

    /// Ask the session to export and end. `false` when there is no such session, or it
    /// is already ending.
    pub(crate) fn hand_over(&self, request_id: &str) -> bool {
        self.control(request_id, Control::HandOver)
    }

    /// Ask the session to end with `reason`. `false` when there is no such session, or
    /// it is already ending.
    pub(crate) fn cancel(&self, request_id: &str, reason: &'static str) -> bool {
        self.control(request_id, Control::Cancel(reason))
    }

    fn control(&self, request_id: &str, control: Control) -> bool {
        let Some(session) = lock(&self.sessions).get(request_id).cloned() else { return false };
        // Hold the status while applying, so the session's own status update (a failed
        // hand-over, say) lands after this one.
        let mut info = lock(&session.info);
        let applied = session.set_control(control);
        if applied && control == Control::HandOver {
            info.status = "handing over…".into();
        }
        applied
    }

    /// Stop every session at once: kill Chrome, delete the profiles. Requests stay
    /// pending for the next start (which reports them interrupted).
    pub(crate) fn shutdown(&self) {
        let sessions: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        for s in &sessions {
            s.set_control(Control::Shutdown);
            kill_group(s.pid);
        }
        for s in sessions {
            if let Some(t) = lock(&s.thread).take() {
                let _ = t.join();
            }
            remove_profile(&s.profile);
        }
        lock(&self.sessions).clear();
    }

    /// Launch Chrome for an approved sign-in and start its fill loop.
    pub(crate) fn start(&self, spec: SessionSpec, started_at: i64) -> Result<(), String> {
        let (chrome, extra) = self.chrome().ok_or(NO_CHROME)?;
        crate::paths::ensure_private_dir(&self.root).map_err(|e| format!("cannot create the browser profile: {e}"))?;
        let profile = self.root.join(&spec.request_id);
        let launched = launch(&chrome, &profile, &extra, &spec.url);
        let (child, cdp, page) = match launched {
            Ok(l) => l,
            Err(e) => {
                remove_profile(&profile);
                return Err(format!("the sign-in browser could not start: {e}"));
            }
        };
        let session = Arc::new(Session {
            info: Mutex::new(SessionInfo {
                request_id: spec.request_id.clone(),
                url: spec.url.clone(),
                host_label: spec.host_label.clone(),
                started_at,
                status: "opening the sign-in page".into(),
            }),
            pid: child.id(),
            profile: profile.clone(),
            control: Mutex::new((Control::Run, 0)),
            wake: Condvar::new(),
            thread: Mutex::new(None),
            #[cfg(test)]
            page: Mutex::new(Some((cdp.clone(), page.clone()))),
        });
        let runner = Runner {
            spec, child, cdp, page, profile, started: Instant::now(), timeout: self.session_timeout(),
            world: None, created: Vec::new(), detached: false, filled: Vec::new(), held_status: None,
            totp_retry: None, session: session.clone(), core: self.core.clone(),
        };
        let id = runner.spec.request_id.clone();
        lock(&self.sessions).insert(id.clone(), session.clone());
        let spawned = std::thread::Builder::new().name("asm-broker".into()).spawn(move || runner.run());
        match spawned {
            Ok(handle) => {
                *lock(&session.thread) = Some(handle);
                Ok(())
            }
            Err(e) => {
                // The runner (and its Chrome) was dropped with the closure.
                kill_group(session.pid);
                remove_profile(&session.profile);
                lock(&self.sessions).remove(&id);
                Err(format!("the sign-in browser could not start: {e}"))
            }
        }
    }

    fn session_timeout(&self) -> Duration {
        #[cfg(test)]
        if let Some(t) = *lock(&self.session_timeout) {
            return t;
        }
        Duration::from_secs(SESSION_SECS)
    }

    /// Forget a finished session (its thread is ending).
    fn remove(&self, request_id: &str) {
        lock(&self.sessions).remove(request_id);
    }

    /// Tests: evaluate `expression` in the page's main world.
    #[cfg(test)]
    pub(crate) fn eval_in_page(&self, request_id: &str, expression: &str) -> Option<Value> {
        let session = lock(&self.sessions).get(request_id).cloned()?;
        let (cdp, page) = lock(&session.page).clone()?;
        let r = cdp.call("Runtime.evaluate", json!({ "expression": expression, "returnByValue": true }),
            Some(&page), CALL_TIMEOUT).ok()?;
        Some(r["result"]["value"].clone())
    }

    #[cfg(test)]
    pub(crate) fn profile_dir(&self, request_id: &str) -> PathBuf {
        self.root.join(request_id)
    }
}

/// Everything the session thread owns.
struct Runner {
    spec: SessionSpec,
    child: Child,
    cdp: Arc<Cdp>,
    /// Attached page session.
    page: String,
    profile: PathBuf,
    started: Instant,
    timeout: Duration,
    /// The `asm-fill` world of the current document.
    world: Option<World>,
    /// `asm-fill` worlds Chrome reported created since the last look: `(id, uniqueId, frameId)`.
    created: Vec<(i64, String, String)>,
    /// The attached page went away (tab closed, renderer swapped).
    detached: bool,
    /// Kinds filled in the current document.
    filled: Vec<&'static str>,
    /// A failed hand-over's status stays until the control generation moves past this.
    held_status: Option<u64>,
    /// After a failed one-time code read: no new read before this instant; the status.
    totp_retry: Option<(Instant, String)>,
    session: Arc<Session>,
    core: Weak<Core>,
}

/// An isolated world, addressed by its `uniqueId` (execution context ids are reused
/// across renderer processes; unique ids are not).
struct World {
    loader: String,
    id: i64,
    unique_id: String,
}

enum End {
    Outcome(Outcome),
    Shutdown,
}

impl Runner {
    fn run(mut self) {
        let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.drive()))
            .unwrap_or(End::Outcome(Outcome::Deny(DENY_CLOSED)));
        // From here on no control is accepted, so one the operator saw acknowledged is
        // honoured: a cancel that arrived during the export wins over the hand-over.
        let end = match (self.session.finish(), end) {
            (Control::Shutdown, _) => End::Shutdown,
            (Control::Cancel(reason), End::Outcome(Outcome::HandOver { .. })) => End::Outcome(Outcome::Deny(reason)),
            (_, end) => end,
        };
        match &end {
            End::Shutdown => self.kill(),
            End::Outcome(_) => self.close(),
        }
        remove_profile(&self.profile);
        let request_id = self.spec.request_id.clone();
        let core = self.core.upgrade();
        drop(self);
        let Some(core) = core else { return };
        if let End::Outcome(outcome) = end {
            core.broker_finished(&request_id, outcome);
        }
        core.broker.remove(&request_id);
        core.notify(crate::manager::TOPIC_REQUESTS);
    }

    fn drive(&mut self) -> End {
        loop {
            match self.session.wait(TICK) {
                // Only `run` finishes a session, after `drive` returned.
                Control::Shutdown | Control::Finished => return End::Shutdown,
                Control::Cancel(reason) => return End::Outcome(Outcome::Deny(reason)),
                Control::HandOver => match self.export() {
                    Ok(state) => return End::Outcome(Outcome::HandOver { state, lease_secs: self.spec.lease_secs }),
                    Err(_) if self.exited() || self.cdp.is_closed() => return End::Outcome(Outcome::Deny(DENY_CLOSED)),
                    Err(e) => {
                        self.set_status(format!("hand-over failed: {e}"));
                        self.held_status = Some(self.session.generation());
                        self.session.resume();
                        continue;
                    }
                },
                Control::Run => {}
            }
            if self.exited() || self.cdp.is_closed() {
                return End::Outcome(Outcome::Deny(DENY_CLOSED));
            }
            let Some(core) = self.core.upgrade() else { return End::Shutdown };
            if matches!(core.host_is_active(&self.spec.host_id), Ok(false)) {
                return End::Outcome(Outcome::Deny(DENY_REVOKED));
            }
            if self.started.elapsed() >= self.timeout {
                return End::Outcome(Outcome::Deny(DENY_TIMED_OUT));
            }
            self.process_events();
            if self.detached && !self.reattach() {
                return End::Outcome(Outcome::Deny(DENY_CLOSED));
            }
            match self.fill_step(&core) {
                Ok(status) => {
                    if self.held_status.is_some_and(|g| g == self.session.generation()) {
                        continue;
                    }
                    self.held_status = None;
                    self.set_status(status);
                }
                Err(CdpError::Closed) => return End::Outcome(Outcome::Deny(DENY_CLOSED)),
                Err(CdpError::Protocol(m)) if m.contains("ession") && m.contains("not found") => {
                    if !self.reattach() {
                        return End::Outcome(Outcome::Deny(DENY_CLOSED));
                    }
                }
                // A navigation destroyed the world or the element: retry next tick.
                Err(_) => self.world = None,
            }
        }
    }

    fn set_status(&self, status: String) {
        let changed = {
            let mut info = lock(&self.session.info);
            let changed = info.status != status;
            info.status = status;
            changed
        };
        if changed && let Some(core) = self.core.upgrade() {
            core.notify(crate::manager::TOPIC_REQUESTS);
        }
    }

    fn exited(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(None))
    }

    /// Note what Chrome reported: page detachment, `asm-fill` worlds created, and
    /// contexts destroyed (forgetting the world when it is one of them).
    fn process_events(&mut self) {
        for e in self.cdp.drain_events() {
            let ours = e.session.as_deref() == Some(self.page.as_str());
            let context = &e.params["context"];
            match e.method.as_str() {
                "Target.detachedFromTarget" if e.params["sessionId"].as_str() == Some(self.page.as_str()) => {
                    self.detached = true;
                }
                "Runtime.executionContextCreated" if ours && context["name"] == "asm-fill" => {
                    if let (Some(id), Some(unique), Some(frame)) = (context["id"].as_i64(),
                        context["uniqueId"].as_str(), context["auxData"]["frameId"].as_str()) {
                        self.created.push((id, unique.to_owned(), frame.to_owned()));
                    }
                }
                "Runtime.executionContextDestroyed" if ours => {
                    let id = e.params["executionContextId"].as_i64();
                    let unique = e.params["executionContextUniqueId"].as_str();
                    let gone = |i: i64, u: &str| Some(i) == id || Some(u) == unique;
                    self.created.retain(|(i, u, _)| !gone(*i, u));
                    if self.world.as_ref().is_some_and(|w| gone(w.id, &w.unique_id)) {
                        self.world = None;
                    }
                }
                "Runtime.executionContextsCleared" if ours => {
                    self.created.clear();
                    self.world = None;
                }
                _ => {}
            }
        }
    }

    /// Attach to the browser's first page again; `false` when it has none left.
    fn reattach(&mut self) -> bool {
        match cdp::attach_first_page(&self.cdp, Duration::from_secs(2)) {
            Ok(page) => {
                #[cfg(test)]
                {
                    *lock(&self.session.page) = Some((self.cdp.clone(), page.clone()));
                }
                self.page = page;
                self.detached = false;
                self.world = None;
                self.created.clear();
                self.filled.clear();
                true
            }
            Err(_) => false,
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.cdp.call(method, params, Some(&self.page), CALL_TIMEOUT)
    }

    /// One pass of the fill loop; the status to show. The origin check that matters runs
    /// inside the `asm-fill` world, in the same call as finding and filling the field: a
    /// world belongs to one document, and both scripts refuse unless that document is a
    /// top-level document of an approved origin.
    fn fill_step(&mut self, core: &Core) -> Result<String, CdpError> {
        let tree = self.call("Page.getFrameTree", json!({}))?;
        let frame = &tree["frameTree"]["frame"];
        let url = frame["url"].as_str().unwrap_or("");
        let loader = frame["loaderId"].as_str().unwrap_or("").to_owned();
        if url.is_empty() || url == "about:blank" {
            return Ok("opening the sign-in page".into());
        }
        if !fill::https_origin(url).is_some_and(|o| self.spec.fill_origins.contains(&o)) {
            return Ok(paused(url));
        }
        let world = match self.world.take() {
            Some(w) if w.loader == loader => w,
            _ => {
                let frame_id = frame["id"].as_str().unwrap_or("").to_owned();
                let created = self.call("Page.createIsolatedWorld",
                    json!({ "frameId": frame_id, "worldName": "asm-fill" }))?;
                let id = created["executionContextId"].as_i64()
                    .ok_or_else(|| CdpError::Protocol("no isolated world".into()))?;
                // Chrome reports the context before it answers.
                self.process_events();
                let unique_id = self.created.iter().find(|(i, _, f)| *i == id && *f == frame_id)
                    .map(|(_, u, _)| u.clone())
                    .ok_or_else(|| CdpError::Protocol("the isolated world went away".into()))?;
                self.created.clear();
                self.filled.clear();
                World { loader, id, unique_id }
            }
        };
        let context = world.unique_id.clone();
        self.world = Some(world);
        let mut kinds: Vec<&str> = fill::KINDS.iter().copied().filter(|k| match *k {
            "username" => self.spec.username.as_ref().is_some_and(|u| !u.is_empty()),
            "totp" => self.spec.totp.is_some(),
            _ => true,
        }).collect();
        let totp_status = match &self.totp_retry {
            Some((until, status)) if Instant::now() < *until => Some(status.clone()),
            _ => None,
        };
        if totp_status.is_some() {
            kinds.retain(|k| *k != "totp");
        }
        let found = self.call("Runtime.evaluate", json!({
            "expression": format!("({})({}, {})", fill::FIND_JS, json!(kinds), json!(self.spec.fill_origins)),
            "uniqueContextId": context, "returnByValue": true,
        }))?;
        if found.get("exceptionDetails").is_some() {
            return Err(CdpError::Protocol("the field finder failed".into()));
        }
        let found = &found["result"]["value"];
        let origin = found["origin"].as_str().unwrap_or("null").to_owned();
        if !self.spec.fill_origins.contains(&origin) {
            return Ok(paused(&origin));
        }
        let Some(kind) = found["kind"].as_str().and_then(|k| fill::KINDS.iter().find(|x| **x == k).copied()) else {
            return Ok(totp_status.unwrap_or_else(|| self.filled_status(&origin)));
        };
        let value: Zeroizing<String> = match kind {
            "password" => self.spec.password.clone(),
            "username" => self.spec.username.clone().unwrap_or_default(),
            _ => match self.totp_code(core) {
                Ok(code) => code,
                Err(e) => {
                    let status = format!("one-time code unavailable: {e}");
                    self.totp_retry = Some((Instant::now() + TOTP_RETRY, status.clone()));
                    return Ok(status);
                }
            },
        };
        let marked = self.call("Runtime.evaluate", json!({ "expression": fill::MARKED_JS, "uniqueContextId": context }))?;
        let Some(object) = marked["result"]["objectId"].as_str().map(str::to_owned) else {
            return Ok(self.filled_status(&origin));
        };
        let params = fill::fill_call(&object, &value, &self.spec.fill_origins);
        drop(value);
        let filled = self.cdp.call_raw("Runtime.callFunctionOn", &params, Some(&self.page), CALL_TIMEOUT);
        drop(params);
        let _ = self.call("Runtime.releaseObject", json!({ "objectId": object }));
        if filled?["result"]["value"] == true && !self.filled.contains(&kind) {
            self.filled.push(kind);
        }
        Ok(self.filled_status(&origin))
    }

    fn filled_status(&self, origin: &str) -> String {
        if self.filled.is_empty() {
            format!("waiting for a sign-in form on {origin}")
        } else {
            format!("filled {} on {origin}; sign in, then hand over", self.filled.join(", "))
        }
    }

    /// A fresh one-time code. The item's other values, read along with it, are zeroized.
    fn totp_code(&self, core: &Core) -> Result<Zeroizing<String>, String> {
        let source = self.spec.totp.as_ref().ok_or("no authenticator key")?;
        let vault = core.registry.get(&source.vault_id).ok_or("vault was removed")?;
        let values = vault.provider.read(&source.key).map_err(|e| e.message)?;
        let mut code = None;
        for (field, value) in values {
            let value = Zeroizing::new(value);
            if field == "totp" && code.is_none() {
                code = Some(value);
            }
        }
        code.ok_or_else(|| "the item has no authenticator key".to_owned())
    }

    /// The storage state: cookies valid for the export host and the export origin's
    /// localStorage.
    fn export(&self) -> Result<Zeroizing<String>, CdpError> {
        let cookies = self.cdp.call("Storage.getCookies", json!({}), None, CALL_TIMEOUT)?;
        let cookies = cookies["cookies"].as_array().cloned().unwrap_or_default();
        let local = self.call("DOMStorage.getDOMStorageItems", json!({
            "storageId": { "securityOrigin": self.spec.export_origin, "isLocalStorage": true },
        }));
        let entries = match local {
            Ok(v) => v["entries"].as_array().cloned().unwrap_or_default(),
            // No document of the export origin is open: it has no localStorage to export.
            Err(CdpError::Protocol(m)) if storage_missing(&m) => Vec::new(),
            // Never export a partial state.
            Err(e) => return Err(e),
        };
        let state = fill::storage_state(&cookies, &self.spec.export_host, &self.spec.export_origin, &entries);
        Ok(Zeroizing::new(state.to_string()))
    }

    /// `Browser.close`, then kill after [`CLOSE_GRACE`].
    fn close(&mut self) {
        if !self.exited() {
            let _ = self.cdp.call("Browser.close", json!({}), None, Duration::from_secs(2));
            let deadline = Instant::now() + CLOSE_GRACE;
            while Instant::now() < deadline && !self.exited() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.kill();
    }

    fn kill(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            kill_group(self.child.id());
        }
        let _ = self.child.wait();
    }
}

/// The status while the page shows an origin the operator did not approve.
fn paused(url_or_origin: &str) -> String {
    format!("paused: {} is not approved", fill::display_origin(url_or_origin))
}

/// `DOMStorage.getDOMStorageItems` found no storage for the origin (no document of it
/// is open), as opposed to failing.
fn storage_missing(message: &str) -> bool {
    message.contains("not found") && (message.contains("Frame") || message.contains("torage"))
}

/// Start Chrome on a new profile with the debugging pipe on fds 3 and 4, attach to its
/// first page and open `url`.
fn launch(chrome: &Path, profile: &Path, extra: &[String], url: &str) -> std::io::Result<(Child, Arc<Cdp>, String)> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(profile)?;
    let (commands_read, commands_write) = std::io::pipe()?;
    let (replies_read, replies_write) = std::io::pipe()?;
    let (r, w) = (commands_read.as_raw_fd(), replies_write.as_raw_fd());
    let mut command = Command::new(chrome);
    command
        .arg(format!("--user-data-dir={}", profile.display()))
        .args(["--remote-debugging-pipe", "--no-first-run", "--no-default-browser-check", "--use-mock-keychain"])
        .args(extra)
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: only async-signal-safe calls (fcntl, dup2) between fork and exec. The
    // copies above 9 keep a source already at 3 or 4 from being overwritten, and dup2
    // leaves 3 and 4 open across exec.
    unsafe {
        command.pre_exec(move || {
            let r = libc::fcntl(r, libc::F_DUPFD_CLOEXEC, 10);
            let w = libc::fcntl(w, libc::F_DUPFD_CLOEXEC, 10);
            if r < 0 || w < 0 || libc::dup2(r, 3) < 0 || libc::dup2(w, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(commands_read);
    drop(replies_write);
    let started = (|| {
        std::fs::write(profile.join(PID_FILE), format!("{}\n", child.id()))?;
        let cdp = Arc::new(Cdp::new(commands_write, replies_read)?);
        let page = cdp::attach_first_page(&cdp, STARTUP_TIMEOUT).map_err(std::io::Error::other)?;
        cdp.call("Page.navigate", json!({ "url": url }), Some(&page), CALL_TIMEOUT).map_err(std::io::Error::other)?;
        Ok((cdp, page))
    })();
    match started {
        Ok((cdp, page)) => Ok((child, cdp, page)),
        Err(e) => {
            kill_group(child.id());
            let _ = child.wait();
            Err(e)
        }
    }
}

/// SIGKILL the process group led by `pid` (Chrome and its helpers), and `pid`.
fn kill_group(pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return };
    if pid <= 1 {
        return;
    }
    // SAFETY: plain signal delivery.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Delete a profile directory; Chrome's helpers may still be writing for a moment.
fn remove_profile(profile: &Path) {
    for _ in 0..20 {
        match std::fs::remove_dir_all(profile) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    log::error!("cannot delete the sign-in browser profile {}", profile.display());
}

/// The process name of `pid` (macOS `proc_name`).
fn process_name(pid: libc::pid_t) -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length.
    let n = unsafe { libc::proc_name(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// The raw `KERN_PROCARGS2` block of `pid` (its executable path and arguments).
fn process_args(pid: libc::pid_t) -> Option<Vec<u8>> {
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `argmax` is valid for `size` bytes.
    let ok = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 2, (&raw mut argmax).cast(), &mut size, std::ptr::null_mut(), 0)
    } == 0;
    if !ok || argmax <= 0 {
        return None;
    }
    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buf` is valid for `size` bytes.
    let ok = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0)
    } == 0;
    ok.then(|| {
        buf.truncate(size);
        buf
    })
}

/// Whether `pid` is still the Chrome a broker session started on `profile`: its
/// process name names Chrome or Chromium and it runs on that profile. A reused pid
/// (the operator's own Chrome, say) is never killed.
fn is_broker_chrome(pid: libc::pid_t, profile: &Path) -> bool {
    if !process_name(pid).is_some_and(|n| n.contains("Chrome") || n.contains("Chromium")) {
        return false;
    }
    let flag = format!("--user-data-dir={}", profile.display()).into_bytes();
    process_args(pid).is_some_and(|args| args.split(|b| *b == 0).any(|arg| arg == flag.as_slice()))
}

/// Kill each leftover profile's Chrome (when its pid still is that Chrome) and
/// delete everything under `root`.
fn cleanup_leftovers(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let pid = std::fs::read_to_string(path.join(PID_FILE)).ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
            .filter(|pid| *pid > 1);
        if let Some(pid) = pid
            && is_broker_chrome(pid, &path)
        {
            kill_group(pid as u32);
        }
        let removed = if entry.file_type().is_ok_and(|t| t.is_dir()) {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = removed {
            log::error!("cannot delete the old sign-in browser profile {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests;
