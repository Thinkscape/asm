//! Proxy supervisor (plan step 6): owns the patched iron-proxy child, its config, the
//! value files the config points at, and the redacted log capture.
//!
//! Locking: `ops` serialises every operation that touches the child or the files
//! (public mutators and the monitor's restart). `state` is only held briefly.

pub mod audit;
mod ca;
mod config;
mod files;
mod http;
mod logs;
mod redact;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use asm_proto::crypto::{new_token, sha256_hex};
use asm_proto::rules::is_sentinel;
use asm_proto::time::now_rfc3339;

use crate::error::{CoreError, Result};
use crate::paths::DataDirs;

pub use audit::ProxyEvent;
pub use config::DEFAULT_DENY_CIDRS;
pub use redact::REDACTED;

/// Receives activity events from the proxy's threads; must not block.
pub type EventSink = Arc<dyn Fn(ProxyEvent) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Tunnel listener bind address (HTTP proxy + CONNECT + SOCKS5).
    pub bind: String,
    /// Tunnel listener port.
    pub port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub mgmt_port: u16,
    pub metrics_port: u16,
    pub max_body: u64,
    pub allow_plain_http: bool,
    /// `None` = [`DEFAULT_DENY_CIDRS`].
    pub upstream_deny_cidrs: Option<Vec<String>>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 7412,
            http_port: 7413,
            https_port: 7414,
            mgmt_port: 7415,
            metrics_port: 7416,
            max_body: 10_485_760,
            allow_plain_http: false,
            upstream_deny_cidrs: None,
        }
    }
}

/// One sentinel field of an active sentinel lease.
#[derive(Clone)]
pub struct ProxyEntry {
    pub lease_id: String,
    pub index: usize,
    pub sentinel: String,
    pub value: String,
    pub hosts: Vec<String>,
}

impl std::fmt::Debug for ProxyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEntry")
            .field("lease_id", &self.lease_id)
            .field("index", &self.index)
            .field("sentinel", &self.sentinel)
            .field("value", &REDACTED)
            .field("hosts", &self.hosts)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ProxyStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub healthy: bool,
    /// RFC 3339 time the current config was last applied (reload or start).
    pub last_reload: Option<String>,
    pub ca_path: String,
    pub ca_expiry: Option<String>,
    pub error: Option<String>,
}

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A child that ran at least this long restarts after `BACKOFF_MIN` again.
const STABLE_UPTIME: Duration = Duration::from_secs(30);
const SETTLE_WINDOW: Duration = Duration::from_secs(3);
const TERM_GRACE: Duration = Duration::from_secs(3);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_millis(250);
const HEALTH_EVERY_TICKS: u32 = 8;
const PID_FILE: &str = "iron-proxy.pid";
const BLOCKED_VALUE_FILE: &str = "blocked.value";

struct Running {
    child: Child,
    pid: u32,
    started: Instant,
    api_key: String,
    mgmt_port: u16,
    metrics_port: u16,
}

struct State {
    cfg: ProxyConfig,
    entries: Vec<ProxyEntry>,
    sentinels: files::SentinelStore,
    child: Option<Running>,
    healthy: bool,
    last_reload: Option<String>,
    error: Option<String>,
    backoff: Duration,
    restart_at: Option<Instant>,
    shutdown: bool,
    /// Successful spawns so far (the first is "started", later ones "restarted").
    spawns: u32,
}

pub struct ProxySupervisor {
    binary: PathBuf,
    dirs: DataDirs,
    ca: ca::CaPaths,
    ca_expiry: Option<String>,
    on_change: Arc<dyn Fn() + Send + Sync>,
    on_event: EventSink,
    logs: Arc<logs::LogSink>,
    ops: Mutex<()>,
    state: Mutex<State>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl ProxySupervisor {
    /// Ensure the CA, write config and value files for `entries`, spawn iron-proxy and
    /// start the restart-with-backoff monitor. Succeeds even when the binary cannot be
    /// spawned (the status carries the error); fails when the CA cannot be created.
    pub fn start(
        bin_dir: PathBuf,
        dirs: DataDirs,
        cfg: ProxyConfig,
        entries: Vec<ProxyEntry>,
        on_change: Arc<dyn Fn() + Send + Sync>,
        on_event: EventSink,
    ) -> Result<Arc<Self>> {
        validate_entries(&entries)?;
        let binary = bin_dir.join("iron-proxy");
        let ca = ca::ensure(&binary, &dirs.proxy)?;
        let ca_expiry = std::fs::read_to_string(&ca.cert)
            .ok()
            .and_then(|pem| ca::pem_to_der(&pem).ok())
            .and_then(|der| ca::not_after(&der));
        files::write_private_atomic(&dirs.proxy, BLOCKED_VALUE_FILE, b"-")?;
        kill_stale_child(&dirs.proxy, &binary);

        let sup = Arc::new(Self {
            logs: Arc::new(logs::LogSink::new(dirs.logs.join("proxy.log"))),
            binary,
            ca,
            ca_expiry,
            on_change,
            on_event,
            ops: Mutex::new(()),
            state: Mutex::new(State {
                cfg,
                entries: Vec::new(),
                sentinels: files::SentinelStore::load(&dirs.proxy),
                child: None,
                healthy: false,
                last_reload: None,
                error: None,
                backoff: BACKOFF_MIN,
                restart_at: None,
                shutdown: false,
                spawns: 0,
            }),
            dirs,
        });
        {
            let _ops = lock(&sup.ops);
            sup.logs
                .set_redactor(redact::Redactor::new(&values_of(&entries)));
            sup.write_files(&entries)?;
            let cfg = lock(&sup.state).cfg.clone();
            sup.write_config(&cfg, &entries)?;
            lock(&sup.state).entries = entries;
            if let Err(e) = sup.spawn_locked() {
                sup.schedule_retry(e.message);
            }
            sup.prune_values();
        }
        let weak = Arc::downgrade(&sup);
        std::thread::Builder::new()
            .name("asm-proxy-monitor".into())
            .spawn(move || monitor(weak))
            .map_err(|e| CoreError::internal(format!("cannot start proxy monitor: {e}")))?;
        sup.notify();
        Ok(sup)
    }

    /// Replace the full entry set: write/delete value files, rewrite the config, reload;
    /// on reload failure restart the child. Also replaces the log-redaction value set.
    pub fn apply(&self, entries: Vec<ProxyEntry>) -> Result<()> {
        validate_entries(&entries)?;
        let r = {
            let _ops = lock(&self.ops);
            self.apply_locked(entries)
        };
        self.notify();
        r
    }

    fn apply_locked(&self, entries: Vec<ProxyEntry>) -> Result<()> {
        let (cfg, running, old_values) = {
            let st = lock(&self.state);
            if st.shutdown {
                return Err(CoreError::internal("proxy supervisor is shut down"));
            }
            (st.cfg.clone(), st.child.is_some(), values_of(&st.entries))
        };
        // Until the old config is gone, lines may still mention ended values.
        let new_values = values_of(&entries);
        let union: Vec<String> = old_values.iter().chain(&new_values).cloned().collect();
        self.logs.set_redactor(redact::Redactor::new(&union));

        self.write_files(&entries)?;
        self.write_config(&cfg, &entries)?;
        lock(&self.state).entries = entries;
        let result = if running {
            self.reload_or_restart()
        } else {
            Ok(())
        };
        self.prune_values();
        self.logs.set_redactor(redact::Redactor::new(&new_values));
        result
    }

    /// POST /v1/reload; any failure → terminate the child and start it on the new config.
    fn reload_or_restart(&self) -> Result<()> {
        let target = lock(&self.state)
            .child
            .as_ref()
            .map(|r| (r.mgmt_port, r.api_key.clone()));
        let Some((port, key)) = target else {
            return Ok(());
        };
        let outcome = match http::request(port, "POST", "/v1/reload", Some(&key), RELOAD_TIMEOUT) {
            Ok(r) if r.status == 200 => Ok(()),
            Ok(r) => Err(format!("HTTP {}: {}", r.status, r.body.trim())),
            Err(e) => Err(e.to_string()),
        };
        match outcome {
            Ok(()) => {
                lock(&self.state).last_reload = Some(now_rfc3339());
                Ok(())
            }
            Err(e) => {
                self.logs
                    .push(&format!("asm: proxy reload failed ({e}); restarting"));
                self.event(
                    "reload_failed",
                    format!("proxy reload failed ({e}); restarting"),
                );
                self.kill_locked();
                self.spawn_locked()
                    .inspect_err(|e| self.schedule_retry(e.message.clone()))
            }
        }
    }

    /// Change listen settings: rewrite config and restart. If the child exits within
    /// 3 s, the previous settings are restored and the error returned.
    pub fn set_config(&self, cfg: ProxyConfig) -> Result<()> {
        let r = {
            let _ops = lock(&self.ops);
            self.set_config_locked(cfg)
        };
        self.notify();
        r
    }

    fn set_config_locked(&self, cfg: ProxyConfig) -> Result<()> {
        let (old, entries) = {
            let st = lock(&self.state);
            if st.shutdown {
                return Err(CoreError::internal("proxy supervisor is shut down"));
            }
            (st.cfg.clone(), st.entries.clone())
        };
        if old == cfg {
            return Ok(());
        }
        self.write_config(&cfg, &entries)?;
        lock(&self.state).cfg = cfg;
        self.kill_locked();
        let failure = match self.spawn_locked() {
            Err(e) => Some(e.message),
            Ok(()) => self.exited_within(SETTLE_WINDOW),
        };
        let Some(why) = failure else { return Ok(()) };

        self.logs.push(&format!(
            "asm: proxy failed with the new settings ({why}); restoring the previous settings"
        ));
        self.event(
            "crashed",
            format!(
                "proxy failed with the new listen settings ({why}); previous settings restored"
            ),
        );
        self.kill_locked();
        self.write_config(&old, &entries)?;
        {
            let mut st = lock(&self.state);
            st.cfg = old;
            st.backoff = BACKOFF_MIN;
        }
        if let Err(e) = self.spawn_locked() {
            self.schedule_retry(e.message);
        }
        Err(CoreError::invalid(format!(
            "proxy did not start with the new settings: {why}"
        )))
    }

    /// Polls the current child for `window`; `Some(reason)` when it exited.
    fn exited_within(&self, window: Duration) -> Option<String> {
        let deadline = Instant::now() + window;
        loop {
            {
                let mut st = lock(&self.state);
                let r = st.child.as_mut()?;
                if let Ok(Some(status)) = r.child.try_wait() {
                    st.child = None;
                    st.healthy = false;
                    drop(st);
                    return Some(self.exit_message(status));
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn config(&self) -> ProxyConfig {
        lock(&self.state).cfg.clone()
    }

    pub fn status(&self) -> ProxyStatus {
        let st = lock(&self.state);
        ProxyStatus {
            running: st.child.is_some(),
            pid: st.child.as_ref().map(|r| r.pid),
            healthy: st.child.is_some() && st.healthy,
            last_reload: st.last_reload.clone(),
            ca_path: self.ca.cert.to_string_lossy().into_owned(),
            ca_expiry: self.ca_expiry.clone(),
            error: st.error.clone(),
        }
    }

    /// Terminate and respawn the child on the current config.
    pub fn restart(&self) -> Result<()> {
        let r = {
            let _ops = lock(&self.ops);
            if lock(&self.state).shutdown {
                Err(CoreError::internal("proxy supervisor is shut down"))
            } else {
                self.kill_locked();
                lock(&self.state).backoff = BACKOFF_MIN;
                self.spawn_locked()
                    .inspect_err(|e| self.schedule_retry(e.message.clone()))
            }
        };
        self.notify();
        r
    }

    /// Last `n` redacted log lines, oldest first.
    pub fn log_tail(&self, n: usize) -> Vec<String> {
        self.logs.tail(n)
    }

    pub fn ca_pem(&self) -> Result<String> {
        Ok(std::fs::read_to_string(&self.ca.cert)?)
    }

    /// SHA-256 of the CA certificate DER, lowercase hex.
    pub fn ca_sha256_hex(&self) -> Result<String> {
        Ok(sha256_hex(ca::pem_to_der(&self.ca_pem()?)?))
    }

    /// Kill the child (process group) and delete every value file.
    pub fn shutdown(&self) {
        {
            let _ops = lock(&self.ops);
            self.shutdown_locked();
        }
        self.notify();
    }

    fn shutdown_locked(&self) {
        {
            let mut st = lock(&self.state);
            if st.shutdown {
                return;
            }
            st.shutdown = true;
            st.restart_at = None;
        }
        self.kill_locked();
        lock(&self.state).entries.clear();
        files::prune_dir(&self.dirs.values, &HashSet::new());
        self.logs.push("asm: proxy stopped");
    }

    // ----- internals (callers hold `ops`) -----

    fn notify(&self) {
        (self.on_change)();
    }

    fn event(&self, kind: &'static str, summary: String) {
        (self.on_event)(ProxyEvent::Lifecycle { kind, summary });
    }

    fn write_files(&self, entries: &[ProxyEntry]) -> Result<()> {
        for e in entries {
            files::write_private_atomic(
                &self.dirs.values,
                &files::value_file_name(&e.lease_id, e.index),
                e.value.as_bytes(),
            )?;
        }
        Ok(())
    }

    fn prune_values(&self) {
        let keep: HashSet<String> = lock(&self.state)
            .entries
            .iter()
            .map(|e| files::value_file_name(&e.lease_id, e.index))
            .collect();
        files::prune_dir(&self.dirs.values, &keep);
    }

    /// Record the active sentinel set, then render and atomically write the config.
    fn write_config(&self, cfg: &ProxyConfig, entries: &[ProxyEntry]) -> Result<()> {
        let blocked = {
            let mut st = lock(&self.state);
            let active: Vec<&str> = entries.iter().map(|e| e.sentinel.as_str()).collect();
            st.sentinels.update(&active);
            st.sentinels.save(&self.dirs.proxy)?;
            st.sentinels.ended()
        };
        let render: Vec<config::RenderEntry<'_>> = entries
            .iter()
            .map(|e| config::RenderEntry {
                value_path: self
                    .dirs
                    .values
                    .join(files::value_file_name(&e.lease_id, e.index)),
                sentinel: &e.sentinel,
                hosts: &e.hosts,
            })
            .collect();
        let yaml = config::render(&config::RenderInput {
            cfg,
            ca_cert: &self.ca.cert,
            ca_key: &self.ca.key,
            entries: &render,
            blocked: &blocked,
            blocked_value_path: &self.dirs.proxy.join(BLOCKED_VALUE_FILE),
        });
        let path = config::config_path(&self.dirs);
        let name = path
            .file_name()
            .expect("config path has a file name")
            .to_string_lossy()
            .into_owned();
        files::write_private_atomic(&self.dirs.proxy, &name, yaml.as_bytes())?;
        Ok(())
    }

    fn spawn_locked(&self) -> Result<()> {
        let (shutdown, mgmt_port, metrics_port) = {
            let st = lock(&self.state);
            (st.shutdown, st.cfg.mgmt_port, st.cfg.metrics_port)
        };
        if shutdown {
            return Err(CoreError::internal("proxy supervisor is shut down"));
        }
        let api_key = new_token();
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--config")
            .arg(config::config_path(&self.dirs))
            .env_clear()
            .env("IRON_MANAGEMENT_API_KEY", &api_key)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.dirs.proxy)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(home) = std::env::var_os("HOME") {
            cmd.env("HOME", home);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("cannot start {}: {e}", self.binary.display());
                if lock(&self.state).error.as_deref() != Some(msg.as_str()) {
                    self.event("start_failed", format!("proxy failed to start: {msg}"));
                }
                return Err(CoreError::internal(msg));
            }
        };
        let pid = child.id();
        if let Some(stderr) = child.stderr.take() {
            let sink = Arc::clone(&self.logs);
            let on_event = Arc::clone(&self.on_event);
            let _ = std::thread::Builder::new()
                .name("asm-proxy-log".into())
                .spawn(move || {
                    let mut r = BufReader::new(stderr);
                    let mut buf = Vec::with_capacity(1024);
                    while matches!(r.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
                        let audit = sink.push_inspect(&String::from_utf8_lossy(&buf), audit::parse);
                        if let Some(a) = audit {
                            on_event(ProxyEvent::Request(a));
                        }
                        buf.clear();
                    }
                });
        }
        let _ = std::fs::write(self.dirs.proxy.join(PID_FILE), pid.to_string());
        self.logs
            .push(&format!("asm: started iron-proxy pid {pid}"));
        let mut st = lock(&self.state);
        st.child = Some(Running {
            child,
            pid,
            started: Instant::now(),
            api_key,
            mgmt_port,
            metrics_port,
        });
        st.healthy = false;
        st.error = None;
        st.restart_at = None;
        st.last_reload = Some(now_rfc3339());
        st.spawns += 1;
        let kind = if st.spawns == 1 {
            "started"
        } else {
            "restarted"
        };
        drop(st);
        self.event(kind, format!("proxy {kind} (pid {pid})"));
        Ok(())
    }

    /// SIGTERM the child's process group, SIGKILL after a grace period, reap it.
    fn kill_locked(&self) {
        let running = {
            let mut st = lock(&self.state);
            st.healthy = false;
            st.child.take()
        };
        let Some(mut r) = running else { return };
        let pgid = r.pid as libc::pid_t;
        // SAFETY: plain syscall; the group was created for this child (process_group(0)).
        unsafe { libc::killpg(pgid, libc::SIGTERM) };
        let deadline = Instant::now() + TERM_GRACE;
        loop {
            match r.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) if Instant::now() >= deadline => {
                    // SAFETY: as above.
                    unsafe { libc::killpg(pgid, libc::SIGKILL) };
                    let _ = r.child.wait();
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = std::fs::remove_file(self.dirs.proxy.join(PID_FILE));
    }

    fn schedule_retry(&self, error: String) {
        self.logs.push(&format!("asm: {error}"));
        let mut st = lock(&self.state);
        let delay = st.backoff;
        st.backoff = (delay * 2).min(BACKOFF_MAX);
        st.restart_at = Some(Instant::now() + delay);
        st.error = Some(error);
    }

    fn exit_message(&self, status: std::process::ExitStatus) -> String {
        match self.logs.last() {
            Some(line) => format!("iron-proxy exited ({status}); last log line: {line}"),
            None => format!("iron-proxy exited ({status})"),
        }
    }

    /// One monitor step. Returns false once shut down.
    fn tick(&self, check_health: bool) -> bool {
        let mut changed = false;
        if let Ok(_ops) = self.ops.try_lock() {
            let exited = {
                let mut st = lock(&self.state);
                if st.shutdown {
                    return false;
                }
                match st.child.as_mut().map(|r| (r.child.try_wait(), r.started)) {
                    Some((Ok(Some(status)), started)) => {
                        st.child = None;
                        st.healthy = false;
                        if started.elapsed() >= STABLE_UPTIME {
                            st.backoff = BACKOFF_MIN;
                        }
                        Some(status)
                    }
                    _ => None,
                }
            };
            if let Some(status) = exited {
                let _ = std::fs::remove_file(self.dirs.proxy.join(PID_FILE));
                let msg = self.exit_message(status);
                self.event("crashed", format!("proxy exited unexpectedly: {msg}"));
                self.schedule_retry(msg);
                changed = true;
            }
            let due = {
                let st = lock(&self.state);
                st.child.is_none() && st.restart_at.is_some_and(|t| Instant::now() >= t)
            };
            if due {
                if let Err(e) = self.spawn_locked() {
                    self.schedule_retry(e.message);
                }
                changed = true;
            }
        }
        let port = {
            let st = lock(&self.state);
            st.child
                .as_ref()
                .filter(|_| check_health || !st.healthy)
                .map(|r| r.metrics_port)
        };
        {
            if let Some(port) = port {
                let ok = http::request(port, "GET", "/healthz", None, HEALTH_TIMEOUT)
                    .is_ok_and(|r| r.status == 200);
                let mut st = lock(&self.state);
                if st.child.is_some() && st.healthy != ok {
                    st.healthy = ok;
                    changed = true;
                }
            }
        }
        if changed {
            self.notify();
        }
        true
    }
}

impl Drop for ProxySupervisor {
    fn drop(&mut self) {
        let _ops = lock(&self.ops);
        self.shutdown_locked();
    }
}

fn monitor(weak: Weak<ProxySupervisor>) {
    let mut n: u32 = 0;
    loop {
        std::thread::sleep(TICK);
        let Some(sup) = weak.upgrade() else { return };
        if !sup.tick(n % HEALTH_EVERY_TICKS == 0) {
            return;
        }
        n = n.wrapping_add(1);
    }
}

fn values_of(entries: &[ProxyEntry]) -> Vec<String> {
    entries.iter().map(|e| e.value.clone()).collect()
}

fn validate_entries(entries: &[ProxyEntry]) -> Result<()> {
    let mut seen = HashSet::new();
    for e in entries {
        if !is_sentinel(&e.sentinel) {
            return Err(CoreError::invalid(format!(
                "proxy entry {}.{}: malformed sentinel",
                e.lease_id, e.index
            )));
        }
        if e.value.is_empty() {
            return Err(CoreError::invalid(format!(
                "proxy entry {}.{}: empty value",
                e.lease_id, e.index
            )));
        }
        if e.hosts.is_empty() || e.hosts.iter().any(|h| h.is_empty()) {
            return Err(CoreError::invalid(format!(
                "proxy entry {}.{}: no hosts",
                e.lease_id, e.index
            )));
        }
        if !seen.insert(files::value_file_name(&e.lease_id, e.index)) {
            return Err(CoreError::invalid(format!(
                "proxy entry {}.{}: duplicate",
                e.lease_id, e.index
            )));
        }
    }
    Ok(())
}

/// A previous manager that died without shutdown leaves its iron-proxy running (own
/// process group) with a config that may hold ended leases: kill it when the recorded
/// pid still runs our binary.
fn kill_stale_child(proxy_dir: &Path, binary: &Path) {
    let pid_path = proxy_dir.join(PID_FILE);
    let Some(pid) = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
    else {
        return;
    };
    let _ = std::fs::remove_file(&pid_path);
    let binary = std::fs::canonicalize(binary).unwrap_or_else(|_| binary.to_path_buf());
    if pid <= 1 || process_path(pid).as_deref() != Some(binary.as_path()) {
        return;
    }
    // SAFETY: plain syscalls on a pid verified to run our binary.
    unsafe { libc::killpg(pid, libc::SIGTERM) };
    let deadline = Instant::now() + TERM_GRACE;
    while process_path(pid).is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if process_path(pid).is_some() {
        // SAFETY: as above.
        unsafe { libc::killpg(pid, libc::SIGKILL) };
    }
}

fn process_path(pid: libc::pid_t) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is valid for `len` bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let p = PathBuf::from(String::from_utf8(buf).ok()?);
    Some(std::fs::canonicalize(&p).unwrap_or(p))
}
