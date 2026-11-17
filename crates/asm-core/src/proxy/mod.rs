//! Proxy supervisor (plan step 6): owns the patched iron-proxy child, its config, the
//! value files the config points at, and the redacted log capture.
//!
//! Locking: `ops` serialises every operation that touches the child or the files
//! (public mutators and the monitor's restart). `state` is only held briefly.

pub mod audit;
mod ca;
mod config;
mod files;
pub mod health;
mod http;
mod logs;
mod procs;
mod redact;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use asm_proto::crypto::{new_token, sha256_hex};
use asm_proto::rules::is_sentinel;
use asm_proto::time::now_rfc3339;

use crate::error::{CoreError, Result};
use crate::paths::DataDirs;

pub use audit::ProxyEvent;
pub use config::DEFAULT_DENY_CIDRS;
pub use health::Phase;
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
    pub phase: Phase,
    /// Failed exits/starts since the proxy was last healthy.
    pub consecutive_failures: u32,
    /// RFC 3339 time the current config was last applied (reload or start).
    pub last_reload: Option<String>,
    pub ca_path: String,
    pub ca_expiry: Option<String>,
    /// Cause of the last failure; cleared once the proxy is healthy.
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
/// How long an exited child's log thread may take to drain stderr.
const LOG_DRAIN: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_millis(250);
const HEALTH_EVERY_TICKS: u32 = 8;
const PID_FILE: &str = "iron-proxy.pid";

struct Running {
    child: Child,
    pid: u32,
    started: Instant,
    api_key: String,
    mgmt_port: u16,
    metrics_port: u16,
    log_thread: Option<JoinHandle<()>>,
    /// Cause from the child's last ERROR log line ([`health::error_cause`]).
    last_error: Arc<Mutex<Option<String>>>,
}

/// Why a child exited, for status and activity.
struct Failure {
    message: String,
    /// The port it needed is held by an iron-proxy of this data directory.
    own_holder: Option<libc::pid_t>,
}

struct State {
    cfg: ProxyConfig,
    entries: Vec<ProxyEntry>,
    sentinels: files::SentinelStore,
    child: Option<Running>,
    health: health::Health,
    /// Phase at the last monitor step (a change notifies the observer).
    last_phase: Phase,
    /// An own iron-proxy holding a port was killed during this outage (done at most once).
    killed_port_holder: bool,
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
        // Dummy value file of the ended-sentinel entries of earlier versions.
        let _ = std::fs::remove_file(dirs.proxy.join("blocked.value"));

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
                health: health::Health::default(),
                last_phase: Phase::Starting,
                killed_port_holder: false,
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
            sup.kill_orphans();
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
                    let r = st.child.take().expect("child checked above");
                    st.health.stopped();
                    drop(st);
                    return Some(self.diagnose(r, status).message);
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
        let running = st.child.is_some();
        ProxyStatus {
            running,
            pid: st.child.as_ref().map(|r| r.pid),
            healthy: st.health.healthy(running),
            phase: if st.shutdown {
                Phase::Down {
                    reason: "the proxy is stopped".into(),
                    since: SystemTime::now(),
                }
            } else {
                st.health.phase(running, Instant::now())
            },
            consecutive_failures: st.health.failures(),
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
        let ended = {
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
            ended: &ended,
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
            // The patched iron-proxy exits when this process does (no orphans holding ports).
            .env("IRON_PARENT_PID", std::process::id().to_string())
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
                if lock(&self.state).health.should_log_failure(&msg) {
                    self.event("start_failed", format!("proxy failed to start: {msg}"));
                }
                return Err(CoreError::internal(msg));
            }
        };
        let pid = child.id();
        let last_error = Arc::new(Mutex::new(None));
        let log_thread = child.stderr.take().and_then(|stderr| {
            let sink = Arc::clone(&self.logs);
            let on_event = Arc::clone(&self.on_event);
            let last_error = Arc::clone(&last_error);
            std::thread::Builder::new()
                .name("asm-proxy-log".into())
                .spawn(move || {
                    let mut r = BufReader::new(stderr);
                    let mut buf = Vec::with_capacity(1024);
                    while matches!(r.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
                        let (audit, error, stop) =
                            sink.push_inspect(&String::from_utf8_lossy(&buf), |l| {
                                (
                                    audit::parse(l),
                                    health::error_cause(l),
                                    health::stop_cause(l),
                                )
                            });
                        if let Some(a) = audit {
                            on_event(ProxyEvent::Request(a));
                        }
                        let mut last = lock(&last_error);
                        if error.is_some() {
                            *last = error;
                        } else if stop.is_some() && last.is_none() {
                            *last = stop;
                        }
                        drop(last);
                        buf.clear();
                    }
                })
                .ok()
        });
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
            log_thread,
            last_error,
        });
        st.health.spawned(Instant::now(), SystemTime::now());
        st.restart_at = None;
        st.last_reload = Some(now_rfc3339());
        st.spawns += 1;
        let kind = if st.spawns == 1 {
            "started"
        } else {
            "restarted"
        };
        // Restarts within a reported outage are summed up by the `recovered` row.
        let quiet = st.health.reported_down();
        drop(st);
        if !quiet {
            self.event(kind, format!("proxy {kind} (pid {pid})"));
        }
        Ok(())
    }

    /// SIGTERM the child's process group, SIGKILL after a grace period, reap it.
    fn kill_locked(&self) {
        let running = {
            let mut st = lock(&self.state);
            st.health.stopped();
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
        st.health
            .failed(error.clone(), Instant::now(), SystemTime::now());
        st.error = Some(error);
    }

    /// The cause of an exited child's failure: its last ERROR log line (a port conflict
    /// names the process holding the port), else the exit status and last log line.
    fn diagnose(&self, r: Running, status: ExitStatus) -> Failure {
        // Stderr reaches EOF once the child is gone; let the log thread finish its lines.
        if let Some(t) = &r.log_thread {
            let deadline = Instant::now() + LOG_DRAIN;
            while !t.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let cause = lock(&r.last_error).take();
        let Some(cause) = cause else {
            let message = match self.logs.last() {
                Some(line) => format!("iron-proxy exited ({status}); last log line: {line}"),
                None => format!("iron-proxy exited ({status})"),
            };
            return Failure {
                message,
                own_holder: None,
            };
        };
        let Some(port) = health::port_in_use(&cause) else {
            return Failure {
                message: cause,
                own_holder: None,
            };
        };
        let holder = procs::port_holder(port);
        let config = config::config_path(&self.dirs);
        let own_holder = holder
            .as_ref()
            .filter(|h| procs::is_own_proxy(h.pid, &self.binary, &config))
            .map(|h| h.pid);
        Failure {
            message: health::port_conflict_message(
                port,
                holder.as_ref().map(|h| (h.name.as_str(), h.pid)),
            ),
            own_holder,
        }
    }

    /// Kill iron-proxy processes of this data directory left by an earlier manager that
    /// died without shutting down: every `iron-proxy` started with our `--config`, and the
    /// pid in the pid file when it still runs our binary.
    fn kill_orphans(&self) {
        let config = config::config_path(&self.dirs);
        let pid_path = self.dirs.proxy.join(PID_FILE);
        let mut pids = procs::find_proxies_for_config(&config, None);
        if let Some(pid) = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
            && pid > 1
            && !pids.contains(&pid)
            && procs::is_own_proxy(pid, &self.binary, &config)
        {
            pids.push(pid);
        }
        let _ = std::fs::remove_file(&pid_path);
        for pid in pids {
            self.kill_orphan(pid, "left running by an earlier manager");
        }
    }

    fn kill_orphan(&self, pid: libc::pid_t, why: &str) {
        let msg = if procs::terminate(pid, TERM_GRACE) {
            format!("killed orphaned iron-proxy pid {pid} ({why})")
        } else {
            format!("could not kill orphaned iron-proxy pid {pid} ({why})")
        };
        self.logs.push(&format!("asm: {msg}"));
        self.event("orphan_killed", msg);
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
                match st.child.as_mut().map(|r| r.child.try_wait()) {
                    Some(Ok(Some(status))) => {
                        let r = st.child.take().expect("child checked above");
                        if r.started.elapsed() >= STABLE_UPTIME {
                            st.backoff = BACKOFF_MIN;
                        }
                        Some((r, status))
                    }
                    _ => None,
                }
            };
            if let Some((r, status)) = exited {
                let _ = std::fs::remove_file(self.dirs.proxy.join(PID_FILE));
                let failure = self.diagnose(r, status);
                if lock(&self.state)
                    .health
                    .should_log_failure(&failure.message)
                {
                    self.event(
                        "crashed",
                        format!("proxy exited unexpectedly: {}", failure.message),
                    );
                }
                self.schedule_retry(failure.message);
                if let Some(pid) = failure.own_holder {
                    let first = !std::mem::replace(&mut lock(&self.state).killed_port_holder, true);
                    if first {
                        // Our own leftover blocks the port: remove it and retry at once.
                        self.kill_orphan(pid, "it held a port the proxy needs");
                        lock(&self.state).restart_at = Some(Instant::now());
                    }
                }
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
                .filter(|_| check_health || !st.health.healthy(true))
                .map(|r| r.metrics_port)
        };
        if let Some(port) = port {
            let ok = http::request(port, "GET", "/healthz", None, HEALTH_TIMEOUT)
                .is_ok_and(|r| r.status == 200);
            let recovered = {
                let mut st = lock(&self.state);
                if st.child.is_some() {
                    let was = st.health.healthy(true);
                    let t = st.health.checked(ok, Instant::now(), SystemTime::now());
                    if ok {
                        st.error = None;
                        st.killed_port_holder = false;
                    }
                    changed |= was != st.health.healthy(true);
                    t
                } else {
                    None
                }
            };
            if let Some(health::Transition::Recovered { downtime, failures }) = recovered {
                // The incident is over: the next failure starts a fresh backoff.
                lock(&self.state).backoff = BACKOFF_MIN;
                let starts = match failures {
                    0 => String::new(),
                    1 => " (1 failed start)".into(),
                    n => format!(" ({n} failed starts)"),
                };
                self.logs.push("asm: proxy recovered");
                self.event(
                    "recovered",
                    format!(
                        "proxy recovered after {} down{starts}",
                        health::fmt_downtime(downtime)
                    ),
                );
            }
        }
        let (phase_changed, transition) = {
            let mut st = lock(&self.state);
            let running = st.child.is_some();
            let now = Instant::now();
            let transition = st.health.transitions(running, now);
            let phase = st.health.phase(running, now);
            let phase_changed = phase != st.last_phase;
            st.last_phase = phase;
            (phase_changed, transition)
        };
        match transition {
            Some(health::Transition::Down { reason }) => {
                self.logs.push(&format!("asm: proxy is down: {reason}"));
                self.event("down", format!("proxy is down: {reason}"));
            }
            Some(health::Transition::Unhealthy) => self.event(
                "unhealthy",
                format!(
                    "proxy is running but has failed health checks for over {} s",
                    health::UNHEALTHY_AFTER.as_secs()
                ),
            ),
            _ => {}
        }
        if changed || phase_changed {
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
