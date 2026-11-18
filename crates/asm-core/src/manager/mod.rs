//! Manager core: shared state, startup, the HTTPS API listener, lease sweep and the
//! proxy entry set. Request flows live in `requests`, pairing in `pairing`, UI operations
//! in `admin`, HTTP handlers in `api`, the audit trail in `activity`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asm_proto::wire::LeaseMode;
use asm_proto::generators::SourceKind;
use tokio::sync::{Notify, watch};

use crate::error::{CoreError, Result};
use crate::ffi::ManagerObserver;
use crate::paths::DataDirs;
use crate::proxy::{EventSink, ProxyEntry, ProxyEvent, ProxySupervisor};
use crate::settings::Settings;
use crate::store::{LeaseRecord, Store};
use crate::tls::ServerCert;
use crate::vault::registry::{Registry, VaultEntry};
use crate::vault::{VaultConfig, creds};

pub mod activity;
pub mod admin;
pub(crate) mod catalog;
pub mod api;
pub mod firewall;
pub mod generation;
pub(crate) mod gcloud;
mod gcloud_ledger;
pub(crate) mod gcloud_profiles;
pub mod netinfo;
pub mod pairing;
pub mod requests;

pub use requests::Book;

pub const TOPIC_REQUESTS: &str = "requests";
pub const TOPIC_LEASES: &str = "leases";
pub const TOPIC_HOSTS: &str = "hosts";
pub const TOPIC_VAULTS: &str = "vaults";
pub const TOPIC_GENERATORS: &str = "generators";
pub const TOPIC_GCLOUD_ACCOUNTS: &str = "gcloud_accounts";
pub const TOPIC_PROXY: &str = "proxy";
pub const TOPIC_FIREWALL: &str = "firewall";
pub const TOPIC_SETTINGS: &str = "settings";
pub const TOPIC_ACTIVITY: &str = "activity";

const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Sleep past an expiry instant by this much, so `now()` (whole seconds) has reached it.
const EXPIRY_MARGIN: Duration = Duration::from_millis(20);
const BW_SYNC_EVERY: Duration = Duration::from_secs(300);
/// Resolved requests are kept in the database this long.
const HISTORY_SECS: i64 = 30 * 86_400;
/// Held (exclusive `flock`) by the running manager of a data directory.
const LOCK_FILE: &str = "manager.lock";
/// Error message when another manager holds [`LOCK_FILE`] (code `exists`).
pub const ALREADY_RUNNING: &str =
    "another Agents Secrets Manager is already running with this data directory";

/// Options for `Manager::start_with` (not exported over FFI).
#[derive(Debug, Clone, Default)]
pub struct StartOptions {
    /// Root for proxy value files; default `std::env::temp_dir()`.
    pub values_root: Option<PathBuf>,
    /// Settings written before start, as `(key, JSON value)` (see `settings` key constants).
    pub settings: Vec<(String, serde_json::Value)>,
}

/// Current wall-clock time in Unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn to_system_time(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Proxy substitution entries for active sentinel leases.
#[derive(Default)]
pub struct ProxyState {
    pub entries: BTreeMap<String, Vec<ProxyEntry>>,
    /// Active sentinel leases whose vault cannot be read (lease id → message).
    pub suspended: BTreeMap<String, String>,
    /// Desired entries have not been successfully published to the proxy.
    pub dirty: bool,
    /// Resume transitions await successful publication and are audited after locks.
    pending_resumed: BTreeMap<String, LeaseRecord>,
    /// Journal rows whose prior sentinel cutover still needs publication in this process.
    account_cutovers: HashSet<i64>,
}

impl ProxyState {
    fn flatten(&self) -> Vec<ProxyEntry> {
        self.entries.values().flatten().cloned().collect()
    }

    pub(crate) fn resume(&mut self, lease: &LeaseRecord) {
        if self.suspended.remove(&lease.id).is_some() {
            self.pending_resumed.insert(lease.id.clone(), lease.clone());
        }
    }
}


struct ApiServer {
    handle: axum_server::Handle<SocketAddr>,
    addr: SocketAddr,
}

pub struct Core {
    pub dirs: DataDirs,
    pub bin_dir: PathBuf,
    pub store: Arc<Store>,
    pub registry: Registry,
    pub generators: crate::generator::GeneratorRegistry,
    /// Generation authority linearization; never held during provider calls.
    pub(crate) authorization: Mutex<()>,
    pub(crate) generation: Mutex<generation::GenerationState>,
    pub(crate) gcloud: gcloud::GcloudSetup,
    gcloud_profiles: gcloud_profiles::GcloudProfiles,
    pub proxy: Arc<ProxySupervisor>,
    pub cert: ServerCert,
    pub settings: RwLock<Settings>,
    /// Pending/resolved requests and pairing attempts; every state change goes through it.
    pub book: Mutex<Book>,
    /// Bumped on every request/pairing state change (wakes long polls).
    pub changes: watch::Sender<u64>,
    pub proxy_state: Mutex<ProxyState>,
    observer: Arc<dyn ManagerObserver>,
    rt: Mutex<Option<tokio::runtime::Runtime>>,
    rt_handle: tokio::runtime::Handle,
    api: Mutex<Option<ApiServer>>,
    /// Lease ids active at the last sweep (to notice expiries).
    last_active: Mutex<HashSet<String>>,
    /// Wakes the sweep loop to recompute its deadline when leases change.
    lease_wake: Arc<Notify>,
    /// Vaults whose provider could not be built (id → message).
    pub(crate) vault_errors: Mutex<HashMap<String, String>>,
    /// Audit trail writer.
    pub activity: activity::ActivityLog,
    /// Vault id → ready at the last [`Core::track_vaults`].
    pub(crate) vault_ready: Mutex<HashMap<String, bool>>,
    /// Collection id → name from Bitwarden "Connect" calls (a new vault has no id yet when
    /// it connects; its save picks the names up from here).
    pub(crate) connect_names: Mutex<HashMap<String, String>>,
    /// Exclusive lock on `<data>/manager.lock`; released by `shutdown`.
    instance_lock: Mutex<Option<std::fs::File>>,
    /// Last macOS Firewall check (see [`firewall`]).
    pub(crate) firewall: Mutex<firewall::FirewallCheck>,
    /// Wakes the firewall check loop (listener changes, proxy starts, wake).
    firewall_wake: Arc<Notify>,
}

/// One manager per data directory: take an exclusive lock on its lock file, or fail with
/// [`ALREADY_RUNNING`] (code `exists`) while another process holds it.
fn lock_data_dir(data: &std::path::Path) -> Result<std::fs::File> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(data.join(LOCK_FILE))?;
    match f.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(CoreError::exists(ALREADY_RUNNING)),
        Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
    }
    // The holder's pid, for people looking at the file.
    f.set_len(0)?;
    writeln!(f, "{}", std::process::id())?;
    Ok(f)
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn second_lock_on_a_data_dir_is_refused_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_data_dir(dir.path()).unwrap();
        let e = lock_data_dir(dir.path()).unwrap_err();
        assert_eq!(e.code, asm_proto::error::ErrorCode::Exists);
        assert_eq!(e.message, ALREADY_RUNNING);
        drop(first);
        // Other tests in this process spawn children; one forked in the instant after
        // the lock was taken shares the open file (and its flock) until it execs and
        // closes the descriptor. Allow that window instead of failing intermittently.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match lock_data_dir(dir.path()) {
                Ok(_) => break,
                Err(e) if e.code == asm_proto::error::ErrorCode::Exists
                    && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(e) => panic!("lock not released: {e:?}"),
            }
        }
    }
}

/// `(field, value)` pairs read from a vault.
type Values = Vec<(String, String)>;

/// Build the proxy entries of one sentinel lease from the secret's current values.
fn lease_entries(
    lease: &LeaseRecord,
    values: &Values,
) -> std::result::Result<Vec<ProxyEntry>, String> {
    let mut out = Vec::new();
    for (index, f) in lease.fields.iter().enumerate() {
        let Some(sentinel) = &f.sentinel else {
            continue;
        };
        let Some((_, value)) = values.iter().find(|(name, _)| name == &f.field) else {
            return Err(format!("field {:?} is no longer in the vault", f.field));
        };
        out.push(ProxyEntry {
            lease_id: lease.id.clone(),
            index,
            sentinel: sentinel.clone(),
            value: value.clone(),
            hosts: lease.hosts.clone(),
        });
    }
    Ok(out)
}

/// Read values of the given leases' secrets (one read per secret) and build entries.
fn build_entries(registry: &Registry, leases: &[&LeaseRecord], state: &mut ProxyState) {
    let mut cache: HashMap<(String, String), std::result::Result<Values, String>> = HashMap::new();
    for lease in leases {
        if lease.source_kind != SourceKind::Vault || !lease.fields.iter().any(|f| f.sentinel.is_some()) {
            continue;
        }
        let k = (lease.vault_id.clone(), lease.secret_key.clone());
        let values = cache
            .entry(k)
            .or_insert_with(|| match registry.get(&lease.vault_id) {
                None => Err("vault removed".to_string()),
                Some(v) => v.provider.read(&lease.secret_key).map_err(|e| e.message),
            });
        match values
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|v| lease_entries(lease, v))
        {
            Ok(e) => {
                state.suspended.remove(&lease.id);
                state.entries.insert(lease.id.clone(), e);
            }
            Err(msg) => {
                state.entries.remove(&lease.id);
                state.suspended.insert(lease.id.clone(), msg);
            }
        }
    }
}

impl Core {
    pub fn start(
        data_dir: PathBuf,
        bin_dir: PathBuf,
        observer: Arc<dyn ManagerObserver>,
        options: StartOptions,
    ) -> Result<Arc<Self>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dirs = DataDirs::create(&data_dir, options.values_root.as_deref())?;
        let instance_lock = lock_data_dir(&dirs.data)?;
        let gcloud = gcloud::GcloudSetup::new(dirs.gcloud.clone())?;
        let store = Arc::new(Store::open(&dirs.db())?);
        let activity = activity::ActivityLog::start(store.clone(), observer.clone());
        Settings::seed(&store, &options.settings)?;
        let settings = Settings::load(&store)?;
        let cert = ServerCert::load_or_create(&dirs.tls)?;

        // Vaults: build providers in parallel (Bitwarden may block while logging in). A
        // Bitwarden vault starts Locked; first drop any master password an earlier build
        // stored in the keychain.
        let registry = Registry::new();
        let vaults = store.list_vaults()?;
        let built: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = vaults
                .iter()
                .map(|v| {
                    let dirs = &dirs;
                    let cfg = effective_config(&settings, &v.config);
                    s.spawn(move || {
                        if matches!(cfg, VaultConfig::Bitwarden(_))
                            && let Err(e) = creds::delete_legacy_master_password(&v.id)
                        {
                            log::warn!("vault {}: {}", v.name, e.message);
                        }
                        Registry::build_provider(dirs, &v.id, &cfg)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(CoreError::internal("vault start panicked")))
                })
                .collect()
        });
        let mut vault_errors = HashMap::new();
        for (v, provider) in vaults.into_iter().zip(built) {
            match provider {
                Ok(provider) => registry.insert(VaultEntry {
                    id: v.id,
                    name: v.name,
                    config: v.config,
                    provider,
                }),
                Err(e) => {
                    log::error!("vault {}: {}", v.name, e.message);
                    vault_errors.insert(v.id, e.message);
                }
            }
        }
        let generators = crate::generator::GeneratorRegistry::new();
        generators.load(store.list_generators()?, &gcloud.runner);

        // Proxy entries of active sentinel leases.
        let t = now();
        let active = store.active_leases(t)?;
        let sentinel: Vec<&LeaseRecord> = active
            .iter()
            .filter(|l| l.mode == LeaseMode::Sentinel)
            .collect();
        let mut proxy_state = ProxyState::default();
        build_entries(&registry, &sentinel, &mut proxy_state);
        for lease in &active {
            if lease.source_kind == SourceKind::Generator {
                proxy_state.suspended.insert(lease.id.clone(),
                    "credential unavailable; run asm get to generate a token".into());
            }
        }

        let obs = observer.clone();
        let on_change: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || obs.changed(TOPIC_PROXY.to_string()));
        // A (re)started proxy may meet a firewall rule that changed meanwhile.
        let firewall_wake = Arc::new(Notify::new());
        let on_event: EventSink = {
            let sink = activity.proxy_sink();
            let wake = firewall_wake.clone();
            Arc::new(move |e: ProxyEvent| {
                if let ProxyEvent::Lifecycle { kind, .. } = &e
                    && matches!(*kind, "started" | "restarted")
                {
                    wake.notify_one();
                }
                sink(e)
            })
        };
        let proxy = ProxySupervisor::start(
            bin_dir.clone(),
            dirs.clone(),
            settings.proxy.clone(),
            proxy_state.flatten(),
            on_change,
            on_event,
        )?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("asm-manager")
            .enable_all()
            .build()?;
        let rt_handle = rt.handle().clone();
        let (changes, _) = watch::channel(0u64);
        let core = Arc::new(Self {
            dirs,
            bin_dir,
            store,
            registry,
            generators,
            authorization: Mutex::new(()),
            generation: Mutex::new(generation::GenerationState::new(Arc::new(now))),
            gcloud,
            gcloud_profiles: gcloud_profiles::GcloudProfiles::default(),
            proxy,
            cert,
            settings: RwLock::new(settings.clone()),
            book: Mutex::new(Book::default()),
            changes,
            proxy_state: Mutex::new(proxy_state),
            observer,
            rt: Mutex::new(Some(rt)),
            rt_handle,
            api: Mutex::new(None),
            last_active: Mutex::new(active.iter().map(|l| l.id.clone()).collect()),
            vault_errors: Mutex::new(vault_errors),
            activity,
            vault_ready: Mutex::new(HashMap::new()),
            connect_names: Mutex::new(HashMap::new()),
            instance_lock: Mutex::new(Some(instance_lock)),
            lease_wake: Arc::new(Notify::new()),
            firewall: Mutex::new(firewall::FirewallCheck::default()),
            firewall_wake,
        });
        {
            let suspended = lock(&core.proxy_state).suspended.clone();
            for l in &sentinel {
                if let Some(why) = suspended.get(&l.id) {
                    core.log_lease_suspended(l, why);
                }
            }
        }
        core.track_vaults();

        if let Err(e) = core.bind_api(&settings.api_bind, settings.api_port) {
            core.shutdown();
            return Err(e);
        }
        core.spawn_background();
        Ok(core)
    }

    fn spawn_background(self: &Arc<Self>) {
        // Sweep at the earliest active lease expiry, and at least every SWEEP_EVERY, so an
        // ended lease leaves the proxy within about a second of `expires_at`. The deadline
        // is wall-clock (tokio's monotonic sleep is only a bounded wait; `on_wake` covers
        // system sleep) and is recomputed whenever leases change.
        let weak = Arc::downgrade(self);
        let wake = self.lease_wake.clone();
        self.rt_handle.spawn(async move {
            let mut next_periodic = tokio::time::Instant::now() + SWEEP_EVERY;
            loop {
                let Some(core) = weak.upgrade() else { return };
                let notified = wake.notified();
                tokio::pin!(notified);
                // Register before reading the leases, so a change in between is not lost.
                notified.as_mut().enable();
                let next = {
                    let core = core.clone();
                    tokio::task::spawn_blocking(move || core.until_next_expiry())
                        .await
                        .ok()
                        .flatten()
                };
                drop(core);
                let periodic = next_periodic.saturating_duration_since(tokio::time::Instant::now());
                let delay = next.map_or(periodic, |d| d.min(periodic));
                let woken = tokio::select! {
                    _ = tokio::time::sleep(delay) => false,
                    _ = &mut notified => true,
                };
                if woken {
                    continue;
                }
                let Some(core) = weak.upgrade() else { return };
                let _ = tokio::task::spawn_blocking(move || core.sweep()).await;
                if tokio::time::Instant::now() >= next_periodic {
                    next_periodic = tokio::time::Instant::now() + SWEEP_EVERY;
                }
            }
        });
        let weak = Arc::downgrade(self);
        self.rt_handle.spawn(async move {
            let mut iv = tokio::time::interval(BW_SYNC_EVERY);
            iv.tick().await;
            loop {
                iv.tick().await;
                let Some(core) = weak.upgrade() else { return };
                let _ = tokio::task::spawn_blocking(move || core.sync_bitwarden()).await;
            }
        });
        // macOS Firewall: at start, every CHECK_EVERY and whenever woken.
        let weak = Arc::downgrade(self);
        let wake = self.firewall_wake.clone();
        self.rt_handle.spawn(async move {
            loop {
                let notified = wake.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let Some(core) = weak.upgrade() else { return };
                    let _ = tokio::task::spawn_blocking(move || core.check_firewall()).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(firewall::CHECK_EVERY) => {}
                    _ = &mut notified => {}
                }
            }
        });
    }

    pub fn notify(&self, topic: &str) {
        if topic == TOPIC_LEASES {
            self.lease_wake.notify_one();
        }
        self.observer.changed(topic.to_string())
    }

    /// Wall-clock time until the earliest expiry of an active lease (plus a small margin),
    /// `None` when no active lease expires.
    fn until_next_expiry(&self) -> Option<Duration> {
        let t = self.generation_now();
        let leases = self.store.active_leases(t).ok()?;
        let live = lock(&self.generation).next_expiry(t);
        let next = leases.iter().filter_map(|l| l.expires_at).chain(live).min()?;
        Some(
            to_system_time(next)
                .duration_since(SystemTime::now())
                .unwrap_or_default()
                + EXPIRY_MARGIN,
        )
    }

    /// Wake long polls after a request/pairing change.
    pub fn bump(&self) {
        self.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn settings(&self) -> Settings {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_settings(&self, s: Settings) -> Result<()> {
        s.save(&self.store)?;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = s;
        Ok(())
    }

    pub fn rt(&self) -> &tokio::runtime::Handle {
        &self.rt_handle
    }

    // ---- API listener ----

    /// Bind the HTTPS API to `bind:port` and replace the current listener. On failure the
    /// current listener stays.
    pub fn bind_api(self: &Arc<Self>, bind: &str, port: u16) -> Result<SocketAddr> {
        let ip: IpAddr = bind
            .trim()
            .parse()
            .map_err(|_| CoreError::invalid(format!("invalid bind address {bind:?}")))?;
        let addr = SocketAddr::new(ip, port);
        let listener = match std::net::TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e)
                if e.kind() == std::io::ErrorKind::AddrInUse
                    && port != 0
                    && self.api_addr().is_some_and(|a| a.port() == port) =>
            {
                // Same port, different address: the old listener must go first.
                let old = lock(&self.api).take();
                if let Some(old) = &old {
                    old.handle.shutdown();
                }
                let mut bound = None;
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(50));
                    if let Ok(l) = std::net::TcpListener::bind(addr) {
                        bound = Some(l);
                        break;
                    }
                }
                match bound {
                    Some(l) => l,
                    None => {
                        if let Some(old) = old {
                            self.bind_api(&old.addr.ip().to_string(), old.addr.port())?;
                        }
                        return Err(CoreError::invalid(format!("cannot listen on {addr}: {e}")));
                    }
                }
            }
            Err(e) => return Err(CoreError::invalid(format!("cannot listen on {addr}: {e}"))),
        };
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(self.cert.server_config()?);
        let handle = axum_server::Handle::new();
        let server = {
            let _g = self.rt_handle.enter();
            axum_server::tls_rustls::from_tcp_rustls(listener, tls)?.handle(handle.clone())
        };
        let app = api::router(self.clone()).into_make_service_with_connect_info::<SocketAddr>();
        self.rt_handle.spawn(async move {
            if let Err(e) = server.serve(app).await {
                log::error!("manager API server stopped: {e}");
            }
        });
        if let Some(old) = lock(&self.api).replace(ApiServer {
            handle,
            addr: local,
        }) {
            old.handle.graceful_shutdown(Some(Duration::from_secs(1)));
        }
        Ok(local)
    }

    /// Address the API listener is bound to.
    pub fn api_addr(&self) -> Option<SocketAddr> {
        lock(&self.api).as_ref().map(|a| a.addr)
    }

    // ---- proxy entries ----

    /// Static provider reads run outside every manager state lock. Authorization is
    /// rechecked before merging their result with live, per-lease generated values.
    pub(crate) fn reconcile_proxy_with(
        &self,
        retry_suspended: bool,
        mutate: impl FnOnce(&mut ProxyState),
    ) -> Result<()> {
        let (snapshot, todo) = {
            let _authority = lock(&self.authorization);
            let active = self.store.active_leases(self.generation_now())?;
            let mut state = lock(&self.proxy_state);
            mutate(&mut state);
            // Mutators mark material changes; ordinary sweeps avoid rewriting values.
            let todo: Vec<LeaseRecord> = active.iter()
                .filter(|l| l.source_kind == SourceKind::Vault && l.mode == LeaseMode::Sentinel
                    && l.fields.iter().any(|f| f.sentinel.is_some()))
                .filter(|l| (!state.entries.contains_key(&l.id) && !state.suspended.contains_key(&l.id))
                    || (retry_suspended && state.suspended.contains_key(&l.id)))
                .cloned().collect();
            (active, todo)
        };
        let mut read = ProxyState::default();
        build_entries(&self.registry, &todo.iter().collect::<Vec<_>>(), &mut read);
        let result = {
            let authority = lock(&self.authorization);
            let active = self.store.active_leases(self.generation_now())?;
            let mut state = lock(&self.proxy_state);
            for lease in &active {
                if lease.source_kind != SourceKind::Vault
                    || !snapshot.iter().any(|old| old.id == lease.id && old.revoked_at == lease.revoked_at) {
                    continue;
                }
                if let Some(entries) = read.entries.remove(&lease.id) {
                    state.dirty = true;
                    state.entries.insert(lease.id.clone(), entries);
                    state.resume(lease);
                } else if let Some(why) = read.suspended.remove(&lease.id) {
                    state.entries.remove(&lease.id);
                    state.dirty = true;
                    state.suspended.insert(lease.id.clone(), why);
                }
            }
            drop(state);
            self.publish_proxy_locked(&authority)
        };
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        self.notify(TOPIC_PROXY);
        result
    }

    pub fn sync_proxy_with(&self, retry_suspended: bool, mutate: impl FnOnce(&mut ProxyState)) {
        if let Err(e) = self.reconcile_proxy_with(retry_suspended, mutate) {
            log::error!("proxy apply: {}", e.message);
        }
    }

    /// Caller owns generation authorization. No observer callback is invoked here.
    pub(crate) fn publish_proxy_locked(&self, _guard: &MutexGuard<'_, ()>) -> Result<()> {
        let t = self.generation_now();
        let active = self.store.active_leases(t)?;
        let mut state = lock(&self.proxy_state);
        let ids: HashSet<&str> = active.iter().map(|l| l.id.as_str()).collect();
        let before = state.entries.len();
        state.entries.retain(|id, _| ids.contains(id.as_str()));
        state.dirty |= state.entries.len() != before;
        state.suspended.retain(|id, _| ids.contains(id.as_str()));
        let generation = lock(&self.generation);
        for lease in active.iter().filter(|l| l.source_kind == SourceKind::Generator) {
            match generation.cached.get(&lease.id).filter(|c|
                c.version == lease.credential_version && c.current.expires_at > t) {
                Some(cached) => {
                    state.resume(lease);
                    if lease.mode == LeaseMode::Sentinel {
                        let unchanged = state.entries.get(&lease.id).is_some_and(|entries|
                            entries.len() == lease.fields.iter().filter(|f| f.sentinel.is_some()).count()
                                && entries.iter().all(|entry| entry.value == cached.current.token
                                    && lease.fields.get(entry.index).and_then(|f| f.sentinel.as_ref()) == Some(&entry.sentinel)
                                    && entry.hosts == lease.hosts));
                        if !unchanged {
                            let entries = lease.fields.iter().enumerate().filter_map(|(index, f)|
                                f.sentinel.as_ref().map(|sentinel| ProxyEntry { lease_id: lease.id.clone(), index,
                                    sentinel: sentinel.clone(), value: cached.current.token.clone(), hosts: lease.hosts.clone() })).collect();
                            state.entries.insert(lease.id.clone(), entries);
                            state.dirty = true;
                        }
                    }
                }
                None => {
                    if state.entries.remove(&lease.id).is_some() { state.dirty = true; }
                    state.suspended.entry(lease.id.clone()).or_insert_with(||
                        "credential unavailable; run asm get to generate a token".into());
                }
            }
        }
        drop(generation);
        if !state.dirty { return Ok(()); }
        let result = self.proxy.apply_deferred(state.flatten());
        if result.is_ok() {
            state.dirty = false;
            state.account_cutovers.clear();
        }
        else {
            for lease in active.iter().filter(|l| l.source_kind == SourceKind::Generator && l.mode == LeaseMode::Sentinel) {
                state.suspended.insert(lease.id.clone(), "credential publication failed; run asm get to retry".into());
            }
        }
        result
    }

    /// Account deletion already removed the affected entries under authorization.
    /// Cut off forwarding on the old process even if writing new config fails.
    fn publish_proxy_account_retirement_locked(&self, _guard: &MutexGuard<'_, ()>, profile_id: i64) -> Result<()> {
        let mut state = lock(&self.proxy_state);
        let result = self.proxy.apply_after_stopping_deferred(state.flatten());
        state.dirty = result.is_err();
        if state.dirty {
            state.account_cutovers.insert(profile_id);
        } else {
            state.account_cutovers.clear();
        }
        result
    }

    /// Publish callbacks and resume audit rows only after releasing authorization.
    pub(crate) fn notify_proxy_changed(&self) {
        let resumed = {
            let mut state = lock(&self.proxy_state);
            if state.dirty {
                Vec::new()
            } else {
                let pending = std::mem::take(&mut state.pending_resumed);
                pending.into_values().filter(|lease| !state.suspended.contains_key(&lease.id)).collect()
            }
        };
        for lease in resumed {
            if self.store.get_lease(&lease.id).ok().flatten()
                .is_some_and(|current| current.is_active(self.generation_now())) {
                self.log_lease_resumed(&lease);
            }
        }
        self.proxy.notify_changed();
    }

    pub fn sync_proxy(&self, retry_suspended: bool) {
        self.sync_proxy_with(retry_suspended, |_| {})
    }

    /// Lease ids of active sentinel leases that are suspended.
    pub fn suspended(&self) -> BTreeMap<String, String> {
        lock(&self.proxy_state).suspended.clone()
    }

    // ---- periodic work ----

    /// Expire requests, prune history and the activity log, notice lease expiry, vault
    /// availability changes, and drop ended leases from the proxy.
    pub fn sweep(&self) {
        let t = now();
        self.expire_requests(t);
        self.sweep_generated_at(self.generation_now());
        self.sweep_gcloud_setup(t);
        let _ = self.store.prune_history(t - HISTORY_SECS);
        self.prune_activity(t);
        if let Ok(active) = self.store.active_leases(t) {
            let ids: HashSet<String> = active.into_iter().map(|l| l.id).collect();
            let mut last = lock(&self.last_active);
            if *last != ids {
                let gone: Vec<String> = last.difference(&ids).cloned().collect();
                *last = ids;
                drop(last);
                // Revocations were logged when they happened.
                for id in gone {
                    if let Ok(Some(l)) = self.store.get_lease(&id)
                        && l.revoked_at.is_none()
                    {
                        self.log_lease_expired(&l);
                    }
                }
                self.notify(TOPIC_LEASES);
            }
        }
        self.track_vaults();
        self.sync_proxy(false);
    }

    pub fn on_wake(&self) {
        self.sweep();
        self.sync_proxy(true);
        self.recheck_firewall();
    }

    fn sync_bitwarden(&self) {
        let mut any = false;
        for v in self.registry.all() {
            if matches!(v.config, VaultConfig::Bitwarden(_)) {
                any = true;
                if let Err(e) = v.provider.sync() {
                    log::warn!("bitwarden sync {}: {}", v.name, e.message);
                }
            }
        }
        if any {
            self.notify(TOPIC_VAULTS);
            self.track_vaults();
            self.sync_proxy(true);
        }
    }

    pub fn shutdown(&self) {
        self.begin_generation_shutdown();
        self.shutdown_gcloud_setup();
        self.gcloud_profiles.shutdown();
        if let Some(api) = lock(&self.api).take() {
            api.handle.shutdown();
        }
        self.proxy.shutdown();
        self.registry.shutdown_all();
        self.finish_generation_shutdown();
        if let Some(rt) = lock(&self.rt).take() {
            rt.shutdown_background();
        }
        self.activity.stop();
        // Another manager may use the data directory from now on.
        lock(&self.instance_lock).take();
    }
}

/// Vault config with the global default `bw` path filled in.
pub fn effective_config(settings: &Settings, cfg: &VaultConfig) -> VaultConfig {
    match cfg {
        VaultConfig::Bitwarden(b) if b.bw_path.is_none() && settings.bw_path.is_some() => {
            let mut b = b.clone();
            b.bw_path = settings.bw_path.clone();
            VaultConfig::Bitwarden(b)
        }
        c => c.clone(),
    }
}
