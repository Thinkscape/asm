//! Manager core: shared state, startup, the HTTPS API listener, lease sweep and the
//! proxy entry set. Request flows live in `requests`, pairing in `pairing`, UI operations
//! in `admin`, HTTP handlers in `api`, the audit trail in `activity`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asm_proto::wire::LeaseMode;
use tokio::sync::{Notify, watch};

use crate::error::{CoreError, Result};
use crate::ffi::ManagerObserver;
use crate::paths::DataDirs;
use crate::proxy::{ProxyEntry, ProxySupervisor};
use crate::settings::Settings;
use crate::store::{LeaseRecord, Store};
use crate::tls::ServerCert;
use crate::vault::registry::{Registry, VaultEntry};
use crate::vault::{VaultConfig, creds};

pub mod activity;
pub mod admin;
pub mod api;
pub mod netinfo;
pub mod pairing;
pub mod requests;

pub use requests::Book;

pub const TOPIC_REQUESTS: &str = "requests";
pub const TOPIC_LEASES: &str = "leases";
pub const TOPIC_HOSTS: &str = "hosts";
pub const TOPIC_VAULTS: &str = "vaults";
pub const TOPIC_PROXY: &str = "proxy";
pub const TOPIC_SETTINGS: &str = "settings";
pub const TOPIC_ACTIVITY: &str = "activity";

const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Sleep past an expiry instant by this much, so `now()` (whole seconds) has reached it.
const EXPIRY_MARGIN: Duration = Duration::from_millis(20);
const BW_SYNC_EVERY: Duration = Duration::from_secs(300);
/// Resolved requests are kept in the database this long.
const HISTORY_SECS: i64 = 30 * 86_400;

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
}

impl ProxyState {
    fn flatten(&self) -> Vec<ProxyEntry> {
        self.entries.values().flatten().cloned().collect()
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

        // Proxy entries of active sentinel leases.
        let t = now();
        let active = store.active_leases(t)?;
        let sentinel: Vec<&LeaseRecord> = active
            .iter()
            .filter(|l| l.mode == LeaseMode::Sentinel)
            .collect();
        let mut proxy_state = ProxyState::default();
        build_entries(&registry, &sentinel, &mut proxy_state);

        let obs = observer.clone();
        let on_change: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || obs.changed(TOPIC_PROXY.to_string()));
        let proxy = ProxySupervisor::start(
            bin_dir.clone(),
            dirs.clone(),
            settings.proxy.clone(),
            proxy_state.flatten(),
            on_change,
            activity.proxy_sink(),
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
            lease_wake: Arc::new(Notify::new()),
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
        let t = now();
        let next = self
            .store
            .active_leases(t)
            .ok()?
            .iter()
            .filter_map(|l| l.expires_at)
            .min()?;
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

    /// Bring the proxy entry set in line with the active sentinel leases and apply it when
    /// anything changed. `mutate` runs first under the state lock (insert entries built from
    /// values just read, or patch values after an update); `retry_suspended` re-reads
    /// suspended leases.
    pub fn sync_proxy_with(&self, retry_suspended: bool, mutate: impl FnOnce(&mut ProxyState)) {
        let t = now();
        let active = match self.store.active_leases(t) {
            Ok(a) => a,
            Err(e) => {
                log::error!("sync proxy: {}", e.message);
                return;
            }
        };
        let active: Vec<&LeaseRecord> = active
            .iter()
            .filter(|l| l.mode == LeaseMode::Sentinel)
            .collect();
        let ids: BTreeSet<&str> = active.iter().map(|l| l.id.as_str()).collect();
        let mut st = lock(&self.proxy_state);
        let fingerprint = |st: &ProxyState| -> Vec<(String, usize, String, String)> {
            st.entries
                .values()
                .flatten()
                .map(|e| {
                    (
                        e.lease_id.clone(),
                        e.index,
                        e.sentinel.clone(),
                        e.value.clone(),
                    )
                })
                .collect()
        };
        let before = (fingerprint(&st), st.suspended.clone());
        mutate(&mut st);
        st.entries.retain(|id, _| ids.contains(id.as_str()));
        st.suspended.retain(|id, _| ids.contains(id.as_str()));
        let todo: Vec<&LeaseRecord> = active
            .iter()
            .copied()
            .filter(|l| {
                let known = st.entries.contains_key(&l.id);
                let suspended = st.suspended.contains_key(&l.id);
                (!known && !suspended) || (suspended && retry_suspended)
            })
            .collect();
        build_entries(&self.registry, &todo, &mut st);
        let changed = before != (fingerprint(&st), st.suspended.clone());
        if changed {
            for l in &active {
                let was = before.1.contains_key(&l.id);
                match st.suspended.get(&l.id) {
                    Some(why) if !was => self.log_lease_suspended(l, why),
                    None if was && st.entries.contains_key(&l.id) => self.log_lease_resumed(l),
                    _ => {}
                }
            }
            let entries = st.flatten();
            if let Err(e) = self.proxy.apply(entries) {
                log::error!("proxy apply: {}", e.message);
            }
            drop(st);
            self.notify(TOPIC_LEASES);
            self.notify(TOPIC_PROXY);
        }
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
        if let Some(api) = lock(&self.api).take() {
            api.handle.shutdown();
        }
        self.proxy.shutdown();
        self.registry.shutdown_all();
        if let Some(rt) = lock(&self.rt).take() {
            rt.shutdown_background();
        }
        self.activity.stop();
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
