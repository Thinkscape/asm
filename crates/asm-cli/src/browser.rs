//! `asm browser install|uninstall|status`: send a browser's HTTPS through this
//! machine's proxy router and make it trust the asm browser CA (plan step 11).
//!
//! Installs are recorded in `<config>/browsers.json` (changed under an flock on
//! `<config>/browsers.lock`), keyed by target and location. The CA is saved as
//! `<config>/browser/ca-<sha8>.crt`.

use crate::api::Api;
use crate::error::CliError;
use crate::files::{ensure_private_dir, lock_file, write_file_atomic};
use crate::router::{self, DEFAULT_PORT, RouterStatus};
use crate::service;
use crate::state;
use crate::tls::pem_to_der;
use asm_proto::crypto::{hex_encode, random_bytes, sha256_hex};
use asm_proto::error::EXIT_INVALID;
use asm_proto::wire::ProxyInfo;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RECORDS_NAME: &str = "browsers.json";
const RECORDS_LOCK: &str = "browsers.lock";
const CHROME: &str = "chrome";
const T3CODE: &str = "t3code";
const OPENBOT: &str = "openbot";
/// Oldest Chrome whose `ServerCertificate` trust rows asm relies on.
const MIN_CHROME_MAJOR: u32 = 134;
/// `trust_settings` of a `ServerCertificate` row: trusted anchor.
const CA_TRUST: [u8; 4] = [0x0A, 0x02, 0x08, 0x03];
const SHELL_DIR: &str = "tools/chrome-headless-shell";
const SHELL_NAME: &str = "chrome-headless-shell";
/// Under the shell directory: the real binaries behind asm's wrappers.
const REAL_DIR: &str = "asm-real";
const WRAPPER_HEAD: &str = "#!/bin/sh\n# asm browser install t3code ";
const NSS_TOOLS: &str = "install NSS tools: sudo apt install libnss3-tools (Debian/Ubuntu) or sudo dnf install nss-tools (Fedora)";
const TRUST_USER_WIDE: &str = "This adds the asm browser CA to your user's trust store; every app using it will trust certificates the asm manager issues (asm issues them only for sites with an active login grant). Re-run with --trust-user-wide to continue.";

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

#[derive(clap::Subcommand)]
pub enum BrowserCommand {
    /// Send a browser's HTTPS through asm's proxy router and trust the asm browser CA,
    /// so login grants (asm get --login-url) work in it.
    Install {
        #[command(subcommand)]
        target: InstallTarget,
    },
    /// Undo asm browser install for one browser.
    Uninstall {
        #[command(subcommand)]
        target: UninstallTarget,
    },
    /// Show each installed browser and the proxy router.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum InstallTarget {
    /// A Chrome profile (other Chromium browsers: --user-data-dir). Quit the browser first.
    Chrome {
        #[command(flatten)]
        location: ChromeLocation,
        #[command(flatten)]
        router: RouterArgs,
    },
    /// T3 Code's preview browser (chrome-headless-shell under $T3CODE_HOME or ~/.t3).
    T3code {
        /// macOS: add the asm browser CA to your login keychain (required there).
        #[arg(long)]
        trust_user_wide: bool,
        #[command(flatten)]
        router: RouterArgs,
    },
    /// OpenBot (trusts only the OS certificate store).
    Openbot {
        /// Add the asm browser CA to your user's certificate trust store (required).
        #[arg(long)]
        trust_user_wide: bool,
        #[command(flatten)]
        router: RouterArgs,
    },
}

#[derive(clap::Subcommand)]
pub enum UninstallTarget {
    /// A Chrome profile. Quit the browser first.
    Chrome {
        #[command(flatten)]
        location: ChromeLocation,
    },
    /// T3 Code's preview browser.
    T3code,
    /// OpenBot.
    Openbot,
}

#[derive(clap::Args)]
pub struct ChromeLocation {
    /// Profile directory name or display name (default: Default).
    #[arg(long)]
    profile: Option<String>,
    /// The browser's user data directory (default: Chrome's).
    #[arg(long)]
    user_data_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct RouterArgs {
    /// Don't install the proxy router service; run "asm proxy-router run" yourself.
    #[arg(long)]
    no_service: bool,
    /// Proxy router port on 127.0.0.1 (default: the one other browsers use, else 7418).
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
}

pub fn run(cmd: BrowserCommand) -> Result<(), CliError> {
    match cmd {
        BrowserCommand::Install { target } => match target {
            InstallTarget::Chrome { location, router } => install_chrome(location, router),
            InstallTarget::T3code { trust_user_wide, router } => install_t3code(trust_user_wide, router),
            InstallTarget::Openbot { trust_user_wide, router } => install_openbot(trust_user_wide, router),
        },
        BrowserCommand::Uninstall { target } => match target {
            UninstallTarget::Chrome { location } => uninstall_chrome(location),
            UninstallTarget::T3code => uninstall_t3code(),
            UninstallTarget::Openbot => uninstall_openbot(),
        },
        BrowserCommand::Status { json } => status(json),
    }
}

// ---------------------------------------------------------------------------
// Records (`browsers.json`)
// ---------------------------------------------------------------------------

/// One install: a target at one location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Record {
    target: String,
    /// The location: Chrome profile directory, T3 base directory, or OpenBot's trust store.
    key: String,
    /// The setting before asm's first install (Chrome's `proxy` pref; null = unset).
    #[serde(default)]
    original: Value,
    /// Every CA sha256 asm may have installed here and not yet removed.
    ca_shas: Vec<String>,
    current_sha: String,
    router_port: u16,
    service: bool,
    installed_at: String,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_data_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// t3code: the browser versions asm wrapped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_store: Option<TrustStore>,
}

#[derive(Default, Serialize, Deserialize)]
struct RecordsFile {
    records: Vec<Record>,
}

fn records_path() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join(RECORDS_NAME))
}

fn load_records() -> Result<Vec<Record>, CliError> {
    let path = records_path()?;
    match fs::read(&path) {
        Ok(b) => serde_json::from_slice::<RecordsFile>(&b)
            .map(|f| f.records)
            .map_err(|e| CliError::failure(format!("{} is not valid: {e}", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(io_err("reading", &path, e)),
    }
}

fn save_records(records: &[Record]) -> Result<(), CliError> {
    let dir = state::config_dir()?;
    let json = serde_json::to_vec_pretty(&RecordsFile { records: records.to_vec() }).expect("records serialize");
    write_file_atomic(&dir, RECORDS_NAME, &json).map(|_| ())
}

/// Take the records lock (held until the returned file is dropped).
fn lock_records() -> Result<File, CliError> {
    let dir = state::config_dir()?;
    ensure_private_dir(&dir)?;
    lock_file(&dir, RECORDS_LOCK, true)
        .map_err(|e| io_err("locking", &dir.join(RECORDS_LOCK), e))
        .map(|f| f.expect("a blocking lock is always taken"))
}

/// The record of `target` at `key`.
fn find(records: &[Record], target: &str, key: &str) -> Option<usize> {
    records.iter().position(|r| r.target == target && r.key == key)
}

fn upsert(records: &mut Vec<Record>, record: Record) {
    match find(records, &record.target, &record.key) {
        Some(i) => records[i] = record,
        None => records.push(record),
    }
}

/// The router port for an install: `--port`, else the one other installs use, else 7418.
fn router_port(records: &[Record], requested: Option<u16>, target: &str, key: &str) -> Result<u16, CliError> {
    let others = records
        .iter()
        .find(|r| !(r.target == target && r.key == key))
        .map(|r| r.router_port);
    match (requested, others) {
        (Some(p), Some(o)) if p != o => Err(CliError::invalid(format!(
            "the proxy router already serves other browsers on port {o}; pass --port {o}"
        ))),
        (Some(p), _) => Ok(p),
        (None, Some(o)) => Ok(o),
        (None, None) => Ok(DEFAULT_PORT),
    }
}

/// After removing a record: drop CA files no record needs; with no records left,
/// remove the router service and its saved routes.
fn finish_removal(records: &[Record]) -> Result<(), CliError> {
    let dir = browser_dir()?;
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(sha8) = name.strip_prefix("ca-").and_then(|n| n.strip_suffix(".crt")) else {
                continue;
            };
            if !records.iter().any(|r| r.ca_shas.iter().any(|s| s.starts_with(sha8))) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    if !records.is_empty() {
        return Ok(());
    }
    if service::service_installed()? {
        service::remove_service()?;
    }
    remove_if_exists(&router::routes_path()?)
}

// ---------------------------------------------------------------------------
// The asm browser CA
// ---------------------------------------------------------------------------

struct Ca {
    der: Vec<u8>,
    sha: String,
    file: PathBuf,
}

impl Ca {
    fn nickname(&self) -> String {
        nickname(&self.sha)
    }
}

fn nickname(sha: &str) -> String {
    format!("asm browser CA {}", &sha[..8])
}

/// `<config>/browser` (0700).
fn browser_dir() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join("browser"))
}

fn ca_file(sha: &str) -> Result<PathBuf, CliError> {
    Ok(browser_dir()?.join(format!("ca-{}.crt", &sha[..8])))
}

/// Fetch the manager's browser CA and save it as `<config>/browser/ca-<sha8>.crt`.
fn fetch_ca() -> Result<Ca, CliError> {
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    let info: ProxyInfo = api.get("/proxy-info")?;
    let pem = info
        .browser_ca_pem
        .ok_or_else(|| CliError::failure("the manager does not support browser logins; upgrade it"))?;
    let der = pem_to_der(pem.as_bytes())
        .ok_or_else(|| CliError::failure("the manager sent an invalid browser CA"))?;
    let sha = sha256_hex(&der);
    let dir = browser_dir()?;
    ensure_private_dir(&dir)?;
    let mut pem = pem;
    if !pem.ends_with('\n') {
        pem.push('\n');
    }
    let file = write_file_atomic(&dir, &format!("ca-{}.crt", &sha[..8]), pem.as_bytes())?;
    Ok(Ca { der, sha, file })
}

/// The manager's current browser CA sha256, when this machine is paired and the
/// manager answers (`None` otherwise; a warning explains why when it should have).
fn manager_ca_sha(info: Option<&ProxyInfo>) -> Option<String> {
    info.and_then(|i| i.browser_ca_pem.as_deref())
        .and_then(|pem| pem_to_der(pem.as_bytes()))
        .map(sha256_hex)
}

fn fetch_proxy_info() -> Option<ProxyInfo> {
    let host = state::load().ok().flatten()?;
    let fetched = Api::for_host(&host).and_then(|api| api.get::<ProxyInfo>("/proxy-info"));
    match fetched {
        Ok(info) => Some(info),
        Err(e) => {
            eprintln!("warning: cannot check the manager's browser CA: {}", e.message);
            None
        }
    }
}

/// Install the router service (or restart it on this asm version) and wait for it,
/// unless `no_service`. Returns whether the service is used.
fn ensure_router(port: u16, no_service: bool) -> Result<bool, CliError> {
    if no_service {
        return Ok(false);
    }
    let installed = service::service_installed()?;
    match router::status().ok().flatten() {
        Some(st) if installed && st.port == port && st.version == VERSION => {}
        Some(st) if installed && st.port == port => {
            // The router runs an older asm: restart it on this one.
            service::remove_service()?;
            service::install_service(port)?;
        }
        _ => service::install_service(port)?,
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Trust stores: NSS databases (Linux) and the macOS login keychain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TrustStore {
    /// An NSS database directory (`sql:` format).
    Nss { db: String },
    /// A macOS keychain plus the user's SSL trust settings.
    Keychain { path: String },
}

impl TrustStore {
    fn location(&self) -> &str {
        match self {
            TrustStore::Nss { db } => db,
            TrustStore::Keychain { path } => path,
        }
    }

    fn add(&self, ca: &Ca) -> Result<(), CliError> {
        match self {
            TrustStore::Nss { db } => {
                let certutil = nss_prepare(Path::new(db))?;
                run_cmd(Command::new(&certutil)
                    .args(["-A", "-t", "C,,", "-n", &ca.nickname(), "-i"])
                    .arg(&ca.file)
                    .arg("-d")
                    .arg(format!("sql:{db}")))
                .map(|_| ())
            }
            TrustStore::Keychain { path } => {
                let added = run_cmd(Command::new("security")
                    .args(["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", path])
                    .arg(&ca.file));
                match added {
                    Err(e) if e.message.contains("already exists") => Ok(()),
                    other => other.map(|_| ()),
                }
            }
        }
    }

    fn has(&self, sha: &str) -> Result<bool, String> {
        match self {
            TrustStore::Nss { db } => {
                let certutil = certutil().map_err(|_| "certutil is missing".to_owned())?;
                Ok(Command::new(certutil)
                    .args(["-L", "-n", &nickname(sha), "-d", &format!("sql:{db}")])
                    .output()
                    .is_ok_and(|o| o.status.success()))
            }
            TrustStore::Keychain { path } => {
                let out = Command::new("security")
                    .args(["find-certificate", "-a", "-Z", path])
                    .output()
                    .map_err(|e| format!("running security: {e}"))?;
                let text = String::from_utf8_lossy(&out.stdout).to_ascii_uppercase();
                let sha1 = ca_sha1(sha);
                Ok(text.contains(&sha.to_ascii_uppercase())
                    || sha1.is_some_and(|s| text.contains(&s.to_ascii_uppercase())))
            }
        }
    }

    /// Remove the CA `sha` when present.
    fn remove(&self, sha: &str) -> Result<(), CliError> {
        if !self.has(sha).map_err(CliError::failure)? {
            return Ok(());
        }
        match self {
            TrustStore::Nss { db } => run_cmd(Command::new(certutil()?)
                .args(["-D", "-n", &nickname(sha), "-d", &format!("sql:{db}")]))
            .map(|_| ()),
            TrustStore::Keychain { path } => {
                let file = ca_file(sha)?;
                if file.exists() {
                    run_cmd(Command::new("security").arg("remove-trusted-cert").arg(&file))?;
                }
                let hash = ca_sha1(sha).unwrap_or_else(|| sha.to_owned());
                run_cmd(Command::new("security").args(["delete-certificate", "-Z", &hash, path])).map(|_| ())
            }
        }
    }
}

/// SHA-1 (hex) of the saved CA `sha`, for `security delete-certificate -Z`.
fn ca_sha1(sha: &str) -> Option<String> {
    let pem = fs::read(ca_file(sha).ok()?).ok()?;
    let der = pem_to_der(&pem)?;
    Some(hex_encode(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &der).as_ref()))
}

/// Remove old CAs from `store`, except those another install still trusts there.
fn remove_old(store: &TrustStore, records: &[Record], target: &str, key: &str, shas: &[String]) -> Result<(), CliError> {
    for sha in shas {
        let shared = records.iter().any(|r| {
            !(r.target == target && r.key == key)
                && r.trust_store.as_ref() == Some(store)
                && r.ca_shas.contains(sha)
        });
        if !shared {
            store.remove(sha)?;
        }
    }
    Ok(())
}

/// `certutil` on `PATH`.
fn certutil() -> Result<PathBuf, CliError> {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("certutil"))
                .find(|p| p.is_file())
        })
        .ok_or_else(|| CliError::failure(NSS_TOOLS))
}

/// Create the NSS database `db` unless it exists; returns `certutil`.
fn nss_prepare(db: &Path) -> Result<PathBuf, CliError> {
    let certutil = certutil()?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(db)
        .map_err(|e| io_err("creating", db, e))?;
    if !db.join("cert9.db").exists() {
        run_cmd(Command::new(&certutil)
            .args(["-N", "--empty-password", "-d"])
            .arg(format!("sql:{}", db.display())))?;
    }
    Ok(certutil)
}

fn login_keychain() -> Result<TrustStore, CliError> {
    Ok(TrustStore::Keychain {
        path: state::home_dir()?
            .join("Library/Keychains/login.keychain-db")
            .to_string_lossy()
            .into_owned(),
    })
}

/// OpenBot on Linux: `~/.pki/nssdb` when it exists, else
/// `${XDG_DATA_HOME:-~/.local/share}/pki/nssdb`.
fn user_nss_db() -> Result<PathBuf, CliError> {
    let home = state::home_dir()?;
    let legacy = home.join(".pki/nssdb");
    if legacy.is_dir() {
        return Ok(legacy);
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"));
    Ok(data.join("pki/nssdb"))
}

// ---------------------------------------------------------------------------
// PAC
// ---------------------------------------------------------------------------

/// Only `https:`/`wss:` go to the router, never with a direct fallback.
fn pac_script(port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{\n  if (url.substring(0, 6) == \"https:\" || url.substring(0, 4) == \"wss:\") return \"PROXY 127.0.0.1:{port}\";\n  return \"DIRECT\";\n}}\n"
    )
}

fn pac_url(port: u16) -> String {
    format!(
        "data:application/x-ns-proxy-autoconfig;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(pac_script(port))
    )
}

/// The Chrome `proxy` pref asm writes.
fn proxy_pref(port: u16) -> Value {
    json!({"mode": "pac_script", "pac_url": pac_url(port)})
}

/// Whether `v` is a `proxy` pref asm wrote (for any port).
fn is_asm_proxy_pref(v: &Value) -> bool {
    let Some(url) = v.get("pac_url").and_then(Value::as_str) else {
        return false;
    };
    let Some(b64) = url.strip_prefix("data:application/x-ns-proxy-autoconfig;base64,") else {
        return false;
    };
    let Some(text) = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return false;
    };
    let port = text
        .split_once("PROXY 127.0.0.1:")
        .and_then(|(_, rest)| rest.split('"').next())
        .and_then(|p| p.parse::<u16>().ok());
    port.is_some_and(|p| *v == proxy_pref(p))
}

/// A system-wide HTTPS proxy browsers would use: `scutil --proxy` (macOS) or
/// `HTTPS_PROXY`/`https_proxy` (Linux).
fn system_proxy() -> Option<String> {
    if cfg!(target_os = "macos") {
        let out = Command::new("scutil").arg("--proxy").output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let on = |key: &str| {
            text.lines().any(|l| {
                l.split_once(':')
                    .is_some_and(|(k, v)| k.trim() == key && v.trim() == "1")
            })
        };
        if on("HTTPSEnable") {
            return Some("the macOS HTTPS proxy".into());
        }
        if on("ProxyAutoConfigEnable") {
            return Some("the macOS automatic proxy configuration".into());
        }
        None
    } else {
        ["HTTPS_PROXY", "https_proxy"]
            .into_iter()
            .find(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
            .map(|k| format!("{k} is set"))
    }
}

fn existing_proxy(what: &str) -> CliError {
    CliError::failure(format!(
        "this browser already uses a proxy ({what}); asm browser logins can't chain proxies yet"
    ))
}

// ---------------------------------------------------------------------------
// chrome
// ---------------------------------------------------------------------------

struct ChromeProfile {
    udd: PathBuf,
    /// Profile directory name inside `udd`.
    dir: String,
    path: PathBuf,
    /// "Chrome", or "the browser" for other user data directories.
    browser: &'static str,
}

fn default_user_data_dir() -> Result<PathBuf, CliError> {
    let home = state::home_dir()?;
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library/Application Support/Google/Chrome"));
    }
    // Chrome itself honors XDG_CONFIG_HOME.
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    Ok(config.join("google-chrome"))
}

/// Profiles listed in `Local State` (`profile.info_cache`): (directory, display name).
fn local_state_profiles(udd: &Path) -> Vec<(String, String)> {
    let Ok(bytes) = fs::read(udd.join("Local State")) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = v
        .pointer("/profile/info_cache")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(dir, e)| (dir.clone(), e.get("name").and_then(Value::as_str).unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn resolve_profile(loc: &ChromeLocation) -> Result<ChromeProfile, CliError> {
    let (udd, browser) = match &loc.user_data_dir {
        Some(p) => (p.clone(), "the browser"),
        None => (default_user_data_dir()?, "Chrome"),
    };
    if !udd.is_dir() {
        return Err(CliError::failure(format!(
            "no browser user data directory at {}; start {browser} once, or pass --user-data-dir",
            udd.display()
        )));
    }
    let udd = fs::canonicalize(&udd).unwrap_or(udd);
    let wanted = loc.profile.as_deref().unwrap_or("Default");
    let plain = !wanted.is_empty() && !wanted.contains('/') && wanted != "." && wanted != "..";
    let profiles = local_state_profiles(&udd);
    let dir = if plain && udd.join(wanted).is_dir() {
        wanted.to_owned()
    } else {
        let named: Vec<&(String, String)> = profiles.iter().filter(|(_, n)| n == wanted).collect();
        match named.as_slice() {
            [(dir, _)] if udd.join(dir).is_dir() => dir.clone(),
            [] | [_] => {
                let list = if profiles.is_empty() {
                    "none found".to_owned()
                } else {
                    profiles
                        .iter()
                        .map(|(d, n)| format!("{d} ({n})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                return Err(CliError::failure(format!(
                    "no profile {wanted:?} in {}; profiles: {list}",
                    udd.display()
                )));
            }
            many => {
                return Err(CliError::failure(format!(
                    "several profiles are named {wanted:?}: {}; pass the directory name",
                    many.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>().join(", ")
                )));
            }
        }
    };
    let path = udd.join(&dir);
    Ok(ChromeProfile { udd, dir, path, browser })
}

/// The pid of a live browser holding `<udd>/SingletonLock` on this host.
fn running_pid(udd: &Path) -> Option<i32> {
    let target = fs::read_link(udd.join("SingletonLock")).ok()?;
    let (host, pid) = target.to_str()?.rsplit_once('-')?;
    let pid: i32 = pid.parse().ok().filter(|p| *p > 0)?;
    if host != crate::hostinfo::hostname() {
        return None;
    }
    // SAFETY: kill with signal 0 only checks for the process.
    let alive = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive.then_some(pid)
}

fn refuse_running(p: &ChromeProfile) -> Result<(), CliError> {
    match running_pid(&p.udd) {
        Some(pid) => Err(CliError::failure(format!(
            "quit {} first (pid {pid}), then re-run",
            p.browser
        ))),
        None => Ok(()),
    }
}

/// `<udd>/Last Version` must be at least 134 (a warning when the file is missing).
fn check_chrome_version(udd: &Path) -> Result<(), CliError> {
    let path = udd.join("Last Version");
    match fs::read_to_string(&path) {
        Ok(v) => {
            let v = v.trim();
            match v.split('.').next().and_then(|m| m.parse::<u32>().ok()) {
                Some(major) if major >= MIN_CHROME_MAJOR => Ok(()),
                Some(_) => Err(CliError::failure(format!(
                    "the browser is version {v}; asm browser logins need Chrome {MIN_CHROME_MAJOR} or later"
                ))),
                None => {
                    eprintln!("warning: cannot read the browser version in {}", path.display());
                    Ok(())
                }
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!(
                "warning: {} is missing; cannot check that the browser is Chrome {MIN_CHROME_MAJOR} or later",
                path.display()
            );
            Ok(())
        }
        Err(e) => Err(io_err("reading", &path, e)),
    }
}

/// Add (or replace) the CA row in `<profile>/ServerCertificate`, removing `old` rows.
fn write_ca_row(profile: &Path, ca: &Ca, old: &[String]) -> Result<(), CliError> {
    let path = profile.join("ServerCertificate");
    let created = !path.exists();
    let db_err = |e: rusqlite::Error| CliError::failure(format!("updating {}: {e}", path.display()));
    let mut conn = rusqlite::Connection::open(&path).map_err(db_err)?;
    if created {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io_err("setting permissions of", &path, e))?;
    }
    let tx = conn.transaction().map_err(db_err)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
         INSERT OR IGNORE INTO meta(key, value) VALUES('version', 1);
         INSERT OR IGNORE INTO meta(key, value) VALUES('last_compatible_version', 1);
         CREATE TABLE IF NOT EXISTS certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL);",
    )
    .map_err(db_err)?;
    for sha in old {
        tx.execute("DELETE FROM certificates WHERE sha256hash_hex = ?1", [sha])
            .map_err(db_err)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO certificates(sha256hash_hex, der_cert, trust_settings) VALUES(?1, ?2, ?3)",
        rusqlite::params![ca.sha, ca.der, CA_TRUST.as_slice()],
    )
    .map_err(db_err)?;
    tx.commit().map_err(db_err)
}

fn remove_ca_rows(profile: &Path, shas: &[String]) -> Result<(), CliError> {
    let path = profile.join("ServerCertificate");
    if !path.exists() {
        return Ok(());
    }
    let db_err = |e: rusqlite::Error| CliError::failure(format!("updating {}: {e}", path.display()));
    let conn = rusqlite::Connection::open(&path).map_err(db_err)?;
    for sha in shas {
        match conn.execute("DELETE FROM certificates WHERE sha256hash_hex = ?1", [sha]) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(m))) if m.contains("no such table") => return Ok(()),
            Err(e) => return Err(db_err(e)),
        }
    }
    Ok(())
}

fn has_ca_row(profile: &Path, sha: &str) -> bool {
    let path = profile.join("ServerCertificate");
    rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|c| {
            c.query_row(
                "SELECT count(*) FROM certificates WHERE sha256hash_hex = ?1 AND trust_settings = ?2",
                rusqlite::params![sha, CA_TRUST.as_slice()],
                |row| row.get::<_, i64>(0),
            )
        })
        .is_ok_and(|n| n > 0)
}

/// `<profile>/Preferences` as a JSON object (empty when missing) and its file mode.
fn read_prefs(path: &Path) -> Result<(serde_json::Map<String, Value>, Option<u32>), CliError> {
    match fs::read(path) {
        Ok(b) => {
            let v: Value = serde_json::from_slice(&b)
                .map_err(|e| CliError::failure(format!("{} is not valid JSON: {e}", path.display())))?;
            let Value::Object(map) = v else {
                return Err(CliError::failure(format!("{} is not a JSON object", path.display())));
            };
            let mode = fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o7777);
            Ok((map, mode))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok((serde_json::Map::new(), None)),
        Err(e) => Err(io_err("reading", path, e)),
    }
}

/// Replace `path` atomically, keeping its mode (0600 for a new file).
fn write_prefs(path: &Path, prefs: &serde_json::Map<String, Value>, mode: Option<u32>) -> Result<(), CliError> {
    let dir = path.parent().expect("Preferences has a parent");
    let name = path.file_name().expect("Preferences has a name").to_string_lossy();
    let data = serde_json::to_vec(prefs).expect("prefs serialize");
    let written = write_file_atomic(dir, &name, &data)?;
    fs::set_permissions(&written, fs::Permissions::from_mode(mode.unwrap_or(0o600)))
        .map_err(|e| io_err("setting permissions of", &written, e))
}

fn install_chrome(loc: ChromeLocation, r: RouterArgs) -> Result<(), CliError> {
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let p = resolve_profile(&loc)?;
    refuse_running(&p)?;
    check_chrome_version(&p.udd)?;
    let prefs_path = p.path.join("Preferences");
    let (mut prefs, mode) = read_prefs(&prefs_path)?;
    let current = prefs.get("proxy").cloned();
    if let Some(v) = &current
        && !is_asm_proxy_pref(v)
        && *v != json!({"mode": "system"})
    {
        let mode = v.get("mode").and_then(Value::as_str).unwrap_or("custom");
        return Err(existing_proxy(&format!("profile proxy setting, mode {mode}")));
    }
    if let Some(what) = system_proxy() {
        return Err(existing_proxy(&what));
    }
    let key = p.path.to_string_lossy().into_owned();
    let port = router_port(&records, r.port, CHROME, &key)?;
    let existing = find(&records, CHROME, &key).map(|i| records[i].clone());
    let ca = fetch_ca()?;
    let service = ensure_router(port, r.no_service)?;
    let old: Vec<String> = existing
        .as_ref()
        .map(|e| e.ca_shas.iter().filter(|s| **s != ca.sha).cloned().collect())
        .unwrap_or_default();
    write_ca_row(&p.path, &ca, &old)?;
    let original = match &existing {
        Some(e) => e.original.clone(),
        None => current.unwrap_or(Value::Null),
    };
    prefs.insert("proxy".into(), proxy_pref(port));
    write_prefs(&prefs_path, &prefs, mode)?;
    upsert(
        &mut records,
        Record {
            target: CHROME.into(),
            key,
            original,
            ca_shas: vec![ca.sha.clone()],
            current_sha: ca.sha,
            router_port: port,
            service,
            installed_at: asm_proto::time::now_rfc3339(),
            version: VERSION.into(),
            user_data_dir: Some(p.udd.to_string_lossy().into_owned()),
            profile: Some(p.dir.clone()),
            versions: Vec::new(),
            trust_store: None,
        },
    );
    save_records(&records)?;
    println!("installed asm browser logins in {} (profile {})", p.path.display(), p.dir);
    no_service_hint(service, port);
    let browser = if p.browser == "Chrome" { "Chrome" } else { "the browser" };
    println!("restart {browser} once. HTTPS pages need asm's proxy router; asm doctor checks it.");
    Ok(())
}

fn uninstall_chrome(loc: ChromeLocation) -> Result<(), CliError> {
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let p = resolve_profile(&loc)?;
    let key = p.path.to_string_lossy().into_owned();
    let i = find(&records, CHROME, &key).ok_or_else(|| not_installed(CHROME, &key))?;
    refuse_running(&p)?;
    let rec = records[i].clone();
    remove_ca_rows(&p.path, &rec.ca_shas)?;
    let prefs_path = p.path.join("Preferences");
    let (mut prefs, mode) = read_prefs(&prefs_path)?;
    if prefs.get("proxy") == Some(&proxy_pref(rec.router_port)) {
        match rec.original {
            Value::Null => prefs.remove("proxy"),
            v => prefs.insert("proxy".into(), v),
        };
        write_prefs(&prefs_path, &prefs, mode)?;
    } else {
        eprintln!(
            "warning: the proxy setting in {} was changed after install; left as is",
            prefs_path.display()
        );
    }
    records.remove(i);
    save_records(&records)?;
    finish_removal(&records)?;
    println!("removed asm browser logins from {}; restart {} once", p.path.display(), p.browser);
    Ok(())
}

// ---------------------------------------------------------------------------
// t3code
// ---------------------------------------------------------------------------

/// `$T3CODE_HOME`, else `~/.t3`.
fn t3_base() -> Result<PathBuf, CliError> {
    match std::env::var_os("T3CODE_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        Some(p) => Ok(p),
        None => Ok(state::home_dir()?.join(".t3")),
    }
}

/// `<config>/browser/t3code`: `XDG_DATA_HOME` of the wrapped browser (Linux).
fn t3_data_dir() -> Result<PathBuf, CliError> {
    Ok(browser_dir()?.join("t3code"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Shell {
    version: String,
    /// `<base>/tools/chrome-headless-shell/<platform>/<version>`.
    dir: PathBuf,
}

impl Shell {
    fn exe(&self) -> PathBuf {
        self.dir.join(SHELL_NAME)
    }
}

/// T3's browsers: `<base>/tools/chrome-headless-shell/<platform>/<version>/chrome-headless-shell`.
fn find_shells(base: &Path) -> Vec<Shell> {
    let root = base.join(SHELL_DIR);
    let mut out = Vec::new();
    for platform in read_dirs(&root) {
        if platform.file_name().is_some_and(|n| n == REAL_DIR) {
            continue;
        }
        for dir in read_dirs(&platform) {
            if dir.join(SHELL_NAME).is_file() {
                let version = dir.file_name().expect("entries have names").to_string_lossy().into_owned();
                out.push(Shell { version, dir });
            }
        }
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

fn read_dirs(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

fn is_wrapper(exe: &Path) -> bool {
    let mut head = vec![0u8; WRAPPER_HEAD.len()];
    File::open(exe)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| head == WRAPPER_HEAD.as_bytes())
}

/// Single-quote for `sh`.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The script replacing T3's browser. `data_dir` (Linux) selects the private NSS DB.
fn wrapper_script(real: &Path, port: u16, data_dir: Option<&Path>) -> String {
    let mut s = format!("{WRAPPER_HEAD}{VERSION}; real binary: {}\n", real.display());
    if let Some(d) = data_dir {
        s.push_str(&format!("export XDG_DATA_HOME={}\n", sq(&d.to_string_lossy())));
        s.push_str(&format!(
            "[ -d \"$HOME/.pki/nssdb\" ] && export HOME={}\n",
            sq(&d.join("home").to_string_lossy())
        ));
    }
    s.push_str(&format!(
        "exec {} {} \"$@\"\n",
        sq(&real.to_string_lossy()),
        sq(&format!("--proxy-server=https=127.0.0.1:{port}"))
    ));
    s
}

fn is_exdev(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EXDEV)
}

/// Copy `src` to `dst` with hard links (copies across file systems).
fn link_copy(src: &Path, dst: &Path) -> Result<(), CliError> {
    fs::create_dir_all(dst).map_err(|e| io_err("creating", dst, e))?;
    if let Ok(m) = fs::metadata(src) {
        let _ = fs::set_permissions(dst, m.permissions());
    }
    for entry in fs::read_dir(src).map_err(|e| io_err("reading", src, e))? {
        let entry = entry.map_err(|e| io_err("reading", src, e))?;
        let (from, to) = (entry.path(), dst.join(entry.file_name()));
        let kind = entry.file_type().map_err(|e| io_err("inspecting", &from, e))?;
        if kind.is_dir() {
            link_copy(&from, &to)?;
        } else if kind.is_symlink() {
            let target = fs::read_link(&from).map_err(|e| io_err("reading", &from, e))?;
            std::os::unix::fs::symlink(target, &to).map_err(|e| io_err("creating", &to, e))?;
        } else {
            match fs::hard_link(&from, &to) {
                Ok(()) => {}
                Err(e) if is_exdev(&e) => {
                    fs::copy(&from, &to).map_err(|e| io_err("copying to", &to, e))?;
                }
                Err(e) => return Err(io_err("linking", &to, e)),
            }
        }
    }
    Ok(())
}

/// Replace `path` atomically with an executable (0755) holding `data`.
fn write_exec_atomic(path: &Path, data: &[u8]) -> Result<(), CliError> {
    let dir = path.parent().expect("executables have a parent");
    let name = path.file_name().expect("executables have a name").to_string_lossy();
    let tmp = dir.join(format!(".{name}.asm-{}", hex_encode(&random_bytes::<6>())));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| io_err("creating", &tmp, e))?;
        f.write_all(data).map_err(|e| io_err("writing", &tmp, e))?;
        f.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|e| io_err("setting permissions of", &tmp, e))?;
        f.sync_all().map_err(|e| io_err("syncing", &tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| io_err("renaming to", path, e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Move `from` over `to` (a copy and rename across file systems).
fn move_over(from: &Path, to: &Path) -> Result<(), CliError> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if is_exdev(&e) => {
            let dir = to.parent().expect("files have a parent");
            let tmp = dir.join(format!(".asm-restore-{}", hex_encode(&random_bytes::<6>())));
            fs::copy(from, &tmp).map_err(|e| io_err("copying to", &tmp, e))?;
            fs::rename(&tmp, to).map_err(|e| {
                let _ = fs::remove_file(&tmp);
                io_err("renaming to", to, e)
            })?;
            remove_if_exists(from)
        }
        Err(e) => Err(io_err("renaming to", to, e)),
    }
}

/// Wrap every T3 browser under `base`; returns the wrapped versions. Real binaries go
/// to `<base>/tools/chrome-headless-shell/asm-real/<version>/`; leftovers of versions
/// T3 removed are deleted.
fn install_wrappers(base: &Path, port: u16, data_dir: Option<&Path>) -> Result<Vec<String>, CliError> {
    let shells = find_shells(base);
    let real_root = base.join(SHELL_DIR).join(REAL_DIR);
    let mut versions = Vec::new();
    for shell in &shells {
        let real_dir = real_root.join(&shell.version);
        let real = real_dir.join(SHELL_NAME);
        if is_wrapper(&shell.exe()) {
            if !real.is_file() {
                return Err(CliError::failure(format!(
                    "{} is an asm wrapper but its real browser {} is missing; delete {} so T3 downloads it again, then re-run",
                    shell.exe().display(),
                    real.display(),
                    shell.dir.display()
                )));
            }
        } else {
            if fs::symlink_metadata(&real_dir).is_ok() {
                fs::remove_dir_all(&real_dir).map_err(|e| io_err("removing", &real_dir, e))?;
            }
            link_copy(&shell.dir, &real_dir)?;
        }
        write_exec_atomic(&shell.exe(), wrapper_script(&real, port, data_dir).as_bytes())?;
        versions.push(shell.version.clone());
    }
    for stale in read_dirs(&real_root) {
        let name = stale.file_name().expect("entries have names").to_string_lossy().into_owned();
        if !versions.contains(&name) {
            fs::remove_dir_all(&stale).map_err(|e| io_err("removing", &stale, e))?;
        }
    }
    Ok(versions)
}

/// Put each real binary back over its wrapper and delete `asm-real`.
fn remove_wrappers(base: &Path) -> Result<(), CliError> {
    let real_root = base.join(SHELL_DIR).join(REAL_DIR);
    for shell in find_shells(base) {
        let real = real_root.join(&shell.version).join(SHELL_NAME);
        if !is_wrapper(&shell.exe()) {
            if real.exists() {
                eprintln!("warning: {} was changed after install; left as is", shell.exe().display());
            }
            continue;
        }
        if real.is_file() {
            move_over(&real, &shell.exe())?;
        } else {
            eprintln!(
                "warning: the real browser for {} is missing; delete {} so T3 downloads it again",
                shell.exe().display(),
                shell.dir.display()
            );
        }
    }
    if fs::symlink_metadata(&real_root).is_ok() {
        fs::remove_dir_all(&real_root).map_err(|e| io_err("removing", &real_root, e))?;
    }
    Ok(())
}

/// A proxy that T3's `service.env` sets.
fn service_env_proxy(base: &Path) -> Option<String> {
    let path = base.join("service.env");
    let text = fs::read_to_string(&path).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line.split_once('=')?;
        let name = name.trim();
        let upper = name.to_ascii_uppercase();
        let value = value.trim().trim_matches(['"', '\'']);
        (!line.starts_with('#') && upper.ends_with("_PROXY") && upper != "NO_PROXY" && !value.is_empty())
            .then(|| format!("{} sets {name}", path.display()))
    })
}

fn trust_user_wide(app: &str) -> CliError {
    CliError::new(EXIT_INVALID, format!("{app} only trusts the OS certificate store. {TRUST_USER_WIDE}"))
}

fn install_t3code(trust_user_wide_ok: bool, r: RouterArgs) -> Result<(), CliError> {
    let macos = cfg!(target_os = "macos");
    if macos && !trust_user_wide_ok {
        return Err(trust_user_wide("T3 Code's browser on macOS"));
    }
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let base = t3_base()?;
    let shells = find_shells(&base);
    if shells.is_empty() {
        return Err(CliError::failure(format!(
            "no T3 browser under {}; open a preview in T3 once, then re-run",
            base.join(SHELL_DIR).display()
        )));
    }
    if let Some(what) = service_env_proxy(&base) {
        return Err(existing_proxy(&what));
    }
    let data_dir = t3_data_dir()?;
    let store = if macos {
        login_keychain()?
    } else {
        certutil()?;
        TrustStore::Nss { db: data_dir.join("pki/nssdb").to_string_lossy().into_owned() }
    };
    let key = base.to_string_lossy().into_owned();
    let port = router_port(&records, r.port, T3CODE, &key)?;
    let existing = find(&records, T3CODE, &key).map(|i| records[i].clone());
    let ca = fetch_ca()?;
    let service = ensure_router(port, r.no_service)?;
    if !macos {
        ensure_private_dir(&data_dir)?;
        ensure_private_dir(&data_dir.join("pki"))?;
    }
    store.add(&ca)?;
    if let Some(e) = &existing {
        let old: Vec<String> = e.ca_shas.iter().filter(|s| **s != ca.sha).cloned().collect();
        remove_old(&store, &records, T3CODE, &key, &old)?;
    }
    if !macos {
        let pki = data_dir.join("home/.pki");
        ensure_private_dir(&pki)?;
        let link = pki.join("nssdb");
        let db = data_dir.join("pki/nssdb");
        if fs::read_link(&link).ok().as_deref() != Some(db.as_path()) {
            remove_if_exists(&link)?;
            std::os::unix::fs::symlink(&db, &link).map_err(|e| io_err("creating", &link, e))?;
        }
    }
    let versions = install_wrappers(&base, port, (!macos).then_some(data_dir.as_path()))?;
    upsert(
        &mut records,
        Record {
            target: T3CODE.into(),
            key,
            original: Value::Null,
            ca_shas: vec![ca.sha.clone()],
            current_sha: ca.sha,
            router_port: port,
            service,
            installed_at: asm_proto::time::now_rfc3339(),
            version: VERSION.into(),
            user_data_dir: None,
            profile: None,
            versions: versions.clone(),
            trust_store: Some(store),
        },
    );
    save_records(&records)?;
    println!("wrapped T3's browser {} under {}", versions.join(", "), base.join(SHELL_DIR).display());
    no_service_hint(service, port);
    println!("takes effect the next time T3 starts its browser (idle browsers close after 5 minutes; restart T3 to apply now)");
    Ok(())
}

fn uninstall_t3code() -> Result<(), CliError> {
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let base = t3_base()?;
    let key = base.to_string_lossy().into_owned();
    let i = find(&records, T3CODE, &key).ok_or_else(|| not_installed(T3CODE, &key))?;
    let rec = records.remove(i);
    remove_wrappers(&base)?;
    match &rec.trust_store {
        Some(store @ TrustStore::Keychain { .. }) => remove_old(store, &records, T3CODE, &key, &rec.ca_shas)?,
        Some(TrustStore::Nss { .. }) => {
            let dir = t3_data_dir()?;
            if fs::symlink_metadata(&dir).is_ok() {
                fs::remove_dir_all(&dir).map_err(|e| io_err("removing", &dir, e))?;
            }
        }
        None => {}
    }
    save_records(&records)?;
    finish_removal(&records)?;
    println!("restored T3's browser under {}; restart T3 to apply now", base.join(SHELL_DIR).display());
    Ok(())
}

// ---------------------------------------------------------------------------
// openbot
// ---------------------------------------------------------------------------

fn install_openbot(trust_user_wide_ok: bool, r: RouterArgs) -> Result<(), CliError> {
    if !trust_user_wide_ok {
        return Err(trust_user_wide("OpenBot"));
    }
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let store = if cfg!(target_os = "macos") {
        login_keychain()?
    } else {
        certutil()?;
        TrustStore::Nss { db: user_nss_db()?.to_string_lossy().into_owned() }
    };
    let key = store.location().to_owned();
    let port = router_port(&records, r.port, OPENBOT, &key)?;
    let existing = find(&records, OPENBOT, &key).map(|i| records[i].clone());
    let ca = fetch_ca()?;
    let service = ensure_router(port, r.no_service)?;
    store.add(&ca)?;
    if let Some(e) = &existing {
        let old: Vec<String> = e.ca_shas.iter().filter(|s| **s != ca.sha).cloned().collect();
        remove_old(&store, &records, OPENBOT, &key, &old)?;
    }
    upsert(
        &mut records,
        Record {
            target: OPENBOT.into(),
            key,
            original: Value::Null,
            ca_shas: vec![ca.sha.clone()],
            current_sha: ca.sha,
            router_port: port,
            service,
            installed_at: asm_proto::time::now_rfc3339(),
            version: VERSION.into(),
            user_data_dir: None,
            profile: None,
            versions: Vec::new(),
            trust_store: Some(store),
        },
    );
    save_records(&records)?;
    no_service_hint(service, port);
    println!(
        "In OpenBot: create a named browser profile, set its proxy to http://127.0.0.1:{port}, assign it to your agents, and restart OpenBot. OpenBot can't put a proxy on the Shared or agent-only profiles; on a Linux server an auto_proxy setting on the OpenBot service routes those too (asm skill install --print-setup, section OpenBot)."
    );
    Ok(())
}

fn uninstall_openbot() -> Result<(), CliError> {
    let _lock = lock_records()?;
    let mut records = load_records()?;
    let i = records
        .iter()
        .position(|r| r.target == OPENBOT)
        .ok_or_else(|| CliError::failure("asm browser install openbot is not installed on this machine"))?;
    let rec = records.remove(i);
    if let Some(store) = &rec.trust_store {
        remove_old(store, &records, OPENBOT, &rec.key, &rec.ca_shas)?;
    }
    save_records(&records)?;
    finish_removal(&records)?;
    println!("removed the asm browser CA from {}; restart OpenBot", rec.key);
    Ok(())
}

// ---------------------------------------------------------------------------
// status and doctor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Installed,
    Incomplete(String),
    /// T3 downloaded a browser version asm has not wrapped.
    Drift(String),
    Stale,
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::Installed => "installed",
            State::Incomplete(_) | State::Drift(_) => "incomplete",
            State::Stale => "stale",
        }
    }
}

/// The command that (re)installs `r`.
fn fix_command(r: &Record) -> String {
    let mut cmd = String::new();
    if r.target == T3CODE
        && t3_base().is_ok_and(|b| b.to_string_lossy() != r.key)
    {
        cmd.push_str(&format!("T3CODE_HOME={} ", quote_arg(&r.key)));
    }
    cmd.push_str("asm browser install ");
    cmd.push_str(&r.target);
    if r.target == CHROME {
        if let Some(udd) = &r.user_data_dir {
            cmd.push_str(&format!(" --user-data-dir {}", quote_arg(udd)));
        }
        if let Some(p) = &r.profile {
            cmd.push_str(&format!(" --profile {}", quote_arg(p)));
        }
    }
    if r.target == OPENBOT || (r.target == T3CODE && matches!(r.trust_store, Some(TrustStore::Keychain { .. }))) {
        cmd.push_str(" --trust-user-wide");
    }
    if !r.service {
        cmd.push_str(" --no-service");
    }
    if r.router_port != DEFAULT_PORT {
        cmd.push_str(&format!(" --port {}", r.router_port));
    }
    cmd
}

fn quote_arg(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+:@%=,".contains(&b)) {
        s.to_owned()
    } else {
        sq(s)
    }
}

fn check(r: &Record, manager_sha: Option<&str>) -> State {
    if manager_sha.is_some_and(|s| s != r.current_sha) {
        return State::Stale;
    }
    let trusted = |store: &TrustStore| match store.has(&r.current_sha) {
        Ok(true) => None,
        Ok(false) => Some(format!("the asm browser CA is missing from {}", store.location())),
        Err(e) => Some(e),
    };
    match r.target.as_str() {
        CHROME => {
            let profile = Path::new(&r.key);
            if !has_ca_row(profile, &r.current_sha) {
                return State::Incomplete(format!(
                    "the asm browser CA is missing from {}",
                    profile.join("ServerCertificate").display()
                ));
            }
            let prefs = profile.join("Preferences");
            let ok = read_prefs(&prefs).is_ok_and(|(p, _)| p.get("proxy") == Some(&proxy_pref(r.router_port)));
            if !ok {
                return State::Incomplete(format!("the proxy setting in {} is not asm's", prefs.display()));
            }
            State::Installed
        }
        T3CODE => {
            let shells = find_shells(Path::new(&r.key));
            if shells.is_empty() {
                return State::Incomplete(format!("no T3 browser under {}", Path::new(&r.key).join(SHELL_DIR).display()));
            }
            if let Some(s) = shells.iter().find(|s| !is_wrapper(&s.exe())) {
                return State::Drift(format!("T3 updated its browser to {}", s.version));
            }
            match r.trust_store.as_ref().and_then(trusted) {
                Some(reason) => State::Incomplete(reason),
                None => State::Installed,
            }
        }
        OPENBOT => match r.trust_store.as_ref().and_then(trusted) {
            Some(reason) => State::Incomplete(reason),
            None => State::Installed,
        },
        other => State::Incomplete(format!("unknown target {other}")),
    }
}

fn status_line(r: &Record, state: &State) -> String {
    let fix = fix_command(r);
    let what = match state {
        State::Installed => "installed".to_owned(),
        State::Incomplete(reason) => format!("incomplete {reason} — fix: {fix}"),
        State::Drift(reason) => format!("{reason} — fix: {fix}"),
        State::Stale => format!("stale CA — fix: {fix}"),
    };
    format!("{} {}: {what}", r.target, r.key)
}

/// Status lines of browser installs that would not route a login grant right now
/// (for example T3 downloaded a browser version asm has not wrapped). The CA is not
/// compared with the manager's here; `asm browser status` does that.
pub(crate) fn unready_installs() -> Vec<String> {
    load_records()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| match check(r, None) {
            State::Installed => None,
            state => Some(status_line(r, &state)),
        })
        .collect()
}

/// What to do when the router is not running.
fn router_fix(records: &[Record]) -> String {
    if service::service_installed().unwrap_or(false) {
        if cfg!(target_os = "macos") {
            format!(
                "launchctl kickstart -k gui/$UID/{} (logs: ~/Library/Logs/asm-proxy-router.log)",
                service::LAUNCHD_LABEL
            )
        } else {
            "systemctl --user restart asm-proxy-router (logs: journalctl --user -u asm-proxy-router)".to_owned()
        }
    } else if let Some(r) = records.iter().find(|r| r.service) {
        fix_command(r)
    } else {
        let port = records.first().map_or(DEFAULT_PORT, |r| r.router_port);
        let port = if port == DEFAULT_PORT { String::new() } else { format!(" --port {port}") };
        format!("start \"asm proxy-router run{port}\" under your supervisor")
    }
}

fn last_routed(st: &RouterStatus) -> String {
    st.last_routed
        .as_ref()
        .map_or("never".to_owned(), |l| format!("{}:{} at {}", l.host, l.port, l.at))
}

fn no_service_hint(service: bool, port: u16) {
    if !service {
        let port = if port == DEFAULT_PORT { String::new() } else { format!(" --port {port}") };
        println!("no router service installed: start \"asm proxy-router run{port}\" under your supervisor");
    }
}

#[derive(Serialize)]
struct JsonBrowser<'a> {
    target: &'a str,
    key: &'a str,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
    router_port: u16,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    versions: &'a [String],
}

#[derive(Serialize)]
struct JsonRouter {
    running: bool,
    service_installed: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    status: Option<RouterStatus>,
}

fn status(json: bool) -> Result<(), CliError> {
    let records = load_records()?;
    let manager_sha = if records.is_empty() { None } else { manager_ca_sha(fetch_proxy_info().as_ref()) };
    let states: Vec<State> = records.iter().map(|r| check(r, manager_sha.as_deref())).collect();
    let router = router::status()?;
    let service_installed = service::service_installed()?;
    if json {
        let browsers: Vec<JsonBrowser> = records
            .iter()
            .zip(&states)
            .map(|(r, s)| JsonBrowser {
                target: &r.target,
                key: &r.key,
                state: s.name(),
                reason: match s {
                    State::Incomplete(x) | State::Drift(x) => Some(x),
                    _ => None,
                },
                fix: (*s != State::Installed).then(|| fix_command(r)),
                router_port: r.router_port,
                versions: &r.versions,
            })
            .collect();
        let out = json!({
            "browsers": browsers,
            "router": JsonRouter { running: router.is_some(), service_installed, status: router },
        });
        println!("{}", serde_json::to_string_pretty(&out).expect("status serializes"));
        return Ok(());
    }
    if records.is_empty() {
        println!("no browser installs; run asm browser install chrome|t3code|openbot");
    }
    for (r, s) in records.iter().zip(&states) {
        println!("{}", status_line(r, s));
    }
    let service = if service_installed { "service installed" } else { "no service" };
    match &router {
        Some(st) => println!(
            "router: running on 127.0.0.1:{} (asm {}, {service}) routes:{} last_routed:{} last_error:{}",
            st.port,
            st.version,
            st.routes.len(),
            last_routed(st),
            st.last_error.as_deref().unwrap_or("none")
        ),
        None if records.is_empty() => println!("router: not running ({service})"),
        None => println!("router: not running ({service}) — fix: {}", router_fix(&records)),
    }
    Ok(())
}

/// Severity of an `asm doctor` line.
pub(crate) enum Level {
    Ok,
    Warn,
    Fail,
}

/// `asm doctor` lines for the router and installed browsers; none without installs.
pub(crate) fn doctor_checks(info: Option<&ProxyInfo>) -> Vec<(Level, &'static str, String)> {
    let records = match load_records() {
        Ok(r) => r,
        Err(e) => return vec![(Level::Fail, "browsers", e.message)],
    };
    let Some(first) = records.first() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let reinstall = format!("asm browser install {}", first.target);
    match router::status() {
        Ok(Some(st)) => {
            out.push((
                Level::Ok,
                "router",
                format!(
                    "127.0.0.1:{} asm {} routes:{} last_routed:{}",
                    st.port,
                    st.version,
                    st.routes.len(),
                    last_routed(&st)
                ),
            ));
            if let Some(e) = &st.last_error {
                out.push((Level::Fail, "router", e.clone()));
            }
            if st.port != first.router_port {
                out.push((
                    Level::Fail,
                    "router",
                    format!("listens on port {} but browsers use {} — fix: {reinstall}", st.port, first.router_port),
                ));
            }
            if st.version != VERSION {
                out.push((
                    Level::Warn,
                    "router",
                    format!("runs asm {}, this CLI is {VERSION} — fix: {reinstall}", st.version),
                ));
            }
        }
        Ok(None) => {
            let held = router::lock_path().ok().and_then(|p| {
                let dir = p.parent()?;
                let name = p.file_name()?.to_str()?;
                p.exists().then(|| lock_file(dir, name, false).ok()).flatten()
            });
            let detail = if matches!(held, Some(None)) {
                "proxy router runs but its admin socket does not answer"
            } else {
                "proxy router not running"
            };
            out.push((Level::Fail, "router", format!("{detail} — fix: {}", router_fix(&records))));
        }
        Err(e) => out.push((Level::Fail, "router", e.message)),
    }
    if cfg!(target_os = "linux") && service::service_installed().unwrap_or(false) && linger_off() {
        out.push((
            Level::Warn,
            "router",
            "router stops when you log out — fix: loginctl enable-linger $USER".to_owned(),
        ));
    }
    let manager_sha = manager_ca_sha(info);
    for r in &records {
        let s = check(r, manager_sha.as_deref());
        let level = if s == State::Installed { Level::Ok } else { Level::Fail };
        out.push((level, "browser", status_line(r, &s)));
    }
    out
}

/// `loginctl show-user $USER --property=Linger` says `Linger=no`.
fn linger_off() -> bool {
    let Some(user) = std::env::var_os("USER").filter(|u| !u.is_empty()) else {
        return false;
    };
    Command::new("loginctl")
        .arg("show-user")
        .arg(user)
        .arg("--property=Linger")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "Linger=no")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn io_err(what: &str, path: &Path, e: std::io::Error) -> CliError {
    CliError::failure(format!("{what} {}: {e}", path.display()))
}

fn remove_if_exists(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("removing", path, e)),
    }
}

fn not_installed(target: &str, key: &str) -> CliError {
    CliError::failure(format!("asm browser install {target} is not installed for {key}"))
}

/// Run a command; its stdout, or an error with its stderr.
fn run_cmd(cmd: &mut Command) -> Result<String, CliError> {
    let shown = format!("{cmd:?}").replace('"', "");
    let out = cmd
        .output()
        .map_err(|e| CliError::failure(format!("running {shown}: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    Err(CliError::failure(format!(
        "{shown} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_routes_only_https_and_wss() {
        assert_eq!(
            pac_script(7418),
            "function FindProxyForURL(url, host) {\n  if (url.substring(0, 6) == \"https:\" || url.substring(0, 4) == \"wss:\") return \"PROXY 127.0.0.1:7418\";\n  return \"DIRECT\";\n}\n"
        );
        let url = pac_url(7418);
        let b64 = url.strip_prefix("data:application/x-ns-proxy-autoconfig;base64,").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), pac_script(7418));
        assert!(is_asm_proxy_pref(&proxy_pref(7500)));
        assert!(!is_asm_proxy_pref(&json!({"mode": "system"})));
        assert!(!is_asm_proxy_pref(&json!({"mode": "pac_script", "pac_url": "https://wpad/x.pac"})));
        let mut other = proxy_pref(7418);
        other["pac_mandatory"] = json!(true);
        assert!(!is_asm_proxy_pref(&other));
    }

    #[test]
    fn wrapper_scripts() {
        let real = Path::new("/home/u/.t3/tools/chrome-headless-shell/asm-real/157.0.1/chrome-headless-shell");
        assert_eq!(
            wrapper_script(real, 7418, Some(Path::new("/home/u/.config/asm/browser/t3code"))),
            format!(
                "#!/bin/sh\n# asm browser install t3code {VERSION}; real binary: {}\nexport XDG_DATA_HOME='/home/u/.config/asm/browser/t3code'\n[ -d \"$HOME/.pki/nssdb\" ] && export HOME='/home/u/.config/asm/browser/t3code/home'\nexec '{}' '--proxy-server=https=127.0.0.1:7418' \"$@\"\n",
                real.display(),
                real.display()
            )
        );
        assert_eq!(
            wrapper_script(Path::new("/a/it's/chrome-headless-shell"), 7500, None),
            format!(
                "#!/bin/sh\n# asm browser install t3code {VERSION}; real binary: /a/it's/chrome-headless-shell\nexec '/a/it'\\''s/chrome-headless-shell' '--proxy-server=https=127.0.0.1:7500' \"$@\"\n"
            )
        );
    }

    fn fake_t3(base: &Path, platform: &str, version: &str) -> PathBuf {
        let dir = base.join(SHELL_DIR).join(platform).join(version);
        fs::create_dir_all(dir.join("resources")).unwrap();
        fs::write(dir.join(SHELL_NAME), "#!/bin/sh\necho real\n").unwrap();
        fs::set_permissions(dir.join(SHELL_NAME), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.join("resources/icudtl.dat"), "icu").unwrap();
        std::os::unix::fs::symlink("resources/icudtl.dat", dir.join("icu-link")).unwrap();
        dir.join(SHELL_NAME)
    }

    #[test]
    fn t3_wrappers_install_and_uninstall() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("t3");
        let exe = fake_t3(&base, "linux64", "157.0.1");
        let data = tmp.path().join("cfg/asm/browser/t3code");
        // A leftover of a version T3 since removed.
        fs::create_dir_all(base.join(SHELL_DIR).join(REAL_DIR).join("150.0.0")).unwrap();

        assert_eq!(install_wrappers(&base, 7418, Some(&data)).unwrap(), vec!["157.0.1"]);
        let real = base.join(SHELL_DIR).join(REAL_DIR).join("157.0.1");
        assert!(is_wrapper(&exe));
        assert_eq!(fs::read_to_string(&exe).unwrap(), wrapper_script(&real.join(SHELL_NAME), 7418, Some(&data)));
        assert_eq!(fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::read_to_string(real.join(SHELL_NAME)).unwrap(), "#!/bin/sh\necho real\n");
        assert_eq!(fs::read_to_string(real.join("resources/icudtl.dat")).unwrap(), "icu");
        assert_eq!(fs::read_link(real.join("icu-link")).unwrap(), Path::new("resources/icudtl.dat"));
        assert!(!base.join(SHELL_DIR).join(REAL_DIR).join("150.0.0").exists());
        // The real directory is not a platform.
        assert_eq!(find_shells(&base).len(), 1);
        let out = Command::new(&exe).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "real\n");

        // Reinstall on another port rewrites the wrapper; a new T3 version is wrapped too.
        let newer = fake_t3(&base, "linux64", "158.0.2");
        assert!(!is_wrapper(&newer));
        assert_eq!(install_wrappers(&base, 7500, None).unwrap(), vec!["157.0.1", "158.0.2"]);
        assert!(fs::read_to_string(&exe).unwrap().contains("127.0.0.1:7500"));
        assert!(is_wrapper(&newer));

        remove_wrappers(&base).unwrap();
        assert_eq!(fs::read_to_string(&exe).unwrap(), "#!/bin/sh\necho real\n");
        assert_eq!(fs::read_to_string(&newer).unwrap(), "#!/bin/sh\necho real\n");
        assert!(!base.join(SHELL_DIR).join(REAL_DIR).exists());
    }

    #[test]
    fn t3_wrapper_without_real_binary_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = fake_t3(tmp.path(), "mac-arm64", "157.0.1");
        fs::write(&exe, wrapper_script(Path::new("/gone"), 7418, None)).unwrap();
        let e = install_wrappers(tmp.path(), 7418, None).unwrap_err();
        assert!(e.message.contains("is an asm wrapper but its real browser"), "{}", e.message);
    }

    #[test]
    fn service_env_proxies() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(service_env_proxy(tmp.path()), None);
        fs::write(tmp.path().join("service.env"), "# HTTPS_PROXY=x\nNO_PROXY=localhost\nFOO=1\n").unwrap();
        assert_eq!(service_env_proxy(tmp.path()), None);
        fs::write(tmp.path().join("service.env"), "export https_proxy=\"http://p:3128\"\n").unwrap();
        assert!(service_env_proxy(tmp.path()).unwrap().ends_with("service.env sets https_proxy"));
    }

    #[test]
    fn router_ports() {
        let rec = |target: &str, key: &str, port| Record {
            target: target.into(),
            key: key.into(),
            original: Value::Null,
            ca_shas: vec![],
            current_sha: "ab".repeat(32),
            router_port: port,
            service: true,
            installed_at: String::new(),
            version: VERSION.into(),
            user_data_dir: None,
            profile: None,
            versions: vec![],
            trust_store: None,
        };
        assert_eq!(router_port(&[], None, CHROME, "/p").unwrap(), DEFAULT_PORT);
        assert_eq!(router_port(&[], Some(7500), CHROME, "/p").unwrap(), 7500);
        let records = [rec(T3CODE, "/t3", 7500)];
        assert_eq!(router_port(&records, None, CHROME, "/p").unwrap(), 7500);
        assert!(router_port(&records, Some(7418), CHROME, "/p").is_err());
        assert_eq!(router_port(&records, Some(7418), T3CODE, "/t3").unwrap(), 7418);
        let mut chrome = rec(CHROME, "/u/Default", 7418);
        chrome.user_data_dir = Some("/u".into());
        chrome.profile = Some("Default".into());
        assert_eq!(fix_command(&chrome), "asm browser install chrome --user-data-dir /u --profile Default");
        chrome.service = false;
        chrome.router_port = 7500;
        chrome.profile = Some("Profile 1".into());
        assert_eq!(
            fix_command(&chrome),
            "asm browser install chrome --user-data-dir /u --profile 'Profile 1' --no-service --port 7500"
        );
        assert_eq!(fix_command(&rec(OPENBOT, "/db", 7418)), "asm browser install openbot --trust-user-wide");
    }
}
