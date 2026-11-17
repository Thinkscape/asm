//! macOS Application Firewall: would it stop other machines from reaching the proxy
//! (iron-proxy) or the manager API (this app)? Read with `socketfilterfw`, which needs no
//! sudo: the global state, "Block all incoming connections", stealth mode (informational)
//! and the per-application rules of `--listapps`. Only a listener bound to a non-loopback
//! address cares; a loopback bind is a one-machine setup and is never reported.
//!
//! A TCP connect through a blocking rule still succeeds; the firewall then drops the
//! connection, so agents see CONNECT aborted or reset without anything in the proxy log.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;

use super::activity::{Category, Event};
use super::{Core, TOPIC_FIREWALL, lock, now, to_system_time};
use crate::ffi;

pub const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
/// The background check runs this often (and at start, on wake, after proxy starts and
/// after listener settings change).
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// Debug builds only (see [`crate::ffi::enable_debug_overrides`]): a file whose text
/// replaces every `socketfilterfw` answer (the `--listapps` output, optionally with
/// `--getglobalstate` / `--getblockall` / `--getstealthmode` lines; without a
/// global-state line the firewall counts as on).
pub const DEBUG_LISTAPPS_ENV: &str = "ASM_DEBUG_FIREWALL_LISTAPPS";

/// What the firewall does to incoming connections for one executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Allowed,
    Blocked,
    /// "Block all incoming connections" is on.
    BlockAll,
    FirewallOff,
    /// No rule for the executable (macOS asks the first time another machine connects),
    /// or `socketfilterfw` could not be read.
    Unknown,
}

/// Activity-log name of a state.
fn state_name(s: ffi::FirewallState) -> &'static str {
    match s {
        ffi::FirewallState::Allowed => "allowed",
        ffi::FirewallState::Blocked => "blocked",
        ffi::FirewallState::BlockAll => "block_all",
        ffi::FirewallState::FirewallOff => "firewall_off",
        ffi::FirewallState::Unknown => "unknown",
    }
}

impl From<State> for ffi::FirewallState {
    fn from(s: State) -> Self {
        match s {
            State::Allowed => Self::Allowed,
            State::Blocked => Self::Blocked,
            State::BlockAll => Self::BlockAll,
            State::FirewallOff => Self::FirewallOff,
            State::Unknown => Self::Unknown,
        }
    }
}

/// One `--listapps` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRule {
    pub path: String,
    pub allowed: bool,
}

/// What `socketfilterfw` reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// `None`: the tool could not be run or its answer was not understood.
    pub enabled: Option<bool>,
    pub block_all: bool,
    pub stealth: bool,
    pub apps: Vec<AppRule>,
}

impl Observed {
    /// The state for an executable known under any of `paths`.
    pub fn state_for(&self, paths: &[PathBuf]) -> State {
        match self.enabled {
            None => return State::Unknown,
            Some(false) => return State::FirewallOff,
            Some(true) => {}
        }
        if self.block_all {
            return State::BlockAll;
        }
        self.apps
            .iter()
            .rev()
            .find(|r| paths.iter().any(|p| Path::new(&r.path) == p))
            .map_or(State::Unknown, |r| {
                if r.allowed {
                    State::Allowed
                } else {
                    State::Blocked
                }
            })
    }

    /// Parse fixture text (see [`DEBUG_LISTAPPS_ENV`]).
    pub fn from_text(text: &str) -> Self {
        Self {
            enabled: parse_global_state(text).or(Some(true)),
            block_all: parse_global_block_all(text) || parse_block_all(text),
            stealth: parse_stealth(text),
            apps: parse_listapps(text),
        }
    }
}

/// `--getglobalstate`: `Firewall is enabled. (State = 1)`; `(State = 0)` is off.
pub fn parse_global_state(out: &str) -> Option<bool> {
    if let Some(n) = state_number(out) {
        return Some(n != 0);
    }
    let lower = out.to_ascii_lowercase();
    if lower.contains("firewall is disabled") {
        Some(false)
    } else if lower.contains("firewall is enabled") || lower.contains("firewall is blocking") {
        Some(true)
    } else {
        None
    }
}

/// `(State = 2)` of `--getglobalstate`: only essential services (block all).
pub fn parse_global_block_all(out: &str) -> bool {
    state_number(out) == Some(2)
}

fn state_number(out: &str) -> Option<u32> {
    let lower = out.to_ascii_lowercase();
    let rest = &lower[lower.find("(state = ")? + "(state = ".len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// `--getblockall`: `Firewall has block all state set to enabled.`
pub fn parse_block_all(out: &str) -> bool {
    out.lines()
        .map(str::to_ascii_lowercase)
        .any(|l| l.contains("block all") && l.contains("enabled") && !l.contains("disabled"))
}

/// `--getstealthmode`: `Firewall stealth mode is on` (or `… enabled`).
pub fn parse_stealth(out: &str) -> bool {
    out.lines().map(str::to_ascii_lowercase).any(|l| {
        let l = l.trim().trim_end_matches(['.', '!']);
        l.contains("stealth") && (l.ends_with(" on") || l.ends_with("enabled"))
    })
}

/// `--listapps`: `N : <path>` lines, each followed by `(Allow incoming connections)` or
/// `(Block incoming connections)`.
pub fn parse_listapps(out: &str) -> Vec<AppRule> {
    let mut rules = Vec::new();
    let mut current: Option<String> = None;
    for line in out.lines() {
        let t = line.trim();
        if let Some((n, path)) = t.split_once(" : ")
            && !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
        {
            current = Some(path.trim().to_string());
            continue;
        }
        let lower = t.to_ascii_lowercase();
        let allowed = if lower.starts_with("(allow incoming") {
            true
        } else if lower.starts_with("(block incoming") {
            false
        } else {
            continue;
        };
        if let Some(path) = current.take() {
            rules.push(AppRule { path, allowed });
        }
    }
    rules
}

/// True when `bind` serves other machines: anything but a loopback address or
/// `localhost` (`0.0.0.0`, `::` and interface addresses all do).
pub fn intends_remote(bind: &str) -> bool {
    let b = bind.trim();
    if b.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match b
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        Ok(ip) => !ip.to_canonical().is_loopback(),
        Err(_) => true,
    }
}

/// Run `socketfilterfw` (blocking; a few milliseconds).
pub fn observe() -> Observed {
    if crate::ffi::debug_overrides_enabled()
        && let Some(path) = std::env::var_os(DEBUG_LISTAPPS_ENV)
    {
        return match std::fs::read_to_string(&path) {
            Ok(text) => Observed::from_text(&text),
            Err(e) => {
                log::warn!("{DEBUG_LISTAPPS_ENV}: {}: {e}", Path::new(&path).display());
                Observed::default()
            }
        };
    }
    let run = |arg: &str| -> Option<String> {
        let out = Command::new(SOCKETFILTERFW)
            .arg(arg)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let Some(global) = run("--getglobalstate") else {
        return Observed::default();
    };
    Observed {
        enabled: parse_global_state(&global),
        block_all: parse_global_block_all(&global)
            || run("--getblockall").is_some_and(|o| parse_block_all(&o)),
        stealth: run("--getstealthmode").is_some_and(|o| parse_stealth(&o)),
        apps: run("--listapps")
            .map(|o| parse_listapps(&o))
            .unwrap_or_default(),
    }
}

/// The path itself and its canonical form; with `bundle`, also the enclosing `.app`
/// (a rule for an app bundle covers its main executable).
fn candidates(path: &Path, bundle: bool) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    if let Ok(c) = path.canonicalize()
        && c != path
    {
        out.push(c);
    }
    if bundle {
        let bundles: Vec<PathBuf> = out.iter().filter_map(|p| enclosing_bundle(p)).collect();
        out.extend(bundles);
    }
    out
}

/// `/X.app` for `/X.app/Contents/MacOS/<exe>`.
fn enclosing_bundle(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then(|| app.to_path_buf())
}

fn canonical(p: PathBuf) -> PathBuf {
    p.canonicalize().unwrap_or(p)
}

/// Last check and the status last published to the UI.
#[derive(Default)]
pub(crate) struct FirewallCheck {
    proxy: Option<State>,
    api: Option<State>,
    stealth: bool,
    checked_at: Option<i64>,
    /// Without `checked_at` (so a periodic check that changes nothing stays quiet).
    published: Option<ffi::FirewallStatus>,
}

fn reach(bind: &str, state: Option<State>, exe: &Path) -> ffi::ListenerReach {
    let intent_remote = intends_remote(bind);
    let state = state.unwrap_or(State::Unknown);
    ffi::ListenerReach {
        intent_remote,
        state: state.into(),
        blocked: intent_remote && matches!(state, State::Blocked | State::BlockAll),
        bind_address: bind.to_string(),
        executable: exe.display().to_string(),
    }
}

#[derive(Clone, Copy)]
enum Listener {
    Proxy,
    Api,
}

fn incident_event(which: Listener, r: &ffi::ListenerReach, blocked: bool) -> Event {
    let (name, consequence) = match which {
        Listener::Proxy => ("iron-proxy", "other machines can't use their leases"),
        Listener::Api => (
            "the manager API (AsmApp)",
            "other machines can't pair or request secrets",
        ),
    };
    let summary = if !blocked {
        format!("macOS Firewall no longer blocks {name}")
    } else if r.state == ffi::FirewallState::BlockAll {
        format!("macOS Firewall blocks all incoming connections, {name} included: {consequence}")
    } else {
        format!("macOS Firewall blocks incoming connections to {name}: {consequence}")
    };
    Event::new(
        Category::Proxy,
        if blocked {
            "firewall_blocked"
        } else {
            "firewall_allowed"
        },
        summary,
    )
    .detail(json!({
        "listener": match which { Listener::Proxy => "proxy", Listener::Api => "api" },
        "executable": r.executable,
        "bind": r.bind_address,
        "remote": r.intent_remote,
        "state": state_name(r.state),
    }))
}

impl Core {
    /// The iron-proxy binary the firewall rule must name.
    pub(crate) fn proxy_executable(&self) -> PathBuf {
        canonical(self.bin_dir.join("iron-proxy"))
    }

    /// This process's executable (AsmApp in the app; the test binary in tests).
    fn app_executable() -> PathBuf {
        std::env::current_exe().map(canonical).unwrap_or_default()
    }

    /// Firewall reach of both listeners from the last check and the current bind addresses.
    pub fn firewall_status(&self) -> ffi::FirewallStatus {
        let api_bind = self.settings().api_bind;
        let proxy_bind = self.proxy.config().bind;
        let (proxy, api, stealth, checked_at) = {
            let fw = lock(&self.firewall);
            (fw.proxy, fw.api, fw.stealth, fw.checked_at)
        };
        ffi::FirewallStatus {
            proxy: reach(&proxy_bind, proxy, &self.proxy_executable()),
            api: reach(&api_bind, api, &Self::app_executable()),
            checked_at: checked_at.map(to_system_time),
            stealth_mode: stealth,
        }
    }

    /// For `GET /v1/proxy-info`: `None` until the first check has run.
    pub fn firewall_blocks_proxy(&self) -> Option<bool> {
        let st = self.firewall_status();
        st.checked_at.map(|_| st.proxy.blocked)
    }

    /// Ask the background loop for a check now (non-blocking).
    pub fn recheck_firewall(&self) {
        self.firewall_wake.notify_one();
    }

    /// Run `socketfilterfw` (blocking) and publish the result.
    pub fn check_firewall(&self) {
        let obs = observe();
        let proxy = obs.state_for(&candidates(&self.proxy_executable(), false));
        let api = obs.state_for(&candidates(&Self::app_executable(), true));
        {
            let mut fw = lock(&self.firewall);
            fw.proxy = Some(proxy);
            fw.api = Some(api);
            fw.stealth = obs.stealth;
            fw.checked_at = Some(now());
        }
        self.publish_firewall();
    }

    /// Log incidents that began or ended since the last publication and notify the UI
    /// (topic `firewall`) when anything it shows changed.
    fn publish_firewall(&self) {
        let st = self.firewall_status();
        let key = ffi::FirewallStatus {
            checked_at: None,
            ..st.clone()
        };
        let prev = {
            let mut fw = lock(&self.firewall);
            if fw.published.as_ref() == Some(&key) {
                return;
            }
            fw.published.replace(key)
        };
        let was = prev
            .as_ref()
            .map_or((false, false), |p| (p.proxy.blocked, p.api.blocked));
        for (which, r, was) in [
            (Listener::Proxy, &st.proxy, was.0),
            (Listener::Api, &st.api, was.1),
        ] {
            if r.blocked != was {
                self.log(incident_event(which, r, r.blocked));
            }
        }
        self.notify(TOPIC_FIREWALL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `socketfilterfw --listapps` on the development Mac (2026-11-17, macOS 27).
    const LISTAPPS: &str = include_str!("../../tests/fixtures/socketfilterfw-listapps.txt");
    const PROXY: &str =
        "/Users/thinkscape/asm/dist/Agents Secrets Manager.app/Contents/MacOS/iron-proxy";
    const APP: &str = "/Users/thinkscape/asm/dist/Agents Secrets Manager.app/Contents/MacOS/AsmApp";

    fn on(apps: &str) -> Observed {
        Observed {
            enabled: Some(true),
            block_all: false,
            stealth: false,
            apps: parse_listapps(apps),
        }
    }

    fn state(obs: &Observed, path: &str, bundle: bool) -> State {
        obs.state_for(&candidates(Path::new(path), bundle))
    }

    #[test]
    fn listapps_from_this_mac() {
        let rules = parse_listapps(LISTAPPS);
        assert_eq!(rules.len(), 32);
        assert_eq!(
            rules[0],
            AppRule {
                path: PROXY.into(),
                allowed: true
            }
        );
        assert!(rules.iter().all(|r| r.allowed));
        assert!(rules.iter().any(|r| r.path == "/Applications/RustDesk.app"));
        assert!(
            rules.iter().any(|r| r.path
                == "/Applications/T3 Code (Nightly).app/Contents/MacOS/T3 Code (Nightly)")
        );
        let obs = on(LISTAPPS);
        assert_eq!(state(&obs, PROXY, false), State::Allowed);
        assert_eq!(state(&obs, APP, true), State::Allowed);
        assert_eq!(state(&obs, "/usr/local/bin/other", false), State::Unknown);
    }

    #[test]
    fn blocked_rule() {
        let text = LISTAPPS.replacen(
            "(Allow incoming connections)",
            "(Block incoming connections)",
            1,
        );
        let obs = on(&text);
        assert_eq!(state(&obs, PROXY, false), State::Blocked);
        assert_eq!(state(&obs, APP, true), State::Allowed);
    }

    #[test]
    fn bundle_rule_covers_the_main_executable_only_when_asked() {
        let obs = on(
            "Total number of apps = 1\n1 : /Applications/X.app \n   (Block incoming connections)\n",
        );
        assert_eq!(
            state(&obs, "/Applications/X.app/Contents/MacOS/X", true),
            State::Blocked
        );
        assert_eq!(
            state(&obs, "/Applications/X.app/Contents/MacOS/helper", false),
            State::Unknown
        );
    }

    #[test]
    fn global_settings() {
        assert_eq!(
            parse_global_state("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            parse_global_state("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
        assert_eq!(parse_global_state("Firewall is disabled.\n"), Some(false));
        assert_eq!(parse_global_state("usage: …"), None);
        assert!(parse_global_block_all(
            "Firewall is blocking all non-essential incoming connections. (State = 2)"
        ));
        assert!(!parse_block_all(
            "Firewall has block all state set to disabled.\n"
        ));
        assert!(parse_block_all(
            "Firewall has block all state set to enabled.\n"
        ));
        assert!(!parse_stealth("Firewall stealth mode is off\n"));
        assert!(parse_stealth("Firewall stealth mode is on\n"));

        let mut obs = on(LISTAPPS);
        obs.block_all = true;
        assert_eq!(state(&obs, PROXY, false), State::BlockAll);
        obs.enabled = Some(false);
        assert_eq!(state(&obs, PROXY, false), State::FirewallOff);
        obs.enabled = None;
        assert_eq!(state(&obs, PROXY, false), State::Unknown);
    }

    #[test]
    fn fixture_text_with_global_lines() {
        let obs = Observed::from_text(LISTAPPS);
        assert_eq!(obs.enabled, Some(true));
        assert!(!obs.block_all);
        let text = format!("Firewall has block all state set to enabled.\n{LISTAPPS}");
        assert!(Observed::from_text(&text).block_all);
        let text = format!("Firewall is disabled. (State = 0)\n{LISTAPPS}");
        assert_eq!(Observed::from_text(&text).enabled, Some(false));
    }

    #[test]
    fn remote_intent_by_bind_address() {
        for b in [
            "0.0.0.0",
            "::",
            "192.168.1.20",
            "100.64.1.2",
            "fd00::1",
            " 0.0.0.0 ",
        ] {
            assert!(intends_remote(b), "{b}");
        }
        for b in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
            "localhost",
            "::ffff:127.0.0.1",
        ] {
            assert!(!intends_remote(b), "{b}");
        }
    }

    #[test]
    fn reach_warns_only_for_remote_intent() {
        let exe = Path::new(PROXY);
        let r = reach("0.0.0.0", Some(State::Blocked), exe);
        assert!(r.intent_remote && r.blocked);
        assert!(reach("0.0.0.0", Some(State::BlockAll), exe).blocked);
        assert!(!reach("127.0.0.1", Some(State::Blocked), exe).blocked);
        assert!(!reach("0.0.0.0", Some(State::Unknown), exe).blocked);
        assert!(!reach("0.0.0.0", None, exe).blocked);
        assert!(!reach("0.0.0.0", Some(State::FirewallOff), exe).blocked);
        assert_eq!(r.executable, PROXY);
    }
}
