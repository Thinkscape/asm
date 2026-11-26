//! SSH targets, the user CA, SSH leases, signing and session cleanup.
//!
//! An SSH lease is a per-lease Ed25519 key with one OpenSSH user certificate per
//! approved target, each naming that target's role principal for the access the
//! operator chose there. The key never leaves the manager: the CLI's ssh-agent forwards
//! sign requests to `/v1/ssh/sign` while the lease is active. When a lease ends, the
//! manager logs in to each target as `asm-ops` with a short-lived cleanup certificate,
//! and the host ends the lease's recorded sessions and reports watched files that
//! changed during the lease.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::Duration;

use asm_proto::crypto::{hex_encode, new_uuid_v4, random_bytes};
use asm_proto::rules::{is_bidi_control, validate_reason};
use asm_proto::ssh::{
    MAX_SIGN_DATA, PRIVILEGED_LOGIN, RESTRICTED_LOGIN, SshAccess, SshResult, SshSignRequest, SshSignResponse,
    SshTargetAccess, SshTargetSummary, b64_decode, b64_encode, validate_target_name,
};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{DEFAULT_LEASE_SECS, RequestBody, RequestKind, RequestResult, RequestState, RequestStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssh_key::{HashAlg, PublicKey};

use super::activity::{self, Category, Event};
use super::requests::{Detail, Done, Fail, Pending, SshDetail, SshDetailTarget, SshExtendDetail};
use super::{Core, TOPIC_LEASES, TOPIC_SSH_TARGETS, lock};
use crate::error::{CoreError, Result};
use crate::ffi;
use crate::process::{OutputErrors, collect_output};
use crate::proxy::write_private_atomic;
use crate::ssh::cert::{CERT_TYPE, CertSpec, build_user_cert, cert_line};
use crate::ssh::keys::SshKey;
use crate::ssh::scripts::{
    EnrollParams, cleanup_stdin, is_target_id, render_enroll, render_remove, render_users, scripts_version,
};
use crate::ssh::userauth::parse_userauth;
use crate::store::{
    HostRecord, SshCleanup, SshCleanupState, SshEnrollState, SshGrant, SshGrantTarget, SshLeaseRecord,
    SshRequested, SshTargetConfig, SshTargetRecord, validate_destination,
};

const CA_NAMESPACE: &str = "ssh-ca-v1";
const CA_ID: &str = "user-ca";
const KEY_NAMESPACE: &str = "ssh-lease-keys-v1";
const SSH: &str = "/usr/bin/ssh";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const ENROLL_TIMEOUT: Duration = Duration::from_secs(120);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
const LOCAL_TIMEOUT: Duration = Duration::from_secs(5);
/// One host key fetch: a connection that ends when authentication is refused.
const SCAN_TIMEOUT: Duration = Duration::from_secs(20);
/// Host key types fetched, one connection each; an RSA key answers to `rsa-sha2-512`.
const SCAN_ALGORITHMS: [&str; 5] =
    ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512"];
/// The name fetched keys are written under in the throwaway `known_hosts`.
const SCAN_ALIAS: &str = "asm-host-key-fetch";
/// A check login before a target is saved: connect, log in, `sudo -n`.
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_LEASE_LEFT: i64 = 60;
/// Lifetime of cleanup and enrollment-check certificates.
const RUN_CERT_SECS: i64 = 300;
/// At most this many signatures per lease per `SIGN_WINDOW` seconds.
const SIGN_LIMIT: u32 = 30;
const SIGN_WINDOW: i64 = 60;
/// Longest wait between cleanup attempts, and how long asm keeps trying.
const RETRY_MAX_SECS: i64 = 1800;
const RETRY_FOR_SECS: i64 = 86_400;
const HOST_TEXT_MAX: usize = 200;
/// At most this many changed paths of a lease's end on one target are listed.
const MAX_CHANGES: usize = 20;

const SSH_OUTPUT: OutputErrors = OutputErrors {
    read: "Could not read ssh output",
    timeout: "ssh timed out. Check that the Mac can reach the target",
    capture: "Could not capture ssh output",
    too_large: "ssh output exceeded the size limit",
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSeed {
    seed: String,
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// How the manager logs in to a target.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAuth {
    /// The operator's own ssh, as `privileged_login`; runs `sh -s` or `sudo -n sh -s`.
    /// asm's ssh config for the run goes in `dir`.
    Operator { dir: PathBuf },
    /// A certificate run: `dir` holds `id` and `id-cert.pub`; ssh writes `dir/config`.
    Certificate { login: &'static str, dir: PathBuf, command: Option<&'static str> },
}

/// Why a run on a target failed.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// ssh exit 255, an ssh timeout, or a failure to start ssh.
    Unreachable(String),
    /// The target proved none of its pinned host keys.
    HostKeyChanged,
    /// The host script's error line (`code` `unexpected` for anything unrecognized).
    Host { code: String, message: String },
    /// A route asm refuses, a failure of `ssh -G`, or of writing the run directory.
    Local(String),
}

impl RemoteError {
    /// Worth trying again later. A changed host key is: the operator may pin the new one.
    fn is_transient(&self) -> bool {
        match self {
            Self::Unreachable(_) | Self::HostKeyChanged => true,
            Self::Host { code, .. } => code == "busy",
            Self::Local(_) => false,
        }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "could not reach the host: {m}"),
            Self::HostKeyChanged => f.write_str("the host didn't prove its pinned host key"),
            Self::Host { code, message } if code == "unexpected" => {
                write!(f, "host reported an unexpected result: {message}")
            }
            Self::Host { code, message } => write!(f, "host reported: {message} ({code})"),
            Self::Local(m) => f.write_str(m),
        }
    }
}

impl From<RemoteError> for CoreError {
    fn from(e: RemoteError) -> Self {
        CoreError::vault_unavailable(e.to_string())
    }
}

/// Runs a script or command on a target. The production implementation uses
/// `/usr/bin/ssh`; tests install a fake.
#[doc(hidden)]
pub trait SshRemote: Send + Sync {
    fn run(&self, target: &SshTargetRecord, auth: &RemoteAuth, stdin: &str, timeout: Duration)
        -> std::result::Result<RemoteOutput, RemoteError>;

    /// Checks that certificate runs on `target` can use the operator's route to it,
    /// without connecting; `dir` is a private directory for the run.
    fn check_route(&self, _target: &SshTargetRecord, _dir: &Path) -> std::result::Result<(), RemoteError> {
        Ok(())
    }
}

#[doc(hidden)]
pub struct OpenSshRemote {
    known_hosts: PathBuf,
    /// The operator's ssh config that asm's own config includes; `None` includes
    /// ~/.ssh/config and /etc/ssh/ssh_config (`wrapper_config`).
    config: Option<PathBuf>,
}

impl OpenSshRemote {
    #[doc(hidden)]
    pub fn new(known_hosts: PathBuf, config: Option<PathBuf>) -> Self {
        Self { known_hosts, config }
    }

    fn operator_command(&self, target: &SshTargetRecord, dir: &Path) -> Result<Command> {
        let c = &target.config;
        let wrapper = write_wrapper_config(dir, self.config.as_deref())?;
        operator_ssh(&wrapper, &self.known_hosts, &target.id, &c.privileged_login, &c.destination)
    }

    /// asm's config for a certificate run on `target` as `login`, from what `ssh -G`
    /// says of the operator's route.
    fn certificate_route_config(&self, target: &SshTargetRecord, login: &str, dir: &Path)
        -> std::result::Result<String, RemoteError>
    {
        let destination = &target.config.destination;
        let wrapper = write_wrapper_config(dir, self.config.as_deref()).map_err(|e| RemoteError::Local(e.message))?;
        let mut g = Command::new(SSH);
        g.arg("-F").arg(&wrapper).args(["-G", "--"]).arg(destination);
        let (status, stdout, stderr) = run_local(g, None, LOCAL_TIMEOUT).map_err(|e| RemoteError::Local(e.message))?;
        if status != 0 {
            let why = host_text(last_line(&stderr).unwrap_or("ssh -G failed"));
            return Err(RemoteError::Local(format!("could not read your ssh settings for {destination}: {why}")));
        }
        let route = parse_route(&stdout).map_err(|e| RemoteError::Local(e.message))?;
        render_certificate_config(&route, &self.known_hosts, &target.id, login, dir, Some(&wrapper), destination)
            .map_err(|e| RemoteError::Local(e.message))
    }

    fn certificate_command(
        &self, target: &SshTargetRecord, login: &str, dir: &Path, command: Option<&str>,
    ) -> std::result::Result<Command, RemoteError> {
        let text = self.certificate_route_config(target, login, dir)?;
        write_private_atomic(dir, "config", text.as_bytes()).map_err(|e| RemoteError::Local(
            format!("could not write the ssh config for {}: {e}", target.config.destination)))?;
        let mut run = Command::new(SSH);
        run.arg("-F").arg(dir.join("config")).args(["-T", "asm-target"]);
        if let Some(command) = command {
            run.arg(command);
        }
        Ok(run)
    }
}

impl SshRemote for OpenSshRemote {
    fn run(&self, target: &SshTargetRecord, auth: &RemoteAuth, stdin: &str, timeout: Duration)
        -> std::result::Result<RemoteOutput, RemoteError>
    {
        let command = match auth {
            RemoteAuth::Operator { dir } => self.operator_command(target, dir).map_err(|e| RemoteError::Local(e.message))?,
            RemoteAuth::Certificate { login, dir, command } => self.certificate_command(target, login, dir, *command)?,
        };
        let (status, stdout, stderr) = run_local(command, Some(stdin), timeout)
            .map_err(|e| RemoteError::Unreachable(e.message))?;
        Ok(RemoteOutput { status, stdout, stderr })
    }

    fn check_route(&self, target: &SshTargetRecord, dir: &Path) -> std::result::Result<(), RemoteError> {
        self.certificate_route_config(target, RESTRICTED_LOGIN, dir).map(drop)
    }
}

/// Every option of an operator run before `-l`, each `-o` value as its own argument.
#[doc(hidden)]
pub fn ssh_options(known_hosts: &Path, target_id: &str) -> Result<Vec<String>> {
    if !is_target_id(target_id) {
        return Err(CoreError::internal("invalid SSH target id"));
    }
    let known_hosts = config_path(known_hosts)?;
    let mut out = vec!["-T".to_owned()];
    for option in [
        "BatchMode=yes", "ConnectTimeout=10", "StrictHostKeyChecking=yes", "CheckHostIP=no",
        &format!("UserKnownHostsFile={known_hosts}"),
        "GlobalKnownHostsFile=/dev/null", &format!("HostKeyAlias=asm-target-{target_id}"), "UpdateHostKeys=no",
        "KnownHostsCommand=none", "VerifyHostKeyDNS=no",
        "ControlMaster=no", "ControlPath=none", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
        "ClearAllForwardings=yes", "Tunnel=no",
        "GSSAPIAuthentication=no", "GSSAPIDelegateCredentials=no", "PermitLocalCommand=no", "RemoteCommand=none",
        "RequestTTY=no", "LogLevel=ERROR",
    ] {
        out.push("-o".to_owned());
        out.push(option.to_owned());
    }
    Ok(out)
}

/// `"<path>"` for an ssh option or config line; ssh splits values at whitespace and
/// expands `%` tokens.
fn config_path(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or_else(|| CoreError::internal("the data directory path is not valid UTF-8"))?;
    if text.contains(['"', '%']) || text.chars().any(char::is_control) {
        return Err(CoreError::internal("the data directory path cannot contain \" or %"));
    }
    Ok(format!("\"{text}\""))
}

/// Where `ssh -G` says a destination is, and how it is reached.
#[doc(hidden)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    pub hostname: String,
    pub port: u16,
    pub proxy_command: Option<String>,
    pub proxy_jump: Option<String>,
}

/// The route in `ssh -G` output; `none` means unset.
#[doc(hidden)]
pub fn parse_route(ssh_g: &str) -> Result<Route> {
    let mut route = Route { port: 22, ..Route::default() };
    for line in ssh_g.lines() {
        let Some((key, value)) = line.split_once(' ') else { continue };
        let set = (value != "none").then(|| value.to_owned());
        match key {
            "hostname" => route.hostname = value.trim().to_owned(),
            "port" => {
                route.port = value.trim().parse().ok().filter(|p| *p != 0)
                    .ok_or_else(|| CoreError::vault_unavailable(format!("ssh -G reported an invalid port {value:?}")))?;
            }
            "proxycommand" => route.proxy_command = set,
            "proxyjump" => route.proxy_jump = set,
            _ => {}
        }
    }
    if route.hostname.is_empty() {
        return Err(CoreError::vault_unavailable("ssh -G reported no hostname"));
    }
    Ok(route)
}

/// The ssh config of a certificate run: only the certificate in `run_dir` reaches the
/// target; a jump host uses the operator's own ssh setup.
#[doc(hidden)]
pub fn certificate_config(
    route: &Route, known_hosts: &Path, target_id: &str, login: &str, run_dir: &Path, operator_config: Option<&Path>,
) -> Result<String> {
    render_certificate_config(route, known_hosts, target_id, login, run_dir, operator_config, &route.hostname)
}

fn render_certificate_config(
    route: &Route, known_hosts: &Path, target_id: &str, login: &str, run_dir: &Path, operator_config: Option<&Path>,
    destination: &str,
) -> Result<String> {
    if !is_target_id(target_id) {
        return Err(CoreError::internal("invalid SSH target id"));
    }
    if login != RESTRICTED_LOGIN && login != PRIVILEGED_LOGIN {
        return Err(CoreError::internal("invalid SSH login for a certificate run"));
    }
    let h = &route.hostname;
    if h.is_empty() || !h.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-')) {
        return Err(CoreError::invalid(format!("asm cannot use the host name {h:?} of {destination} for unattended cleanup")));
    }
    let refused = || CoreError::invalid(
        format!("asm cannot use the ProxyJump/ProxyCommand of {destination} for unattended cleanup"));
    let proxy = match (&route.proxy_command, &route.proxy_jump) {
        (Some(command), _) => {
            if command.trim().is_empty() || command.chars().any(char::is_control) {
                return Err(refused());
            }
            if uses_login_tokens(command) {
                return Err(CoreError::invalid(format!(
                    "asm cannot use the ProxyCommand of {destination} for unattended runs: it uses %n, %r, %k or %C")));
            }
            Some(command.clone())
        }
        (None, Some(spec)) => {
            let hops: Vec<&str> = spec.split(',').collect();
            let last = hops[hops.len() - 1];
            if !spec.bytes().all(|c| c.is_ascii_alphanumeric() || b"._@:[],-".contains(&c))
                || hops.iter().any(|h| h.is_empty() || h.starts_with('-'))
                || (last.matches(':').count() >= 2 && !last.contains('['))
            {
                return Err(refused());
            }
            let mut command = "/usr/bin/ssh -o BatchMode=yes".to_owned();
            if let Some(config) = operator_config {
                command.push_str(&format!(" -F {}", config_path(config)?));
            }
            if hops.len() > 1 {
                command.push_str(&format!(" -J '{}'", hops[..hops.len() - 1].join(",")));
            }
            command.push_str(&format!(" -W '[%h]:%p' 'ssh://{last}'"));
            Some(command)
        }
        (None, None) => None,
    };
    let mut text = format!(
        "Host asm-target\n  HostName {h}\n  Port {port}\n  User {login}\n  HostKeyAlias asm-target-{target_id}\n  \
         UserKnownHostsFile {known_hosts}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  \
         CheckHostIP no\n  UpdateHostKeys no\n  VerifyHostKeyDNS no\n  IdentityAgent none\n  IdentitiesOnly yes\n  \
         IdentityFile {id}\n  CertificateFile {cert}\n  PKCS11Provider none\n  PreferredAuthentications publickey\n  \
         BatchMode yes\n  ConnectTimeout 10\n  ControlMaster no\n  ControlPath none\n  ForwardAgent no\n  \
         ForwardX11 no\n  ClearAllForwardings yes\n  RequestTTY no\n  LogLevel ERROR\n",
        port = route.port,
        known_hosts = config_path(known_hosts)?,
        id = config_path(&run_dir.join("id"))?,
        cert = config_path(&run_dir.join("id-cert.pub"))?,
    );
    if let Some(proxy) = proxy {
        text.push_str(&format!("  ProxyCommand {proxy}\n"));
    }
    Ok(text)
}

/// Whether `command` uses a `%` token for the original host name, the login, the host
/// key alias or their hash: asm runs it under its own `Host asm-target` and logins.
fn uses_login_tokens(command: &str) -> bool {
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        // `%%` is a literal `%`, so the character after it is not a token.
        if c == '%' && matches!(chars.next(), Some('n' | 'r' | 'k' | 'C')) {
            return true;
        }
    }
    false
}

/// asm's ssh config for runs over the operator's route. It is given with `-F`, and ssh
/// hands `-F` on to ProxyJump hops, so every host on the way, jump hosts included, is
/// checked against the operator's known_hosts and never added to it, and nothing
/// prompts. The operator's own settings follow: `include`, or ~/.ssh/config and
/// /etc/ssh/ssh_config.
#[doc(hidden)]
pub fn wrapper_config(include: Option<&Path>) -> Result<String> {
    let mut text = String::from(
        "# Written by asm for its own ssh runs: hosts are checked against your known_hosts and never\n\
         # added to it, and nothing prompts. Your own settings follow.\n\
         Host *\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  CheckHostIP no\n  BatchMode yes\n");
    match include {
        Some(path) => text.push_str(&format!("  Include {}\n", config_path(path)?)),
        None => text.push_str("  Include ~/.ssh/config\n  Include /etc/ssh/ssh_config\n"),
    }
    Ok(text)
}

/// Writes `wrapper_config` as `dir/ssh_config`. ssh pastes a `-F` path unquoted into the
/// command it runs for each ProxyJump hop, so the path must not need shell quoting.
fn write_wrapper_config(dir: &Path, include: Option<&Path>) -> Result<PathBuf> {
    let path = dir.join("ssh_config");
    if !path.to_str().is_some_and(|p| p.bytes().all(|c| c.is_ascii_alphanumeric() || b"/._-+,@".contains(&c))) {
        return Err(CoreError::internal(format!(
            "asm's ssh config path {} must not contain spaces or shell characters", path.display())));
    }
    write_private_atomic(dir, "ssh_config", wrapper_config(include)?.as_bytes())
        .map_err(|e| CoreError::vault_unavailable(format!("could not write asm's ssh config in {}: {e}", dir.display())))
}

/// Which host failed a host key check, from ssh's messages: they name the target by its
/// `HostKeyAlias`, and a jump host by its own name.
#[derive(Debug, PartialEq, Eq)]
enum KeyFailure {
    Target,
    /// Why, for the operator: the jump host's key is unknown or changed.
    Jump(String),
}

fn key_failure(stderr: &str, alias: &str) -> Option<KeyFailure> {
    if !stderr.contains("Host key verification failed") {
        return None;
    }
    if stderr.contains(alias) {
        return Some(KeyFailure::Target);
    }
    let line = stderr.lines().map(str::trim)
        .find(|l| l.contains("host key is known for") || (l.starts_with("Host key for") && l.contains("has changed")))
        .unwrap_or("Host key verification failed.");
    Some(KeyFailure::Jump(format!(
        "a jump host failed its host key check: {}. Connect to it once with ssh in Terminal and check its fingerprint, then try again",
        host_text(line).trim_end_matches('.'))))
}

/// ssh exit 255 of a run on `target`: a changed key of the target, a jump host that
/// failed its key check, or a connection failure.
fn connection_error(target: &SshTargetRecord, stderr: &str) -> RemoteError {
    match key_failure(stderr, &format!("asm-target-{}", target.id)) {
        Some(KeyFailure::Target) => RemoteError::HostKeyChanged,
        Some(KeyFailure::Jump(why)) => RemoteError::Unreachable(why),
        None => RemoteError::Unreachable(host_text(last_line(stderr).unwrap_or("connection failed"))),
    }
}

/// Asks `destination` for its host keys over the operator's own ssh route (their config,
/// jump hosts and proxies included) without authenticating. Each key type gets one
/// connection that records the offered key in a throwaway `known_hosts` in `run_dir`
/// (`StrictHostKeyChecking=accept-new`) and then fails authentication, since every
/// method is off. ssh records the key before it checks the key exchange signature, so a
/// run's key counts only when the run got as far as `Permission denied`. The keys are
/// unverified: whoever answers at that address chooses them.
/// `config` is the operator's ssh config asm's own config includes (tests; `None` in use).
#[doc(hidden)]
pub fn fetch_host_keys(destination: &str, config: Option<&Path>, run_dir: &Path) -> Result<Vec<String>> {
    validate_destination(destination)?;
    let wrapper = write_wrapper_config(run_dir, config)?;
    let attempts: Vec<Result<(Vec<String>, String)>> = std::thread::scope(|scope| {
        let workers: Vec<_> = SCAN_ALGORITHMS.iter().enumerate().map(|(i, algorithm)| {
            let wrapper = &wrapper;
            scope.spawn(move || -> Result<(Vec<String>, String)> {
                let file = run_dir.join(format!("known_hosts-{i}"));
                let mut command = Command::new(SSH);
                command.arg("-F").arg(wrapper).arg("-T");
                for option in [
                    "BatchMode=yes", "ConnectTimeout=10", "StrictHostKeyChecking=accept-new",
                    &format!("UserKnownHostsFile={}", config_path(&file)?), "GlobalKnownHostsFile=/dev/null",
                    &format!("HostKeyAlias={SCAN_ALIAS}"), "HashKnownHosts=no", &format!("HostKeyAlgorithms={algorithm}"),
                    "CheckHostIP=no", "UpdateHostKeys=no", "KnownHostsCommand=none", "VerifyHostKeyDNS=no",
                    "ControlMaster=no", "ControlPath=none", "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
                    "Tunnel=no", "PubkeyAuthentication=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                    "GSSAPIAuthentication=no", "HostbasedAuthentication=no", "IdentityAgent=none",
                    "PermitLocalCommand=no", "RemoteCommand=none", "RequestTTY=no", "LogLevel=ERROR",
                ] {
                    command.arg("-o").arg(option);
                }
                command.args(["--", destination, "true"]);
                let (_, _, stderr) = run_local(command, None, SCAN_TIMEOUT)?;
                if !stderr.contains("Permission denied") {
                    return Ok((Vec::new(), stderr));
                }
                let text = match std::fs::read_to_string(&file) {
                    Ok(text) => text,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(e) => return Err(CoreError::vault_unavailable(format!("could not read {}: {e}", file.display()))),
                };
                let mut keys = Vec::new();
                for line in text.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if let [SCAN_ALIAS, kind, b64] = fields[..] {
                        let key = format!("{kind} {b64}");
                        crate::store::validate_host_key(&key)?;
                        keys.push(key);
                    }
                }
                Ok((keys, stderr))
            })
        }).collect();
        workers.into_iter().map(|w| w.join().unwrap_or_else(|_| Err(CoreError::internal("host key fetch panicked")))).collect()
    });
    let mut keys: Vec<String> = Vec::new();
    let mut why: Option<String> = None;
    for attempt in attempts {
        let (found, stderr) = attempt?;
        for key in found {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        // The target is accepted as new, so a failed key check is a jump host's.
        if let Some(KeyFailure::Jump(message)) = key_failure(&stderr, SCAN_ALIAS) {
            return Err(CoreError::invalid(format!("could not get the host keys of {destination}: {message}")));
        }
        // A type the host lacks is expected; any other failure explains an empty result.
        let last = last_line(&stderr).unwrap_or_default();
        if !last.is_empty() && !last.contains("no matching host key type") && !last.contains("Permission denied") {
            why.get_or_insert_with(|| last.to_owned());
        }
    }
    if keys.is_empty() {
        let why = host_text(why.as_deref().unwrap_or("the host offered no supported host key"));
        return Err(CoreError::vault_unavailable(format!("could not get the host keys of {destination}: {why}")));
    }
    Ok(keys)
}

/// The operator's ssh as `login` with asm's config `wrapper`, pinned to the keys
/// `known_hosts` lists under `asm-target-<target_id>`, running `sh -s` (`sudo -n sh -s`
/// unless the login is root).
fn operator_ssh(wrapper: &Path, known_hosts: &Path, target_id: &str, login: &str, destination: &str) -> Result<Command> {
    let remote = if login == "root" { "sh -s" } else { "sudo -n sh -s" };
    let mut command = Command::new(SSH);
    command.arg("-F").arg(wrapper)
        .args(ssh_options(known_hosts, target_id)?)
        .arg("-l").arg(login)
        .arg("--").arg(destination).arg(remote);
    Ok(command)
}

/// What `check_destination` found.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCheck {
    /// The host proved one of the pinned keys, and the login and its sudo work.
    Verified,
    /// The host proved none of the pinned keys; these are the keys it offers (unverified).
    KeyMismatch(Vec<String>),
    /// The connection failed before any host key check: why.
    Unreachable(String),
}

/// Logs in to `destination` as enrollment will: the operator's ssh as `login`, pinned to
/// `host_keys` through a throwaway `known_hosts` in `run_dir`, running `exit 0` through
/// `sh -s` or `sudo -n sh -s`. A host that proves none of the keys gives `KeyMismatch`
/// with the keys it offers; a refused login or sudo, or a jump host that fails its key
/// check, is an error. `config` is the operator's ssh config asm's own config includes
/// (tests; `None` in use).
#[doc(hidden)]
pub fn check_destination(
    destination: &str, login: &str, host_keys: &[String], config: Option<&Path>, run_dir: &Path,
) -> Result<HostCheck> {
    let (command, alias) = pinned_operator_ssh(destination, login, host_keys, config, run_dir)?;
    let (status, _, stderr) = match run_local(command, Some("exit 0\n"), CHECK_TIMEOUT) {
        Ok(out) => out,
        Err(e) => return Ok(HostCheck::Unreachable(format!("could not reach {destination}: {}", e.message))),
    };
    match check_outcome(status, &stderr, destination, login, &alias)? {
        CheckOutcome::Ran => Ok(HostCheck::Verified),
        CheckOutcome::Unreachable(why) => Ok(HostCheck::Unreachable(why)),
        CheckOutcome::KeyMismatch => {
            let fetch_dir = run_dir.join("fetch");
            std::fs::DirBuilder::new().mode(0o700).create(&fetch_dir)
                .map_err(|e| CoreError::vault_unavailable(format!("could not create {}: {e}", fetch_dir.display())))?;
            Ok(HostCheck::KeyMismatch(fetch_host_keys(destination, config, &fetch_dir)?))
        }
    }
}

/// The operator's ssh to `destination` as `login` (see `operator_ssh`), pinned to
/// `host_keys` through a throwaway `known_hosts` in `run_dir`, and the alias ssh's host
/// key messages name the target by.
fn pinned_operator_ssh(
    destination: &str, login: &str, host_keys: &[String], config: Option<&Path>, run_dir: &Path,
) -> Result<(Command, String)> {
    validate_destination(destination)?;
    let id = hex_encode(&random_bytes::<4>());
    let text: String = host_keys.iter().map(|key| format!("asm-target-{id} {key}\n")).collect();
    let known_hosts = write_private_atomic(run_dir, "known_hosts", text.as_bytes())
        .map_err(|e| CoreError::vault_unavailable(format!("could not write {}: {e}", run_dir.display())))?;
    let wrapper = write_wrapper_config(run_dir, config)?;
    Ok((operator_ssh(&wrapper, &known_hosts, &id, login, destination)?, format!("asm-target-{id}")))
}

/// Logs in to `destination` as `login` the way `check_destination` does and runs
/// `users.sh` as root: the accounts agents could log in as. A host that proves none of
/// the keys, a refused login or sudo, or a failed listing is an error. `config` as for
/// `check_destination`.
#[doc(hidden)]
pub fn list_host_users(
    destination: &str, login: &str, host_keys: &[String], config: Option<&Path>, run_dir: &Path,
) -> Result<Vec<ffi::SshHostUser>> {
    let script = render_users(login)?;
    let (command, alias) = pinned_operator_ssh(destination, login, host_keys, config, run_dir)?;
    let (status, stdout, stderr) = run_local(command, Some(&script), CHECK_TIMEOUT)
        .map_err(|e| CoreError::vault_unavailable(format!("could not reach {destination}: {}", e.message)))?;
    if status == 0 {
        return parse_host_users(&stdout);
    }
    if let Some(why) = last_line(&stdout).and_then(|l| l.strip_prefix("asm-users-error ")) {
        return Err(CoreError::vault_unavailable(format!("listing the users of {destination} failed: {}", host_text(why))));
    }
    Err(match check_outcome(status, &stderr, destination, login, &alias)? {
        CheckOutcome::KeyMismatch => CoreError::invalid(format!(
            "{destination} didn't prove any of the host keys in the sheet; check them before listing its users")),
        CheckOutcome::Unreachable(why) => CoreError::vault_unavailable(why),
        CheckOutcome::Ran => CoreError::internal("listing users ended with an error status"),
    })
}

/// `users.sh` output: `asm-user NAME UID SYSTEM LOGIN_SHELL WHY` lines, then
/// `asm-users-ok`. Other lines are ignored; the list is sorted by name.
fn parse_host_users(stdout: &str) -> Result<Vec<ffi::SshHostUser>> {
    let bad = || CoreError::vault_unavailable("the host sent a malformed list of users");
    let mut lines: Vec<&str> = stdout.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.pop() != Some("asm-users-ok") {
        return Err(bad());
    }
    let flag = |s: &str| match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(bad()),
    };
    let mut users = Vec::new();
    for line in lines {
        let Some(rest) = line.strip_prefix("asm-user ") else { continue };
        let fields: Vec<&str> = rest.splitn(5, ' ').collect();
        let [name, uid, system, login_shell, why] = fields[..] else { return Err(bad()) };
        asm_proto::ssh::validate_login(name).map_err(|_| bad())?;
        users.push(ffi::SshHostUser {
            name: name.to_owned(),
            uid: uid.parse().map_err(|_| bad())?,
            system: flag(system)?,
            login_shell: flag(login_shell)?,
            admin: (why != "-").then(|| host_text(why).chars().take(64).collect()),
        });
    }
    users.sort_by(|a, b| a.name.cmp(&b.name));
    users.dedup_by(|a, b| a.name == b.name);
    Ok(users)
}

#[derive(Debug, PartialEq, Eq)]
enum CheckOutcome {
    Ran,
    KeyMismatch,
    Unreachable(String),
}

/// The check login ran, the target (named `alias`) proved none of its keys, or the host
/// wasn't reached; otherwise why the login failed.
fn check_outcome(status: i32, stderr: &str, destination: &str, login: &str, alias: &str) -> Result<CheckOutcome> {
    if status == 0 {
        return Ok(CheckOutcome::Ran);
    }
    match key_failure(stderr, alias) {
        Some(KeyFailure::Target) => return Ok(CheckOutcome::KeyMismatch),
        Some(KeyFailure::Jump(why)) => return Err(CoreError::invalid(format!("could not reach {destination}: {why}"))),
        None => {}
    }
    let why = last_line(stderr).map_or_else(|| format!("exit status {status}"), host_text);
    if status == 255 && let Some(denied) = stderr.lines().map(str::trim).find(|l| l.contains("Permission denied")) {
        return Err(CoreError::invalid(format!(
            "asm could not log in to {destination} as {login} with your ssh setup: {}", host_text(denied))));
    }
    if stderr.contains("sudo:") {
        return Err(CoreError::invalid(format!("{login} on {destination} needs passwordless sudo: {why}")));
    }
    if status == 255 {
        return Ok(CheckOutcome::Unreachable(format!("could not reach {destination}: {why}")));
    }
    Err(CoreError::vault_unavailable(format!("checking {destination} failed: {why}")))
}

/// What the operator's known_hosts files and ssh settings say about one destination.
struct KnownHostsView {
    hostname: String,
    port: u16,
    keys: Vec<String>,
    revoked: HashSet<String>,
    proxy_jump: Option<String>,
    proxy_command: bool,
}

fn host_key_item(line: String) -> ffi::SshHostKey {
    ffi::SshHostKey { fingerprint: host_key_fingerprint(&line), line }
}

fn host_key_lookup(view: &KnownHostsView, keys: Vec<String>) -> ffi::SshHostKeyLookup {
    ffi::SshHostKeyLookup {
        hostname: view.hostname.clone(),
        port: view.port,
        keys: keys.into_iter().map(host_key_item).collect(),
        proxy_jump: view.proxy_jump.clone(),
        proxy_command: view.proxy_command,
    }
}

/// `destination` and `login` trimmed and valid, with 1+ valid `host_keys` to pin.
fn checked_destination<'a>(destination: &'a str, login: &'a str, host_keys: &[String]) -> Result<(&'a str, &'a str)> {
    let (destination, login) = (destination.trim(), login.trim());
    validate_destination(destination)?;
    asm_proto::ssh::validate_login(login)?;
    if host_keys.is_empty() {
        return Err(CoreError::invalid("the target has no host keys yet"));
    }
    for key in host_keys {
        crate::store::validate_host_key(key)?;
    }
    Ok((destination, login))
}

/// Run a local program with a minimal environment (the operator's ssh config and agent
/// still apply), its output bounded and its process group killed on exit or timeout.
fn run_local(mut command: Command, stdin: Option<&str>, timeout: Duration) -> Result<(i32, String, String)> {
    command.env_clear();
    for key in ["HOME", "USER", "LOGNAME", "SSH_AUTH_SOCK"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LANG", "C")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|e| CoreError::vault_unavailable(format!("could not run ssh: {e}")))?;
    let writer = match (stdin, child.stdin.take()) {
        (Some(text), Some(mut pipe)) => {
            // SAFETY: F_SETNOSIGPIPE on our own pipe descriptor turns SIGPIPE into EPIPE,
            // so a child that exits early cannot kill the manager.
            unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) };
            let text = text.to_owned();
            Some(std::thread::spawn(move || {
                let _ = pipe.write_all(text.as_bytes());
            }))
        }
        _ => None,
    };
    let collected = collect_output(child, timeout, || Ok(()), &SSH_OUTPUT);
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let (status, stdout, stderr) = collected?;
    Ok((status.code().unwrap_or(-1), String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned()))
}

fn last_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).rfind(|l| !l.is_empty())
}

/// Text a host sent, safe to show: trimmed, control and bidi characters replaced, at
/// most 200 characters.
fn host_text(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.trim().chars().enumerate() {
        if i == HOST_TEXT_MAX {
            out.push('…');
            break;
        }
        out.push(if c.is_control() || is_bidi_control(c) { '?' } else { c });
    }
    out
}

/// The numbers after `ok_token` on the last stdout line of a host script, or what went wrong.
fn host_result(
    target: &SshTargetRecord, out: RemoteOutput, ok_token: &str, error_prefix: &str, counts: usize,
) -> std::result::Result<Vec<u64>, RemoteError> {
    if out.status == 255 {
        return Err(connection_error(target, &out.stderr));
    }
    let last = last_line(&out.stdout).unwrap_or_default();
    if out.status == 0
        && let Some(rest) = last.strip_prefix(ok_token)
    {
        let numbers: Option<Vec<u64>> = if counts == 0 {
            rest.is_empty().then(Vec::new)
        } else {
            rest.strip_prefix(' ').and_then(|rest| {
                let parts: Vec<&str> = rest.split(' ').collect();
                (parts.len() == counts && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())))
                    .then(|| parts.iter().map(|p| p.parse().ok()).collect::<Option<Vec<u64>>>())
                    .flatten()
            })
        };
        if let Some(numbers) = numbers {
            return Ok(numbers);
        }
    }
    if let Some(rest) = last.strip_prefix(error_prefix).and_then(|r| r.strip_prefix(' ')) {
        let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
        if (1..=32).contains(&code.len()) && code.bytes().all(|c| c.is_ascii_lowercase() || c == b'-') {
            return Err(RemoteError::Host { code: code.to_owned(), message: host_text(message) });
        }
    }
    let what = last_line(&out.stdout).or_else(|| last_line(&out.stderr))
        .map_or_else(|| format!("exit status {}", out.status), host_text);
    Err(RemoteError::Host { code: "unexpected".into(), message: what })
}

/// What a host reported when a lease ended there.
#[derive(Debug, PartialEq, Eq)]
struct EndReport {
    sessions: u64,
    /// The watched paths that changed during the lease, at most `MAX_CHANGES`.
    changes: Vec<String>,
    changes_total: u32,
}

/// The output of `end LEASE VB`: `changed <path>` lines, then `asm-end-ok <ended> <changed>`.
fn end_report(target: &SshTargetRecord, out: RemoteOutput) -> std::result::Result<EndReport, RemoteError> {
    let changes: Vec<String> = out.stdout.lines().filter_map(|l| l.strip_prefix("changed ")).map(host_text)
        .take(MAX_CHANGES + 1).collect();
    let counts = host_result(target, out, "asm-end-ok", "asm-end-error", 2)?;
    let changes_total = u32::try_from(counts[1]).unwrap_or(u32::MAX);
    if changes.len() != (changes_total as usize).min(MAX_CHANGES) {
        return Err(RemoteError::Host { code: "unexpected".into(),
            message: format!("{changes_total} changed files, but {} listed", changes.len()) });
    }
    Ok(EndReport { sessions: counts[0], changes, changes_total })
}

pub(crate) struct SshState {
    ca: Mutex<Option<Arc<SshKey>>>,
    keys: Mutex<HashMap<String, Arc<SshKey>>>,
    remote: RwLock<Arc<dyn SshRemote>>,
    /// Target ids with a running enroll, removal, save or cleanup.
    busy: Mutex<HashSet<String>>,
    /// Target ids whose last run failed the host key check (until a run passes it or the
    /// operator pins new keys).
    key_changed: Mutex<HashSet<String>>,
    /// Per lease id: the start of its signing window and the signatures in it.
    sign_window: Mutex<HashMap<String, (i64, u32)>>,
    /// Per lease id: when a refused signature was last logged.
    refused_at: Mutex<HashMap<String, i64>>,
    stopping: AtomicBool,
    /// Cleanup threads need an owned handle; set once after start.
    core: OnceLock<Weak<Core>>,
}

impl SshState {
    pub(crate) fn new(known_hosts: PathBuf) -> Self {
        Self {
            ca: Mutex::new(None),
            keys: Mutex::new(HashMap::new()),
            remote: RwLock::new(Arc::new(OpenSshRemote::new(known_hosts, None))),
            busy: Mutex::new(HashSet::new()),
            key_changed: Mutex::new(HashSet::new()),
            sign_window: Mutex::new(HashMap::new()),
            refused_at: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
            core: OnceLock::new(),
        }
    }

    pub(crate) fn attach(&self, core: &Arc<Core>) {
        let _ = self.core.set(Arc::downgrade(core));
    }

    pub(crate) fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// Removes a target id from `busy` when its operation finishes.
struct Busy<'a> {
    set: &'a Mutex<HashSet<String>>,
    id: String,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        lock(self.set).remove(&self.id);
    }
}

/// Removes a certificate run's directory, with its key, when the run ends.
struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            log::error!("removing {}: {error}", self.0.display());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CertRole {
    /// `asm-ops` with the cleanup principal; the key line forces `asm-cleanup`.
    Cleanup,
    /// `asm-priv` running `true`, to check enrollment.
    CheckPrivileged,
    /// `asm-priv` running `true` as this user, to check enrollment.
    CheckUser(String),
}

/// The id and end that certificate runs present to the host: a check login's "lease".
struct CertRun {
    id: String,
    until: i64,
}

/// The operator's decision on an SSH request, as passed over FFI: the access of each
/// approved target, and the duration.
pub(crate) struct SshApproval {
    pub targets: Vec<ffi::SshTargetDecision>,
    pub duration_secs: u64,
}

fn target_allows(target: &SshTargetRecord, grant: &str) -> bool {
    let c = &target.config;
    let listed = |list: &[String], value: &str| list.iter().any(|v| v == value);
    if let Some(unit) = grant.strip_prefix("logs:") {
        listed(&c.log_units, unit)
    } else if let Some(unit) = grant.strip_prefix("restart:") {
        listed(&c.restart_units, unit)
    } else if let Some(unit) = grant.strip_prefix("reload:") {
        listed(&c.reload_units, unit)
    } else {
        grant.strip_prefix("read:").is_some_and(|path| listed(&c.read_files, path))
    }
}

fn target_grants(config: &SshTargetConfig) -> Vec<String> {
    config.log_units.iter().map(|u| format!("logs:{u}"))
        .chain(config.restart_units.iter().map(|u| format!("restart:{u}")))
        .chain(config.reload_units.iter().map(|u| format!("reload:{u}")))
        .chain(config.read_files.iter().map(|f| format!("read:{f}")))
        .collect()
}

/// Agents may log in to `target` as `user`.
fn target_has_user(target: &SshTargetRecord, user: &str) -> bool {
    target.config.users.iter().any(|u| u.name == user)
}

/// `target` is enrolled with other host scripts than this asm ships.
fn scripts_outdated(target: &SshTargetRecord) -> bool {
    target.enroll_state == SshEnrollState::Enrolled && target.enrolled_scripts.as_deref() != Some(scripts_version())
}

/// `privileged`, the grants of restricted access, or `as <user>`.
pub(crate) fn access_summary(access: SshAccess, grants: &[String], user: Option<&str>) -> String {
    match access {
        SshAccess::Privileged => "privileged".to_owned(),
        SshAccess::Restricted => grants.join(", "),
        SshAccess::User => format!("as {}", user.unwrap_or("-")),
    }
}

/// `nuk1 (as deploy), db (restricted)`: each target of a lease with its access.
pub(crate) fn targets_text<'a>(targets: impl IntoIterator<Item = (&'a str, SshAccess, Option<&'a str>)>) -> String {
    targets.into_iter().map(|(name, access, user)| match access {
        SshAccess::User => format!("{name} (as {})", user.unwrap_or("-")),
        access => format!("{name} ({})", access.as_str()),
    }).collect::<Vec<_>>().join(", ")
}

fn host_key_fingerprint(line: &str) -> String {
    PublicKey::from_openssh(line).map(|k| k.fingerprint(HashAlg::Sha256).to_string()).unwrap_or_default()
}

/// The decoded blob of a pinned `<type> <b64>` host key.
fn host_key_blob(line: &str) -> Option<Vec<u8>> {
    line.split(' ').nth(1).and_then(b64_decode)
}

/// The certificate blob of a lease's certificate line.
fn certificate_blob(line: &str) -> Option<Vec<u8>> {
    line.split(' ').nth(1).and_then(b64_decode)
}

fn role_principal(target_id: &str, access: SshAccess) -> String {
    match access {
        SshAccess::Privileged => format!("asm-{target_id}-privileged"),
        SshAccess::Restricted => format!("asm-{target_id}-restricted"),
        SshAccess::User => format!("asm-{target_id}-user"),
    }
}

/// The forced command of a lease certificate for `target`, valid until `until`.
fn lease_command(id: &str, until: i64, target: &SshGrantTarget) -> String {
    match target.access {
        SshAccess::Privileged => format!("asm-shell lease={id} until={until}"),
        SshAccess::User => format!("asm-shell lease={id} until={until} as={}", target.user.as_deref().unwrap_or_default()),
        SshAccess::Restricted => format!("asm-grant lease={id} until={until} {}", target.grants.join(" ")),
    }
}

/// One certificate line per lease target, all for `key` and valid from `now - 60` until
/// `until`: target id → certificate.
fn lease_certificates(ca: &SshKey, key: &SshKey, id: &str, grant: &SshGrant, now: i64, until: i64)
    -> Result<BTreeMap<String, String>>
{
    let key_id = format!("asm-lease-{id}");
    grant.targets.iter().map(|target| {
        let command = lease_command(id, until, target);
        let blob = build_user_cert(ca, &key.public_key(), &CertSpec {
            key_id: &key_id,
            principals: &[role_principal(&target.target_id, target.access)],
            valid_after: now.saturating_sub(60).max(0) as u64,
            valid_before: until.max(0) as u64,
            force_command: Some(&command),
            permit_pty: target.access != SshAccess::Restricted,
        })?;
        Ok((target.target_id.clone(), cert_line(&blob, &key_id)))
    }).collect()
}

pub(crate) fn ssh_result(lease: &SshLeaseRecord) -> SshResult {
    SshResult {
        lease_id: lease.id.clone(),
        expires_at: fmt_unix(lease.expires_at),
        targets: lease.grant.targets.iter().map(|t| SshTargetAccess {
            name: t.name.clone(),
            target_id: t.target_id.clone(),
            login: t.login.clone(),
            hostname: t.hostname.clone(),
            port: t.port,
            host_keys: t.host_keys.clone(),
            access: t.access,
            grants: t.grants.clone(),
            user: t.user.clone(),
            certificate: lease.certificates.get(&t.target_id).cloned().unwrap_or_default(),
        }).collect(),
    }
}

fn lease_names(lease: &SshLeaseRecord) -> String {
    lease.grant.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")
}

/// Each target of a lease with its access (`targets_text`).
fn lease_targets_text(grant: &SshGrant) -> String {
    targets_text(grant.targets.iter().map(|t| (t.name.as_str(), t.access, t.user.as_deref())))
}

/// Per target of a lease, what its activity events record.
fn lease_targets_detail(grant: &SshGrant) -> serde_json::Value {
    json!(grant.targets.iter().map(|t| json!({
        "name": t.name, "login": t.login, "access": t.access, "grants": t.grants, "user": t.user,
    })).collect::<Vec<_>>())
}

impl SshRequested {
    /// The request `d` as a lease records it: grants and target ids sorted.
    fn of(d: &SshDetail) -> Self {
        let mut grants = d.grants.clone();
        grants.sort_unstable();
        grants.dedup();
        let mut target_ids: Vec<String> = d.targets.iter().map(|t| t.target_id.clone()).collect();
        target_ids.sort_unstable();
        Self { access: d.access, grants, user: d.user.clone(), target_ids }
    }
}

/// `target` allows `access` with these grants (restricted) or this user; otherwise why not.
fn target_refusal(target: &SshTargetRecord, access: SshAccess, grants: &[String], user: Option<&str>) -> Result<()> {
    let name = &target.name;
    match access {
        SshAccess::Privileged if !target.config.allow_privileged => {
            Err(CoreError::invalid(format!("SSH target {name} does not allow privileged access")))
        }
        SshAccess::Privileged => Ok(()),
        SshAccess::User => match user {
            Some(user) if target_has_user(target, user) => Ok(()),
            user => Err(CoreError::invalid(format!(
                "SSH target {name} does not allow access as {}; see asm ssh hosts", user.unwrap_or("-")))),
        },
        SshAccess::Restricted => match grants.iter().find(|g| !target_allows(target, g)) {
            Some(grant) => Err(CoreError::invalid(format!("SSH target {name} does not allow {grant}"))),
            None => Ok(()),
        },
    }
}

fn ssh_event(kind: &'static str, summary: impl Into<String>) -> Event {
    Event::new(Category::Ssh, kind, summary)
}

/// A refused signature: the error, and the event to log for it.
struct SignRefusal {
    error: CoreError,
    event: Option<Box<(String, Event)>>,
}

impl From<CoreError> for SignRefusal {
    fn from(error: CoreError) -> Self {
        Self { error, event: None }
    }
}

impl Core {
    // ---- CA ----

    pub(crate) fn ssh_ca(&self) -> Result<Arc<SshKey>> {
        let mut ca = lock(&self.ssh.ca);
        if let Some(key) = ca.as_ref() {
            return Ok(key.clone());
        }
        let key = match self.resume.get::<SavedSeed>(CA_NAMESPACE, CA_ID)? {
            Some(saved) => SshKey::from_seed_b64(&saved.seed)?,
            None => {
                let key = SshKey::generate();
                self.resume.put(CA_NAMESPACE, CA_ID, &SavedSeed { seed: key.seed_b64().to_string() })?;
                key
            }
        };
        let key = Arc::new(key);
        *ca = Some(key.clone());
        Ok(key)
    }

    // ---- targets ----

    /// Why a target cannot serve leases now; `None` when it is ready.
    fn ssh_target_issue(&self, t: &SshTargetRecord) -> Result<Option<String>> {
        let issue = match t.enroll_state {
            SshEnrollState::NotEnrolled => Some("not enrolled"),
            SshEnrollState::Enrolling => Some("enrollment is running"),
            SshEnrollState::Failed => Some("the last enrollment or removal failed"),
            SshEnrollState::Removing => Some("asm is being removed from this host"),
            SshEnrollState::Enrolled if t.enrolled_revision != t.revision => Some("settings changed; enroll again"),
            SshEnrollState::Enrolled if t.enrolled_ca.as_deref() != Some(self.ssh_ca()?.fingerprint().as_str()) => {
                Some("enrolled with another CA key; enroll again")
            }
            SshEnrollState::Enrolled if scripts_outdated(t) => Some("asm updated its host scripts; enroll again"),
            SshEnrollState::Enrolled => None,
        };
        Ok(issue.map(str::to_owned))
    }

    fn ssh_target_ready(&self, t: &SshTargetRecord) -> Result<bool> {
        Ok(self.ssh_target_issue(t)?.is_none())
    }

    fn write_ssh_known_hosts(&self) -> Result<()> {
        let mut text = String::new();
        for target in self.store.list_ssh_targets()? {
            for key in &target.config.host_keys {
                text.push_str(&format!("asm-target-{} {key}\n", target.id));
            }
        }
        write_private_atomic(&self.dirs.ssh, "known_hosts", text.as_bytes())?;
        Ok(())
    }

    /// Before serving requests: finish interrupted target operations as failed.
    pub(crate) fn restore_ssh(&self) -> Result<()> {
        let t = self.generation_now();
        for target in self.store.list_ssh_targets()? {
            self.store.set_ssh_enrollment(&target.id, &[SshEnrollState::Enrolling, SshEnrollState::Removing],
                SshEnrollState::Failed, None, None, None, Some("interrupted; run it again"), t)?;
        }
        self.write_ssh_known_hosts()
    }

    fn ssh_target_info(&self, t: SshTargetRecord, active: &HashMap<String, u32>) -> Result<ffi::SshTargetInfo> {
        let ready = self.ssh_target_ready(&t)?;
        let state = match t.enroll_state {
            SshEnrollState::NotEnrolled => ffi::SshTargetState::NotEnrolled,
            SshEnrollState::Enrolling => ffi::SshTargetState::Enrolling,
            SshEnrollState::Enrolled if ready => ffi::SshTargetState::Enrolled,
            SshEnrollState::Enrolled => ffi::SshTargetState::NeedsReenroll,
            SshEnrollState::Failed => ffi::SshTargetState::Failed,
            SshEnrollState::Removing => ffi::SshTargetState::Removing,
        };
        let scripts_outdated = scripts_outdated(&t);
        let c = t.config;
        Ok(ffi::SshTargetInfo {
            active_leases: active.get(&t.id).copied().unwrap_or(0),
            host_key_changed: lock(&self.ssh.key_changed).contains(&t.id),
            id: t.id,
            name: t.name,
            destination: c.destination,
            agent_hostname: c.agent_hostname,
            agent_port: c.agent_port,
            privileged_login: c.privileged_login,
            allow_privileged: c.allow_privileged,
            host_keys: c.host_keys.iter().map(|line| ffi::SshHostKey {
                line: line.clone(), fingerprint: host_key_fingerprint(line),
            }).collect(),
            log_units: c.log_units,
            restart_units: c.restart_units,
            reload_units: c.reload_units,
            read_files: c.read_files,
            max_duration_secs: c.max_duration_secs,
            users: c.users.into_iter().map(Into::into).collect(),
            revision: t.revision,
            state,
            error: t.enroll_error,
            scripts_outdated,
        })
    }

    fn active_ssh_counts(&self) -> Result<HashMap<String, u32>> {
        let mut counts = HashMap::new();
        for lease in self.store.active_ssh_leases(self.generation_now())? {
            for target in &lease.grant.targets {
                *counts.entry(target.target_id.clone()).or_insert(0) += 1;
            }
        }
        Ok(counts)
    }

    pub fn list_ssh_targets(&self) -> Result<Vec<ffi::SshTargetInfo>> {
        let active = self.active_ssh_counts()?;
        self.store.list_ssh_targets()?.into_iter().map(|t| self.ssh_target_info(t, &active)).collect()
    }

    fn ssh_target_info_by_id(&self, id: &str) -> Result<ffi::SshTargetInfo> {
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        self.ssh_target_info(target, &self.active_ssh_counts()?)
    }

    /// What the operator's own known_hosts files say about `destination`, without
    /// contacting it. `keys` leaves out keys marked `@revoked`.
    fn known_hosts_view(&self, destination: &str) -> Result<KnownHostsView> {
        let destination = destination.trim();
        validate_destination(destination)?;
        let run = self.ssh_run_dir()?;
        let mut command = Command::new(SSH);
        command.arg("-F").arg(write_wrapper_config(&run.0, None)?).args(["-G", "--", destination]);
        let (status, stdout, stderr) = run_local(command, None, LOCAL_TIMEOUT)?;
        if status != 0 {
            let why = host_text(last_line(&stderr).unwrap_or("ssh -G failed"));
            return Err(CoreError::vault_unavailable(format!("could not read your ssh settings for {destination}: {why}")));
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let expand = |path: &str| -> PathBuf {
            match path.strip_prefix('~') {
                Some(rest) if rest.is_empty() || rest.starts_with('/') => PathBuf::from(format!("{home}{rest}")),
                _ => PathBuf::from(path),
            }
        };
        let (mut hostname, mut port, mut alias) = (String::new(), 22u16, None::<String>);
        let (mut proxy_jump, mut proxy_command) = (None::<String>, false);
        let mut files: Vec<PathBuf> = Vec::new();
        for line in stdout.lines() {
            let Some((key, value)) = line.split_once(' ') else { continue };
            let value = value.trim();
            match key {
                "hostname" => hostname = value.to_owned(),
                "port" => port = value.parse().unwrap_or(22),
                "hostkeyalias" if !value.is_empty() && value != "none" => alias = Some(value.to_owned()),
                "proxyjump" if !value.is_empty() && value != "none" => proxy_jump = Some(host_text(value)),
                "proxycommand" => proxy_command = !value.is_empty() && value != "none",
                "userknownhostsfile" | "globalknownhostsfile" => {
                    files.extend(value.split_whitespace().filter(|p| *p != "none").map(expand));
                }
                _ => {}
            }
        }
        if hostname.is_empty() {
            return Err(CoreError::vault_unavailable(format!("ssh did not report a hostname for {destination}")));
        }
        let name = alias.unwrap_or_else(|| if port == 22 { hostname.clone() } else { format!("[{hostname}]:{port}") });
        let mut keys: Vec<String> = Vec::new();
        let mut revoked: HashSet<String> = HashSet::new();
        for file in files.iter().filter(|f| f.is_file()) {
            let mut command = Command::new(SSH_KEYGEN);
            command.arg("-F").arg(&name).arg("-f").arg(file);
            let (status, stdout, stderr) = run_local(command, None, LOCAL_TIMEOUT)?;
            match status {
                0 => {}
                1 => continue,
                _ => {
                    let why = host_text(last_line(&stderr).unwrap_or("ssh-keygen -F failed"));
                    return Err(CoreError::vault_unavailable(format!("could not read {}: {why}", file.display())));
                }
            }
            for line in stdout.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if line.starts_with("@revoked") {
                    if let (Some(kind), Some(b64)) = (fields.get(2), fields.get(3)) {
                        revoked.insert(format!("{kind} {b64}"));
                    }
                    continue;
                }
                if line.starts_with("@cert-authority") {
                    return Err(CoreError::invalid(format!(
                        "{destination} uses a host certificate authority; asm needs its plain host keys")));
                }
                let (Some(kind), Some(b64)) = (fields.get(1), fields.get(2)) else { continue };
                let key = format!("{kind} {b64}");
                crate::store::validate_host_key(&key)?;
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        keys.retain(|k| !revoked.contains(k));
        Ok(KnownHostsView { hostname, port, keys, revoked, proxy_jump, proxy_command })
    }

    /// Host keys for `destination` from the operator's own known_hosts files, without
    /// contacting it. `keys` is empty when they don't know it.
    pub fn lookup_ssh_host_keys(&self, destination: &str) -> Result<ffi::SshHostKeyLookup> {
        let view = self.known_hosts_view(destination.trim())?;
        Ok(host_key_lookup(&view, view.keys.clone()))
    }

    /// The host keys `destination` offers over the operator's ssh route, without logging
    /// in (`fetch_host_keys`). Unverified; keys known_hosts marks `@revoked` are refused.
    pub fn fetch_ssh_host_keys(&self, destination: &str) -> Result<ffi::SshHostKeyLookup> {
        let destination = destination.trim();
        let view = self.known_hosts_view(destination)?;
        let run = self.ssh_run_dir()?;
        let mut keys = fetch_host_keys(destination, None, &run.0)?;
        keys.retain(|k| !view.revoked.contains(k));
        if keys.is_empty() {
            return Err(CoreError::invalid(format!(
                "{destination} offered only host keys that your known_hosts marks as revoked")));
        }
        Ok(host_key_lookup(&view, keys))
    }

    /// Before a target is saved: logs in to `destination` as enrollment will, as `login`,
    /// pinned to `host_keys` (`check_destination`). Writes no known_hosts file but a
    /// throwaway one of asm's.
    pub fn check_ssh_destination(&self, destination: &str, login: &str, host_keys: &[String]) -> Result<ffi::SshHostCheck> {
        let (destination, login) = checked_destination(destination, login, host_keys)?;
        let run = self.ssh_run_dir()?;
        match check_destination(destination, login, host_keys, None, &run.0)? {
            HostCheck::Verified => Ok(ffi::SshHostCheck::Verified),
            HostCheck::Unreachable(message) => Ok(ffi::SshHostCheck::Unreachable { message }),
            HostCheck::KeyMismatch(presented) => Ok(ffi::SshHostCheck::KeyMismatch {
                presented: self.unrevoked(destination, presented)?.into_iter().map(host_key_item).collect(),
            }),
        }
    }

    /// While choosing a target's users: logs in to `destination` as `login`, pinned to
    /// `host_keys`, and lists the accounts agents could log in as (`list_host_users`).
    pub fn list_ssh_host_users(&self, destination: &str, login: &str, host_keys: &[String])
        -> Result<Vec<ffi::SshHostUser>>
    {
        let (destination, login) = checked_destination(destination, login, host_keys)?;
        let run = self.ssh_run_dir()?;
        list_host_users(destination, login, host_keys, None, &run.0)
    }

    /// `presented` without the keys known_hosts marks `@revoked`; an error when none is left.
    fn unrevoked(&self, destination: &str, mut presented: Vec<String>) -> Result<Vec<String>> {
        let revoked = self.known_hosts_view(destination)?.revoked;
        presented.retain(|k| !revoked.contains(k));
        if presented.is_empty() {
            return Err(CoreError::invalid(format!(
                "{destination} presented only host keys that your known_hosts marks as revoked")));
        }
        Ok(presented)
    }

    /// Asks an existing target for its host keys (without logging in) and compares them
    /// with the pinned ones. A match clears the target's changed-key mark; a mismatch sets
    /// it and returns the keys the host offers for the operator to review.
    pub fn review_ssh_host_keys(&self, id: &str) -> Result<ffi::SshHostCheck> {
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        let destination = &target.config.destination;
        let run = self.ssh_run_dir()?;
        let presented = fetch_host_keys(destination, None, &run.0)?;
        let matched = presented.iter().any(|k| target.config.host_keys.contains(k));
        self.mark_host_key(id, !matched);
        if matched {
            return Ok(ffi::SshHostCheck::Verified);
        }
        Ok(ffi::SshHostCheck::KeyMismatch {
            presented: self.unrevoked(destination, presented)?.into_iter().map(host_key_item).collect(),
        })
    }

    /// Pins new host keys for a target after the operator reviewed them, in any state but
    /// a running enrollment or removal. Like a saved change, this ends the target's
    /// active leases and, for an enrolled target, asks for enrolling again.
    pub fn replace_ssh_host_keys(&self, id: &str, expected_revision: u64, keys: Vec<String>) -> Result<ffi::SshTargetInfo> {
        let busy = self.claim_ssh_target(id)?;
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        if target.revision != expected_revision {
            return Err(CoreError::invalid("SSH target changed; reload it"));
        }
        if matches!(target.enroll_state, SshEnrollState::Enrolling | SshEnrollState::Removing) {
            return Err(CoreError::invalid("this SSH target is being enrolled or removed"));
        }
        let mut config = target.config.clone();
        config.host_keys = keys;
        config.canonicalize();
        config.validate()?;
        self.refuse_pinned_elsewhere(Some(id), &config.host_keys)?;
        let revision = self.store.update_ssh_target(id, &target.name, &config, expected_revision)?;
        self.end_target_leases(id, "target host keys replaced")?;
        self.write_ssh_known_hosts()?;
        drop(busy);
        self.kick_ssh_cleanup();
        self.mark_host_key(id, false);
        self.log(ssh_event("host_keys_replaced", format!("SSH target {}: host keys replaced", target.name))
            .detail(json!({ "target_id": id, "name": target.name, "revision": revision,
                "fingerprints": config.host_keys.iter().map(|k| host_key_fingerprint(k)).collect::<Vec<_>>() })));
        self.notify(TOPIC_SSH_TARGETS);
        self.ssh_target_info_by_id(id)
    }

    /// Each target needs its own host keys.
    fn refuse_pinned_elsewhere(&self, id: Option<&str>, keys: &[String]) -> Result<()> {
        for other in self.store.list_ssh_targets()? {
            if id == Some(other.id.as_str()) {
                continue;
            }
            if let Some(key) = keys.iter().find(|k| other.config.host_keys.contains(k)) {
                return Err(CoreError::invalid(format!(
                    "host key {} is already pinned for SSH target {}; each target needs its own host keys",
                    host_key_fingerprint(key), other.name)));
            }
        }
        Ok(())
    }

    /// Ends the active leases that include target `id`.
    fn end_target_leases(&self, id: &str, reason: &str) -> Result<()> {
        let ended = {
            let authority = lock(&self.authorization);
            let mut ended = false;
            for lease in self.store.active_ssh_leases(self.generation_now())? {
                if lease.grant.targets.iter().any(|target| target.target_id == id) {
                    ended |= self.end_ssh_lease_locked(&lease.id, reason, &authority)?;
                }
            }
            ended
        };
        if ended {
            self.notify(TOPIC_LEASES);
        }
        Ok(())
    }

    /// Records whether target `id` last failed its host key check.
    fn mark_host_key(&self, id: &str, changed: bool) {
        let flipped = {
            let mut set = lock(&self.ssh.key_changed);
            if changed { set.insert(id.to_owned()) } else { set.remove(id) }
        };
        if flipped {
            self.notify(TOPIC_SSH_TARGETS);
        }
    }

    /// Notes what a run on `target` says about its host key and passes the result on.
    fn track_host_key<T>(&self, target: &SshTargetRecord, result: std::result::Result<T, RemoteError>)
        -> std::result::Result<T, RemoteError>
    {
        match &result {
            // The host answered, so it proved its key.
            Ok(_) | Err(RemoteError::Host { .. }) => self.mark_host_key(&target.id, false),
            Err(RemoteError::HostKeyChanged) => self.mark_host_key(&target.id, true),
            Err(_) => {}
        }
        result
    }

    /// A private directory under `ssh_run`, removed when the guard drops.
    fn ssh_run_dir(&self) -> Result<RunDir> {
        let dir = self.dirs.ssh_run.join(new_uuid_v4());
        std::fs::DirBuilder::new().mode(0o700).create(&dir)
            .map_err(|e| CoreError::vault_unavailable(format!("could not create {}: {e}", dir.display())))?;
        Ok(RunDir(dir))
    }

    pub fn save_ssh_target(&self, draft: ffi::SshTargetDraft) -> Result<ffi::SshTargetInfo> {
        let name = draft.name.trim().to_owned();
        validate_target_name(&name)?;
        let or_name = |value: &str| {
            let value = value.trim();
            if value.is_empty() { name.clone() } else { value.to_owned() }
        };
        let trimmed = |values: &[String]| -> Vec<String> {
            values.iter().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()).collect()
        };
        let mut config = SshTargetConfig {
            destination: or_name(&draft.destination),
            agent_hostname: or_name(&draft.agent_hostname),
            agent_port: draft.agent_port,
            privileged_login: draft.privileged_login.trim().to_owned(),
            allow_privileged: draft.allow_privileged,
            host_keys: draft.host_keys,
            log_units: trimmed(&draft.log_units),
            restart_units: trimmed(&draft.restart_units),
            reload_units: trimmed(&draft.reload_units),
            read_files: trimmed(&draft.read_files),
            max_duration_secs: draft.max_duration_secs,
            users: draft.users.into_iter().map(Into::into).collect(),
        };
        config.canonicalize();
        config.validate()?;
        let _busy = match &draft.id {
            Some(id) => {
                let busy = self.claim_ssh_target(id)?;
                let stored = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
                if stored.enroll_state != SshEnrollState::NotEnrolled
                    && (stored.config.destination != config.destination || stored.config.host_keys != config.host_keys)
                {
                    return Err(CoreError::invalid("remove asm from the host before changing its destination or host keys"));
                }
                Some(busy)
            }
            None => None,
        };
        self.refuse_pinned_elsewhere(draft.id.as_deref(), &config.host_keys)?;
        let t = self.generation_now();
        let (id, revision) = match draft.id {
            None => {
                let id = hex_encode(&random_bytes::<4>());
                self.store.insert_ssh_target(&SshTargetRecord {
                    id: id.clone(), name: name.clone(), config: config.clone(), revision: 1,
                    enroll_state: SshEnrollState::NotEnrolled, enrolled_revision: 0, enrolled_ca: None,
                    enroll_at: None, enroll_error: None, created_at: t, enrolled_scripts: None,
                })?;
                (id, 1)
            }
            Some(id) => {
                let expected = draft.expected_revision.ok_or_else(|| CoreError::invalid("expected_revision is required"))?;
                let revision = self.store.update_ssh_target(&id, &name, &config, expected)?;
                (id, revision)
            }
        };
        if revision > 1 {
            self.end_target_leases(&id, "target changed")?;
        }
        self.write_ssh_known_hosts()?;
        drop(_busy);
        if revision > 1 {
            self.kick_ssh_cleanup();
        }
        self.log(ssh_event("target_saved", format!("SSH target {name} saved"))
            .detail(json!({ "target_id": id, "name": name, "destination": config.destination, "revision": revision })));
        self.notify(TOPIC_SSH_TARGETS);
        self.ssh_target_info_by_id(&id)
    }

    pub fn remove_ssh_target(&self, id: &str) -> Result<()> {
        let busy = self.claim_ssh_target(id)?;
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        if matches!(target.enroll_state, SshEnrollState::Enrolled | SshEnrollState::Enrolling | SshEnrollState::Removing) {
            return Err(CoreError::invalid("remove asm from the host first"));
        }
        self.end_target_leases(id, "target removed from asm")?;
        self.store.delete_ssh_target(id)?;
        self.write_ssh_known_hosts()?;
        drop(busy);
        self.kick_ssh_cleanup();
        self.log(ssh_event("target_removed", format!("SSH target {} removed", target.name))
            .detail(json!({ "target_id": id, "name": target.name })));
        self.notify(TOPIC_SSH_TARGETS);
        Ok(())
    }

    fn claim_ssh_target(&self, id: &str) -> Result<Busy<'_>> {
        if !lock(&self.ssh.busy).insert(id.to_owned()) {
            return Err(CoreError::invalid(
                "asm is enrolling, removing or ending sessions on this target; try again in a moment"));
        }
        Ok(Busy { set: &self.ssh.busy, id: id.to_owned() })
    }

    fn render_target_enroll(&self, target: &SshTargetRecord) -> Result<String> {
        let c = &target.config;
        let ca = self.ssh_ca()?;
        render_enroll(&EnrollParams {
            target_id: &target.id,
            privileged_login: &c.privileged_login,
            allow_privileged: c.allow_privileged,
            ca_key: &ca.openssh_line(),
            ca_fingerprint: &ca.fingerprint(),
            log_units: &c.log_units,
            restart_units: &c.restart_units,
            reload_units: &c.reload_units,
            read_files: &c.read_files,
            users: &c.users.iter().map(|u| (u.name.clone(), u.admin.is_some())).collect::<Vec<_>>(),
            agent_hostname: &c.agent_hostname,
            agent_port: c.agent_port,
        })
    }

    pub fn ssh_enroll_script(&self, id: &str) -> Result<String> {
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        self.render_target_enroll(&target)
    }

    fn remote(&self) -> Arc<dyn SshRemote> {
        self.ssh.remote.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Run `stdin` on `target` over the operator's own ssh (enroll, remove).
    fn operator_run(&self, target: &SshTargetRecord, stdin: &str, timeout: Duration)
        -> std::result::Result<RemoteOutput, RemoteError>
    {
        let run = self.ssh_run_dir().map_err(|e| RemoteError::Local(e.message))?;
        self.remote().run(target, &RemoteAuth::Operator { dir: run.0.clone() }, stdin, timeout)
    }

    /// A new run id, ending `RUN_CERT_SECS` from now.
    fn cert_run(&self) -> CertRun {
        CertRun { id: new_uuid_v4(), until: self.generation_now().saturating_add(RUN_CERT_SECS) }
    }

    /// Log in to `target` with a fresh short-lived certificate for `role`, valid until
    /// `run.until`; a check login presents `run.id` as its lease.
    fn certificate_run(&self, target: &SshTargetRecord, role: CertRole, run: &CertRun, stdin: &str)
        -> std::result::Result<RemoteOutput, RemoteError>
    {
        let local = |e: CoreError| RemoteError::Local(e.message);
        let now = self.generation_now();
        let (run_id, until) = (&run.id, run.until);
        let (key_id, principal, command, login, remote_command) = match role {
            CertRole::Cleanup => (format!("asm-cleanup-{run_id}"), format!("asm-{}-cleanup", target.id), None,
                RESTRICTED_LOGIN, None),
            CertRole::CheckPrivileged => (format!("asm-check-{run_id}"), format!("asm-{}-privileged", target.id),
                Some(format!("asm-shell lease={run_id} until={until}")), PRIVILEGED_LOGIN, Some("true")),
            CertRole::CheckUser(user) => (format!("asm-check-{run_id}"), format!("asm-{}-user", target.id),
                Some(format!("asm-shell lease={run_id} until={until} as={user}")), PRIVILEGED_LOGIN, Some("true")),
        };
        let key = SshKey::generate();
        let blob = build_user_cert(&*self.ssh_ca().map_err(local)?, &key.public_key(), &CertSpec {
            key_id: &key_id,
            principals: &[principal],
            valid_after: now.saturating_sub(60).max(0) as u64,
            valid_before: until.max(0) as u64,
            force_command: command.as_deref(),
            permit_pty: false,
        }).map_err(local)?;
        let dir = self.dirs.ssh_run.join(new_uuid_v4());
        std::fs::DirBuilder::new().mode(0o700).create(&dir)
            .map_err(|e| RemoteError::Local(format!("could not create {}: {e}", dir.display())))?;
        let guard = RunDir(dir);
        let write = |name: &str, data: &[u8]| write_private_atomic(&guard.0, name, data)
            .map_err(|e| RemoteError::Local(format!("could not write {}: {e}", guard.0.join(name).display())));
        write("id", key.private_openssh().map_err(local)?.as_bytes())?;
        write("id-cert.pub", format!("{}\n", cert_line(&blob, &key_id)).as_bytes())?;
        let auth = RemoteAuth::Certificate { login, dir: guard.0.clone(), command: remote_command };
        self.remote().run(target, &auth, stdin, CLEANUP_TIMEOUT)
    }

    /// Enrollment's test logins, all under one run id: `asm-priv` when privileged access is
    /// allowed and `asm-priv` as each user (each registers under the id, so the host also
    /// records the files it watches), then the cleanup login, which ends the id like a
    /// lease and so drops that record (`check` when there was no shell login). The error
    /// names the login that failed.
    fn check_enrollment(&self, target: &SshTargetRecord) -> std::result::Result<(), (String, RemoteError)> {
        let run = self.cert_run();
        let mut shells = Vec::new();
        if target.config.allow_privileged {
            shells.push((CertRole::CheckPrivileged, PRIVILEGED_LOGIN.to_owned()));
        }
        for user in &target.config.users {
            shells.push((CertRole::CheckUser(user.name.clone()), format!("{PRIVILEGED_LOGIN} as {}", user.name)));
        }
        let ops = || RESTRICTED_LOGIN.to_owned();
        let ending = !shells.is_empty();
        let stdin = if ending {
            cleanup_stdin(&run.id, run.until).map_err(|e| (ops(), RemoteError::Local(e.message)))?
        } else {
            "check\n".to_owned()
        };
        for (role, login) in shells {
            let out = self.certificate_run(target, role, &run, "").map_err(|e| (login.clone(), e))?;
            let why = || last_line(&out.stderr).map_or_else(|| format!("exit status {}", out.status), host_text);
            match out.status {
                0 => {}
                255 => {
                    let e = connection_error(target, &out.stderr);
                    let _ = self.track_host_key::<()>(target, Err(e.clone()));
                    return Err((login, e));
                }
                _ => return Err((login, RemoteError::Host { code: "unexpected".into(), message: why() })),
            }
        }
        let out = self.certificate_run(target, CertRole::Cleanup, &run, &stdin).map_err(|e| (ops(), e))?;
        // `end` reports two counts (sessions ended, files changed; the paths are left
        // out), `check` one zero.
        let counts = if ending { 2 } else { 1 };
        match self.track_host_key(target, host_result(target, out, "asm-end-ok", "asm-end-error", counts)) {
            Ok(_) if ending => Ok(()),
            Ok(n) if n == [0] => Ok(()),
            Ok(n) => Err((ops(), RemoteError::Host { code: "unexpected".into(), message: format!("asm-end-ok {}", n[0]) })),
            Err(e) => Err((ops(), e)),
        }
    }

    pub fn enroll_ssh_target(&self, id: &str, expected_revision: u64) -> Result<ffi::SshTargetInfo> {
        let busy = self.claim_ssh_target(id)?;
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        if target.revision != expected_revision {
            return Err(CoreError::invalid("SSH target changed; reload it"));
        }
        let script = self.render_target_enroll(&target)?;
        let ca = self.ssh_ca()?.fingerprint();
        // A route certificate runs refuse must fail enrollment before the host is changed.
        self.remote().check_route(&target, &self.ssh_run_dir()?.0)?;
        if !self.store.set_ssh_enrollment(id, &[SshEnrollState::NotEnrolled, SshEnrollState::Failed, SshEnrollState::Enrolled],
            SshEnrollState::Enrolling, None, None, None, None, self.generation_now())?
        {
            return Err(CoreError::invalid("this SSH target is being enrolled or removed"));
        }
        self.notify(TOPIC_SSH_TARGETS);
        self.log(ssh_event("enroll_started", format!("{}: host may be partly changed until enrollment finishes", target.name))
            .detail(json!({ "target_id": id, "name": target.name, "destination": target.config.destination,
                "revision": target.revision })));
        let ended = self.end_target_leases(id, "target enrolled again")
            .map_err(|e| format!("could not end the target's active leases: {}", e.message));
        self.kick_ssh_cleanup();
        let outcome = ended
            .and_then(|()| self.operator_run(&target, &script, ENROLL_TIMEOUT)
                .and_then(|out| self.track_host_key(&target, host_result(&target, out, "asm-enroll-ok", "asm-enroll-error", 0)))
                .map_err(|e| e.to_string()))
            .and_then(|_| self.check_enrollment(&target)
                .map_err(|(login, e)| format!("enrolled, but a test login as {login} failed: {e}")));
        let t = self.generation_now();
        let result = match outcome {
            Ok(()) => {
                self.store.set_ssh_enrollment(id, &[SshEnrollState::Enrolling], SshEnrollState::Enrolled,
                    Some(target.revision), Some(&ca), Some(scripts_version()), None, t)?;
                self.log(ssh_event("enrolled", format!("SSH target {} enrolled", target.name))
                    .detail(json!({ "target_id": id, "name": target.name, "revision": target.revision, "ca": ca,
                        "scripts": scripts_version() })));
                Ok(())
            }
            Err(message) => {
                self.store.set_ssh_enrollment(id, &[SshEnrollState::Enrolling], SshEnrollState::Failed,
                    None, None, None, Some(&message), t)?;
                self.log(ssh_event("enroll_failed", format!("enrolling SSH target {} failed: {message}", target.name))
                    .detail(json!({ "target_id": id, "name": target.name, "message": message })));
                Err(CoreError::vault_unavailable(message))
            }
        };
        self.notify(TOPIC_SSH_TARGETS);
        drop(busy);
        self.kick_ssh_cleanup();
        result?;
        self.ssh_target_info_by_id(id)
    }

    pub fn unenroll_ssh_target(&self, id: &str) -> Result<()> {
        let _busy = self.claim_ssh_target(id)?;
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        let ended = {
            let authority = lock(&self.authorization);
            if !self.store.set_ssh_enrollment(id,
                &[SshEnrollState::NotEnrolled, SshEnrollState::Enrolled, SshEnrollState::Failed],
                SshEnrollState::Removing, None, None, None, None, self.generation_now())?
            {
                return Err(CoreError::invalid("this SSH target is being enrolled or removed"));
            }
            let mut ended = false;
            for lease in self.store.active_ssh_leases(self.generation_now())? {
                if lease.grant.targets.iter().any(|t| t.target_id == id) {
                    ended |= self.end_ssh_lease_locked(&lease.id, "target removed from host", &authority)?;
                }
            }
            ended
        };
        if ended {
            self.notify(TOPIC_LEASES);
        }
        self.notify(TOPIC_SSH_TARGETS);
        self.kick_ssh_cleanup();
        let outcome = render_remove(&target.id).map_err(|e| e.message)
            .and_then(|script| self.operator_run(&target, &script, REMOVE_TIMEOUT)
                .and_then(|out| self.track_host_key(&target, host_result(&target, out, "asm-unenroll-ok", "asm-unenroll-error", 1)))
                .map_err(|e| e.to_string()));
        let t = self.generation_now();
        let result = match outcome {
            Ok(n) => {
                self.store.set_ssh_enrollment(id, &[SshEnrollState::Removing], SshEnrollState::NotEnrolled,
                    None, None, None, None, t)?;
                let detail = format!("host reported: asm removed; ended {} sessions", n[0]);
                {
                    let _authority = lock(&self.authorization);
                    for mut lease in self.store.ssh_leases_needing_cleanup()? {
                        let Some(entry) = lease.cleanup.get_mut(id) else { continue };
                        if entry.state != SshCleanupState::Pending {
                            continue;
                        }
                        *entry = SshCleanup::new(SshCleanupState::Done, t, detail.clone(), entry.attempts, 0);
                        self.store.set_ssh_cleanup(&lease.id, &lease.cleanup)?;
                    }
                }
                self.log(ssh_event("unenrolled", format!("asm removed from SSH target {}", target.name))
                    .detail(json!({ "target_id": id, "name": target.name, "sessions_ended": n[0] })));
                Ok(())
            }
            Err(message) => {
                self.store.set_ssh_enrollment(id, &[SshEnrollState::Removing], SshEnrollState::Failed,
                    None, None, None, Some(&message), t)?;
                self.log(ssh_event("unenroll_failed",
                    format!("removing asm from SSH target {} failed: {message}", target.name))
                    .detail(json!({ "target_id": id, "name": target.name, "message": message })));
                Err(CoreError::vault_unavailable(message))
            }
        };
        self.notify(TOPIC_SSH_TARGETS);
        self.notify(TOPIC_LEASES);
        result
    }

    /// Test seam: mark a target enrolled for its current revision, CA and host scripts
    /// without touching the host.
    #[doc(hidden)]
    pub fn install_ssh_target_enrollment(&self, id: &str) -> Result<()> {
        let target = self.store.get_ssh_target(id)?.ok_or_else(|| CoreError::not_found("no such SSH target"))?;
        let ca = self.ssh_ca()?.fingerprint();
        self.store.set_ssh_enrollment(id, &[SshEnrollState::NotEnrolled, SshEnrollState::Enrolling,
            SshEnrollState::Enrolled, SshEnrollState::Failed, SshEnrollState::Removing],
            SshEnrollState::Enrolled, Some(target.revision), Some(&ca), Some(scripts_version()), None,
            self.generation_now())?;
        self.notify(TOPIC_SSH_TARGETS);
        Ok(())
    }

    /// Test seam: reach targets through `remote` instead of `/usr/bin/ssh`.
    #[doc(hidden)]
    pub fn install_ssh_remote(&self, remote: Arc<dyn SshRemote>) {
        *self.ssh.remote.write().unwrap_or_else(|e| e.into_inner()) = remote;
    }

    /// Ready targets and every grant each allows (`GET /v1/ssh/targets`).
    pub fn ssh_target_summaries(&self) -> Result<Vec<SshTargetSummary>> {
        let mut out = Vec::new();
        for target in self.store.list_ssh_targets()? {
            if self.ssh_target_ready(&target)? {
                out.push(SshTargetSummary {
                    grants: target_grants(&target.config),
                    privileged_login: target.config.allow_privileged.then(|| target.config.privileged_login.clone()),
                    users: target.config.users.iter().map(|u| u.name.clone()).collect(),
                    name: target.name,
                });
            }
        }
        Ok(out)
    }

    // ---- requests ----

    pub(super) fn create_ssh(&self, host: &HostRecord, agent: &str, address: &str, body: RequestBody) -> Result<RequestState> {
        let RequestBody::Ssh { targets, access, grants, user, new_lease, reason, .. } = body else {
            return Err(CoreError::internal("not an SSH request"));
        };
        let reason = validate_reason(&reason)?;
        let mut resolved = Vec::with_capacity(targets.len());
        for name in &targets {
            let target = self.store.ssh_target_by_name(name)?
                .ok_or_else(|| CoreError::not_found(format!("no SSH host named {name}; see asm ssh hosts")))?;
            if !self.ssh_target_ready(&target)? {
                return Err(CoreError::invalid(format!("SSH target {name} is not enrolled")));
            }
            target_refusal(&target, access, &grants, user.as_deref())?;
            resolved.push(SshDetailTarget { target_id: target.id, name: target.name, revision: target.revision });
        }
        let detail = SshDetail { targets: resolved, access, grants, user, reason };
        if !new_lease {
            let authority = lock(&self.authorization);
            if let Some(lease) = self.reusable_ssh_lease(&host.id, &detail)? {
                let id = new_uuid_v4();
                let state = RequestState {
                    request_id: id.clone(), kind: RequestKind::Ssh, status: RequestStatus::Approved, deny_reason: None,
                    result: Some(RequestResult::Ssh(ssh_result(&lease))), expires_at: None,
                    pending_lifetime_secs: self.settings().request_lifetime_secs.max(1),
                };
                self.insert_done_locked(&mut lock(&self.book), id, Done {
                    host_id: host.id.clone(), state: state.clone(), at: self.generation_now(), generated: None,
                }, None)?;
                drop(authority);
                self.log(ssh_event("lease_reused", format!("SSH lease on {} reused for {}", lease_names(&lease), host.label()))
                    .host(Some(&host.id))
                    .detail(json!({ "lease_id": lease.id, "agent": agent, "reason": detail.reason })));
                return Ok(state);
            }
        }
        let pending = self.new_pending(host, agent, address, Detail::Ssh(detail.clone()));
        let agent = agent.to_owned();
        self.push_pending(pending, move |q| q.agent == agent && matches!(&q.detail, Detail::Ssh(d) if d.same_request(&detail)))
    }

    /// An active lease of this host made for exactly this request (access, grants, user
    /// and targets), whatever the operator approved then, with every granted target at
    /// its current revision and at least a minute left.
    fn reusable_ssh_lease(&self, host_id: &str, detail: &SshDetail) -> Result<Option<SshLeaseRecord>> {
        let now = self.generation_now();
        let requested = SshRequested::of(detail);
        let mut best: Option<SshLeaseRecord> = None;
        for lease in self.store.active_ssh_leases(now)? {
            if lease.host_id != host_id || lease.grant.requested != requested || lease.expires_at - now < MIN_LEASE_LEFT {
                continue;
            }
            let mut current = true;
            for target in &lease.grant.targets {
                current &= self.store.get_ssh_target(&target.target_id)?.is_some_and(|t| t.revision == target.revision);
            }
            if current && best.as_ref().is_none_or(|b| lease.expires_at > b.expires_at) {
                best = Some(lease);
            }
        }
        Ok(best)
    }

    /// One target of an approval popup as configured now (`max_duration_secs` 0 when it
    /// was removed).
    fn ssh_approval_target(&self, target_id: &str, name: &str, revision: u64) -> ffi::SshApprovalTarget {
        match self.store.get_ssh_target(target_id).ok().flatten() {
            Some(t) => {
                let issue = if t.revision != revision {
                    Some("settings changed since the request".to_owned())
                } else {
                    self.ssh_target_issue(&t).unwrap_or_else(|e| Some(e.message))
                };
                ffi::SshApprovalTarget {
                    ready: issue.is_none(),
                    issue,
                    host_key_fingerprints: t.config.host_keys.iter().map(|k| host_key_fingerprint(k)).collect(),
                    target_id: t.id,
                    name: t.name,
                    hostname: t.config.agent_hostname,
                    port: t.config.agent_port,
                    privileged_login: t.config.privileged_login,
                    allow_privileged: t.config.allow_privileged,
                    log_units: t.config.log_units,
                    restart_units: t.config.restart_units,
                    reload_units: t.config.reload_units,
                    read_files: t.config.read_files,
                    users: t.config.users.into_iter().map(Into::into).collect(),
                    max_duration_secs: t.config.max_duration_secs,
                }
            }
            None => ffi::SshApprovalTarget {
                target_id: target_id.to_owned(), name: name.to_owned(), hostname: String::new(), port: 0,
                privileged_login: String::new(), allow_privileged: false, log_units: Vec::new(),
                restart_units: Vec::new(), reload_units: Vec::new(), read_files: Vec::new(), users: Vec::new(),
                ready: false, issue: Some("target was removed".into()), host_key_fingerprints: Vec::new(),
                max_duration_secs: 0,
            },
        }
    }

    /// The longest lease all `targets` allow (removed ones aside), and the default
    /// duration within it.
    fn ssh_durations<'a>(targets: impl IntoIterator<Item = &'a ffi::SshApprovalTarget>, default_duration: Option<u64>)
        -> (u64, u64)
    {
        let max = targets.into_iter().map(|t| t.max_duration_secs).filter(|m| *m > 0).min().unwrap_or(DEFAULT_LEASE_SECS);
        (default_duration.unwrap_or(DEFAULT_LEASE_SECS).min(max), max)
    }

    pub(super) fn ssh_approval_detail(&self, d: &SshDetail, default_duration: Option<u64>) -> ffi::RequestDetail {
        let targets: Vec<ffi::SshApprovalTarget> = d.targets.iter()
            .map(|t| self.ssh_approval_target(&t.target_id, &t.name, t.revision)).collect();
        let (default_duration_secs, max_duration_secs) = Self::ssh_durations(&targets, default_duration);
        ffi::RequestDetail::Ssh {
            reason: d.reason.clone(),
            access: d.access.into(),
            grants: d.grants.clone(),
            user: d.user.clone(),
            targets,
            default_duration_secs,
            max_duration_secs,
        }
    }

    /// The operator decides per requested target: left out (denied), or approved with its
    /// own access (privileged, restricted with grants, or one of its users). A restricted
    /// request's grants are a ceiling for restricted access.
    pub(super) fn approve_ssh(&self, p: &Pending, d: &SshDetail, a: SshApproval) -> std::result::Result<(), Fail> {
        // 1. The decisions themselves, in request order.
        if a.targets.is_empty() {
            return Err(CoreError::invalid("choose at least one of the requested SSH targets").into());
        }
        let mut decisions: Vec<(&SshDetailTarget, SshAccess, Vec<String>, Option<String>)> = Vec::new();
        for decision in a.targets {
            let wanted = d.targets.iter().find(|t| t.target_id == decision.target_id)
                .filter(|w| !decisions.iter().any(|(t, ..)| t.target_id == w.target_id))
                .ok_or_else(|| CoreError::invalid("approve only the requested SSH targets, each at most once"))?;
            let access = SshAccess::from(decision.access);
            let mut grants = decision.grants;
            asm_proto::ssh::validate_access(access, &grants, decision.user.as_deref())?;
            if access == SshAccess::Restricted && d.access == SshAccess::Restricted
                && grants.iter().any(|g| !d.grants.contains(g))
            {
                return Err(CoreError::invalid("approve only grants the request asked for").into());
            }
            grants.sort_unstable();
            grants.dedup();
            decisions.push((wanted, access, grants, decision.user));
        }
        decisions.sort_by_key(|(wanted, ..)| d.targets.iter().position(|t| t.target_id == wanted.target_id));

        // 2. Under authorization: current targets, the grant, the key and the certificates.
        let (lease, key, result) = {
            let _authority = lock(&self.authorization);
            let mut targets = Vec::with_capacity(decisions.len());
            let mut max = u64::MAX;
            for (wanted, access, grants, user) in decisions {
                let changed = || Fail::Keep(CoreError::invalid(
                    format!("SSH target {} changed; review the request again", wanted.name)));
                let target = self.store.get_ssh_target(&wanted.target_id)?.ok_or_else(changed)?;
                if target.revision != wanted.revision || !self.ssh_target_ready(&target)? {
                    return Err(changed());
                }
                target_refusal(&target, access, &grants, user.as_deref())?;
                max = max.min(target.config.max_duration_secs);
                targets.push(SshGrantTarget {
                    target_id: target.id,
                    name: target.name,
                    revision: target.revision,
                    login: access.login().to_owned(),
                    hostname: target.config.agent_hostname,
                    port: target.config.agent_port,
                    host_keys: target.config.host_keys,
                    access,
                    grants,
                    user,
                });
            }
            if a.duration_secs < 60 || a.duration_secs > max {
                return Err(CoreError::invalid(format!("choose a duration between 1 minute and {} minutes", max / 60)).into());
            }
            let now = self.generation_now();
            let id = new_uuid_v4();
            let expires_at = now.saturating_add(a.duration_secs as i64);
            let grant = SshGrant { requested: SshRequested::of(d), targets };
            let key = SshKey::generate();
            let certificates = lease_certificates(&*self.ssh_ca()?, &key, &id, &grant, now, expires_at)?;
            let lease = SshLeaseRecord {
                id: id.clone(), host_id: p.host_id.clone().unwrap_or_default(), agent: p.agent.clone(),
                reason: d.reason.clone(), grant, certificates, created_at: now, expires_at,
                revoked_at: None, ended_at: None, cleanup: BTreeMap::new(),
            };
            let sealed_key = self.resume.seal(KEY_NAMESPACE, &id, &SavedSeed { seed: key.seed_b64().to_string() })?;
            let result = ssh_result(&lease);
            let mut state = p.state_for(&p.id, RequestStatus::Approved);
            state.result = Some(RequestResult::Ssh(result.clone()));
            let done = Done { host_id: lease.host_id.clone(), state, at: now, generated: None };
            let sealed_done = self.seal_done(&p.id, &done)?;
            let history = p.history(RequestStatus::Approved, None, now);
            self.complete_pending_locked(&mut lock(&self.book), done, [sealed_key, sealed_done], |rows|
                self.store.insert_ssh_lease_with_request(&lease, rows, &history))?;
            (lease, key, result)
        };

        // 3. After the lock.
        lock(&self.ssh.keys).insert(lease.id.clone(), Arc::new(key));
        self.lease_wake.notify_one();
        self.notify(TOPIC_LEASES);
        self.log(ssh_event("lease_created", format!("SSH lease on {}, {}", lease_targets_text(&lease.grant),
            activity::fmt_duration(Some(lease.expires_at - lease.created_at))))
            .host(Some(&lease.host_id))
            .detail(json!({ "lease_id": lease.id, "targets": lease_targets_detail(&lease.grant),
                "expires_at": fmt_unix(lease.expires_at) })));
        self.log(activity::approved(p, Some(&RequestResult::Ssh(result)), self.generation_now()));
        self.notify_request_ended();
        Ok(())
    }

    // ---- extensions ----

    pub(super) fn create_ssh_extend(&self, host: &HostRecord, agent: &str, address: &str, body: RequestBody)
        -> Result<RequestState>
    {
        let RequestBody::SshExtend { lease_id, reason, .. } = body else {
            return Err(CoreError::internal("not an SSH extension request"));
        };
        let reason = validate_reason(&reason)?;
        let now = self.generation_now();
        let lease = self.store.get_ssh_lease(&lease_id)?
            .filter(|l| l.host_id == host.id && l.is_active(now))
            .ok_or_else(|| CoreError::not_found(
                format!("no active SSH lease {lease_id}; request a new one with asm ssh request")))?;
        let names = lease.grant.targets.iter().map(|t| t.name.clone()).collect();
        let pending = self.new_pending(host, agent, address, Detail::SshExtend(SshExtendDetail {
            lease_id: lease_id.clone(), reason, names,
        }));
        let agent = agent.to_owned();
        self.push_pending(pending, move |q| q.agent == agent
            && matches!(&q.detail, Detail::SshExtend(e) if e.lease_id == lease_id))
    }

    pub(super) fn ssh_extend_approval_detail(&self, d: &SshExtendDetail, default_duration: Option<u64>)
        -> ffi::RequestDetail
    {
        let now = self.generation_now();
        let lease = self.store.get_ssh_lease(&d.lease_id).ok().flatten();
        let targets: Vec<ffi::SshExtendTarget> = lease.iter().flat_map(|l| &l.grant.targets).map(|t| ffi::SshExtendTarget {
            target: self.ssh_approval_target(&t.target_id, &t.name, t.revision),
            access: t.access.into(),
            grants: t.grants.clone(),
            user: t.user.clone(),
        }).collect();
        let (default_duration_secs, max_duration_secs) =
            Self::ssh_durations(targets.iter().map(|t| &t.target), default_duration);
        let active = lease.as_ref().is_some_and(|l| l.is_active(now));
        ffi::RequestDetail::SshExtend {
            lease_id: d.lease_id.clone(),
            reason: d.reason.clone(),
            targets,
            expires_at: super::to_system_time(lease.as_ref().map_or(now, |l| l.expires_at)),
            issue: (!active).then(|| "the lease has ended".to_owned()),
            default_duration_secs,
            max_duration_secs,
        }
    }

    pub(super) fn approve_ssh_extend(&self, p: &Pending, d: &SshExtendDetail, duration_secs: u64)
        -> std::result::Result<(), Fail>
    {
        let (lease, from, result) = {
            let _authority = lock(&self.authorization);
            let now = self.generation_now();
            let ended = || Fail::Deny("the SSH lease ended before the extension was approved".into());
            let lease = self.store.get_ssh_lease(&d.lease_id)?
                .filter(|l| Some(&l.host_id) == p.host_id.as_ref() && l.is_active(now))
                .ok_or_else(ended)?;
            let mut max = u64::MAX;
            for t in &lease.grant.targets {
                let changed = || Fail::Deny(format!("SSH target {} changed; request a new lease", t.name));
                let target = self.store.get_ssh_target(&t.target_id)?.ok_or_else(changed)?;
                if target.revision != t.revision || !self.ssh_target_ready(&target)?
                    || target_refusal(&target, t.access, &t.grants, t.user.as_deref()).is_err()
                {
                    return Err(changed());
                }
                max = max.min(target.config.max_duration_secs);
            }
            if duration_secs < 60 || duration_secs > max {
                return Err(CoreError::invalid(format!("choose a duration between 1 minute and {} minutes", max / 60)).into());
            }
            let expires_at = now.saturating_add(duration_secs as i64);
            if expires_at <= lease.expires_at {
                return Err(CoreError::invalid("the lease already ends later; choose a longer duration").into());
            }
            let key = self.ssh_lease_key(&lease.id)?;
            let certificates = lease_certificates(&*self.ssh_ca()?, &key, &lease.id, &lease.grant, now, expires_at)?;
            let from = lease.expires_at;
            let lease = SshLeaseRecord { expires_at, certificates, ..lease };
            let result = ssh_result(&lease);
            let mut state = p.state_for(&p.id, RequestStatus::Approved);
            state.result = Some(RequestResult::Ssh(result.clone()));
            let done = Done { host_id: lease.host_id.clone(), state, at: now, generated: None };
            let sealed_done = self.seal_done(&p.id, &done)?;
            let history = p.history(RequestStatus::Approved, None, now);
            self.complete_pending_locked(&mut lock(&self.book), done, [sealed_done], |rows|
                self.store.extend_ssh_lease_with_request(&lease.id, from, expires_at, &lease.certificates, rows,
                    &history))?;
            (lease, from, result)
        };
        self.lease_wake.notify_one();
        self.notify(TOPIC_LEASES);
        self.log(ssh_event("lease_extended", format!("SSH lease on {} extended to {}", lease_names(&lease),
            fmt_unix(lease.expires_at)))
            .host(Some(&lease.host_id))
            .detail(json!({ "lease_id": lease.id, "from": fmt_unix(from), "to": fmt_unix(lease.expires_at),
                "targets": lease_targets_detail(&lease.grant) })));
        self.log(activity::approved(p, Some(&RequestResult::Ssh(result)), self.generation_now()));
        self.notify_request_ended();
        Ok(())
    }

    // ---- signing ----

    pub fn ssh_sign(&self, host: &HostRecord, token_hash: &[u8; 32], req: SshSignRequest) -> Result<SshSignResponse> {
        let now = self.generation_now();
        let outcome = {
            let _authority = lock(&self.authorization);
            self.ssh_sign_locked(host, token_hash, &req, now)
        };
        match outcome {
            Ok((response, event)) => {
                self.log(event);
                Ok(response)
            }
            Err(SignRefusal { error, event }) => {
                if let Some((lease_id, event)) = event.map(|e| *e) {
                    let mut refused = lock(&self.ssh.refused_at);
                    refused.retain(|_, at| now - *at < SIGN_WINDOW);
                    if let std::collections::hash_map::Entry::Vacant(entry) = refused.entry(lease_id) {
                        entry.insert(now);
                        drop(refused);
                        self.log(event);
                    }
                }
                Err(error)
            }
        }
    }

    /// The signature and its event; the caller holds authorization.
    fn ssh_sign_locked(&self, host: &HostRecord, token_hash: &[u8; 32], req: &SshSignRequest, now: i64)
        -> std::result::Result<(SshSignResponse, Event), SignRefusal>
    {
        if self.store.host_by_token(token_hash)?.is_none_or(|h| h.id != host.id) {
            return Err(CoreError::unauthorized("token rejected; run asm pair").into());
        }
        let lease = self.store.get_ssh_lease(&req.lease_id)?
            .filter(|l| l.host_id == host.id)
            .ok_or_else(|| CoreError::not_found("no such SSH lease"))?;
        if !lease.is_active(now) {
            return Err(CoreError::not_found("SSH lease has ended").into());
        }
        {
            let mut windows = lock(&self.ssh.sign_window);
            windows.retain(|_, (start, _)| now - *start < SIGN_WINDOW);
            let (_, count) = windows.entry(lease.id.clone()).or_insert((now, 0));
            if *count >= SIGN_LIMIT {
                return Err(CoreError::rate_limited("too many SSH sign requests for this lease; wait a minute").into());
            }
            *count += 1;
        }
        let data = b64_decode(&req.data).ok_or_else(|| CoreError::invalid("invalid sign data"))?;
        if data.len() > MAX_SIGN_DATA {
            return Err(CoreError::invalid("sign data is too large").into());
        }
        let refuse = |why: &str| SignRefusal {
            error: CoreError::invalid(why.to_owned()),
            event: Some(Box::new((lease.id.clone(), ssh_event("sign_refused",
                format!("SSH signature refused for {}: {why}", lease_names(&lease)))
                .host(Some(&host.id))
                .detail(json!({ "lease_id": lease.id, "message": why }))))),
        };
        let auth = parse_userauth(&data).map_err(refuse)?;
        if auth.alg != CERT_TYPE {
            return Err(refuse("unexpected key algorithm"));
        }
        let target = lease.grant.targets.iter()
            .find(|t| lease.certificates.get(&t.target_id).and_then(|c| certificate_blob(c)).as_deref() == Some(auth.key_blob))
            .ok_or_else(|| refuse("the request is not for this lease's certificate"))?;
        if target.login != auth.user {
            return Err(refuse(&format!("login {} is not part of this lease", auth.user)));
        }
        if self.store.get_ssh_target(&target.target_id)?.is_none_or(|t| t.revision != target.revision) {
            return Err(refuse("the SSH target changed; request a new lease"));
        }
        if let Some(host_key) = auth.host_key
            && !target.host_keys.iter().any(|k| host_key_blob(k).as_deref() == Some(host_key))
        {
            return Err(refuse("the request is for a host this lease does not pin"));
        }
        let key = self.ssh_lease_key(&lease.id)?;
        let signature = key.sign_blob(&data);
        let event = ssh_event("signed", format!("SSH signature for {} on {}", auth.user, target.name))
            .host(Some(&host.id))
            .detail(json!({ "lease_id": lease.id, "target_id": target.target_id, "login": auth.user }));
        Ok((SshSignResponse { signature: b64_encode(&signature) }, event))
    }

    fn ssh_lease_key(&self, id: &str) -> Result<Arc<SshKey>> {
        if let Some(key) = lock(&self.ssh.keys).get(id) {
            return Ok(key.clone());
        }
        let saved = self.resume.get::<SavedSeed>(KEY_NAMESPACE, id)?
            .ok_or_else(|| CoreError::vault_unavailable("SSH lease key is unavailable"))?;
        let key = Arc::new(SshKey::from_seed_b64(&saved.seed)?);
        lock(&self.ssh.keys).insert(id.to_owned(), key.clone());
        Ok(key)
    }

    // ---- ending leases ----

    /// End one SSH lease (the caller holds authorization). Returns false when it had
    /// already ended. `reason` `expired` records an expiry, anything else a revocation.
    pub(crate) fn end_ssh_lease_locked(&self, id: &str, reason: &str, _authority: &MutexGuard<'_, ()>) -> Result<bool> {
        let Some(lease) = self.store.get_ssh_lease(id)? else { return Ok(false) };
        let now = self.generation_now();
        let cleanup: BTreeMap<String, SshCleanup> = lease.grant.targets.iter()
            .map(|t| (t.target_id.clone(), SshCleanup::new(SshCleanupState::Pending, now, String::new(), 0, 0)))
            .collect();
        let expired = reason == "expired";
        if !self.store.end_ssh_lease(id, (!expired).then_some(now), now, &cleanup)? {
            return Ok(false);
        }
        lock(&self.ssh.keys).remove(id);
        if let Err(error) = self.resume.remove(KEY_NAMESPACE, id) {
            log::error!("removing SSH lease key: {}", error.message);
        }
        let (kind, summary) = if expired {
            ("lease_expired", format!("SSH lease on {} expired", lease_names(&lease)))
        } else {
            ("lease_revoked", format!("SSH lease on {} revoked: {reason}", lease_names(&lease)))
        };
        self.log(ssh_event(kind, summary).host(Some(&lease.host_id))
            .detail(json!({ "lease_id": lease.id, "reason": reason })));
        Ok(true)
    }

    /// Operator revocation of an SSH lease; `Ok(false)` when `id` is not one.
    pub(crate) fn revoke_ssh_lease(&self, id: &str) -> Result<bool> {
        if self.store.get_ssh_lease(id)?.is_none() {
            return Ok(false);
        }
        self.end_ssh_lease_locked(id, "operator", &lock(&self.authorization))?;
        self.kick_ssh_cleanup();
        self.notify(TOPIC_LEASES);
        Ok(true)
    }

    /// End every active SSH lease of a revoked host (the caller holds authorization).
    pub(crate) fn end_host_ssh_leases_locked(&self, host_id: &str, authority: &MutexGuard<'_, ()>) -> Result<bool> {
        let now = self.generation_now();
        let mut ended = false;
        for lease in self.store.ssh_leases_of_host(host_id)? {
            if lease.is_active(now) {
                ended |= self.end_ssh_lease_locked(&lease.id, "host revoked", authority)?;
            }
        }
        Ok(ended)
    }

    pub(crate) fn sweep_ssh_at(&self, now: i64) {
        let ended = (|| -> Result<bool> {
            let authority = lock(&self.authorization);
            let mut ended = false;
            for lease in self.store.ssh_leases_expiring(now)? {
                ended |= self.end_ssh_lease_locked(&lease.id, "expired", &authority)?;
            }
            Ok(ended)
        })();
        match ended {
            Ok(true) => self.notify(TOPIC_LEASES),
            Ok(false) => {}
            Err(error) => log::error!("expiring SSH leases: {}", error.message),
        }
        self.kick_ssh_cleanup();
    }

    /// The earliest active lease expiry or cleanup retry after `now`.
    pub(crate) fn next_ssh_wake(&self, now: i64) -> Option<i64> {
        let expiries = self.store.active_ssh_leases(now).ok()?.into_iter().map(|l| l.expires_at);
        let retries: Vec<i64> = self.store.ssh_leases_needing_cleanup().unwrap_or_default().into_iter()
            .flat_map(|l| l.cleanup.into_values())
            .filter(|c| c.state == SshCleanupState::Pending && c.due > now)
            .map(|c| c.due)
            .collect();
        expiries.chain(retries).min()
    }

    pub fn retry_ssh_cleanup(&self, lease_id: &str) -> Result<()> {
        {
            let _authority = lock(&self.authorization);
            let mut lease = self.store.get_ssh_lease(lease_id)?.ok_or_else(|| CoreError::not_found("no such SSH lease"))?;
            let now = self.generation_now();
            let mut changed = false;
            for entry in lease.cleanup.values_mut().filter(|c| c.state == SshCleanupState::Failed) {
                *entry = SshCleanup::new(SshCleanupState::Pending, now, String::new(), 0, 0);
                changed = true;
            }
            if !changed {
                return Err(CoreError::invalid("no failed cleanup to retry"));
            }
            self.store.set_ssh_cleanup(lease_id, &lease.cleanup)?;
        }
        self.notify(TOPIC_LEASES);
        self.kick_ssh_cleanup();
        Ok(())
    }

    /// Per target id, the ids of leases whose cleanup there is due at `now`.
    fn ssh_cleanup_work(&self, now: i64) -> BTreeMap<String, Vec<String>> {
        let mut work: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for lease in self.store.ssh_leases_needing_cleanup().unwrap_or_default() {
            for (target_id, entry) in &lease.cleanup {
                if entry.state == SshCleanupState::Pending && entry.due <= now {
                    work.entry(target_id.clone()).or_default().push(lease.id.clone());
                }
            }
        }
        work
    }

    /// Start one cleanup thread per target with due work and no running operation.
    pub(crate) fn kick_ssh_cleanup(&self) {
        if self.ssh.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Some(core) = self.ssh.core.get().and_then(Weak::upgrade) else { return };
        for target_id in self.ssh_cleanup_work(self.generation_now()).into_keys() {
            if lock(&self.ssh.busy).contains(&target_id) {
                continue;
            }
            let core = core.clone();
            let spawned = std::thread::Builder::new().name("asm-ssh-cleanup".into())
                .spawn(move || core.run_target_cleanup(&target_id));
            if let Err(error) = spawned {
                log::error!("starting SSH cleanup: {error}");
            }
        }
    }

    /// Run every due cleanup of one target, one at a time.
    fn run_target_cleanup(&self, target_id: &str) {
        let Ok(busy) = self.claim_ssh_target(target_id) else { return };
        let mut tried = HashSet::new();
        while !self.ssh.stopping.load(Ordering::SeqCst) {
            let due = self.ssh_cleanup_work(self.generation_now()).remove(target_id).unwrap_or_default();
            let Some(lease_id) = due.into_iter().find(|id| !tried.contains(id)) else { break };
            self.cleanup_ssh_target(&lease_id, target_id);
            tried.insert(lease_id);
        }
        drop(busy);
        self.kick_ssh_cleanup();
    }

    /// End one lease's sessions on one target (already claimed) and record the outcome
    /// if the entry is still pending.
    fn cleanup_ssh_target(&self, lease_id: &str, target_id: &str) {
        let now = self.generation_now();
        let Ok(Some(lease)) = self.store.get_ssh_lease(lease_id) else { return };
        let Some(previous) = lease.cleanup.get(target_id).cloned() else { return };
        if previous.state != SshCleanupState::Pending || previous.due > now {
            return;
        }
        let name = lease.grant.targets.iter().find(|t| t.target_id == target_id)
            .map_or_else(|| target_id.to_owned(), |t| t.name.clone());
        let outcome = match self.store.get_ssh_target(target_id) {
            Ok(Some(target)) => cleanup_stdin(&lease.id, lease.expires_at)
                .map_err(|e| RemoteError::Local(e.message))
                .and_then(|stdin| self.certificate_run(&target, CertRole::Cleanup, &self.cert_run(), &stdin))
                .and_then(|out| self.track_host_key(&target, end_report(&target, out))),
            Ok(None) => Err(RemoteError::Local("the target was removed from asm".into())),
            Err(error) => Err(RemoteError::Local(error.message)),
        };
        let now = self.generation_now();
        let next = match outcome {
            Ok(report) => SshCleanup {
                changes: report.changes,
                changes_total: report.changes_total,
                ..SshCleanup::new(SshCleanupState::Done, now, format!("host reported: ended {} sessions", report.sessions),
                    previous.attempts, 0)
            },
            Err(e) if e.is_transient() && lease.ended_at.is_some_and(|ended| now > ended + RETRY_FOR_SECS) => {
                SshCleanup::new(SshCleanupState::Failed, now, format!("could not reach the host for 24 hours: {e}"),
                    previous.attempts + 1, 0)
            }
            Err(e) if e.is_transient() => {
                let attempts = previous.attempts + 1;
                let backoff = 60i64.saturating_mul(1i64 << (attempts - 1).min(20)).min(RETRY_MAX_SECS);
                SshCleanup::new(SshCleanupState::Pending, now, e.to_string(), attempts, now + backoff)
            }
            Err(e) => SshCleanup::new(SshCleanupState::Failed, now, e.to_string(), previous.attempts, 0),
        };
        let recorded = (|| -> Result<bool> {
            let _authority = lock(&self.authorization);
            let Some(mut lease) = self.store.get_ssh_lease(lease_id)? else { return Ok(false) };
            match lease.cleanup.get_mut(target_id) {
                Some(entry) if entry.state == SshCleanupState::Pending => *entry = next.clone(),
                _ => return Ok(false),
            }
            self.store.set_ssh_cleanup(lease_id, &lease.cleanup)?;
            Ok(true)
        })();
        match recorded {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                log::error!("recording SSH cleanup: {}", error.message);
                return;
            }
        }
        self.notify(TOPIC_LEASES);
        let event = match next.state {
            SshCleanupState::Done => ssh_event("sessions_ended", format!("SSH lease on {name}: {}", next.detail)),
            SshCleanupState::Pending => ssh_event("cleanup_retrying",
                format!("ending SSH sessions on {name} will be retried: {}", next.detail)),
            SshCleanupState::Failed => ssh_event("cleanup_failed",
                format!("ending SSH sessions on {name} failed: {}", next.detail)),
        };
        self.log(event.host(Some(&lease.host_id)).detail(json!({
            "lease_id": lease.id, "target_id": target_id, "name": name, "state": next.state,
            "attempts": next.attempts, "detail": next.detail,
        })));
        if let Some(first) = next.changes.first() {
            let more = next.changes_total.saturating_sub(1);
            let summary = if more > 0 {
                format!("Files changed on {name} during an SSH lease: {first} and {more} more")
            } else {
                format!("Files changed on {name} during an SSH lease: {first}")
            };
            self.log(ssh_event("files_changed", summary).host(Some(&lease.host_id)).detail(json!({
                "lease_id": lease.id, "target_id": target_id, "name": name, "changes": next.changes,
                "total": next.changes_total,
            })));
        }
    }

    // ---- lease list ----

    pub(crate) fn ssh_lease_infos(&self, names: &mut super::admin::HostNames<'_>) -> Vec<ffi::LeaseInfo> {
        let t = self.generation_now();
        self.store.list_ssh_leases().unwrap_or_default().into_iter().map(|l| {
            let (host_label, hostname) = names.get(&l.host_id).cloned().unwrap_or_default();
            let status = l.status(t);
            ffi::LeaseInfo {
                lease_id: l.id.clone(),
                host_id: l.host_id.clone(),
                host_label,
                hostname,
                vault_id: String::new(),
                vault_name: "SSH".into(),
                name: lease_names(&l),
                mode: ffi::LeaseMode::Raw,
                hosts: Vec::new(),
                fields: Vec::new(),
                reason: l.reason.clone(),
                agent: l.agent.clone(),
                created_at: super::to_system_time(l.created_at),
                expires_at: Some(super::to_system_time(l.expires_at)),
                status: status.into(),
                suspended: false,
                raw_delivered: false,
                source_kind: ffi::SourceKind::Ssh,
                generation: None,
                generator_name: None,
                credential_expires_at: None,
                credential_version: None,
                suspension_reason: None,
                ssh: Some(ffi::SshLeaseDetail {
                    targets: l.grant.targets.iter().map(|target| {
                        let cleanup = l.cleanup.get(&target.target_id);
                        ffi::SshLeaseTarget {
                            name: target.name.clone(),
                            login: target.login.clone(),
                            access: target.access.into(),
                            grants: target.grants.clone(),
                            user: target.user.clone(),
                            cleanup: cleanup.map(Into::into),
                            cleanup_detail: cleanup.map(|c| c.detail.clone()).unwrap_or_default(),
                            changes: cleanup.map(|c| c.changes.clone()).unwrap_or_default(),
                            changes_total: cleanup.map_or(0, |c| c.changes_total),
                        }
                    }).collect(),
                }),
            }
        }).collect()
    }
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;
