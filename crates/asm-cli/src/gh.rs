//! `asm gh`: the GitHub CLI through the manager.
//!
//! `asm gh install` puts a small `gh` script first on `PATH` (default `~/.local/bin/gh`)
//! that runs `asm gh shim`. `asm gh repo add OWNER/REPO` saves the repositories and
//! permissions `gh` may use per owner (one GitHub App installation) in
//! `${XDG_CONFIG_HOME:-~/.config}/asm/gh.json`. For a `gh` command that talks to GitHub,
//! the shim asks the manager for that owner's token and runs the real `gh` with
//! `GH_TOKEN`; `gh auth token` prints the default owner's token (T3 Code reads it).
//!
//! Every request uses the fixed agent label `asm-gh`, the exact saved scope, and neither
//! broader-lease reuse nor operator edits, so the manager either renews the lease it
//! approved for exactly that scope or asks the operator again. Tokens are cached in
//! `$XDG_RUNTIME_DIR/asm/gh/` (tmpfs only) and rechecked with the manager after a minute.

use crate::api::Api;
use crate::bindings::{self, GetCapabilities};
use crate::error::CliError;
use crate::files::{ensure_private_dir, lock_file, write_exec_atomic, write_file_atomic};
use crate::requests::{self, unix_now};
use crate::state;
use asm_proto::crypto::sha256_hex;
use asm_proto::error::{EXIT_DENIED, EXIT_PENDING};
use asm_proto::generators::{
    GITHUB_TOKEN_NAME, GenerationGrant, GenerationRequest, GithubPermission, GithubScopeRequest,
    normalize_repository_name,
};
use asm_proto::wire::{
    CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, GetResult, LeaseInfo,
    LeaseMode, LeaseStatus, LeasesResponse, RequestBody,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Agent label of every `asm gh` request. Without broader reuse the manager reuses only
/// leases approved for this label and exactly the requested scope.
const AGENT: &str = "asm-gh";
/// Start of the installed script; marks a `gh` that `asm gh` may update or remove.
const SHIM_HEAD: &str = "#!/bin/sh\n# asm gh shim ";
const CONFIG_NAME: &str = "gh.json";
const STATE_NAME: &str = "gh-state.json";
const LOCK_NAME: &str = "gh.lock";
/// Read access `repo add` asks for when a new owner gets no `--permissions`.
const DEFAULT_PERMISSIONS: &[&str] = &[
    "actions", "checks", "contents", "issues", "metadata", "pull_requests", "statuses",
];
/// A cached token is used without asking the manager for this long.
const REVALIDATE_SECS: i64 = 60;
/// Never hand out a token with less provider lifetime left: T3 Code keeps a token for
/// five minutes; two more cover clock skew.
const MIN_TOKEN_SECS: i64 = 420;
/// After a denial the shim does not ask again for this long (or until `asm gh repo add`).
const DENIAL_BACKOFF_SECS: i64 = 3600;
/// Budget of callers that must not wait: `gh auth token`, `gh auth status`.
const QUICK_BUDGET: Duration = Duration::from_secs(4);
/// How long other `gh` commands wait for an approval; `ASM_GH_WAIT` overrides.
const DEFAULT_WAIT_SECS: u64 = 120;
/// How long `install` waits for the login shell to report its `gh`.
const LOGIN_SHELL_WAIT: Duration = Duration::from_secs(10);
/// Top-level `gh` commands that never talk to GitHub.
const LOCAL_COMMANDS: &[&str] = &["--version", "version", "help", "completion", "config", "alias"];

#[derive(clap::Subcommand)]
pub enum GhCommand {
    /// Put the asm `gh` shim first on PATH (default ~/.local/bin/gh). It runs the real gh
    /// with a GitHub App token from the manager for the repositories added with
    /// asm gh repo add.
    Install {
        /// Directory for the shim; must come before the real gh on PATH.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        /// Replace a script at DIR/gh that asm did not install, or a symlink there.
        #[arg(long)]
        force: bool,
    },
    /// Choose the repositories gh may use through the manager.
    #[command(subcommand)]
    Repo(RepoCommand),
    /// Show the shim, the configured repositories and their leases (issues no token).
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Remove the shim (if asm installed it), the repository list and cached tokens.
    Uninstall {
        /// Directory the shim was installed in (default ~/.local/bin).
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// What the installed gh script runs.
    #[command(hide = true)]
    Shim {
        #[arg(last = true, value_parser = clap::value_parser!(OsString))]
        args: Vec<OsString>,
    },
}

#[derive(clap::Subcommand)]
pub enum RepoCommand {
    /// Let gh use OWNER/REPO. Asks the operator to approve the owner's repositories and
    /// permissions now; later gh commands renew that grant without asking.
    Add {
        /// OWNER/REPO.
        repo: String,
        /// KEY=LEVEL (read, write or admin), repeat or separate with commas. Applies to
        /// all of the owner's repositories (default for a new owner: actions, checks,
        /// contents, issues, metadata, pull_requests and statuses, all read).
        #[arg(long, value_name = "KEY=LEVEL", value_delimiter = ',')]
        permissions: Vec<String>,
        /// Use this owner for gh auth token and commands that name no repository.
        #[arg(long)]
        default: bool,
        /// Seconds to wait for the operator's decision.
        #[arg(long)]
        wait: Option<u64>,
    },
    /// Stop using OWNER/REPO. The owner's remaining repositories need a new approval on
    /// their next use.
    Remove {
        /// OWNER/REPO.
        repo: String,
    },
}

pub fn run(cmd: GhCommand) -> Result<(), CliError> {
    match cmd {
        GhCommand::Install { dir, force } => install(dir, force),
        GhCommand::Repo(RepoCommand::Add { repo, permissions, default, wait }) => {
            repo_add(&repo, &permissions, default, wait)
        }
        GhCommand::Repo(RepoCommand::Remove { repo }) => repo_remove(&repo),
        GhCommand::Status { json } => status(json),
        GhCommand::Uninstall { dir } => uninstall(dir),
        GhCommand::Shim { args } => shim(args),
    }
}

// ---------------------------------------------------------------------------------------
// Configuration and state

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    /// Owner used by `gh auth token` and by commands that name no repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_owner: Option<String>,
    /// Lowercase owner login → its saved scope.
    #[serde(default)]
    owners: BTreeMap<String, Owner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Owner {
    /// Catalog name requested (`GH_TOKEN`, or a qualified name when names collide).
    source: String,
    /// Lowercase `owner/repo` names, sorted.
    repositories: Vec<String>,
    /// Canonical permissions (with `metadata: read`) for all of them.
    permissions: BTreeMap<String, GithubPermission>,
}

impl Owner {
    fn request(&self) -> Result<GenerationRequest, CliError> {
        let mut request = GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(self.repositories.clone()),
            permissions: Some(self.permissions.clone()),
        });
        request.canonicalize()?;
        Ok(request)
    }

    /// Identifies the approved scope in the token cache and the denial record.
    fn scope_key(&self) -> String {
        let bytes = serde_json::to_vec(&(&self.source, &self.repositories, &self.permissions))
            .expect("scope serializes");
        sha256_hex(bytes)[..16].to_owned()
    }

    fn permissions_text(&self) -> String {
        self.permissions
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str()))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Config {
    /// The configured owner for `user` (case-insensitive), else the default owner, else
    /// the first one; `None` without owners.
    fn owner_for(&self, user: Option<&str>) -> Option<String> {
        if let Some(u) = user.map(str::to_ascii_lowercase).filter(|u| self.owners.contains_key(u)) {
            return Some(u);
        }
        self.default_owner
            .clone()
            .filter(|d| self.owners.contains_key(d))
            .or_else(|| self.owners.keys().next().cloned())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GhState {
    /// Owner → the scope the operator denied and when.
    #[serde(default)]
    denied: BTreeMap<String, Denial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Denial {
    scope: String,
    at: i64,
}

impl GhState {
    /// Seconds until the shim asks again after a denial of exactly `scope`.
    fn backoff_left(&self, owner: &str, scope: &str, now: i64) -> Option<i64> {
        self.denied
            .get(owner)
            .filter(|d| d.scope == scope && d.at <= now)
            .map(|d| d.at + DENIAL_BACKOFF_SECS - now)
            .filter(|left| *left > 0)
    }
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> CliError {
    CliError::failure(format!("{what} {}: {e}", path.display()))
}

fn config_path() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join(CONFIG_NAME))
}

fn load_json<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> Result<T, CliError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| CliError::failure(format!("{} is not valid: {e}", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(io_err("reading", path, e)),
    }
}

fn save_json<T: Serialize>(name: &str, value: &T) -> Result<(), CliError> {
    let dir = state::config_dir()?;
    ensure_private_dir(&dir)?;
    let json = serde_json::to_vec_pretty(value).expect("gh files serialize");
    write_file_atomic(&dir, name, &json).map(|_| ())
}

fn load_config() -> Result<Config, CliError> {
    load_json(&config_path()?)
}

fn load_state() -> GhState {
    state::config_dir()
        .ok()
        .and_then(|d| load_json(&d.join(STATE_NAME)).ok())
        .unwrap_or_default()
}

/// Serializes `repo add`, `repo remove` and `uninstall` (held until dropped).
fn config_lock() -> Result<File, CliError> {
    let dir = state::config_dir()?;
    ensure_private_dir(&dir)?;
    lock_file(&dir, LOCK_NAME, true)
        .map_err(|e| io_err("locking", &dir.join(LOCK_NAME), e))
        .map(|f| f.expect("a blocking lock is always taken"))
}

fn update_state(f: impl FnOnce(&mut GhState)) {
    let mut st = load_state();
    f(&mut st);
    let _ = save_json(STATE_NAME, &st);
}

// ---------------------------------------------------------------------------------------
// Token cache: `$XDG_RUNTIME_DIR/asm/gh/<owner>.json`, tmpfs only

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cached {
    token: String,
    /// Provider expiry of the token (Unix seconds, manager clock).
    expires_at: i64,
    lease_id: String,
    scope: String,
    /// When the manager last confirmed the lease (Unix seconds, local clock).
    checked_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
enum CacheUse {
    /// Confirmed within [`REVALIDATE_SECS`]: use without asking the manager.
    Fresh,
    /// Older: ask the manager; use it only when the manager cannot be reached.
    Fallback,
    Unusable,
}

fn cache_use(c: &Cached, scope: &str, now: i64) -> CacheUse {
    if c.scope != scope || c.expires_at - now <= MIN_TOKEN_SECS {
        CacheUse::Unusable
    } else if (0..REVALIDATE_SECS).contains(&(now - c.checked_at)) {
        CacheUse::Fresh
    } else {
        CacheUse::Fallback
    }
}

struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// The cache directory, created 0700; `None` unless `$XDG_RUNTIME_DIR` is a tmpfs.
    fn open() -> Option<Cache> {
        let dir = cache_dir()?;
        ensure_private_dir(&dir).ok()?;
        Some(Cache { dir })
    }

    fn read(&self, owner: &str) -> Option<Cached> {
        let path = self.dir.join(format!("{owner}.json"));
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .ok()?;
        let meta = f.metadata().ok()?;
        // SAFETY: geteuid has no preconditions.
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return None;
        }
        let mut bytes = Vec::new();
        Read::take(&mut f, 64 * 1024).read_to_end(&mut bytes).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn write(&self, owner: &str, c: &Cached) {
        let json = serde_json::to_vec(c).expect("cache entry serializes");
        let _ = write_file_atomic(&self.dir, &format!("{owner}.json"), &json);
    }

    fn remove(&self, owner: &str) {
        let _ = fs::remove_file(self.dir.join(format!("{owner}.json")));
    }
}

fn cache_dir() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())?;
    is_tmpfs(&runtime).then(|| runtime.join("asm").join("gh"))
}

#[cfg(target_os = "linux")]
fn is_tmpfs(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: statfs writes into the zeroed struct we own; `c` is NUL-terminated.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statfs(c.as_ptr(), &mut s) == 0 && s.f_type as i64 == libc::TMPFS_MAGIC as i64 }
}

#[cfg(not(target_os = "linux"))]
fn is_tmpfs(_: &Path) -> bool {
    false
}

/// Remove an owner's cached token (when a cache exists).
fn forget_token(owner: &str) {
    if let Some(dir) = cache_dir() {
        let _ = fs::remove_file(dir.join(format!("{owner}.json")));
    }
}

// ---------------------------------------------------------------------------------------
// Tokens from the manager

#[derive(Clone, Copy)]
enum Wait {
    /// Never poll a pending request; the whole call stays within [`QUICK_BUDGET`].
    Quick,
    /// Poll a pending request until the deadline (`None`: the manager's request lifetime).
    Until(Option<Instant>),
}

struct Grant {
    token: String,
    expires_at: i64,
    lease_id: String,
    lease_expires_at: Option<String>,
}

fn request_body(owner_key: &str, owner: &Owner) -> Result<RequestBody, CliError> {
    let mut body = RequestBody::Get {
        name: owner.source.clone(),
        raw: true,
        sentinel: false,
        fields: None,
        generation: Some(owner.request()?),
        refresh: false,
        new_lease: false,
        lease_id: None,
        refresh_from_version: None,
        // No broader-lease reuse and no operator edits: the manager either renews the
        // lease approved for exactly this scope and agent, or asks the operator.
        client_capabilities: vec![
            CAPABILITY_GENERATED_CREDENTIALS_V1.to_owned(),
            CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1.to_owned(),
        ],
        hosts: Vec::new(),
        login: None,
        reason: format!("GitHub CLI (asm gh) for {owner_key} repositories"),
        agent: AGENT.to_owned(),
    };
    body.canonicalize()?;
    Ok(body)
}

fn request_token(owner_key: &str, owner: &Owner, wait: Wait) -> Result<Grant, CliError> {
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    let body = request_body(owner_key, owner)?;
    let (deadline, poll) = match wait {
        Wait::Quick => (Some(Instant::now() + QUICK_BUDGET), false),
        Wait::Until(deadline) => (deadline, true),
    };
    let result = requests::submit_get_with(&api, &body, deadline, poll, None, GetCapabilities::default())?;
    grant_from(result, unix_now())
}

/// The token of an exact-scope result. `submit_get_with` already checked that the grant
/// matches the request exactly.
fn grant_from(result: GetResult, now: i64) -> Result<Grant, CliError> {
    let file = match (&result.mode, result.files.as_slice(), &result.generation) {
        (LeaseMode::Raw, [file], Some(selection)) if matches!(selection.grant, GenerationGrant::GithubApp(_)) => file,
        _ => return Err(CliError::failure("the manager sent an unexpected GitHub token result")),
    };
    let expires_at = result
        .credential_expires_at
        .as_deref()
        .and_then(asm_proto::time::parse_unix)
        .ok_or_else(|| CliError::failure("the manager sent no token expiry"))?;
    if expires_at - now <= MIN_TOKEN_SECS {
        return Err(CliError::failure(
            "the manager sent a GitHub token that expires too soon; check the clocks with asm doctor",
        ));
    }
    let token = &file.content;
    if token.is_empty() || token.len() > 16 * 1024 || !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(CliError::failure("the manager sent an invalid GitHub token"));
    }
    Ok(Grant {
        token: token.clone(),
        expires_at,
        lease_id: result.lease_id,
        lease_expires_at: result.expires_at,
    })
}

/// A token for `owner`: from the cache while confirmed recently, else from the manager;
/// a cached token still serves while the manager is unreachable.
fn owner_token(owner_key: &str, owner: &Owner, wait: Wait) -> Result<String, CliError> {
    let now = unix_now();
    let scope = owner.scope_key();
    let cache = Cache::open();
    let cached = cache.as_ref().and_then(|c| c.read(owner_key));
    let usable = match cached.as_ref().map(|c| cache_use(c, &scope, now)) {
        Some(CacheUse::Fresh) => return Ok(cached.expect("present").token),
        Some(CacheUse::Fallback) => cached,
        _ => None,
    };
    if let Some(left) = load_state().backoff_left(owner_key, &scope, now) {
        if let Some(c) = &cache {
            c.remove(owner_key);
        }
        return Err(CliError::new(
            EXIT_DENIED,
            format!(
                "asm gh: the operator denied GitHub access for {owner_key}; gh asks again in {} min, or now after asm gh repo add",
                (left + 59) / 60
            ),
        ));
    }
    let attempt = match wait {
        // Ask without waiting first, so a pending approval is announced before the wait.
        Wait::Until(deadline) => match request_token(owner_key, owner, Wait::Quick) {
            Err(e) if e.exit == EXIT_PENDING && deadline.is_none_or(|d| d > Instant::now()) => {
                let secs = deadline.map(|d| d.saturating_duration_since(Instant::now()).as_secs());
                eprintln!(
                    "asm gh: waiting{} for the operator to approve GitHub access for {owner_key} on the manager",
                    secs.map(|s| format!(" up to {s}s")).unwrap_or_default()
                );
                request_token(owner_key, owner, wait)
            }
            other => other,
        },
        Wait::Quick => request_token(owner_key, owner, wait),
    };
    match attempt {
        Ok(grant) => {
            if let Some(c) = &cache {
                c.write(owner_key, &Cached {
                    token: grant.token.clone(),
                    expires_at: grant.expires_at,
                    lease_id: grant.lease_id,
                    scope,
                    checked_at: now,
                });
            }
            Ok(grant.token)
        }
        Err(e) if e.transient && usable.is_some() => Ok(usable.expect("present").token),
        Err(e) => {
            if let Some(c) = &cache {
                c.remove(owner_key);
            }
            if e.exit == EXIT_DENIED && e.message.starts_with("denied") {
                update_state(|st| {
                    st.denied.insert(owner_key.to_owned(), Denial { scope, at: now });
                });
            }
            Err(e)
        }
    }
}

/// Prefix manager errors for `gh` users.
fn shim_error(owner: &str, e: CliError) -> CliError {
    if e.message.starts_with("asm gh:") {
        return e;
    }
    let message = if e.exit == EXIT_PENDING {
        format!("asm gh: GitHub access for {owner} is waiting for the operator's approval on the manager; run the command again")
    } else {
        format!("asm gh: {}", e.message)
    };
    CliError { message, ..e }
}

// ---------------------------------------------------------------------------------------
// The shim

#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Run the real gh unchanged.
    Pass,
    /// `gh auth token`: print the token of the matching or default owner.
    Token { user: Option<String> },
    /// `gh auth status`: the real gh, with the default owner's token when one is available.
    Status,
    /// Any other command: the real gh with the routed owner's token.
    Run,
}

/// Arguments before a literal `--`.
fn options(args: &[String]) -> &[String] {
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    &args[..end]
}

/// The value of `--NAME VALUE`, `--NAME=VALUE`, `-S VALUE` or `-SVALUE`.
fn flag_value<'a>(args: &'a [String], long: &str, short: Option<&str>) -> Option<&'a str> {
    let mut it = options(args).iter();
    while let Some(a) = it.next() {
        if a == long || short.is_some_and(|s| a == s) {
            return it.next().map(String::as_str);
        }
        if let Some(v) = a.strip_prefix(long).and_then(|r| r.strip_prefix('=')) {
            return Some(v);
        }
        if let Some(v) = short.and_then(|s| a.strip_prefix(s)).filter(|v| !v.is_empty() && !v.starts_with('=')) {
            return Some(v);
        }
    }
    None
}

/// `auth token` flags T3 Code and scripts use; `None` for anything else.
fn token_flags(rest: &[String]) -> Option<Option<String>> {
    let mut user = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
            _ => (a.as_str(), None),
        };
        let value = match inline {
            Some(v) => v,
            None => match name {
                "--hostname" | "-h" | "--user" | "-u" => it.next()?.clone(),
                _ => return None,
            },
        };
        match name {
            "--hostname" | "-h" if value.eq_ignore_ascii_case("github.com") => {}
            "--user" | "-u" => user = Some(value),
            _ => return None,
        }
    }
    Some(user)
}

fn classify(args: &[String], env_token: bool, gh_host: Option<&str>) -> Action {
    if env_token || gh_host.is_some_and(|h| !h.eq_ignore_ascii_case("github.com")) {
        return Action::Pass;
    }
    let Some(command) = args.first() else {
        return Action::Pass;
    };
    if options(args).iter().any(|a| a == "--help")
        || flag_value(args, "--hostname", None).is_some_and(|h| !h.eq_ignore_ascii_case("github.com"))
        || LOCAL_COMMANDS.contains(&command.as_str())
    {
        return Action::Pass;
    }
    if command == "auth" {
        return match args.get(1).map(String::as_str) {
            Some("token") => token_flags(&args[2..]).map_or(Action::Pass, |user| Action::Token { user }),
            Some("status") => Action::Status,
            _ => Action::Pass,
        };
    }
    Action::Run
}

fn valid_login(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// The owner in `OWNER/REPO`, `HOST/OWNER/REPO` (github.com) or a github.com URL.
fn owner_of(spec: &str) -> Option<String> {
    let s = spec.trim();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(s);
    let mut parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 3 || (parts.len() == 2 && parts[0].contains('.')) {
        if !parts[0].eq_ignore_ascii_case("github.com") && !parts[0].eq_ignore_ascii_case("www.github.com") {
            return None;
        }
        parts.remove(0);
    }
    if parts.len() < 2 {
        return None;
    }
    let owner = parts[0];
    valid_login(owner).then(|| owner.to_ascii_lowercase())
}

/// The owner of a git remote URL on github.com.
fn owner_from_git_url(url: &str) -> Option<String> {
    let url = url.trim();
    let path = if let Some(rest) = url.strip_prefix("git@github.com:") {
        rest
    } else if let Some(rest) = url.strip_prefix("ssh://") {
        let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
        let (host, path) = rest.split_once('/')?;
        if !host.split(':').next().is_some_and(|h| h.eq_ignore_ascii_case("github.com")) {
            return None;
        }
        path
    } else {
        let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
        let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
        let (host, path) = rest.split_once('/')?;
        if !host.eq_ignore_ascii_case("github.com") {
            return None;
        }
        path
    };
    let owner = path.split('/').next()?;
    valid_login(owner).then(|| owner.to_ascii_lowercase())
}

/// The owner a command names: `-R/--repo`, `$GH_REPO`, `repo … OWNER[/REPO]`,
/// `api repos|orgs|users/OWNER/…` or a github.com URL argument.
fn named_owner(args: &[String], gh_repo: Option<&str>) -> Option<String> {
    if let Some(spec) = flag_value(args, "--repo", Some("-R")).or(gh_repo) {
        return owner_of(spec);
    }
    let opts = options(args);
    if let Some(url) = opts.iter().find(|a| a.starts_with("https://github.com/")) {
        return owner_of(url);
    }
    match opts.first().map(String::as_str) {
        Some("repo") => {
            let sub = opts.get(1).map(String::as_str);
            let first = opts.get(2).filter(|a| !a.starts_with('-'));
            if sub == Some("list") {
                return first.filter(|a| valid_login(a)).map(|a| a.to_ascii_lowercase());
            }
            opts[2.min(opts.len())..].iter().filter(|a| !a.starts_with('-') && a.contains('/')).find_map(|a| owner_of(a))
        }
        Some("api") => {
            let endpoint = opts[1..].iter().find(|a| !a.starts_with('-'))?;
            let mut segments = endpoint.trim_start_matches('/').split(['/', '?']);
            match segments.next()? {
                "repos" | "orgs" | "users" => segments.next().filter(|o| valid_login(o)).map(str::to_ascii_lowercase),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The owner of this directory's GitHub remote, in gh's order: upstream, github, origin.
fn remote_owner() -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--get-regexp", r"^remote\.(upstream|github|origin)\.url$"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found: Vec<(usize, String)> = text
        .lines()
        .filter_map(|line| {
            let (key, url) = line.split_once(' ')?;
            let rank = ["remote.upstream.url", "remote.github.url", "remote.origin.url"]
                .iter()
                .position(|k| *k == key)?;
            Some((rank, owner_from_git_url(url)?))
        })
        .collect();
    found.sort();
    found.into_iter().next().map(|(_, owner)| owner)
}

/// The configured owner a command uses: the only one, the one it names, the one of this
/// directory's remote, else the default.
fn route(cfg: &Config, args: &[String], gh_repo: Option<&str>, remote: impl FnOnce() -> Option<String>) -> Option<String> {
    if cfg.owners.len() == 1 {
        return cfg.owners.keys().next().cloned();
    }
    named_owner(args, gh_repo)
        .or_else(remote)
        .filter(|o| cfg.owners.contains_key(o))
        .or_else(|| cfg.owner_for(None))
}

/// Whether `path` is a script `asm gh install` wrote.
fn is_shim(path: &Path) -> bool {
    let mut head = vec![0u8; SHIM_HEAD.len()];
    File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok_and(|()| head == SHIM_HEAD.as_bytes())
}

fn shim_script(asm: &Path) -> String {
    format!(
        "{SHIM_HEAD}{VERSION}: runs the GitHub CLI through asm (asm gh status; asm gh uninstall removes it)\nexec {} gh shim -- \"$@\"\n",
        bindings::shell_quote(&asm.to_string_lossy())
    )
}

/// The first executable `gh` on `PATH` that is neither an asm shim nor this program.
fn real_gh() -> Option<PathBuf> {
    let me = std::env::current_exe().ok().and_then(|p| fs::canonicalize(p).ok());
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("gh"))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                && !is_shim(candidate)
                && me.as_ref().is_none_or(|me| fs::canonicalize(candidate).ok().as_ref() != Some(me))
        })
}

/// The first `gh` on `PATH`, whatever it is.
fn first_gh_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("gh"))
        .find(|c| fs::metadata(c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// Replace this process with the real gh (with `GH_TOKEN`/`GITHUB_TOKEN` = `token`).
fn exec_gh(args: &[OsString], token: Option<&str>) -> CliError {
    use std::os::unix::process::CommandExt;
    let Some(real) = real_gh() else {
        return CliError::new(127, "asm gh: no GitHub CLI (gh) on PATH besides the asm gh shim; install gh");
    };
    let mut cmd = Command::new(&real);
    cmd.arg0("gh").args(args);
    if let Some(t) = token {
        cmd.env("GH_TOKEN", t).env("GITHUB_TOKEN", t);
    }
    let error = cmd.exec();
    let code = if error.kind() == ErrorKind::NotFound { 127 } else { 126 };
    CliError::new(code, format!("asm gh: could not run {}: {}", real.display(), error.kind()))
}

fn wait_deadline() -> Wait {
    let secs = std::env::var("ASM_GH_WAIT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_WAIT_SECS);
    if secs == 0 {
        Wait::Quick
    } else {
        Wait::Until(Some(Instant::now() + Duration::from_secs(secs)))
    }
}

fn shim(args: Vec<OsString>) -> Result<(), CliError> {
    let text: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    let env_token = ["GH_TOKEN", "GITHUB_TOKEN"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()));
    let gh_host = std::env::var("GH_HOST").ok().filter(|h| !h.is_empty());
    let action = classify(&text, env_token, gh_host.as_deref());
    if action == Action::Pass {
        return Err(exec_gh(&args, None));
    }
    let cfg = match load_config() {
        Ok(cfg) if !cfg.owners.is_empty() => cfg,
        Ok(_) => return Err(exec_gh(&args, None)),
        Err(e) => {
            eprintln!("asm gh: {}", e.message);
            return Err(exec_gh(&args, None));
        }
    };
    match action {
        Action::Token { user } => {
            let key = cfg.owner_for(user.as_deref()).expect("owners configured");
            let token = owner_token(&key, &cfg.owners[&key], Wait::Quick).map_err(|e| shim_error(&key, e))?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{token}").and_then(|()| out.flush())
                .map_err(|e| CliError::failure(format!("writing the token: {e}")))
        }
        Action::Status => {
            let key = cfg.owner_for(None).expect("owners configured");
            match owner_token(&key, &cfg.owners[&key], Wait::Quick) {
                Ok(token) => Err(exec_gh(&args, Some(&token))),
                Err(e) => {
                    eprintln!("{}", shim_error(&key, e).message);
                    Err(exec_gh(&args, None))
                }
            }
        }
        Action::Run => {
            let gh_repo = std::env::var("GH_REPO").ok().filter(|r| !r.is_empty());
            let key = route(&cfg, &text, gh_repo.as_deref(), remote_owner).expect("owners configured");
            let token = owner_token(&key, &cfg.owners[&key], wait_deadline()).map_err(|e| shim_error(&key, e))?;
            Err(exec_gh(&args, Some(&token)))
        }
        Action::Pass => unreachable!("handled above"),
    }
}

// ---------------------------------------------------------------------------------------
// install / uninstall

fn shim_dir(dir: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let dir = match dir {
        Some(d) => d,
        None => state::home_dir()?.join(".local").join("bin"),
    };
    if dir.is_absolute() {
        return Ok(dir);
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(dir))
        .map_err(|e| CliError::failure(format!("current directory: {e}")))
}

fn is_script(path: &Path) -> bool {
    let mut head = [0u8; 2];
    File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok_and(|()| &head == b"#!")
}

fn install(dir: Option<PathBuf>, force: bool) -> Result<(), CliError> {
    let dir = shim_dir(dir)?;
    let path = dir.join("gh");
    let exe = crate::service::stable_exe()?;
    let script = shim_script(&exe);
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() && is_shim(&path) => {}
        Ok(m) if m.is_file() && !is_script(&path) => {
            return Err(CliError::invalid(format!(
                "{} is a program, not a script asm installed; it may be the GitHub CLI itself. Use --dir with a directory that comes before it on PATH",
                path.display()
            )));
        }
        Ok(_) if force => {}
        Ok(_) => {
            return Err(CliError::invalid(format!(
                "{} exists and was not installed by asm gh; pass --force to replace it",
                path.display()
            )));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("inspecting", &path, e)),
    }
    let unchanged = fs::read_to_string(&path).is_ok_and(|current| current == script);
    if !unchanged {
        fs::create_dir_all(&dir).map_err(|e| io_err("creating", &dir, e))?;
        write_exec_atomic(&path, script.as_bytes())?;
    }
    println!(
        "{}: {} (runs {} gh shim)",
        if unchanged { "up to date" } else { "installed" },
        path.display(),
        exe.display()
    );
    match real_gh() {
        Some(real) => println!("real gh: {}", real.display()),
        None => eprintln!("warning: no GitHub CLI (gh) on PATH besides the shim; install gh"),
    }
    match login_shell_gh() {
        Some(found) if same_file(&found, &path) => {
            println!("login shell: finds the shim first (T3 Code and agents use this PATH)");
        }
        Some(found) => eprintln!(
            "warning: your login shell finds gh at {} before the shim; put {} earlier on PATH",
            found.display(),
            dir.display()
        ),
        None => {}
    }
    if state::load()?.is_none() {
        eprintln!("warning: not paired; run asm pair <manager-host>");
    }
    let cfg = load_config()?;
    if cfg.owners.is_empty() {
        println!("next: asm gh repo add OWNER/REPO");
    } else {
        for (key, owner) in &cfg.owners {
            println!("{key}: {} repositories", owner.repositories.len());
        }
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// What the login shell finds for `gh` (`SHELL -ilc 'command -v gh'`), choosing the shell as
/// T3 Code does: `$SHELL`, else the passwd login shell, else `/bin/bash` (`/bin/zsh` on
/// macOS). `None` without an answer within [`LOGIN_SHELL_WAIT`].
fn login_shell_gh() -> Option<PathBuf> {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| s.starts_with('/'))
        .or_else(crate::hostinfo::passwd_shell)
        .unwrap_or_else(|| if cfg!(target_os = "macos") { "/bin/zsh" } else { "/bin/bash" }.to_owned());
    let mut child = Command::new(shell)
        .args(["-ilc", "command -v gh"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + LOGIN_SHELL_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = reader.join().ok()?;
    out.lines().rev().map(str::trim).find(|l| l.starts_with('/')).map(PathBuf::from)
}

fn uninstall(dir: Option<PathBuf>) -> Result<(), CliError> {
    let dir = shim_dir(dir)?;
    let path = dir.join("gh");
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() && is_shim(&path) => {
            fs::remove_file(&path).map_err(|e| io_err("removing", &path, e))?;
            println!("removed: {}", path.display());
        }
        Ok(_) => println!("left alone (not installed by asm gh): {}", path.display()),
        Err(_) => println!("not installed: {}", path.display()),
    }
    let _lock = config_lock()?;
    let cfg = load_config()?;
    if !cfg.owners.is_empty()
        && let Ok(leases) = manager_leases()
    {
        for (key, owner) in &cfg.owners {
            if let Some(lease) = matching_lease(&leases, owner) {
                println!(
                    "lease {} ({key}) stays active {}; revoke it in the manager if gh should lose access now",
                    lease.lease_id,
                    lease.expires_at.as_deref().map_or("without expiry".to_owned(), |t| format!("until {t}"))
                );
            }
        }
    }
    let config_dir = state::config_dir()?;
    for name in [CONFIG_NAME, STATE_NAME] {
        let p = config_dir.join(name);
        if fs::remove_file(&p).is_ok() {
            println!("removed: {}", p.display());
        }
    }
    if let Some(cache) = cache_dir()
        && let Ok(entries) = fs::read_dir(&cache)
    {
        for e in entries.flatten() {
            let _ = fs::remove_file(e.path());
        }
        let _ = fs::remove_dir(&cache);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// repo add / remove

fn parse_permissions(items: &[String]) -> Result<BTreeMap<String, GithubPermission>, CliError> {
    let mut out = BTreeMap::new();
    for item in items {
        let invalid = || CliError::invalid("permissions must be KEY=read|write|admin");
        let (key, level) = item.trim().split_once('=').ok_or_else(invalid)?;
        let level = match level {
            "read" => GithubPermission::Read,
            "write" => GithubPermission::Write,
            "admin" => GithubPermission::Admin,
            _ => return Err(invalid()),
        };
        if out.insert(key.to_owned(), level).is_some() {
            return Err(CliError::invalid("duplicate permission key"));
        }
    }
    Ok(out)
}

fn default_permissions() -> BTreeMap<String, GithubPermission> {
    DEFAULT_PERMISSIONS.iter().map(|k| ((*k).to_owned(), GithubPermission::Read)).collect()
}

/// The catalog name of the manager's generated GitHub token.
fn github_source(api: &Api) -> Result<String, CliError> {
    let entries = bindings::catalog(api)?;
    let resolved = asm_proto::names::resolve_catalog_name(GITHUB_TOKEN_NAME, &entries)?;
    if resolved.generated_output != Some(GITHUB_TOKEN_NAME) {
        return Err(CliError::invalid(
            "the manager has no GitHub App generator for GH_TOKEN; add one in the manager's Generators settings",
        ));
    }
    Ok(resolved.request_name)
}

fn repo_add(repo: &str, permissions: &[String], make_default: bool, wait: Option<u64>) -> Result<(), CliError> {
    let name = normalize_repository_name(repo)?;
    let key = name.split('/').next().expect("validated owner/repo").to_owned();
    let extra = parse_permissions(permissions)?;
    let _lock = config_lock()?;
    let mut cfg = load_config()?;
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    bindings::require_capabilities(&api, true, false, Some(CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1))?;
    let mut owner = match cfg.owners.get(&key) {
        Some(o) => o.clone(),
        None => Owner {
            source: github_source(&api)?,
            repositories: Vec::new(),
            permissions: default_permissions(),
        },
    };
    if !owner.repositories.contains(&name) {
        owner.repositories.push(name.clone());
        owner.repositories.sort();
    }
    owner.permissions.extend(extra);
    if let GenerationRequest::GithubApp(scope) = owner.request()? {
        owner.permissions = scope.permissions.unwrap_or_default();
    }
    update_state(|st| {
        st.denied.remove(&key);
    });
    eprintln!(
        "asking the manager to approve gh access to {key}: {} ({}); approve it on the Mac",
        owner.repositories.join(", "),
        owner.permissions_text()
    );
    let grant = request_token(&key, &owner, Wait::Until(requests::deadline(wait)))?;
    if let Some(cache) = Cache::open() {
        cache.write(&key, &Cached {
            token: grant.token.clone(),
            expires_at: grant.expires_at,
            lease_id: grant.lease_id.clone(),
            scope: owner.scope_key(),
            checked_at: unix_now(),
        });
    }
    let count = owner.repositories.len();
    cfg.owners.insert(key.clone(), owner);
    if make_default || cfg.default_owner.as_ref().is_none_or(|d| !cfg.owners.contains_key(d)) {
        cfg.default_owner = Some(key.clone());
    }
    save_json(CONFIG_NAME, &cfg)?;
    println!(
        "added {name}: gh uses lease {} for {key} ({count} repositories), approved {}",
        grant.lease_id,
        grant.lease_expires_at.as_deref().map_or("without expiry".to_owned(), |t| format!("until {t}"))
    );
    Ok(())
}

fn repo_remove(repo: &str) -> Result<(), CliError> {
    let name = normalize_repository_name(repo)?;
    let key = name.split('/').next().expect("validated owner/repo").to_owned();
    let _lock = config_lock()?;
    let mut cfg = load_config()?;
    let Some(owner) = cfg.owners.get_mut(&key).filter(|o| o.repositories.contains(&name)) else {
        return Err(CliError::new(5, format!("not found: {name} is not configured for asm gh")));
    };
    owner.repositories.retain(|r| r != &name);
    let remaining = owner.repositories.len();
    if remaining == 0 {
        cfg.owners.remove(&key);
        if cfg.default_owner.as_deref() == Some(key.as_str()) {
            cfg.default_owner = cfg.owners.keys().next().cloned();
        }
    }
    save_json(CONFIG_NAME, &cfg)?;
    forget_token(&key);
    update_state(|st| {
        st.denied.remove(&key);
    });
    if remaining == 0 {
        println!("removed {name}; gh no longer uses a token for {key}");
    } else {
        println!("removed {name}; the next gh command for {key} asks the manager to approve its remaining {remaining} repositories");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// status

fn manager_leases() -> Result<LeasesResponse, CliError> {
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    api.get_until("/leases", Some(Instant::now() + Duration::from_secs(5)))
}

/// The active raw lease whose grant is exactly the owner's saved scope.
fn matching_lease<'a>(leases: &'a LeasesResponse, owner: &Owner) -> Option<&'a LeaseInfo> {
    let request = owner.request().ok()?;
    let now = unix_now();
    leases
        .leases
        .iter()
        .filter(|l| {
            l.status == LeaseStatus::Active
                && l.mode == LeaseMode::Raw
                && l.expires_at.as_deref().is_none_or(|t| asm_proto::time::parse_unix(t).is_some_and(|t| t > now))
                && l.generation.as_ref().is_some_and(|g| g.grant.matches_request_exactly(&request).unwrap_or(false))
        })
        .max_by_key(|l| l.expires_at.as_deref().and_then(asm_proto::time::parse_unix).unwrap_or(i64::MAX))
}

#[derive(Serialize)]
struct OwnerStatus {
    owner: String,
    default: bool,
    repositories: Vec<String>,
    permissions: BTreeMap<String, GithubPermission>,
    /// The approved lease, when the manager could be asked.
    lease_id: Option<String>,
    lease_expires_at: Option<String>,
    token_expires_at: Option<String>,
    cached_token: bool,
    denied_until: Option<String>,
}

#[derive(Serialize)]
struct Status {
    shim: String,
    shim_state: &'static str,
    gh_on_path: Option<String>,
    real_gh: Option<String>,
    manager: Option<String>,
    owners: Vec<OwnerStatus>,
}

fn shim_state(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && is_shim(path) => {
            let current = crate::service::stable_exe().ok().map(|exe| shim_script(&exe));
            if fs::read_to_string(path).ok() == current { "installed" } else { "outdated" }
        }
        Ok(_) => "foreign",
        Err(_) => "missing",
    }
}

fn status(json: bool) -> Result<(), CliError> {
    let path = shim_dir(None)?.join("gh");
    let cfg = load_config()?;
    let leases = if cfg.owners.is_empty() { None } else { Some(manager_leases()) };
    let manager_error = match &leases {
        Some(Err(e)) => Some(e.message.clone()),
        _ => None,
    };
    let now = unix_now();
    let st = load_state();
    let cache = cache_dir().map(|dir| Cache { dir });
    let default = cfg.owner_for(None);
    let owners = cfg
        .owners
        .iter()
        .map(|(key, owner)| {
            let lease = match &leases {
                Some(Ok(l)) => matching_lease(l, owner),
                _ => None,
            };
            let scope = owner.scope_key();
            OwnerStatus {
                owner: key.clone(),
                default: default.as_deref() == Some(key.as_str()),
                repositories: owner.repositories.clone(),
                permissions: owner.permissions.clone(),
                lease_id: lease.map(|l| l.lease_id.clone()),
                lease_expires_at: lease.and_then(|l| l.expires_at.clone()),
                token_expires_at: lease.and_then(|l| l.credential_expires_at.clone()),
                cached_token: cache
                    .as_ref()
                    .and_then(|c| c.read(key))
                    .is_some_and(|c| cache_use(&c, &scope, now) != CacheUse::Unusable),
                denied_until: st
                    .backoff_left(key, &scope, now)
                    .map(|left| asm_proto::time::fmt_unix(now + left)),
            }
        })
        .collect::<Vec<_>>();
    let report = Status {
        shim: path.display().to_string(),
        shim_state: shim_state(&path),
        gh_on_path: first_gh_on_path().map(|p| p.display().to_string()),
        real_gh: real_gh().map(|p| p.display().to_string()),
        manager: manager_error,
        owners,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report).expect("status serializes"));
        return Ok(());
    }
    let fix = match report.shim_state {
        "installed" => String::new(),
        "foreign" => " (not installed by asm gh; asm gh install --force replaces it)".to_owned(),
        _ => " — fix: asm gh install".to_owned(),
    };
    println!("shim: {} {}{fix}", report.shim, report.shim_state);
    match &report.gh_on_path {
        Some(p) if same_file(Path::new(p), &path) => println!("gh on PATH: {p} (the shim)"),
        Some(p) => println!("gh on PATH: {p} (not the shim; gh commands bypass asm here)"),
        None => println!("gh on PATH: none"),
    }
    println!("real gh: {}", report.real_gh.as_deref().unwrap_or("none; install the GitHub CLI"));
    if let Some(e) = &report.manager {
        println!("manager: {e}");
    }
    if report.owners.is_empty() {
        println!("repositories: none; add one with asm gh repo add OWNER/REPO");
    }
    for o in &report.owners {
        let perms = o.permissions.iter().map(|(k, v)| format!("{k}={}", v.as_str())).collect::<Vec<_>>().join(",");
        println!("{}{}: {} ({perms})", o.owner, if o.default { " (default)" } else { "" }, o.repositories.join(", "));
        if let Some(until) = &o.denied_until {
            println!("  denied by the operator; gh asks again after {until} or after asm gh repo add");
        } else if let Some(id) = &o.lease_id {
            println!(
                "  lease {id}, approved until {}, token until {}{}",
                o.lease_expires_at.as_deref().unwrap_or("revoked"),
                o.token_expires_at.as_deref().unwrap_or("unknown"),
                if o.cached_token { " (cached)" } else { "" }
            );
        } else if report.manager.is_none() {
            println!("  no active lease; the next gh command asks the operator to approve it");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn owner(repos: &[&str]) -> Owner {
        Owner {
            source: "GH_TOKEN".into(),
            repositories: repos.iter().map(|r| (*r).to_owned()).collect(),
            permissions: default_permissions(),
        }
    }

    fn config(owners: &[&str], default: Option<&str>) -> Config {
        Config {
            default_owner: default.map(str::to_owned),
            owners: owners.iter().map(|o| ((*o).to_owned(), owner(&[&format!("{o}/repo")]))).collect(),
        }
    }

    #[test]
    fn classify_routes_only_github_commands_to_tokens() {
        let token = |user: Option<&str>| Action::Token { user: user.map(str::to_owned) };
        for (line, want) in [
            ("auth token --hostname github.com", token(None)),
            ("auth token -h github.com --user AnswerShiftAI", token(Some("AnswerShiftAI"))),
            ("auth token --hostname=github.com --user=x", token(Some("x"))),
            ("auth token", token(None)),
            ("auth token --hostname ghe.example.com", Action::Pass),
            ("auth token --secure-storage", Action::Pass),
            ("auth status --json hosts", Action::Status),
            ("auth login", Action::Pass),
            ("auth git-credential get", Action::Pass),
            ("--version", Action::Pass),
            ("version", Action::Pass),
            ("config get http_unix_socket", Action::Pass),
            ("completion -s bash", Action::Pass),
            ("pr list --help", Action::Pass),
            ("pr list -R acme/web", Action::Run),
            ("api repos/acme/web --hostname ghe.example.com", Action::Pass),
            ("repo list acme", Action::Run),
            ("", Action::Pass),
        ] {
            assert_eq!(classify(&args(line), false, None), want, "{line}");
        }
        assert_eq!(classify(&args("pr list"), true, None), Action::Pass, "GH_TOKEN set");
        assert_eq!(classify(&args("auth token"), true, None), Action::Pass, "GH_TOKEN set");
        assert_eq!(classify(&args("pr list"), false, Some("ghe.example.com")), Action::Pass);
        assert_eq!(classify(&args("pr list"), false, Some("github.com")), Action::Run);
    }

    #[test]
    fn named_owner_reads_flags_environment_positionals_and_urls() {
        for (line, repo_env, want) in [
            ("pr list -R AnswerShiftAI/platform", None, Some("answershiftai")),
            ("pr list --repo=acme/web", None, Some("acme")),
            ("pr list -Racme/web", None, Some("acme")),
            ("pr list --repo github.com/acme/web", None, Some("acme")),
            ("pr list --repo ghe.example.com/acme/web", None, None),
            ("pr list", Some("acme/web"), Some("acme")),
            ("repo list Org", None, Some("org")),
            ("repo list --limit 5", None, None),
            ("repo view acme/web --json name", None, Some("acme")),
            ("api /repos/acme/web/pulls", None, Some("acme")),
            ("api orgs/acme/repos", None, Some("acme")),
            ("api graphql -f query=x", None, None),
            ("pr view https://github.com/acme/web/pull/1", None, Some("acme")),
            ("pr view 616", None, None),
        ] {
            assert_eq!(named_owner(&args(line), repo_env).as_deref(), want, "{line}");
        }
    }

    #[test]
    fn git_remote_urls() {
        for (url, want) in [
            ("https://github.com/AnswerShiftAI/platform.git", Some("answershiftai")),
            ("https://user@github.com/acme/web", Some("acme")),
            ("git@github.com:acme/web.git", Some("acme")),
            ("ssh://git@github.com/acme/web.git", Some("acme")),
            ("ssh://git@github.com:22/acme/web.git", Some("acme")),
            ("https://gitlab.com/acme/web.git", None),
            ("git@example.com:acme/web.git", None),
        ] {
            assert_eq!(owner_from_git_url(url).as_deref(), want, "{url}");
        }
    }

    #[test]
    fn route_prefers_the_named_owner_then_the_remote_then_the_default() {
        let cfg = config(&["acme", "other"], Some("other"));
        let none = || None::<String>;
        assert_eq!(route(&cfg, &args("pr list -R acme/web"), None, none).as_deref(), Some("acme"));
        assert_eq!(route(&cfg, &args("pr list"), None, || Some("acme".into())).as_deref(), Some("acme"));
        assert_eq!(route(&cfg, &args("pr list"), None, none).as_deref(), Some("other"));
        // An owner that is not configured falls back to the default.
        assert_eq!(route(&cfg, &args("repo list stranger"), None, none).as_deref(), Some("other"));
        // A single owner is used without inspecting the command or the remote.
        let single = config(&["acme"], None);
        assert_eq!(route(&single, &args("repo list stranger"), None, || panic!("no remote lookup")).as_deref(), Some("acme"));
        assert_eq!(route(&Config::default(), &args("pr list"), None, none), None);
    }

    #[test]
    fn owner_for_matches_user_case_insensitively_else_default_else_first() {
        let cfg = config(&["acme", "other"], Some("other"));
        assert_eq!(cfg.owner_for(Some("ACME")).as_deref(), Some("acme"));
        assert_eq!(cfg.owner_for(Some("bot[bot]")).as_deref(), Some("other"));
        let no_default = config(&["acme", "other"], Some("gone"));
        assert_eq!(no_default.owner_for(None).as_deref(), Some("acme"));
    }

    #[test]
    fn scope_key_changes_with_repositories_and_permissions() {
        let a = owner(&["acme/web"]);
        let mut b = owner(&["acme/api", "acme/web"]);
        assert_ne!(a.scope_key(), b.scope_key());
        b.repositories = a.repositories.clone();
        assert_eq!(a.scope_key(), b.scope_key());
        b.permissions.insert("pull_requests".into(), GithubPermission::Write);
        assert_ne!(a.scope_key(), b.scope_key());
    }

    #[test]
    fn cache_entries_are_fresh_for_a_minute_and_need_token_headroom() {
        let c = Cached { token: "t".into(), expires_at: 10_000, lease_id: "l".into(), scope: "s".into(), checked_at: 1_000 };
        assert_eq!(cache_use(&c, "s", 1_000), CacheUse::Fresh);
        assert_eq!(cache_use(&c, "s", 1_059), CacheUse::Fresh);
        assert_eq!(cache_use(&c, "s", 1_060), CacheUse::Fallback);
        // A clock that went backwards does not make an entry fresh.
        assert_eq!(cache_use(&c, "s", 999), CacheUse::Fallback);
        assert_eq!(cache_use(&c, "other", 1_000), CacheUse::Unusable);
        assert_eq!(cache_use(&c, "s", 10_000 - MIN_TOKEN_SECS), CacheUse::Unusable);
        assert_eq!(cache_use(&c, "s", 10_000 - MIN_TOKEN_SECS - 1), CacheUse::Fallback);
    }

    #[test]
    fn denial_backs_off_for_the_denied_scope_only() {
        let mut st = GhState::default();
        st.denied.insert("acme".into(), Denial { scope: "s".into(), at: 1_000 });
        assert_eq!(st.backoff_left("acme", "s", 1_000), Some(DENIAL_BACKOFF_SECS));
        assert_eq!(st.backoff_left("acme", "s", 1_000 + DENIAL_BACKOFF_SECS), None);
        assert_eq!(st.backoff_left("acme", "changed", 1_000), None);
        assert_eq!(st.backoff_left("other", "s", 1_000), None);
    }

    #[test]
    fn shim_script_is_recognized_and_quotes_the_asm_path() {
        let dir = tempfile::tempdir().unwrap();
        let script = shim_script(Path::new("/opt/it's/asm"));
        assert!(script.starts_with(SHIM_HEAD));
        assert!(script.contains("exec '/opt/it'\\''s/asm' gh shim -- \"$@\"\n"));
        let path = dir.path().join("gh");
        fs::write(&path, &script).unwrap();
        assert!(is_shim(&path));
        fs::write(&path, "#!/bin/sh\nexec /usr/bin/gh \"$@\"\n").unwrap();
        assert!(!is_shim(&path));
    }

    #[test]
    fn permissions_parse_and_merge_into_canonical_scope() {
        assert!(parse_permissions(&["contents=maybe".into()]).is_err());
        assert!(parse_permissions(&["contents=read".into(), "contents=write".into()]).is_err());
        let mut o = owner(&["acme/web"]);
        o.permissions = parse_permissions(&["pull_requests=write".into()]).unwrap();
        let GenerationRequest::GithubApp(scope) = o.request().unwrap() else { unreachable!() };
        let perms = scope.permissions.unwrap();
        assert_eq!(perms.get("metadata"), Some(&GithubPermission::Read));
        assert_eq!(perms.get("pull_requests"), Some(&GithubPermission::Write));
    }
}
