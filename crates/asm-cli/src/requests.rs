//! `asm list`, `get`, `update`, `add`: listing secrets and the request/approval flow.

use crate::api::Api;
use crate::error::{CliError, RERUN_TO_PICK_UP};
use crate::files::SecretsDir;
use crate::state::{self, HostState};
use asm_proto::error::ErrorCode;
use asm_proto::wire::{
    GetResult, LeaseMode, LeaseStatus, LeasesResponse, MAX_POLL_WAIT_SECS, RequestBody,
    RequestResult, RequestState, RequestStatus, SecretsResponse, WriteResult,
};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A paired session: host state, API client, and (when usable) the secrets directory
/// after the expiry cleanup every command except `pair` performs.
pub struct Session {
    pub host: HostState,
    pub api: Api,
    pub secrets: Result<SecretsDir, CliError>,
}

impl Session {
    /// Load `host.json` and delete the files of leases past expiry.
    pub fn open() -> Result<Self, CliError> {
        let host = state::require()?;
        let api = Api::for_host(&host)?;
        let secrets = SecretsDir::open_default().and_then(|d| d.remove_expired().map(|()| d));
        Ok(Session { host, api, secrets })
    }

    /// The secrets directory, or its error (fatal for `get`).
    pub fn secrets_dir(&self) -> Result<&SecretsDir, CliError> {
        self.secrets.as_ref().map_err(Clone::clone)
    }

    /// Print a secrets-directory problem as a warning (commands that do not need it).
    pub fn warn_secrets(&self) {
        if let Err(e) = &self.secrets {
            eprintln!("warning: secrets directory: {}", e.message);
        }
    }

    /// `GET /leases`; delete the files of leases no longer reported active.
    pub fn sync_leases(&self) -> Result<LeasesResponse, CliError> {
        let leases: LeasesResponse = self.api.get("/leases")?;
        if let Ok(dir) = &self.secrets {
            let active: HashSet<String> = leases
                .leases
                .iter()
                .filter(|l| l.status == LeaseStatus::Active)
                .map(|l| l.lease_id.clone())
                .collect();
            dir.reconcile(&active)?;
        }
        Ok(leases)
    }
}

pub fn list(json: bool) -> Result<(), CliError> {
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = s.api.get_bytes("/secrets")?;
    let parsed: SecretsResponse = serde_json::from_slice(&body)
        .map_err(|e| CliError::failure(format!("unexpected answer from the manager: {e}")))?;
    for w in &parsed.warnings {
        eprintln!("warning: {w}");
    }
    let mut out = std::io::stdout().lock();
    if json {
        let _ = out.write_all(&body);
        let _ = out.write_all(b"\n");
    } else {
        for secret in &parsed.secrets {
            let _ = writeln!(out, "{}", secret.name);
        }
    }
    Ok(())
}

/// Parse `--hosts a,b` values (already split on commas) into normalised patterns.
fn parse_hosts(hosts: &[String]) -> Result<Vec<String>, CliError> {
    let raw: Vec<&str> = hosts
        .iter()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .collect();
    Ok(asm_proto::rules::normalize_host_patterns(&raw)?)
}

fn check_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() {
        return Err(CliError::invalid("secret name is empty"));
    }
    asm_proto::rules::validate_agent_text("secret name", name)?;
    Ok(())
}

/// Waited past the manager's expiry before giving up on an unreachable manager.
const EXPIRY_MARGIN: Duration = Duration::from_secs(15);
/// Wait when the manager does not say when a request expires (older managers).
const FALLBACK_WAIT: Duration = Duration::from_secs(600);
/// Longest pause between retries while the manager is unreachable.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// How long, from now, the manager keeps a pending request (plus a margin): from its
/// `expires_at`, bounded by its lifetime (`0` = not sent). A request that is pending
/// cannot already be past its expiry nor outlive its lifetime; such a value means the two
/// clocks differ, and the lifetime is used instead. Neither sent → 600 s.
pub fn pending_window(expires_at: Option<&str>, lifetime_secs: u64, now: i64) -> Duration {
    let left = expires_at
        .and_then(asm_proto::time::parse_unix)
        .map(|e| e - now)
        .filter(|l| *l > 0)
        .map(|l| l as u64);
    let secs = match (left, lifetime_secs) {
        (Some(l), 0) => l,
        (Some(l), max) if l <= max => l,
        (_, 0) => return FALLBACK_WAIT,
        (_, max) => max,
    };
    Duration::from_secs(secs) + EXPIRY_MARGIN
}

/// `"10 minutes"`, `"1 minute"`, `"90 seconds"`.
fn fmt_lifetime(secs: u64) -> String {
    match secs {
        60 => "1 minute".to_owned(),
        s if s % 60 == 0 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

/// Retry pacing while the manager is unreachable: 1 s, doubling, at most 30 s.
pub struct Backoff(Duration);

impl Backoff {
    pub fn new() -> Self {
        Backoff(Duration::from_secs(1))
    }

    pub fn reset(&mut self) {
        self.0 = Duration::from_secs(1);
    }

    /// Sleep before the next attempt, never past `until`; `false` once `until` has passed.
    pub fn wait(&mut self, until: Instant) -> bool {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(self.0.min(left));
        self.0 = (self.0 * 2).min(MAX_BACKOFF);
        true
    }
}

/// Submit a request and wait for its outcome. `wait: None` waits as long as the manager
/// keeps the request pending (its `expires_at` plus a margin); `Some(w)` stops after `w`
/// with exit 4 while it is still pending. An unreachable manager is retried until the
/// earlier of the two.
fn submit(
    api: &Api,
    body: &RequestBody,
    wait: Option<Duration>,
) -> Result<RequestResult, CliError> {
    let started = Instant::now();
    let mut state: RequestState = api.post("/requests", body)?;
    if !asm_proto::crypto::is_uuid(&state.request_id) {
        return Err(CliError::failure("the manager sent an invalid request id"));
    }
    let lifetime = state.pending_lifetime_secs;
    let expected = started
        + pending_window(
            state.expires_at.as_deref(),
            state.pending_lifetime_secs,
            unix_now(),
        );
    let hard = wait.map(|w| started + w);
    let retry_until = hard.map_or(expected, |h| h.min(expected));
    let mut backoff = Backoff::new();
    // The last connection error, while the manager is unreachable.
    let mut last_error: Option<String> = None;
    while state.status == RequestStatus::Pending {
        let now = Instant::now();
        let secs = match hard {
            Some(h) if now >= h => {
                return Err(match last_error {
                    Some(msg) => CliError::lost_contact(&msg, RERUN_TO_PICK_UP),
                    None => CliError::pending(),
                });
            }
            Some(h) => {
                (h.duration_since(now).as_secs_f64().ceil() as u64).clamp(1, MAX_POLL_WAIT_SECS)
            }
            None => MAX_POLL_WAIT_SECS,
        };
        let polled = Instant::now();
        match api.get(&format!("/requests/{}?wait={secs}", state.request_id)) {
            Ok(s) => {
                state = s;
                backoff.reset();
                last_error = None;
                if state.status == RequestStatus::Pending {
                    pace(polled);
                }
            }
            Err(e) if e.code == Some(ErrorCode::NotFound) => return Err(CliError::request_lost()),
            Err(e) if e.transient => {
                if !backoff.wait(retry_until) {
                    return Err(CliError::lost_contact(&e.message, RERUN_TO_PICK_UP));
                }
                last_error = Some(e.message);
            }
            Err(e) => return Err(e),
        }
    }
    match state.status {
        RequestStatus::Approved => state.result.ok_or_else(|| {
            CliError::failure("the manager approved the request but sent no result")
        }),
        RequestStatus::Denied => Err(CliError::denied(state.deny_reason.as_deref())),
        RequestStatus::Expired => {
            let lifetime = match state.pending_lifetime_secs {
                0 => lifetime,
                l => l,
            };
            Err(CliError::ended(match lifetime {
                0 => "expired: the request was not answered in time".to_owned(),
                l => format!("expired: no decision within {}", fmt_lifetime(l)),
            }))
        }
        RequestStatus::Cancelled => Err(CliError::ended("cancelled: the request was cancelled")),
        RequestStatus::Pending => unreachable!("loop exits only on a terminal status"),
    }
}

/// Keep at least one second between polls when the manager answers a long poll early.
pub fn pace(started: Instant) {
    if let Some(rest) = Duration::from_secs(1).checked_sub(started.elapsed()) {
        std::thread::sleep(rest);
    }
}

#[derive(Serialize)]
struct JsonFile<'a> {
    field: &'a str,
    relative_path: &'a str,
    path: &'a PathBuf,
}

#[derive(Serialize)]
struct JsonGet<'a> {
    lease_id: &'a str,
    mode: LeaseMode,
    hosts: &'a [String],
    expires_at: &'a Option<String>,
    files: Vec<JsonFile<'a>>,
}

pub struct GetArgs {
    pub raw: bool,
    pub hosts: Vec<String>,
    /// `None` = until the request expires on the manager.
    pub wait: Option<u64>,
    pub json: bool,
    pub name: String,
    pub reason: String,
}

pub fn get(a: GetArgs) -> Result<(), CliError> {
    check_name(&a.name)?;
    let reason = asm_proto::rules::validate_reason(&a.reason)?;
    let hosts = parse_hosts(&a.hosts)?;
    let s = Session::open()?;
    let dir = s.secrets_dir()?;
    s.sync_leases()?;
    let body = RequestBody::Get {
        name: a.name,
        raw: a.raw,
        hosts,
        reason,
        agent: crate::hostinfo::agent_label(),
    };
    let result = match submit(&s.api, &body, a.wait.map(Duration::from_secs))? {
        RequestResult::Get(r) => r,
        RequestResult::Write(_) => {
            return Err(CliError::failure(
                "the manager sent a write result for a get",
            ));
        }
    };
    let stored = dir.store(&result)?;
    let mut out = std::io::stdout().lock();
    if a.json {
        let j = JsonGet {
            lease_id: &result.lease_id,
            mode: result.mode,
            hosts: &result.hosts,
            expires_at: &result.expires_at,
            files: stored
                .iter()
                .map(|f| JsonFile {
                    field: &f.field,
                    relative_path: &f.relative_path,
                    path: &f.path,
                })
                .collect(),
        };
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&j).expect("serializes")
        );
    } else {
        let _ = write!(
            out,
            "{}",
            get_block(
                &result,
                &stored.iter().map(|f| f.path.clone()).collect::<Vec<_>>()
            )
        );
    }
    Ok(())
}

/// The text block `asm get` prints.
fn get_block(r: &GetResult, paths: &[PathBuf]) -> String {
    let mode = match r.mode {
        LeaseMode::Sentinel => "sentinel",
        LeaseMode::Raw => "raw",
    };
    let hosts = match r.mode {
        LeaseMode::Raw => "none (raw value)".to_owned(),
        LeaseMode::Sentinel => r.hosts.join(","),
    };
    let expires = r.expires_at.as_deref().unwrap_or("never");
    let mut s = format!("mode: {mode}\nhosts: {hosts}\nexpires: {expires}\n");
    for p in paths {
        s.push_str(&p.to_string_lossy());
        s.push('\n');
    }
    s
}

fn write_result(r: RequestResult) -> Result<WriteResult, CliError> {
    match r {
        RequestResult::Write(w) => Ok(w),
        RequestResult::Get(_) => Err(CliError::failure(
            "the manager sent a get result for a write",
        )),
    }
}

fn read_value() -> Result<String, CliError> {
    Ok(asm_proto::rules::read_secret_value(
        std::io::stdin().lock(),
    )?)
}

pub fn update(field: Option<String>, wait: Option<u64>, name: String) -> Result<(), CliError> {
    check_name(&name)?;
    let field = field.map(|f| f.trim().to_owned()).filter(|f| !f.is_empty());
    let value = read_value()?;
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = RequestBody::Update {
        name,
        field,
        value,
        agent: crate::hostinfo::agent_label(),
    };
    let w = write_result(submit(&s.api, &body, wait.map(Duration::from_secs))?)?;
    // Raw leases on this secret were revoked by the update: remove their files.
    if let Err(e) = s.sync_leases() {
        eprintln!("warning: {}", e.message);
    }
    println!("updated {} in {}", w.name, w.vault);
    Ok(())
}

pub fn add(wait: Option<u64>, name: String) -> Result<(), CliError> {
    check_name(&name)?;
    if name.contains('/') {
        return Err(CliError::invalid("a new secret name must not contain '/'"));
    }
    let value = read_value()?;
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let body = RequestBody::Add {
        name,
        value,
        agent: crate::hostinfo::agent_label(),
    };
    let w = write_result(submit(&s.api, &body, wait.map(Duration::from_secs))?)?;
    println!("added {} to {}; run asm get to use it", w.name, w.vault);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asm_proto::wire::ResultFile;

    #[test]
    fn get_block_format() {
        let mut r = GetResult {
            lease_id: "l".into(),
            mode: LeaseMode::Sentinel,
            hosts: vec!["api.github.com".into(), "*.githubusercontent.com".into()],
            expires_at: Some("2026-11-16T12:34:56Z".into()),
            files: vec![ResultFile {
                field: "value".into(),
                relative_path: "T".into(),
                content: "x".into(),
            }],
        };
        let p = vec![PathBuf::from("/run/user/1000/asm/secrets/GITHUB_TOKEN")];
        assert_eq!(
            get_block(&r, &p),
            "mode: sentinel\nhosts: api.github.com,*.githubusercontent.com\nexpires: 2026-11-16T12:34:56Z\n/run/user/1000/asm/secrets/GITHUB_TOKEN\n"
        );
        r.mode = LeaseMode::Raw;
        r.hosts.clear();
        r.expires_at = None;
        assert_eq!(
            get_block(&r, &[]),
            "mode: raw\nhosts: none (raw value)\nexpires: never\n"
        );
    }

    #[test]
    fn host_parsing() {
        let h =
            parse_hosts(&["API.github.com".into(), " ".into(), "*.example.com".into()]).unwrap();
        assert_eq!(h, vec!["*.example.com", "api.github.com"]);
        assert!(parse_hosts(&["https://x".into()]).is_err());
    }

    #[test]
    fn pending_windows() {
        let now = 1_000_000;
        let at = |s: i64| asm_proto::time::fmt_unix(now + s);
        let m = EXPIRY_MARGIN;
        // The manager's expiry wins when it fits the lifetime (a re-attached request).
        assert_eq!(
            pending_window(Some(&at(300)), 600, now),
            Duration::from_secs(300) + m
        );
        assert_eq!(
            pending_window(Some(&at(600)), 600, now),
            Duration::from_secs(600) + m
        );
        // Clock skew: already past, or longer than the lifetime → the lifetime.
        assert_eq!(
            pending_window(Some(&at(-30)), 600, now),
            Duration::from_secs(600) + m
        );
        assert_eq!(
            pending_window(Some(&at(5000)), 600, now),
            Duration::from_secs(600) + m
        );
        // Only one of them sent.
        assert_eq!(pending_window(None, 120, now), Duration::from_secs(120) + m);
        assert_eq!(
            pending_window(Some(&at(90)), 0, now),
            Duration::from_secs(90) + m
        );
        // Neither (an older manager) → 600 s.
        assert_eq!(pending_window(None, 0, now), FALLBACK_WAIT);
        assert_eq!(pending_window(Some("garbage"), 0, now), FALLBACK_WAIT);
    }

    #[test]
    fn lifetimes() {
        assert_eq!(fmt_lifetime(600), "10 minutes");
        assert_eq!(fmt_lifetime(60), "1 minute");
        assert_eq!(fmt_lifetime(90), "90 seconds");
    }
}
