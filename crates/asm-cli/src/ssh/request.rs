//! `asm ssh request HOSTS REASON (--privileged | --as USER | --grant G...) [-- command...]`.

use super::store::{self, CONFIG_FILE, LocalSshLease, cert_blob, lease_dir};
use super::{agent, install, require_ssh, ssh_dir};
use crate::api::Api;
use crate::error::CliError;
use crate::files::ensure_private_dir;
use crate::requests::{self, unix_now};
use crate::{hostinfo, state};
use asm_proto::crypto::is_uuid;
use asm_proto::ssh::{
    SshAccess, SshResult, SshTargetAccess, b64_decode, validate_access, validate_target_name,
};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{RequestBody, RequestResult};
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Longest `<dir>/agent.sock` accepted (`sun_path` is 104 bytes on macOS).
const MAX_SOCKET_PATH: usize = 100;
/// Seconds before the end at which `run_command` warns, largest first.
const WARN_AT: [i64; 2] = [600, 120];
/// Longest pause between two reads of `leases.json` while a command runs.
const WARN_POLL: i64 = 30;

#[derive(clap::Args)]
pub struct RequestArgs {
    /// Host names, comma-separated (see asm ssh hosts)
    #[arg(value_name = "HOSTS")]
    pub hosts: String,
    /// Why you need access; shown to the operator.
    pub reason: String,
    /// Full shell access as the host's privileged login.
    #[arg(long, conflicts_with = "grant")]
    pub privileged: bool,
    /// Shell access as another user on the host (see asm ssh hosts)
    #[arg(long = "as", value_name = "USER", conflicts_with_all = ["privileged", "grant"])]
    pub as_user: Option<String>,
    /// Restricted access: logs:<unit> or restart:<unit>. Repeatable.
    #[arg(long = "grant", value_name = "GRANT")]
    pub grant: Vec<String>,
    /// Ask for a new lease even if a matching one is active.
    #[arg(long)]
    pub new_lease: bool,
    /// Wait at most this many seconds for the decision.
    #[arg(long)]
    pub wait: Option<u64>,
    /// Print the lease as JSON.
    #[arg(long, conflicts_with = "command")]
    pub json: bool,
    /// Command to run on the single host, after `--`.
    #[arg(last = true)]
    pub command: Vec<OsString>,
}

pub fn request(a: RequestArgs) -> Result<(), CliError> {
    let (access, user) = if a.privileged {
        (SshAccess::Privileged, None)
    } else if let Some(user) = a.as_user {
        (SshAccess::User, Some(user))
    } else if !a.grant.is_empty() {
        (SshAccess::Restricted, None)
    } else {
        return Err(CliError::invalid(
            "choose --privileged, --as <user> or at least one --grant (logs:<unit>, restart:<unit>)",
        ));
    };
    let mut body = RequestBody::Ssh {
        targets: a.hosts.split(',').map(|t| t.trim().to_owned()).collect(),
        access,
        grants: a.grant,
        user,
        new_lease: a.new_lease,
        reason: a.reason,
        agent: hostinfo::agent_label(),
    };
    body.canonicalize()?;
    let RequestBody::Ssh { targets, user, .. } = &body else {
        unreachable!("built as Ssh");
    };
    if !a.command.is_empty() && targets.len() != 1 {
        return Err(CliError::invalid(
            "a command needs exactly one host; use ssh <host> for several",
        ));
    }
    let dir = ssh_dir()?;
    if dir.join(store::AGENT_SOCK).as_os_str().len() > MAX_SOCKET_PATH {
        return Err(CliError::invalid(
            "ssh agent socket path too long; set XDG_CONFIG_HOME to a shorter directory",
        ));
    }
    // The client (and its runtime thread) is gone before `run_command` blocks signals.
    let result = {
        let host = state::require()?;
        let api = Api::for_host(&host)?;
        require_ssh(&api)?;
        requests::submit(&api, &body, requests::deadline(a.wait))?.0
    };
    let invalid = || CliError::failure("the manager sent an invalid SSH result");
    let RequestResult::Ssh(result) = result else {
        return Err(invalid());
    };
    let lease = validate(result, targets).ok_or_else(invalid)?;
    if lease.access != access || lease.user != *user {
        eprintln!(
            "asm: the operator approved {}, not the {} requested",
            access_name(lease.access, lease.user.as_deref()),
            access_name(access, user.as_deref())
        );
    }
    ensure_private_dir(&dir)?;
    let lease = store::store(&dir, &lease)?;
    agent::ensure_running(&dir);

    let config = lease_dir(&dir, &lease.lease_id).join(CONFIG_FILE);
    if !a.command.is_empty() {
        run_command(&dir, &lease.lease_id, &lease.targets[0].name, &a.command);
    }
    let installed = install::installed();
    let mut out = std::io::stdout().lock();
    if a.json {
        let targets: Vec<_> = lease
            .targets
            .iter()
            .map(|t| serde_json::json!({"name": t.name, "login": t.login}))
            .collect();
        let doc = serde_json::json!({
            "lease_id": lease.lease_id,
            "expires_at": fmt_unix(lease.expires_at),
            "access": lease.access,
            "grants": lease.grants,
            "user": lease.user,
            "config": config.to_string_lossy(),
            "installed": installed,
            "targets": targets,
        });
        let _ = writeln!(out, "{doc}");
    } else {
        let _ = writeln!(
            out,
            "ssh lease {} until {} ({})",
            lease.lease_id,
            fmt_unix(lease.expires_at),
            access_text(&lease, ", ")
        );
        let as_user = lease.user.as_deref().map(|u| format!(" as {u}")).unwrap_or_default();
        for t in &lease.targets {
            let ssh = if installed {
                format!("ssh {}", t.name)
            } else {
                format!("ssh -F {} {}", config.display(), t.name)
            };
            let _ = writeln!(out, "{}: {ssh}   (login {}{as_user})", t.name, t.login);
        }
    }
    Ok(())
}

/// `privileged access`, `restricted access` or `access as <user>`.
fn access_name(access: SshAccess, user: Option<&str>) -> String {
    match access {
        SshAccess::Privileged => "privileged access".to_owned(),
        SshAccess::Restricted => "restricted access".to_owned(),
        SshAccess::User => format!("access as {}", user.unwrap_or("-")),
    }
}

/// `privileged`, `restricted: <grants joined by sep>`, or `as <user>`.
pub(super) fn access_text(lease: &LocalSshLease, sep: &str) -> String {
    match lease.access {
        SshAccess::Privileged => "privileged".to_owned(),
        SshAccess::Restricted => format!("restricted: {}", lease.grants.join(sep)),
        SshAccess::User => format!("as {}", lease.user.as_deref().unwrap_or("-")),
    }
}

/// Check an approved result against the request; `None` when anything is off. The
/// operator may approve a subset of the hosts and any access (and any user). Everything
/// that ends up in a config or `known_hosts` is checked so the manager cannot inject ssh
/// options.
fn validate(r: SshResult, requested: &[String]) -> Option<LocalSshLease> {
    let expires_at = asm_proto::time::parse_unix(&r.expires_at)?;
    let mut names = HashSet::new();
    let ok = is_uuid(&r.lease_id)
        && cert_blob(&r.certificate).is_some()
        && !r.certificate.contains(|c: char| c.is_control())
        && validate_access(r.access, &r.grants, r.user.as_deref()).is_ok()
        && expires_at > unix_now()
        && !r.targets.is_empty()
        && r.targets.iter().all(|t| names.insert(t.name.as_str()) && requested.contains(&t.name))
        && r.targets.iter().all(|t| target_ok(t, r.access));
    ok.then_some(LocalSshLease {
        lease_id: r.lease_id,
        expires_at,
        access: r.access,
        grants: r.grants,
        user: r.user,
        requested_at: 0,
        certificate: r.certificate,
        targets: r.targets,
    })
}

fn target_ok(t: &SshTargetAccess, access: SshAccess) -> bool {
    validate_target_name(&t.name).is_ok()
        && t.login == access.login()
        && t.target_id.len() == 8
        && t.target_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && !t.hostname.is_empty()
        && !t.hostname.starts_with('-')
        && t.hostname.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
        && t.port != 0
        && t.host_keys.iter().all(|k| {
            k.split_once(' ').is_some_and(|(kind, b64)| {
                !kind.is_empty()
                    && kind.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'-' | b'_'))
                    && b64_decode(b64).is_some_and(|blob| !blob.is_empty())
            })
        })
}

fn signal_set(signals: &[libc::c_int]) -> libc::sigset_t {
    // SAFETY: sigemptyset initialises the set before sigaddset reads it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in signals {
            libc::sigaddset(&mut set, s);
        }
        set
    }
}

/// Run `ssh -F <lease dir>/config -- <name> <command...>` as a child process, warn on
/// stderr before the lease ends, forward SIGTERM and SIGHUP to ssh, and exit with its
/// status.
fn run_command(dir: &Path, lease_id: &str, name: &str, command: &[OsString]) -> ! {
    let forwarded = signal_set(&[libc::SIGTERM, libc::SIGHUP]);
    // SAFETY: changes this thread's mask; threads started later inherit it, so only the
    // sigwait thread below receives these signals.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &forwarded, std::ptr::null_mut()) };
    let mut cmd = Command::new("ssh");
    cmd.arg("-F")
        .arg(lease_dir(dir, lease_id).join(CONFIG_FILE))
        .arg("--")
        .arg(name)
        .args(command);
    // SAFETY: only async-signal-safe calls (sigemptyset, pthread_sigmask) between fork
    // and exec. `Command` keeps the parent's mask in the child; ssh must see the
    // signals this process forwards.
    unsafe {
        cmd.pre_exec(|| {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            match libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) {
                0 => Ok(()),
                e => Err(std::io::Error::from_raw_os_error(e)),
            }
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let e = CliError::failure(format!("could not run ssh: {e}"));
            eprintln!("{}", e.message);
            std::process::exit(e.exit);
        }
    };
    // SAFETY: setting dispositions to SIG_IGN has no preconditions. Ctrl-C reaches ssh
    // through the terminal's process group.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    let pid = child.id() as libc::pid_t;
    std::thread::spawn(move || {
        loop {
            let mut sig: libc::c_int = 0;
            // SAFETY: `forwarded` is blocked in every thread; sigwait writes `sig`.
            if unsafe { libc::sigwait(&forwarded, &mut sig) } == 0 {
                // SAFETY: kill has no memory preconditions; `pid` is our child.
                unsafe { libc::kill(pid, sig) };
            }
        }
    });
    let (dir, lease_id, name) = (dir.to_owned(), lease_id.to_owned(), name.to_owned());
    std::thread::spawn(move || warn_until_end(&dir, &lease_id, &name));
    let code = match child.wait() {
        Ok(status) => status
            .code()
            .or_else(|| status.signal().map(|s| 128 + s))
            .unwrap_or(1),
        Err(e) => {
            eprintln!("error: waiting for ssh: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Print the end-of-lease warnings at 10 and 2 minutes left, following extensions,
/// until the lease is gone or has ended.
fn warn_until_end(dir: &Path, lease_id: &str, name: &str) {
    let mut warned: HashSet<(i64, i64)> = HashSet::new();
    loop {
        let Some(lease) = store::read_leases(dir)
            .ok()
            .and_then(|l| l.into_iter().find(|l| l.lease_id == lease_id))
        else {
            return;
        };
        let left = lease.expires_at - unix_now();
        if left <= 0 {
            return;
        }
        // One line even when both thresholds are already passed.
        let due: Vec<i64> = WARN_AT.iter().copied().filter(|&t| left <= t).collect();
        if due.iter().any(|&t| !warned.contains(&(lease.expires_at, t))) {
            warned.extend(due.iter().map(|&t| (lease.expires_at, t)));
            eprintln!(
                "{}",
                warning(lease_id, name, lease.expires_at, (left + 59) / 60)
            );
        }
        let next = WARN_AT.iter().map(|&t| left - t).filter(|&d| d > 0).min();
        let pause = next.map_or(WARN_POLL, |d| d.min(WARN_POLL)).max(1);
        std::thread::sleep(Duration::from_secs(pause as u64));
    }
}

fn warning(lease_id: &str, name: &str, expires_at: i64, minutes: i64) -> String {
    format!(
        "asm: SSH lease {lease_id} on {name} ends at {} (in {minutes} minutes). To keep running processes, run: asm ssh extend {lease_id} \"<reason>\"",
        fmt_unix(expires_at)
    )
}

#[cfg(test)]
mod tests {
    use super::super::store::tests::lease;
    use super::*;
    use asm_proto::ssh::{PRIVILEGED_LOGIN, RESTRICTED_LOGIN};

    const ID: &str = "11111111-2222-4333-8444-555555555555";

    fn target(name: &str, login: &str) -> SshTargetAccess {
        SshTargetAccess {
            name: name.into(),
            target_id: "0123abcd".into(),
            login: login.into(),
            hostname: format!("{name}.example.com"),
            port: 22,
            host_keys: vec!["ssh-ed25519 AAAA".into()],
        }
    }

    fn result(access: SshAccess, grants: &[&str], targets: Vec<SshTargetAccess>) -> SshResult {
        SshResult {
            lease_id: ID.into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            access,
            grants: grants.iter().map(|g| (*g).to_owned()).collect(),
            user: None,
            certificate: format!("{} AAAA", store::CERT_TYPE),
            targets,
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn validate_accepts_a_subset_and_either_access() {
        let priv_t1 = || vec![target("t1", PRIVILEGED_LOGIN)];
        let r = result(SshAccess::Privileged, &[], priv_t1());
        let lease = validate(r, &names(&["t1", "t2"])).unwrap();
        assert_eq!(lease.targets.len(), 1);
        assert_eq!(lease.requested_at, 0);

        let r = result(SshAccess::Restricted, &["logs:nginx.service"], vec![target("t1", RESTRICTED_LOGIN)]);
        let lease = validate(r, &names(&["t1", "t2"])).unwrap();
        assert_eq!(lease.access, SshAccess::Restricted);
        assert_eq!(lease.grants, ["logs:nginx.service"]);
    }

    fn as_user(user: Option<&str>, grants: &[&str], login: &str) -> SshResult {
        let mut r = result(SshAccess::User, grants, vec![target("t1", login)]);
        r.user = user.map(str::to_owned);
        r
    }

    #[test]
    fn validate_accepts_access_as_a_user() {
        let lease = validate(as_user(Some("deploy"), &[], PRIVILEGED_LOGIN), &names(&["t1"])).unwrap();
        assert_eq!(lease.access, SshAccess::User);
        assert_eq!(lease.user.as_deref(), Some("deploy"));
        assert_eq!(access_text(&lease, ","), "as deploy");
    }

    #[test]
    fn validate_rejects_a_bad_user() {
        let requested = names(&["t1"]);
        // Access as a user without a user, with grants, through asm-ops, or as an invalid user.
        assert!(validate(as_user(None, &[], PRIVILEGED_LOGIN), &requested).is_none());
        assert!(validate(as_user(Some("deploy"), &["logs:a.service"], PRIVILEGED_LOGIN), &requested).is_none());
        assert!(validate(as_user(Some("deploy"), &[], RESTRICTED_LOGIN), &requested).is_none());
        assert!(validate(as_user(Some("asm-ops"), &[], PRIVILEGED_LOGIN), &requested).is_none());
        assert!(validate(as_user(Some("Deploy;x"), &[], PRIVILEGED_LOGIN), &requested).is_none());
        // A user on privileged or restricted access.
        let mut r = result(SshAccess::Privileged, &[], vec![target("t1", PRIVILEGED_LOGIN)]);
        r.user = Some("deploy".into());
        assert!(validate(r, &requested).is_none());
        let mut r = result(SshAccess::Restricted, &["logs:a.service"], vec![target("t1", RESTRICTED_LOGIN)]);
        r.user = Some("deploy".into());
        assert!(validate(r, &requested).is_none());
    }

    #[test]
    fn validate_rejects_what_was_not_requested() {
        let requested = names(&["t1"]);
        // An extra target.
        let r = result(
            SshAccess::Privileged,
            &[],
            vec![target("t1", PRIVILEGED_LOGIN), target("t2", PRIVILEGED_LOGIN)],
        );
        assert!(validate(r, &requested).is_none());
        // A duplicate target.
        let r = result(
            SshAccess::Privileged,
            &[],
            vec![target("t1", PRIVILEGED_LOGIN), target("t1", PRIVILEGED_LOGIN)],
        );
        assert!(validate(r, &requested).is_none());
        // The bare grant `logs`.
        let r = result(SshAccess::Restricted, &["logs"], vec![target("t1", RESTRICTED_LOGIN)]);
        assert!(validate(r, &requested).is_none());
        // Restricted access without grants, and privileged access with grants.
        let r = result(SshAccess::Restricted, &[], vec![target("t1", RESTRICTED_LOGIN)]);
        assert!(validate(r, &requested).is_none());
        let r = result(SshAccess::Privileged, &["logs:a.service"], vec![target("t1", PRIVILEGED_LOGIN)]);
        assert!(validate(r, &requested).is_none());
        // A privileged target whose login is root.
        let r = result(SshAccess::Privileged, &[], vec![target("t1", "root")]);
        assert!(validate(r, &requested).is_none());
    }

    #[test]
    fn hostile_target_fields_are_rejected() {
        let mut t = lease(ID, 1, "db").targets.remove(0);
        assert!(target_ok(&t, SshAccess::Privileged));
        assert!(!target_ok(&t, SshAccess::Restricted));
        t.hostname = "db\n  ProxyCommand x".into();
        assert!(!target_ok(&t, SshAccess::Privileged));
    }

    #[test]
    fn warning_names_the_extend_command() {
        assert_eq!(
            warning(ID, "t1", 0, 2),
            format!("asm: SSH lease {ID} on t1 ends at 1970-01-01T00:00:00Z (in 2 minutes). To keep running processes, run: asm ssh extend {ID} \"<reason>\"")
        );
    }
}
