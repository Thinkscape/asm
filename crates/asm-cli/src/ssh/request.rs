//! `asm ssh request HOSTS REASON (--privileged | --as USER | --grant G...) [-- command...]`.

use super::store::{self, CONFIG_FILE, LocalSshLease, cert_ok, lease_dir};
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
use std::fmt::Write as _;
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
    /// Restricted access: logs:<unit>, restart:<unit>, reload:<unit> or read:<path>. Repeatable.
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
            "choose --privileged, --as <user> or at least one --grant (logs:<unit>, restart:<unit>, reload:<unit> or read:<path>)",
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
    for note in notes(&lease, targets, access, user.as_deref()) {
        eprintln!("{note}");
    }
    ensure_private_dir(&dir)?;
    let store::Stored { lease, hosts_conf_names } = store::store(&dir, &lease)?;
    agent::ensure_running(&dir);

    let config = lease_dir(&dir, &lease.lease_id).join(CONFIG_FILE);
    if !a.command.is_empty() {
        run_command(&dir, &lease.lease_id, &lease.targets[0].name, &a.command);
    }
    let installed = install::installed();
    // Plain `ssh <name>` uses the hosts conf, which may map a name to another lease.
    let plain = if installed { hosts_conf_names } else { HashSet::new() };
    let mut out = std::io::stdout().lock();
    if a.json {
        let doc = render_json(&lease, targets, &config, installed, &plain);
        let _ = writeln!(out, "{doc}");
    } else {
        let _ = out.write_all(render_text(&lease, targets, &config, &plain).as_bytes());
    }
    Ok(())
}

/// The command that connects to `name` with this lease: `ssh <name>` for the names in
/// `plain`, otherwise `ssh -F <config> <name>`.
fn connect_command(name: &str, config: &Path, plain: &HashSet<String>) -> String {
    if plain.contains(name) {
        format!("ssh {name}")
    } else {
        format!("ssh -F {} {name}", config.display())
    }
}

/// `ssh lease <id> until <time>`, then per requested host in request order its connect
/// command and access, or `<name>: denied`.
fn render_text(lease: &LocalSshLease, requested: &[String], config: &Path, plain: &HashSet<String>) -> String {
    let mut out = format!("ssh lease {} until {}\n", lease.lease_id, fmt_unix(lease.expires_at));
    for name in requested {
        match lease.targets.iter().find(|t| t.name == *name) {
            Some(t) => {
                let _ = writeln!(out, "{name}: {}   ({})", connect_command(name, config, plain), access_text(t));
            }
            None => {
                let _ = writeln!(out, "{name}: denied");
            }
        }
    }
    out
}

/// The `--json` document: the approved hosts with their access and connect command,
/// and the denied ones.
fn render_json(
    lease: &LocalSshLease,
    requested: &[String],
    config: &Path,
    installed: bool,
    plain: &HashSet<String>,
) -> serde_json::Value {
    let targets: Vec<serde_json::Value> = lease
        .targets
        .iter()
        .map(|t| {
            let mut v = target_json(t);
            v["connect"] = connect_command(&t.name, config, plain).into();
            v
        })
        .collect();
    let denied: Vec<&String> = requested
        .iter()
        .filter(|name| !lease.targets.iter().any(|t| t.name == **name))
        .collect();
    serde_json::json!({
        "lease_id": lease.lease_id,
        "expires_at": fmt_unix(lease.expires_at),
        "config": config.to_string_lossy(),
        "installed": installed,
        "targets": targets,
        "denied": denied,
    })
}

/// The stderr lines for requested hosts the operator approved with other access than
/// requested, or denied.
fn notes(lease: &LocalSshLease, requested: &[String], access: SshAccess, user: Option<&str>) -> Vec<String> {
    requested
        .iter()
        .filter_map(|name| match lease.targets.iter().find(|t| t.name == *name) {
            Some(t) if t.access != access || t.user.as_deref() != user => Some(format!(
                "asm: {name}: the operator approved {}, not the {} requested",
                access_name(t.access, t.user.as_deref()),
                access_name(access, user)
            )),
            Some(_) => None,
            None => Some(format!("asm: {name}: denied by the operator")),
        })
        .collect()
}

/// `privileged access`, `restricted access` or `access as <user>`.
fn access_name(access: SshAccess, user: Option<&str>) -> String {
    match access {
        SshAccess::Privileged => "privileged access".to_owned(),
        SshAccess::Restricted => "restricted access".to_owned(),
        SshAccess::User => format!("access as {}", user.unwrap_or("-")),
    }
}

/// `privileged`, `restricted: <grants joined by ", ">`, or `as <user>`.
pub(super) fn access_text(t: &SshTargetAccess) -> String {
    match t.access {
        SshAccess::Privileged => "privileged".to_owned(),
        SshAccess::Restricted => format!("restricted: {}", t.grants.join(", ")),
        SshAccess::User => format!("as {}", t.user.as_deref().unwrap_or("-")),
    }
}

/// One host of a lease in JSON output.
pub(super) fn target_json(t: &SshTargetAccess) -> serde_json::Value {
    serde_json::json!({"name": t.name, "login": t.login, "access": t.access, "grants": t.grants, "user": t.user})
}

/// Check an approved result against the request; `None` when anything is off. The
/// operator may approve a subset of the hosts and any access (and any user) per host.
/// Everything that ends up in a config, `known_hosts` or a certificate file is checked
/// so the manager cannot inject ssh options. The targets come back in request order.
fn validate(r: SshResult, requested: &[String]) -> Option<LocalSshLease> {
    let expires_at = asm_proto::time::parse_unix(&r.expires_at)?;
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    let ok = is_uuid(&r.lease_id)
        && expires_at > unix_now()
        && !r.targets.is_empty()
        && r.targets.iter().all(|t| {
            names.insert(t.name.as_str())
                && ids.insert(t.target_id.as_str())
                && requested.contains(&t.name)
                && target_ok(t)
        });
    if !ok {
        return None;
    }
    let mut targets = r.targets;
    targets.sort_by_key(|t| requested.iter().position(|n| *n == t.name));
    Some(LocalSshLease {
        lease_id: r.lease_id,
        expires_at,
        requested_at: 0,
        targets,
    })
}

/// One approved host: its access, login and certificate agree, and its name, id,
/// address and host keys are safe to write into ssh files.
fn target_ok(t: &SshTargetAccess) -> bool {
    validate_target_name(&t.name).is_ok()
        && validate_access(t.access, &t.grants, t.user.as_deref()).is_ok()
        && t.login == t.access.login()
        && cert_ok(&t.certificate)
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
    use super::*;
    use asm_proto::ssh::PRIVILEGED_LOGIN;

    const ID: &str = "11111111-2222-4333-8444-555555555555";

    /// Target `name` (id `tid`) with `access`, the login it needs, and a certificate.
    fn target(name: &str, tid: &str, access: SshAccess, grants: &[&str], user: Option<&str>) -> SshTargetAccess {
        SshTargetAccess {
            name: name.into(),
            target_id: tid.into(),
            login: access.login().into(),
            hostname: format!("{name}.example.com"),
            port: 22,
            host_keys: vec!["ssh-ed25519 AAAA".into()],
            access,
            grants: grants.iter().map(|g| (*g).to_owned()).collect(),
            user: user.map(str::to_owned),
            certificate: format!("{} AAAA asm-lease-{ID}", store::CERT_TYPE),
        }
    }

    fn privileged(name: &str) -> SshTargetAccess {
        target(name, "0123abcd", SshAccess::Privileged, &[], None)
    }

    fn result(targets: Vec<SshTargetAccess>) -> SshResult {
        SshResult {
            lease_id: ID.into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            targets,
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| (*s).to_owned()).collect()
    }

    /// t1 privileged, t2 restricted, t3 as deploy, t4 denied, in another order than requested.
    fn mixed() -> SshResult {
        result(vec![
            target("t3", "0000000c", SshAccess::User, &[], Some("deploy")),
            target("t1", "0000000a", SshAccess::Privileged, &[], None),
            target("t2", "0000000b", SshAccess::Restricted, &["logs:a.service", "read:/etc/a.conf"], None),
        ])
    }

    #[test]
    fn validate_accepts_other_access_per_host_in_request_order() {
        let requested = names(&["t1", "t2", "t3", "t4"]);
        let lease = validate(mixed(), &requested).unwrap();
        assert_eq!(lease.requested_at, 0);
        let got: Vec<(&str, &str)> = lease.targets.iter().map(|t| (t.name.as_str(), t.login.as_str())).collect();
        assert_eq!(got, [("t1", "asm-priv"), ("t2", "asm-ops"), ("t3", "asm-priv")]);

        assert_eq!(
            render_text(&lease, &requested, Path::new("/c/config"), &HashSet::new()),
            format!(
                "ssh lease {ID} until 2999-01-01T00:00:00Z\nt1: ssh -F /c/config t1   (privileged)\nt2: ssh -F /c/config t2   (restricted: logs:a.service, read:/etc/a.conf)\nt3: ssh -F /c/config t3   (as deploy)\nt4: denied\n"
            )
        );
        // Plain `ssh` only for the names the hosts conf maps to this lease.
        let plain = HashSet::from(["t1".to_owned(), "t3".to_owned()]);
        let text = render_text(&lease, &requested, Path::new("/c/config"), &plain);
        assert!(text.contains("\nt1: ssh t1   (privileged)\nt2: ssh -F /c/config t2   "), "{text}");
        assert!(text.contains("\nt3: ssh t3   (as deploy)\n"), "{text}");
        let doc = render_json(&lease, &requested, Path::new("/c/config"), true, &plain);
        let connect: Vec<&str> = doc["targets"].as_array().unwrap().iter().map(|t| t["connect"].as_str().unwrap()).collect();
        assert_eq!(connect, ["ssh t1", "ssh -F /c/config t2", "ssh t3"]);
        assert_eq!(doc["denied"], serde_json::json!(["t4"]));

        assert_eq!(
            notes(&lease, &requested, SshAccess::Privileged, None),
            [
                "asm: t2: the operator approved restricted access, not the privileged access requested",
                "asm: t3: the operator approved access as deploy, not the privileged access requested",
                "asm: t4: denied by the operator",
            ]
        );
        assert_eq!(
            notes(&lease, &requested, SshAccess::User, Some("deploy")),
            [
                "asm: t1: the operator approved privileged access, not the access as deploy requested",
                "asm: t2: the operator approved restricted access, not the access as deploy requested",
                "asm: t4: denied by the operator",
            ]
        );
        // Other grants than requested are no note: the output line shows them.
        assert_eq!(notes(&lease, &names(&["t2"]), SshAccess::Restricted, None), Vec::<String>::new());
    }

    #[test]
    fn validate_rejects_a_bad_target() {
        let requested = names(&["t1"]);
        let bad = |edit: &dyn Fn(&mut SshTargetAccess)| {
            let mut t = privileged("t1");
            edit(&mut t);
            validate(result(vec![t]), &requested).is_none()
        };
        assert!(!bad(&|_| {}));
        assert_eq!(privileged("t1").login, PRIVILEGED_LOGIN);
        // A login that doesn't match the access.
        assert!(bad(&|t| t.login = "asm-ops".into()));
        assert!(bad(&|t| t.login = "root".into()));
        assert!(bad(&|t| {
            t.access = SshAccess::Restricted;
            t.grants = vec!["logs:a.service".into()];
        }));
        // A certificate that is not a certificate line, or holds a control character.
        assert!(bad(&|t| t.certificate = "ssh-ed25519 AAAA".into()));
        assert!(bad(&|t| t.certificate = format!("{} !!", store::CERT_TYPE)));
        assert!(bad(&|t| t.certificate = format!("{} AAAA\nx", store::CERT_TYPE)));
        // Access as a user without a user, with grants or as an invalid user; a user on
        // privileged access; grants on privileged access; restricted access without
        // grants or with the bare grant `logs`.
        assert!(bad(&|t| t.access = SshAccess::User));
        for user in ["Deploy;x", "asm-ops"] {
            assert!(bad(&|t| {
                t.access = SshAccess::User;
                t.user = Some(user.into());
            }));
        }
        assert!(bad(&|t| {
            t.access = SshAccess::User;
            t.user = Some("deploy".into());
            t.grants = vec!["logs:a.service".into()];
        }));
        assert!(bad(&|t| t.user = Some("deploy".into())));
        assert!(bad(&|t| t.grants = vec!["logs:a.service".into()]));
        assert!(bad(&|t| {
            t.access = SshAccess::Restricted;
            t.login = "asm-ops".into();
        }));
        assert!(bad(&|t| {
            t.access = SshAccess::Restricted;
            t.login = "asm-ops".into();
            t.grants = vec!["logs".into()];
        }));
        // Fields that end up in ssh files.
        assert!(bad(&|t| t.hostname = "db\n  ProxyCommand x".into()));
        assert!(bad(&|t| t.target_id = "../x".into()));
        assert!(bad(&|t| t.host_keys = vec!["ssh-ed25519".into()]));
        assert!(bad(&|t| t.port = 0));
    }

    #[test]
    fn validate_rejects_what_was_not_requested() {
        let requested = names(&["t1", "t2"]);
        let other_id = |name: &str| target(name, "4567cdef", SshAccess::Privileged, &[], None);
        assert!(validate(result(vec![privileged("t1"), other_id("t2")]), &requested).is_some());
        // An extra target, a duplicate name, a duplicate target id, no target at all.
        assert!(validate(result(vec![privileged("t1"), other_id("t3")]), &requested).is_none());
        assert!(validate(result(vec![privileged("t1"), other_id("t1")]), &requested).is_none());
        assert!(validate(result(vec![privileged("t1"), privileged("t2")]), &requested).is_none());
        assert!(validate(result(vec![]), &requested).is_none());
        // A bad lease id, or an end in the past.
        let mut r = result(vec![privileged("t1")]);
        r.lease_id = "x".into();
        assert!(validate(r, &requested).is_none());
        let mut r = result(vec![privileged("t1")]);
        r.expires_at = "2000-01-01T00:00:00Z".into();
        assert!(validate(r, &requested).is_none());
    }

    #[test]
    fn warning_names_the_extend_command() {
        assert_eq!(
            warning(ID, "t1", 0, 2),
            format!("asm: SSH lease {ID} on t1 ends at 1970-01-01T00:00:00Z (in 2 minutes). To keep running processes, run: asm ssh extend {ID} \"<reason>\"")
        );
    }
}
