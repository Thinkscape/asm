//! Shell scripts asm runs on SSH targets, and the scripts enrollment installs there.

use asm_proto::crypto::is_uuid;
use asm_proto::ssh::{validate_login, validate_unit};

use crate::error::{CoreError, Result};

/// Shared helpers, prepended to `ENROLL` and `REMOVE`.
pub(crate) const COMMON: &str = include_str!("scripts/common.sh");
/// `admin_why`, after `COMMON` in `ENROLL` and `USERS` and inside the installed `END_LEASE`.
pub(crate) const ADMIN: &str = include_str!("scripts/admin.sh");
pub(crate) const ENROLL: &str = include_str!("scripts/enroll.sh");
pub(crate) const REMOVE: &str = include_str!("scripts/remove.sh");
/// `asm-dispatch`, the login shell of `asm-ops`.
pub(crate) const DISPATCH: &str = include_str!("scripts/dispatch.sh");
/// `asm-shell`, the login shell of `asm-priv`.
pub(crate) const SHELL: &str = include_str!("scripts/shell.sh");
pub(crate) const LOGS: &str = include_str!("scripts/logs.sh");
pub(crate) const END_LEASE: &str = include_str!("scripts/end-lease.sh");
/// Lists the accounts of a host agents could log in as (after `COMMON` and `ADMIN`).
pub(crate) const USERS: &str = include_str!("scripts/users.sh");

/// `asm-end-lease` as enrollment installs it, with `admin_why` in place.
fn end_lease() -> String {
    END_LEASE.replace("@@ADMIN@@\n", ADMIN)
}

pub(crate) struct EnrollParams<'a> {
    pub target_id: &'a str,
    pub privileged_login: &'a str,
    pub allow_privileged: bool,
    /// `ssh-ed25519 <b64>`.
    pub ca_key: &'a str,
    /// `SHA256:<b64>`.
    pub ca_fingerprint: &'a str,
    pub log_units: &'a [String],
    pub restart_units: &'a [String],
    /// Other users agents may log in as, and whether each can become root.
    pub users: &'a [(String, bool)],
    pub agent_hostname: &'a str,
    pub agent_port: u16,
}

pub(crate) fn is_target_id(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_b64(text: &str, padding: bool) -> bool {
    text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || (padding && c == b'='))
}

fn is_ca_key(key: &str) -> bool {
    key.strip_prefix("ssh-ed25519 ").is_some_and(|b64| !b64.is_empty() && is_b64(b64, true))
}

fn is_ca_fingerprint(fp: &str) -> bool {
    fp.strip_prefix("SHA256:").is_some_and(|b64| b64.len() == 43 && is_b64(b64, false))
}

fn is_agent_hostname(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// `common.sh + enroll.sh` with the installed scripts embedded and every value
/// placeholder replaced by a revalidated value.
pub(crate) fn render_enroll(p: &EnrollParams<'_>) -> Result<String> {
    if !is_target_id(p.target_id) {
        return Err(CoreError::internal("invalid SSH target id"));
    }
    validate_login(p.privileged_login).map_err(|e| CoreError::internal(e.message))?;
    for unit in p.log_units.iter().chain(p.restart_units) {
        validate_unit(unit).map_err(|e| CoreError::internal(e.message))?;
    }
    for (user, _) in p.users {
        validate_login(user).map_err(|e| CoreError::internal(e.message))?;
    }
    let users: Vec<String> = p.users.iter().map(|(user, admin)| format!("{user}:{}", u8::from(*admin))).collect();
    if !is_ca_key(p.ca_key) {
        return Err(CoreError::internal("invalid SSH CA public key"));
    }
    if !is_ca_fingerprint(p.ca_fingerprint) {
        return Err(CoreError::internal("invalid SSH CA fingerprint"));
    }
    if !is_agent_hostname(p.agent_hostname) {
        return Err(CoreError::internal("invalid agent hostname"));
    }
    if p.agent_port == 0 {
        return Err(CoreError::internal("invalid agent port"));
    }
    let remove = format!("{COMMON}{REMOVE}");
    Ok(format!("{COMMON}{ADMIN}{ENROLL}")
        .replace("@@DISPATCH@@", DISPATCH.trim_end_matches('\n'))
        .replace("@@SHELL@@", SHELL.trim_end_matches('\n'))
        .replace("@@END_LEASE@@", end_lease().trim_end_matches('\n'))
        .replace("@@LOGS@@", LOGS.trim_end_matches('\n'))
        .replace("@@REMOVE@@", remove.trim_end_matches('\n'))
        .replace("@@TID@@", p.target_id)
        .replace("@@PRIV@@", p.privileged_login)
        .replace("@@PRIV_TRUST@@", if p.allow_privileged { "1" } else { "0" })
        .replace("@@CA_KEY@@", p.ca_key)
        .replace("@@CA_FP@@", p.ca_fingerprint)
        .replace("@@LOG_UNITS@@", &p.log_units.join("\n"))
        .replace("@@RESTART_UNITS@@", &p.restart_units.join("\n"))
        .replace("@@USERS@@", &users.join("\n"))
        .replace("@@AGENT_HOST@@", p.agent_hostname)
        .replace("@@AGENT_PORT@@", &p.agent_port.to_string()))
}

/// The removal script, refusing a host enrolled as another target.
pub(crate) fn render_remove(target_id: &str) -> Result<String> {
    if !is_target_id(target_id) {
        return Err(CoreError::internal("invalid SSH target id"));
    }
    Ok(format!("set -- '{target_id}'\n{COMMON}{REMOVE}"))
}

/// The script that lists a host's accounts for the privileged login `privileged_login`
/// (`users.sh`).
pub(crate) fn render_users(privileged_login: &str) -> Result<String> {
    validate_login(privileged_login).map_err(|e| CoreError::internal(e.message))?;
    Ok(format!("{COMMON}{ADMIN}{USERS}").replace("@@PRIV@@", privileged_login))
}

/// Stdin for the cleanup login: end one lease and its recorded sessions.
pub(crate) fn cleanup_stdin(lease_id: &str, valid_before: i64) -> Result<String> {
    if !is_uuid(lease_id) || valid_before < 0 {
        return Err(CoreError::internal("invalid SSH lease for cleanup"));
    }
    Ok(format!("end {lease_id} {valid_before}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    const LEASE: &str = "00000000-0000-4000-8000-000000000001";
    const CA_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+/=";
    const CA_FP: &str = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    fn sh_syntax_ok(text: &str) -> bool {
        let mut child = Command::new("/bin/sh").arg("-n").stdin(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        child.wait().unwrap().success()
    }

    /// Run `script` as `/bin/sh -c SCRIPT name ARGS…` and return its exit code, stdout
    /// and stderr.
    fn run(script: &str, name: &str, args: &[&str], original: Option<&str>) -> (i32, String, String) {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script).arg(name).args(args).env_remove("SSH_ORIGINAL_COMMAND")
            .stdin(Stdio::null());
        if let Some(original) = original {
            command.env("SSH_ORIGINAL_COMMAND", original);
        }
        let out = command.output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn params<'a>(log_units: &'a [String], restart_units: &'a [String]) -> EnrollParams<'a> {
        EnrollParams {
            target_id: "0a1b2c3d", privileged_login: "root", allow_privileged: true, ca_key: CA_KEY,
            ca_fingerprint: CA_FP, log_units, restart_units, users: &[], agent_hostname: "web.example.com",
            agent_port: 22,
        }
    }

    fn now() -> i64 {
        crate::manager::now()
    }

    #[test]
    fn scripts_parse_and_installed_scripts_have_no_heredoc_terminator() {
        let remove = format!("{COMMON}{REMOVE}");
        let end_lease = end_lease();
        assert!(!end_lease.contains("@@"));
        for script in [&format!("{COMMON}{ADMIN}{ENROLL}"), &remove, &format!("{COMMON}{ADMIN}{USERS}"), DISPATCH,
            SHELL, LOGS, &end_lease]
        {
            assert!(sh_syntax_ok(script), "{script}");
        }
        for script in [DISPATCH, SHELL, &end_lease, LOGS, &remove] {
            assert!(!script.lines().any(|l| l == "ASM_EOF"), "{script}");
        }
    }

    #[test]
    fn enroll_and_remove_render_validated_values() {
        let logs = vec!["web.service".to_string()];
        let units = vec!["web.service".to_string(), "worker@1.service".to_string()];
        let rendered = render_enroll(&params(&logs, &units)).unwrap();
        assert!(sh_syntax_ok(&rendered));
        assert!(!rendered.contains("@@"));
        assert!(rendered.contains(r#"principals=\"asm-$TID-cleanup\",restrict,command=\"asm-cleanup\""#));
        assert!(rendered.contains("PRIV='root'; PRIV_TRUST='1'\nUSERS=''"));
        assert!(rendered.contains("TID='0a1b2c3d'; PRIV='root'; PRIV_TRUST='1'"));
        assert!(rendered.contains(&format!("CA_KEY='{CA_KEY}'; CA_FP='{CA_FP}'")));
        assert!(rendered.contains("ca=%s"));
        assert!(rendered.contains("RESTART_UNITS='web.service\nworker@1.service'"));
        let users = [("deploy".to_string(), false), ("ops".to_string(), true)];
        let with_users = render_enroll(&EnrollParams { users: &users, ..params(&logs, &units) }).unwrap();
        assert!(sh_syntax_ok(&with_users));
        assert_eq!(with_users.matches("USERS='deploy:0\nops:1'").count(), 2, "enroll.sh and asm-shell");
        let bad_users = [("asm-ops".to_string(), false)];
        assert!(render_enroll(&EnrollParams { users: &bad_users, ..params(&logs, &units) }).is_err());
        let listing = render_users("root").unwrap();
        assert!(sh_syntax_ok(&listing) && listing.contains("PRIV='root'") && !listing.contains("@@"));
        assert!(render_users("bad user").is_err());
        assert!(rendered.contains("AGENT_HOST='web.example.com'; PORT='22'"));

        let mut bad = params(&logs, &units);
        bad.ca_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+/= asm-ca";
        assert!(render_enroll(&bad).is_err());
        let mut bad = params(&logs, &units);
        bad.ca_fingerprint = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP'";
        assert!(render_enroll(&bad).is_err());
        let mut bad = params(&logs, &units);
        bad.agent_hostname = "web example";
        assert!(render_enroll(&bad).is_err());
        let mut bad = params(&logs, &units);
        bad.target_id = "0A1B2C3D";
        assert!(render_enroll(&bad).is_err());
        let mut bad = params(&logs, &units);
        bad.privileged_login = "asm-ops";
        assert!(render_enroll(&bad).is_err());
        let bad_units = vec!["bad'unit.service".to_string()];
        assert!(render_enroll(&params(&bad_units, &units)).is_err());

        let remove = render_remove("0a1b2c3d").unwrap();
        assert!(remove.starts_with("set -- '0a1b2c3d'\n#!/bin/sh\n"));
        assert!(sh_syntax_ok(&remove));
        assert!(render_remove("0a1b2c3").is_err());

        assert_eq!(cleanup_stdin(LEASE, 42).unwrap(), format!("end {LEASE} 42\n"));
        assert!(cleanup_stdin("asm-lease-x", 42).is_err());
        assert!(cleanup_stdin(LEASE, -1).is_err());
    }

    #[test]
    fn dispatcher_refuses_logins_and_ungranted_operations() {
        let until = now() + 3600;
        let grant = format!("asm-grant lease={LEASE} until={until} logs:a.service");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &[], None);
        assert_eq!(code, 126);
        assert!(err.contains("interactive login is not allowed"), "{err}");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &grant], None);
        assert_eq!(code, 126);
        assert!(err.contains("usage"), "{err}");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &grant], Some("logs b.service"));
        assert_eq!(code, 126);
        assert!(err.contains("logs of b.service not granted"), "{err}");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &grant], Some("restart a.service"));
        assert_eq!(code, 126);
        assert!(err.contains("restart of a.service not granted"), "{err}");
        let ended = format!("asm-grant lease={LEASE} until=1 logs:a.service");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &ended], Some("logs a.service"));
        assert_eq!(code, 126);
        assert!(err.contains("the SSH lease has ended"), "{err}");
        let no_lease = format!("asm-grant until={until} logs:a.service");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &no_lease], Some("logs a.service"));
        assert_eq!(code, 126);
        assert!(err.contains("no asm grant"), "{err}");
    }

    #[test]
    fn shell_refuses_anything_but_a_lease_login() {
        let until = now() + 3600;
        let (code, _, err) = run(SHELL, "asm-shell", &[], None);
        assert_eq!(code, 126);
        assert!(err.contains("this account only accepts asm SSH lease logins"), "{err}");
        let (code, _, err) = run(SHELL, "asm-shell", &["-c", &format!("asm-shell lease=bad until={until}")], None);
        assert_eq!(code, 126);
        assert!(err.contains("no asm lease"), "{err}");
        let (code, _, err) = run(SHELL, "asm-shell", &["-c", &format!("asm-shell lease={LEASE} until=1")], None);
        assert_eq!(code, 126);
        assert!(err.contains("the SSH lease has ended"), "{err}");
        let grant = format!("asm-grant lease={LEASE} until={until} logs:a.service");
        let (code, _, err) = run(SHELL, "asm-shell", &["-c", &grant], None);
        assert_eq!(code, 126);
        assert!(err.contains("no asm lease"), "{err}");
        // Access as a user names one the host allows; privileged access needs it allowed.
        let shell = SHELL.replace("@@PRIV@@", "root").replace("@@PRIV_TRUST@@", "0").replace("@@USERS@@", "deploy:0");
        let (code, _, err) = run(&shell, "asm-shell", &["-c", &format!("asm-shell lease={LEASE} until={until} as=web")], None);
        assert_eq!(code, 126);
        assert!(err.contains("this host does not allow access as web"), "{err}");
        let (code, _, err) = run(&shell, "asm-shell", &["-c", &format!("asm-shell lease={LEASE} until={until}")], None);
        assert_eq!(code, 126);
        assert!(err.contains("this host does not allow privileged access"), "{err}");
        let (code, _, err) = run(&shell, "asm-shell", &["-c", &format!("asm-shell lease={LEASE} until={until} as=")], None);
        assert_eq!(code, 126);
        assert!(err.contains("no asm lease"), "{err}");
    }

    #[test]
    fn logs_and_end_lease_refuse_bad_calls() {
        for args in [&["a.service"][..], &["a.service", "x"], &["a.service", "0"], &["a", "b.service", "5"]] {
            let (code, _, err) = run(LOGS, "asm-logs", args, None);
            assert_eq!(code, 126, "{args:?}: {err}");
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            let (code, out, _) = run(&end_lease(), "asm-end-lease", &[], None);
            assert_eq!(code, 3);
            assert!(out.starts_with("asm-end-error not-root "), "{out}");
        }
    }
}
