//! Shell scripts asm runs on SSH targets, and the scripts enrollment installs there.

use std::sync::LazyLock;

use asm_proto::crypto::{hex_encode, is_uuid, sha256};
use asm_proto::ssh::{validate_login, validate_read_path, validate_unit};

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
/// `asm-logs UNIT LINES [WHEN]`: a unit's journal.
pub(crate) const LOGS: &str = include_str!("scripts/logs.sh");
/// `asm-status UNIT`: a unit's state, without its processes' command lines.
pub(crate) const STATUS: &str = include_str!("scripts/status.sh");
/// `asm-read PATH`: a file in a directory only root can write.
pub(crate) const READ: &str = include_str!("scripts/read.sh");
pub(crate) const END_LEASE: &str = include_str!("scripts/end-lease.sh");
/// Lists the accounts of a host agents could log in as (after `COMMON` and `ADMIN`).
pub(crate) const USERS: &str = include_str!("scripts/users.sh");

/// `asm-end-lease` as enrollment installs it, with `admin_why` in place.
fn end_lease() -> String {
    END_LEASE.replace("@@ADMIN@@\n", ADMIN)
}

static SCRIPTS_VERSION: LazyLock<String> = LazyLock::new(|| {
    let mut all = String::new();
    for script in [COMMON, ADMIN, ENROLL, REMOVE, DISPATCH, SHELL, LOGS, STATUS, READ, END_LEASE] {
        // Each script's length first, so no two sets of scripts hash alike.
        all.push_str(&format!("{}\n{script}", script.len()));
    }
    hex_encode(&sha256(all.as_bytes())[..8])
});

/// The first 16 hex digits of SHA-256 over every script enrollment installs or runs. A
/// target enrolled with other scripts needs enrolling again.
pub(crate) fn scripts_version() -> &'static str {
    &SCRIPTS_VERSION
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
    pub reload_units: &'a [String],
    pub read_files: &'a [String],
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
    for unit in p.log_units.iter().chain(p.restart_units).chain(p.reload_units) {
        validate_unit(unit).map_err(|e| CoreError::internal(e.message))?;
    }
    for file in p.read_files {
        validate_read_path(file).map_err(|e| CoreError::internal(e.message))?;
    }
    // A value must not hold a placeholder another replacement would fill in.
    if p.log_units.iter().chain(p.restart_units).chain(p.reload_units).chain(p.read_files).any(|v| v.contains("@@")) {
        return Err(CoreError::internal("an SSH unit or file name contains @@"));
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
        .replace("@@STATUS@@", STATUS.trim_end_matches('\n'))
        .replace("@@READ@@", READ.trim_end_matches('\n'))
        .replace("@@REMOVE@@", remove.trim_end_matches('\n'))
        .replace("@@TID@@", p.target_id)
        .replace("@@PRIV@@", p.privileged_login)
        .replace("@@PRIV_TRUST@@", if p.allow_privileged { "1" } else { "0" })
        .replace("@@CA_KEY@@", p.ca_key)
        .replace("@@CA_FP@@", p.ca_fingerprint)
        .replace("@@LOG_UNITS@@", &p.log_units.join("\n"))
        .replace("@@RESTART_UNITS@@", &p.restart_units.join("\n"))
        .replace("@@RELOAD_UNITS@@", &p.reload_units.join("\n"))
        .replace("@@READ_FILES@@", &p.read_files.join("\n"))
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
    const WHEN: &str = "WHEN must look like 30m, 2h, 1d or 2026-11-25T10:00";

    /// `sh -n`, and `dash -n` where dash is installed.
    fn sh_syntax_ok(text: &str) -> bool {
        ["/bin/sh", "/bin/dash", "/usr/bin/dash"].iter()
            .filter(|shell| *shell == &"/bin/sh" || std::path::Path::new(shell).exists())
            .all(|shell| {
                let mut child = Command::new(shell).arg("-n").stdin(Stdio::piped()).spawn().unwrap();
                child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
                child.wait().unwrap().success()
            })
    }

    /// Run `script` as `/bin/sh -c SCRIPT name ARGS…` and return its exit code, stdout
    /// and stderr.
    fn run(script: &str, name: &str, args: &[&str], original: Option<&str>) -> (i32, String, String) {
        run_with_stdin(script, name, args, original, "")
    }

    fn run_with_stdin(script: &str, name: &str, args: &[&str], original: Option<&str>, stdin: &str)
        -> (i32, String, String)
    {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script).arg(name).args(args).env_remove("SSH_ORIGINAL_COMMAND")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(original) = original {
            command.env("SSH_ORIGINAL_COMMAND", original);
        }
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn params<'a>(log_units: &'a [String], restart_units: &'a [String]) -> EnrollParams<'a> {
        EnrollParams {
            target_id: "0a1b2c3d", privileged_login: "root", allow_privileged: true, ca_key: CA_KEY,
            ca_fingerprint: CA_FP, log_units, restart_units, reload_units: &[], read_files: &[], users: &[],
            agent_hostname: "web.example.com", agent_port: 22,
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
            SHELL, LOGS, STATUS, READ, &end_lease]
        {
            assert!(sh_syntax_ok(script), "{script}");
        }
        for script in [DISPATCH, SHELL, &end_lease, LOGS, STATUS, READ, &remove] {
            assert!(!script.lines().any(|l| l == "ASM_EOF"), "{script}");
        }
    }

    #[test]
    fn scripts_version_is_a_short_digest_of_the_scripts() {
        let version = scripts_version();
        assert_eq!(version.len(), 16);
        assert!(version.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{version}");
        assert_eq!(version, scripts_version());
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
        assert!(rendered.contains("RELOAD_UNITS=''\n"));
        assert!(rendered.contains("READ_FILES=''\n"));
        for installed in ["asm-dispatch", "asm-shell", "asm-end-lease", "asm-logs", "asm-status", "asm-read", "asm-remove"] {
            assert!(rendered.contains(&format!("put \"$LIB\" {installed} 0755 <<'ASM_EOF'\n#!/bin/sh\n")), "{installed}");
        }
        let reload = vec!["nginx.service".to_string()];
        let files = vec!["/etc/nginx/nginx.conf".to_string(), "/srv/app/.env".to_string()];
        let with_ops = render_enroll(&EnrollParams { reload_units: &reload, read_files: &files, ..params(&logs, &units) })
            .unwrap();
        assert!(sh_syntax_ok(&with_ops));
        assert!(with_ops.contains("RELOAD_UNITS='nginx.service'\n"));
        assert!(with_ops.contains("READ_FILES='/etc/nginx/nginx.conf\n/srv/app/.env'\n"));
        for bad_files in [vec!["etc/x".to_string()], vec!["/a/../b".to_string()], vec!["/a b".to_string()],
            vec!["/a/@@TID@@".to_string()]]
        {
            assert!(render_enroll(&EnrollParams { read_files: &bad_files, ..params(&logs, &units) }).is_err(),
                "{bad_files:?}");
        }
        let bad_reload = vec!["x@@TID@@.service".to_string()];
        assert!(render_enroll(&EnrollParams { reload_units: &bad_reload, ..params(&logs, &units) }).is_err());
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
        assert!(remove.contains("\"$STATE/baselines\""));
        assert!(sh_syntax_ok(&remove));
        assert!(render_remove("0a1b2c3").is_err());

        assert_eq!(cleanup_stdin(LEASE, 42).unwrap(), format!("end {LEASE} 42\n"));
        assert!(cleanup_stdin("asm-lease-x", 42).is_err());
        assert!(cleanup_stdin(LEASE, -1).is_err());
    }

    #[test]
    fn dispatcher_refuses_logins_and_ungranted_operations() {
        let until = now() + 3600;
        let grant = format!("asm-grant lease={LEASE} until={until} logs:a.service reload:r.service read:/etc/app.conf");
        let refused = |original: Option<&str>| {
            let (code, _, err) = run(DISPATCH, "asm-dispatch", &["-c", &grant], original);
            assert_eq!(code, 126, "{original:?}: {err}");
            err
        };
        let interactive = "asm: interactive login is not allowed; run: logs UNIT [LINES] [--since WHEN] | status UNIT \
            | restart UNIT | reload UNIT | read PATH\n";
        let when = format!("asm: {WHEN}\n");
        let (code, _, err) = run(DISPATCH, "asm-dispatch", &[], None);
        assert_eq!((code, err.as_str()), (126, interactive));
        assert_eq!(refused(None), interactive);
        for (original, message) in [
            ("logs b.service", "asm: logs of b.service not granted\n"),
            ("restart a.service", "asm: restart of a.service not granted\n"),
            ("reload a.service", "asm: reload of a.service not granted\n"),
            ("status b.service", "asm: status of b.service not granted\n"),
            ("read /etc/other.conf", "asm: read of /etc/other.conf not granted\n"),
            ("read etc/app.conf", "asm: invalid file\n"),
            ("read /etc/../etc/app.conf", "asm: invalid file\n"),
            ("read /etc//app.conf", "asm: invalid file\n"),
            ("read /etc/app.conf/", "asm: invalid file\n"),
            ("read /etc/app.conf x", "asm: usage: read PATH\n"),
            ("status", "asm: usage: status UNIT\n"),
            ("status a", "asm: invalid unit\n"),
            ("shell", "asm: unknown operation; allowed: logs, status, restart, reload, read\n"),
            ("", "asm: unknown operation; allowed: logs, status, restart, reload, read\n"),
            ("logs a.service 0", "asm: LINES must be 1-10000\n"),
            ("logs a.service x", "asm: LINES must be a number\n"),
            ("logs a.service 5 6", "asm: usage: logs UNIT [LINES] [--since WHEN]\n"),
            ("logs a.service --since", "asm: usage: logs UNIT [LINES] [--since WHEN]\n"),
            ("logs a.service --since 1h --since 2h", "asm: usage: logs UNIT [LINES] [--since WHEN]\n"),
            ("logs a.service --since 1w", when.as_str()),
            ("logs a.service --since 2026-11-25T10", when.as_str()),
        ] {
            assert_eq!(refused(Some(original)), message, "{original}");
        }
        // Allowed operations get past every check to recording the session, which needs
        // the installed asm-end-lease.
        for original in ["logs a.service", "logs a.service --since 10m 50", "logs a.service 5 --since 2026-11-25T10:00Z",
            "status a.service", "status r.service", "reload r.service", "read /etc/app.conf"]
        {
            let err = refused(Some(original));
            for checked in ["not granted", "usage", "invalid", "WHEN", "LINES", "unknown"] {
                assert!(!err.contains(checked), "{original}: {err}");
            }
        }

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
    fn logs_checks_its_arguments_and_the_when_grammar() {
        for args in [&["a.service"][..], &["a.service", "x"], &["a.service", "0"], &["a", "b.service", "5"],
            &["a.service\nb.service", "5"], &["a.service", "5", "1h", "x"]]
        {
            let (code, _, err) = run(LOGS, "asm-logs", args, None);
            assert_eq!(code, 126, "{args:?}: {err}");
        }
        for bad in ["", "30", "m", "1w", "1234567m", "-1h", "2026-11-25 10:00", "2026-11-25T10", "2026-11-25T10:00:00:00",
            "26-11-25", "2026-11-25T10:00ZZ", "1h;id", "1h\n2h"]
        {
            let (code, _, err) = run(LOGS, "asm-logs", &["a.service", "5", bad], None);
            assert_eq!((code, err.as_str()), (126, format!("asm: {WHEN}\n").as_str()), "{bad:?}");
        }
        // Valid times reach journalctl (missing on macOS).
        for good in ["45s", "30m", "2h", "1d", "999999d", "2026-11-25", "2026-11-25T10:00", "2026-11-25T10:00:59",
            "2026-11-25T10:00Z", "2026-11-25Z"]
        {
            let (code, _, err) = run(LOGS, "asm-logs", &["a.service", "5", good], None);
            assert!(code != 126 && !err.contains("asm:"), "{good}: {code} {err}");
        }
    }

    #[test]
    fn status_and_read_refuse_bad_arguments() {
        for args in [&[][..], &["a.service", "b.service"], &["a"], &["a.service\nb.service"], &["-a.service"]] {
            let (code, _, err) = run(STATUS, "asm-status", args, None);
            assert_eq!(code, 126, "{args:?}: {err}");
        }
        let (code, _, err) = run(READ, "asm-read", &[], None);
        assert_eq!((code, err.as_str()), (126, "asm: usage: read PATH\n"));
        let too_long = format!("/{}", "a".repeat(255));
        for bad in ["", "/", "a", "//a", "/a/", "/a//b", "/a/./b", "/a/../b", "/..", "/a b", "/a*", "/a\nb", "/a:b",
            too_long.as_str()]
        {
            let (code, _, err) = run(READ, "asm-read", &[bad], None);
            assert_eq!((code, err.as_str()), (126, "asm: invalid file\n"), "{bad:?}");
        }
        // A file in a directory its owner can write is refused (as is any on macOS, whose
        // stat has no -c).
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.conf");
        std::fs::write(&file, "secret").unwrap();
        let file = file.to_str().unwrap();
        let (code, out, err) = run(READ, "asm-read", &[file], None);
        assert_eq!((code, out.as_str()), (126, ""));
        assert_eq!(err, format!("asm: {file} is not in a directory only root can write; asm can't read it safely\n"));
    }

    /// The change report functions of `asm-end-lease`, then `body`, as one script (with
    /// the script's own `set -f`).
    fn change_report(body: &str) -> String {
        let start = END_LEASE.find("# ---- Change report ----").unwrap();
        let end = END_LEASE.find("# ---- End of the change report ----").unwrap();
        format!("set -f\nSTATE=/nonexistent\n{}\n{body}", &END_LEASE[start..end])
    }

    const INCOMPLETE: &str = "changed (asm could not check every watched file: too many files or too slow)\n";

    /// `report` on a baseline and a new snapshot in the documented line format.
    #[test]
    fn end_lease_reports_each_changed_path_once() {
        let script = change_report("report \"$1\" \"$(cat)\"; echo \"total=$TOTAL\"");
        let dir = tempfile::tempdir().unwrap();
        let baseline = dir.path().join("baseline");
        let base_path = baseline.to_str().unwrap();
        let entries = "d 66:4 - - - 700 0:0 /root/.ssh\n\
            f 66:1 10 100.5 100.5 644 0:0 /etc/cron.d/a\n\
            f 66:2 5 100.5 100.5 644 0:0 /etc/cron.d/b c\n\
            f 66:9 1 1.0 1.0 600 1000:1000 (a name with a line break)\n\
            l 66:3 7 100.5 100.5 777 0:0 /etc/systemd/system/l\n";
        std::fs::write(&baseline, format!("until=100\nscope=root\ncomplete=1\n{entries}")).unwrap();
        let run_report = |current: &str| {
            let (code, out, err) = run_with_stdin(&script, "asm-end-lease", &[base_path], None, current);
            assert_eq!((code, err.as_str()), (0, ""), "{current}");
            out
        };

        // Modified (a new ctime), removed, added, and a name with a line break that is now
        // another file.
        let current = "complete=1\nd 66:4 - - - 700 0:0 /root/.ssh\n\
            f 66:1 10 100.5 100.5 644 0:0 /etc/cron.d/a\n\
            f 66:2 5 200.5 100.5 644 0:0 /etc/cron.d/b c\n\
            f 66:7 1 200.5 200.5 644 0:0 /etc/cron.d/new\n\
            f 66:8 1 1.0 1.0 600 1000:1000 (a name with a line break)\n";
        assert_eq!(run_report(current), "changed (a name with a line break)\nchanged /etc/cron.d/b c\n\
            changed /etc/cron.d/new\nchanged /etc/systemd/system/l\ntotal=4\n");
        assert_eq!(run_report(&format!("complete=1\n{entries}")), "total=0\n");
        // A changed directory mode is reported; at most 20 paths are listed.
        assert_eq!(run_report(&format!("complete=1\n{}", entries.replace("700 0:0 /root/.ssh", "755 0:0 /root/.ssh"))),
            "changed /root/.ssh\ntotal=1\n");
        let many: String = (0..25).map(|i| format!("f 66:{} 1 1.0 1.0 644 0:0 /etc/cron.d/n{i:02}\n", 100 + i)).collect();
        let out = run_report(&format!("complete=1\n{entries}{many}"));
        assert_eq!((out.lines().count(), out.lines().nth(19), out.lines().last()),
            (21, Some("changed /etc/cron.d/n19"), Some("total=25")));

        // An incomplete snapshot, then or now, reports one line instead of a diff.
        assert_eq!(run_report(&format!("complete=0\n{entries}")), format!("{INCOMPLETE}total=1\n"));
        std::fs::write(&baseline, "until=100\nscope=root\ncomplete=0\n").unwrap();
        assert_eq!(run_report(&format!("complete=1\n{entries}")), format!("{INCOMPLETE}total=1\n"));
    }

    /// A `PATH` whose `find` is GNU find, and the directory that provides it, when this
    /// machine has GNU find and `timeout`.
    fn gnu_path() -> Option<(tempfile::TempDir, String)> {
        let path = std::env::var("PATH").unwrap_or_default();
        let lookup = |tool: &str| Command::new("/bin/sh").arg("-c").arg(format!("command -v {tool}")).output().ok()
            .filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
        lookup("timeout")?;
        let dir = tempfile::tempdir().unwrap();
        let gnu = Command::new("find").arg("--version").output().is_ok_and(|o| o.status.success());
        if !gnu {
            std::os::unix::fs::symlink(lookup("gfind")?, dir.path().join("find")).unwrap();
        }
        let path = format!("{}:{path}", dir.path().display());
        Some((dir, path))
    }

    /// The real walk: metadata lines, no way into a home through a symbolic link, one
    /// entry per real path, and a report of what changed (needs GNU find).
    #[test]
    fn end_lease_snapshots_metadata_and_reports_changes() {
        let Some((_bin, path)) = gnu_path() else {
            eprintln!("skipping: no GNU find or timeout here");
            return;
        };
        let run_sh = |body: &str, args: &[&str]| {
            let out = Command::new("/bin/sh").arg("-c").arg(change_report(body)).arg("asm-end-lease").args(args)
                .env("PATH", &path).stdin(Stdio::null()).output().unwrap();
            assert!(out.status.success(), "{body}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let home = root.join("home");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(elsewhere.join("systemd/user")).unwrap();
        std::fs::write(home.join(".ssh/authorized_keys"), "key\n").unwrap();
        std::fs::write(home.join(".ssh/odd\nname"), "x").unwrap();
        std::fs::write(home.join(".profile"), "x").unwrap();
        std::fs::write(elsewhere.join("systemd/user/evil.service"), "x").unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".config")).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("x"), home.join(".bashrc")).unwrap();
        let h = home.to_str().unwrap();

        // .config leads elsewhere, so .config/systemd/user is not walked; .bashrc itself
        // may be a link.
        assert_eq!(run_sh("home_entries \"$1\"", &[h]), format!("{h}/.ssh\n{h}/.profile\n{h}/.bashrc\n"));
        // One entry per real path; a link counts as itself.
        let via = root.join("via");
        std::os::unix::fs::symlink(&home, &via).unwrap();
        let listed = run_sh("printf '%s\\n' \"$1/.ssh\" \"$2/.ssh\" \"$1/.bashrc\" \"$1/missing\" | start_paths",
            &[h, via.to_str().unwrap()]);
        assert_eq!(listed, format!("{h}/.ssh\n{h}/.bashrc\n"));

        let snapshot = "snap=$(walk \"$@\"); echo complete=1; printf '%s\\n' \"$snap\" | LC_ALL=C sort";
        let starts = [format!("{h}/.ssh"), format!("{h}/.profile"), format!("{h}/.bashrc")];
        let starts: Vec<&str> = starts.iter().map(String::as_str).collect();
        let before = run_sh(snapshot, &starts);
        let lines: Vec<&str> = before.lines().skip(1).collect();
        assert_eq!(lines.len(), 5, "{before}");
        for line in &lines {
            let fields: Vec<&str> = line.splitn(8, ' ').collect();
            assert_eq!(fields.len(), 8, "{line}");
            assert!(fields[1].contains(':') && fields[6].contains(':'), "{line}");
        }
        assert!(lines.iter().any(|l| l.starts_with("d ") && l.contains(" - - - ") && l.ends_with(&format!(" {h}/.ssh"))),
            "{before}");
        assert!(lines.iter().any(|l| l.starts_with("l ") && l.ends_with(&format!(" {h}/.bashrc"))), "{before}");
        assert!(lines.iter().any(|l| l.starts_with("f ") && l.ends_with(" (a name with a line break)")), "{before}");
        assert!(!before.contains("odd"), "{before}");

        let baseline = root.join("baseline");
        std::fs::write(&baseline, format!("until=100\nscope=root\n{before}")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut keys = std::fs::OpenOptions::new().append(true).open(home.join(".ssh/authorized_keys")).unwrap();
        std::io::Write::write_all(&mut keys, b"another key\n").unwrap();
        std::fs::write(home.join(".ssh/rc"), "x").unwrap();
        let report = format!("{{ {snapshot}; }} > \"$TMPDIR_REPORT\"; report \"$BASELINE\" \"$(cat \"$TMPDIR_REPORT\")\"; \
            echo \"total=$TOTAL\"");
        let out = Command::new("/bin/sh").arg("-c").arg(change_report(&report)).arg("asm-end-lease").args(&starts)
            .env("PATH", &path).env("BASELINE", &baseline).env("TMPDIR_REPORT", root.join("current"))
            .stdin(Stdio::null()).output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(),
            format!("changed {h}/.ssh/authorized_keys\nchanged {h}/.ssh/rc\ntotal=2\n"),
            "{}", String::from_utf8_lossy(&out.stderr));

        // More than 20000 entries: the walk stops and says so.
        let many = root.join("many");
        std::fs::create_dir(&many).unwrap();
        for i in 0..20_000 {
            std::fs::write(many.join(i.to_string()), "").unwrap();
        }
        let out = run_sh("walk \"$1\" | tail -n 1; walk \"$1\" | wc -l", &[many.to_str().unwrap()]);
        assert_eq!(out.split_whitespace().collect::<Vec<_>>(), ["incomplete", "20001"]);
    }

    #[test]
    fn end_lease_refuses_to_run_without_root() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            let (code, out, _) = run(&end_lease(), "asm-end-lease", &[], None);
            assert_eq!(code, 3);
            assert!(out.starts_with("asm-end-error not-root "), "{out}");
        }
    }
}
