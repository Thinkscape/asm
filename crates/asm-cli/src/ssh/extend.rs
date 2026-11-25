//! `asm ssh extend LEASE_ID REASON`: ask the operator to extend one of this machine's
//! SSH leases, store the new certificate, and for privileged leases and leases as a user
//! log in once to each host so it records the new end.

use super::store::{self, CONFIG_FILE, LocalSshLease, cert_blob, lease_dir};
use super::{agent, require_ssh, ssh_dir};
use crate::api::Api;
use crate::error::CliError;
use crate::requests::{self, unix_now};
use crate::{hostinfo, state};
use asm_proto::ssh::{SshAccess, SshResult};
use asm_proto::time::fmt_unix;
use asm_proto::wire::{RequestBody, RequestResult};
use std::io::{Read, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);
const TOUCH_POLL: Duration = Duration::from_millis(100);

#[derive(clap::Args)]
pub struct ExtendArgs {
    /// The lease to extend (see asm ssh leases).
    pub lease_id: String,
    /// Why you need more time; shown to the operator.
    pub reason: String,
    /// Wait at most this many seconds for the decision.
    #[arg(long)]
    pub wait: Option<u64>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

pub fn extend(a: ExtendArgs) -> Result<(), CliError> {
    let dir = ssh_dir()?;
    let now = unix_now();
    let local = store::read_leases(&dir)
        .map_err(CliError::failure)?
        .into_iter()
        .find(|l| l.lease_id == a.lease_id && l.expires_at > now)
        .ok_or_else(|| {
            CliError::invalid(format!(
                "no active SSH lease {} on this machine; see asm ssh leases",
                a.lease_id
            ))
        })?;
    let mut body = RequestBody::SshExtend {
        lease_id: a.lease_id,
        reason: a.reason,
        agent: hostinfo::agent_label(),
    };
    body.canonicalize()?;
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    require_ssh(&api)?;
    let (result, _) = requests::submit(&api, &body, requests::deadline(a.wait))?;
    let invalid = || CliError::failure("the manager sent an invalid SSH result");
    let RequestResult::Ssh(result) = result else {
        return Err(invalid());
    };
    let lease = validate_extension(result, &local).ok_or_else(invalid)?;
    let stored = store::store(&dir, &lease)?;
    agent::ensure_running(&dir);

    let touched: Vec<(String, Result<(), String>)> = match stored.access {
        SshAccess::Privileged | SshAccess::User => stored
            .targets
            .iter()
            .map(|t| (t.name.clone(), touch(&dir, &stored.lease_id, &t.name)))
            .collect(),
        SshAccess::Restricted => Vec::new(),
    };
    let previous = fmt_unix(local.expires_at);
    for (name, outcome) in &touched {
        if let Err(why) = outcome {
            eprintln!(
                "asm: could not reach {name} ({why}); its running sessions still end at {previous} unless a later login to it succeeds first"
            );
        }
    }
    let config = lease_dir(&dir, &stored.lease_id).join(CONFIG_FILE);
    let mut out = std::io::stdout().lock();
    if a.json {
        let targets: Vec<_> = touched
            .iter()
            .map(|(name, outcome)| serde_json::json!({"name": name, "confirmed": outcome.is_ok()}))
            .collect();
        let doc = serde_json::json!({
            "lease_id": stored.lease_id,
            "expires_at": fmt_unix(stored.expires_at),
            "previous_expires_at": previous,
            "config": config.to_string_lossy(),
            "targets": targets,
        });
        let _ = writeln!(out, "{doc}");
    } else {
        let _ = writeln!(
            out,
            "ssh lease {} extended until {}",
            stored.lease_id,
            fmt_unix(stored.expires_at)
        );
        for (name, outcome) in &touched {
            if outcome.is_ok() {
                let _ = writeln!(out, "{name}: confirmed");
            }
        }
    }
    Ok(())
}

/// The extended lease, when the result is the local lease with a later end and a new
/// certificate; `None` when anything else changed.
fn validate_extension(r: SshResult, local: &LocalSshLease) -> Option<LocalSshLease> {
    let expires_at = asm_proto::time::parse_unix(&r.expires_at)?;
    let ok = r.lease_id == local.lease_id
        && r.access == local.access
        && r.grants == local.grants
        && r.user == local.user
        && r.targets == local.targets
        && expires_at > local.expires_at
        && cert_blob(&r.certificate).is_some()
        && !r.certificate.contains(|c: char| c.is_control());
    ok.then(|| LocalSshLease {
        expires_at,
        certificate: r.certificate,
        ..local.clone()
    })
}

/// Log in once with the lease's own config and run `true`, so the host records the new
/// end. `Err` holds why it failed: ssh's last stderr line, or `timed out`.
fn touch(dir: &Path, lease_id: &str, name: &str) -> Result<(), String> {
    let mut child = Command::new("ssh")
        .arg("-F")
        .arg(lease_dir(dir, lease_id).join(CONFIG_FILE))
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", name, "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run ssh: {e}"))?;
    // Read stderr on a thread so a chatty ssh never blocks on a full pipe.
    let (tx, rx) = mpsc::channel();
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
    }
    let until = Instant::now() + TOUCH_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < until => std::thread::sleep(TOUCH_POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timed out".into());
            }
            Err(e) => return Err(format!("waiting for ssh: {e}")),
        }
    };
    if status.success() {
        return Ok(());
    }
    let stderr = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    let text = String::from_utf8_lossy(&stderr);
    let last = text
        .lines()
        .map(|l| l.chars().filter(|c| !c.is_control()).collect::<String>())
        .map(|l| l.trim().to_owned())
        .rfind(|l| !l.is_empty());
    Err(last.unwrap_or_else(|| format!("ssh {status}")))
}

#[cfg(test)]
mod tests {
    use super::super::store::tests::lease;
    use super::*;

    const ID: &str = "11111111-2222-4333-8444-555555555555";

    fn result_for(local: &LocalSshLease, expires_at: &str) -> SshResult {
        SshResult {
            lease_id: local.lease_id.clone(),
            expires_at: expires_at.into(),
            access: local.access,
            grants: local.grants.clone(),
            user: local.user.clone(),
            certificate: format!("{} BBBB", store::CERT_TYPE),
            targets: local.targets.clone(),
        }
    }

    #[test]
    fn extension_needs_a_later_end_and_the_same_lease() {
        let mut local = lease(ID, 1_000, "db");
        local.requested_at = 7;
        let extended = validate_extension(result_for(&local, "1970-01-01T00:20:00Z"), &local).unwrap();
        assert_eq!(extended.expires_at, 1_200);
        assert_eq!(extended.requested_at, 7);
        assert_eq!(extended.certificate, format!("{} BBBB", store::CERT_TYPE));

        assert!(validate_extension(result_for(&local, "1970-01-01T00:16:40Z"), &local).is_none());
        let mut r = result_for(&local, "1970-01-01T00:20:00Z");
        r.targets[0].port = 2222;
        assert!(validate_extension(r, &local).is_none());
        let mut r = result_for(&local, "1970-01-01T00:20:00Z");
        r.access = SshAccess::Restricted;
        assert!(validate_extension(r, &local).is_none());
        let mut r = result_for(&local, "1970-01-01T00:20:00Z");
        r.user = Some("deploy".into());
        assert!(validate_extension(r, &local).is_none());
        let mut r = result_for(&local, "1970-01-01T00:20:00Z");
        r.lease_id = "22222222-2222-4333-8444-555555555555".into();
        assert!(validate_extension(r, &local).is_none());
        let mut r = result_for(&local, "1970-01-01T00:20:00Z");
        r.certificate = "ssh-ed25519 AAAA".into();
        assert!(validate_extension(r, &local).is_none());
    }
}
