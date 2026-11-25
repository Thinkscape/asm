//! The CLI's SSH files in `<config_dir>/ssh/` (mode 0700): `leases.json` with its lock,
//! one folder per lease (`cert.pub`, `known_hosts`, `config`), and `asm-ssh-hosts.conf`,
//! the file `asm ssh install` includes from `~/.ssh/config`.

use crate::error::CliError;
use crate::files::{ensure_private_dir, lock_file, write_file_atomic};
use crate::requests::unix_now;
use asm_proto::crypto::is_uuid;
use asm_proto::ssh::{SshAccess, SshTargetAccess, b64_decode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
pub const LEASES_FILE: &str = "leases.json";
const LEASES_LOCK: &str = "leases.lock";
pub const AGENT_SOCK: &str = "agent.sock";
pub const HOSTS_CONF: &str = "asm-ssh-hosts.conf";
pub const CONFIG_FILE: &str = "config";
const KNOWN_HOSTS_FILE: &str = "known_hosts";
const CERT_FILE: &str = "cert.pub";

const HOSTS_CONF_HEADER: &str = "# Managed by asm: rewritten whenever this machine's SSH leases change. Don't edit.\n# `asm ssh install` includes it from ~/.ssh/config; `asm ssh uninstall` stops that.\n";

/// One lease in `leases.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSshLease {
    pub lease_id: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub access: SshAccess,
    #[serde(default)]
    pub grants: Vec<String>,
    /// The user a `User` lease runs as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Unix seconds: when `store` first saved this lease; an extension keeps it.
    #[serde(default)]
    pub requested_at: i64,
    /// One OpenSSH certificate line.
    pub certificate: String,
    pub targets: Vec<SshTargetAccess>,
}

/// The decoded blob (field 2) of a certificate line.
pub fn cert_blob(line: &str) -> Option<Vec<u8>> {
    let rest = line.strip_prefix(CERT_TYPE)?.strip_prefix(' ')?;
    b64_decode(rest.split(' ').next()?)
}

/// The folder of one lease.
pub fn lease_dir(dir: &Path, id: &str) -> PathBuf {
    dir.join(id)
}

/// Read `leases.json`; a missing file is an empty list. Entries whose id is not a
/// UUID are dropped: the id names a folder in the directory.
pub fn read_leases(dir: &Path) -> Result<Vec<LocalSshLease>, String> {
    let path = dir.join(LEASES_FILE);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    let mut leases: Vec<LocalSshLease> = serde_json::from_slice(&data)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    leases.retain(|l| is_uuid(&l.lease_id));
    Ok(leases)
}

fn io_failure(what: &str, path: &Path, e: std::io::Error) -> CliError {
    CliError::failure(format!("{what} {}: {e}", path.display()))
}

fn lock(dir: &Path) -> Result<std::fs::File, CliError> {
    let path = dir.join(LEASES_LOCK);
    match lock_file(dir, LEASES_LOCK, true) {
        Ok(Some(f)) => Ok(f),
        Ok(None) => Err(CliError::failure(format!("locking {}: busy", path.display()))),
        Err(e) => Err(io_failure("locking", &path, e)),
    }
}

/// Remove a lease's folder; a missing folder is fine.
fn remove_lease_dir(dir: &Path, id: &str) -> Result<(), CliError> {
    if !is_uuid(id) {
        return Ok(());
    }
    let path = lease_dir(dir, id);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_failure("removing", &path, e)),
    }
}

/// Split off the expired leases and remove their folders.
fn drop_expired(dir: &Path, leases: Vec<LocalSshLease>) -> Result<Vec<LocalSshLease>, CliError> {
    let now = unix_now();
    let (live, expired): (Vec<_>, Vec<_>) = leases.into_iter().partition(|l| l.expires_at > now);
    for old in expired {
        remove_lease_dir(dir, &old.lease_id)?;
    }
    Ok(live)
}

fn save_leases(dir: &Path, leases: &[LocalSshLease]) -> Result<(), CliError> {
    let json = serde_json::to_vec_pretty(leases)
        .map_err(|e| CliError::failure(format!("encoding {LEASES_FILE}: {e}")))?;
    write_file_atomic(dir, LEASES_FILE, &json).map(drop)
}

/// Under the lease lock: drop expired leases and their folders, then save `lease`
/// (its folder, `cert.pub`, and `known_hosts` and `config` once), `leases.json` and
/// `asm-ssh-hosts.conf`. A stored lease with a later end wins over `lease`, so a slower,
/// older response never rolls a lease back. Returns the stored lease.
pub fn store(dir: &Path, lease: &LocalSshLease) -> Result<LocalSshLease, CliError> {
    let _lock = lock(dir)?;
    let mut leases = drop_expired(dir, read_leases(dir).map_err(CliError::failure)?)?;
    let existing = leases.iter().find(|l| l.lease_id == lease.lease_id).cloned();
    let stored = match existing {
        Some(old) if old.expires_at > lease.expires_at => old,
        _ => {
            let stored = LocalSshLease {
                requested_at: existing.as_ref().map_or_else(unix_now, |old| old.requested_at),
                ..lease.clone()
            };
            let config = render_config(dir, &stored)?;
            let ldir = lease_dir(dir, &stored.lease_id);
            ensure_private_dir(&ldir)?;
            write_file_atomic(&ldir, CERT_FILE, format!("{}\n", stored.certificate).as_bytes())?;
            // Written once: an extension changes only the certificate.
            if !ldir.join(KNOWN_HOSTS_FILE).exists() {
                write_file_atomic(&ldir, KNOWN_HOSTS_FILE, render_known_hosts(&stored).as_bytes())?;
            }
            if !ldir.join(CONFIG_FILE).exists() {
                write_file_atomic(&ldir, CONFIG_FILE, config.as_bytes())?;
            }
            leases.retain(|l| l.lease_id != stored.lease_id);
            leases.push(stored.clone());
            leases.sort_by(|a, b| (a.requested_at, &a.lease_id).cmp(&(b.requested_at, &b.lease_id)));
            stored
        }
    };
    save_leases(dir, &leases)?;
    write_hosts_conf(dir, &leases)?;
    Ok(stored)
}

/// Under the lease lock: forget one lease (the manager no longer knows it).
pub fn forget_lease(dir: &Path, lease_id: &str) -> Result<(), String> {
    let _lock = lock(dir).map_err(|e| e.message)?;
    let mut leases = read_leases(dir)?;
    leases.retain(|l| l.lease_id != lease_id);
    remove_lease_dir(dir, lease_id).map_err(|e| e.message)?;
    save_leases(dir, &leases).map_err(|e| e.message)?;
    write_hosts_conf(dir, &leases).map_err(|e| e.message)
}

/// Under the lease lock: drop expired leases and their folders, and rewrite
/// `leases.json` and `asm-ssh-hosts.conf`.
pub fn prune(dir: &Path) -> Result<(), CliError> {
    let _lock = lock(dir)?;
    let leases = drop_expired(dir, read_leases(dir).map_err(CliError::failure)?)?;
    save_leases(dir, &leases)?;
    write_hosts_conf(dir, &leases)
}

/// `known_hosts` of one lease: `asm-target-<tid> <key>` per key of each target.
pub fn render_known_hosts(lease: &LocalSshLease) -> String {
    let mut out = String::new();
    let mut seen = HashSet::new();
    for t in &lease.targets {
        for key in &t.host_keys {
            let line = format!("asm-target-{} {key}\n", t.target_id);
            if seen.insert(line.clone()) {
                out.push_str(&line);
            }
        }
    }
    out
}

/// A path as one ssh_config argument: quoted, with `%` escaped (ssh expands tokens
/// in these options).
pub fn config_path(path: &Path) -> Result<String, CliError> {
    match path.to_str() {
        Some(p) if !p.contains(|c: char| c == '"' || c.is_control()) => {
            Ok(format!("\"{}\"", p.replace('%', "%%")))
        }
        _ => Err(CliError::failure(format!(
            "{} cannot be used in an ssh config",
            path.display()
        ))),
    }
}

/// The `Host` block of one target of one lease, matching its name and, when `alias`,
/// its address. Names and addresses were validated, so they hold no whitespace, quotes
/// or pattern characters.
pub fn render_block(
    dir: &Path,
    lease: &LocalSshLease,
    t: &SshTargetAccess,
    alias: bool,
) -> Result<String, CliError> {
    let ldir = lease_dir(dir, &lease.lease_id);
    let known_hosts = config_path(&ldir.join(KNOWN_HOSTS_FILE))?;
    let agent = config_path(&dir.join(AGENT_SOCK))?;
    let identity = config_path(&ldir.join(CERT_FILE))?;
    let also = if alias {
        format!(" {}", t.hostname)
    } else {
        String::new()
    };
    Ok(format!(
        "Host {name}{also}\n  HostName {hostname}\n  Port {port}\n  User {login}\n  HostKeyAlias asm-target-{tid}\n  UserKnownHostsFile {known_hosts}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  IdentityAgent {agent}\n  IdentityFile {identity}\n  IdentitiesOnly yes\n  ControlMaster no\n  ControlPath none\n  ForwardAgent no\n",
        name = t.name,
        hostname = t.hostname,
        port = t.port,
        login = t.login,
        tid = t.target_id,
    ))
}

/// Whether `t`'s address can be a `Host` alias in a file with blocks for `targets`
/// (`t` among them): ssh uses the first block that matches, so the alias must not be
/// a target's name or another target's address.
fn address_alias(t: &SshTargetAccess, targets: &[&SshTargetAccess]) -> bool {
    !targets.iter().any(|o| o.name == t.hostname)
        && targets.iter().filter(|o| o.hostname == t.hostname).count() == 1
}

/// `<lease dir>/config`.
pub fn render_config(dir: &Path, lease: &LocalSshLease) -> Result<String, CliError> {
    let targets: Vec<&SshTargetAccess> = lease.targets.iter().collect();
    let mut out = format!("# Written by asm ssh for lease {}.\n", lease.lease_id);
    for t in &lease.targets {
        let _ = write!(out, "\n{}", render_block(dir, lease, t, address_alias(t, &targets))?);
    }
    Ok(out)
}

/// `asm-ssh-hosts.conf`: one block per host name of an unexpired lease, from the lease
/// requested last (ties: the larger lease id).
pub fn render_hosts_conf(dir: &Path, leases: &[LocalSshLease]) -> Result<String, CliError> {
    let now = unix_now();
    let mut newest: BTreeMap<&str, (&LocalSshLease, &SshTargetAccess)> = BTreeMap::new();
    for l in leases.iter().filter(|l| l.expires_at > now) {
        for t in &l.targets {
            let entry = newest.entry(t.name.as_str()).or_insert((l, t));
            if (l.requested_at, &l.lease_id) > (entry.0.requested_at, &entry.0.lease_id) {
                *entry = (l, t);
            }
        }
    }
    let targets: Vec<&SshTargetAccess> = newest.values().map(|(_, t)| *t).collect();
    let mut out = String::from(HOSTS_CONF_HEADER);
    for (l, t) in newest.values() {
        let _ = write!(out, "\n{}", render_block(dir, l, t, address_alias(t, &targets))?);
    }
    Ok(out)
}

/// Rewrite `asm-ssh-hosts.conf` (0600) atomically.
pub fn write_hosts_conf(dir: &Path, leases: &[LocalSshLease]) -> Result<(), CliError> {
    write_file_atomic(dir, HOSTS_CONF, render_hosts_conf(dir, leases)?.as_bytes()).map(drop)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn lease(id: &str, expires_at: i64, name: &str) -> LocalSshLease {
        LocalSshLease {
            lease_id: id.into(),
            expires_at,
            access: SshAccess::Privileged,
            grants: Vec::new(),
            user: None,
            requested_at: 0,
            certificate: format!("{CERT_TYPE} AAAA"),
            targets: vec![SshTargetAccess {
                name: name.into(),
                target_id: "0123abcd".into(),
                login: "asm-priv".into(),
                hostname: "db.example.com".into(),
                port: 22,
                host_keys: vec!["ssh-ed25519 AAAA".into()],
            }],
        }
    }

    const A: &str = "11111111-2222-4333-8444-555555555555";
    const B: &str = "22222222-2222-4333-8444-555555555555";

    #[test]
    fn config_has_one_block_per_target_with_lease_paths() {
        let config = render_config(Path::new("/d"), &lease(A, 100, "db")).unwrap();
        assert!(config.starts_with(&format!("# Written by asm ssh for lease {A}.\n\nHost db db.example.com\n")), "{config}");
        assert!(config.contains("\n  User asm-priv\n"), "{config}");
        assert!(config.contains(&format!("\n  IdentityFile \"/d/{A}/cert.pub\"\n")), "{config}");
        assert!(config.contains(&format!("\n  UserKnownHostsFile \"/d/{A}/known_hosts\"\n")), "{config}");
        assert!(config.contains("\n  IdentityAgent \"/d/agent.sock\"\n"), "{config}");

        let mut same = lease(A, 100, "db");
        same.targets[0].hostname = "db".into();
        let config = render_config(Path::new("/d"), &same).unwrap();
        assert!(config.contains("\nHost db\n  HostName db\n"), "{config}");
    }

    #[test]
    fn hosts_conf_uses_the_newest_request_and_skips_expired_leases() {
        let now = unix_now();
        let mut a = lease(A, now + 100, "db");
        let mut b = lease(B, now + 50, "db");
        a.requested_at = 20;
        b.requested_at = 10;
        let conf = render_hosts_conf(Path::new("/d"), &[a.clone(), b.clone()]).unwrap();
        assert!(conf.starts_with(HOSTS_CONF_HEADER));
        assert_eq!(conf.matches("\nHost ").count(), 1, "{conf}");
        assert!(conf.contains(&format!("/d/{A}/cert.pub")), "{conf}");
        // Equal request times: the larger lease id wins.
        b.requested_at = 20;
        let conf = render_hosts_conf(Path::new("/d"), &[b.clone(), a.clone()]).unwrap();
        assert!(conf.contains(&format!("/d/{B}/cert.pub")), "{conf}");
        // Expired leases are skipped; with none left only the header remains.
        b.expires_at = now - 1;
        let conf = render_hosts_conf(Path::new("/d"), &[b.clone(), a.clone()]).unwrap();
        assert!(conf.contains(&format!("/d/{A}/cert.pub")), "{conf}");
        a.expires_at = now - 1;
        assert_eq!(render_hosts_conf(Path::new("/d"), &[a, b]).unwrap(), HOSTS_CONF_HEADER);
    }

    #[test]
    fn address_aliases_never_shadow_another_block() {
        let now = unix_now();
        // db's address is web's name: only web's block may match `web`.
        let mut a = lease(A, now + 100, "db");
        a.targets[0].hostname = "web".into();
        let mut b = lease(B, now + 100, "web");
        b.targets[0].hostname = "web.example.com".into();
        let conf = render_hosts_conf(Path::new("/d"), &[a.clone(), b.clone()]).unwrap();
        assert!(conf.contains("\nHost db\n  HostName web\n"), "{conf}");
        assert!(conf.contains("\nHost web web.example.com\n"), "{conf}");
        // Two targets at one address: neither block takes it.
        a.targets[0].hostname = "10.0.0.5".into();
        b.targets[0].hostname = "10.0.0.5".into();
        let conf = render_hosts_conf(Path::new("/d"), &[a.clone(), b]).unwrap();
        assert!(conf.contains("\nHost db\n") && conf.contains("\nHost web\n"), "{conf}");
        // The same within one lease's config.
        let web = SshTargetAccess {
            name: "web".into(),
            ..a.targets[0].clone()
        };
        a.targets.push(web);
        let config = render_config(Path::new("/d"), &a).unwrap();
        assert!(config.contains("\nHost db\n") && config.contains("\nHost web\n"), "{config}");
    }

    #[test]
    fn store_writes_config_once_and_never_rolls_a_lease_back() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ssh");
        ensure_private_dir(&dir).unwrap();
        let now = unix_now();
        let first = store(&dir, &lease(A, now + 100, "db")).unwrap();
        assert!(first.requested_at >= now);
        let ldir = lease_dir(&dir, A);
        let config = std::fs::read(ldir.join(CONFIG_FILE)).unwrap();

        let mut later = lease(A, now + 200, "db");
        later.certificate = format!("{CERT_TYPE} BBBB");
        later.targets[0].hostname = "elsewhere".into();
        let stored = store(&dir, &later).unwrap();
        assert_eq!(stored.expires_at, now + 200);
        assert_eq!(stored.requested_at, first.requested_at);
        assert_eq!(std::fs::read(ldir.join(CONFIG_FILE)).unwrap(), config);
        assert_eq!(std::fs::read_to_string(ldir.join(CERT_FILE)).unwrap(), format!("{CERT_TYPE} BBBB\n"));

        // An older response keeps the stored lease.
        let stored = store(&dir, &lease(A, now + 150, "db")).unwrap();
        assert_eq!(stored.expires_at, now + 200);
        assert_eq!(read_leases(&dir).unwrap(), vec![stored]);
        assert_eq!(std::fs::read_to_string(ldir.join(CERT_FILE)).unwrap(), format!("{CERT_TYPE} BBBB\n"));

        // Forgetting removes the folder and the hosts block; the file stays.
        forget_lease(&dir, A).unwrap();
        assert!(!ldir.exists());
        assert!(read_leases(&dir).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(dir.join(HOSTS_CONF)).unwrap(), HOSTS_CONF_HEADER);
    }

    #[test]
    fn prune_removes_expired_leases_and_their_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ssh");
        ensure_private_dir(&dir).unwrap();
        let now = unix_now();
        store(&dir, &lease(A, now + 100, "db")).unwrap();
        store(&dir, &lease(B, now + 100, "web")).unwrap();
        let mut leases = read_leases(&dir).unwrap();
        leases[0].expires_at = now - 1;
        save_leases(&dir, &leases).unwrap();
        prune(&dir).unwrap();
        assert!(!lease_dir(&dir, A).exists());
        assert!(lease_dir(&dir, B).exists());
        let conf = std::fs::read_to_string(dir.join(HOSTS_CONF)).unwrap();
        assert!(conf.contains("\nHost web ") && !conf.contains("\nHost db "), "{conf}");
    }

    #[test]
    fn config_paths_are_quoted_and_escaped() {
        assert_eq!(config_path(Path::new("/a b/%h")).unwrap(), "\"/a b/%%h\"");
        assert!(config_path(Path::new("/a\"b")).is_err());
    }

    #[test]
    fn cert_blob_needs_the_certificate_type() {
        assert_eq!(cert_blob(&format!("{CERT_TYPE} AAEC comment")), Some(vec![0, 1, 2]));
        assert_eq!(cert_blob("ssh-ed25519 AAEC"), None);
        assert_eq!(cert_blob(&format!("{CERT_TYPE} !!")), None);
    }
}
