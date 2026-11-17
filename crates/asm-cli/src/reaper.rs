//! Background reaper (`asm reap`, hidden): deletes the files of a lease when it ends,
//! so an agent that finds a secret file missing knows to run `asm get` again.
//!
//! Commands that leave leases in the manifest start one detached reaper per secrets
//! directory (double fork, new session, stdio on /dev/null). An exclusive `flock` on
//! `<secrets dir>/.reaper.lock` keeps it single. The reaper deletes a lease's files at
//! its `expires_at`, asks the manager every minute which leases are still active
//! (revocations), and exits once the manifest holds no lease.

use crate::api::Api;
use crate::error::CliError;
use crate::files::{Manifest, SecretsDir, default_secrets_path, lock_file};
use asm_proto::error::ErrorCode;
use asm_proto::wire::{LeaseStatus, LeasesResponse};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LOCK_FILE: &str = ".reaper.lock";
/// How often the manager is asked which leases are still active; also the longest sleep.
pub const POLL_INTERVAL: Duration = Duration::from_secs(60);

static DISABLED: AtomicBool = AtomicBool::new(false);

/// `--no-reaper`: this process never starts a reaper.
pub fn disable() {
    DISABLED.store(true, Ordering::Relaxed);
}

/// `--no-reaper` was given, or `$ASM_NO_REAPER` is set to anything but `""` / `0`.
fn disabled() -> bool {
    DISABLED.load(Ordering::Relaxed)
        || std::env::var_os("ASM_NO_REAPER").is_some_and(|v| !v.is_empty() && v != "0")
}

/// The exclusive reaper lock of a secrets directory; released on drop.
pub struct Lock(#[allow(dead_code)] File);

/// Take the reaper lock of `dir` without blocking; `Ok(None)` when another process holds it.
pub fn try_lock(dir: &Path) -> std::io::Result<Option<Lock>> {
    Ok(lock_file(dir, LOCK_FILE, false)?.map(Lock))
}

/// Start a reaper for `dir` unless disabled, the manifest is empty, or one already
/// holds the lock. A failure to start is a warning on stderr: later commands still
/// delete ended leases' files.
pub fn ensure_running(dir: &SecretsDir) {
    if disabled() || !dir.load_manifest().is_ok_and(|m| !m.is_empty()) {
        return;
    }
    let started = match try_lock(dir.root()) {
        Ok(Some(probe)) => {
            drop(probe);
            spawn(dir.root())
        }
        Ok(None) => return,
        Err(e) => Err(e),
    };
    if let Err(e) = started {
        eprintln!(
            "warning: cannot start the background cleanup ({e}); files of ended leases are removed by later asm commands"
        );
    }
}

/// Run `asm reap --dir <dir>` fully detached: the forked child starts a new session
/// and forks again; the intermediate process exits at once and is reaped here, so the
/// reaper is re-parented to init and never becomes our zombie.
fn spawn(dir: &Path) -> std::io::Result<()> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("reap")
        .arg("--dir")
        .arg(dir)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls (setsid, fork, _exit) between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            match libc::fork() {
                -1 => Err(std::io::Error::last_os_error()),
                0 => Ok(()),
                _ => libc::_exit(0),
            }
        });
    }
    cmd.spawn()?.wait().map(drop)
}

/// `asm reap [--dir DIR]`: the reaper process. Exits 0 at once when the directory
/// does not exist or another reaper holds the lock.
pub fn run(dir: Option<PathBuf>) -> Result<(), CliError> {
    let root = match dir {
        Some(d) => d,
        None => default_secrets_path()?,
    };
    if !root.is_dir() {
        return Ok(());
    }
    let dir = SecretsDir::open(root)?;
    let lock = try_lock(dir.root()).map_err(|e| {
        CliError::failure(format!(
            "locking {}: {e}",
            dir.root().join(LOCK_FILE).display()
        ))
    })?;
    let Some(lock) = lock else {
        log("another reaper holds the lock; exiting");
        return Ok(());
    };
    log(&format!("started for {}", dir.root().display()));
    reap(&dir, lock, POLL_INTERVAL, active_leases);
    log("no leases left; exiting");
    Ok(())
}

/// Lease ids the manager reports active; `None` when it cannot say (not paired,
/// network error, other API errors): files then stay until they expire. A rejected
/// token means the host was revoked, and revoking a host revokes all its leases.
fn active_leases() -> Option<HashSet<String>> {
    let host = crate::state::load().ok()??;
    let api = Api::for_host(&host).ok()?;
    match api.get::<LeasesResponse>("/leases") {
        Ok(l) => Some(
            l.leases
                .into_iter()
                .filter(|l| l.status == LeaseStatus::Active)
                .map(|l| l.lease_id)
                .collect(),
        ),
        Err(e) if e.code == Some(ErrorCode::Unauthorized) => {
            log("token rejected (host revoked)");
            Some(HashSet::new())
        }
        Err(e) => {
            log(&format!("lease check failed: {}", e.message));
            None
        }
    }
}

/// The reaper loop: delete expired leases' files at their expiry, reconcile with
/// `fetch_active` every `poll`, return when the manifest is empty (or unreadable).
fn reap(
    dir: &SecretsDir,
    mut lock: Lock,
    poll: Duration,
    mut fetch_active: impl FnMut() -> Option<HashSet<String>>,
) {
    // The command that started us has just synced with the manager.
    let mut next_poll = Instant::now() + poll;
    loop {
        let before = dir.load_manifest().unwrap_or_default();
        if let Err(e) = dir.remove_expired() {
            log(&e.message);
        }
        if Instant::now() >= next_poll {
            if let Some(active) = fetch_active()
                && let Err(e) = dir.reconcile(&active)
            {
                log(&e.message);
            }
            next_poll = Instant::now() + poll;
        }
        let m = match dir.load_manifest() {
            Ok(m) => m,
            Err(e) => {
                log(&e.message);
                return;
            }
        };
        for id in before.keys().filter(|id| !m.contains_key(*id)) {
            log(&format!("removed the files of lease {id}"));
        }
        if m.is_empty() {
            // A command may have added a lease after the read above and seen the
            // lock held: release it, look again, and carry on only if still needed.
            drop(lock);
            match dir.load_manifest() {
                Ok(m) if !m.is_empty() => {}
                _ => return,
            }
            match try_lock(dir.root()) {
                Ok(Some(l)) => lock = l,
                _ => return,
            }
            continue;
        }
        let until_poll = next_poll.saturating_duration_since(Instant::now());
        std::thread::sleep(next_sleep(&m, SystemTime::now(), until_poll));
    }
}

/// Sleep until the earliest expiry or the next poll, at most `POLL_INTERVAL`. An
/// expiry already passed (its deletion failed) waits for the next poll.
fn next_sleep(m: &Manifest, now: SystemTime, until_poll: Duration) -> Duration {
    let earliest = m
        .values()
        .filter_map(|e| e.expires_at.as_deref())
        .filter_map(asm_proto::time::parse_unix)
        .min();
    let until_expiry = earliest
        .and_then(|t| u64::try_from(t).ok())
        .map(|t| UNIX_EPOCH + Duration::from_secs(t))
        .and_then(|t| t.duration_since(now).ok())
        .filter(|d| !d.is_zero());
    until_expiry
        .map_or(until_poll, |d| d.min(until_poll))
        .min(POLL_INTERVAL)
}

/// Append a line to `$ASM_REAPER_LOG` when set (debugging only).
fn log(msg: &str) {
    let Some(path) = std::env::var_os("ASM_REAPER_LOG").filter(|p| !p.is_empty()) else {
        return;
    };
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        let _ = writeln!(
            f,
            "{} asm reap[{}]: {msg}",
            asm_proto::time::now_rfc3339(),
            std::process::id()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::ManifestEntry;
    use asm_proto::wire::LeaseMode;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Mutex};

    const L1: &str = "11111111-2222-4333-8444-555555555555";
    const L2: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn secrets() -> (tempfile::TempDir, SecretsDir) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        (tmp, dir)
    }

    fn add(dir: &SecretsDir, id: &str, file: &str, expires: Option<i64>) {
        let mut m = dir.load_manifest().unwrap();
        fs::write(dir.root().join(file), "asm_x").unwrap();
        m.insert(
            id.into(),
            ManifestEntry {
                mode: LeaseMode::Sentinel,
                expires_at: expires.map(asm_proto::time::fmt_unix),
                paths: vec![file.into()],
            },
        );
        dir.save_manifest(&m).unwrap();
    }

    fn lock(dir: &SecretsDir) -> Lock {
        try_lock(dir.root()).unwrap().unwrap()
    }

    #[test]
    fn deletes_at_expiry_and_exits() {
        let (_tmp, dir) = secrets();
        let expiry = unix_now() + 2;
        add(&dir, L1, "TOKEN", Some(expiry));
        let calls = Arc::new(Mutex::new(0));
        let c = calls.clone();
        reap(&dir, lock(&dir), POLL_INTERVAL, move || {
            *c.lock().unwrap() += 1;
            None
        });
        let done = SystemTime::now();
        let at = UNIX_EPOCH + Duration::from_secs(expiry as u64);
        assert!(done >= at, "not before expiry");
        assert!(
            done.duration_since(at).unwrap() < Duration::from_secs(1),
            "within a second of expiry"
        );
        assert!(!dir.root().join("TOKEN").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
        assert_eq!(*calls.lock().unwrap(), 0, "no poll before the interval");
        // The lock was released on exit.
        assert!(try_lock(dir.root()).unwrap().is_some());
    }

    #[test]
    fn revocation_is_noticed_through_the_manager() {
        let (_tmp, dir) = secrets();
        add(&dir, L1, "A", None);
        add(&dir, L2, "B", Some(unix_now() + 3600));
        let answers = Arc::new(Mutex::new(vec![
            Some(HashSet::from([L2.to_owned()])),
            None, // network error: nothing deleted
            Some(HashSet::from([L1.to_owned(), L2.to_owned()])),
        ]));
        let a = answers.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let root = dir.root().to_path_buf();
        let started = Instant::now();
        reap(&dir, lock(&dir), Duration::from_millis(100), move || {
            s.lock()
                .unwrap()
                .push((root.join("A").exists(), root.join("B").exists()));
            a.lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| Some(HashSet::new()))
        });
        assert!(started.elapsed() < Duration::from_secs(5));
        // Polls: both active, a failed poll keeps both, L1 revoked, then L2 revoked.
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(true, true), (true, true), (true, true), (false, true)]
        );
        assert!(!dir.root().join("A").exists() && !dir.root().join("B").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn exits_at_once_when_nothing_is_left() {
        let (_tmp, dir) = secrets();
        let started = Instant::now();
        reap(&dir, lock(&dir), POLL_INTERVAL, || panic!("no poll"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn lock_admits_one_reaper() {
        let (_tmp, dir) = secrets();
        let held = lock(&dir);
        assert!(try_lock(dir.root()).unwrap().is_none());
        drop(held);
        assert!(try_lock(dir.root()).unwrap().is_some());
    }

    #[test]
    fn never_deletes_outside_the_dir() {
        let (tmp, dir) = secrets();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        let outside = tmp.path().join("outdir");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("f"), "keep").unwrap();
        symlink(&outside, dir.root().join("link")).unwrap();
        let mut m = Manifest::new();
        m.insert(
            L1.into(),
            ManifestEntry {
                mode: LeaseMode::Raw,
                expires_at: Some(asm_proto::time::fmt_unix(unix_now() + 1)),
                paths: vec![
                    "../victim".into(),
                    victim.to_string_lossy().into_owned(),
                    "link/f".into(),
                ],
            },
        );
        m.insert(
            L2.into(),
            ManifestEntry {
                mode: LeaseMode::Raw,
                expires_at: None,
                paths: vec!["a/../../victim".into(), "link".into()],
            },
        );
        dir.save_manifest(&m).unwrap();
        // The expiring lease goes by its expiry (polls fail at first), the other on
        // the first successful poll.
        let mut polls = 0;
        reap(&dir, lock(&dir), Duration::from_millis(50), move || {
            polls += 1;
            (polls > 40).then(HashSet::new)
        });
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read_to_string(outside.join("f")).unwrap(), "keep");
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn sleeps_until_the_earliest_expiry_capped() {
        let now = UNIX_EPOCH + Duration::from_millis(1_000_000_250);
        let entry = |t: Option<i64>| ManifestEntry {
            mode: LeaseMode::Sentinel,
            expires_at: t.map(asm_proto::time::fmt_unix),
            paths: vec![],
        };
        let mut m = Manifest::new();
        m.insert(L1.into(), entry(None));
        let long = Duration::from_secs(600);
        assert_eq!(next_sleep(&m, now, long), POLL_INTERVAL);
        assert_eq!(
            next_sleep(&m, now, Duration::from_secs(7)),
            Duration::from_secs(7)
        );
        m.insert(L2.into(), entry(Some(1_000_005)));
        assert_eq!(next_sleep(&m, now, long), Duration::from_millis(4_750));
        // Already passed (its deletion failed): wait for the next poll.
        m.insert(L2.into(), entry(Some(1_000_000)));
        assert_eq!(
            next_sleep(&m, now, Duration::from_secs(9)),
            Duration::from_secs(9)
        );
    }
}
