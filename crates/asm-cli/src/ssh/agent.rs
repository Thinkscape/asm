//! The asm ssh agent (`asm ssh agent --dir DIR`, hidden): an ssh-agent protocol
//! server on `<dir>/agent.sock` that offers the certificates of unexpired SSH leases
//! and has the manager sign with their keys. The private keys never leave the manager.
//!
//! `asm ssh request` and `asm ssh extend` start one detached agent per directory; an
//! exclusive `flock` on `<dir>/agent.lock` keeps it single. It exits after 60 s without
//! an unexpired lease.

use super::store::{self, AGENT_SOCK, LEASES_FILE};
use crate::api::Api;
use crate::error::CliError;
use crate::files::lock_file;
use crate::reaper::spawn_detached;
use crate::requests::unix_now;
use crate::state;
use asm_proto::error::ErrorCode;
use asm_proto::ssh::{
    MAX_SIGN_DATA, Reader, SshSignRequest, SshSignResponse, b64_decode, b64_encode, put_string,
    put_u32,
};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

const LOCK_FILE: &str = "agent.lock";
/// Largest agent message accepted, without its length prefix.
const MAX_MESSAGE: usize = 256 * 1024;
const IDLE_EXIT: Duration = Duration::from_secs(60);
const ACCEPT_SLEEP: Duration = Duration::from_millis(250);
const RELOAD_EVERY: Duration = Duration::from_secs(1);
const SIGN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long `ensure_running` waits for the socket to accept connections.
const START_WAIT: Duration = Duration::from_secs(3);

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// One lease's certificate as offered to ssh.
struct Identity {
    lease_id: String,
    expires_at: i64,
    blob: Vec<u8>,
}

type Identities = Arc<RwLock<Vec<Identity>>>;
/// Identity of the loaded `leases.json`: (mtime, inode, length); `Some(None)` once
/// loaded while missing, `None` before the first load.
type Stamp = Option<Option<(SystemTime, u64, u64)>>;

/// What every connection shares. The API client is built per sign request, so a new
/// `asm pair` takes effect without restarting the agent.
struct Shared {
    dir: PathBuf,
    identities: Identities,
    loaded: Mutex<Stamp>,
}

/// Start an agent for `dir` unless one holds the lock, then wait until its socket
/// accepts connections, so an ssh started right after finds it. A failure is a
/// warning on stderr.
pub fn ensure_running(dir: &Path) {
    let started = match lock_file(dir, LOCK_FILE, false) {
        Ok(Some(probe)) => {
            drop(probe);
            spawn_detached(&["ssh".into(), "agent".into(), "--dir".into(), dir.into()])
        }
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    };
    if let Err(e) = started {
        eprintln!("warning: cannot start the asm ssh agent ({e}); ssh cannot authenticate");
        return;
    }
    let sock = dir.join(AGENT_SOCK);
    let until = Instant::now() + START_WAIT;
    while UnixStream::connect(&sock).is_err() {
        if Instant::now() >= until {
            eprintln!("warning: the asm ssh agent did not start; ssh cannot authenticate");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `asm ssh agent [--dir DIR]`: the agent process. Exits 0 at once when the
/// directory does not exist or another agent holds the lock.
pub fn run(dir: Option<PathBuf>) -> Result<(), CliError> {
    let dir = match dir {
        Some(d) => d,
        None => super::ssh_dir()?,
    };
    if !dir.is_dir() {
        return Ok(());
    }
    serve_dir(&dir).inspect_err(|e| log(&e.message))
}

fn serve_dir(dir: &Path) -> Result<(), CliError> {
    let failure = |what: &str, path: &Path, e: std::io::Error| {
        CliError::failure(format!("{what} {}: {e}", path.display()))
    };
    let lock_path = dir.join(LOCK_FILE);
    let Some(_lock) = lock_file(dir, LOCK_FILE, false).map_err(|e| failure("locking", &lock_path, e))? else {
        log("another agent holds the lock; exiting");
        return Ok(());
    };
    let shared = Arc::new(Shared {
        dir: dir.to_owned(),
        identities: Arc::new(RwLock::new(Vec::new())),
        loaded: Mutex::new(None),
    });
    let sock = dir.join(AGENT_SOCK);
    match std::fs::remove_file(&sock) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(failure("removing", &sock, e)),
    }
    let listener = UnixListener::bind(&sock).map_err(|e| failure("binding", &sock, e))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| failure("setting permissions of", &sock, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| failure("configuring", &sock, e))?;
    log(&format!("started for {}", dir.display()));

    let mut checked = Instant::now() - RELOAD_EVERY;
    let mut idle_since: Option<Instant> = None;
    loop {
        if checked.elapsed() >= RELOAD_EVERY {
            checked = Instant::now();
            refresh(dir, &shared.identities, &shared.loaded);
            let now = unix_now();
            let (live, expired) = shared.identities.read().map_or((false, false), |ids| {
                (
                    ids.iter().any(|i| i.expires_at > now),
                    ids.iter().any(|i| i.expires_at <= now),
                )
            });
            // Expired hosts leave asm-ssh-hosts.conf; the next refresh drops them here.
            if expired && let Err(e) = store::prune(dir) {
                log(&e.message);
            }
            if live {
                idle_since = None;
            } else if idle_since.get_or_insert_with(Instant::now).elapsed() >= IDLE_EXIT {
                break;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let shared = shared.clone();
                std::thread::spawn(move || serve(stream, &shared));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(ACCEPT_SLEEP),
            Err(e) => {
                log(&format!("accept: {e}"));
                std::thread::sleep(ACCEPT_SLEEP);
            }
        }
    }
    // Still under the lock: a new agent binds only after taking it.
    let _ = std::fs::remove_file(&sock);
    log("no unexpired lease for 60 s; exiting");
    Ok(())
}

/// Reload the identities when `leases.json` changed since the last load.
fn refresh(dir: &Path, identities: &Identities, loaded: &Mutex<Stamp>) {
    let Ok(mut loaded) = loaded.lock() else {
        return;
    };
    let stamp = std::fs::metadata(dir.join(LEASES_FILE))
        .ok()
        .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.ino(), m.len()));
    if *loaded == Some(stamp) {
        return;
    }
    let leases = match store::read_leases(dir) {
        Ok(l) => l,
        Err(e) => {
            log(&e);
            return;
        }
    };
    *loaded = Some(stamp);
    let fresh: Vec<Identity> = leases
        .into_iter()
        .filter_map(|l| {
            Some(Identity {
                blob: store::cert_blob(&l.certificate)?,
                lease_id: l.lease_id,
                expires_at: l.expires_at,
            })
        })
        .collect();
    if let Ok(mut ids) = identities.write() {
        *ids = fresh;
    }
}

/// Answer one client's requests until it disconnects.
fn serve(mut stream: UnixStream, shared: &Shared) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    loop {
        let msg = match read_message(&mut stream) {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                log(&format!("reading a request: {e}"));
                return;
            }
        };
        let reply = match msg.split_first() {
            Some((&SSH_AGENTC_REQUEST_IDENTITIES, [])) => {
                refresh(&shared.dir, &shared.identities, &shared.loaded);
                list_identities(&shared.identities)
            }
            Some((&SSH_AGENTC_SIGN_REQUEST, body)) => {
                refresh(&shared.dir, &shared.identities, &shared.loaded);
                sign(body, shared).unwrap_or_else(|e| {
                    log(&format!("sign: {e}"));
                    vec![SSH_AGENT_FAILURE]
                })
            }
            // Includes extensions such as session-bind@openssh.com, which ssh may fail.
            _ => vec![SSH_AGENT_FAILURE],
        };
        let mut framed = Vec::with_capacity(4 + reply.len());
        put_string(&mut framed, &reply);
        if stream.write_all(&framed).is_err() {
            return;
        }
    }
}

/// One framed message; `Ok(None)` at a clean end of stream.
fn read_message(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("message length {len}"),
        ));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg)?;
    Ok(Some(msg))
}

fn list_identities(identities: &Identities) -> Vec<u8> {
    let Ok(ids) = identities.read() else {
        return vec![SSH_AGENT_FAILURE];
    };
    let now = unix_now();
    let live: Vec<&Identity> = ids.iter().filter(|i| i.expires_at > now).collect();
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(&mut out, live.len() as u32);
    for i in live {
        put_string(&mut out, &i.blob);
        put_string(&mut out, format!("asm-lease-{}", i.lease_id).as_bytes());
    }
    out
}

/// `string key_blob, string data, u32 flags` → `14 string signature`. A lease the
/// manager no longer knows is forgotten here and in the lease files.
fn sign(body: &[u8], shared: &Shared) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(body);
    let parsed = (|| {
        let key = r.string()?;
        let data = r.string()?;
        r.u32()?;
        Some((key, data))
    })();
    let (key, data) = match parsed {
        Some(v) if r.is_empty() => v,
        _ => return Err("malformed sign request".into()),
    };
    if data.len() > MAX_SIGN_DATA {
        return Err(format!("{} bytes to sign is too much", data.len()));
    }
    let now = unix_now();
    let lease_id = shared
        .identities
        .read()
        .map_err(|_| "identities unavailable".to_owned())?
        .iter()
        .find(|i| i.expires_at > now && i.blob == key)
        .map(|i| i.lease_id.clone())
        .ok_or("no unexpired lease has this key")?;
    let api = state::require()
        .and_then(|host| Api::for_host(&host))
        .map_err(|e| format!("lease {lease_id}: {}", e.message))?;
    let resp: SshSignResponse = match api.post_until(
        "/ssh/sign",
        &SshSignRequest {
            lease_id: lease_id.clone(),
            data: b64_encode(data),
        },
        Some(Instant::now() + SIGN_TIMEOUT),
    ) {
        Ok(resp) => resp,
        Err(e) if e.code == Some(ErrorCode::NotFound) => {
            if let Err(err) = store::forget_lease(&shared.dir, &lease_id) {
                log(&err);
            }
            if let Ok(mut ids) = shared.identities.write() {
                ids.retain(|i| i.lease_id != lease_id);
            }
            return Err(format!("lease {lease_id}: {}; forgot it", e.message));
        }
        Err(e) => return Err(format!("lease {lease_id}: {}", e.message)),
    };
    let signature = b64_decode(&resp.signature)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("lease {lease_id}: the manager sent an invalid signature"))?;
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut out, &signature);
    Ok(out)
}

fn log(msg: &str) {
    let Some(path) = std::env::var_os("ASM_SSH_AGENT_LOG").filter(|p| !p.is_empty()) else {
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
            "{} asm ssh-agent[{}]: {msg}",
            asm_proto::time::now_rfc3339(),
            std::process::id()
        );
    }
}
