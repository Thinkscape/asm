//! Bitwarden / Vaultwarden vault through `bw serve` (plan step 4).
//!
//! Each instance has its own `BITWARDENCLI_APPDATA_DIR=<data>/bw/<vault_id>`. Start-up:
//! `bw status`; when logged out (or logged in to another server/account): `bw config server`
//! → `bw login --apikey`; then `bw serve --hostname unix://<dir>/serve.sock` in its own
//! process group, poll `GET /status` up to 10 s. `bw serve` refuses to start while logged
//! out, so login happens before the first spawn.
//!
//! The master password is used once at `POST /unlock` and never stored. For a managed
//! vault only the provider's session key may be retained in the encrypted resume store.
//! `bw serve` validates it against its own locked state on restart. Quitting stops
//! the helper without locking the vault; explicit retirement locks and forgets it.
//!
//! HTTP to serve uses a minimal HTTP/1.1 client over the Unix socket (or loopback TCP in
//! the fallback): `Host: localhost:8087`, never an `Origin` header (serve answers 403),
//! `Connection: close`. A hand-rolled client keeps this provider free of a second async
//! runtime and works identically for both transports.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{
    AddTarget, BitwardenConfig, BitwardenSecrets, CollectionInfo, SecretKind, SecretMeta,
    VaultConfig, VaultProvider, VaultStatus,
};
use crate::error::{CoreError, Result};
use crate::manager::resume::ResumeStore;
use crate::paths::{DataDirs, ensure_private_dir};

const SERVE_WAIT: Duration = Duration::from_secs(10);
const CLI_TIMEOUT: Duration = Duration::from_secs(90);
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
/// Explicit retirement's `POST /lock` is best effort.
const LOCK_TIMEOUT: Duration = Duration::from_secs(3);
/// `sun_path` is 104 bytes on macOS, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 103;
const TCP_NOTE: &str = "bw serve listens on 127.0.0.1 (reachable by other local processes); restart cannot resume this session";
const RESUME_NAMESPACE: &str = "bitwarden_session";
const AUTH_REJECTED: &str = "Bitwarden rejected the vault session";

/// Default bw path: first existing of /opt/homebrew/bin/bw, /usr/local/bin/bw.
pub fn default_bw_path() -> Option<String> {
    ["/opt/homebrew/bin/bw", "/usr/local/bin/bw"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Unix(PathBuf),
    Tcp(u16),
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

impl Endpoint {
    fn connect(&self, timeout: Duration) -> std::io::Result<Box<dyn Stream>> {
        Ok(match self {
            Endpoint::Unix(p) => {
                let s = UnixStream::connect(p)?;
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                Box::new(s)
            }
            Endpoint::Tcp(port) => {
                let s = TcpStream::connect_timeout(
                    &([127, 0, 0, 1], *port).into(),
                    Duration::from_secs(5).min(timeout),
                )?;
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                Box::new(s)
            }
        })
    }

    /// One request; returns status code and body.
    fn http(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> std::io::Result<(u16, Vec<u8>)> {
        let mut s = self.connect(timeout)?;
        let body = body.map(|b| serde_json::to_vec(b).expect("json value serialises"));
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:8087\r\nAccept: application/json\r\nConnection: close\r\n"
        );
        if let Some(b) = &body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        } else if method != "GET" {
            req.push_str("Content-Length: 0\r\n");
        }
        req.push_str("\r\n");
        let mut out = req.into_bytes();
        if let Some(b) = body {
            out.extend_from_slice(&b);
        }
        s.write_all(&out)?;
        s.flush()?;
        // Read until the message is complete, not until EOF: `bw serve` keeps some
        // connections open after the response despite `Connection: close` (seen on
        // `POST /unlock`), and waiting for EOF then blocks until the read timeout.
        let mut raw = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = s.read(&mut buf)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if response_complete(&raw) {
                break;
            }
        }
        parse_http_response(&raw)
    }
}

fn bad_response(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bw serve: {m}"))
}

/// Whether `raw` holds a whole response: headers plus `Content-Length` bytes, or a
/// chunked body through its final `0` chunk. Without either, only EOF ends it.
fn response_complete(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&raw[..head_end]) else {
        return true; // parse_http_response reports it
    };
    let body = &raw[head_end + 4..];
    for l in head.split("\r\n").skip(1) {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        if k == "transfer-encoding" && v.contains("chunked") {
            return decode_chunked(body).is_ok();
        }
        if k == "content-length" {
            return v.parse::<usize>().map_or(true, |n| body.len() >= n);
        }
    }
    false
}

fn parse_http_response(raw: &[u8]) -> std::io::Result<(u16, Vec<u8>)> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad_response("truncated response"))?;
    let head =
        std::str::from_utf8(&raw[..head_end]).map_err(|_| bad_response("non-UTF-8 headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad_response("bad status line"))?;
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if k == "content-length" {
                length = v.parse().ok();
            }
        }
    }
    let rest = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(n) = length {
        rest.get(..n)
            .ok_or_else(|| bad_response("truncated body"))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok((code, body))
}

fn decode_chunked(mut b: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let le = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| bad_response("bad chunk"))?;
        let size_str = std::str::from_utf8(&b[..le]).map_err(|_| bad_response("bad chunk size"))?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad_response("bad chunk size"))?;
        b = &b[le + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(
            b.get(..size)
                .ok_or_else(|| bad_response("truncated chunk"))?,
        );
        b = b
            .get(size + 2..)
            .ok_or_else(|| bad_response("truncated chunk"))?;
    }
}

/// Errors from `bw serve` responses (`{"success":false,"message":…}`).
fn bw_error(message: &str) -> CoreError {
    if message
        .trim_end_matches('.')
        .eq_ignore_ascii_case("not found")
    {
        CoreError::not_found("the Bitwarden item no longer exists")
    } else {
        CoreError::vault_unavailable(format!("bw: {message}"))
    }
}

/// Call serve and unwrap the `{"success":…,"data":…}` envelope.
fn call(ep: &Endpoint, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    call_timeout(ep, method, path, body, HTTP_TIMEOUT)
}

fn call_timeout(
    ep: &Endpoint,
    method: &str,
    path: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<Value> {
    let (code, bytes) = ep
        .http(method, path, body, timeout)
        .map_err(|e| CoreError::vault_unavailable(format!("bw serve unreachable: {e}")))?;
    if code == 401 {
        return Err(CoreError::vault_unavailable(AUTH_REJECTED));
    }
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CoreError::vault_unavailable(format!(
            "bw serve answered HTTP {code} with a non-JSON body"
        ))
    })?;
    if (200..300).contains(&code) && v.get("success").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("data").cloned().unwrap_or(Value::Null))
    } else {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("request failed");
        Err(bw_error(msg))
    }
}

fn list_data(v: &Value) -> Vec<Value> {
    v.get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Only UUID-shaped ids go into request paths.
fn check_id(id: &str) -> Result<()> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
        Ok(())
    } else {
        Err(CoreError::not_found("unknown Bitwarden item id"))
    }
}

// ---------------------------------------------------------------------------
// Item mapping (pure; unit-tested)
// ---------------------------------------------------------------------------

const TYPE_LOGIN: i64 = 1;
const TYPE_SECURE_NOTE: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Username,
    Password,
    /// Index into `item.fields`.
    Custom(usize),
    Notes,
    /// `login.totp`: the authenticator key; [`BitwardenProvider::read`] yields the
    /// current code, never the key.
    Totp,
}

/// Reserved field name for the generated one-time code of a login item.
const TOTP_FIELD: &str = "totp";

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_str()
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

/// Exposed fields of an item in order: `(field name, where it lives, value)`. The value
/// of [`Source::Totp`] is the authenticator key; it must be mapped before leaving.
fn field_sources(item: &Value) -> Vec<(String, Source, String)> {
    let mut out: Vec<(String, Source, String)> = Vec::new();
    let ty = item.get("type").and_then(Value::as_i64).unwrap_or(0);
    if ty != TYPE_LOGIN && ty != TYPE_SECURE_NOTE {
        return out;
    }
    let push = |name: &str, src: Source, value: &str, out: &mut Vec<(String, Source, String)>| {
        if !out.iter().any(|(n, _, _)| n == name) {
            out.push((name.to_owned(), src, value.to_owned()));
        }
    };
    if ty == TYPE_LOGIN {
        if let Some(u) = non_empty(str_at(item, &["login", "username"])) {
            push("username", Source::Username, u, &mut out);
        }
        if let Some(p) = non_empty(str_at(item, &["login", "password"])) {
            push("password", Source::Password, p, &mut out);
        }
        if let Some(k) = non_empty(str_at(item, &["login", "totp"]))
            && crate::totp::parse(k).is_ok()
        {
            push(TOTP_FIELD, Source::Totp, k, &mut out);
        }
    }
    if let Some(fields) = item.get("fields").and_then(Value::as_array) {
        for (i, f) in fields.iter().enumerate() {
            let ft = f.get("type").and_then(Value::as_i64);
            if !matches!(ft, Some(0) | Some(1)) {
                continue;
            }
            if let (Some(name), Some(value)) = (
                non_empty(str_at(f, &["name"])),
                non_empty(str_at(f, &["value"])),
            ) && name != TOTP_FIELD
            {
                push(name, Source::Custom(i), value, &mut out);
            }
        }
    }
    if ty == TYPE_SECURE_NOTE
        && let Some(n) = non_empty(str_at(item, &["notes"]))
    {
        push("notes", Source::Notes, n, &mut out);
    }
    out
}

/// Host of a login URI (`https://host:port/path`, or a bare `host/path`); other schemes are ignored.
fn uri_host(uri: &str) -> Option<String> {
    let s = uri.trim();
    let rest = match s.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return None;
            }
            rest
        }
        None => s,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if hostport.starts_with('[') {
        return None;
    }
    let host = hostport.split(':').next()?;
    asm_proto::rules::normalize_host_pattern(host).ok()
}

fn map_item(item: &Value) -> Option<SecretMeta> {
    let id = item.get("id").and_then(Value::as_str)?;
    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
    let fields: Vec<String> = field_sources(item).into_iter().map(|(n, _, _)| n).collect();
    if fields.is_empty() {
        return None;
    }
    let ty = item.get("type").and_then(Value::as_i64).unwrap_or(0);
    let kind = if ty == TYPE_LOGIN {
        SecretKind::Login
    } else if fields.len() == 1 {
        SecretKind::Single
    } else {
        SecretKind::Multi
    };
    let mut uri_hosts: Vec<String> = Vec::new();
    if let Some(uris) = item.pointer("/login/uris").and_then(Value::as_array) {
        for u in uris {
            if let Some(h) = u.get("uri").and_then(Value::as_str).and_then(uri_host)
                && !uri_hosts.contains(&h)
            {
                uri_hosts.push(h);
            }
        }
    }
    Some(SecretMeta {
        key: id.to_owned(),
        name: name.to_owned(),
        kind,
        fields,
        uri_hosts,
    })
}

/// Whether the item is exposed: in an exposed collection, or personal while the flag is on.
fn is_visible(item: &Value, cfg: &BitwardenConfig) -> bool {
    let org = item.get("organizationId").filter(|v| !v.is_null());
    if org.is_none() && cfg.personal {
        return true;
    }
    item.get("collectionIds")
        .and_then(Value::as_array)
        .is_some_and(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .any(|c| cfg.collections.iter().any(|e| e == c))
        })
}

/// Set `field` of a fetched item to `value` in place.
fn set_field(item: &mut Value, field: &str, value: &str) -> Result<()> {
    if field == TOTP_FIELD {
        return Err(CoreError::invalid(
            "totp is generated from the item's authenticator key and cannot be updated",
        ));
    }
    let src = field_sources(item)
        .into_iter()
        .find(|(n, _, _)| n == field)
        .map(|(_, s, _)| s)
        .or_else(|| {
            // Writing a currently empty login username/password is allowed too.
            let ty = item.get("type").and_then(Value::as_i64);
            match (ty, field) {
                (Some(TYPE_LOGIN), "username") => Some(Source::Username),
                (Some(TYPE_LOGIN), "password") => Some(Source::Password),
                _ => None,
            }
        })
        .ok_or_else(|| CoreError::invalid(format!("this Bitwarden item has no field {field:?}")))?;
    let v = Value::String(value.to_owned());
    match src {
        Source::Username | Source::Password => {
            let login = item.get_mut("login").filter(|l| l.is_object());
            let login = match login {
                Some(l) => l,
                None => {
                    item["login"] = json!({});
                    &mut item["login"]
                }
            };
            login[if src == Source::Username {
                "username"
            } else {
                "password"
            }] = v;
        }
        Source::Custom(i) => item["fields"][i]["value"] = v,
        Source::Notes => item["notes"] = v,
        Source::Totp => unreachable!("totp is rejected above"),
    }
    Ok(())
}

/// `(field, value)` pairs of an item as handed out at `now`: a login's authenticator key
/// becomes its current TOTP code.
fn field_values(item: &Value, now: u64) -> Vec<(String, String)> {
    field_sources(item)
        .into_iter()
        .filter_map(|(n, src, v)| match src {
            Source::Totp => crate::totp::parse(&v)
                .ok()
                .map(|key| (n, crate::totp::current_code(&key, now))),
            _ => Some((n, v)),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// bw CLI and serve process
// ---------------------------------------------------------------------------

struct Instance {
    bw: String,
    dir: PathBuf,
}

/// Output lines kept for error messages.
type LogTail = Arc<Mutex<VecDeque<String>>>;

fn push_tail(tail: &LogTail, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut t = tail.lock().unwrap_or_else(|p| p.into_inner());
    if t.len() >= 50 {
        t.pop_front();
    }
    t.push_back(line.chars().take(500).collect());
}

fn tail_text(tail: &LogTail, n: usize) -> String {
    let t = tail.lock().unwrap_or_else(|p| p.into_inner());
    let skip = t.len().saturating_sub(n);
    t.iter().skip(skip).cloned().collect::<Vec<_>>().join("; ")
}

fn drain(r: impl Read + Send + 'static, tail: LogTail) {
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            match line {
                Ok(l) => push_tail(&tail, &l),
                Err(_) => break,
            }
        }
    });
}

impl Instance {
    fn command(&self) -> Command {
        let mut c = Command::new(&self.bw);
        for k in [
            "BW_SESSION",
            "BW_CLIENTID",
            "BW_CLIENTSECRET",
            "BW_PASSWORD",
            "BW_NOINTERACTION",
            "BW_RAW",
            "BW_PRETTY",
            "BW_RESPONSE",
            "BW_QUIET",
        ] {
            c.env_remove(k);
        }
        let mut path = String::new();
        if let Some(parent) = Path::new(&self.bw).parent() {
            path.push_str(&parent.to_string_lossy());
            path.push(':');
        }
        path.push_str("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
        c.env("PATH", path)
            .env("BITWARDENCLI_APPDATA_DIR", &self.dir)
            .env("BW_NOINTERACTION", "true")
            .stdin(Stdio::null());
        c
    }

    /// Run a bw CLI command to completion (with timeout); Err carries bw's output.
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
        let mut c = self.command();
        c.args(args)
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = c
            .spawn()
            .map_err(|e| CoreError::vault_unavailable(format!("cannot run {}: {e}", self.bw)))?;
        let out_tail: LogTail = Arc::default();
        let err_tail: LogTail = Arc::default();
        let mut stdout = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        drain(err, err_tail.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let deadline = Instant::now() + CLI_TIMEOUT;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() >= deadline {
                kill_group(&mut child);
                return Err(CoreError::vault_unavailable(format!(
                    "bw {} timed out",
                    args[0]
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stdout = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        for l in stdout.lines() {
            push_tail(&out_tail, l);
        }
        if status.success() {
            Ok(stdout)
        } else {
            let mut msg = tail_text(&err_tail, 5);
            if msg.is_empty() {
                msg = tail_text(&out_tail, 5);
            }
            if msg.is_empty() {
                msg = format!("exit status {status}");
            }
            Err(CoreError::vault_unavailable(format!(
                "bw {}: {msg}",
                args[0]
            )))
        }
    }

    fn status(&self) -> Result<Value> {
        let out = self.run(&["status"], &[])?;
        out.lines()
            .rev()
            .find(|l| l.trim_start().starts_with('{'))
            .and_then(|l| serde_json::from_str(l).ok())
            .ok_or_else(|| CoreError::vault_unavailable("bw status: unexpected output"))
    }

    fn pid_file(&self) -> PathBuf {
        self.dir.join("serve.pid")
    }

    /// Kill a `bw serve` left behind by a crashed manager (its process group id is its pid).
    fn kill_stale_serve(&self) {
        let pf = self.pid_file();
        let Ok(text) = std::fs::read_to_string(&pf) else {
            return;
        };
        let _ = std::fs::remove_file(&pf);
        let Ok(pid) = text.trim().parse::<i32>() else {
            return;
        };
        if pid <= 1 {
            return;
        }
        let Ok(out) = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
        else {
            return;
        };
        let cmd = String::from_utf8_lossy(&out.stdout);
        if cmd.contains("serve") && cmd.contains(&*self.dir.to_string_lossy()) {
            unsafe {
                libc::killpg(pid, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(300));
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
        }
    }

    fn spawn_serve(&self, endpoint: &Endpoint, session: Option<&str>) -> Result<Serve> {
        let hostname_args: Vec<String> = match endpoint {
            Endpoint::Unix(p) => {
                let _ = std::fs::remove_file(p);
                vec!["--hostname".into(), format!("unix://{}", p.display())]
            }
            Endpoint::Tcp(port) => vec![
                "--hostname".into(),
                "127.0.0.1".into(),
                "--port".into(),
                port.to_string(),
            ],
        };
        let mut c = self.command();
        if let Some(session) = session {
            // This is bw's documented hand-off. Never put the key in argv.
            c.env("BW_SESSION", session);
        }
        c.arg("serve")
            .args(&hostname_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = c
            .spawn()
            .map_err(|e| CoreError::vault_unavailable(format!("cannot run {}: {e}", self.bw)))?;
        let _ = std::fs::write(self.pid_file(), child.id().to_string());
        Ok(Serve {
            child,
            endpoint: endpoint.clone(),
            pid_file: self.pid_file(),
            stopped: false,
        })
    }
}

fn kill_group(child: &mut Child) {
    let pid = child.id() as i32;
    unsafe {
        libc::killpg(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::killpg(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

struct Serve {
    child: Child,
    endpoint: Endpoint,
    pid_file: PathBuf,
    stopped: bool,
}

impl Serve {
    fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(st)) => Some(format!("bw serve exited ({st})")),
            Ok(None) => None,
            Err(e) => Some(format!("bw serve: {e}")),
        }
    }

    /// Poll `GET /status` until serve answers.
    fn wait_ready(&mut self) -> Result<Value> {
        let deadline = Instant::now() + SERVE_WAIT;
        loop {
            if let Some(m) = self.exited() {
                return Err(CoreError::vault_unavailable(m));
            }
            match call_timeout(&self.endpoint, "GET", "/status", None, Duration::from_secs(2)) {
                Ok(v) => return Ok(v),
                Err(e) if auth_rejected(&e) => return Err(e),
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(CoreError::vault_unavailable(
                    "bw serve did not answer within 10 s",
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn stop(&mut self) {
        if std::mem::replace(&mut self.stopped, true) {
            return;
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            kill_group(&mut self.child);
        }
        if let Endpoint::Unix(p) = &self.endpoint {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_file(&self.pid_file);
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        self.stop();
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

fn norm_url(u: &str) -> String {
    u.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn serve_status(data: &Value) -> &Value {
    data.get("template").unwrap_or(&Value::Null)
}

fn valid_session_key(key: &str) -> bool {
    // bw generates a 64-byte base64 symmetric session key, not an API token.
    let mut decoded = [0; 66];
    key.len() == 88 && matches!(STANDARD.decode_slice(key, &mut decoded), Ok(64))
}

fn auth_rejected(e: &CoreError) -> bool {
    matches!(
        e.message.as_str(),
        AUTH_REJECTED
            | "bw: Vault is locked."
            | "bw: You are not logged in."
            | "bw: Syncing failed: Refresh Access token error"
    )
}

#[derive(Serialize, Deserialize)]
struct SavedSession {
    key: String,
    user_id: String,
    connection: [u8; 32],
}

impl Drop for SavedSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

struct SessionStore {
    store: Arc<ResumeStore>,
    vault_id: String,
}

enum UnlockOutcome {
    Complete(Option<String>),
    Pending(Receiver<Result<Option<String>>>),
}

struct PendingUnlock {
    result: Receiver<Result<Option<String>>>,
    user_id: String,
}

pub(crate) fn forget_session(store: &ResumeStore, vault_id: &str) -> Result<()> {
    store.remove(RESUME_NAMESPACE, vault_id)
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

struct State {
    serve: Option<Serve>,
    stopped: bool,
    pending_unlock: Option<PendingUnlock>,
    session_revision: u64,
    status: VaultStatus,
    note: Option<String>,
}

pub struct BitwardenVault {
    dir: PathBuf,
    /// Exposure fields may change in place (`reconfigure`); connection fields never do.
    cfg: RwLock<BitwardenConfig>,
    secrets: BitwardenSecrets,
    resume: Option<SessionStore>,
    state: Mutex<State>,
    /// Serialises start/stop.
    lifecycle: Mutex<()>,
}

impl BitwardenVault {
    /// Spawns `bw serve`, logging in as needed (plan step 4). The vault is `Locked` until
    /// `unlock`. Errors carry bw's stderr.
    pub fn start(
        dirs: &DataDirs,
        vault_id: &str,
        cfg: BitwardenConfig,
        secrets: BitwardenSecrets,
    ) -> Result<Self> {
        let v = Self::new(dirs.bw_vault(vault_id), cfg, secrets, None);
        v.ensure_running()?;
        Ok(v)
    }

    /// Like `start`, but a failure leaves a provider whose status is `Error(<message>)`;
    /// `sync()` retries the start.
    pub fn start_or_error(
        dirs: &DataDirs,
        vault_id: &str,
        cfg: BitwardenConfig,
        secrets: BitwardenSecrets,
    ) -> Self {
        Self::start_with_resume(dirs, vault_id, cfg, secrets, None)
    }

    pub(crate) fn start_with_resume(
        dirs: &DataDirs,
        vault_id: &str,
        cfg: BitwardenConfig,
        secrets: BitwardenSecrets,
        resume: Option<Arc<ResumeStore>>,
    ) -> Self {
        let v = Self::new(
            dirs.bw_vault(vault_id),
            cfg,
            secrets,
            resume.map(|store| SessionStore { store, vault_id: vault_id.to_owned() }),
        );
        let _ = v.ensure_running();
        v
    }

    fn new(
        dir: PathBuf,
        cfg: BitwardenConfig,
        secrets: BitwardenSecrets,
        resume: Option<SessionStore>,
    ) -> Self {
        BitwardenVault {
            dir,
            cfg: RwLock::new(cfg),
            secrets,
            resume,
            state: Mutex::new(State {
                serve: None,
                stopped: false,
                session_revision: 0,
                pending_unlock: None,
                status: VaultStatus::Error("not started".into()),
                note: None,
            }),
            lifecycle: Mutex::new(()),
        }
    }

    /// The bw CLI for this instance; the path is resolved on every start.
    fn instance(&self) -> Result<Instance> {
        let bw = self
            .cfg()
            .bw_path
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(default_bw_path)
            .ok_or_else(|| {
                CoreError::vault_unavailable(
                    "bw not found (install the Bitwarden CLI or set its path)",
                )
            })?;
        if !Path::new(&bw).exists() {
            return Err(CoreError::vault_unavailable(format!(
                "bw not found at {bw}"
            )));
        }
        Ok(Instance {
            bw,
            dir: self.dir.clone(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cfg(&self) -> RwLockReadGuard<'_, BitwardenConfig> {
        self.cfg.read().unwrap_or_else(|p| p.into_inner())
    }

    fn set_status(&self, s: VaultStatus) {
        let mut state = self.state();
        if s == VaultStatus::Ready {
            state.session_revision = state.session_revision.wrapping_add(1);
        }
        state.status = s;
    }

    /// Start (or restart) serve. Only the provider can accept a saved session.
    fn ensure_running(&self) -> Result<()> {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        self.restart_serve_held().map(|_| ())
    }

    /// `restart_serve` with the outcome recorded as the vault status. Caller holds
    /// `lifecycle`.
    fn restart_serve_held(&self) -> Result<Endpoint> {
        if self.state().stopped {
            return Err(CoreError::vault_unavailable("vault provider stopped"));
        }
        match self.restart_serve() {
            Ok((ep, status)) => {
                self.set_status(status);
                Ok(ep)
            }
            Err(e) => {
                self.set_status(VaultStatus::Error(e.message.clone()));
                Err(e)
            }
        }
    }

    fn matches_account(&self, status: &Value) -> bool {
        let cfg = self.cfg();
        self.matches_server(status, &cfg.server_url)
            && (cfg.email.trim().is_empty()
                || str_at(status, &["userEmail"])
                    .is_some_and(|email| email.eq_ignore_ascii_case(cfg.email.trim())))
    }

    fn matches_server(&self, status: &Value, server_url: &str) -> bool {
        match str_at(status, &["serverUrl"]) {
            Some(url) => norm_url(url) == norm_url(server_url),
            // bw's built-in US environment has no base URL.
            None => matches!(norm_url(server_url).as_str(), "https://bitwarden.com" | "bitwarden.com"),
        }
    }

    fn connection(&self, bw: &str) -> [u8; 32] {
        let cfg = self.cfg();
        let mut digest = Sha256::new();
        for part in [
            cfg.server_url.as_str(), cfg.email.as_str(), cfg.client_id.as_str(),
            bw, self.secrets.client_secret.as_str(),
        ] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
        digest.finalize().into()
    }

    fn clear_session(&self) -> Result<()> {
        if let Some(resume) = &self.resume {
            forget_session(&resume.store, &resume.vault_id)?;
        }
        Ok(())
    }

    /// Determine the previously logged-in provider identity before consulting resume state.
    fn login_if_needed(&self, inst: &Instance) -> Result<Option<String>> {
        let st = inst.status()?;
        let status = str_at(&st, &["status"]);
        if matches!(status, Some("locked" | "unlocked")) && self.matches_account(&st) {
            return Ok(str_at(&st, &["userId"]).map(str::to_owned));
        }
        // Reauthentication can never revive an old decryption session.
        self.clear_session()?;
        let cfg = self.cfg();
        let server_url = cfg.server_url.trim();
        if matches!(status, Some("locked" | "unlocked")) {
            inst.run(&["logout"], &[])?;
        }
        if !self.matches_server(&st, server_url) {
            inst.run(&["config", "server", server_url], &[])?;
        }
        inst.run(
            &["login", "--apikey"],
            &[
                ("BW_CLIENTID", cfg.client_id.trim()),
                ("BW_CLIENTSECRET", &self.secrets.client_secret),
            ],
        )?;
        Ok(None)
    }

    /// Restore only when the provider accepts the key and verifies the same active account.
    /// Caller holds `lifecycle`.
    fn restart_serve(&self) -> Result<(Endpoint, VaultStatus)> {
        let old = {
            let mut state = self.state();
            state.status = VaultStatus::Error("bw serve restarting".into());
            state.pending_unlock = None;
            state.serve.take()
        };
        drop(old);
        let inst = self.instance()?;
        ensure_private_dir(&inst.dir)?;
        inst.kill_stale_serve();
        let user_id = self.login_if_needed(&inst)?;
        let session = if let Some(resume) = &self.resume {
            match resume.store.get::<SavedSession>(RESUME_NAMESPACE, &resume.vault_id)? {
                Some(entry)
                    if user_id.as_deref() == Some(entry.user_id.as_str())
                        && Path::new(&inst.bw).is_absolute()
                        && entry.connection == self.connection(&inst.bw)
                        && valid_session_key(&entry.key) =>
                {
                    Some(entry)
                }
                Some(_) => {
                    self.clear_session()?;
                    None
                }
                None => None,
            }
        } else {
            None
        };

        let sock = inst.dir.join("serve.sock");
        let mut note = None;
        let mut serve = None;
        let mut first_err = None;
        if sock.as_os_str().len() <= MAX_SOCKET_PATH {
            let mut s = inst.spawn_serve(
                &Endpoint::Unix(sock),
                session.as_ref().map(|s| s.key.as_str()),
            )?;
            match s.wait_ready() {
                Ok(st) => serve = Some((s, st)),
                Err(e) => {
                    if session.is_some() {
                        if auth_rejected(&e) {
                            self.clear_session()?;
                        }
                        // No TCP fallback with a live key or an indeterminate provider result.
                        return Err(e);
                    }
                    s.stop();
                    first_err = Some(e);
                }
            }
        }
        if serve.is_none() {
            let mut s = inst.spawn_serve(&Endpoint::Tcp(free_port()?), None)?;
            match s.wait_ready() {
                Ok(st) => {
                    note = Some(TCP_NOTE.to_owned());
                    serve = Some((s, st));
                }
                Err(e) => {
                    s.stop();
                    return Err(first_err.unwrap_or(e));
                }
            }
        }
        let (mut s, mut st) = serve.expect("serve started");
        let accepted = session.as_ref().is_some_and(|session| {
            str_at(serve_status(&st), &["status"]) == Some("unlocked")
                && str_at(serve_status(&st), &["userId"]) == Some(session.user_id.as_str())
                && self.matches_account(serve_status(&st))
        });
        if session.is_some() && matches!(&s.endpoint, Endpoint::Unix(_)) && !accepted {
            let endpoint = s.endpoint.clone();
            if str_at(serve_status(&st), &["status"]) == Some("unlocked") {
                let _ = call_timeout(&endpoint, "POST", "/lock", None, LOCK_TIMEOUT);
            }
            drop(s);
            self.clear_session()?;
            s = inst.spawn_serve(&endpoint, None)?;
            st = s.wait_ready()?;
        }
        if str_at(serve_status(&st), &["status"]) == Some("unauthenticated") {
            // Session expired between `bw status` and serve: log in again once.
            let endpoint = s.endpoint.clone();
            self.clear_session()?;
            drop(s);
            inst.run(&["logout"], &[]).ok();
            self.login_if_needed(&inst)?;
            s = inst.spawn_serve(&endpoint, None)?;
            st = s.wait_ready()?;
        }
        let status = match str_at(serve_status(&st), &["status"]) {
            Some("unlocked") if self.resume.is_none() || accepted => VaultStatus::Ready,
            Some("unlocked") => {
                call_timeout(&s.endpoint, "POST", "/lock", None, LOCK_TIMEOUT)?;
                VaultStatus::Locked
            }
            Some("locked") => VaultStatus::Locked,
            _ => {
                return Err(CoreError::vault_unavailable("bw serve reports an unexpected status"));
            }
        };
        let endpoint = s.endpoint.clone();
        let mut state = self.state();
        state.serve = Some(s);
        state.note = note;
        Ok((endpoint, status))
    }

    /// Unlock serve with the master password (`POST /unlock`); the password is not kept.
    /// Starts serve first when it is not running.
    pub fn unlock(&self, master_password: &str) -> Result<()> {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let running = {
            let mut st = self.state();
            if st.stopped {
                return Err(CoreError::vault_unavailable("vault provider stopped"));
            }
            if let Some(msg) = st.serve.as_mut().and_then(Serve::exited) {
                st.serve = None;
                st.status = VaultStatus::Error(msg);
            }
            st.serve
                .as_ref()
                .map(|s| (s.endpoint.clone(), st.status == VaultStatus::Ready))
        };
        let ep = match running {
            Some((_, true)) => return Ok(()),
            Some((ep, false)) => ep,
            None => {
                let ep = self.restart_serve_held()?;
                if self.state().status == VaultStatus::Ready {
                    return Ok(());
                }
                ep
            }
        };
        let outcome = Self::unlock_serve(&ep, master_password)?;
        if self.resume.is_some() && matches!(&ep, Endpoint::Unix(_)) {
            let provider = call_timeout(&ep, "GET", "/status", None, Duration::from_secs(5))?;
            let status = serve_status(&provider);
            if str_at(status, &["status"]) != Some("unlocked") || !self.matches_account(status) {
                let _ = call_timeout(&ep, "POST", "/lock", None, LOCK_TIMEOUT);
                return Err(CoreError::vault_unavailable("Bitwarden did not verify the unlocked account"));
            }
            if let Some(user_id) = str_at(status, &["userId"]).filter(|s| !s.is_empty()) {
                match outcome {
                    UnlockOutcome::Complete(key) => self.persist_unlock(user_id, key),
                    UnlockOutcome::Pending(result) => {
                        self.state().pending_unlock = Some(PendingUnlock {
                            result,
                            user_id: user_id.to_owned(),
                        });
                    }
                }
            }
        }
        self.set_status(VaultStatus::Ready);
        Ok(())
    }
    /// `POST /unlock`, finished by whichever comes first: its response, or `/status`
    /// reporting `unlocked`. bw 2026.2.0 sets the user key and then runs post-unlock
    /// steps (key-connector check, KDF migrations) before answering; on a real
    /// Vaultwarden account those steps were seen to never answer, leaving the vault
    /// unlocked behind a request that blocks until the read timeout. `unlocked` is only
    /// reported after the password checked out, so it is a sound success signal.
    fn unlock_serve(ep: &Endpoint, master_password: &str) -> Result<UnlockOutcome> {
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let ep = ep.clone();
            let body = json!({ "password": master_password });
            std::thread::spawn(move || {
                let result = call(&ep, "POST", "/unlock", Some(&body))
                    .map(|mut data| {
                        // Inspect only the projected raw key, not the descriptive message
                        // (which on success contains additional copies of the key).
                        data.get_mut("raw")
                            .and_then(|raw| match raw.take() {
                                Value::String(key) if valid_session_key(&key) => Some(key),
                                _ => None,
                            })
                    })
                    .map_err(|e| {
                        if e.message == "bw: Invalid master password." {
                            CoreError::invalid("unlock failed: Invalid master password.")
                        } else if e.message.starts_with("bw: ") {
                            CoreError::invalid("unlock failed: Bitwarden rejected the password or account")
                        } else {
                            CoreError::new(e.code, "unlock failed: bw serve did not confirm unlock")
                        }
                    });
                let _ = tx.send(result);
            });
        }
        let deadline = Instant::now() + HTTP_TIMEOUT;
        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(result) => return result.map(UnlockOutcome::Complete),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(CoreError::internal("unlock failed: worker thread ended"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if let Ok(st) = call_timeout(ep, "GET", "/status", None, Duration::from_secs(5))
                && str_at(&st, &["template", "status"]) == Some("unlocked")
            {
                return Ok(UnlockOutcome::Pending(rx));
            }
            if Instant::now() >= deadline {
                return Err(CoreError::vault_unavailable(
                    "unlock failed: bw serve did not answer",
                ));
            }
        }
    }

    fn persist_unlock(&self, user_id: &str, key: Option<String>) {
        let (Some(resume), Some(key)) = (&self.resume, key) else {
            return;
        };
        let Ok(inst) = self.instance() else { return };
        if !Path::new(&inst.bw).is_absolute() {
            return;
        }
        let entry = SavedSession {
            key,
            user_id: user_id.to_owned(),
            connection: self.connection(&inst.bw),
        };
        if resume.store.put(RESUME_NAMESPACE, &resume.vault_id, &entry).is_err() {
            log::warn!("Bitwarden could not save its session for manager restart");
        }
    }

    /// Some bw releases report `unlocked` while the session-export response is pending.
    /// Accept a late response only while that same provider is current and still Ready.
    /// Caller holds `lifecycle`, and clearing/stopping drops the pending receiver.
    fn flush_unlock(&self) {
        let Some(pending) = self.state().pending_unlock.take() else { return };
        match pending.result.try_recv() {
            Ok(Ok(key)) => self.persist_unlock(&pending.user_id, key),
            Err(std::sync::mpsc::TryRecvError::Empty) => self.state().pending_unlock = Some(pending),
            _ => {}
        }
    }

    /// Endpoint of a running, ready serve.
    fn endpoint(&self) -> Result<(u32, Endpoint)> {
        let mut st = self.state();
        if let Some(msg) = st.serve.as_mut().and_then(Serve::exited) {
            st.serve = None;
            st.status = VaultStatus::Error(msg);
        }
        match (&st.status, &st.serve) {
            (VaultStatus::Ready, Some(s)) => Ok((s.child.id(), s.endpoint.clone())),
            (VaultStatus::Error(m), _) => Err(CoreError::vault_unavailable(m.clone())),
            (VaultStatus::Locked, _) => Err(CoreError::vault_unavailable("vault is locked")),
            (VaultStatus::Ready, None) => {
                Err(CoreError::vault_unavailable("bw serve is not running"))
            }
        }
    }

    fn request(
        &self,
        (pid, endpoint): &(u32, Endpoint),
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let result = call(endpoint, method, path, body);
        if result.as_ref().is_err_and(auth_rejected) {
            self.reject_session(*pid)?;
        }
        result
    }

    fn reject_session(&self, pid: u32) -> Result<()> {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let serve = {
            let mut state = self.state();
            if !state.serve.as_ref().is_some_and(|s| s.child.id() == pid) {
                return Ok(());
            }
            state.pending_unlock = None;
            state.status = VaultStatus::Locked;
            state.serve.take()
        };
        if let Some(serve) = serve {
            let _ = call_timeout(&serve.endpoint, "POST", "/lock", None, LOCK_TIMEOUT);
        }
        self.clear_session()
    }

    /// Every collection the account can see (for the UI picker).
    pub fn collections(&self) -> Result<Vec<CollectionInfo>> {
        let data = self.request(&self.endpoint()?, "GET", "/list/object/collections", None)?;
        Ok(list_data(&data)
            .iter()
            .filter_map(|c| {
                Some(CollectionInfo {
                    id: c.get("id")?.as_str()?.to_owned(),
                    name: c
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    organization_id: c
                        .get("organizationId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
            })
            .collect())
    }

    fn fetch_visible(&self, endpoint: &(u32, Endpoint), key: &str) -> Result<Value> {
        check_id(key)?;
        let item = self.request(endpoint, "GET", &format!("/object/item/{key}"), None)?;
        if !is_visible(&item, &self.cfg()) {
            return Err(CoreError::not_found(
                "the Bitwarden item is not exposed by this vault",
            ));
        }
        Ok(item)
    }

    fn stop(&self, preserve: bool) -> Result<()> {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        if preserve && self.state().status == VaultStatus::Ready {
            self.flush_unlock();
        }
        let serve = {
            let mut st = self.state();
            st.stopped = true;
            st.pending_unlock = None;
            st.status = VaultStatus::Error("stopped".into());
            st.serve.take()
        };
        if let Some(mut s) = serve {
            if !preserve && s.exited().is_none() {
                let _ = call_timeout(&s.endpoint, "POST", "/lock", None, LOCK_TIMEOUT);
            }
            s.stop();
        }
        if !preserve {
            self.clear_session()?;
        }
        Ok(())
    }
}

impl VaultProvider for BitwardenVault {
    fn status(&self) -> VaultStatus {
        match self.endpoint() {
            Ok(_) => VaultStatus::Ready,
            Err(_) => self.state().status.clone(),
        }
    }

    fn list(&self) -> Result<Vec<SecretMeta>> {
        let data = self.request(&self.endpoint()?, "GET", "/list/object/items", None)?;
        let mut seen = HashSet::new();
        let cfg = self.cfg();
        Ok(list_data(&data)
            .iter()
            .filter(|i| is_visible(i, &cfg))
            .filter_map(map_item)
            .filter(|m| seen.insert(m.key.clone()))
            .collect())
    }

    fn read(&self, key: &str) -> Result<Vec<(String, String)>> {
        let item = self.fetch_visible(&self.endpoint()?, key)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let fields = field_values(&item, now);
        if fields.is_empty() {
            return Err(CoreError::not_found(
                "the Bitwarden item has no usable fields",
            ));
        }
        Ok(fields)
    }

    fn update(&self, key: &str, field: &str, value: &str) -> Result<()> {
        let ep = self.endpoint()?;
        let mut item = self.fetch_visible(&ep, key)?;
        set_field(&mut item, field, value)?;
        self.request(&ep, "PUT", &format!("/object/item/{key}"), Some(&item))?;
        Ok(())
    }

    fn add(&self, name: &str, value: &str, target: &AddTarget) -> Result<()> {
        let ep = self.endpoint()?;
        let (org, collections) = match &target.collection_id {
            Some(c) => {
                if !self.cfg().collections.iter().any(|e| e == c) {
                    return Err(CoreError::invalid(
                        "that collection is not exposed by this vault",
                    ));
                }
                let info = self
                    .collections()?
                    .into_iter()
                    .find(|i| &i.id == c)
                    .ok_or_else(|| CoreError::invalid("that collection no longer exists"))?;
                (
                    info.organization_id
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                    json!([c]),
                )
            }
            None => {
                if !self.cfg().personal {
                    return Err(CoreError::invalid(
                        "this vault does not expose the personal vault; choose a collection",
                    ));
                }
                (Value::Null, Value::Null)
            }
        };
        let tmpl = self.request(&ep, "GET", "/object/template/item", None)?;
        let mut item = tmpl
            .get("template")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        item["type"] = json!(TYPE_LOGIN);
        item["name"] = json!(name);
        item["notes"] = Value::Null;
        item["fields"] = json!([]);
        item["folderId"] = Value::Null;
        item["login"] = json!({ "uris": [], "username": null, "password": value, "totp": null });
        item["organizationId"] = org;
        item["collectionIds"] = collections;
        self.request(&ep, "POST", "/object/item", Some(&item))?;
        Ok(())
    }

    fn note(&self) -> Option<String> {
        self.state().note.clone()
    }

    /// Quiescent locked vaults stay locked. A dead helper may resume only a still-valid
    /// provider session; provider lock/logout clears the resumable authority.
    fn sync(&self) -> Result<()> {
        let ep = match self.endpoint() {
            Ok(ep) => ep,
            Err(_) => {
                let st = self.state();
                if st.status == VaultStatus::Locked && st.serve.is_some() {
                    return Ok(());
                }
                drop(st);
                return self.ensure_running();
            }
        };
        let synced = self.request(&ep, "POST", "/sync", None).map(|_| ());
        if synced.as_ref().is_err_and(auth_rejected) {
            return synced;
        }
        let st = self.request(&ep, "GET", "/status", None);
        if let Ok(st) = st {
            match str_at(serve_status(&st), &["status"]) {
                Some("unlocked") if self.matches_account(serve_status(&st)) => {
                    let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
                    if self.state().serve.as_ref().is_some_and(|s| s.child.id() == ep.0) {
                        self.flush_unlock();
                    }
                }
                Some("locked" | "unauthenticated" | "unlocked") => self.reject_session(ep.0)?,
                _ => {}
            }
        }
        synced
    }

    fn shutdown(&self) {
        let _ = self.stop(self.resume.is_some());
    }

    fn discard(&self) -> Result<()> {
        self.stop(false)
    }

    fn bitwarden_session_revision(&self) -> Option<u64> {
        let state = self.state();
        (state.status == VaultStatus::Ready).then_some(state.session_revision)
    }

    fn unlock(&self, master_password: &str) -> Result<()> {
        BitwardenVault::unlock(self, master_password)
    }

    /// Exposed collections with their names (for the `add` popup).
    fn collections(&self) -> Result<Vec<CollectionInfo>> {
        let all = BitwardenVault::collections(self)?;
        let cfg = self.cfg();
        Ok(all
            .into_iter()
            .filter(|c| cfg.collections.contains(&c.id))
            .collect())
    }

    fn all_collections(&self) -> Result<Vec<CollectionInfo>> {
        BitwardenVault::collections(self)
    }

    fn reconfigure(&self, config: &VaultConfig) -> bool {
        let VaultConfig::Bitwarden(new) = config else {
            return false;
        };
        let mut cfg = self.cfg.write().unwrap_or_else(|p| p.into_inner());
        if !cfg.same_connection(new) {
            return false;
        }
        *cfg = new.clone();
        true
    }
}

impl Drop for BitwardenVault {
    fn drop(&mut self) {
        let _ = self.stop(self.resume.is_some());
    }
}

/// UI "Connect": start with these settings, unlock with `master_password`, return
/// collections, stop serve again. Uses a separate data directory so it never disturbs a
/// running instance of the vault. The password is not kept.
pub fn connect(
    dirs: &DataDirs,
    vault_id: &str,
    cfg: &BitwardenConfig,
    secrets: &BitwardenSecrets,
    master_password: &str,
) -> Result<Vec<CollectionInfo>> {
    let dir = dirs.bw.join(format!("{vault_id}.connect"));
    let res = (|| {
        let v = BitwardenVault::new(dir.clone(), cfg.clone(), secrets.clone(), None);
        v.ensure_running()?;
        v.unlock(master_password)?;
        let c = BitwardenVault::collections(&v);
        v.discard()?;
        c
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// A fake `bw` (Perl script, no network, no real Bitwarden) for tests: `status` reports a
/// logged-in, locked account; `serve` answers `/status`, `/unlock` (password
/// [`fake_bw::PASSWORD`]), `/lock`, `/sync` and the two list endpoints over a Unix socket.
/// Events (`serve`, `unlock`, `unlock-failed`, `lock`, `sync`, other commands) are appended
/// to `<app data dir>/events.log`.
#[cfg(test)]
pub(crate) mod fake_bw {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::BitwardenConfig;

    pub const PASSWORD: &str = "correct horse";

    const SCRIPT: &str = r#"#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

my $dir = $ENV{BITWARDENCLI_APPDATA_DIR} // die "no app data dir";
my $cmd = shift(@ARGV) // '';
sub event { open(my $f, '>>', "$dir/events.log") or return; print $f "$_[0]\n"; close $f; }
my $session = ('A' x 86) . '==';
my $session_file = "$dir/provider-key-present";
my $user = -e "$dir/other-user" ? 'different-user-id' : 'fixture-user-id';
my $identity = qq("serverUrl":"https://vault.example.invalid","userEmail":"me\@example.invalid","userId":"$user");
if ($cmd eq 'status') {
    print qq({$identity,"status":"locked"}), "\n";
    exit 0;
}
if ($cmd ne 'serve') { event($cmd); exit 0; }
my %opt = @ARGV;
my $path = $opt{'--hostname'} // '';
$path =~ s{^unix://}{} or exit 2;
unlink $path;
my $srv = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 8) or die "listen: $!";
event('serve');
event('session-attempt') if defined $ENV{BW_SESSION};
my $unlocked = ($ENV{BW_SESSION} // '') eq $session && -e $session_file;
my @stalled;
my $ok = '{"success":true,"data":{}}';
my $unlock_ok = qq({"success":true,"data":{"object":"message","raw":"$session"}});
while (my $c = $srv->accept) {
    my $line = <$c>;
    next unless defined $line;
    my (undef, $p) = split / /, $line;
    my $len = 0;
    while (my $h = <$c>) {
        last if $h =~ /^\r?\n$/;
        $len = $1 if $h =~ /^content-length:\s*(\d+)/i;
    }
    my $body = '';
    read($c, $body, $len) if $len;
    my $r;
    if ($p eq '/status') {
        my $s = $unlocked ? 'unlocked' : 'locked';
        $r = qq({"success":true,"data":{"object":"template","template":{$identity,"status":"$s"}}});
    } elsif ($p eq '/unlock') {
        if ($body =~ /"password":"correct horse"/) {
            $unlocked = 1;
            open(my $key, '>', $session_file) or die "fixture session marker: $!";
            close($key);
            event('unlock');
            $r = $unlock_ok;
        }
        # Like bw 2026.2.0 against a real account: unlocked, but the response never comes.
        elsif ($body =~ /"password":"stalling horse"/) { $unlocked = 1; event('unlock'); push @stalled, $c; next; }
        else { event('unlock-failed'); $r = '{"success":false,"message":"Invalid master password."}'; }
    } elsif ($p eq '/lock') {
        unlink $session_file;
        $unlocked = 0; event('lock'); $r = $ok;
    } elsif (!$unlocked) {
        $r = '{"success":false,"message":"Vault is locked."}';
    } elsif ($p eq '/sync') {
        event('sync');
        $r = -e "$dir/reject-provider"
            ? '{"success":false,"message":"Syncing failed: Refresh Access token error"}'
            : $ok;
    } elsif ($p eq '/list/object/items') {
        $r = '{"success":true,"data":{"object":"list","data":[]}}';
    } elsif ($p eq '/list/object/collections') {
        $r = '{"success":true,"data":{"object":"list","data":[{"object":"collection","id":"c-1","name":"Team","organizationId":"o-1"}]}}';
    } elsif ($p eq '/object/item/abcdef') {
        $r = '{"success":true,"data":{"type":1,"organizationId":"o-1","collectionIds":["c-1"],"login":{"password":"fixture-value"}}}';
    } else {
        $r = '{"success":false,"message":"Not found."}';
    }
    print $c "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . length($r) . "\r\nConnection: close\r\n\r\n" . $r;
    close $c;
}
"#;

    /// Temp dir under /tmp (Unix socket paths are limited to 103 bytes).
    pub fn tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("asmbw")
            .tempdir_in("/tmp")
            .unwrap()
    }

    /// Write the script into `dir`; returns its path.
    pub fn install(dir: &Path) -> String {
        let p = dir.join("fake-bw");
        std::fs::write(&p, SCRIPT).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// A config matching the fake account, using `bw_path`.
    pub fn config(bw_path: &str) -> BitwardenConfig {
        BitwardenConfig {
            server_url: "https://vault.example.invalid".into(),
            email: "me@example.invalid".into(),
            client_id: "user.x".into(),
            collections: vec!["c-1".into()],
            personal: false,
            bw_path: Some(bw_path.into()),
            collection_names: Default::default(),
        }
    }

    pub fn events(app_dir: &Path) -> Vec<String> {
        std::fs::read_to_string(app_dir.join("events.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(collections: &[&str], personal: bool) -> BitwardenConfig {
        BitwardenConfig {
            server_url: "https://vault.example.invalid".into(),
            email: "me@example.invalid".into(),
            client_id: "user.x".into(),
            collections: collections.iter().map(|s| s.to_string()).collect(),
            personal,
            bw_path: None,
            collection_names: Default::default(),
        }
    }

    fn login_item() -> Value {
        serde_json::from_str(
            r#"{"passwordHistory":[],"revisionDate":"2026-11-01T10:00:00.000Z","creationDate":"2026-11-01T10:00:00.000Z",
            "deletedDate":null,"object":"item","id":"0b4b2a7e-1c5a-4f0e-9c1d-7f3e2a1b0c9d","organizationId":"9a8b7c6d-0000-4000-8000-000000000001",
            "folderId":null,"type":1,"reprompt":0,"name":"GitHub","notes":"not exposed for logins","favorite":false,
            "fields":[{"name":"otp seed","value":"JBSWY3DP","type":1,"linkedId":null},
                      {"name":"password","value":"shadowed","type":0,"linkedId":null},
                      {"name":"linked","value":null,"type":3,"linkedId":101},
                      {"name":"flag","value":"true","type":2,"linkedId":null},
                      {"name":"empty","value":"","type":0,"linkedId":null},
                      {"name":"totp","value":"reserved name","type":0,"linkedId":null}],
            "login":{"uris":[{"match":null,"uri":"https://GitHub.com/login"},{"match":null,"uri":"api.github.com"},
                             {"match":null,"uri":"androidapp://com.github.android"},{"match":null,"uri":"https://user@github.com:443/x"}],
                     "username":"octocat","password":"hunter2","totp":null,"passwordRevisionDate":null},
            "collectionIds":["c-1"]}"#,
        )
        .unwrap()
    }

    fn note_item(fields: &str, notes: &str) -> Value {
        serde_json::from_str(&format!(
            r#"{{"object":"item","id":"1c2d3e4f-0000-4000-8000-00000000000a","organizationId":null,"type":2,"name":"Deploy keys",
            "notes":{notes},"secureNote":{{"type":0}},"fields":{fields},"collectionIds":[]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn maps_login_item() {
        let item = login_item();
        let m = map_item(&item).unwrap();
        assert_eq!(m.key, "0b4b2a7e-1c5a-4f0e-9c1d-7f3e2a1b0c9d");
        assert_eq!(m.name, "GitHub");
        assert_eq!(m.kind, SecretKind::Login);
        assert_eq!(m.fields, ["username", "password", "otp seed"]);
        assert_eq!(m.uri_hosts, ["github.com", "api.github.com"]);
        let values: Vec<(String, String)> = field_sources(&item)
            .into_iter()
            .map(|(n, _, v)| (n, v))
            .collect();
        assert_eq!(values[1], ("password".to_owned(), "hunter2".to_owned()));
        assert_eq!(values[2], ("otp seed".to_owned(), "JBSWY3DP".to_owned()));
        assert!(
            !values.iter().any(|(n, _)| n == "totp"),
            "a custom field named totp is reserved and skipped"
        );
    }

    #[test]
    fn login_totp_reads_as_the_current_code() {
        let mut item = login_item();
        item["login"]["totp"] = json!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
        let m = map_item(&item).unwrap();
        assert_eq!(m.fields, ["username", "password", "totp", "otp seed"]);
        let key = crate::totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let values = field_values(&item, 1_111_111_109);
        assert_eq!(
            values[2],
            ("totp".to_owned(), crate::totp::current_code(&key, 1_111_111_109))
        );
        assert!(values.iter().all(|(_, v)| !v.contains("JBSWY3DPEHPK3PXP")));
        assert_eq!(values[2].1.len(), 6);
        assert_eq!(
            set_field(&mut item, "totp", "123456").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );
        item["login"]["totp"] = json!("steam://JBSWY3DP");
        assert_eq!(map_item(&item).unwrap().fields, ["username", "password", "otp seed"]);
    }

    #[test]
    fn maps_secure_notes() {
        let multi = note_item(
            r#"[{"name":"api","value":"k1","type":1},{"name":"notes","value":"custom","type":0}]"#,
            r#""body""#,
        );
        let m = map_item(&multi).unwrap();
        assert_eq!(m.kind, SecretKind::Multi);
        assert_eq!(
            m.fields,
            ["api", "notes"],
            "custom field named notes shadows the note body"
        );
        assert!(m.uri_hosts.is_empty());

        let single = note_item("[]", r#""-----BEGIN KEY-----\nabc""#);
        let m = map_item(&single).unwrap();
        assert_eq!(m.kind, SecretKind::Single);
        assert_eq!(m.fields, ["notes"]);
        assert_eq!(field_sources(&single)[0].2, "-----BEGIN KEY-----\nabc");

        assert!(
            map_item(&note_item("null", "null")).is_none(),
            "no fields → skipped"
        );
        let mut card = login_item();
        card["type"] = json!(3);
        assert!(map_item(&card).is_none(), "cards are skipped");
        let mut empty_login = login_item();
        empty_login["login"] = json!({"username":"","password":null,"uris":[]});
        empty_login["fields"] = json!([]);
        assert!(map_item(&empty_login).is_none());
    }

    #[test]
    fn visibility() {
        let item = login_item();
        assert!(is_visible(&item, &cfg(&["c-1"], false)));
        assert!(
            !is_visible(&item, &cfg(&["c-2"], true)),
            "org item outside exposed collections"
        );
        let personal = note_item("[]", r#""x""#);
        assert!(is_visible(&personal, &cfg(&[], true)));
        assert!(!is_visible(&personal, &cfg(&["c-1"], false)));
    }

    #[test]
    fn set_field_targets_the_listed_source() {
        let mut item = login_item();
        set_field(&mut item, "password", "new-pw").unwrap();
        assert_eq!(item["login"]["password"], "new-pw");
        assert_eq!(
            item["fields"][1]["value"], "shadowed",
            "custom 'password' untouched"
        );
        set_field(&mut item, "otp seed", "SEED2").unwrap();
        assert_eq!(item["fields"][0]["value"], "SEED2");
        assert_eq!(
            set_field(&mut item, "notes", "x").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );

        let mut note = note_item(r#"[{"name":"api","value":"k1","type":1}]"#, r#""body""#);
        set_field(&mut note, "notes", "new body").unwrap();
        assert_eq!(note["notes"], "new body");
        assert_eq!(
            set_field(&mut note, "password", "x").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );
    }

    #[test]
    fn uri_hosts() {
        assert_eq!(
            uri_host("https://Example.COM:8443/path?q").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            uri_host("example.org/login").as_deref(),
            Some("example.org")
        );
        assert_eq!(uri_host("ftp://example.net"), None);
        assert_eq!(uri_host("https://[::1]/"), None);
        assert_eq!(uri_host("  "), None);
    }

    #[test]
    fn http_parsing() {
        let (c, b) =
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA").unwrap();
        assert_eq!((c, b.as_slice()), (200, &b"hello"[..]));
        let (c, b) =
            parse_http_response(b"HTTP/1.1 400 Bad\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!((c, b.as_slice()), (400, &b"abcde"[..]));
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(check_id("../../etc").is_err());
        assert!(check_id("0b4b2a7e-1c5a-4f0e-9c1d-7f3e2a1b0c9d").is_ok());
        assert_eq!(bw_error("Not found.").code, asm_proto::ErrorCode::NotFound);
    }

    /// Smoke test against the real `bw` binary: a throwaway app-data dir with a fake
    /// logged-in (locked) account so `bw serve` starts; checks `/status` over the Unix
    /// socket with this client, that an `Origin` header is refused, and that the process
    /// group is gone after stop. No network access, no credentials. Run with `--ignored`.
    #[test]
    #[ignore]
    fn bw_serve_unix_socket_smoke() {
        let bw = default_bw_path().expect("bw installed");
        let tmp = tempfile::Builder::new()
            .prefix("asmbw")
            .tempdir_in("/tmp")
            .unwrap();
        let dir = tmp.path().join("vault");
        ensure_private_dir(&dir).unwrap();
        let inst = Instance {
            bw,
            dir: dir.clone(),
        };
        // Creates data.json.
        let st = inst.status().unwrap();
        assert_eq!(str_at(&st, &["status"]), Some("unauthenticated"));
        let data_path = dir.join("data.json");
        let mut data: Value = serde_json::from_slice(&std::fs::read(&data_path).unwrap()).unwrap();
        let uid = "11111111-2222-4333-8444-555555555555";
        data["global_account_accounts"] =
            json!({ uid: {"email":"probe@example.invalid","name":null,"emailVerified":true} });
        data["global_account_activeAccountId"] = json!(uid);
        data[format!("user_{uid}_token_accessToken")] = json!("fake.token.value");
        std::fs::write(&data_path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(str_at(&inst.status().unwrap(), &["status"]), Some("locked"));

        let sock = dir.join("serve.sock");
        let mut serve = inst.spawn_serve(&Endpoint::Unix(sock.clone()), None).unwrap();
        let pid = serve.child.id() as i32;
        let started = Instant::now();
        let status = serve.wait_ready().unwrap();
        println!(
            "bw serve answered /status over the socket after {:?}: {status}",
            started.elapsed()
        );
        assert_eq!(str_at(serve_status(&status), &["status"]), Some("locked"));
        let (code, _) = {
            let mut s = UnixStream::connect(&sock).unwrap();
            s.write_all(b"GET /status HTTP/1.1\r\nHost: localhost:8087\r\nOrigin: http://evil\r\nConnection: close\r\n\r\n").unwrap();
            let mut raw = Vec::new();
            s.read_to_end(&mut raw).unwrap();
            parse_http_response(&raw).unwrap()
        };
        assert_eq!(code, 403, "Origin header refused");
        let locked = call(&serve.endpoint, "GET", "/list/object/items", None).unwrap_err();
        println!("list while locked: {}", locked.message);
        assert!(dir.join("serve.pid").exists());
        serve.stop();
        assert!(!sock.exists());
        assert_eq!(unsafe { libc::killpg(pid, 0) }, -1, "process group gone");
        // Stale serve cleanup: a pid file pointing at a dead process is just removed.
        std::fs::write(inst.pid_file(), pid.to_string()).unwrap();
        inst.kill_stale_serve();
        assert!(!inst.pid_file().exists());
    }

    /// Lifecycle against the fake `bw`: starts Locked, sync never unlocks, a wrong password
    /// is an `invalid` error, unlock makes it Ready, a crashed serve comes back Locked, stop
    /// locks serve first; `connect` unlocks a throwaway instance.
    #[test]
    fn starts_locked_and_unlocks_only_on_request() {
        let tmp = fake_bw::tempdir();
        let dirs = DataDirs::create(&tmp.path().join("d"), Some(&tmp.path().join("t"))).unwrap();
        let cfg = fake_bw::config(&fake_bw::install(tmp.path()));
        let secrets = BitwardenSecrets {
            client_secret: "cs".into(),
        };
        let app_dir = dirs.bw_vault("v1");
        let v = BitwardenVault::start_or_error(&dirs, "v1", cfg.clone(), secrets.clone());
        assert_eq!(v.status(), VaultStatus::Locked);
        assert_eq!(
            v.list().unwrap_err().code,
            asm_proto::ErrorCode::VaultUnavailable
        );
        v.sync().unwrap();
        assert_eq!(v.status(), VaultStatus::Locked, "sync never unlocks");

        let e = VaultProvider::unlock(&v, "wrong").unwrap_err();
        assert_eq!(e.code, asm_proto::ErrorCode::Invalid);
        assert_eq!(e.message, "unlock failed: Invalid master password.");
        assert_eq!(v.status(), VaultStatus::Locked);

        VaultProvider::unlock(&v, fake_bw::PASSWORD).unwrap();
        assert_eq!(v.status(), VaultStatus::Ready);
        assert!(v.list().unwrap().is_empty());
        v.sync().unwrap();
        assert_eq!(v.status(), VaultStatus::Ready);
        assert_eq!(
            fake_bw::events(&app_dir),
            ["serve", "unlock-failed", "unlock", "sync"]
        );

        // Exposure changes apply in place: serve keeps running, still unlocked.
        let ids = |cols: Vec<CollectionInfo>| cols.into_iter().map(|c| c.id).collect::<Vec<_>>();
        assert_eq!(ids(VaultProvider::all_collections(&v).unwrap()), ["c-1"]);
        assert_eq!(ids(VaultProvider::collections(&v).unwrap()), ["c-1"]);
        let mut exposed = cfg.clone();
        exposed.collections.clear();
        exposed.personal = true;
        exposed.collection_names.insert("c-1".into(), "Team".into());
        assert!(v.reconfigure(&VaultConfig::Bitwarden(exposed)));
        assert_eq!(v.status(), VaultStatus::Ready);
        assert!(
            VaultProvider::collections(&v).unwrap().is_empty(),
            "c-1 no longer exposed"
        );
        let mut moved = cfg.clone();
        moved.server_url = "https://other.example.invalid".into();
        assert!(
            !v.reconfigure(&VaultConfig::Bitwarden(moved)),
            "a new account needs a restart"
        );
        assert!(!v.reconfigure(&VaultConfig::Keychain));
        assert!(v.reconfigure(&VaultConfig::Bitwarden(cfg.clone())));
        assert_eq!(ids(VaultProvider::collections(&v).unwrap()), ["c-1"]);
        assert_eq!(
            fake_bw::events(&app_dir),
            ["serve", "unlock-failed", "unlock", "sync"],
            "no restart"
        );

        // serve crashes: the vault is unavailable, and sync restarts it Locked.
        let pid: i32 = std::fs::read_to_string(app_dir.join("serve.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(v.status(), VaultStatus::Error(_)) {
            assert!(Instant::now() < deadline, "crash not noticed");
            std::thread::sleep(Duration::from_millis(50));
        }
        v.sync().unwrap();
        assert_eq!(v.status(), VaultStatus::Locked, "restart leaves it locked");

        VaultProvider::unlock(&v, fake_bw::PASSWORD).unwrap();
        v.shutdown();
        assert_eq!(
            fake_bw::events(&app_dir).last().map(String::as_str),
            Some("lock"),
            "stop locks serve before killing it"
        );
        assert!(matches!(v.status(), VaultStatus::Error(_)));

        let cols = connect(&dirs, "v2", &cfg, &secrets, fake_bw::PASSWORD).unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].id, "c-1");
        assert_eq!(
            connect(&dirs, "v3", &cfg, &secrets, "nope")
                .unwrap_err()
                .code,
            asm_proto::ErrorCode::Invalid
        );
    }

    fn test_resume(dirs: &DataDirs) -> Arc<ResumeStore> {
        let store = Arc::new(crate::store::Store::open(&dirs.db()).unwrap());
        Arc::new(ResumeStore::open(store, Some([31; 32])).unwrap())
    }

    #[test]
    fn session_is_durable_before_quit_and_reuses_provider_state() {
        let tmp = fake_bw::tempdir();
        let dirs = DataDirs::create(&tmp.path().join("d"), Some(&tmp.path().join("t"))).unwrap();
        let cfg = fake_bw::config(&fake_bw::install(tmp.path()));
        let secrets = BitwardenSecrets { client_secret: "fixture-client-secret".into() };
        let start = |resume| {
            BitwardenVault::start_with_resume(&dirs, "v1", cfg.clone(), secrets.clone(), Some(resume))
        };
        let app_dir = dirs.bw_vault("v1");
        let resume = test_resume(&dirs);
        let first = start(resume.clone());
        assert_eq!(first.status(), VaultStatus::Locked);
        first.unlock(fake_bw::PASSWORD).unwrap();
        let saved: SavedSession = resume.get(RESUME_NAMESPACE, "v1").unwrap().unwrap();
        assert!(valid_session_key(&saved.key), "persisted at unlock, not first written on shutdown");

        let pid = first.state().serve.as_ref().unwrap().child.id() as i32;
        assert_eq!(unsafe { libc::killpg(pid, libc::SIGKILL) }, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(first.status(), VaultStatus::Error(_)) {
            assert!(Instant::now() < deadline, "fixture helper did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(first);
        drop(resume);

        let resume = test_resume(&dirs);
        let second = start(resume.clone());
        assert_eq!(second.status(), VaultStatus::Ready);
        assert_eq!(second.read("abcdef").unwrap(), [("password".into(), "fixture-value".into())]);
        second.shutdown();
        drop(second);
        drop(resume);
        assert_eq!(
            fake_bw::events(&app_dir),
            ["serve", "unlock", "serve", "session-attempt"],
            "no additional master password, lock, or login on quit/relaunch",
        );
        for entry in std::fs::read_dir(&dirs.data).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(path).unwrap();
                for secret in [saved.key.as_str(), fake_bw::PASSWORD, "fixture-client-secret", "fixture-value"] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
                }
            }
        }

        let resume = test_resume(&dirs);
        let third = start(resume.clone());
        assert_eq!(third.status(), VaultStatus::Ready);
        third.discard().unwrap();
        assert!(third.sync().is_err(), "a retired provider cannot restart");
        assert!(resume.get::<SavedSession>(RESUME_NAMESPACE, "v1").unwrap().is_none());
        assert_eq!(start(resume).status(), VaultStatus::Locked);
    }

    #[test]
    fn provider_lock_rejection_and_changed_authority_cannot_restore() {
        let tmp = fake_bw::tempdir();
        let dirs = DataDirs::create(&tmp.path().join("d"), Some(&tmp.path().join("t"))).unwrap();
        let cfg = fake_bw::config(&fake_bw::install(tmp.path()));
        let resume = test_resume(&dirs);
        let start = |id, client_secret: &str| {
            BitwardenVault::start_with_resume(
                &dirs, id, cfg.clone(), BitwardenSecrets { client_secret: client_secret.into() },
                Some(resume.clone()),
            )
        };
        for id in ["external-lock", "provider-reject", "account-edit", "secret-edit"] {
            let first = start(id, "fixture-client-secret");
            first.unlock(fake_bw::PASSWORD).unwrap();
            let app_dir = dirs.bw_vault(id);
            match id {
                "external-lock" => {
                    let (_, ep) = first.endpoint().unwrap();
                    call(&ep, "POST", "/lock", None).unwrap();
                    // Simulate quitting before manager polling detects the external lock.
                }
                "provider-reject" => {
                    std::fs::write(app_dir.join("reject-provider"), []).unwrap();
                    assert!(first.sync().is_err());
                    assert_eq!(first.status(), VaultStatus::Locked);
                }
                "account-edit" => std::fs::write(app_dir.join("other-user"), []).unwrap(),
                _ => {}
            };
            first.shutdown();
            let secret = if id == "secret-edit" { "changed-client-secret" } else { "fixture-client-secret" };
            let next = start(id, secret);
            assert_eq!(next.status(), VaultStatus::Locked, "{id}");
            assert!(resume.get::<SavedSession>(RESUME_NAMESPACE, id).unwrap().is_none(), "{id}");
            if id != "external-lock" {
                assert!(!fake_bw::events(&app_dir).iter().any(|event| event == "session-attempt"), "{id}");
            }
        }
    }

    /// bw 2026.2.0 can unlock the vault and then never answer `POST /unlock` (seen
    /// against the lab Vaultwarden): unlock must still finish, via `/status`.
    #[test]
    fn unlock_finishes_when_serve_never_answers() {
        let tmp = fake_bw::tempdir();
        let dirs = DataDirs::create(&tmp.path().join("d"), Some(&tmp.path().join("t"))).unwrap();
        let cfg = fake_bw::config(&fake_bw::install(tmp.path()));
        let secrets = BitwardenSecrets {
            client_secret: "cs".into(),
        };
        let resume = test_resume(&dirs);
        let v = BitwardenVault::start_with_resume(&dirs, "v1", cfg, secrets, Some(resume.clone()));
        assert_eq!(v.status(), VaultStatus::Locked);
        let started = Instant::now();
        VaultProvider::unlock(&v, "stalling horse").unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "unlock waited for the stalled response"
        );
        assert_eq!(v.status(), VaultStatus::Ready);
        assert!(v.list().unwrap().is_empty());
        v.shutdown();
        assert!(resume.get::<SavedSession>(RESUME_NAMESPACE, "v1").unwrap().is_none());
    }
}
