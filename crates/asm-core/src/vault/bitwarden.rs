//! Bitwarden / Vaultwarden vault through `bw serve` (plan step 4).
//!
//! Each instance has its own `BITWARDENCLI_APPDATA_DIR=<data>/bw/<vault_id>`. Start-up:
//! `bw status`; when logged out (or logged in to another server/account): `bw config server`
//! → `bw login --apikey`; then `bw serve --hostname unix://<dir>/serve.sock` in its own
//! process group, poll `GET /status` up to 10 s, `POST /unlock` when locked. `bw serve`
//! refuses to start while logged out, so login happens before the first spawn.
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{
    AddTarget, BitwardenConfig, BitwardenSecrets, CollectionInfo, SecretKind, SecretMeta,
    VaultProvider, VaultStatus,
};
use crate::error::{CoreError, Result};
use crate::paths::{DataDirs, ensure_private_dir};

const SERVE_WAIT: Duration = Duration::from_secs(10);
const CLI_TIMEOUT: Duration = Duration::from_secs(90);
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
/// `sun_path` is 104 bytes on macOS, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 103;
const TCP_NOTE: &str = "bw serve listens on 127.0.0.1 (reachable by other local processes)";

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
    fn connect(&self) -> std::io::Result<Box<dyn Stream>> {
        Ok(match self {
            Endpoint::Unix(p) => {
                let s = UnixStream::connect(p)?;
                s.set_read_timeout(Some(HTTP_TIMEOUT))?;
                s.set_write_timeout(Some(HTTP_TIMEOUT))?;
                Box::new(s)
            }
            Endpoint::Tcp(port) => {
                let s = TcpStream::connect_timeout(
                    &([127, 0, 0, 1], *port).into(),
                    Duration::from_secs(5),
                )?;
                s.set_read_timeout(Some(HTTP_TIMEOUT))?;
                s.set_write_timeout(Some(HTTP_TIMEOUT))?;
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
    ) -> std::io::Result<(u16, Vec<u8>)> {
        let mut s = self.connect()?;
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
        let mut raw = Vec::new();
        s.read_to_end(&mut raw)?;
        parse_http_response(&raw)
    }
}

fn bad_response(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bw serve: {m}"))
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
    let (code, bytes) = ep
        .http(method, path, body)
        .map_err(|e| CoreError::vault_unavailable(format!("bw serve unreachable: {e}")))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CoreError::vault_unavailable(format!(
            "bw serve answered HTTP {code} with a non-JSON body"
        ))
    })?;
    if v.get("success").and_then(Value::as_bool) == Some(true) {
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
}

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

/// Exposed fields of an item in order: `(field name, where it lives, value)`.
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
            ) {
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
    }
    Ok(())
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

    fn spawn_serve(&self, endpoint: &Endpoint) -> Result<Serve> {
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
        c.arg("serve")
            .args(&hostname_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = c
            .spawn()
            .map_err(|e| CoreError::vault_unavailable(format!("cannot run {}: {e}", self.bw)))?;
        let tail: LogTail = Arc::default();
        drain(child.stdout.take().expect("piped"), tail.clone());
        drain(child.stderr.take().expect("piped"), tail.clone());
        let _ = std::fs::write(self.pid_file(), child.id().to_string());
        Ok(Serve {
            child,
            endpoint: endpoint.clone(),
            tail,
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
    tail: LogTail,
    pid_file: PathBuf,
    stopped: bool,
}

impl Serve {
    fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(st)) => {
                let t = tail_text(&self.tail, 5);
                Some(if t.is_empty() {
                    format!("bw serve exited ({st})")
                } else {
                    format!("bw serve exited: {t}")
                })
            }
            Ok(None) => None,
            Err(e) => Some(format!("bw serve: {e}")),
        }
    }

    /// Poll `GET /status` until serve answers; returns `data.template.status`.
    fn wait_ready(&mut self) -> Result<String> {
        let deadline = Instant::now() + SERVE_WAIT;
        loop {
            if let Some(m) = self.exited() {
                return Err(CoreError::vault_unavailable(m));
            }
            if let Ok(v) = call(&self.endpoint, "GET", "/status", None) {
                return Ok(str_at(&v, &["template", "status"])
                    .unwrap_or("unknown")
                    .to_owned());
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

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

struct State {
    serve: Option<Serve>,
    status: VaultStatus,
    note: Option<String>,
}

pub struct BitwardenVault {
    dir: PathBuf,
    cfg: BitwardenConfig,
    secrets: BitwardenSecrets,
    state: Mutex<State>,
    /// Serialises start/stop.
    lifecycle: Mutex<()>,
}

impl BitwardenVault {
    /// Spawns `bw serve`, logs in / unlocks as needed (plan step 4). Errors carry bw's stderr.
    pub fn start(
        dirs: &DataDirs,
        vault_id: &str,
        cfg: BitwardenConfig,
        secrets: BitwardenSecrets,
    ) -> Result<Self> {
        let v = Self::new(dirs.bw_vault(vault_id), cfg, secrets);
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
        let v = Self::new(dirs.bw_vault(vault_id), cfg, secrets);
        let _ = v.ensure_running();
        v
    }

    fn new(dir: PathBuf, cfg: BitwardenConfig, secrets: BitwardenSecrets) -> Self {
        BitwardenVault {
            dir,
            cfg,
            secrets,
            state: Mutex::new(State {
                serve: None,
                status: VaultStatus::Error("not started".into()),
                note: None,
            }),
            lifecycle: Mutex::new(()),
        }
    }

    /// The bw CLI for this instance; the path is resolved on every start.
    fn instance(&self) -> Result<Instance> {
        let bw = self
            .cfg
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

    fn set_status(&self, s: VaultStatus) {
        self.state().status = s;
    }

    /// Start (or restart) serve and bring the vault to `Ready`.
    fn ensure_running(&self) -> Result<()> {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let res = self.start_locked();
        match &res {
            Ok(()) => self.set_status(VaultStatus::Ready),
            Err(e) => self.set_status(VaultStatus::Error(e.message.clone())),
        }
        res
    }

    fn login_if_needed(&self, inst: &Instance) -> Result<()> {
        let st = inst.status()?;
        let status = str_at(&st, &["status"]).unwrap_or("unauthenticated");
        let server_ok = str_at(&st, &["serverUrl"])
            .is_some_and(|u| norm_url(u) == norm_url(&self.cfg.server_url));
        let email_ok = self.cfg.email.trim().is_empty()
            || str_at(&st, &["userEmail"])
                .is_some_and(|e| e.eq_ignore_ascii_case(self.cfg.email.trim()));
        if status != "unauthenticated" && server_ok && email_ok {
            return Ok(());
        }
        if status != "unauthenticated" {
            inst.run(&["logout"], &[])?;
        }
        if !server_ok {
            inst.run(&["config", "server", self.cfg.server_url.trim()], &[])?;
        }
        inst.run(
            &["login", "--apikey"],
            &[
                ("BW_CLIENTID", self.cfg.client_id.trim()),
                ("BW_CLIENTSECRET", &self.secrets.client_secret),
            ],
        )?;
        Ok(())
    }

    fn start_locked(&self) -> Result<()> {
        if let Some(mut s) = self.state().serve.take() {
            s.stop();
        }
        let inst = self.instance()?;
        ensure_private_dir(&inst.dir)?;
        inst.kill_stale_serve();
        self.login_if_needed(&inst)?;

        let sock = inst.dir.join("serve.sock");
        let mut note = None;
        let mut serve = None;
        let mut first_err = None;
        if sock.as_os_str().len() <= MAX_SOCKET_PATH {
            let mut s = inst.spawn_serve(&Endpoint::Unix(sock))?;
            match s.wait_ready() {
                Ok(st) => serve = Some((s, st)),
                Err(e) => {
                    s.stop();
                    first_err = Some(e);
                }
            }
        }
        if serve.is_none() {
            let mut s = inst.spawn_serve(&Endpoint::Tcp(free_port()?))?;
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
        if st == "unauthenticated" {
            // Session expired between `bw status` and serve: log in again once.
            let endpoint = s.endpoint.clone();
            drop(s);
            inst.run(&["logout"], &[]).ok();
            self.login_if_needed(&inst)?;
            s = inst.spawn_serve(&endpoint)?;
            st = s.wait_ready()?;
        }
        if st == "locked" {
            call(
                &s.endpoint,
                "POST",
                "/unlock",
                Some(&json!({ "password": self.secrets.master_password })),
            )
            .map_err(|e| CoreError::vault_unavailable(format!("unlock failed: {}", e.message)))?;
        } else if st != "unlocked" {
            return Err(CoreError::vault_unavailable(format!(
                "bw serve reports status {st:?}"
            )));
        }
        let mut state = self.state();
        state.serve = Some(s);
        state.note = note;
        Ok(())
    }

    /// Endpoint of a running, ready serve.
    fn endpoint(&self) -> Result<Endpoint> {
        let mut st = self.state();
        if let Some(msg) = st.serve.as_mut().and_then(Serve::exited) {
            st.serve = None;
            st.status = VaultStatus::Error(msg);
        }
        match (&st.status, &st.serve) {
            (VaultStatus::Ready, Some(s)) => Ok(s.endpoint.clone()),
            (VaultStatus::Error(m), _) => Err(CoreError::vault_unavailable(m.clone())),
            (VaultStatus::Locked, _) => Err(CoreError::vault_unavailable("vault is locked")),
            (VaultStatus::Ready, None) => {
                Err(CoreError::vault_unavailable("bw serve is not running"))
            }
        }
    }

    /// Every collection the account can see (for the UI picker).
    pub fn collections(&self) -> Result<Vec<CollectionInfo>> {
        let data = call(&self.endpoint()?, "GET", "/list/object/collections", None)?;
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

    fn fetch_visible(&self, ep: &Endpoint, key: &str) -> Result<Value> {
        check_id(key)?;
        let item = call(ep, "GET", &format!("/object/item/{key}"), None)?;
        if !is_visible(&item, &self.cfg) {
            return Err(CoreError::not_found(
                "the Bitwarden item is not exposed by this vault",
            ));
        }
        Ok(item)
    }

    fn stop(&self) {
        let _l = self.lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let serve = {
            let mut st = self.state();
            st.status = VaultStatus::Error("stopped".into());
            st.serve.take()
        };
        if let Some(mut s) = serve {
            s.stop();
        }
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
        let data = call(&self.endpoint()?, "GET", "/list/object/items", None)?;
        let mut seen = HashSet::new();
        Ok(list_data(&data)
            .iter()
            .filter(|i| is_visible(i, &self.cfg))
            .filter_map(map_item)
            .filter(|m| seen.insert(m.key.clone()))
            .collect())
    }

    fn read(&self, key: &str) -> Result<Vec<(String, String)>> {
        let item = self.fetch_visible(&self.endpoint()?, key)?;
        let fields: Vec<(String, String)> = field_sources(&item)
            .into_iter()
            .map(|(n, _, v)| (n, v))
            .collect();
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
        call(&ep, "PUT", &format!("/object/item/{key}"), Some(&item))?;
        Ok(())
    }

    fn add(&self, name: &str, value: &str, target: &AddTarget) -> Result<()> {
        let ep = self.endpoint()?;
        let (org, collections) = match &target.collection_id {
            Some(c) => {
                if !self.cfg.collections.iter().any(|e| e == c) {
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
                if !self.cfg.personal {
                    return Err(CoreError::invalid(
                        "this vault does not expose the personal vault; choose a collection",
                    ));
                }
                (Value::Null, Value::Null)
            }
        };
        let tmpl = call(&ep, "GET", "/object/template/item", None)?;
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
        call(&ep, "POST", "/object/item", Some(&item))?;
        Ok(())
    }

    fn note(&self) -> Option<String> {
        self.state().note.clone()
    }

    fn sync(&self) -> Result<()> {
        let ep = match self.endpoint() {
            Ok(ep) => ep,
            Err(_) => return self.ensure_running(),
        };
        call(&ep, "POST", "/sync", None)?;
        let st = call(&ep, "GET", "/status", None)?;
        match str_at(&st, &["template", "status"]) {
            Some("unlocked") => Ok(()),
            _ => self.ensure_running(),
        }
    }

    fn shutdown(&self) {
        self.stop();
    }

    /// Exposed collections with their names (for the `add` popup).
    fn collections(&self) -> Result<Vec<CollectionInfo>> {
        Ok(BitwardenVault::collections(self)?
            .into_iter()
            .filter(|c| self.cfg.collections.contains(&c.id))
            .collect())
    }
}

impl Drop for BitwardenVault {
    fn drop(&mut self) {
        self.stop();
    }
}

/// UI "Connect": start with these settings, return collections, stop serve again.
/// Uses a separate data directory so it never disturbs a running instance of the vault.
pub fn connect(
    dirs: &DataDirs,
    vault_id: &str,
    cfg: &BitwardenConfig,
    secrets: &BitwardenSecrets,
) -> Result<Vec<CollectionInfo>> {
    let dir = dirs.bw.join(format!("{vault_id}.connect"));
    let res = (|| {
        let v = BitwardenVault::new(dir.clone(), cfg.clone(), secrets.clone());
        v.ensure_running()?;
        let c = BitwardenVault::collections(&v);
        v.stop();
        c
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
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
                      {"name":"empty","value":"","type":0,"linkedId":null}],
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
        let mut serve = inst.spawn_serve(&Endpoint::Unix(sock.clone())).unwrap();
        let pid = serve.child.id() as i32;
        let started = Instant::now();
        let status = serve.wait_ready().unwrap();
        println!(
            "bw serve answered /status over the socket after {:?}: {status}",
            started.elapsed()
        );
        assert_eq!(status, "locked");
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
}
