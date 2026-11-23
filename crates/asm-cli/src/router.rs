//! `asm proxy-router` (hidden; installed by `asm browser install`): a local HTTP proxy
//! on `127.0.0.1` for browsers. CONNECTs to (host, port) pairs with an active login
//! grant go to the manager's proxy with the `Asm-Browser-Route: 1` marker and this
//! host's proxy credentials; everything else goes direct.
//!
//! Files in the configuration directory: `router.lock` (one router per user),
//! `router.sock` (0600 admin socket: `GET /status`, `POST /routes`) and
//! `router-routes.json` (0600, the routes across restarts).

use crate::error::CliError;
use crate::files::{ensure_private_dir, lock_file, write_file_atomic};
use crate::requests::unix_now;
use crate::proxy::authority;
use crate::state::{self, HostState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs, UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time::timeout;

/// Port the router listens on unless `--port` says otherwise.
pub(crate) const DEFAULT_PORT: u16 = 7418;
const LOCK_NAME: &str = "router.lock";
const SOCKET_NAME: &str = "router.sock";
const ROUTES_NAME: &str = "router-routes.json";
/// Longest request or response head.
const MAX_HEAD: usize = 16 * 1024;
/// Longest admin request body or relayed error body.
const MAX_BODY: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 512;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Reading the body of an error response from the manager's proxy.
const BODY_TIMEOUT: Duration = Duration::from_secs(2);
/// The manager's proxy refused the route: no grant covers this (host, port) now.
const NO_GRANT: &[u8] = b"no active login grant";
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// Request headers never forwarded on absolute-form requests (plus `Host`, rewritten).
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

#[derive(clap::Subcommand)]
pub enum RouterCommand {
    /// Run the router in the foreground; exits 0 at once when one already runs.
    Run {
        /// Port on 127.0.0.1 that browsers use as their HTTPS proxy.
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// Show whether the router runs, its routes and its last error.
    Status {
        #[arg(long)]
        json: bool,
    },
}

pub fn run(cmd: RouterCommand) -> Result<(), CliError> {
    match cmd {
        RouterCommand::Run { port } => serve(port),
        RouterCommand::Status { json } => print_status(json),
    }
}

/// `<config>/router.sock`: the router's admin socket (0600).
pub(crate) fn socket_path() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join(SOCKET_NAME))
}

/// `<config>/router-routes.json`: the routes the router keeps across restarts.
pub(crate) fn routes_path() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join(ROUTES_NAME))
}

/// `<config>/router.lock`: held (flock) by the running router.
pub(crate) fn lock_path() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join(LOCK_NAME))
}

// ---------------------------------------------------------------------------
// Admin API types and the synchronous client
// ---------------------------------------------------------------------------

/// `GET /status` of a running router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RouterStatus {
    /// The `asm` version the router runs.
    pub version: String,
    pub port: u16,
    pub routes: Vec<RouteStatus>,
    /// The last failure on a routed connection; cleared by the next routed success.
    pub last_error: Option<String>,
    pub last_routed: Option<LastRouted>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RouteStatus {
    pub host: String,
    pub port: u16,
    /// RFC 3339.
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LastRouted {
    pub host: String,
    pub port: u16,
    /// RFC 3339.
    pub at: String,
}

/// One route: CONNECTs to `host:port` go to `proxy` (`<hint>:<port>` of the manager's
/// proxy) until the unix time `until`. Also the `POST /routes` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Route {
    host: String,
    port: u16,
    until: i64,
    proxy: String,
}

#[derive(Default, Serialize, Deserialize)]
struct RoutesFile {
    routes: Vec<Route>,
}

/// The running router's status; `Ok(None)` when no router listens on this machine's
/// socket (no socket, or a stale one).
pub(crate) fn status() -> Result<Option<RouterStatus>, CliError> {
    admin_call("GET", "/status", None)?
        .map(|body| decode_status(&body))
        .transpose()
}

/// Add or replace the route for `host:port` until the unix time `until`, through the
/// manager proxy at `proxy` (`<hint>:<port>`). Fails when no router is running.
pub(crate) fn push_route(host: &str, port: u16, until: i64, proxy: &str) -> Result<RouterStatus, CliError> {
    let body = serde_json::to_vec(&Route {
        host: host.to_owned(),
        port,
        until,
        proxy: proxy.to_owned(),
    })
    .expect("route serializes");
    let body = admin_call("POST", "/routes", Some(&body))?
        .ok_or_else(|| CliError::failure("no asm proxy-router is running on this machine"))?;
    decode_status(&body)
}

fn decode_status(body: &[u8]) -> Result<RouterStatus, CliError> {
    serde_json::from_slice(body)
        .map_err(|e| CliError::failure(format!("the proxy router sent an invalid status: {e}")))
}

/// One HTTP/1.1 request over the admin socket; `Ok(None)` when nothing listens.
fn admin_call(method: &str, path: &str, body: Option<&[u8]>) -> Result<Option<Vec<u8>>, CliError> {
    let sock = socket_path()?;
    let fail = |e: std::io::Error| {
        CliError::failure(format!("talking to the proxy router at {}: {e}", sock.display()))
    };
    let mut s = match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            return Ok(None);
        }
        Err(e) => return Err(fail(e)),
    };
    s.set_read_timeout(Some(Duration::from_secs(5))).map_err(fail)?;
    s.set_write_timeout(Some(Duration::from_secs(5))).map_err(fail)?;
    let body = body.unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: asm-proxy-router\r\nConnection: close\r\n"
    )
    .into_bytes();
    if method == "POST" {
        req.extend_from_slice(
            format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()).as_bytes(),
        );
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    s.write_all(&req).map_err(fail)?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(fail)?;
    let invalid = || CliError::failure("the proxy router sent an invalid response");
    let end = head_end(&resp).ok_or_else(invalid)?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    if !matches!(parsed.parse(&resp[..end]), Ok(httparse::Status::Complete(_))) {
        return Err(invalid());
    }
    let code = parsed.code.ok_or_else(invalid)?;
    let body = resp[end..].to_vec();
    if code != 200 {
        return Err(CliError::failure(format!(
            "the proxy router answered {code}: {}",
            String::from_utf8_lossy(&body).trim()
        )));
    }
    Ok(Some(body))
}

/// `asm proxy-router status`.
fn print_status(json: bool) -> Result<(), CliError> {
    let st = status()?.ok_or_else(|| CliError::failure("no asm proxy-router is running on this machine"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&st).expect("serializes"));
        return Ok(());
    }
    println!("router: running on 127.0.0.1:{} (asm {})", st.port, st.version);
    println!("routes: {}", st.routes.len());
    for r in &st.routes {
        println!("  {}:{} until {}", r.host, r.port, r.expires_at);
    }
    match &st.last_routed {
        Some(l) => println!("last routed: {}:{} at {}", l.host, l.port, l.at),
        None => println!("last routed: never"),
    }
    if let Some(e) = &st.last_error {
        println!("last error: {e}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Router state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Direct,
    Routed,
}

struct Tunnel {
    host: String,
    port: u16,
    kind: Kind,
    abort: Arc<Notify>,
}

#[derive(Default)]
struct RouteState {
    routes: Vec<Route>,
    last_error: Option<String>,
    last_routed: Option<LastRouted>,
}

struct Router {
    port: u16,
    dir: PathBuf,
    /// `host.json` at startup; re-read per routed CONNECT so a re-pairing applies.
    host: HostState,
    state: RwLock<RouteState>,
    tunnels: Mutex<HashMap<u64, Tunnel>>,
    next_id: AtomicU64,
}

/// Removes its tunnel from the registry when the connection ends.
struct TunnelGuard {
    router: Arc<Router>,
    id: u64,
    abort: Arc<Notify>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.router.tunnels.lock().unwrap().remove(&self.id);
    }
}

fn live_route<'a>(routes: &'a [Route], host: &str, port: u16, now: i64) -> Option<&'a Route> {
    routes
        .iter()
        .find(|r| r.host == host && r.port == port && r.until > now)
}

impl Router {
    fn current_route(&self, host: &str, port: u16) -> Option<Route> {
        let st = self.state.read().unwrap();
        live_route(&st.routes, host, port, unix_now()).cloned()
    }

    /// Register a tunnel while the routing decision `kind` still holds for
    /// `host:port`, under the read lock so no route update slips in between.
    /// `None` when it no longer holds.
    fn register(self: &Arc<Self>, host: &str, port: u16, kind: Kind) -> Option<TunnelGuard> {
        let st = self.state.read().unwrap();
        let routed = live_route(&st.routes, host, port, unix_now()).is_some();
        if routed != (kind == Kind::Routed) {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let abort = Arc::new(Notify::new());
        self.tunnels.lock().unwrap().insert(
            id,
            Tunnel {
                host: host.to_owned(),
                port,
                kind,
                abort: abort.clone(),
            },
        );
        drop(st);
        Some(TunnelGuard {
            router: self.clone(),
            id,
            abort,
        })
    }

    /// Change the routes under the write lock; when they changed, persist them and
    /// close direct tunnels to newly routed pairs and routed tunnels whose route is gone.
    fn update(&self, change: impl FnOnce(&mut Vec<Route>)) {
        let mut st = self.state.write().unwrap();
        let before = st.routes.clone();
        change(&mut st.routes);
        if st.routes == before {
            return;
        }
        let file = RoutesFile {
            routes: st.routes.clone(),
        };
        if let Err(e) = write_file_atomic(
            &self.dir,
            ROUTES_NAME,
            &serde_json::to_vec_pretty(&file).expect("routes serialize"),
        ) {
            eprintln!("asm proxy-router: saving routes: {}", e.message);
        }
        let routed = |host: &str, port: u16| st.routes.iter().any(|r| r.host == host && r.port == port);
        for t in self.tunnels.lock().unwrap().values() {
            let abort = match t.kind {
                Kind::Direct => routed(&t.host, t.port),
                Kind::Routed => !routed(&t.host, t.port),
            };
            if abort {
                t.abort.notify_one();
            }
        }
    }

    fn status(&self) -> RouterStatus {
        let st = self.state.read().unwrap();
        RouterStatus {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            port: self.port,
            routes: st
                .routes
                .iter()
                .map(|r| RouteStatus {
                    host: r.host.clone(),
                    port: r.port,
                    expires_at: asm_proto::time::fmt_unix(r.until),
                })
                .collect(),
            last_error: st.last_error.clone(),
            last_routed: st.last_routed.clone(),
        }
    }

    /// Record a routed CONNECT's outcome and log it. `error` replaces `last_error`;
    /// a 200 clears it; otherwise it stays.
    fn note_routed(&self, host: &str, port: u16, status: u16, error: Option<String>) {
        eprintln!("routed {}:{port} -> {status}", host);
        let mut st = self.state.write().unwrap();
        st.last_routed = Some(LastRouted {
            host: host.to_owned(),
            port,
            at: asm_proto::time::fmt_unix(unix_now()),
        });
        match error {
            Some(e) => {
                eprintln!("asm proxy-router: {e}");
                st.last_error = Some(e);
            }
            None if status == 200 => st.last_error = None,
            None => {}
        }
    }

    /// `Proxy-Authorization` for the manager's proxy, from the current `host.json`.
    fn proxy_authorization(&self) -> String {
        match state::load() {
            Ok(Some(h)) => crate::proxy::proxy_authorization(&h),
            _ => crate::proxy::proxy_authorization(&self.host),
        }
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn serve(port: u16) -> Result<(), CliError> {
    let dir = state::config_dir()?;
    ensure_private_dir(&dir)?;
    let lock = lock_file(&dir, LOCK_NAME, false).map_err(|e| {
        CliError::failure(format!("locking {}: {e}", dir.join(LOCK_NAME).display()))
    })?;
    let Some(_lock) = lock else {
        eprintln!("asm proxy-router: already running");
        return Ok(());
    };
    let host = state::require()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::failure(format!("starting the router runtime: {e}")))?;
    rt.block_on(serve_async(port, dir, host))
}

async fn serve_async(port: u16, dir: PathBuf, host: HostState) -> Result<(), CliError> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| CliError::failure(format!("binding 127.0.0.1:{port}: {e}")))?;
    let sock = dir.join(SOCKET_NAME);
    match std::fs::remove_file(&sock) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(CliError::failure(format!("removing {}: {e}", sock.display()))),
    }
    let admin = UnixListener::bind(&sock)
        .map_err(|e| CliError::failure(format!("binding {}: {e}", sock.display())))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CliError::failure(format!("setting permissions of {}: {e}", sock.display())))?;
    }
    let routes = load_routes(&dir);
    let router = Arc::new(Router {
        port,
        dir,
        host,
        state: RwLock::new(RouteState::default()),
        tunnels: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(0),
    });
    // Persists the reloaded set (expired routes dropped) when it differs from the file.
    router.update(|r| *r = routes);
    eprintln!(
        "asm proxy-router {} listening on 127.0.0.1:{port}",
        env!("CARGO_PKG_VERSION")
    );

    let ticker = router.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(1));
        loop {
            every.tick().await;
            let now = unix_now();
            let expired = ticker.state.read().unwrap().routes.iter().any(|r| r.until <= now);
            if expired {
                ticker.update(|routes| {
                    routes.retain(|r| {
                        let keep = r.until > now;
                        if !keep {
                            eprintln!("route {}:{} expired", r.host, r.port);
                        }
                        keep
                    })
                });
            }
        }
    });

    let admin_router = router.clone();
    tokio::spawn(async move {
        loop {
            match admin.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(admin_conn(admin_router.clone(), s));
                }
                Err(e) => {
                    eprintln!("asm proxy-router: admin accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((mut client, _)) => match slots.clone().try_acquire_owned() {
                Ok(permit) => {
                    let router = router.clone();
                    tokio::spawn(async move {
                        proxy_conn(router, client).await;
                        drop(permit);
                    });
                }
                Err(_) => {
                    tokio::spawn(async move {
                        respond(&mut client, 503, "Service Unavailable", "asm proxy-router: too many connections").await;
                    });
                }
            },
            Err(e) => {
                eprintln!("asm proxy-router: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Routes from `router-routes.json`, without those already past `until`.
fn load_routes(dir: &Path) -> Vec<Route> {
    let path = dir.join(ROUTES_NAME);
    let file: RoutesFile = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!("asm proxy-router: ignoring {}: {e}", path.display());
            RoutesFile::default()
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => RoutesFile::default(),
        Err(e) => {
            eprintln!("asm proxy-router: reading {}: {e}", path.display());
            RoutesFile::default()
        }
    };
    let now = unix_now();
    file.routes
        .into_iter()
        .filter(|r| r.until > now && validate_route(r).is_ok())
        .collect()
}

fn validate_route(r: &Route) -> Result<(), String> {
    let host = asm_proto::rules::normalize_host_pattern(&r.host).map_err(|e| e.message)?;
    if host != r.host || host.contains(['*', '?', '[']) {
        return Err("host must be a lowercase host name".into());
    }
    if r.port == 0 {
        return Err("port must be 1-65535".into());
    }
    if r.until <= 0 {
        return Err("until must be a unix time".into());
    }
    if split_authority(&r.proxy, None).is_none() {
        return Err("proxy must be <host>:<port>".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// End of an HTTP head (after the blank line), if complete.
fn head_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[derive(Debug)]
enum HeadError {
    TooLarge,
    Closed,
}

/// Read until the end of a head (at most [`MAX_HEAD`] bytes). Returns the buffer and
/// the head length; bytes past the head stay in the buffer.
async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Vec<u8>, usize), HeadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buf) {
            return if end > MAX_HEAD {
                Err(HeadError::TooLarge)
            } else {
                Ok((buf, end))
            };
        }
        if buf.len() > MAX_HEAD {
            return Err(HeadError::TooLarge);
        }
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(HeadError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

struct RequestHead {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl RequestHead {
    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

fn parse_request(head: &[u8]) -> Result<RequestHead, httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head)? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(httparse::Error::Token),
    }
    Ok(RequestHead {
        method: req.method.unwrap_or_default().to_owned(),
        target: req.path.unwrap_or_default().to_owned(),
        headers: req
            .headers
            .iter()
            .map(|h| (h.name.to_owned(), h.value.to_vec()))
            .collect(),
    })
}

struct ResponseHead {
    code: u16,
    reason: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl ResponseHead {
    fn content_length(&self) -> Option<usize> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| std::str::from_utf8(v).ok()?.trim().parse().ok())
    }
}

fn parse_response(head: &[u8]) -> Option<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    Some(ResponseHead {
        code: resp.code?,
        reason: resp.reason.unwrap_or_default().to_owned(),
        headers: resp
            .headers
            .iter()
            .map(|h| (h.name.to_owned(), h.value.to_vec()))
            .collect(),
    })
}

/// `host[:port]` or `[v6][:port]` → lowercase host and port (`default` when absent).
fn split_authority(a: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(p) => (h, Some(p)),
            None if after.is_empty() => (h, None),
            None => return None,
        }
    } else {
        match a.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        }
    };
    if host.is_empty() || host.contains(['/', '@', ' ']) || (!a.starts_with('[') && host.contains(':')) {
        return None;
    }
    let port = match port {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u16>().ok().filter(|p| *p != 0)?
        }
        Some(_) => return None,
        None => default?,
    };
    Some((host.to_ascii_lowercase(), port))
}

/// Write a complete plain-text response and close, letting the client read it first.
async fn respond<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, code: u16, reason: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_and_close(s, msg.as_bytes()).await;
}

/// Write `data`, shut down the write side, and drain briefly so unread request bytes
/// do not turn the close into a reset that hides the response.
async fn write_and_close<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, data: &[u8]) {
    let _ = timeout(Duration::from_secs(5), async {
        let _ = s.write_all(data).await;
        let _ = s.shutdown().await;
    })
    .await;
    let _ = timeout(Duration::from_millis(500), async {
        let mut sink = [0u8; 4096];
        let mut total = 0;
        while total < MAX_BODY {
            match s.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    })
    .await;
}

async fn tunnel(mut client: TcpStream, mut upstream: TcpStream, guard: TunnelGuard) {
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
        _ = guard.abort.notified() => {}
    }
}

/// Connect the way browsers do (RFC 8305, simplified): resolve, alternate address
/// families, and start the next attempt every 250 ms while earlier ones are still
/// pending; the first connection wins. A network whose IPv6 route silently drops
/// packets then still connects over IPv4 instead of timing out.
async fn dial(target: impl ToSocketAddrs) -> Result<TcpStream, String> {
    match timeout(DIAL_TIMEOUT, race_addresses(target)).await {
        Ok(result) => result,
        Err(_) => Err("connection timed out".into()),
    }
}

async fn race_addresses(target: impl ToSocketAddrs) -> Result<TcpStream, String> {
    const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await.map_err(|e| e.to_string())?.collect();
    let mut queue = interleave_families(addrs).into_iter();
    let mut attempts = tokio::task::JoinSet::new();
    let mut last_error = String::from("no addresses");
    loop {
        if let Some(addr) = queue.next() {
            attempts.spawn(TcpStream::connect(addr));
        }
        let outcome = if queue.len() > 0 {
            match timeout(ATTEMPT_DELAY, attempts.join_next()).await {
                Ok(outcome) => outcome,
                Err(_) => continue,
            }
        } else {
            attempts.join_next().await
        };
        match outcome {
            // Dropping `attempts` aborts the slower connections.
            Some(Ok(Ok(stream))) => return Ok(stream),
            Some(Ok(Err(e))) => last_error = e.to_string(),
            Some(Err(e)) => last_error = e.to_string(),
            None => return Err(last_error),
        }
    }
}

/// Alternate address families, starting with the resolver's first choice.
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (mut first, mut other): (VecDeque<_>, VecDeque<_>) =
        addrs.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(first.len() + other.len());
    while !first.is_empty() || !other.is_empty() {
        out.extend(first.pop_front());
        out.extend(other.pop_front());
    }
    out
}

// ---------------------------------------------------------------------------
// Admin connections
// ---------------------------------------------------------------------------

async fn admin_conn(router: Arc<Router>, mut s: UnixStream) {
    let json = |code: u16, v: &serde_json::Value| {
        let body = v.to_string();
        let reason = match code {
            200 => "OK",
            404 => "Not Found",
            431 => "Request Header Fields Too Large",
            _ => "Bad Request",
        };
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let error = |code: u16, msg: &str| json(code, &serde_json::json!({ "error": msg }));
    let (buf, end) = match timeout(HEAD_TIMEOUT, read_head(&mut s)).await {
        Ok(Ok(h)) => h,
        Ok(Err(HeadError::TooLarge)) => {
            return write_and_close(&mut s, error(431, "request head too large").as_bytes()).await;
        }
        _ => return,
    };
    let Ok(head) = parse_request(&buf[..end]) else {
        return write_and_close(&mut s, error(400, "malformed request").as_bytes()).await;
    };
    let reply = match (head.method.as_str(), head.target.as_str()) {
        ("GET", "/status") => json(200, &serde_json::to_value(router.status()).expect("status serializes")),
        ("POST", "/routes") => {
            let len = head
                .values("content-length")
                .next()
                .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse::<usize>().ok());
            match len {
                Some(len) if len <= MAX_BODY => {
                    let mut body = buf[end..].to_vec();
                    body.truncate(len);
                    let rest = len - body.len();
                    let mut more = vec![0u8; rest];
                    match timeout(HEAD_TIMEOUT, s.read_exact(&mut more)).await {
                        Ok(Ok(_)) => {
                            body.extend_from_slice(&more);
                            match serde_json::from_slice::<Route>(&body)
                                .map_err(|e| e.to_string())
                                .and_then(|r| validate_route(&r).map(|()| r))
                            {
                                Ok(route) => {
                                    eprintln!(
                                        "route {}:{} via {} until {}",
                                        route.host,
                                        route.port,
                                        route.proxy,
                                        asm_proto::time::fmt_unix(route.until)
                                    );
                                    router.update(|routes| {
                                        routes.retain(|r| !(r.host == route.host && r.port == route.port));
                                        routes.push(route);
                                    });
                                    json(200, &serde_json::to_value(router.status()).expect("status serializes"))
                                }
                                Err(e) => error(400, &format!("invalid route: {e}")),
                            }
                        }
                        _ => return,
                    }
                }
                _ => error(400, "POST /routes needs a JSON body with Content-Length"),
            }
        }
        _ => error(404, "not found"),
    };
    write_and_close(&mut s, reply.as_bytes()).await;
}

// ---------------------------------------------------------------------------
// Proxy connections
// ---------------------------------------------------------------------------

async fn proxy_conn(router: Arc<Router>, mut client: TcpStream) {
    let (buf, end) = match timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(h)) => h,
        Ok(Err(HeadError::TooLarge)) => {
            return respond(
                &mut client,
                431,
                "Request Header Fields Too Large",
                "asm proxy-router: request head too large",
            )
            .await;
        }
        _ => return,
    };
    let head = match parse_request(&buf[..end]) {
        Ok(h) => h,
        Err(httparse::Error::TooManyHeaders) => {
            return respond(
                &mut client,
                431,
                "Request Header Fields Too Large",
                "asm proxy-router: too many request headers",
            )
            .await;
        }
        Err(_) => {
            return respond(&mut client, 400, "Bad Request", "asm proxy-router: malformed request").await;
        }
    };
    let extra = buf[end..].to_vec();
    if head.method == "CONNECT" {
        let Some((host, port)) = split_authority(&head.target, None) else {
            return respond(
                &mut client,
                400,
                "Bad Request",
                "asm proxy-router: CONNECT needs host:port",
            )
            .await;
        };
        connect(router, client, host, port, extra).await;
    } else if head.target.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
        forward_http(client, head, extra).await;
    } else {
        respond(&mut client, 400, "Bad Request", "asm proxy-router: not a proxy request").await;
    }
}

async fn connect(router: Arc<Router>, mut client: TcpStream, host: String, port: u16, extra: Vec<u8>) {
    if let Some(route) = router.current_route(&host, port) {
        return routed(router, client, host, port, route, extra).await;
    }
    let mut upstream = match dial((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("asm proxy-router: cannot connect to {}: {e}", authority(&host, port));
            return respond(&mut client, 502, "Bad Gateway", &msg).await;
        }
    };
    let Some(guard) = router.register(&host, port, Kind::Direct) else {
        // A route appeared while dialing: nothing was sent, so route it instead.
        drop(upstream);
        return match router.current_route(&host, port) {
            Some(route) => routed(router, client, host, port, route, extra).await,
            None => respond(&mut client, 503, "Service Unavailable", "asm proxy-router: routes changed; retry").await,
        };
    };
    if client.write_all(ESTABLISHED).await.is_err() || upstream.write_all(&extra).await.is_err() {
        return;
    }
    tunnel(client, upstream, guard).await;
}

async fn routed(router: Arc<Router>, mut client: TcpStream, host: String, port: u16, route: Route, extra: Vec<u8>) {
    let target = authority(&host, port);
    let no_answer = format!(
        "asm proxy-router: the asm proxy at {} did not answer; run asm doctor",
        route.proxy
    );
    let mut up = match dial(route.proxy.as_str()).await {
        Ok(s) => s,
        _ => {
            let msg = format!(
                "asm proxy-router: cannot reach the asm proxy at {}; run asm doctor",
                route.proxy
            );
            router.note_routed(&host, port, 502, Some(format!("{target}: cannot reach the asm proxy at {}", route.proxy)));
            return respond(&mut client, 502, "Bad Gateway", &msg).await;
        }
    };
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nAsm-Browser-Route: 1\r\nProxy-Authorization: {}\r\n\r\n",
        router.proxy_authorization()
    );
    let answer = match up.write_all(req.as_bytes()).await {
        Ok(()) => match timeout(HEAD_TIMEOUT, read_head(&mut up)).await {
            Ok(Ok((buf, end))) => parse_response(&buf[..end]).map(|h| (h, buf[end..].to_vec())),
            _ => None,
        },
        Err(_) => None,
    };
    let Some((resp, rest)) = answer else {
        router.note_routed(&host, port, 502, Some(format!("{target}: the asm proxy at {} did not answer", route.proxy)));
        return respond(&mut client, 502, "Bad Gateway", &no_answer).await;
    };
    match resp.code {
        200 => {
            let Some(guard) = router.register(&host, port, Kind::Routed) else {
                router.note_routed(&host, port, 502, None);
                return respond(
                    &mut client,
                    502,
                    "Bad Gateway",
                    &format!("asm proxy-router: the route for {target} ended; reload the page"),
                )
                .await;
            };
            router.note_routed(&host, port, 200, None);
            if client.write_all(ESTABLISHED).await.is_err()
                || client.write_all(&rest).await.is_err()
                || up.write_all(&extra).await.is_err()
            {
                return;
            }
            tunnel(client, up, guard).await;
        }
        407 => {
            router.note_routed(&host, port, 502, Some(format!("{target}: the manager rejected this host's proxy credentials")));
            respond(
                &mut client,
                502,
                "Bad Gateway",
                "asm proxy-router: the manager rejected this host's proxy credentials; run asm doctor",
            )
            .await;
        }
        code => {
            let body = read_body(&mut up, &resp, rest).await;
            let no_grant = code == 403 && body.windows(NO_GRANT.len()).any(|w| w == NO_GRANT);
            if no_grant {
                router.update(|routes| routes.retain(|r| !(r.host == host && r.port == port)));
                router.note_routed(&host, port, code, None);
            } else {
                let text = String::from_utf8_lossy(&body);
                let text = text.trim();
                let detail = if text.is_empty() { String::new() } else { format!(": {text}") };
                router.note_routed(&host, port, code, Some(format!("{target}: the asm proxy answered {code}{detail}")));
            }
            write_and_close(&mut client, &relay_head(&resp, &body)).await;
        }
    }
}

/// The body of a non-200 CONNECT answer: `Content-Length` bytes, else until close;
/// at most [`MAX_BODY`], within [`BODY_TIMEOUT`].
async fn read_body(up: &mut TcpStream, resp: &ResponseHead, mut body: Vec<u8>) -> Vec<u8> {
    let want = resp.content_length().unwrap_or(MAX_BODY).min(MAX_BODY);
    let _ = timeout(BODY_TIMEOUT, async {
        let mut chunk = [0u8; 4096];
        while body.len() < want {
            match up.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    body.truncate(want);
    body
}

/// A proxy answer relayed to the client with `Connection: close` and an exact length.
fn relay_head(resp: &ResponseHead, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.code, resp.reason).into_bytes();
    for (name, value) in &resp.headers {
        let skip = ["connection", "proxy-connection", "keep-alive", "content-length", "transfer-encoding"]
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h));
        if !skip {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// Absolute-form `http://` request (OpenBot's single-proxy setting): always direct,
/// one request per connection.
async fn forward_http(mut client: TcpStream, head: RequestHead, extra: Vec<u8>) {
    let rest = &head.target[7..];
    let (auth, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let Some((host, port)) = split_authority(auth, Some(80)) else {
        return respond(&mut client, 400, "Bad Request", "asm proxy-router: invalid URL authority").await;
    };
    if head.values("transfer-encoding").next().is_some() {
        return respond(
            &mut client,
            411,
            "Length Required",
            "asm proxy-router: request bodies need Content-Length",
        )
        .await;
    }
    let lengths: Vec<&[u8]> = head.values("content-length").collect();
    let length = match lengths.as_slice() {
        [] => Some(0u64),
        [v] => std::str::from_utf8(v)
            .ok()
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse().ok()),
        _ => None,
    };
    let Some(length) = length else {
        return respond(&mut client, 400, "Bad Request", "asm proxy-router: invalid Content-Length").await;
    };
    let mut up = match dial((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("asm proxy-router: cannot connect to {}: {e}", authority(&host, port));
            return respond(&mut client, 502, "Bad Gateway", &msg).await;
        }
    };
    let mut req = format!("{} {path} HTTP/1.1\r\n", head.method).into_bytes();
    for (name, value) in &head.headers {
        let skip = name.eq_ignore_ascii_case("host") || HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h));
        if !skip {
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(b": ");
            req.extend_from_slice(value);
            req.extend_from_slice(b"\r\n");
        }
    }
    req.extend_from_slice(format!("Host: {auth}\r\nConnection: close\r\n\r\n").as_bytes());
    let buffered = extra.len().min(usize::try_from(length).unwrap_or(usize::MAX));
    req.extend_from_slice(&extra[..buffered]);
    if up.write_all(&req).await.is_err() {
        return;
    }
    let remaining = length - buffered as u64;
    if remaining > 0 {
        let mut body = (&mut client).take(remaining);
        match tokio::io::copy(&mut body, &mut up).await {
            Ok(n) if n == remaining => {}
            _ => return,
        }
    }
    let _ = tokio::io::copy(&mut up, &mut client).await;
    let _ = client.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_families_alternate_starting_with_the_resolvers_choice() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let resolved = vec![a("[2001:db8::1]:443"), a("[2001:db8::2]:443"), a("192.0.2.1:443"), a("192.0.2.2:443"), a("192.0.2.3:443")];
        assert_eq!(
            interleave_families(resolved),
            [a("[2001:db8::1]:443"), a("192.0.2.1:443"), a("[2001:db8::2]:443"), a("192.0.2.2:443"), a("192.0.2.3:443")]
        );
        assert_eq!(interleave_families(vec![a("192.0.2.1:80"), a("[2001:db8::1]:80")]), [a("192.0.2.1:80"), a("[2001:db8::1]:80")]);
    }

    #[tokio::test]
    async fn an_unanswered_first_address_does_not_block_the_next() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // TEST-NET-1 is never routed: its SYN is dropped or refused, like a broken IPv6 path.
        let addrs = [SocketAddr::from(([192, 0, 2, 1], 9)), listener.local_addr().unwrap()];
        let started = std::time::Instant::now();
        let stream = dial(&addrs[..]).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addrs[1]);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn authorities() {
        assert_eq!(split_authority("Example.test:443", None), Some(("example.test".into(), 443)));
        assert_eq!(split_authority("[::1]:8080", None), Some(("::1".into(), 8080)));
        assert_eq!(split_authority("example.test", Some(80)), Some(("example.test".into(), 80)));
        for bad in ["example.test", "example.test:", "example.test:0", "example.test:+1", "::1:80", "a@b:80", ":80"] {
            assert_eq!(split_authority(bad, None), None, "{bad}");
        }
        assert_eq!(split_authority("[::1]", Some(443)), Some(("::1".into(), 443)));
    }

    #[test]
    fn heads_end_at_the_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(head_end(b"GET / HTTP/1.1\n\nx"), Some(16));
    }

    #[test]
    fn routes_are_validated() {
        let ok = Route { host: "example.test".into(), port: 443, until: 1, proxy: "mac.ts.net:7412".into() };
        assert!(validate_route(&ok).is_ok());
        for bad in [
            Route { host: "Example.test".into(), ..ok.clone() },
            Route { host: "*.example.test".into(), ..ok.clone() },
            Route { port: 0, ..ok.clone() },
            Route { until: 0, ..ok.clone() },
            Route { proxy: "mac.ts.net".into(), ..ok.clone() },
        ] {
            assert!(validate_route(&bad).is_err(), "{bad:?}");
        }
    }
}
