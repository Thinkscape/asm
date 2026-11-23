//! Runs `asm proxy-router run` against fake upstreams: a fake manager proxy that
//! records CONNECT heads, a TCP echo server and a plain HTTP origin.

use asm_proto::crypto::{proxy_password, sha256};
use base64::Engine as _;
use serde_json::{Value, json};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TOKEN: &str = "host-token-abc";

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A configuration directory with a paired `host.json`. Kept short: the admin socket
/// path must fit `sun_path`.
struct Env {
    _tmp: tempfile::TempDir,
    cfg: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::Builder::new().prefix("asmr").tempdir_in("/tmp").unwrap();
        let cfg = tmp.path().join("cfg");
        std::fs::create_dir_all(cfg.join("asm")).unwrap();
        let host = json!({"manager_url": "https://127.0.0.1:1", "cert_sha256": "00".repeat(32),
            "host_id": "h1", "token": TOKEN, "paired_at": "2026-11-16T00:00:00Z"});
        std::fs::write(cfg.join("asm/host.json"), host.to_string()).unwrap();
        Env { _tmp: tmp, cfg }
    }

    fn dir(&self) -> PathBuf {
        self.cfg.join("asm")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_asm"));
        c.args(args)
            .env_clear()
            .env("HOME", self.cfg.parent().unwrap())
            .env("XDG_CONFIG_HOME", &self.cfg)
            .stdin(Stdio::null());
        c
    }

    /// One admin request over `router.sock`.
    fn admin(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let mut s = UnixStream::connect(self.dir().join("router.sock")).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: r\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        let (head, body) = resp.split_once("\r\n\r\n").unwrap();
        let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, serde_json::from_str(body).unwrap())
    }

    fn status(&self) -> Value {
        let (code, v) = self.admin("GET", "/status", None);
        assert_eq!(code, 200, "{v}");
        v
    }

    fn push(&self, host: &str, port: u16, until: i64, proxy: &str) -> Value {
        let (code, v) = self.admin(
            "POST",
            "/routes",
            Some(&json!({"host": host, "port": port, "until": until, "proxy": proxy})),
        );
        assert_eq!(code, 200, "{v}");
        v
    }
}

/// A running router, killed on drop.
struct Router {
    child: Child,
    port: u16,
}

impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_router(e: &Env) -> Router {
    let port = free_port();
    let child = e
        .command(&["proxy-router", "run", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let router = Router { child, port };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if UnixStream::connect(e.dir().join("router.sock")).is_ok() && TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return router;
        }
        assert!(Instant::now() < deadline, "router did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn routes(status: &Value) -> Vec<(String, u64)> {
    status["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["host"].as_str().unwrap().to_owned(), r["port"].as_u64().unwrap()))
        .collect()
}

/// Read an HTTP head (through the blank line), byte by byte.
fn read_head(s: &mut impl Read) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn status_code(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0)
}

/// CONNECT through the router; the stream and the response head.
fn connect(router: &Router, target: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(("127.0.0.1", router.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let head = read_head(&mut s);
    (s, head)
}

fn read_rest(s: &mut TcpStream) -> String {
    let mut rest = String::new();
    let _ = s.read_to_string(&mut rest);
    rest
}

fn roundtrip(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).unwrap();
    let mut got = vec![0u8; msg.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, msg);
}

/// Echo every connection's bytes back.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let mut w = s;
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    port
}

#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// 200, then echo.
    Tunnel,
    NoGrant,
    Forbidden,
    BadCredentials,
    /// Close without a response.
    Drop,
}

/// A fake manager proxy recording each CONNECT head.
struct FakeProxy {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
    answer: Arc<Mutex<Answer>>,
}

fn fake_proxy(answer: Answer) -> FakeProxy {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(Mutex::new(answer));
    let (h, a) = (heads.clone(), answer.clone());
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let (h, a) = (h.clone(), a.clone());
            std::thread::spawn(move || {
                let head = read_head(&mut s);
                h.lock().unwrap().push(head);
                let body = |code: &str, text: &str| {
                    format!("HTTP/1.1 {code}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{text}", text.len())
                };
                let answer = *a.lock().unwrap();
                match answer {
                    Answer::Tunnel => {
                        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
                        let mut r = s.try_clone().unwrap();
                        let _ = std::io::copy(&mut r, &mut s);
                    }
                    Answer::NoGrant => {
                        let _ = s.write_all(body("403 Forbidden", "asm: no active login grant routes this host through asm").as_bytes());
                    }
                    Answer::Forbidden => {
                        let _ = s.write_all(body("403 Forbidden", "asm: browser routing is not enabled on this manager").as_bytes());
                    }
                    Answer::BadCredentials => {
                        let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"asm\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Answer::Drop => {}
                }
            });
        }
    });
    FakeProxy { port, heads, answer }
}

impl FakeProxy {
    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
    fn set(&self, a: Answer) {
        *self.answer.lock().unwrap() = a;
    }
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

#[test]
fn routed_connect_sends_marker_and_credentials_and_relays_bytes() {
    let e = Env::new();
    let r = start_router(&e);
    let proxy = fake_proxy(Answer::Tunnel);
    let status = e.push("example.test", 443, unix_now() + 3600, &proxy.addr());
    assert_eq!(routes(&status), vec![("example.test".into(), 443)]);
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["port"], r.port);

    let (mut s, head) = connect(&r, "example.test:443");
    assert_eq!(status_code(&head), 200, "{head}");
    roundtrip(&mut s, b"client hello bytes");

    let heads = proxy.heads();
    assert_eq!(heads.len(), 1);
    let pw = proxy_password(&sha256(TOKEN.as_bytes()));
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("h1:{pw}"));
    let head = &heads[0];
    assert!(head.starts_with("CONNECT example.test:443 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nAsm-Browser-Route: 1\r\n"), "{head}");
    assert!(head.contains(&format!("\r\nProxy-Authorization: Basic {basic}\r\n")), "{head}");

    let status = e.status();
    assert_eq!(status["last_routed"]["host"], "example.test");
    assert_eq!(status["last_routed"]["port"], 443);
    assert!(status["last_error"].is_null());
}

#[test]
fn no_grant_answer_drops_the_route_and_reaches_the_client() {
    let e = Env::new();
    let r = start_router(&e);
    let proxy = fake_proxy(Answer::NoGrant);
    e.push("example.test", 443, unix_now() + 3600, &proxy.addr());
    let (mut s, head) = connect(&r, "example.test:443");
    assert_eq!(status_code(&head), 403, "{head}");
    assert!(head.contains("Connection: close"), "{head}");
    assert!(read_rest(&mut s).contains("no active login grant"));
    assert!(routes(&e.status()).is_empty());
    let saved: Value = serde_json::from_slice(&std::fs::read(e.dir().join("router-routes.json")).unwrap()).unwrap();
    assert_eq!(saved["routes"], json!([]));
    assert_eq!(proxy.heads().len(), 1);
}

#[test]
fn routed_failures_answer_502_and_never_go_direct() {
    let e = Env::new();
    let r = start_router(&e);
    let echo = echo_server();
    let proxy = fake_proxy(Answer::Drop);
    // Routed to a reachable origin: still never dialed directly.
    e.push("127.0.0.1", echo, unix_now() + 3600, &proxy.addr());
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 502, "{head}");
    assert!(read_rest(&mut s).contains("did not answer; run asm doctor"));

    proxy.set(Answer::BadCredentials);
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 502, "{head}");
    assert_eq!(
        read_rest(&mut s),
        "asm proxy-router: the manager rejected this host's proxy credentials; run asm doctor"
    );

    proxy.set(Answer::Forbidden);
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 403, "{head}");
    assert!(head.contains("Connection: close"), "{head}");
    assert!(read_rest(&mut s).contains("browser routing is not enabled"));
    let status = e.status();
    assert_eq!(routes(&status).len(), 1, "only a no-grant answer drops the route");
    assert!(status["last_error"].as_str().unwrap().contains("403"), "{status}");

    let closed = free_port();
    e.push("127.0.0.1", echo, unix_now() + 3600, &format!("127.0.0.1:{closed}"));
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 502, "{head}");
    assert_eq!(
        read_rest(&mut s),
        format!("asm proxy-router: cannot reach the asm proxy at 127.0.0.1:{closed}; run asm doctor")
    );
    assert_eq!(proxy.heads().len(), 3);
}

#[test]
fn other_connects_go_direct_and_close_when_their_target_gets_routed() {
    let e = Env::new();
    let r = start_router(&e);
    let echo = echo_server();
    let proxy = fake_proxy(Answer::Tunnel);
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 200, "{head}");
    roundtrip(&mut s, b"direct");
    assert!(proxy.heads().is_empty());

    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let routed_at = Instant::now();
    e.push("127.0.0.1", echo, unix_now() + 3600, &proxy.addr());
    let mut buf = [0u8; 16];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(err) if err.kind() == ErrorKind::ConnectionReset => {}
        other => panic!("direct tunnel stayed open: {other:?}"),
    }
    assert!(routed_at.elapsed() < Duration::from_secs(1), "closed after {:?}", routed_at.elapsed());

    // New CONNECTs to it are routed now.
    let (mut s, head) = connect(&r, &format!("127.0.0.1:{echo}"));
    assert_eq!(status_code(&head), 200, "{head}");
    roundtrip(&mut s, b"routed");
    assert_eq!(proxy.heads().len(), 1);
}

/// A plain HTTP origin: records each request (head + Content-Length body), answers `ok`.
fn http_origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let head = read_head(&mut s);
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).unwrap();
            seen2.lock().unwrap().push(format!("{head}{}", String::from_utf8_lossy(&body)));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        }
    });
    (port, seen)
}

#[test]
fn absolute_form_http_is_forwarded_once_and_other_forms_are_refused() {
    let e = Env::new();
    let r = start_router(&e);
    let (origin, seen) = http_origin();
    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "POST http://127.0.0.1:{origin}/form?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eA==\r\nX-Keep: yes\r\nContent-Length: 5\r\n\r\nhello\
         GET http://127.0.0.1:{origin}/second HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n\r\n"
    )
    .unwrap();
    let resp = read_rest(&mut s);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("ok"), "{resp}");
    std::thread::sleep(Duration::from_millis(300));
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let req = &requests[0];
    assert!(req.starts_with("POST /form?x=1 HTTP/1.1\r\n"), "{req}");
    assert!(req.contains(&format!("\r\nHost: 127.0.0.1:{origin}\r\n")), "{req}");
    assert!(req.contains("\r\nConnection: close\r\n") && req.contains("\r\nX-Keep: yes\r\n"), "{req}");
    assert!(!req.contains("Proxy-"), "{req}");
    assert!(req.ends_with("\r\n\r\nhello"), "{req}");

    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    write!(
        s,
        "POST http://127.0.0.1:{origin}/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    )
    .unwrap();
    assert_eq!(status_code(&read_head(&mut s)), 411);

    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    write!(s, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    assert_eq!(status_code(&read_head(&mut s)), 400);
    assert_eq!(read_rest(&mut s), "asm proxy-router: not a proxy request");
    assert_eq!(seen.lock().unwrap().len(), 1, "refused requests reached the origin");
}

#[test]
fn oversized_and_malformed_heads_are_answered() {
    let e = Env::new();
    let r = start_router(&e);
    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    let big = format!("CONNECT a.test:443 HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(20 * 1024));
    let _ = s.write_all(big.as_bytes());
    assert_eq!(status_code(&read_head(&mut s)), 431);
    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    s.write_all(b"NOT A REQUEST\r\n\r\n").unwrap();
    assert_eq!(status_code(&read_head(&mut s)), 400);
}

#[test]
fn expired_routes_are_dropped_within_two_seconds() {
    let e = Env::new();
    let _r = start_router(&e);
    e.push("example.test", 443, unix_now() - 5, "127.0.0.1:9");
    let pushed = Instant::now();
    while !routes(&e.status()).is_empty() {
        assert!(pushed.elapsed() < Duration::from_secs(2), "route still listed");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn routes_survive_a_restart_and_files_are_private() {
    let e = Env::new();
    let r = start_router(&e);
    let until = unix_now() + 3600;
    e.push("example.test", 443, until, "127.0.0.1:9");
    e.push("gone.test", 443, unix_now() + 1, "127.0.0.1:9");
    let mode = |name: &str| std::fs::metadata(e.dir().join(name)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("router.sock"), 0o600);
    assert_eq!(mode("router-routes.json"), 0o600);

    // A second router exits at once: one per user.
    let out = e.command(&["proxy-router", "run", "--port", &free_port().to_string()]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"));

    drop(r);
    std::thread::sleep(Duration::from_millis(1200));
    let r = start_router(&e);
    let status = e.status();
    assert_eq!(routes(&status), vec![("example.test".into(), 443)], "{status}");
    assert_eq!(status["routes"][0]["expires_at"], asm_proto::time::fmt_unix(until));
    assert_eq!(status["port"], r.port);
    assert_eq!(mode("router.sock"), 0o600);

    // `asm proxy-router status --json` reads the same.
    let out = e.command(&["proxy-router", "status", "--json"]).output().unwrap();
    assert!(out.status.success());
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(routes(&printed), routes(&status));
    drop(r);
    let out = e.command(&["proxy-router", "status"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "error: no asm proxy-router is running on this machine"
    );
}

#[test]
fn invalid_routes_are_rejected() {
    let e = Env::new();
    let _r = start_router(&e);
    for body in [
        json!({"host": "Example.test", "port": 443, "until": 1, "proxy": "127.0.0.1:9"}),
        json!({"host": "*.example.test", "port": 443, "until": 1, "proxy": "127.0.0.1:9"}),
        json!({"host": "example.test", "port": 0, "until": 1, "proxy": "127.0.0.1:9"}),
        json!({"host": "example.test", "port": 443, "until": 1, "proxy": "nowhere"}),
        json!({"host": "example.test"}),
    ] {
        let (code, v) = e.admin("POST", "/routes", Some(&body));
        assert_eq!(code, 400, "{body} -> {v}");
    }
    let (code, _) = e.admin("GET", "/nothing", None);
    assert_eq!(code, 404);
}
