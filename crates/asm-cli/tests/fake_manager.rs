//! Runs the `asm` binary against a fake manager (HTTPS, self-signed) to check the
//! wire flow: interactive and unattended pairing, `get` (files, output, denial,
//! pending, lost request), `update`, `add`, `list`, and the background reaper.

use asm_proto::crypto::{hex_decode_array, hex_encode, sha256};
use asm_proto::pairing::{UnattendedCode, client_commit, format_pairing_code, pairing_code};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Handler = dyn Fn(&str, &str, &Value) -> (u16, Value) + Send + Sync;

struct Fake {
    port: u16,
    cert_sha256: [u8; 32],
    log: Arc<Mutex<Vec<(String, String, Value)>>>,
}

const SERVER_NONCE: [u8; 16] = [9; 16];
const TOKEN: &str = "host-token-abc";
const LEASE: &str = "11111111-2222-4333-8444-555555555555";
const REQ: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const GITHUB_REPOSITORY: &str = "acme/web";

fn start(handler: Arc<Handler>) -> Fake {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let der = ck.cert.der().to_vec();
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der.clone())],
                PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into()),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (config, handler, log) = (config.clone(), handler.clone(), log2.clone());
            std::thread::spawn(move || {
                let conn = ServerConnection::new(config).unwrap();
                let tls = StreamOwned::new(conn, stream);
                let mut reader = BufReader::new(tls);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let mut parts = line.split_whitespace();
                let (method, path) = (
                    parts.next().unwrap_or("").to_owned(),
                    parts.next().unwrap_or("").to_owned(),
                );
                let mut len = 0usize;
                let mut auth = String::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                    if k.eq_ignore_ascii_case("authorization") {
                        auth = v.trim().to_owned();
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                log.lock()
                    .unwrap()
                    .push((method.clone(), path.clone(), body.clone()));
                let host_call =
                    !(path.starts_with("/v1/pair") || path == "/v1/health" || path == "/v1/ca.crt");
                let (status, resp) = if host_call && auth != format!("Bearer {TOKEN}") {
                    (
                        401,
                        json!({"error":{"code":"unauthorized","message":"token rejected"}}),
                    )
                } else {
                    handler(&method, &path, &body)
                };
                let text = match &resp {
                    Value::String(s) => s.clone(),
                    v => v.to_string(),
                };
                let mut tls = reader.into_inner();
                let _ = write!(
                    tls,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    Fake {
        port,
        cert_sha256: sha256(&der),
        log,
    }
}

fn ca_pem() -> String {
    rcgen::generate_simple_self_signed(vec!["proxy ca".to_string()])
        .unwrap()
        .cert
        .pem()
}

struct Env {
    _tmp: tempfile::TempDir,
    cfg: PathBuf,
    secrets: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("cfg");
    let secrets = tmp.path().join("secrets");
    Env {
        _tmp: tmp,
        cfg,
        secrets,
    }
}

/// Run `asm` with the background reaper disabled.
fn asm(e: &Env, args: &[&str], stdin: &str) -> Output {
    asm_env(e, args, stdin, &[("ASM_NO_REAPER", "1")])
}

fn asm_env(e: &Env, args: &[&str], stdin: &str, vars: &[(&str, &str)]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asm"))
        .args(args)
        .env_clear()
        .env("HOME", e.cfg.parent().unwrap())
        .env("XDG_CONFIG_HOME", &e.cfg)
        .env("ASM_SECRETS_DIR", &e.secrets)
        .env("ASM_AGENT", "test-agent")
        .envs(vars.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn write_host_json(e: &Env, f: &Fake) {
    std::fs::create_dir_all(e.cfg.join("asm")).unwrap();
    let host = json!({"manager_url": format!("https://127.0.0.1:{}", f.port), "cert_sha256": hex_encode(&f.cert_sha256),
        "host_id": "h1", "token": TOKEN, "paired_at": "2026-11-16T00:00:00Z"});
    std::fs::write(e.cfg.join("asm/host.json"), host.to_string()).unwrap();
}

fn pair_handler(ca: String, commit: Arc<Mutex<Option<String>>>) -> Arc<Handler> {
    Arc::new(move |method, path, body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.1.0"})),
        ("GET", "/v1/ca.crt") => (200, Value::String(ca.clone())),
        ("POST", "/v1/pair") => {
            assert_eq!(body["host_info"]["asm_version"], env!("CARGO_PKG_VERSION"));
            if let Some(code) = body["pairing_code"].as_str() {
                assert!(code.starts_with("asm-"));
                return (
                    200,
                    json!({"status":"approved","host_id":"h-unattended","token":TOKEN}),
                );
            }
            *commit.lock().unwrap() = Some(body["client_commit"].as_str().unwrap().to_owned());
            (
                200,
                json!({"status":"awaiting_reveal","pair_id":"p1","poll_token":"pt","server_nonce":hex_encode(&SERVER_NONCE)}),
            )
        }
        ("POST", "/v1/pair/p1/reveal") => {
            let nonce: [u8; 16] = hex_decode_array(body["client_nonce"].as_str().unwrap()).unwrap();
            assert_eq!(
                commit.lock().unwrap().as_deref(),
                Some(hex_encode(&client_commit(&nonce)).as_str())
            );
            *commit.lock().unwrap() = Some(hex_encode(&nonce));
            (200, json!({"status":"pending"}))
        }
        ("GET", "/v1/pair/p1?poll_token=pt&wait=25") => (
            200,
            json!({"status":"approved","host_id":"h-1","token":TOKEN}),
        ),
        _ => (
            404,
            json!({"error":{"code":"not_found","message":format!("{method} {path}")}}),
        ),
    })
}

#[test]
fn interactive_pairing() {
    let ca = ca_pem();
    let commit = Arc::new(Mutex::new(None));
    let f = start(pair_handler(ca.clone(), commit.clone()));
    let e = env();
    let out = asm(&e, &["pair", &format!("127.0.0.1:{}", f.port)], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let nonce: [u8; 16] = hex_decode_array(commit.lock().unwrap().as_deref().unwrap()).unwrap();
    let code = format_pairing_code(pairing_code(&f.cert_sha256, &nonce, &SERVER_NONCE));
    assert!(
        stdout.contains(&format!("verification code: {code}")),
        "{stdout}"
    );
    assert!(stdout.ends_with("paired: h-1\n"), "{stdout}");
    let host: Value =
        serde_json::from_slice(&std::fs::read(e.cfg.join("asm/host.json")).unwrap()).unwrap();
    assert_eq!(host["cert_sha256"], hex_encode(&f.cert_sha256));
    assert_eq!(host["token"], TOKEN);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(e.cfg.join("asm/host.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::read_to_string(e.cfg.join("asm/ca.crt")).unwrap(),
        ca
    );
    assert!(
        std::fs::read_to_string(e.cfg.join("asm/ca-bundle.crt"))
            .unwrap()
            .ends_with(&ca)
    );
}

#[test]
fn unattended_pairing_checks_fingerprint_first() {
    let f = start(pair_handler(ca_pem(), Arc::new(Mutex::new(None))));
    let e = env();
    let wrong = UnattendedCode::generate(&sha256(b"other cert")).to_string();
    let out = asm(&e, &["pair", &format!("127.0.0.1:{}", f.port), &wrong], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("not sending it"));
    assert!(
        f.log
            .lock()
            .unwrap()
            .iter()
            .all(|(m, p, _)| !(m == "POST" && p == "/v1/pair"))
    );

    let good = UnattendedCode::generate(&f.cert_sha256).to_string();
    let out = asm(&e, &["pair", &format!("127.0.0.1:{}", f.port), &good], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "paired: h-unattended\n");
    let sent = f
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/pair")
        .unwrap()
        .2
        .clone();
    assert_eq!(sent["pairing_code"], good);
}

fn get_result(content: &str) -> Value {
    get_result_expiring(content, "2999-01-01T00:00:00Z")
}

fn get_result_expiring(content: &str, expires_at: &str) -> Value {
    json!({"lease_id":LEASE,"mode":"sentinel","hosts":["api.example.com"],"expires_at":expires_at,
        "files":[{"field":"username","relative_path":"work/GitHub.username","content":"octocat"},
                 {"field":"password","relative_path":"work/GitHub.password","content":content}]})
}

fn requests_handler(outcome: &'static str) -> Arc<Handler> {
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // A manager never changes the expiry of an existing lease, so the short lease of
    // "approve-soon" gets one fixed expiry: five seconds after it is first reported.
    let soon = Arc::new(Mutex::new(None::<i64>));
    let soon_expiry = move || *soon.lock().unwrap().get_or_insert_with(|| unix_now() + 5);
    Arc::new(move |method, path, body| match (method, path) {
        // The short lease of "approve-soon" stays active until it expires.
        ("GET", "/v1/leases") if outcome == "approve-soon" => (
            200,
            json!({"leases":[{"lease_id":LEASE,"name":"work/GitHub","mode":"sentinel","hosts":["api.example.com"],
                "expires_at":asm_proto::time::fmt_unix(soon_expiry()),"status":"active"}]}),
        ),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("GET", "/v1/secrets") => (
            200,
            json!({"secrets":[{"name":"work/GitHub","vault":"work","kind":"login","fields":["username","password"],"lease":null}],"warnings":["other: locked"]}),
        ),
        ("POST", "/v1/requests") => {
            assert_eq!(body["agent"], "test-agent");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            (
                202,
                json!({"request_id":REQ,"kind":body["kind"],"status":"pending","deny_reason":null,"result":null,
                    "expires_at":asm_proto::time::fmt_unix(now + 600),"pending_lifetime_secs":600}),
            )
        }
        ("GET", p) if p.starts_with(&format!("/v1/requests/{REQ}?wait=")) => {
            let n = polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match outcome {
                // A short lease: every approval reports the same lease and expiry.
                "approve-soon" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,
                        "result":get_result_expiring("asm_0123456789012345678901234567890123456789",
                            &asm_proto::time::fmt_unix(soon_expiry()))}),
                ),
                "approve-get" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":get_result("asm_0123456789012345678901234567890123456789")}),
                ),
                // The manager is unreachable for two polls, then approves.
                "flaky" if n < 2 => (502, Value::String("bad gateway".into())),
                "flaky" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":get_result("asm_0123456789012345678901234567890123456789"),
                        "expires_at":null,"pending_lifetime_secs":600}),
                ),
                "down" => (502, Value::String("bad gateway".into())),
                "expire" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"expired","deny_reason":null,"result":null,
                        "expires_at":null,"pending_lifetime_secs":600}),
                ),
                "approve-write" => (
                    200,
                    json!({"request_id":REQ,"kind":"update","status":"approved","deny_reason":null,"result":{"name":"work/GitHub","vault":"work"}}),
                ),
                "deny" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"denied","deny_reason":"provide a better reason","result":null}),
                ),
                "lost" => (
                    404,
                    json!({"error":{"code":"not_found","message":"no such request"}}),
                ),
                _ => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"pending","deny_reason":null,"result":null}),
                ),
            }
        }
        _ => (
            404,
            json!({"error":{"code":"not_found","message":format!("{method} {path}")}}),
        ),
    })
}

fn paired(outcome: &'static str) -> (Fake, Env) {
    let f = start(requests_handler(outcome));
    let e = env();
    write_host_json(&e, &f);
    (f, e)
}

#[test]
fn get_writes_files_and_prints_block() {
    let (f, e) = paired("approve-get");
    let out = asm(
        &e,
        &[
            "get",
            "--hosts",
            "API.example.com",
            "work/GitHub",
            "deploy the site",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let expected = format!(
        "mode: sentinel\nhosts: api.example.com\nexpires: 2999-01-01T00:00:00Z\n{}\n{}\n",
        e.secrets.join("work/GitHub.username").display(),
        e.secrets.join("work/GitHub.password").display()
    );
    assert_eq!(text(&out.stdout), expected);
    assert_eq!(
        std::fs::read_to_string(e.secrets.join("work/GitHub.username")).unwrap(),
        "octocat"
    );
    let sent = f
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/requests")
        .unwrap()
        .2
        .clone();
    assert_eq!(
        sent,
        json!({"kind":"get","name":"work/GitHub","raw":false,"sentinel":false,"fields":null,"generation":null,"refresh":false,"refresh_from_version":null,"new_lease":false,"lease_id":null,"client_capabilities":["generated_credentials_v1","secret_fields_v1","github_explicit_scope_v1"],"hosts":["api.example.com"],"reason":"deploy the site","agent":"test-agent"})
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(e.secrets.join(".leases.json")).unwrap()).unwrap();
    assert_eq!(
        manifest[LEASE]["paths"],
        json!(["work/GitHub.username", "work/GitHub.password"])
    );

    // JSON form, and the next command reconciles: /leases reports nothing active.
    let out = asm(&e, &["get", "--json", "work/GitHub", "deploy the site"], "");
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        j["files"][1]["path"],
        e.secrets
            .join("work/GitHub.password")
            .to_string_lossy()
            .as_ref()
    );
    assert!(j["files"][1].get("content").is_none());
    let out = asm(&e, &["list"], "");
    assert_eq!(text(&out.stdout), "work/GitHub\n");
    assert!(text(&out.stderr).contains("warning: other: locked"));
    assert!(
        !e.secrets.join("work").exists(),
        "inactive lease files removed"
    );
}

#[test]
fn get_outcomes_and_exit_codes() {
    let (_f, e) = paired("deny");
    let out = asm(&e, &["get", "X", "why"], "");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(text(&out.stderr), "denied: provide a better reason\n");

    let (_f, e) = paired("lost");
    let out = asm(&e, &["get", "X", "why"], "");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), "request lost; run the command again\n");

    let (_f, e) = paired("pending");
    let out = asm(&e, &["get", "--wait", "0", "X", "why"], "");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        text(&out.stderr),
        "pending: run the same command again to keep waiting\n"
    );

    let out = asm(&e, &["get", "X", &"r".repeat(251)], "");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn request_lifetime_and_unreachable_manager() {
    // Expired on the manager → exit 3 naming its lifetime.
    let (_f, e) = paired("expire");
    let out = asm(&e, &["get", "X", "why"], "");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        text(&out.stderr),
        "expired: no decision within 10 minutes\n"
    );

    // Two failed polls are retried; the approval still arrives.
    let (f, e) = paired("flaky");
    let out = asm(&e, &["get", "X", "why"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with("mode: sentinel\n"));
    let polls = f
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, p, _)| m == "GET" && p.starts_with("/v1/requests/"))
        .count();
    assert_eq!(polls, 3);

    // Unreachable until an explicit --wait ends → exit 1, the request may still be pending.
    let (_f, e) = paired("down");
    let started = std::time::Instant::now();
    let out = asm(&e, &["get", "--wait", "2", "X", "why"], "");
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("answered HTTP 502"), "{err}");
    assert!(err.contains("may still be pending"), "{err}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn update_and_add() {
    let (f, e) = paired("approve-write");
    let out = asm(&e, &["update", "work/GitHub"], "new-value\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "updated work/GitHub in work\n");
    let sent = f
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/requests")
        .unwrap()
        .2
        .clone();
    assert_eq!(sent["value"], "new-value");
    assert_eq!(sent["field"], Value::Null);
    let out = asm(&e, &["add", "work/GitHub"], "v");
    assert_eq!(out.status.code(), Some(2));
    let out = asm(&e, &["add", "NEW"], "");
    assert_eq!(out.status.code(), Some(2), "empty value is invalid");
}

#[test]
fn wrong_token_exits_6() {
    let (_f, e) = paired("pending");
    let host_path = e.cfg.join("asm/host.json");
    let host = std::fs::read_to_string(&host_path)
        .unwrap()
        .replace(TOKEN, "bad");
    std::fs::write(&host_path, host).unwrap();
    let out = asm(&e, &["list"], "");
    assert_eq!(out.status.code(), Some(6));
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Whether some process holds the reaper lock of `dir`.
fn reaper_running(dir: &Path) -> bool {
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(".reaper.lock"))
    else {
        return false;
    };
    // SAFETY: flock on a descriptor owned by `f`; closing it releases the lock.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

#[test]
fn reaper_deletes_files_at_expiry_and_exits() {
    let (_f, e) = paired("approve-soon");
    let log = e.cfg.parent().unwrap().join("reaper.log");
    let vars = [("ASM_REAPER_LOG", log.to_str().unwrap())];
    // `get` returns although the reaper it starts keeps running: its stdio is detached.
    let out = asm_env(&e, &["get", "work/GitHub", "deploy"], "", &vars);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert_eq!(stdout.lines().count(), 5, "no extra output: {stdout}");
    // Watch the log, not the lock: probing the lock could make a starting reaper quit.
    let logged = |s: &str| std::fs::read_to_string(&log).is_ok_and(|l| l.contains(s));
    assert!(
        wait_for(Duration::from_secs(2), || logged("started for")),
        "reaper started"
    );
    // A second command finds it running and does not start another; it receives the
    // same lease with the same expiry.
    let out = asm_env(&e, &["get", "work/GitHub", "deploy"], "", &vars);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let expiry_line = |s: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix("expires: ").map(str::to_owned))
            .unwrap()
    };
    assert_eq!(expiry_line(&text(&out.stdout)), expiry_line(&stdout));
    let expires = asm_proto::time::parse_unix(&expiry_line(&stdout)).unwrap();
    let password = e.secrets.join("work/GitHub.password");
    assert!(password.exists());

    // The reaper deletes the files one by one and then the emptied vault directory:
    // wait for the directory, the last thing to go, not for one of the files.
    let work = e.secrets.join("work");
    assert!(wait_for(Duration::from_secs(8), || !work.exists()));
    let gone = SystemTime::now();
    let at = UNIX_EPOCH + Duration::from_secs(expires as u64);
    assert!(gone >= at, "deleted before expiry");
    assert!(
        gone.duration_since(at).unwrap() < Duration::from_millis(1200),
        "deleted {:?} after expiry",
        gone.duration_since(at).unwrap()
    );
    assert!(!password.exists());
    assert!(
        wait_for(Duration::from_secs(2), || logged("no leases left")),
        "reaper exits when nothing is left"
    );
    assert!(wait_for(Duration::from_secs(1), || !reaper_running(
        &e.secrets
    )));
    let log = std::fs::read_to_string(&log).unwrap();
    assert_eq!(log.matches("started for").count(), 1, "{log}");
    assert!(
        log.contains(&format!("removed the files of lease {LEASE}")),
        "{log}"
    );
    assert!(log.contains("no leases left; exiting"), "{log}");
}

#[test]
fn reaper_can_be_disabled() {
    let (_f, e) = paired("approve-soon");
    let out = asm_env(
        &e,
        &["get", "--no-reaper", "work/GitHub", "deploy"],
        "",
        &[],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!e.secrets.join(".reaper.lock").exists());
    let out = asm_env(
        &e,
        &["get", "work/GitHub", "deploy"],
        "",
        &[("ASM_NO_REAPER", "1")],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!e.secrets.join(".reaper.lock").exists());
    assert!(e.secrets.join("work/GitHub.password").exists());
}

#[test]
fn reaper_lock_admits_one_instance() {
    let e = env();
    std::fs::create_dir_all(&e.secrets).unwrap();
    let manifest = json!({LEASE: {"mode":"sentinel","expires_at":null,"paths":["TOKEN"]}});
    std::fs::write(e.secrets.join(".leases.json"), manifest.to_string()).unwrap();
    std::fs::write(e.secrets.join("TOKEN"), "asm_x").unwrap();
    let lock = std::fs::File::create(e.secrets.join(".reaper.lock")).unwrap();
    // SAFETY: flock on a descriptor owned by `lock`.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let log = e.cfg.parent().unwrap().join("reaper.log");
    let started = Instant::now();
    let out = asm_env(
        &e,
        &["reap", "--dir", e.secrets.to_str().unwrap()],
        "",
        &[("ASM_REAPER_LOG", log.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(out.stdout.is_empty());
    assert!(e.secrets.join("TOKEN").exists());
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("another reaper holds the lock")
    );
}

fn generator_catalog() -> Value {
    json!({"secrets":[
        {"name":"GH_TOKEN","aliases":["GITHUB_TOKEN"],"source_kind":"generator","vault":"GitHub App","kind":"single","fields":["value"],"lease":null,
         "generators":[{"generator_id":"app-a","name":"release-bot","available":true},{"generator_id":"app-b","name":"review-bot","available":true}]},
        {"name":"OTHER_SECRET","vault":"work","kind":"single","fields":["actual_field"],"lease":null},
        {"name":"Vaultwarden/google","vault":"Vaultwarden","kind":"login","fields":["username","password"],"lease":null},
        {"name":"A=b","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"literal::name","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"item\\name","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"work/item,with,commas","vault":"work","kind":"single","fields":["field"],"lease":null},
        {"name":"work/item::literal","vault":"work","kind":"single","fields":["value"],"lease":null}
    ],"warnings":[]})
}

/// Stateful manager fixture: no Keychain, provider, or credential-file dependency.
fn launcher_fixture(scenario: &'static str) -> (Fake, Env) {
    let leases = Arc::new(Mutex::new(Vec::<Value>::new()));
    let ca = rcgen::generate_simple_self_signed(vec!["proxy ca".into()]).unwrap();
    let ca_hash = asm_proto::crypto::sha256_hex(ca.cert.der());
    let ca = ca.cert.pem();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    if scenario != "unreachable-proxy" {
        std::thread::spawn(move || for _ in proxy.incoming() {});
    } else {
        drop(proxy);
    }
    let lease_calls = std::sync::atomic::AtomicUsize::new(0);
    let posts = std::sync::atomic::AtomicUsize::new(0);
    let f = start(Arc::new(move |method, path, body| {
        match (method, path) {
            ("GET", "/v1/health") => {
                let capabilities = match scenario {
                    "old-manager" => vec![],
                    "legacy-github" => vec!["generated_credentials_v1", "secret_fields_v1"],
                    _ => vec!["generated_credentials_v1", "secret_fields_v1", "github_explicit_scope_v1"],
                };
                (200, json!({"name":"asm-manager","version":"0.1.0","capabilities":capabilities}))
            }
            ("GET", "/v1/secrets") => {
                let mut catalog = generator_catalog();
                if scenario == "alias-collision" {
                    catalog["secrets"][0]["name"] = json!("GITHUB_TOKEN");
                    catalog["secrets"][0]["aliases"] = json!([]);
                    catalog["secrets"].as_array_mut().unwrap().push(json!({"name":"work/GH_TOKEN","vault":"work","kind":"single","fields":["value"],"lease":null}));
                }
                if scenario == "static-collision" {
                    for source in ["demo", "other"] {
                        catalog["secrets"].as_array_mut().unwrap().push(json!({
                            "name":format!("{source}/DEMO_TOKEN"),"aliases":[format!("{source}/DEMO_TOKEN")],
                            "vault":source,"kind":"single","fields":["value"],"lease":null
                        }));
                    }
                }
                if scenario == "static-alias-collision" {
                    let mut secrets = Vec::new();
                    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
                        for source in ["demo", "other"] {
                            secrets.push(json!({
                                "name":format!("{source}/{name}"),"aliases":[format!("{source}/{name}")],
                                "vault":source,"kind":"single","fields":["value"],"lease":null
                            }));
                        }
                    }
                    catalog = json!({"secrets":secrets,"warnings":[]});
                }
                if scenario == "no-catalog" {
                    return (
                        404,
                        json!({"error":{"code":"not_found","message":"catalog unavailable"}}),
                    );
                }
                (200, catalog)
            }
            ("GET", "/v1/leases") => {
                let call = lease_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut records = leases.lock().unwrap();
                if matches!(scenario, "version-change" | "changed-twice") && !records.is_empty() {
                    for lease in records.iter_mut().filter(|l| !l["generation"].is_null()) {
                        lease["credential_version"] =
                            json!(if scenario == "changed-twice" && call > 0 {
                                3
                            } else {
                                2
                            });
                    }
                }
                let mut shown = records.clone();
                if scenario == "revoked" {
                    for lease in &mut shown {
                        lease["status"] = json!("revoked");
                    }
                }
                if scenario == "field-loss" {
                    for lease in &mut shown {
                        lease["fields"] = json!([]);
                    }
                }
                (200, json!({"leases":shown}))
            }
            ("POST", "/v1/requests") => {
                let post = posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if scenario == "post-timeout" {
                    std::thread::sleep(Duration::from_millis(1200));
                }
                if scenario == "deadline" && post == 0 {
                    std::thread::sleep(Duration::from_millis(650));
                }
                if scenario == "deadline" && post > 0 {
                    return (
                        202,
                        json!({"request_id":REQ,"kind":"get","status":"pending","result":null,"deny_reason":null,"pending_lifetime_secs":600}),
                    );
                }
                if scenario == "deny-second" && post > 0 {
                    return (
                        200,
                        json!({"request_id":REQ,"kind":"get","status":"denied","result":null,"deny_reason":"fixture denial"}),
                    );
                }
                let name = body["name"].as_str().unwrap();
                let exact = body["lease_id"].as_str();
                let mut records = leases.lock().unwrap();
                let generated = scenario != "static-alias-collision" && matches!(
                    name,
                    "GH_TOKEN" | "GITHUB_TOKEN"
                        | "release-bot/GH_TOKEN" | "release-bot/GITHUB_TOKEN"
                        | "review-bot/GH_TOKEN" | "review-bot/GITHUB_TOKEN"
                );
                let review = name.starts_with("review-bot/");
                let id = if generated {
                    if review {
                        "22222222-2222-4333-8444-555555555555".to_owned()
                    } else {
                        LEASE.to_owned()
                    }
                } else {
                    let hash = asm_proto::crypto::sha256_hex(name.as_bytes());
                    format!("44444444-2222-4333-8444-{}", &hash[..12])
                };
                let existing = records
                    .iter()
                    .position(|l| l["lease_id"] == exact.unwrap_or(&id));
                let old_version = existing
                    .and_then(|i| records[i]["credential_version"].as_u64())
                    .unwrap_or(0);
                let version =
                    if body["refresh"] == true || (scenario == "near-expiry" && exact.is_some()) {
                        old_version + 1
                    } else {
                        old_version.max(1)
                    };
                // Like the manager, one credential version has one expiry; only a new
                // version gets a new one.
                let kept = existing.filter(|_| version == old_version).and_then(|i| {
                    records[i]["credential_expires_at"]
                        .as_str()
                        .map(str::to_owned)
                });
                let expiry = if scenario == "malformed-expiry" {
                    "invalid".to_owned()
                } else if let Some(kept) = kept {
                    kept
                } else {
                    asm_proto::time::fmt_unix(
                        unix_now()
                            + if (scenario == "near-expiry" && exact.is_none())
                                || scenario == "insufficient-refresh"
                            {
                                599
                            } else {
                                3600
                            },
                    )
                };
                let mode = if body["sentinel"] == true || (scenario == "sentinel" && !generated) {
                    "sentinel"
                } else {
                    "raw"
                };
                let generation = if generated {
                    let scope = &body["generation"]["scope"];
                    let grant_scope = if exact.is_some() && scope.is_null() {
                        records[existing.expect("a pin must target an existing lease")]["generation"]["grant"]["scope"].clone()
                    } else {
                        let repositories = scope["repositories"].as_array().expect("explicit GitHub repositories");
                        json!({
                            "installation_id":if review {2} else {1},
                            "repositories":repositories.iter().enumerate().map(|(i, name)| json!({"id":i + 7,"full_name":name})).collect::<Vec<_>>(),
                            "permissions":scope["permissions"]
                        })
                    };
                    json!({
                        "generator_id":if review {"app-b"} else {"app-a"},"generator_revision":1,
                        "grant":{"provider":"github_app","scope":grant_scope}
                    })
                } else {
                    Value::Null
                };
                let fields = body["fields"].as_array().cloned().unwrap_or_else(|| {
                    if name == "Vaultwarden/google" {
                        vec![json!("username"), json!("password")]
                    } else {
                        vec![json!("value")]
                    }
                });
                let files = fields.iter().map(|field| {
                    let field = field.as_str().unwrap();
                    let value = if scenario == "nul" {"fixture\0secret".to_owned()} else if scenario == "raw-prefix" {"asm_raw_not_a_sentinel".to_owned()} else if generated {
                        format!("fixture-{}-v{version}", if review {"review"} else {"release"})
                    } else if field == "username" {"octocat".to_owned()} else if field == "password" {"fixture-password".to_owned()} else {"fixture-other".to_owned()};
                    let substituted = mode == "sentinel" && field != "username";
                    json!({"field":field,"relative_path":if generated {"GH_TOKEN".to_owned()} else if name == "Vaultwarden/google" {format!("{name}.{field}")} else {name.replace('\\', "_")},
                        "content":if substituted {format!("asm_fixture_{field}")} else {value},"substituted":substituted})
                }).collect::<Vec<_>>();
                let lease = json!({"lease_id":id,"name":if generated {if review {"review-bot/GH_TOKEN"} else {"GH_TOKEN"}} else {name},
                    "mode":mode,"hosts":if mode == "sentinel" {vec!["api.github.com"]} else {vec![]},"expires_at":"2999-01-01T00:00:00Z","status":"active","fields":fields,
                    "generation":generation,"credential_version":if generated {json!(version)} else {Value::Null},"credential_expires_at":if generated {json!(expiry)} else {Value::Null},"generator_name":if generated {json!(if review {"review-bot"} else {"release-bot"})} else {Value::Null}});
                let mut result = lease.clone();
                result["files"] = json!(files);
                if scenario == "missing-field" {
                    result["files"] = json!([]);
                }
                if let Some(index) = existing {
                    records[index] = lease;
                } else {
                    records.push(lease);
                }
                (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"approved","result":result,"deny_reason":null}),
                )
            }
            ("GET", p) if p.starts_with("/v1/requests/") && scenario == "deadline" => {
                std::thread::sleep(Duration::from_millis(800));
                (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"pending","result":null,"deny_reason":null}),
                )
            }
            ("GET", "/v1/proxy-info") => (
                200,
                json!({"port":proxy_port,"hints":["127.0.0.1"],"ca_sha256":ca_hash}),
            ),
            ("GET", "/v1/ca.crt") => (200, json!(ca)),
            _ => (
                404,
                json!({"error":{"code":"not_found","message":"fixture route not found"}}),
            ),
        }
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e)
}

fn posted(f: &Fake) -> Vec<Value> {
    f.log
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, p, _)| m == "POST" && p == "/v1/requests")
        .map(|(_, _, b)| b.clone())
        .collect()
}

#[test]
fn exec_github_aliases_are_file_free_and_replace_inherited_pair() {
    let (f, e) = launcher_fixture("raw");
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "GH_TOKEN,GITHUB_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = fixture-release-v1 && test \"$GITHUB_TOKEN\" = \"$GH_TOKEN\" && test \"$1\" = '--literal=$(printf nope)' && test -z \"$HTTPS_PROXY\" && printf child-ok",
            "fixture",
            "--literal=$(printf nope)",
        ],
        "",
        &[("GH_TOKEN", "stale-a"), ("GITHUB_TOKEN", "stale-b")],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "child-ok");
    let sent = posted(&f);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["fields"], json!(["value"]));
    assert_eq!(sent[0]["generation"], json!({
        "provider":"github_app","scope":{"repositories":["acme/web"],"permissions":{"metadata":"read"}}
    }));
    assert!(
        !e.secrets.exists(),
        "exec must not create secrets, manifest or reaper lock"
    );
    assert!(!text(&out.stderr).contains("fixture-release"));
}

#[test]
fn exec_scopes_only_github_bindings_and_preserves_request_spelling() {
    let (f, e) = launcher_fixture("raw");
    let out = asm(
        &e,
        &[
            "exec",
            "--raw",
            "--repositories",
            " ACME/Web , acme/issues ",
            "--repositories",
            "Acme/Docs,acme/WEB",
            "--permissions",
            "contents=read,issues=write",
            "--permissions",
            "pull_requests=read",
            "GITHUB_TOKEN,OTHER_SECRET,GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = fixture-release-v1 && test \"$GITHUB_TOKEN\" = \"$GH_TOKEN\" && test \"$OTHER_SECRET\" = fixture-other && printf scoped-ok",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "scoped-ok");
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["name"], "GITHUB_TOKEN");
    assert_eq!(sent[0]["generation"], json!({
        "provider":"github_app","scope":{
            "repositories":["acme/docs","acme/issues","acme/web"],
            "permissions":{"contents":"read","issues":"write","metadata":"read","pull_requests":"read"}
        }
    }));
    assert_eq!(sent[1]["name"], "OTHER_SECRET");
    assert!(sent[1]["generation"].is_null());
    assert!(!e.secrets.exists());
}

#[test]
fn exec_explicit_destinations_and_grouped_fields() {
    let (f, e) = launcher_fixture("raw");
    let out = asm(
        &e,
        &[
            "exec",
            "--raw",
            "GOOGLE_USER=Vaultwarden/google::username,GOOGLE_PASS=Vaultwarden/google::password",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GOOGLE_USER\" = octocat && test \"$GOOGLE_PASS\" = fixture-password && printf fields-ok",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "fields-ok");
    assert_eq!(posted(&f).len(), 1);
    assert_eq!(posted(&f)[0]["fields"], json!(["password", "username"]));
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "BOT_A_TOKEN=release-bot/GH_TOKEN,BOT_B_TOKEN=review-bot/GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$BOT_A_TOKEN\" = fixture-release-v1 && test \"$BOT_B_TOKEN\" = fixture-review-v1 && test \"$GH_TOKEN\" = inherited && printf apps-ok",
        ],
        "",
        &[("GH_TOKEN", "inherited")],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "apps-ok");
    let sent = posted(&f);
    assert_eq!(sent.len(), 3);
    for request in &sent[1..] {
        assert_eq!(request["generation"], json!({
            "provider":"github_app","scope":{"repositories":["acme/web"],"permissions":{"metadata":"read"}}
        }));
    }
    assert!(!e.secrets.exists());
}

#[test]
fn exec_conflicts_and_shorthand_fail_before_approval() {
    let (f, e) = launcher_fixture("raw");
    for bindings in [
        "X=GH_TOKEN,X=OTHER_SECRET",
        "GH_TOKEN=release-bot/GH_TOKEN,GITHUB_TOKEN=review-bot/GH_TOKEN",
        "https_proxy=GH_TOKEN",
        "Vaultwarden/google",
        "Vaultwarden/google::username",
        "GH_TOKEN,,OTHER_SECRET",
    ] {
        let out = asm(
            &e,
            &[
                "exec",
                bindings,
                "--",
                "/bin/sh",
                "-c",
                "printf SHOULD-NOT-RUN",
            ],
            "",
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "{bindings}: {}",
            text(&out.stderr)
        );
        assert!(out.stdout.is_empty());
    }
    assert!(posted(&f).is_empty());
    let out = asm(&e, &["exec", "GH_TOKEN", "/bin/sh"], "");
    assert_eq!(out.status.code(), Some(2), "literal separator is required");
}

#[test]
fn exec_preserves_process_contract_and_reports_exec_errors() {
    use std::os::unix::process::ExitStatusExt;
    let (_f, e) = launcher_fixture("raw");
    let out = asm(
        &e,
        &[
            "exec",
            "OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "read line; test \"$line\" = fixture-input && test \"$OTHER_SECRET\" = fixture-other && printf inherited-ok; exit 42",
        ],
        "fixture-input\n",
    );
    assert_eq!(out.status.code(), Some(42));
    assert_eq!(text(&out.stdout), "inherited-ok");
    let out = asm(
        &e,
        &[
            "exec",
            "OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "kill -TERM $$",
        ],
        "",
    );
    assert_eq!(out.status.signal(), Some(15));
    let out = asm(&e, &["exec", "OTHER_SECRET", "--", "/does/not/exist"], "");
    assert_eq!(out.status.code(), Some(127));
    let file = e.cfg.join("not-executable");
    std::fs::write(&file, "fixture").unwrap();
    let out = asm(
        &e,
        &["exec", "OTHER_SECRET", "--", file.to_str().unwrap()],
        "",
    );
    assert_eq!(out.status.code(), Some(126));
    assert!(!e.secrets.exists());
}

#[test]
fn exec_never_launches_on_acquisition_or_prelaunch_failure() {
    for scenario in [
        "deny-second",
        "nul",
        "malformed-expiry",
        "missing-field",
        "revoked",
        "field-loss",
        "changed-twice",
    ] {
        let (_f, e) = launcher_fixture(scenario);
        let bindings = if scenario == "deny-second" {
            "GH_TOKEN,OTHER_SECRET"
        } else {
            "GH_TOKEN"
        };
        let out = asm(
            &e,
            &[
                "exec",
                "--repositories",
                GITHUB_REPOSITORY,
                bindings,
                "--",
                "/bin/sh",
                "-c",
                "printf SHOULD-NOT-RUN",
            ],
            "",
        );
        assert!(!out.status.success(), "{scenario}");
        assert!(out.stdout.is_empty(), "{scenario}");
        assert!(!text(&out.stderr).contains("fixture-release"), "{scenario}");
        assert!(!e.secrets.exists(), "{scenario}");
    }
}

#[test]
fn exec_refreshes_once_without_forcing_or_rebinding() {
    for scenario in ["version-change", "near-expiry"] {
        let (f, e) = launcher_fixture(scenario);
        let out = asm(
            &e,
            &[
                "exec",
                "--repositories",
                GITHUB_REPOSITORY,
                "GITHUB_TOKEN",
                "--",
                "/bin/sh",
                "-c",
                "test \"$GH_TOKEN\" = fixture-release-v2 && test \"$GITHUB_TOKEN\" = \"$GH_TOKEN\" && printf renewed-ok",
            ],
            "",
        );
        assert!(out.status.success(), "{scenario}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "renewed-ok");
        let sent = posted(&f);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1]["lease_id"], LEASE);
        assert_eq!(sent[1]["refresh"], false);
        assert_eq!(sent[1]["name"], "GH_TOKEN");
        assert_eq!(sent[1]["fields"], json!(["value"]));
        assert!(sent[1]["generation"].is_null());
    }
}

#[test]
fn exec_sentinel_proxy_settings_are_automatic_and_plain_fields_skip_them() {
    let (f, e) = launcher_fixture("sentinel");
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--sentinel",
            "--hosts",
            "api.github.com",
            "GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = asm_fixture_value && test \"$GITHUB_TOKEN\" = \"$GH_TOKEN\" && test -n \"$HTTPS_PROXY\" && test \"$HTTP_PROXY\" = \"$HTTPS_PROXY\" && test \"$ALL_PROXY\" = \"$HTTPS_PROXY\" && test -z \"$https_proxy$http_proxy$all_proxy$no_proxy$ssl_cert_file$requests_ca_bundle$curl_ca_bundle$git_ssl_cainfo$node_extra_ca_certs\" && test -f \"$SSL_CERT_FILE\" && printf proxy-ok",
        ],
        "",
        &[
            ("https_proxy", "bad"),
            ("http_proxy", "bad"),
            ("all_proxy", "bad"),
            ("no_proxy", "bad"),
            ("ssl_cert_file", "bad"),
            ("requests_ca_bundle", "bad"),
            ("curl_ca_bundle", "bad"),
            ("git_ssl_cainfo", "bad"),
            ("node_extra_ca_certs", "bad"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "proxy-ok");
    assert!(!e.secrets.exists());
    assert!(
        f.log
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p == "/v1/proxy-info")
    );
    let (f, e) = launcher_fixture("sentinel");
    let out = asm(
        &e,
        &[
            "exec",
            "--sentinel",
            "GOOGLE_USER=Vaultwarden/google::username",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GOOGLE_USER\" = octocat && printf plain-ok",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "plain-ok");
    assert!(
        !f.log
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p == "/v1/proxy-info")
    );
    let (_f, e) = launcher_fixture("unreachable-proxy");
    let out = asm(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--sentinel",
            "GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "printf SHOULD-NOT-RUN",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn github_scope_is_required_before_posting_new_requests() {
    let (f, e) = launcher_fixture("raw");
    for args in [
        vec!["get", "GITHUB_TOKEN", "Read GitHub"],
        vec!["get", "--new-lease", "GH_TOKEN", "Read GitHub"],
        vec!["get", "--refresh", "GH_TOKEN", "Renew GitHub"],
        vec!["get", "--permissions", "contents=read", "release-bot/GH_TOKEN", "Read GitHub"],
        vec!["get", "--lease", LEASE, "--permissions", "contents=read", "GH_TOKEN", "Renew GitHub"],
        vec!["exec", "OTHER_SECRET,TOKEN=release-bot/GH_TOKEN", "--", "/bin/echo", "should not run"],
        vec!["exec", "--permissions", "contents=read", "GH_TOKEN", "--", "/bin/echo", "should not run"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("--repositories"));
        assert!(out.stdout.is_empty());
    }
    assert!(posted(&f).is_empty());
}

#[test]
fn static_github_spelling_does_not_turn_into_a_scope_request() {
    let (f, e) = launcher_fixture("alias-collision");
    let get = asm(&e, &["get", "work/GH_TOKEN", "Read a static secret"], "");
    assert!(get.status.success(), "{}", text(&get.stderr));
    let exec = asm(
        &e,
        &[
            "exec", "TOKEN=work/GH_TOKEN", "--", "/bin/sh", "-c",
            "test \"$TOKEN\" = fixture-other",
        ],
        "",
    );
    assert!(exec.status.success(), "{}", text(&exec.stderr));
    for args in [
        vec!["get", "--repositories", GITHUB_REPOSITORY, "work/GH_TOKEN", "Read a static secret"],
        vec!["exec", "--repositories", GITHUB_REPOSITORY, "TOKEN=work/GH_TOKEN", "--", "/bin/true"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("require a generated"));
    }
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|body| body["name"] == "work/GH_TOKEN" && body["generation"].is_null()));
}

#[test]
fn github_scope_requires_manager_support_before_posting() {
    let (f, e) = launcher_fixture("legacy-github");
    for args in [
        vec!["get", "--repositories", GITHUB_REPOSITORY, "GH_TOKEN", "Read GitHub"],
        vec!["exec", "--repositories", GITHUB_REPOSITORY, "OTHER_SECRET,GH_TOKEN", "--", "/bin/true"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("github_explicit_scope_v1; upgrade the manager"));
    }
    assert!(posted(&f).is_empty());
}

#[test]
fn capabilities_fail_closed_and_alias_lookup_preserves_noncolliding_spelling() {
    let (f, e) = launcher_fixture("old-manager");
    for args in [
        vec!["exec", "GH_TOKEN", "--", "/bin/sh", "-c", "exit 0"],
        vec!["get", "--sentinel", "OTHER_SECRET", "why"],
        vec!["get", "--new-lease", "GH_TOKEN", "why"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("upgrade the manager"));
    }
    assert!(posted(&f).is_empty());
    let (f, e) = launcher_fixture("alias-collision");
    let out = asm(
        &e,
        &["exec", "--repositories", GITHUB_REPOSITORY, "GITHUB_TOKEN", "--", "/bin/sh", "-c", "exit 0"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(posted(&f)[0]["name"], "GITHUB_TOKEN");
    let out = asm(
        &e,
        &["exec", "GH_TOKEN", "--", "/bin/sh", "-c", "exit 0"],
        "",
    );
    assert_eq!(out.status.code(), Some(asm_proto::error::EXIT_NOT_FOUND));
    assert!(text(&out.stderr).contains("ambiguous"));
    let out = asm(&e, &["get", "GH_TOKEN", "Read a secret"], "");
    assert_eq!(out.status.code(), Some(asm_proto::error::EXIT_NOT_FOUND));
    assert!(text(&out.stderr).contains("ambiguous"));
    assert_eq!(
        posted(&f).len(),
        1,
        "ambiguous source must not submit another request"
    );
}

#[test]
fn get_bindings_scope_and_stable_generated_aliases() {
    let (f, e) = launcher_fixture("raw");
    let out = asm(
        &e,
        &[
            "get",
            "--json",
            "GOOGLE_USER=Vaultwarden/google::username",
            "Sign in",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["files"].as_array().unwrap().len(), 1);
    assert_eq!(result["files"][0]["field"], "username");
    assert_eq!(result["files"][0]["relative_path"], "GOOGLE_USER");
    assert_eq!(
        std::fs::read_to_string(e.secrets.join("GOOGLE_USER")).unwrap(),
        "octocat"
    );
    assert!(!e.secrets.join("Vaultwarden/google.password").exists());
    let out = asm(
        &e,
        &[
            "get",
            "--repositories",
            " ACME/Web ",
            "--permissions",
            "contents=read",
            "GH_TOKEN",
            "Read acme/web",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sent = posted(&f);
    assert_eq!(
        sent[1]["generation"]["scope"]["repositories"],
        json!(["acme/web"])
    );
    assert_eq!(
        sent[1]["generation"]["scope"]["permissions"]["contents"],
        "read"
    );
    assert!(text(&out.stdout).contains("credential version: 1"));
    assert!(!text(&out.stdout).contains("fixture-release"));
    let out = asm(&e, &["get", "--lease", LEASE, "GITHUB_TOKEN", "Continue reading"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let pin = posted(&f).pop().unwrap();
    assert_eq!(pin["name"], "GITHUB_TOKEN");
    assert_eq!(pin["lease_id"], LEASE);
    assert!(pin["generation"].is_null());
    assert_eq!(
        std::fs::read_to_string(e.secrets.join("GITHUB_TOKEN")).unwrap(),
        "fixture-release-v1"
    );
    let scoped_pin = asm(
        &e,
        &[
            "get",
            "--lease",
            LEASE,
            "--repositories",
            GITHUB_REPOSITORY,
            "--permissions",
            "contents=read",
            "GITHUB_TOKEN",
            "Continue with the same scope",
        ],
        "",
    );
    assert!(scoped_pin.status.success(), "{}", text(&scoped_pin.stderr));
    let pin = posted(&f).pop().unwrap();
    assert_eq!(pin["lease_id"], LEASE);
    assert_eq!(pin["generation"], sent[1]["generation"]);
    let out = asm(
        &e,
        &[
            "get",
            "--lease",
            LEASE,
            "--refresh",
            "GH_TOKEN",
            "Refresh reading",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(posted(&f).last().unwrap()["refresh_from_version"], 1);
    assert!(posted(&f).last().unwrap()["generation"].is_null());
    for alias in ["GH_TOKEN", "GITHUB_TOKEN"] {
        assert_eq!(
            std::fs::read_to_string(e.secrets.join(alias)).unwrap(),
            "fixture-release-v2"
        );
    }
    // Exec never updates or deletes existing get files.
    let before = std::fs::read(e.secrets.join(".leases.json")).unwrap();
    let out = asm(
        &e,
        &["exec", "--repositories", GITHUB_REPOSITORY, "--permissions", "contents=read", "GH_TOKEN", "--", "/bin/sh", "-c", "exit 0"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read(e.secrets.join(".leases.json")).unwrap(),
        before
    );
}

#[test]
fn get_literal_delimiters_require_escaping_without_changing_identity() {
    let (f, e) = launcher_fixture("raw");
    for literal in ["A=b", "literal::name", r"item\name"] {
        let out = asm(&e, &["get", literal, "Read literal"], "");
        assert_eq!(out.status.code(), Some(asm_proto::error::EXIT_NOT_FOUND));
        assert!(text(&out.stderr).contains("ambiguous"));
    }
    assert!(posted(&f).is_empty());
    for (binding, name) in [
        (r"A\=b", "A=b"),
        (r"literal\:\:name", "literal::name"),
        (r"item\\name", r"item\name"),
    ] {
        let out = asm(&e, &["get", binding, "Read literal"], "");
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(posted(&f).last().unwrap()["name"], name);
    }
    let out = asm(
        &e,
        &[
            "exec",
            r"NAME=work/item\,with\,commas::field,OTHER=work/item\:\:literal::value",
            "--",
            "/bin/sh",
            "-c",
            "test \"$NAME$OTHER\" = fixture-otherfixture-other && printf escaped-ok",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn exec_wait_is_one_budget_across_sequential_acquisitions() {
    let (f, e) = launcher_fixture("deadline");
    let started = Instant::now();
    let out = asm(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--wait",
            "1",
            "GH_TOKEN,OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "printf SHOULD-NOT-RUN",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
    assert_eq!(posted(&f).len(), 2);
    assert!(started.elapsed() < Duration::from_millis(1800));
    assert!(!e.secrets.exists());
}

#[test]
fn get_exact_lease_bypasses_catalog_and_refresh_can_be_auto_routed() {
    let grant = json!({"generator_id":"app-a","generator_revision":1,"grant":{"provider":"github_app","scope":{
        "installation_id":1,"repositories":[{"id":7,"full_name":"acme/web"}],"permissions":{"metadata":"read"}}}});
    let lease = json!({"lease_id":LEASE,"name":"old-name/GH_TOKEN","mode":"raw","hosts":[],"expires_at":"2999-01-01T00:00:00Z","status":"active","fields":["value"],
        "generation":grant,"credential_expires_at":"2999-01-01T00:00:00Z","credential_version":9,"generator_name":"renamed-app"});
    let f = start(Arc::new(move |method, path, body| match (method, path) {
        ("GET", "/v1/health") => (
            200,
            json!({"name":"asm-manager","version":"0.1.0","capabilities":["generated_credentials_v1","secret_fields_v1"]}),
        ),
        ("GET", "/v1/leases") => (200, json!({"leases":[lease]})),
        ("POST", "/v1/requests") => {
            assert_eq!(body["name"], "old-name/GITHUB_TOKEN");
            assert_eq!(body["lease_id"], LEASE);
            assert_eq!(body["refresh_from_version"], 9);
            assert!(body["generation"].is_null());
            let mut result = lease.clone();
            result["credential_version"] = json!(10);
            result["files"] = json!([{"field":"value","relative_path":"old-name/GH_TOKEN","content":"fixture-renamed-token","substituted":false}]);
            (
                200,
                json!({"request_id":REQ,"kind":"get","status":"approved","result":result,"deny_reason":null}),
            )
        }
        _ => (
            404,
            json!({"error":{"code":"not_found","message":"no current catalog"}}),
        ),
    }));
    let e = env();
    write_host_json(&e, &f);
    let out = asm(
        &e,
        &[
            "get",
            "--lease",
            LEASE,
            "--refresh",
            "old-name/GITHUB_TOKEN",
            "Continue",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        !f.log
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p == "/v1/secrets")
    );
    assert_eq!(
        std::fs::read_to_string(e.secrets.join("old-name/GITHUB_TOKEN")).unwrap(),
        "fixture-renamed-token"
    );
    let scoped = asm(
        &e,
        &[
            "get", "--lease", LEASE, "--repositories", GITHUB_REPOSITORY,
            "old-name/GITHUB_TOKEN", "Continue with explicit scope",
        ],
        "",
    );
    assert_eq!(scoped.status.code(), Some(2), "{}", text(&scoped.stderr));
    assert!(text(&scoped.stderr).contains("github_explicit_scope_v1; upgrade the manager"));
    assert_eq!(posted(&f).len(), 1);
    let (f, e) = launcher_fixture("raw");
    let out = asm(&e, &["get", "--refresh", "--repositories", GITHUB_REPOSITORY, "GH_TOKEN", "Recover token"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(posted(&f)[0]["refresh"], true);
    assert_eq!(posted(&f)[0]["generation"], json!({
        "provider":"github_app","scope":{"repositories":["acme/web"],"permissions":{"metadata":"read"}}
    }));
    assert!(posted(&f)[0]["refresh_from_version"].is_null());
    assert!(posted(&f)[0]["lease_id"].is_null());
}

#[test]
fn exec_preserves_explicit_standard_variable_and_raw_network_environment() {
    let (f, e) = launcher_fixture("raw");
    let cwd = std::env::current_dir().unwrap();
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "GH_TOKEN=release-bot/GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = fixture-release-v1 && test \"$GITHUB_TOKEN\" = inherited-other && test \"$HTTPS_PROXY\" = inherited-proxy && test \"$PWD\" = \"$EXPECTED_CWD\" && printf explicit-ok",
        ],
        "",
        &[
            ("GITHUB_TOKEN", "inherited-other"),
            ("HTTPS_PROXY", "inherited-proxy"),
            ("EXPECTED_CWD", cwd.to_str().unwrap()),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "explicit-ok");
    assert_eq!(posted(&f)[0]["reason"], "Run sh with approved credentials");
    assert!(
        !f.log
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p == "/v1/proxy-info")
    );
    assert!(!e.secrets.exists());
}

#[test]
fn exec_mixed_delivery_uses_field_metadata_not_token_prefixes() {
    let (_f, e) = launcher_fixture("sentinel");
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--raw",
            "GH_TOKEN,OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = fixture-release-v1 && test \"$OTHER_SECRET\" = asm_fixture_actual_field && test -n \"$HTTPS_PROXY\" && test -z \"$https_proxy\" && printf mixed-ok",
        ],
        "",
        &[("https_proxy", "inherited-wrong-proxy")],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "mixed-ok");
    assert!(!e.secrets.exists());
}

#[test]
fn exec_insufficient_headroom_and_unknown_post_timeout_fail_without_retry() {
    let (f, e) = launcher_fixture("insufficient-refresh");
    let out = asm(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "printf SHOULD-NOT-RUN",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("credentials changed before launch"));
    assert_eq!(
        posted(&f).len(),
        2,
        "only one ordinary exact-lease recovery"
    );
    assert!(out.stdout.is_empty());
    let (f, e) = launcher_fixture("post-timeout");
    let out = asm(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--wait",
            "1",
            "GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "printf SHOULD-NOT-RUN",
        ],
        "",
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "unknown POST outcome must not be called pending"
    );
    assert_eq!(
        posted(&f).len(),
        1,
        "POST must never be automatically retried"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn exec_raw_prefix_does_not_trigger_proxy_setup() {
    let (f, e) = launcher_fixture("raw-prefix");
    let out = asm(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "GH_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = asm_raw_not_a_sentinel && test -z \"$HTTPS_PROXY\" && printf raw-prefix-ok",
        ],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "raw-prefix-ok");
    assert!(
        !f.log
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p, _)| p == "/v1/proxy-info")
    );
    assert!(!e.secrets.exists());
}

#[test]
fn legacy_static_get_delegates_collisions_without_widening_bindings() {
    // An unrelated generator must not change ordinary static leased-name reuse.
    let (f, e) = launcher_fixture("static-collision");
    for flags in [
        vec!["get", "DEMO_TOKEN", "Reuse old lease"],
        vec!["get", "--raw", "DEMO_TOKEN", "Request raw"],
    ] {
        let out = asm(&e, &flags, "");
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert!(
        sent.iter()
            .all(|body| body["name"] == "DEMO_TOKEN" && body["fields"].is_null())
    );
    assert_eq!(sent[1]["raw"], true);
    for args in [
        vec!["get", "DEMO_TOKEN::value", "Select a field"],
        vec!["get", "DEST=DEMO_TOKEN", "Name a file"],
        vec![
            "exec",
            "DEMO_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            "printf SHOULD-NOT-RUN",
        ],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(asm_proto::error::EXIT_NOT_FOUND));
        assert!(text(&out.stderr).contains("ambiguous"));
        assert!(out.stdout.is_empty());
    }
    assert_eq!(
        posted(&f).len(),
        2,
        "bindings and exec cannot defer ambiguous field resolution"
    );

    // Conversely, an actual static/generated collision never reaches a shortcut.
    let (f, e) = launcher_fixture("alias-collision");
    let out = asm(
        &e,
        &["get", "GH_TOKEN", "Do not reuse a colliding name"],
        "",
    );
    assert_eq!(out.status.code(), Some(asm_proto::error::EXIT_NOT_FOUND));
    assert!(text(&out.stderr).contains("ambiguous"));
    assert!(posted(&f).is_empty());
}

#[test]
fn legacy_static_github_spellings_remain_independent_without_generators() {
    let (f, e) = launcher_fixture("static-alias-collision");
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        let out = asm(&e, &["get", name, "Reuse a static lease"], "");
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["name"], "GH_TOKEN");
    assert_eq!(sent[1]["name"], "GITHUB_TOKEN");
    assert!(
        sent.iter()
            .all(|body| body["generation"].is_null() && body["fields"].is_null())
    );
}
