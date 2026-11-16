//! Runs the `asm` binary against a fake manager (HTTPS, self-signed) to check the
//! wire flow: interactive and unattended pairing, `get` (files, output, denial,
//! pending, lost request), `update`, `add`, `list`.

use asm_proto::crypto::{hex_decode_array, hex_encode, sha256};
use asm_proto::pairing::{UnattendedCode, client_commit, format_pairing_code, pairing_code};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

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

fn asm(e: &Env, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asm"))
        .args(args)
        .env_clear()
        .env("HOME", e.cfg.parent().unwrap())
        .env("XDG_CONFIG_HOME", &e.cfg)
        .env("ASM_SECRETS_DIR", &e.secrets)
        .env("ASM_AGENT", "test-agent")
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
    json!({"lease_id":LEASE,"mode":"sentinel","hosts":["api.example.com"],"expires_at":"2999-01-01T00:00:00Z",
        "files":[{"field":"username","relative_path":"work/GitHub.username","content":"octocat"},
                 {"field":"password","relative_path":"work/GitHub.password","content":content}]})
}

fn requests_handler(outcome: &'static str) -> Arc<Handler> {
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Arc::new(move |method, path, body| match (method, path) {
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
        json!({"kind":"get","name":"work/GitHub","raw":false,"hosts":["api.example.com"],"reason":"deploy the site","agent":"test-agent"})
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
