//! Runs the `asm` binary against a fake manager (HTTPS, self-signed) to check the
//! wire flow: interactive and unattended pairing, `get` (files, output, denial,
//! pending, lost request), `update`, `add`, `list`, the background reaper, and SSH
//! leases (`asm ssh request`, `hosts`, `leases`, `extend`, `install`, the ssh agent).

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
const GCLOUD_NAME: &str = "CLOUDSDK_AUTH_ACCESS_TOKEN";
const GCLOUD_LEASE: &str = "33333333-2222-4333-8444-555555555555";
const GCLOUD_LEGACY_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const GCLOUD_PROJECT: &str = "dev-project";
const GCLOUD_OTHER_PROJECT: &str = "other-project";
const SELECT_PROJECT: &str = "operator_selected_project_v1";
const BROADER_REUSE: &str = "broader_lease_reuse_v1";

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
        "files":[{"field":"username","relative_path":"work/GitHub.username","content":"octocat","substituted":false},
                 {"field":"password","relative_path":"work/GitHub.password","content":content,"substituted":true}]})
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
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.1.0",
            "capabilities": if outcome == "approve-add" { vec!["add_destination_v1"] } else { vec![] }})),
        // Two items named DB_PASS in one vault; this host leased the first one earlier.
        ("GET", "/v1/secrets") if outcome.starts_with("dup-") => (
            200,
            json!({"secrets":[
                {"name":"DB_PASS~1a2b3c4d","vault":"work","kind":"login","fields":["username","password"],
                 "lease":{"lease_id":LEASE,"mode":"sentinel","expires_at":null},
                 "aliases":["work/DB_PASS~1a2b3c4d"],"item_name":"DB_PASS"},
                {"name":"DB_PASS~9f8e7d6c","vault":"work","kind":"login","fields":["username","password"],"lease":null,
                 "aliases":["work/DB_PASS~9f8e7d6c"],"item_name":"DB_PASS"}]}),
        ),
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
                "approve-get" | "dup-get" => (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":get_result("asm_0123456789012345678901234567890123456789")}),
                ),
                "dup-update" => (
                    200,
                    json!({"request_id":REQ,"kind":"update","status":"approved","deny_reason":null,
                        "result":{"name":"DB_PASS~1a2b3c4d","vault":"work"}}),
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
                "approve-add" => (
                    200,
                    json!({"request_id":REQ,"kind":"add","status":"approved","deny_reason":null,
                        "result":{"name":"DB, PASS","vault":"work","qualified_name":"work/DB, PASS","collection":"Infra"}}),
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
        json!({"kind":"get","name":"work/GitHub","raw":false,"sentinel":false,"fields":null,"generation":null,"refresh":false,"refresh_from_version":null,"new_lease":false,"lease_id":null,"client_capabilities":["generated_credentials_v1","secret_fields_v1","github_explicit_scope_v1","gcloud_access_v1","operator_selected_grant_v1"],"hosts":["api.example.com"],"reason":"deploy the site","agent":"test-agent"})
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
    assert_eq!(j["files"][0]["delivery"], "raw");
    assert_eq!(j["files"][1]["delivery"], "sentinel");
    let receipt = text(&out.stderr);
    assert!(receipt.contains("work/GitHub.password: sentinel"));
    assert!(receipt.contains("eval \"$(asm proxy-env)\"") && receipt.contains("asm exec --sentinel"));
    assert!(!receipt.contains("octocat") && !receipt.contains("asm_0123456789"));
    let out = asm(&e, &["list"], "");
    assert_eq!(text(&out.stdout), "work/GitHub\n");
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
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
    // A manager without destination hints never receives one.
    let posts = |f: &Fake| f.log.lock().unwrap().iter().filter(|(m, p, _)| m == "POST" && p == "/v1/requests").count();
    let before = posts(&f);
    let out = asm(&e, &["add", "--vault", "work", "NEW"], "v");
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out.stderr).contains("add_destination_v1"), "{}", text(&out.stderr));
    assert_eq!(posts(&f), before);
    let out = asm(&e, &["add", "--collection", "Infra", "NEW"], "v");
    assert_eq!(out.status.code(), Some(2), "a collection needs its vault");
    let out = asm(&e, &["add", "NEW"], "v");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "added work/GitHub to work; run asm get to use it\n");
}

#[test]
fn add_suggests_a_destination_and_reports_where_it_went() {
    let (f, e) = paired("approve-add");
    let out = asm(&e, &["add", "--vault", " work ", "--collection", "Infra", "DB, PASS"], "v");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "added DB, PASS to work (collection Infra); request it as 'work/DB\\, PASS'\n");
    let sent = f.log.lock().unwrap().iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/requests").unwrap().2.clone();
    assert_eq!((&sent["kind"], &sent["vault"], &sent["collection"]), (&json!("add"), &json!("work"), &json!("Infra")));
}

#[test]
fn a_name_that_became_ambiguous_warns_when_the_lease_answers_it() {
    let warning = "warning: DB_PASS is ambiguous now (work/DB_PASS~1a2b3c4d, work/DB_PASS~9f8e7d6c); \
        asm used this host's lease on work/DB_PASS~1a2b3c4d. Request one of these names to choose.\n";
    let (f, e) = paired("dup-get");
    let out = asm(&e, &["get", "DB_PASS", "deploy the site"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).ends_with(warning), "{}", text(&out.stderr));
    let sent = f.log.lock().unwrap().iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/requests").unwrap().2.clone();
    assert_eq!(sent["name"], "DB_PASS", "the manager decides with the host's leases");

    let (_f, e) = paired("dup-update");
    let out = asm(&e, &["update", "DB_PASS"], "new-value\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "updated DB_PASS~1a2b3c4d in work\n");
    assert!(text(&out.stderr).ends_with(&warning.replace("on work/DB_PASS~1a2b3c4d", "on DB_PASS~1a2b3c4d")),
        "{}", text(&out.stderr));
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
         "generators":[{"generator_id":"app-a","name":"release-bot"},{"generator_id":"app-b","name":"review-bot"}]},
        {"name":"OTHER_SECRET","vault":"work","kind":"single","fields":["actual_field"],"lease":null},
        {"name":"Vaultwarden/google","vault":"Vaultwarden","kind":"login","fields":["username","password"],"lease":null},
        {"name":"A=b","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"literal::name","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"item\\name","vault":"work","kind":"single","fields":["value"],"lease":null},
        {"name":"work/item,with,commas","vault":"work","kind":"single","fields":["field"],"lease":null},
        {"name":"work/item::literal","vault":"work","kind":"single","fields":["value"],"lease":null}
    ]})
}

/// Stateful manager fixture: no Keychain, provider, or credential-file dependency.
fn launcher_fixture(scenario: &'static str) -> (Fake, Env) {
    let managed_google = scenario.starts_with("managed-google");
    let project_selection = scenario.starts_with("managed-google-project-");
    let reuse = scenario.contains("-reuse-");
    let edited_approval = matches!(scenario,
        "managed-google-selected-broad" | "managed-google-selected-narrow"
        | "managed-google-selected-wrong-request" | "managed-google-selected-other-project"
        | "github-selected-broad" | "github-selected-narrow")
        || (project_selection && scenario != "managed-google-project-cached");
    let pending = edited_approval || scenario == "managed-google-reuse-pending";
    let approved = Mutex::new(None::<Value>);
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
                let mut capabilities = match scenario {
                    "old-manager" => vec![],
                    "legacy-github" => vec!["generated_credentials_v1", "secret_fields_v1"],
                    "mixed-providers" | "managed-google-unsupported" =>
                        vec!["generated_credentials_v1", "secret_fields_v1", "github_explicit_scope_v1"],
                    _ => vec!["generated_credentials_v1", "secret_fields_v1", "github_explicit_scope_v1", "gcloud_access_v1"],
                };
                if scenario.contains("-selected-") || (project_selection && !matches!(scenario,
                    "managed-google-project-only" | "managed-google-project-only-permission-drift"))
                {
                    capabilities.push("operator_selected_grant_v1");
                }
                if project_selection {
                    capabilities.push(SELECT_PROJECT);
                }
                if reuse && scenario != "managed-google-reuse-unnegotiated" {
                    capabilities.push(BROADER_REUSE);
                }
                (200, json!({"name":"asm-manager","version":"0.1.0","capabilities":capabilities}))
            }
            ("GET", "/v1/secrets") => {
                let mut catalog = generator_catalog();
                if scenario == "legacy-catalog-status" {
                    catalog["warnings"] = json!(["other: vault is locked"]);
                    catalog["secrets"][0]["generators"][0]["available"] = json!(true);
                    catalog["secrets"][0]["generators"][1]["available"] = json!(false);
                    catalog["secrets"][0]["generators"][1]["unavailable_reason"] =
                        json!("private credential diagnostic");
                }
                if scenario == "mixed-providers" || managed_google {
                    let name = if scenario == "managed-google-collision" {
                        "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN"
                    } else {
                        GCLOUD_NAME
                    };
                    catalog["secrets"].as_array_mut().unwrap().push(json!({
                        "name":name,"source_kind":"generator","vault":"gcloud-dev","kind":"single","fields":["value"],"lease":null,
                        "generators":[{"generator_id":"gcp","name":"gcloud-dev"}]
                    }));
                }
                if scenario == "managed-google-collision" {
                    catalog["secrets"].as_array_mut().unwrap().push(json!({
                        "name":"work/CLOUDSDK_AUTH_ACCESS_TOKEN","vault":"work","kind":"single","fields":["value"],"lease":null
                    }));
                }
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
                    catalog = json!({"secrets":secrets});
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
                let gcloud = (scenario == "mixed-providers" || managed_google)
                    && matches!(name, GCLOUD_NAME | "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN");
                let generated = gcloud || (scenario != "static-alias-collision" && matches!(
                    name,
                    "GH_TOKEN" | "GITHUB_TOKEN" | "release-bot/GH_TOKEN" | "review-bot/GH_TOKEN"
                ));
                if generated {
                    assert_eq!(body["raw"], true);
                    assert_eq!(body["sentinel"], false);
                    assert_eq!(body["hosts"], json!([]));
                }
                let review = name.starts_with("review-bot/");
                let id = if generated {
                    if gcloud {
                        GCLOUD_LEASE.to_owned()
                    } else if review {
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
                let near_expiry = edited_approval || reuse || matches!(scenario, "near-expiry" | "managed-google-short" | "managed-google-selected-drift-on-renew");
                let version =
                    if body["refresh"] == true || (near_expiry && exact.is_some()) {
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
                            + if (near_expiry && exact.is_none())
                                || scenario == "insufficient-refresh"
                            {
                                599
                            } else {
                                3600
                            },
                    )
                };
                let unexpectedly_sentinel = generated && matches!(scenario,
                    "legacy-generated-sentinel" | "managed-google-legacy-sentinel");
                let mode = if body["sentinel"] == true || (scenario == "sentinel" && !generated) || unexpectedly_sentinel {
                    "sentinel"
                } else {
                    "raw"
                };
                let generation = if gcloud && managed_google && !matches!(scenario, "managed-google-legacy-response" | "managed-google-selected-legacy-response") {
                    assert_eq!(body["generation"]["provider"], "gcloud_access");
                    let mut access = body["generation"]["scope"].clone();
                    if let Some(exact) = exact {
                        assert_eq!(exact, GCLOUD_LEASE);
                        assert_eq!(access, records[existing.expect("a pin must target an existing lease")]["generation"]["grant"]["scope"]["access"]);
                        if scenario == "managed-google-project-drift-on-renew" {
                            access["project_id"] = json!(GCLOUD_PROJECT);
                        }
                    } else {
                        match scenario {
                            "managed-google-broad" | "managed-google-selected-broad" | "managed-google-selected-wrong-request"
                            | "managed-google-selected-unmarked" | "managed-google-unnegotiated-selection" =>
                                access["permissions"] = json!(["storage=read", "compute=read"]),
                            "managed-google-selected-narrow" => access["permissions"] = json!(["storage=read"]),
                            "managed-google-other-project" | "managed-google-selected-other-project" | "managed-google-reuse-wrong-project" =>
                                access["project_id"] = json!(GCLOUD_OTHER_PROJECT),
                            "managed-google-reuse-missing-claim" => access["permissions"] = json!(["storage=create"]),
                            _ if reuse => access["permissions"] = json!(["storage=read", "compute=read"]),
                            _ if project_selection => {
                                access["project_id"] = json!(GCLOUD_OTHER_PROJECT);
                                if matches!(scenario, "managed-google-project-switched" | "managed-google-project-only-permission-drift") {
                                    access["permissions"] = json!(["compute=read"]);
                                }
                            }
                            _ => {}
                        }
                    }
                    let unique_id = if scenario == "managed-google-selected-drift-on-renew" && exact.is_some() { "444444444" } else { "123456789" };
                    let service_account_email = format!("bot@{}.iam.gserviceaccount.com", access["project_id"].as_str().unwrap());
                    json!({
                        "generator_id":"gcp","generator_revision":1,
                        "grant":{"provider":"gcloud_access","scope":{
                            "state":"issued","access":access,"service_account_unique_id":unique_id,
                            "service_account_email":service_account_email
                        }}
                    })
                } else if gcloud {
                    json!({
                        "generator_id":"gcp","generator_revision":1,
                        "grant":{"provider":"gcloud","scope":{
                            "service_account_unique_id":"123456789",
                            "service_account_email":"bot@dev-project.iam.gserviceaccount.com",
                            "scopes":[GCLOUD_LEGACY_SCOPE]
                        }}
                    })
                } else if generated {
                    let scope = &body["generation"]["scope"];
                    let grant_scope = match (exact, scenario) {
                        (Some(_), _) if scope.is_null() =>
                            records[existing.expect("a pin must target an existing lease")]["generation"]["grant"]["scope"].clone(),
                        (None, "github-selected-narrow") => json!({
                            "installation_id":1,
                            "repositories":[{"id":7,"full_name":"acme/web"}],
                            "permissions":{"contents":"read","metadata":"read"}
                        }),
                        (None, "github-selected-broad" | "github-selected-unmarked" | "github-reuse-broad") => json!({
                            "installation_id":1,
                            "repositories":[{"id":7,"full_name":"acme/web"},{"id":8,"full_name":"acme/docs"}],
                            "permissions":{"contents":"write","metadata":"read"}
                        }),
                        _ => {
                            let repositories = scope["repositories"].as_array().expect("explicit GitHub repositories");
                            json!({
                                "installation_id":if review {2} else {1},
                                "repositories":repositories.iter().enumerate().map(|(i, name)| json!({"id":i + 7,"full_name":name})).collect::<Vec<_>>(),
                                "permissions":scope["permissions"]
                            })
                        }
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
                let output = if gcloud { GCLOUD_NAME } else { "GH_TOKEN" };
                let generator_name = if gcloud { "gcloud-dev" } else if review { "review-bot" } else { "release-bot" };
                let lease_name = if generated { if review { "review-bot/GH_TOKEN" } else { output } } else { name };
                let files = fields.iter().map(|field| {
                    let field = field.as_str().unwrap();
                    let value = if scenario == "nul" {"fixture\0secret".to_owned()} else if scenario == "raw-prefix" {"asm_raw_not_a_sentinel".to_owned()} else if generated {
                        format!("fixture-{}-v{version}", if gcloud {"gcloud"} else if review {"review"} else {"release"})
                    } else if field == "username" {"octocat".to_owned()} else if field == "password" {"fixture-password".to_owned()} else {"fixture-other".to_owned()};
                    let substituted = (mode == "sentinel" && field != "username")
                        || (generated && scenario == "legacy-generated-raw-substituted");
                    json!({"field":field,"relative_path":if generated {output.to_owned()} else if name == "Vaultwarden/google" {format!("{name}.{field}")} else {name.replace('\\', "_")},
                        "content":if substituted {format!("asm_fixture_{field}")} else {value},"substituted":substituted})
                }).collect::<Vec<_>>();
                let lease = json!({"lease_id":id,"name":lease_name,
                    "mode":mode,"hosts":if mode == "sentinel" {vec!["api.github.com"]} else {vec![]},"expires_at":"2999-01-01T00:00:00Z","status":"active","fields":fields,
                    "generation":generation,"credential_version":if generated {json!(version)} else {Value::Null},"credential_expires_at":if generated {json!(expiry)} else {Value::Null},"generator_name":if generated {json!(generator_name)} else {Value::Null}});
                let mut result = lease.clone();
                result["files"] = json!(files);
                if reuse && !matches!(scenario, "managed-google-reuse-unmarked" | "managed-google-reuse-selected-immediate")
                    && (exact.is_none() || scenario == "managed-google-reuse-flag-on-pin") {
                    result["broader_lease_reuse"] = json!(true);
                }
                if exact.is_none() && scenario != "managed-google-project-unmarked"
                    && (edited_approval || matches!(scenario, "managed-google-unnegotiated-selection" | "managed-google-reuse-selected-immediate"
                        | "managed-google-project-cached" | "managed-google-selected-legacy-response"))
                {
                    result["operator_selected_grant"] = json!(true);
                }
                if exact.is_some() && matches!(scenario,
                    "managed-google-selected-drift-on-renew" | "managed-google-project-drift-on-renew")
                {
                    result["operator_selected_grant"] = json!(true);
                }
                if exact.is_some() && scenario == "managed-google-selected-rebound" {
                    result["lease_id"] = json!(LEASE);
                    result["operator_selected_grant"] = json!(true);
                }
                if scenario == "missing-field" {
                    result["files"] = json!([]);
                }
                if let Some(index) = existing {
                    records[index] = lease;
                } else {
                    records.push(lease);
                }
                let state = json!({"request_id":REQ,"kind":"get","status":"approved","result":result,"deny_reason":null});
                if pending && exact.is_none() {
                    *approved.lock().unwrap() = Some(state);
                    (202, json!({"request_id":REQ,"kind":"get","status":"pending","pending_lifetime_secs":600}))
                } else {
                    (200, state)
                }
            }
            ("GET", p) if p.starts_with("/v1/requests/") && scenario == "deadline" => {
                std::thread::sleep(Duration::from_millis(800));
                (
                    200,
                    json!({"request_id":REQ,"kind":"get","status":"pending","result":null,"deny_reason":null}),
                )
            }
            ("GET", p) if p.starts_with("/v1/requests/") && pending => {
                let mut state = approved.lock().unwrap().clone().expect("approval for this request");
                if scenario == "managed-google-selected-wrong-request" {
                    state["request_id"] = json!(LEASE);
                }
                (200, state)
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
fn generated_get_and_exec_reject_sentinel_and_generated_only_host_restrictions_before_posting() {
    for (output, scope) in [
        ("GITHUB_TOKEN", ["--repositories", GITHUB_REPOSITORY]),
        (GCLOUD_NAME, ["--gcloud-scope", GCLOUD_LEGACY_SCOPE]),
    ] {
        let (f, e) = launcher_fixture("mixed-providers");
        for (mode, error) in [
            (&["--sentinel", "--hosts", "api.example.com"][..], "remove --sentinel"),
            (&["--hosts", "api.example.com"][..], "remove --hosts"),
        ] {
            let mut get = vec!["get"];
            get.extend_from_slice(mode);
            get.extend(scope);
            get.extend([output, "Read credential"]);
            let out = asm(&e, &get, "");
            assert_eq!(out.status.code(), Some(2), "{get:?}: {}", text(&out.stderr));
            assert!(text(&out.stderr).contains(error));
            assert!(out.stdout.is_empty());
            assert!(!e.secrets.join(output).exists());

            let mut exec = vec!["exec"];
            exec.extend_from_slice(mode);
            exec.extend(scope);
            exec.extend([output, "--", "/bin/echo", "should not run"]);
            let out = asm(&e, &exec, "");
            assert_eq!(out.status.code(), Some(2), "{exec:?}: {}", text(&out.stderr));
            assert!(text(&out.stderr).contains(error));
            assert!(out.stdout.is_empty());
        }

        let mixed = format!("OTHER_SECRET,{output}");
        let out = asm(&e, &[
            "exec", "--sentinel", scope[0], scope[1], &mixed, "--", "/bin/echo", "should not run",
        ], "");
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("remove --sentinel"));
        assert!(out.stdout.is_empty());
        assert!(posted(&f).is_empty(), "not even the first static constituent may be posted");
    }
}

#[test]
fn get_and_exec_refuse_a_legacy_manager_generated_sentinel_result() {
    for (scenario, output, scope, error) in [
        ("legacy-generated-sentinel", "GH_TOKEN", vec!["--repositories", GITHUB_REPOSITORY],
            "sentinel delivery for a new generated credential"),
        ("managed-google-legacy-sentinel", GCLOUD_NAME, vec!["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
            "sentinel delivery for a new generated credential"),
        ("legacy-generated-raw-substituted", "GH_TOKEN", vec!["--repositories", GITHUB_REPOSITORY],
            "inconsistent get result"),
    ] {
        let (f, e) = launcher_fixture(scenario);
        let mut get = vec!["get", "--json"];
        get.extend_from_slice(&scope);
        get.extend([output, "Read credential"]);
        let out = asm(&e, &get, "");
        assert_eq!(out.status.code(), Some(1), "{scenario}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains(error));
        assert!(out.stdout.is_empty());
        assert!(!e.secrets.join(output).exists());
        assert!(!e.secrets.join(".leases.json").exists());

        let mut exec = vec!["exec"];
        exec.extend_from_slice(&scope);
        exec.extend([output, "--", "/bin/echo", "should not run"]);
        let out = asm(&e, &exec, "");
        assert_eq!(out.status.code(), Some(1), "{scenario}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains(error));
        assert!(out.stdout.is_empty());
        assert!(!f.log.lock().unwrap().iter().any(|(_, p, _)| p == "/v1/proxy-info"));
        assert_eq!(posted(&f).len(), 2);
    }
}

#[test]
fn legacy_catalog_readiness_is_not_printed_or_used_for_bindings() {
    let (f, e) = launcher_fixture("legacy-catalog-status");
    let plain = asm(&e, &["list"], "");
    assert!(plain.status.success(), "{}", text(&plain.stderr));
    assert!(plain.stderr.is_empty(), "{}", text(&plain.stderr));
    assert!(text(&plain.stdout).starts_with("GH_TOKEN\nGITHUB_TOKEN\n"));

    let json = asm(&e, &["list", "--json"], "");
    assert!(json.status.success(), "{}", text(&json.stderr));
    assert!(json.stderr.is_empty(), "{}", text(&json.stderr));
    let catalog: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(catalog.get("warnings").is_none());
    assert_eq!(catalog["secrets"][0]["generators"], json!([
        {"generator_id":"app-a", "name":"release-bot"},
        {"generator_id":"app-b", "name":"review-bot"}
    ]));

    let bound = asm(&e, &[
        "get", "--repositories", GITHUB_REPOSITORY, "TOKEN=review-bot/GH_TOKEN", "Read acme/web",
    ], "");
    assert!(bound.status.success(), "{}", text(&bound.stderr));
    let requests = posted(&f);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["name"], "review-bot/GH_TOKEN");
    assert_eq!(std::fs::read_to_string(e.secrets.join("TOKEN")).unwrap(), "fixture-review-v1");
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
fn exec_combines_explicit_legacy_google_and_github_without_coalescing_or_creating_files() {
    let (f, e) = launcher_fixture("mixed-providers");
    let out = asm_env(
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
            "--gcloud-scope",
            GCLOUD_LEGACY_SCOPE,
            "GITHUB_TOKEN,gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN,GH_TOKEN,OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "test \"$GH_TOKEN\" = fixture-release-v1 && test \"$GITHUB_TOKEN\" = \"$GH_TOKEN\" && test \"$CLOUDSDK_AUTH_ACCESS_TOKEN\" = fixture-gcloud-v1 && test \"$OTHER_SECRET\" = fixture-other && test \"$GOOGLE_APPLICATION_CREDENTIALS\" = untouched && printf mixed-ok",
        ],
        "",
        &[("CLOUDSDK_AUTH_ACCESS_TOKEN", "stale"), ("GOOGLE_APPLICATION_CREDENTIALS", "untouched")],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "mixed-ok");
    let sent = posted(&f);
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0]["name"], "GITHUB_TOKEN");
    assert_eq!(sent[1]["name"], "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN");
    assert_eq!(sent[0]["generation"], json!({
        "provider":"github_app","scope":{
            "repositories":["acme/docs","acme/issues","acme/web"],
            "permissions":{"contents":"read","issues":"write","metadata":"read","pull_requests":"read"}
        }
    }));
    assert_eq!(sent[1]["generation"], json!({"provider":"gcloud","scope":{"scopes":[GCLOUD_LEGACY_SCOPE]}}));
    assert_eq!(sent[2]["name"], "OTHER_SECRET");
    assert!(sent[2]["generation"].is_null());
    assert!(!e.secrets.exists());
}

#[test]
fn get_sends_exact_google_scopes_and_uses_the_google_output_name() {
    let (f, e) = launcher_fixture("mixed-providers");
    let scope = "https://www.googleapis.com/auth/devstorage.read_only";
    let out = asm(
        &e,
        &["get", "--json", "--gcloud-scope", scope, "CLOUDSDK_AUTH_ACCESS_TOKEN", "Read demo storage"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sent = posted(&f);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["generation"], json!({"provider":"gcloud","scope":{"scopes":[scope]}}));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["generation"]["grant"]["provider"], "gcloud");
    assert_eq!(result["files"][0]["relative_path"], "CLOUDSDK_AUTH_ACCESS_TOKEN");
    assert!(!text(&out.stdout).contains("fixture-gcloud"));
    assert_eq!(std::fs::read_to_string(e.secrets.join("CLOUDSDK_AUTH_ACCESS_TOKEN")).unwrap(), "fixture-gcloud-v1");

    let refreshed = asm(
        &e,
        &["get", "--lease", result["lease_id"].as_str().unwrap(), "--refresh", "CLOUDSDK_AUTH_ACCESS_TOKEN", "Refresh demo credentials"],
        "",
    );
    assert!(refreshed.status.success(), "{}", text(&refreshed.stderr));
    assert!(text(&refreshed.stderr).contains("previously released Google tokens may remain usable until credential expiry"));
    let sent = posted(&f);
    assert_eq!(sent[1]["refresh_from_version"], 1);
    assert!(sent[1]["generation"].is_null());
    assert_eq!(std::fs::read_to_string(e.secrets.join("CLOUDSDK_AUTH_ACCESS_TOKEN")).unwrap(), "fixture-gcloud-v2");
}

#[test]
fn get_managed_google_persists_the_exact_claims_and_refreshes_the_pinned_lease() {
    let (f, e) = launcher_fixture("managed-google");
    let get = asm(&e, &[
        "get", "--json", "--project", GCLOUD_PROJECT, "--permissions", "compute=read,storage=read",
        "--permissions", "storage=read", GCLOUD_NAME, "Read project data",
    ], "");
    assert!(get.status.success(), "{}", text(&get.stderr));
    let result: Value = serde_json::from_slice(&get.stdout).unwrap();
    let access = json!({"project_id":GCLOUD_PROJECT,"permissions":["storage=read","compute=read"]});
    assert_eq!(result["generation"]["grant"]["scope"]["access"], access);
    assert!(!text(&get.stdout).contains("fixture-gcloud"));
    let sent = posted(&f);
    assert_eq!(sent[0]["generation"], json!({"provider":"gcloud_access","scope":access}));
    assert!(sent[0]["client_capabilities"].as_array().unwrap().contains(&json!("gcloud_access_v1")));
    let token_path = e.secrets.join(GCLOUD_NAME);
    assert_eq!(std::fs::read_to_string(&token_path).unwrap(), "fixture-gcloud-v1");

    let different = asm(&e, &[
        "get", "--lease", GCLOUD_LEASE, "--project", GCLOUD_PROJECT, "--permissions", "storage=read",
        GCLOUD_NAME, "Change project claims",
    ], "");
    assert_eq!(different.status.code(), Some(2), "{}", text(&different.stderr));
    assert_eq!(posted(&f).len(), 1);
    let refreshed = asm(&e, &[
        "get", "--json", "--lease", GCLOUD_LEASE, "--refresh", GCLOUD_NAME, "Refresh project credentials",
    ], "");
    assert!(refreshed.status.success(), "{}", text(&refreshed.stderr));
    let renewed: Value = serde_json::from_slice(&refreshed.stdout).unwrap();
    assert_eq!(renewed["generation"], result["generation"]);
    let sent = posted(&f);
    assert_eq!(sent[1]["lease_id"], GCLOUD_LEASE);
    assert_eq!(sent[1]["refresh_from_version"], 1);
    assert_eq!(sent[1]["generation"], sent[0]["generation"]);
    assert_eq!(std::fs::read_to_string(token_path).unwrap(), "fixture-gcloud-v2");
}

#[test]
fn get_and_exec_preserve_approved_or_reused_grants_on_renewal() {
    for (scenario, output, lease_id, flags, grant_path, expected) in [
        ("managed-google-reuse-broad", GCLOUD_NAME, GCLOUD_LEASE,
            ["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
            "/generation/grant/scope/access/permissions", json!(["storage=read", "compute=read"])),
        ("github-reuse-broad", "GH_TOKEN", LEASE,
            ["--repositories", "acme/web", "--permissions", "contents=read"],
            "/generation/grant/scope", json!({
                "installation_id":1, "repositories":[{"id":7,"full_name":"acme/web"},{"id":8,"full_name":"acme/docs"}],
                "permissions":{"contents":"write","metadata":"read"}
            })),
        ("managed-google-selected-narrow", GCLOUD_NAME, GCLOUD_LEASE,
            ["--project", GCLOUD_PROJECT, "--permissions", "compute=read,storage=read"],
            "/generation/grant/scope/access/permissions", json!(["storage=read"])),
        ("managed-google-selected-broad", GCLOUD_NAME, GCLOUD_LEASE,
            ["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
            "/generation/grant/scope/access/permissions", json!(["storage=read", "compute=read"])),
        ("managed-google-project-switched", GCLOUD_NAME, GCLOUD_LEASE,
            ["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
            "/generation/grant/scope/access/permissions", json!(["compute=read"])),
        ("managed-google-project-only", GCLOUD_NAME, GCLOUD_LEASE,
            ["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
            "/generation/grant/scope/access/permissions", json!(["storage=read"])),
        ("github-selected-narrow", "GH_TOKEN", LEASE,
            ["--repositories", "acme/docs,acme/web", "--permissions", "contents=write"],
            "/generation/grant/scope", json!({
                "installation_id":1, "repositories":[{"id":7,"full_name":"acme/web"}],
                "permissions":{"contents":"read","metadata":"read"}
            })),
        ("github-selected-broad", "GH_TOKEN", LEASE,
            ["--repositories", "acme/web", "--permissions", "contents=read"],
            "/generation/grant/scope", json!({
                "installation_id":1, "repositories":[{"id":7,"full_name":"acme/web"},{"id":8,"full_name":"acme/docs"}],
                "permissions":{"contents":"write","metadata":"read"}
            })),
    ] {
        let (f, e) = launcher_fixture(scenario);
        let google = output == GCLOUD_NAME;
        let switched = scenario.starts_with("managed-google-project-");
        let approved_project = if switched { GCLOUD_OTHER_PROJECT } else { GCLOUD_PROJECT };
        let (first_value, renewed_value) = if google {
            ("fixture-gcloud-v1", "fixture-gcloud-v2")
        } else {
            ("fixture-release-v1", "fixture-release-v2")
        };
        let mut args = vec!["get", "--json", "--raw"];
        args.extend(flags);
        args.extend([output, "Read approved credentials"]);
        let get = asm(&e, &args, "");
        assert!(get.status.success(), "{scenario}: {}", text(&get.stderr));
        let result: Value = serde_json::from_slice(&get.stdout).unwrap();
        assert_eq!(result["lease_id"], lease_id);
        assert_eq!(result.pointer(grant_path), Some(&expected), "{scenario}");
        if google {
            assert_eq!(result["generation"]["grant"]["scope"]["access"]["project_id"], approved_project);
        }
        assert_eq!(std::fs::read_to_string(e.secrets.join(output)).unwrap(), first_value);
        let refreshed = asm(&e, &[
            "get", "--json", "--lease", lease_id, "--refresh", output, "Renew the approved grant",
        ], "");
        assert!(refreshed.status.success(), "{scenario}: {}", text(&refreshed.stderr));
        let renewed: Value = serde_json::from_slice(&refreshed.stdout).unwrap();
        assert_eq!(renewed["generation"], result["generation"]);
        assert_eq!(std::fs::read_to_string(e.secrets.join(output)).unwrap(), renewed_value);

        let (exec_fake, exec_env) = launcher_fixture(scenario);
        let mut args = vec!["exec", "--raw"];
        args.extend(flags);
        args.extend([output, "--", "/bin/sh", "-c",
            "test \"$(printenv \"$1\")\" = \"$2\" && printf launched", "fixture", output, renewed_value]);
        let exec = asm(&exec_env, &args, "");
        assert!(exec.status.success(), "{scenario}: {}", text(&exec.stderr));
        assert_eq!(text(&exec.stdout), "launched");
        assert!(!exec_env.secrets.exists());

        for (fake, forced) in [(f, true), (exec_fake, false)] {
            let sent = posted(&fake);
            assert_eq!(sent.len(), 2);
            assert!(sent[0]["client_capabilities"].as_array().unwrap().contains(&json!("operator_selected_grant_v1")));
            assert_eq!(sent[0]["client_capabilities"].as_array().unwrap().contains(&json!(SELECT_PROJECT)), switched);
            assert!(!sent[1]["client_capabilities"].as_array().unwrap().contains(&json!(SELECT_PROJECT)));
            assert_eq!(sent[0]["client_capabilities"].as_array().unwrap().contains(&json!(BROADER_REUSE)), scenario.contains("-reuse-"));
            assert!(!sent[1]["client_capabilities"].as_array().unwrap().contains(&json!(BROADER_REUSE)));
            assert!(sent[0]["lease_id"].is_null());
            assert_eq!(sent[1]["lease_id"], lease_id);
            assert_eq!(sent[1]["refresh"], forced);
            if google {
                assert_eq!(sent[0]["generation"]["scope"]["project_id"], GCLOUD_PROJECT);
                assert_eq!(sent[1]["generation"]["scope"]["project_id"], approved_project);
                assert_eq!(sent[1]["generation"]["scope"]["permissions"], expected);
                assert_ne!(sent[0]["generation"], sent[1]["generation"]);
            } else {
                assert!(sent[1]["generation"].is_null());
            }
        }
    }
}

#[test]
fn pinned_get_rejects_a_new_lease_even_if_marked_operator_selected() {
    let (f, e) = launcher_fixture("managed-google-selected-rebound");
    let get = asm(&e, &[
        "get", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read project data",
    ], "");
    assert!(get.status.success(), "{}", text(&get.stderr));
    let get = asm(&e, &[
        "get", "--lease", GCLOUD_LEASE, "--refresh", GCLOUD_NAME, "Renew the approved grant",
    ], "");
    assert!(!get.status.success());
    assert!(text(&get.stderr).contains("inconsistent get result"));
    assert_eq!(std::fs::read_to_string(e.secrets.join(GCLOUD_NAME)).unwrap(), "fixture-gcloud-v1");
    assert_eq!(posted(&f).len(), 2);
}

#[test]
fn reuse_marker_requires_negotiation_immediate_delivery_and_covering_claims() {
    for (scenario, message) in [
        ("managed-google-reuse-pending", "negotiated automatic reuse"),
        ("managed-google-reuse-unnegotiated", "negotiated automatic reuse"),
        ("managed-google-reuse-missing-claim", "does not cover"),
        ("managed-google-reuse-wrong-project", "does not cover"),
        ("managed-google-reuse-unmarked", "exact Google Cloud project and permissions"),
        ("managed-google-reuse-selected-immediate", "exact Google Cloud project and permissions"),
    ] {
        let (_fake, e) = launcher_fixture(scenario);
        let get = asm(&e, &["get", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read data"], "");
        assert!(!get.status.success(), "{scenario}");
        assert!(text(&get.stderr).contains(message), "{scenario}: {}", text(&get.stderr));
        assert!(!e.secrets.join(GCLOUD_NAME).exists());
        let exec = asm(&e, &["exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "--", "/bin/echo", "launched"], "");
        assert!(!exec.status.success(), "{scenario}");
        assert!(text(&exec.stderr).contains(message), "{scenario}: {}", text(&exec.stderr));
        assert!(exec.stdout.is_empty());
    }
}

#[test]
fn explicit_new_lease_and_pinned_deliveries_never_accept_a_reuse_marker() {
    let (fake, e) = launcher_fixture("managed-google-reuse-flag-on-pin");
    let get = asm(&e, &["get", "--new-lease", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read data"], "");
    assert!(!get.status.success());
    assert!(text(&get.stderr).contains("negotiated automatic reuse"));
    assert!(!e.secrets.join(GCLOUD_NAME).exists());
    let get = asm(&e, &["get", "--lease", GCLOUD_LEASE, "--refresh", GCLOUD_NAME, "Renew data access"], "");
    assert!(!get.status.success());
    assert!(text(&get.stderr).contains("negotiated automatic reuse"));
    assert!(!e.secrets.join(GCLOUD_NAME).exists());
    let sent = posted(&fake);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|r| !r["client_capabilities"].as_array().unwrap().contains(&json!(BROADER_REUSE))));

    let (_fake, e) = launcher_fixture("managed-google-reuse-flag-on-pin");
    let exec = asm(&e, &["exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "--", "/bin/echo", "launched"], "");
    assert!(!exec.status.success());
    assert!(text(&exec.stderr).contains("negotiated automatic reuse"));
    assert!(exec.stdout.is_empty());
}

#[test]
fn operator_decision_for_another_request_never_writes_or_launches() {
    let (f, e) = launcher_fixture("managed-google-selected-wrong-request");
    let get = asm(&e, &[
        "get", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read project data",
    ], "");
    assert!(!get.status.success());
    assert!(text(&get.stderr).contains("decision for a different request"));
    assert!(!e.secrets.join(GCLOUD_NAME).exists());
    let exec = asm(&e, &[
        "exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME,
        "--", "/bin/echo", "should not run",
    ], "");
    assert!(!exec.status.success());
    assert!(text(&exec.stderr).contains("decision for a different request"));
    assert!(exec.stdout.is_empty());
    assert_eq!(posted(&f).len(), 2);
}

#[test]
fn managed_google_mismatches_never_write_or_launch() {
    for scenario in [
        "managed-google-broad", "managed-google-other-project", "managed-google-legacy-response",
        "managed-google-selected-unmarked", "managed-google-unnegotiated-selection",
        "managed-google-selected-other-project", "managed-google-selected-legacy-response",
        "managed-google-project-unmarked", "managed-google-project-only-permission-drift",
        "managed-google-project-cached",
    ] {
        let (f, e) = launcher_fixture(scenario);
        let get = asm(&e, &[
            "get", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read project data",
        ], "");
        assert!(!get.status.success(), "{scenario}");
        assert!(text(&get.stderr).contains("exact Google Cloud project and permissions"), "{scenario}: {}", text(&get.stderr));
        assert!(!e.secrets.join(GCLOUD_NAME).exists(), "{scenario}");
        assert!(!e.secrets.join(".leases.json").exists(), "{scenario}");
        let exec = asm(&e, &[
            "exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME,
            "--", "/bin/echo", "should not run",
        ], "");
        assert!(!exec.status.success(), "{scenario}");
        assert!(text(&exec.stderr).contains("exact Google Cloud project and permissions"));
        assert!(exec.stdout.is_empty(), "{scenario}");
        let sent = posted(&f);
        assert_eq!(sent.len(), 2);
        for request in sent {
            assert_eq!(request["client_capabilities"].as_array().unwrap().contains(&json!(SELECT_PROJECT)),
                scenario.starts_with("managed-google-project-"), "{scenario}");
        }
    }
}

#[test]
fn unmarked_github_broadening_never_writes_or_launches() {
    let (f, e) = launcher_fixture("github-selected-unmarked");
    let get = asm(&e, &["get", "--repositories", GITHUB_REPOSITORY, "GH_TOKEN", "Read repository"], "");
    assert!(!get.status.success());
    assert!(text(&get.stderr).contains("exact requested grant"));
    assert!(!e.secrets.join("GH_TOKEN").exists());
    let exec = asm(&e, &[
        "exec", "--repositories", GITHUB_REPOSITORY, "GH_TOKEN", "--", "/bin/echo", "should not run",
    ], "");
    assert!(!exec.status.success());
    assert!(text(&exec.stderr).contains("exact requested grant"));
    assert!(exec.stdout.is_empty());
    assert_eq!(posted(&f).len(), 2);
}

#[test]
fn exec_managed_google_pins_renewal_and_rejects_changed_authority() {
    for (scenario, expected, approved_project) in [
        ("managed-google-short", true, GCLOUD_PROJECT),
        ("managed-google-selected-drift-on-renew", false, GCLOUD_PROJECT),
        ("managed-google-project-drift-on-renew", false, GCLOUD_OTHER_PROJECT),
    ] {
        let (f, e) = launcher_fixture(scenario);
        let out = asm(&e, &[
            "exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME,
            "--", "/bin/sh", "-c", "test \"$CLOUDSDK_AUTH_ACCESS_TOKEN\" = fixture-gcloud-v2 && printf renewed",
        ], "");
        assert_eq!(out.status.success(), expected, "{scenario}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), if expected { "renewed" } else { "" });
        if !expected {
            assert!(text(&out.stderr).contains("changed the pinned generated credential grant"));
        }
        let sent = posted(&f);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1]["lease_id"], GCLOUD_LEASE);
        assert_eq!(sent[0]["generation"]["scope"]["project_id"], GCLOUD_PROJECT);
        assert_eq!(sent[1]["generation"]["scope"], json!({"project_id":approved_project,"permissions":["storage=read"]}));
        assert!(!sent[1]["client_capabilities"].as_array().unwrap().contains(&json!(SELECT_PROJECT)));
        assert!(!e.secrets.exists());
    }
}

#[test]
fn managed_google_requires_capability_and_an_unambiguous_provider_before_posting() {
    let (f, e) = launcher_fixture("managed-google-unsupported");
    for args in [
        vec!["get", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "Read project data"],
        vec!["exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read", GCLOUD_NAME, "--", "/bin/true"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("gcloud_access_v1; upgrade the manager"));
    }
    assert!(posted(&f).is_empty());

    let (f, e) = launcher_fixture("managed-google");
    for args in [
        vec!["get", GCLOUD_NAME, "Read project data"],
        vec!["exec", GCLOUD_NAME, "--", "/bin/true"],
        vec!["exec", "--repositories", GITHUB_REPOSITORY, "GH_TOKEN,CLOUDSDK_AUTH_ACCESS_TOKEN", "--", "/bin/true"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("--project ID --permissions"));
    }
    let mixed = asm(&e, &[
        "exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read",
        "GH_TOKEN,CLOUDSDK_AUTH_ACCESS_TOKEN", "--", "/bin/true",
    ], "");
    assert_eq!(mixed.status.code(), Some(2), "{}", text(&mixed.stderr));
    assert!(text(&mixed.stderr).contains("require separate asm exec commands"));
    assert!(posted(&f).is_empty());
}

#[test]
fn exec_qualified_static_google_spelling_does_not_receive_managed_claims() {
    let (f, e) = launcher_fixture("managed-google-collision");
    let out = asm(&e, &[
        "exec", "--project", GCLOUD_PROJECT, "--permissions", "storage=read",
        "STATIC=work/CLOUDSDK_AUTH_ACCESS_TOKEN,gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN",
        "--", "/bin/sh", "-c", "test \"$STATIC\" = fixture-other && test \"$CLOUDSDK_AUTH_ACCESS_TOKEN\" = fixture-gcloud-v1",
    ], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["name"], "work/CLOUDSDK_AUTH_ACCESS_TOKEN");
    assert!(sent[0]["generation"].is_null());
    assert_eq!(sent[1]["name"], "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN");
    assert_eq!(sent[1]["generation"]["provider"], "gcloud_access");
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
            "--hosts",
            "api.example.com",
            "--sentinel",
            "OTHER_SECRET",
            "--",
            "/bin/sh",
            "-c",
            "test \"$OTHER_SECRET\" = asm_fixture_actual_field && test -n \"$HTTPS_PROXY\" && test \"$HTTP_PROXY\" = \"$HTTPS_PROXY\" && test \"$ALL_PROXY\" = \"$HTTPS_PROXY\" && test -z \"$https_proxy$http_proxy$all_proxy$no_proxy$ssl_cert_file$requests_ca_bundle$curl_ca_bundle$git_ssl_cainfo$node_extra_ca_certs\" && test -f \"$SSL_CERT_FILE\" && printf proxy-ok",
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
            "--sentinel",
            "OTHER_SECRET",
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
    let get = asm(&e, &["get", "--sentinel", "work/GH_TOKEN", "Read a static secret"], "");
    assert!(get.status.success(), "{}", text(&get.stderr));
    assert_eq!(std::fs::read_to_string(e.secrets.join("work/GH_TOKEN")).unwrap(), "asm_fixture_value");
    let exec = asm(
        &e,
        &[
            "exec", "--sentinel", "TOKEN=work/GH_TOKEN", "--", "/bin/sh", "-c",
            "test \"$TOKEN\" = asm_fixture_value",
        ],
        "",
    );
    assert!(exec.status.success(), "{}", text(&exec.stderr));
    let ignored_scope = asm(
        &e,
        &["exec", "--repositories", GITHUB_REPOSITORY, "TOKEN=work/GH_TOKEN", "--", "/bin/true"],
        "",
    );
    assert_eq!(ignored_scope.status.code(), Some(2), "{}", text(&ignored_scope.stderr));
    assert!(text(&ignored_scope.stderr).contains("generated GitHub"));
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|body| body["name"] == "work/GH_TOKEN" && body["generation"].is_null()
        && body["sentinel"] == true && body["raw"] == false));
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
    assert!(posted(&f).last().unwrap()["generation"].is_null());
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
fn get_exact_historical_generated_sentinel_preserves_original_authority() {
    for scenario in ["same", "explicit", "older-manager", "mode", "hosts", "deadline", "field", "unsubstituted"] {
        let grant = json!({"generator_id":"app-a","generator_revision":1,"grant":{"provider":"github_app","scope":{
            "installation_id":1,"repositories":[{"id":7,"full_name":"acme/web"}],"permissions":{"metadata":"read"}}}});
        let lease = json!({"lease_id":LEASE,"name":"old-name/GH_TOKEN","mode":"sentinel","hosts":["api.github.com"],
            "expires_at":"2999-01-01T00:00:00Z","status":"active","fields":["value"],
            "generation":grant,"credential_expires_at":"2999-01-01T00:00:00Z","credential_version":9});
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
                assert_eq!(body["raw"], false);
                assert_eq!(body["sentinel"], true);
                assert_eq!(body["hosts"], json!(["api.github.com"]));
                let mut result = lease.clone();
                result["credential_version"] = json!(10);
                result["files"] = json!([{"field":"value","relative_path":"old-name/GH_TOKEN",
                    "content":"asm_historical_sentinel","substituted":true}]);
                match scenario {
                    "older-manager" => { result["files"][0].as_object_mut().unwrap().remove("substituted"); }
                    "mode" => {
                        result["mode"] = json!("raw");
                        result["hosts"] = json!([]);
                        result["files"][0]["substituted"] = json!(false);
                    }
                    "hosts" => result["hosts"] = json!(["*"]),
                    "deadline" => result["expires_at"] = json!("2999-02-01T00:00:00Z"),
                    "field" => result["files"][0]["field"] = json!("other"),
                    "unsubstituted" => result["files"][0]["substituted"] = json!(false),
                    _ => {}
                }
                (200, json!({"request_id":REQ,"kind":"get","status":"approved","result":result}))
            }
            _ => (404, json!({"error":{"code":"not_found","message":"no current catalog"}})),
        }));
        let e = env();
        write_host_json(&e, &f);
        let name = "old-name/GITHUB_TOKEN";
        let mut args = vec!["get", "--json", "--lease", LEASE, "--refresh", "--hosts", "api.github.com"];
        if scenario == "explicit" {
            args.push("--sentinel");
        }
        args.extend([name, "Continue using the existing lease"]);
        let out = asm(&e, &args, "");
        if matches!(scenario, "same" | "explicit" | "older-manager") {
            assert!(out.status.success(), "{scenario}: {}", text(&out.stderr));
            let result: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(result["mode"], "sentinel");
            assert_eq!(result["hosts"], json!(["api.github.com"]));
            assert_eq!(result["expires_at"], "2999-01-01T00:00:00Z");
            let delivery = if scenario == "older-manager" { "unspecified_sentinel_field" } else { "sentinel" };
            assert_eq!(result["files"][0]["delivery"], delivery);
            assert!(text(&out.stderr).contains("--refresh --sentinel"));
            assert_eq!(std::fs::read_to_string(e.secrets.join(name)).unwrap(), "asm_historical_sentinel");
            let raw = asm(&e, &["get", "--raw", "--lease", LEASE, name, "Do not disclose raw"], "");
            assert_eq!(raw.status.code(), Some(2), "{}", text(&raw.stderr));
            assert!(text(&raw.stderr).contains("delivery mode conflicts"));
        } else {
            assert_eq!(out.status.code(), Some(1), "{scenario}: {}", text(&out.stderr));
            assert!(text(&out.stderr).contains("inconsistent get result"));
            assert!(out.stdout.is_empty());
            assert!(!e.secrets.join(name).exists());
        }
        assert_eq!(posted(&f).len(), 1);
        assert!(!f.log.lock().unwrap().iter().any(|(_, p, _)| p == "/v1/secrets"));
    }
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
    let (f, e) = launcher_fixture("sentinel");
    let out = asm_env(
        &e,
        &[
            "exec",
            "--repositories",
            GITHUB_REPOSITORY,
            "--hosts",
            "api.example.com",
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
    let receipt = text(&out.stderr);
    assert!(receipt.contains("GH_TOKEN: raw") && receipt.contains("OTHER_SECRET: sentinel"));
    assert!(!receipt.contains("fixture-release-v1") && !receipt.contains("asm_fixture_actual_field"));
    let sent = posted(&f);
    assert_eq!(sent[0]["raw"], true);
    assert_eq!(sent[0]["hosts"], json!([]));
    assert_eq!(sent[1]["raw"], false);
    assert_eq!(sent[1]["hosts"], json!(["api.example.com"]));
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

const LOGIN_URL: &str = "https://login.example.test/session?return=%2Fhome";
const LOGIN_EXPIRY: &str = "2999-01-01T00:00:00Z";
const TOTP_PATH: &str = "/v1/login-grants/11111111-2222-4333-8444-555555555555/totp";

fn active_login_lease(url: &str) -> Value {
    json!({"lease_id":LEASE,"name":"work/Site","mode":"sentinel","hosts":["login.example.test"],
        "expires_at":LOGIN_EXPIRY,"status":"active","fields":["username","password","totp"],
        "login":{"url":url}})
}

fn otp_only_result(url: &str) -> Value {
    json!({"lease_id":LEASE,"mode":"sentinel","hosts":["login.example.test"],"expires_at":LOGIN_EXPIRY,
        "login":{"url":url},
        "files":[{"field":"totp","relative_path":"work/Site.totp","content":"061234","substituted":false}]})
}

/// A fake manager proxy answering every CONNECT with `status`; records the heads.
fn connect_answering(status: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            // `resolve_for` opens and closes a bare TCP connection to pick a hint.
            if !head.is_empty() {
                seen.lock().unwrap().push(head);
            }
            let _ = write!(reader.get_mut(), "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, heads)
}

/// A v2 manager that approves a login grant at once, then refreshes its OTP;
/// its proxy (requiring per-host credentials) answers marked CONNECTs with `proxy_status`.
fn login_fixture(granted_url: &'static str, proxy_status: &'static str) -> (Fake, Env, u16, Arc<Mutex<Vec<String>>>) {
    let (proxy_port, heads) = connect_answering(proxy_status);
    let ca = rcgen::generate_simple_self_signed(vec!["proxy ca".into()]).unwrap();
    let ca_hash = asm_proto::crypto::sha256_hex(ca.cert.der());
    let ca = ca.cert.pem();
    let granted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f = start(Arc::new(move |method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (
            200,
            json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]}),
        ),
        ("GET", "/v1/leases") if granted.load(std::sync::atomic::Ordering::SeqCst) => (
            200,
            json!({"leases":[active_login_lease(granted_url)]}),
        ),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("POST", TOTP_PATH) if granted.load(std::sync::atomic::Ordering::SeqCst) => (
            200,
            otp_only_result(granted_url),
        ),
        ("GET", "/v1/proxy-info") => (
            200,
            json!({"port":proxy_port,"hints":["127.0.0.1"],"ca_sha256":ca_hash,"proxy_auth":true}),
        ),
        ("GET", "/v1/ca.crt") => (200, json!(ca)),
        ("POST", "/v1/requests") => {
            granted.store(true, std::sync::atomic::Ordering::SeqCst);
            (
                200,
                json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":{
                    "lease_id":LEASE,"mode":"sentinel","hosts":["login.example.test"],"expires_at":LOGIN_EXPIRY,
                    "login":{"url":granted_url},
                    "files":[{"field":"username","relative_path":"work/Site.username","content":"octocat","substituted":false},
                             {"field":"password","relative_path":"work/Site.password","content":"asm_0123456789012345678901234567890123456789","substituted":true},
                             {"field":"totp","relative_path":"work/Site.totp","content":"123456","substituted":false}]}}),
            )
        }
        _ => (
            404,
            json!({"error":{"code":"not_found","message":format!("{method} {path}")}}),
        ),
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e, proxy_port, heads)
}

/// `asm proxy-router run` in the test's configuration directory, killed on drop.
struct RouterProcess(std::process::Child, u16);

impl RouterProcess {
    /// What a routed browser does when it loads a page: a CONNECT for `authority`
    /// through the router (the router may answer 502 when it can't reach it).
    fn visit(&self, authority: &str) {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.1)).unwrap();
        s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 "), "{line}");
    }
}

impl Drop for RouterProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_router(e: &Env) -> RouterProcess {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let child = Command::new(env!("CARGO_BIN_EXE_asm"))
        .args(["proxy-router", "run", "--port", &port.to_string()])
        .env_clear()
        .env("HOME", e.cfg.parent().unwrap())
        .env("XDG_CONFIG_HOME", &e.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let router = RouterProcess(child, port);
    let sock = e.cfg.join("asm/router.sock");
    assert!(
        wait_for(Duration::from_secs(10), || std::os::unix::net::UnixStream::connect(&sock).is_ok()),
        "router did not start"
    );
    router
}

fn router_status(e: &Env) -> Value {
    let out = asm(e, &["proxy-router", "status", "--json"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn get_login_url_validates_arguments_before_contacting_the_manager() {
    let (f, e, _, _) = login_fixture(LOGIN_URL, "200 Connection established");
    let url = LOGIN_URL;
    for conflict in [
        vec!["--raw"],
        vec!["--sentinel"],
        vec!["--hosts", "a.test"],
        vec!["--lease", LEASE],
        vec!["--refresh"],
        vec!["--new-lease"],
        vec!["--repositories", GITHUB_REPOSITORY],
        vec!["--project", GCLOUD_PROJECT, "--permissions", "storage=read"],
        vec!["--permissions", "contents=read"],
        vec!["--gcloud-scope", GCLOUD_LEGACY_SCOPE],
    ] {
        let mut args = vec!["get", "--login-url", url, "--reason", "sign in"];
        args.extend(conflict.iter().copied());
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{conflict:?}");
        assert!(text(&out.stderr).contains("cannot be used with"), "{conflict:?}: {}", text(&out.stderr));
    }
    for args in [
        vec!["get", "--login-url", url, "work/Site", "--reason", "r"],
        vec!["get", "--login-url", url, "work/Site::password", "--reason", "r"],
        vec!["get", "--login-url", url, "work/Site", "why"],
        vec!["get", "--login-url", url, "work/Site"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = text(&out.stderr);
        assert!(stderr.contains("no longer accepts a positional ITEM"), "{stderr}");
        assert!(stderr.contains("--account USERNAME_OR_EMAIL"), "{stderr}");
    }
    for (args, message) in [
        (vec!["get", "--login-url", "http://login.example.test/session", "--reason", "r"], "invalid: login URL must start with https://"),
        (vec!["get", "--login-url", url], "invalid: --login-url needs a reason: --reason TEXT"),
        (vec!["get", "--login-url", url, "--reason", "r", "--site", "https://app.example.test/path"], "invalid: site must be an HTTPS origin without a path or query"),
        (vec!["get", "--login-url", url, "--reason", "r", "--site", "http://app.example.test"], "invalid: login URL must start with https://"),
        (vec!["get", "--login-url", url, "--reason", "r", "--account", ""], "invalid: account must be 1–320 characters without surrounding whitespace"),
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&out.stderr).trim(), message, "{args:?}");
    }
    // Non-browser get still takes NAME and REASON and forbids browser-only flags.
    for args in [
        vec!["get", "work/Site", "why", "--reason", "why"],
        vec!["get", "work/Site"],
        vec!["get", "--reason", "why"],
        vec!["get", "work/Site", "why", "--site", "https://app.example.test"],
        vec!["get", "work/Site", "why", "--account", "a@example.test"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("Usage: asm get"), "{args:?}: {}", text(&out.stderr));
    }
    assert!(f.log.lock().unwrap().is_empty(), "invalid arguments never reached the manager");
    // --reason also serves ordinary gets.
    let (f, e) = paired("approve-get");
    let out = asm(&e, &["get", "--hosts", "api.example.com", "work/GitHub", "--reason", "deploy the site"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(posted(&f)[0]["reason"], "deploy the site");
}

#[test]
fn get_login_url_requires_a_local_router() {
    let (f, e, _, _) = login_fixture(LOGIN_URL, "200 Connection established");
    let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr).trim(),
        "error: no asm proxy-router on this machine; the browser must run on this machine: asm browser install <target>"
    );
    assert!(posted(&f).is_empty());
}

#[test]
fn get_login_url_requires_the_browser_to_go_through_the_router() {
    let (f, e, _, _) = login_fixture(LOGIN_URL, "200 Connection established");
    let router = start_router(&e);
    // A browser that bypasses the router never shows the sign-in host to it.
    router.visit("other.example.test:443");
    router.visit("login.example.test:8443");
    let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no browser on this machine has sent login.example.test:443 through the asm proxy router"),
        "{}",
        text(&out.stderr)
    );
    assert!(posted(&f).is_empty(), "no approval is requested");
    router.visit("Login.Example.test:443");
    let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn get_login_url_grants_routes_and_prints_the_login() {
    let (f, e, proxy_port, heads) = login_fixture(LOGIN_URL, "200 Connection established");
    let router = start_router(&e);
    router.visit("login.example.test:443");
    let out = asm(
        &e,
        &["get", "--json", "--login-url", "https://Login.Example.test:443/session?return=%2Fhome",
          "--site", "https://App.Example.test:443", "--account", "octocat@example.test", "--reason", "sign in"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sent = posted(&f);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0], json!({
        "kind":"browser_login","mode":"grant","url":LOGIN_URL,"site":"https://app.example.test",
        "account":"octocat@example.test","reason":"sign in","extra_fill_origins":[],
        "agent":"test-agent","client_capabilities":["browser_login_v2"]
    }));

    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["login"], json!({"url": LOGIN_URL}));
    assert_eq!(j["lease_id"], LEASE);
    assert_eq!(j["files"].as_array().unwrap().len(), 3);
    assert_eq!(std::fs::read_to_string(e.secrets.join("work/Site.username")).unwrap(), "octocat");
    let stderr = text(&out.stderr);
    assert!(stderr.contains("open or reload the login page now, type the username and the sentinel, submit once"), "{stderr}");
    assert!(stderr.contains(&format!("for a one-time code run: asm totp {LEASE}")), "{stderr}");
    assert!(!f.log.lock().unwrap().iter().any(|(_, path, _)| path == "/v1/secrets"));

    // The barrier probed the manager proxy with the marker and this host's credentials,
    // then handed the route to the router.
    let heads = heads.lock().unwrap().clone();
    assert!(!heads.is_empty());
    use base64::Engine as _;
    let password = asm_proto::crypto::proxy_password(&sha256(TOKEN.as_bytes()));
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("h1:{password}"));
    assert!(heads[0].starts_with("CONNECT login.example.test:443 HTTP/1.1\r\n"), "{}", heads[0]);
    assert!(heads[0].contains("Asm-Browser-Route: 1\r\n"), "{}", heads[0]);
    assert!(heads[0].contains(&format!("Proxy-Authorization: Basic {basic}\r\n")), "{}", heads[0]);
    let status = router_status(&e);
    assert_eq!(
        status["routes"],
        json!([{"host":"login.example.test","port":443,"expires_at":"2999-01-01T00:00:00Z"}])
    );
    let saved: Value = serde_json::from_slice(&std::fs::read(e.cfg.join("asm/router-routes.json")).unwrap()).unwrap();
    assert_eq!(saved["routes"][0]["proxy"], format!("127.0.0.1:{proxy_port}"));
}

#[test]
fn totp_refreshes_only_the_existing_grants_code_without_a_popup() {
    let (f, e, _, _) = login_fixture(LOGIN_URL, "200 Connection established");
    {
        let router = start_router(&e);
        router.visit("login.example.test:443");
        let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains(&format!("lease: {LEASE}")));
    } // The OTP command works without a running router.
    let password = e.secrets.join("work/Site.password");
    let username = e.secrets.join("work/Site.username");
    let totp = e.secrets.join("work/Site.totp");
    let before = std::fs::read(&password).unwrap();
    assert_eq!(std::fs::read_to_string(&totp).unwrap(), "123456");

    f.log.lock().unwrap().clear();
    let out = asm(&e, &["totp", LEASE, "--json"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["lease_id"], LEASE);
    assert_eq!(j["login"], json!({"url": LOGIN_URL}));
    assert_eq!(j["files"].as_array().unwrap().len(), 1);
    assert_eq!(j["files"][0]["path"], totp.to_str().unwrap());
    assert_eq!(j["files"][0]["delivery"], "raw");
    assert!(!text(&out.stdout).contains("061234"));
    assert!(!text(&out.stderr).contains("061234"));
    assert_eq!(std::fs::read_to_string(&totp).unwrap(), "061234");
    assert_eq!(std::fs::read_to_string(&username).unwrap(), "octocat");
    assert_eq!(std::fs::read(&password).unwrap(), before);
    let log = f.log.lock().unwrap();
    assert_eq!(log.iter().map(|(met, path, _)| (met.as_str(), path.as_str())).collect::<Vec<_>>(),
        [("GET", "/v1/health"), ("GET", "/v1/leases"), ("POST", TOTP_PATH)]);
    drop(log);

    let manifest = read_json(&e.secrets.join(".leases.json"));
    assert_eq!(manifest[LEASE]["paths"], json!(["work/Site.username", "work/Site.password", "work/Site.totp"]));
}

fn otp_fixture(lease: Option<Value>, result: Value) -> (Fake, Env) {
    let f = start(Arc::new(move |method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]})),
        ("GET", "/v1/leases") => (200, json!({"leases":lease.iter().collect::<Vec<_>>()})),
        ("POST", TOTP_PATH) => (200, result.clone()),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e)
}

#[test]
fn totp_refuses_different_lease_metadata_or_extra_material() {
    for (pointer, value) in [
        ("/lease_id", json!(GCLOUD_LEASE)),
        ("/mode", json!("raw")),
        ("/hosts/0", json!("other.example.test")),
        ("/login/url", json!("https://login.example.test/different?return=%2Fhome")),
        ("/expires_at", json!("2998-01-01T00:00:00Z")),
        ("/expires_at", Value::Null),
        ("/files", json!([])),
        ("/files", json!([
            {"field":"totp","relative_path":"work/Site.totp","content":"123456","substituted":false},
            {"field":"password","relative_path":"work/Site.password","content":"not a code","substituted":false}
        ])),
        ("/files/0/field", json!("password")),
        ("/files/0/substituted", json!(true)),
        ("/files/0/content", json!("not a code")),
        ("/files/0/relative_path", json!("../Site.totp")),
    ] {
        let mut result = otp_only_result(LOGIN_URL);
        *result.pointer_mut(pointer).unwrap() = value;
        let (f, e) = otp_fixture(Some(active_login_lease(LOGIN_URL)), result);
        let out = asm(&e, &["totp", LEASE, "--json"], "");
        assert!(!out.status.success(), "{pointer}: {}", text(&out.stderr));
        assert!(out.stdout.is_empty(), "{pointer}");
        assert!(!e.secrets.join("work").exists(), "{pointer}");
        assert!(!e.secrets.parent().unwrap().join("Site.totp").exists(), "{pointer}");
        assert!(f.log.lock().unwrap().iter().any(|(method, path, _)| method == "POST" && path == TOTP_PATH));
    }
}

#[test]
fn totp_requires_a_live_browser_grant() {
    let mut revoked = active_login_lease(LOGIN_URL);
    revoked["status"] = json!("revoked");
    let mut expired = active_login_lease(LOGIN_URL);
    expired["expires_at"] = json!("2000-01-01T00:00:00Z");
    let mut ordinary = active_login_lease(LOGIN_URL);
    ordinary["login"] = Value::Null;
    for lease in [None, Some(revoked), Some(expired), Some(ordinary)] {
        let (f, e) = otp_fixture(lease, otp_only_result(LOGIN_URL));
        let out = asm(&e, &["totp", "work/Site"], "");
        assert_eq!(out.status.code(), Some(2));
        assert!(f.log.lock().unwrap().is_empty());

        let out = asm(&e, &["totp", LEASE], "");
        assert!(!out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("asm get --login-url"));
        assert!(!f.log.lock().unwrap().iter().any(|(method, _, _)| method == "POST"));
    }
}

#[test]
fn totp_does_not_post_for_a_grant_without_a_code() {
    let mut lease = active_login_lease(LOGIN_URL);
    lease["fields"] = json!(["username", "password"]);
    let (f, e) = otp_fixture(Some(lease), otp_only_result(LOGIN_URL));
    let out = asm(&e, &["totp", LEASE], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("does not include a one-time code"));
    assert!(!f.log.lock().unwrap().iter().any(|(method, _, _)| method == "POST"));
}

#[test]
fn list_sites_uses_only_the_dedicated_site_catalog() {
    let sites = ["https://app.example.test", "https://login.example.test:8443"];
    let f = start(Arc::new(move |method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]})),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("GET", "/v1/login-sites") => (200, json!({"sites":sites})),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    let plain = asm(&e, &["list", "--sites"], "");
    assert!(plain.status.success(), "{}", text(&plain.stderr));
    assert_eq!(text(&plain.stdout).lines().collect::<Vec<_>>(), sites);
    let out = asm(&e, &["list", "--sites", "--json"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), json!({"sites":sites}));
    assert_eq!(f.log.lock().unwrap().iter().filter(|(_, path, _)| path == "/v1/login-sites").count(), 2);
}

#[test]
fn browser_commands_require_v2_without_falling_back() {
    let f = start(Arc::new(|method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({
            "name":"asm-manager","version":"0.7.0","capabilities":["login_grant_v1","login_broker_v1"]
        })),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    let router = start_router(&e);
    router.visit("login.example.test:443");
    for args in [
        vec!["get", "--login-url", LOGIN_URL, "--reason", "sign in"],
        vec!["login", LOGIN_URL, "--reason", "sign in"],
        vec!["list", "--sites"],
        vec!["totp", LEASE],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("manager does not support browser_login_v2; upgrade the manager"));
        assert!(out.stdout.is_empty());
    }
    let log = f.log.lock().unwrap();
    assert_eq!(log.len(), 4);
    assert!(log.iter().all(|(method, path, _)| method == "GET" && path == "/v1/health"));
}

#[test]
fn get_login_url_refuses_a_different_grant() {
    let (_f, e, _, _) = login_fixture("https://login.example.test/session?return=%2Fother", "200 Connection established");
    let router = start_router(&e);
    router.visit("login.example.test:443");
    let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr).trim(),
        "error: the manager returned a different login grant than requested"
    );
    assert!(!e.secrets.join("work/Site.password").exists());
    assert_eq!(router_status(&e)["routes"], json!([]));
}

#[test]
fn get_login_url_writes_files_even_when_the_route_does_not_activate() {
    let (_f, e, _, heads) = login_fixture(LOGIN_URL, "403 Forbidden");
    let router = start_router(&e);
    router.visit("login.example.test:443");
    let out = asm(&e, &["get", "--login-url", LOGIN_URL, "--reason", "sign in"], "");
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.trim_end().ends_with("error: the proxy did not activate the route; run asm doctor"), "{stderr}");
    assert!(!stderr.contains("open or reload"), "{stderr}");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(&format!("login: {LOGIN_URL} (single use; routed through asm until 2999-01-01T00:00:00Z)\n")),
        "{stdout}"
    );
    assert!(stdout.contains(&e.secrets.join("work/Site.password").display().to_string()), "{stdout}");
    assert!(e.secrets.join("work/Site.password").exists());
    assert!(heads.lock().unwrap().len() >= 15, "probed every 500 ms for 10 s");
    assert_eq!(router_status(&e)["routes"], json!([]));
}

#[test]
fn proxy_credentials_are_exported_but_never_shown() {
    let (_f, e, proxy_port, _) = login_fixture(LOGIN_URL, "200 Connection established");
    let password = asm_proto::crypto::proxy_password(&sha256(TOKEN.as_bytes()));
    let out = asm(&e, &["proxy-env"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let url = format!("http://h1:{password}@127.0.0.1:{proxy_port}");
    for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        assert!(stdout.contains(&format!("export {name}='{url}'\n")), "{stdout}");
    }
    let out = asm(&e, &["proxy-info"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains(&format!("  http://127.0.0.1:{proxy_port}  (recommended)\n")), "{stdout}");
    assert!(stdout.contains(&format!("  socks5h://127.0.0.1:{proxy_port}  (recommended)\n")), "{stdout}");
    assert!(
        stdout.contains("auth: per-host credentials (added by asm exec, asm proxy-env and the proxy router)\n"),
        "{stdout}"
    );
    assert!(!stdout.contains(&password) && !stdout.contains("h1:"), "{stdout}");
    let out = asm(&e, &["proxy-info", "--json"], "");
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["proxy_auth"], true);
    assert_eq!(j["recommended"], format!("http://127.0.0.1:{proxy_port}"));
}

// ---------------------------------------------------------------------------
// asm browser install|uninstall|status, asm doctor's browser checks
// ---------------------------------------------------------------------------

/// `YYYY, MM, DD` of `now + days`, for certificate validity.
fn ymd(days: i64) -> (i32, u8, u8) {
    let s = asm_proto::time::fmt_unix(unix_now() + days * 86_400);
    (s[0..4].parse().unwrap(), s[5..7].parse().unwrap(), s[8..10].parse().unwrap())
}

fn validity(params: &mut rcgen::CertificateParams, from: i64, to: i64) {
    let (y, m, d) = ymd(from);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = ymd(to);
    params.not_after = rcgen::date_time_ymd(y, m, d);
}

/// A browser CA like the manager's (CN, pathlen 0) that can sign leaves.
struct TestCa {
    pem: String,
    der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Agents Secrets Manager Browser CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        validity(&mut params, -1, 3650);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn sha(&self) -> String {
        asm_proto::crypto::sha256_hex(&self.der)
    }

    /// A server leaf for `host`: (chain DER, key DER). `signed` false gives a
    /// self-signed leaf followed by this CA.
    fn leaf(&self, host: &str, signed: bool) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, host);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut params, -1, 30);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = if signed { params.signed_by(&key, &self.issuer) } else { params.self_signed(&key) }.unwrap();
        (vec![cert.der().to_vec(), self.der.clone()], key.serialize_der())
    }
}

/// A paired manager whose `/proxy-info` carries `browser_ca` (absent when `None`).
fn browser_fixture(browser_ca: Option<String>) -> (Fake, Env, Arc<Mutex<Option<String>>>) {
    let ca = Arc::new(Mutex::new(browser_ca));
    let served = ca.clone();
    let f = start(Arc::new(move |method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]})),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("GET", "/v1/proxy-info") => {
            let mut info = json!({"port":1,"hints":["127.0.0.1"],"ca_sha256":"ab"});
            if let Some(pem) = served.lock().unwrap().clone() {
                info["browser_ca_pem"] = json!(pem);
            }
            (200, info)
        }
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e, ca)
}

/// A Chrome user data directory with `Default/Preferences` = `prefs`.
fn chrome_udd(e: &Env, prefs: &str) -> PathBuf {
    let udd = e.cfg.parent().unwrap().join("udd");
    std::fs::create_dir_all(udd.join("Default")).unwrap();
    std::fs::write(udd.join("Default/Preferences"), prefs).unwrap();
    std::fs::write(udd.join("Last Version"), "158.0.7000.1").unwrap();
    std::fs::canonicalize(udd).unwrap()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn pac_text(port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{\n  if (url.substring(0, 6) == \"https:\" || url.substring(0, 4) == \"wss:\") return \"PROXY 127.0.0.1:{port}\";\n  return \"DIRECT\";\n}}\n"
    )
}

/// The PAC text of a profile's `proxy` pref.
fn profile_pac(profile: &Path) -> Option<String> {
    use base64::Engine;
    let prefs = read_json(&profile.join("Preferences"));
    assert_eq!(prefs["proxy"]["mode"], "pac_script");
    let url = prefs["proxy"]["pac_url"].as_str()?;
    let b64 = url.strip_prefix("data:application/x-ns-proxy-autoconfig;base64,")?;
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64).ok()?).ok()
}

/// `trust_settings` of the CA row `sha` in `<profile>/ServerCertificate`.
fn ca_row(profile: &Path, sha: &str) -> Option<Vec<u8>> {
    let db = rusqlite::Connection::open(profile.join("ServerCertificate")).unwrap();
    db.query_row(
        "SELECT trust_settings FROM certificates WHERE sha256hash_hex = ?1",
        [sha],
        |r| r.get(0),
    )
    .ok()
}

fn install_chrome(e: &Env, udd: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["browser", "install", "chrome", "--no-service", "--user-data-dir", udd.to_str().unwrap()];
    args.extend_from_slice(extra);
    asm(e, &args, "")
}

fn browser_records(e: &Env) -> Vec<Value> {
    match std::fs::read(e.cfg.join("asm/browsers.json")) {
        Ok(b) => serde_json::from_slice::<Value>(&b).unwrap()["records"].as_array().unwrap().clone(),
        Err(_) => Vec::new(),
    }
}

#[test]
fn browser_chrome_install_reinstall_status_doctor_uninstall() {
    let ca = TestCa::new();
    let (f, e, served) = browser_fixture(Some(ca.pem.clone()));
    let udd = chrome_udd(&e, "{}");
    let profile = udd.join("Default");
    let key = profile.to_str().unwrap();

    let out = install_chrome(&e, &udd, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).ends_with("restart the browser once. HTTPS pages need asm's proxy router; asm doctor checks it.\n"),
        "{}",
        text(&out.stdout)
    );
    assert!(text(&out.stdout).contains("start \"asm proxy-router run\" under your supervisor"));
    assert_eq!(ca_row(&profile, &ca.sha()), Some(vec![0x0A, 0x02, 0x08, 0x03]));
    assert_eq!(profile_pac(&profile).unwrap(), pac_text(7418));
    let ca_file = e.cfg.join(format!("asm/browser/ca-{}.crt", &ca.sha()[..8]));
    assert_eq!(std::fs::read_to_string(&ca_file).unwrap(), ca.pem);
    let records = browser_records(&e);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!((r["target"].as_str(), r["key"].as_str()), (Some("chrome"), Some(key)));
    assert_eq!(r["original"], Value::Null);
    assert_eq!(r["ca_shas"], json!([ca.sha()]));
    assert_eq!(r["current_sha"], ca.sha());
    assert_eq!((r["router_port"].as_u64(), r["service"].as_bool()), (Some(7418), Some(false)));
    assert_eq!(r["version"], env!("CARGO_PKG_VERSION"));

    let out = asm(&e, &["browser", "status"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("chrome {key}: installed\nrouter: not running (no service) — fix: start \"asm proxy-router run\" under your supervisor\n")
    );

    // Doctor: the router is down, the browser is fine.
    let out = asm(&e, &["doctor"], "");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("FAIL router: proxy router not running — fix: start \"asm proxy-router run\" under your supervisor\n"),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("ok browser: chrome {key}: installed\n")), "{stdout}");
    assert_eq!(out.status.code(), Some(1));

    // A new manager CA: status calls it stale; reinstall replaces the row.
    let ca2 = TestCa::new();
    *served.lock().unwrap() = Some(ca2.pem.clone());
    let out = asm(&e, &["browser", "status"], "");
    let fix = format!("asm browser install chrome --user-data-dir {} --profile Default --no-service", udd.display());
    assert!(text(&out.stdout).starts_with(&format!("chrome {key}: stale CA — fix: {fix}\n")), "{}", text(&out.stdout));
    let out = asm(&e, &["browser", "status", "--json"], "");
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["browsers"][0]["state"], "stale");
    assert_eq!(j["browsers"][0]["fix"], fix);
    assert_eq!(j["router"]["running"], false);
    let out = install_chrome(&e, &udd, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(ca_row(&profile, &ca.sha()), None);
    assert!(ca_row(&profile, &ca2.sha()).is_some());
    assert_eq!(browser_records(&e)[0]["ca_shas"], json!([ca2.sha()]));
    assert_eq!(browser_records(&e)[0]["original"], Value::Null);

    // A removed pref is reported with the command that fixes it.
    std::fs::write(profile.join("Preferences"), "{\"other\":1}").unwrap();
    let out = asm(&e, &["browser", "status"], "");
    assert!(
        text(&out.stdout).starts_with(&format!(
            "chrome {key}: incomplete the proxy setting in {key}/Preferences is not asm's — fix: {fix}\n"
        )),
        "{}",
        text(&out.stdout)
    );
    let out = install_chrome(&e, &udd, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    // Uninstall: the pref and the row go; the last record takes the saved routes along.
    std::fs::write(e.cfg.join("asm/router-routes.json"), "{\"routes\":[]}").unwrap();
    let out = asm(&e, &["browser", "uninstall", "chrome", "--user-data-dir", udd.to_str().unwrap()], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(read_json(&profile.join("Preferences")), json!({"other": 1}));
    assert_eq!(ca_row(&profile, &ca2.sha()), None);
    assert!(browser_records(&e).is_empty());
    assert!(!e.cfg.join("asm/router-routes.json").exists());
    assert!(!ca_file.exists());
    // Without installs, doctor has no router or browser lines.
    let out = asm(&e, &["doctor"], "");
    assert!(!text(&out.stdout).contains("router:"), "{}", text(&out.stdout));
    assert!(f.log.lock().unwrap().iter().any(|(_, p, _)| p == "/v1/proxy-info"));
}

#[test]
fn browser_chrome_uninstall_restores_only_unchanged_settings() {
    let ca = TestCa::new();
    let (_f, e, _) = browser_fixture(Some(ca.pem.clone()));
    // `system` is not a proxy setup; it comes back on uninstall.
    let udd = chrome_udd(&e, "{\"proxy\":{\"mode\":\"system\"},\"x\":[1]}");
    let profile = udd.join("Default");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(profile.join("Preferences"), std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = install_chrome(&e, &udd, &["--port", "7500"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(profile_pac(&profile).unwrap(), pac_text(7500));
    assert_eq!(std::fs::metadata(profile.join("Preferences")).unwrap().permissions().mode() & 0o777, 0o640);
    assert_eq!(browser_records(&e)[0]["original"], json!({"mode": "system"}));
    // Reinstalling keeps the first original.
    let out = install_chrome(&e, &udd, &["--port", "7500"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(browser_records(&e)[0]["original"], json!({"mode": "system"}));
    let uninstall = || asm(&e, &["browser", "uninstall", "chrome", "--user-data-dir", udd.to_str().unwrap()], "");
    let out = uninstall();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(read_json(&profile.join("Preferences")), json!({"proxy": {"mode": "system"}, "x": [1]}));

    // Changed by the user after install: left as is, with a warning.
    let out = install_chrome(&e, &udd, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let mut prefs = read_json(&profile.join("Preferences"));
    prefs["proxy"] = json!({"mode": "direct"});
    std::fs::write(profile.join("Preferences"), prefs.to_string()).unwrap();
    let out = uninstall();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stderr),
        format!("warning: the proxy setting in {}/Preferences was changed after install; left as is\n", profile.display())
    );
    assert_eq!(read_json(&profile.join("Preferences"))["proxy"], json!({"mode": "direct"}));
    assert_eq!(ca_row(&profile, &ca.sha()), None);
    let out = uninstall();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("is not installed for"), "{}", text(&out.stderr));
}

#[test]
fn browser_chrome_refusals() {
    let (f, e, _) = browser_fixture(Some(TestCa::new().pem));
    // An existing proxy setup.
    let udd = chrome_udd(&e, "{\"proxy\":{\"mode\":\"fixed_servers\",\"server\":\"http://p:3128\"}}");
    let out = install_chrome(&e, &udd, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "error: this browser already uses a proxy (profile proxy setting, mode fixed_servers); asm browser logins can't chain proxies yet\n"
    );
    // A running browser (this test process holds the lock).
    std::fs::write(udd.join("Default/Preferences"), "{}").unwrap();
    let mut host = [0u8; 256];
    // SAFETY: the buffer is valid for its length minus the final NUL.
    assert_eq!(unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len() - 1) }, 0);
    let host = std::ffi::CStr::from_bytes_until_nul(&host).unwrap().to_str().unwrap().to_owned();
    let pid = std::process::id();
    std::os::unix::fs::symlink(format!("{host}-{pid}"), udd.join("SingletonLock")).unwrap();
    let out = install_chrome(&e, &udd, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), format!("error: quit the browser first (pid {pid}), then re-run\n"));
    std::fs::remove_file(udd.join("SingletonLock")).unwrap();
    // Too old.
    std::fs::write(udd.join("Last Version"), "120.0.1.2").unwrap();
    let out = install_chrome(&e, &udd, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("asm browser logins need Chrome 134 or later"), "{}", text(&out.stderr));
    assert!(f.log.lock().unwrap().iter().all(|(_, p, _)| p != "/v1/proxy-info"), "refused before contacting the manager");
    // A manager without browser logins: nothing changes.
    std::fs::write(udd.join("Last Version"), "158.0.1.2").unwrap();
    let (_f2, e2, _) = browser_fixture(None);
    let udd2 = chrome_udd(&e2, "{}");
    let out = install_chrome(&e2, &udd2, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), "error: the manager does not support browser logins; upgrade it\n");
    assert_eq!(read_json(&udd2.join("Default/Preferences")), json!({}));
    assert!(!udd2.join("Default/ServerCertificate").exists());
    assert!(browser_records(&e2).is_empty());
}

#[test]
fn browser_chrome_profile_by_display_name() {
    let ca = TestCa::new();
    let (_f, e, _) = browser_fixture(Some(ca.pem.clone()));
    let udd = chrome_udd(&e, "{}");
    std::fs::create_dir_all(udd.join("Profile 1")).unwrap();
    std::fs::write(udd.join("Profile 1/Preferences"), "{}").unwrap();
    std::fs::write(
        udd.join("Local State"),
        json!({"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 1":{"name":"Work"}}}}).to_string(),
    )
    .unwrap();
    let out = install_chrome(&e, &udd, &["--profile", "Nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        format!("error: no profile \"Nope\" in {}; profiles: Default (Person 1), Profile 1 (Work)\n", udd.display())
    );
    let out = install_chrome(&e, &udd, &["--profile", "Work"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(ca_row(&udd.join("Profile 1"), &ca.sha()).is_some());
    assert_eq!(profile_pac(&udd.join("Profile 1")).unwrap(), pac_text(7418));
    assert_eq!(read_json(&udd.join("Default/Preferences")), json!({}));
    let r = &browser_records(&e)[0];
    assert_eq!(r["key"], udd.join("Profile 1").to_str().unwrap());
    assert_eq!(r["profile"], "Profile 1");
    // Uninstall finds it by directory name too.
    let out = asm(&e, &["browser", "uninstall", "chrome", "--user-data-dir", udd.to_str().unwrap(), "--profile", "Profile 1"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(read_json(&udd.join("Profile 1/Preferences")), json!({}));
}

#[test]
fn browser_openbot_and_t3code_need_user_wide_trust() {
    let (f, e, _) = browser_fixture(Some(TestCa::new().pem));
    let out = asm(&e, &["browser", "install", "openbot"], "");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "OpenBot only trusts the OS certificate store. This adds the asm browser CA to your user's trust store; every app using it will trust certificates the asm manager issues (asm issues them only for sites with an active login grant). Re-run with --trust-user-wide to continue.\n"
    );
    if cfg!(target_os = "macos") {
        let out = asm(&e, &["browser", "install", "t3code"], "");
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(
            text(&out.stderr),
            "T3 Code's browser on macOS only trusts the OS certificate store. This adds the asm browser CA to your user's trust store; every app using it will trust certificates the asm manager issues (asm issues them only for sites with an active login grant). Re-run with --trust-user-wide to continue.\n"
        );
    }
    assert!(f.log.lock().unwrap().is_empty());
    assert!(browser_records(&e).is_empty());
}

/// `certutil` on this machine's `PATH`.
fn certutil_available() -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("certutil").is_file()))
}

/// Linux: the full t3code install against a fake `T3CODE_HOME` (needs `certutil`).
#[test]
fn browser_t3code_linux() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let ca = TestCa::new();
    let (_f, e, _) = browser_fixture(Some(ca.pem.clone()));
    let base = e.cfg.parent().unwrap().join("t3");
    let version = base.join("tools/chrome-headless-shell/linux64/157.0.1");
    std::fs::create_dir_all(&version).unwrap();
    std::fs::write(version.join("chrome-headless-shell"), "#!/bin/sh\necho real \"$@\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(version.join("chrome-headless-shell"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    let vars = [("T3CODE_HOME", base.to_str().unwrap()), ("PATH", path.as_str()), ("ASM_NO_REAPER", "1")];
    let install = || asm_env(&e, &["browser", "install", "t3code", "--no-service"], "", &vars);
    if !certutil_available() {
        let out = install();
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            text(&out.stderr),
            "error: install NSS tools: sudo apt install libnss3-tools (Debian/Ubuntu) or sudo dnf install nss-tools (Fedora)\n"
        );
        return;
    }
    std::fs::write(base.join("service.env"), "HTTPS_PROXY=http://p:3128\n").unwrap();
    let out = install();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("sets HTTPS_PROXY); asm browser logins can't chain proxies yet"));
    std::fs::remove_file(base.join("service.env")).unwrap();
    let out = install();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).ends_with(
        "takes effect the next time T3 starts its browser (idle browsers close after 5 minutes; restart T3 to apply now)\n"
    ));
    let data = e.cfg.join("asm/browser/t3code");
    let wrapper = std::fs::read_to_string(version.join("chrome-headless-shell")).unwrap();
    assert!(wrapper.contains(&format!("export XDG_DATA_HOME='{}'\n", data.display())), "{wrapper}");
    assert_eq!(std::fs::read_link(data.join("home/.pki/nssdb")).unwrap(), data.join("pki/nssdb"));
    let listed = Command::new("certutil")
        .args(["-L", "-d", &format!("sql:{}", data.join("pki/nssdb").display())])
        .output()
        .unwrap();
    assert!(text(&listed.stdout).contains(&format!("asm browser CA {}", &ca.sha()[..8])));
    let out = asm_env(&e, &["browser", "status"], "", &vars);
    assert!(text(&out.stdout).starts_with(&format!("t3code {}: installed\n", base.display())), "{}", text(&out.stdout));
    // T3 downloads a new browser version.
    let newer = base.join("tools/chrome-headless-shell/linux64/158.0.2");
    std::fs::create_dir_all(&newer).unwrap();
    std::fs::write(newer.join("chrome-headless-shell"), "#!/bin/sh\n").unwrap();
    let out = asm_env(&e, &["browser", "status"], "", &vars);
    assert!(
        text(&out.stdout).starts_with(&format!(
            "t3code {}: T3 updated its browser to 158.0.2 — fix: asm browser install t3code --no-service\n",
            base.display()
        )),
        "{}",
        text(&out.stdout)
    );
    let out = asm_env(&e, &["browser", "uninstall", "t3code"], "", &vars);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(std::fs::read_to_string(version.join("chrome-headless-shell")).unwrap(), "#!/bin/sh\necho real \"$@\"\n");
    assert!(!data.exists());
    assert!(!base.join("tools/chrome-headless-shell/asm-real").exists());
}

// ---------------------------------------------------------------------------
// Real Chrome (gated): ASM_TEST_CHROME=<path> cargo test -p asm-cli browser_install_chrome
// ---------------------------------------------------------------------------

/// An HTTPS server presenting `chain` that answers every request with `body`.
fn tls_page(chain: Vec<Vec<u8>>, key: Vec<u8>, body: &'static str) -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                chain.into_iter().map(CertificateDer::from).collect(),
                PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let Ok(conn) = ServerConnection::new(config) else { return };
                let mut tls = StreamOwned::new(conn, stream);
                serve_page(&mut tls, body);
            });
        }
    });
    port
}

/// Read one request head and answer it with an HTML page holding `body`.
fn serve_page(s: &mut (impl Read + Write), body: &str) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let html = format!("<html><body>{body}</body></html>");
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    let _ = s.flush();
}

fn http_page(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_page(&mut stream, body));
        }
    });
    port
}

/// A stand-in for the proxy router on `listener`: records each request line and
/// tunnels every CONNECT to 127.0.0.1:`upstream`.
fn fake_router(listener: TcpListener, upstream: Arc<std::sync::atomic::AtomicU16>) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (log, upstream) = (log.clone(), upstream.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut first = String::new();
                if reader.read_line(&mut first).unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                log.lock().unwrap().push(first.trim_end().to_owned());
                let mut client = reader.into_inner();
                if !first.starts_with("CONNECT ") {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return;
                }
                let port = upstream.load(std::sync::atomic::Ordering::SeqCst);
                let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return };
                let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                let (mut c2, mut u2) = (client.try_clone().unwrap(), up.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut u2);
                    let _ = u2.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut up, &mut client);
                let _ = client.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    seen
}

/// `chrome --headless=new --dump-dom <url>` on the profile in `udd` (60 s at most).
fn chrome_dump(chrome: &Path, udd: &Path, rules: &str, url: &str) -> String {
    let mut child = Command::new(chrome)
        .args([
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--use-mock-keychain",
            "--password-store=basic",
            "--disable-gpu",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable",
        ])
        .arg(format!("--user-data-dir={}", udd.display()))
        .arg(format!("--host-resolver-rules={rules}"))
        .args(["--dump-dom", url])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.wait();
    reader.join().unwrap()
}

#[test]
fn browser_install_chrome() {
    let Some(chrome) = std::env::var_os("ASM_TEST_CHROME").map(PathBuf::from) else {
        eprintln!("skipped: set ASM_TEST_CHROME to a Chrome executable");
        return;
    };
    // 1–2. Install into a temporary profile; the CA row and the PAC are as specified.
    let ca = TestCa::new();
    let (_f, e, _) = browser_fixture(Some(ca.pem.clone()));
    let udd = chrome_udd(&e, "{}");
    let profile = udd.join("Default");
    let router = TcpListener::bind("127.0.0.1:0").unwrap();
    let router_port = router.local_addr().unwrap().port();
    let out = install_chrome(&e, &udd, &["--port", &router_port.to_string()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(ca_row(&profile, &ca.sha()).is_some());
    assert_eq!(profile_pac(&profile).unwrap(), pac_text(router_port));

    // 3. HTTPS goes through the router to a server with a test-CA leaf: trusted.
    let (chain, key) = ca.leaf("example.test", true);
    let trusted = tls_page(chain, key, "TRUST-OK");
    let (chain, key) = ca.leaf("example.test", false);
    let untrusted = tls_page(chain, key, "UNTRUSTED-LOADED");
    let direct = http_page("HTTP-DIRECT");
    let upstream = Arc::new(std::sync::atomic::AtomicU16::new(trusted));
    let seen = fake_router(router, upstream.clone());
    let rules = format!("MAP example.test:443 127.0.0.1:{trusted}, MAP example.test:80 127.0.0.1:{direct}");
    let dom = chrome_dump(&chrome, &udd, &rules, "https://example.test/");
    assert!(dom.contains("TRUST-OK"), "{dom}");
    let ours = |seen: &Mutex<Vec<String>>| {
        seen.lock().unwrap().iter().filter(|l| l.contains("example.test")).cloned().collect::<Vec<_>>()
    };
    assert!(ours(&seen).iter().any(|l| l.starts_with("CONNECT example.test:443 ")), "{:?}", seen.lock().unwrap());

    // 4. http:// goes direct; a chain the test CA did not sign does not load.
    let before = ours(&seen).len();
    let dom = chrome_dump(&chrome, &udd, &rules, "http://example.test/");
    assert!(dom.contains("HTTP-DIRECT"), "{dom}");
    assert_eq!(ours(&seen).len(), before, "{:?}", seen.lock().unwrap());
    upstream.store(untrusted, std::sync::atomic::Ordering::SeqCst);
    let dom = chrome_dump(&chrome, &udd, &rules, "https://example.test/");
    assert!(!dom.contains("UNTRUSTED-LOADED"), "{dom}");
    assert!(ours(&seen).len() > before, "the untrusted page went through the router too");

    // 5. Reinstall, then uninstall: the proxy pref is gone.
    let out = install_chrome(&e, &udd, &["--port", &router_port.to_string()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = asm(&e, &["browser", "uninstall", "chrome", "--user-data-dir", udd.to_str().unwrap()], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(read_json(&profile.join("Preferences")).get("proxy").is_none());
    assert_eq!(ca_row(&profile, &ca.sha()), None);
}

// ---------------------------------------------------------------------------
// asm login
// ---------------------------------------------------------------------------

const STORAGE_STATE: &str = r#"{"cookies":[{"name":"sid","value":"s3cr3t","domain":"the-internet.example.test","path":"/","expires":-1,"httpOnly":true,"secure":true,"sameSite":"Lax"},{"name":"pref","value":"1","domain":".example.test","path":"/","expires":-1,"httpOnly":false,"secure":true,"sameSite":"Lax"}],"origins":[{"origin":"https://the-internet.example.test","localStorage":[]}]}"#;

/// A manager approving `asm login` at once with `result`.
fn login_broker(result: Value) -> (Fake, Env) {
    let f = start(Arc::new(move |method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]})),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("POST", "/v1/requests") => (
            200,
            json!({"request_id":REQ,"kind":"login","status":"approved","deny_reason":null,"result":result.clone()}),
        ),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e)
}

fn storage_state_result(mode: &str, files: Value) -> Value {
    json!({"lease_id":LEASE,"mode":mode,"hosts":[],"expires_at":"2999-01-01T00:00:00Z","files":files})
}

#[test]
fn login_hands_over_the_storage_state() {
    let (f, e) = login_broker(storage_state_result(
        "raw",
        json!([{"field":"storage-state","relative_path":"work/Site.storage-state","content":STORAGE_STATE,"substituted":false}]),
    ));
    let out = asm(
        &e,
        &["login", "https://the-internet.example.test/login", "--reason", "broker test", "--fill-origin", "https://SSO.example.test:443", "--fill-origin", "https://sso.example.test"],
        "",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let path = e.secrets.join("work/Site.storage-state");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), STORAGE_STATE);
    assert_eq!(
        text(&out.stdout),
        format!(
            "storage state: {}\ncookie domains: the-internet.example.test, .example.test\nexpires: 2999-01-01T00:00:00Z\n",
            path.display()
        )
    );
    let p = path.display();
    assert!(
        text(&out.stderr).ends_with(&format!(
            "load it with your browser tool: omp tab.loadState({p}), Playwright MCP --storage-state {p}\n"
        )),
        "{}",
        text(&out.stderr)
    );
    let body = &posted(&f)[0];
    assert_eq!(
        *body,
        json!({"kind":"browser_login","mode":"broker","url":"https://the-internet.example.test/login","reason":"broker test",
            "extra_fill_origins":["https://sso.example.test"],"agent":"test-agent","client_capabilities":["browser_login_v2"]})
    );

    let out = asm(&e, &["login", "https://the-internet.example.test/login", "--account", "person@example.test", "--reason", "again", "--json"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let j: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["path"], path.to_str().unwrap());
    assert_eq!(j["cookie_domains"], json!(["the-internet.example.test", ".example.test"]));
    assert_eq!(j["lease_id"], LEASE);
    assert_eq!(posted(&f)[1]["account"], "person@example.test");
    assert!(!f.log.lock().unwrap().iter().any(|(_, path, _)| path == "/v1/secrets"));
}

#[test]
fn login_refuses_other_result_shapes() {
    let state = |field: &str| json!({"field":field,"relative_path":format!("work/Site.{field}"),"content":STORAGE_STATE,"substituted":false});
    let mut non_expiring = storage_state_result("raw", json!([state("storage-state")]));
    non_expiring["expires_at"] = Value::Null;
    for result in [
        storage_state_result("sentinel", json!([state("storage-state")])),
        storage_state_result("raw", json!([state("password")])),
        storage_state_result("raw", json!([state("storage-state"), state("username")])),
        storage_state_result("raw", json!([])),
        non_expiring,
    ] {
        let (_f, e) = login_broker(result.clone());
        let out = asm(&e, &["login", "https://the-internet.example.test/login", "--reason", "r"], "");
        assert_eq!(out.status.code(), Some(1), "{result}");
        assert_eq!(
            text(&out.stderr),
            "error: the manager did not return a browser storage state (expected one raw storage-state file)\n",
            "{result}"
        );
        assert!(!e.secrets.join("work").exists(), "{result}");
    }
    let (_f, e) = login_broker(storage_state_result(
        "raw",
        json!([{"field":"storage-state","relative_path":"work/Site.storage-state","content":"{\"nope\":1}","substituted":false}]),
    ));
    let out = asm(&e, &["login", "https://the-internet.example.test/login", "--reason", "r"], "");
    assert_eq!(text(&out.stderr), "error: the manager sent an invalid storage state\n");
}

#[test]
fn broker_rejects_a_polled_result_for_the_other_browser_mode() {
    let f = start(Arc::new(|method, path, _body| match (method, path) {
        ("GET", "/v1/health") => (200, json!({"name":"asm-manager","version":"0.8.0","capabilities":["browser_login_v2"]})),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("POST", "/v1/requests") => (202, json!({"request_id":REQ,"kind":"login","status":"pending"})),
        ("GET", path) if path.starts_with("/v1/requests/") => (
            200,
            json!({"request_id":REQ,"kind":"get","status":"approved","result":
                storage_state_result("raw", json!([{"field":"storage-state","relative_path":"work/Site.storage-state",
                    "content":STORAGE_STATE,"substituted":false}]))
            }),
        ),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    let out = asm(&e, &["login", LOGIN_URL, "--reason", "sign in"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("different browser request kind"));
    assert!(!e.secrets.join("work").exists());
    assert_eq!(posted(&f).len(), 1);
}

#[test]
fn login_validates_arguments_before_posting() {
    let (f, e) = login_broker(Value::Null);
    let six: Vec<String> = (0..6).map(|i| format!("https://s{i}.example.test")).collect();
    let mut many = vec!["login", "https://a.example.test/", "--reason", "r"];
    for o in &six {
        many.extend(["--fill-origin", o.as_str()]);
    }
    for (args, message) in [
        (vec!["login", "http://a.example.test/", "--reason", "r"], "invalid: URL must start with https://"),
        (vec!["login", "https://a.example.test/", "--reason", "r", "--fill-origin", "https://b.example.test/login"], "invalid: --fill-origin \"https://b.example.test/login\" must be https://host[:port]"),
        (vec!["login", "https://a.example.test/", "--reason", "r", "--fill-origin", "http://b.example.test"], "invalid: --fill-origin \"http://b.example.test\" must be https://host[:port]"),
        (vec!["login", "https://a.example.test/", "--reason", "r", "--account", " "], "invalid: account must be 1–320 characters without surrounding whitespace"),
        (many, "invalid: at most 5 --fill-origin values"),
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&out.stderr).trim(), message, "{args:?}");
    }
    let out = asm(&e, &["login", "https://a.example.test/", "--reason", "r", "--site", "https://a.example.test"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("unexpected argument '--site'"));
    let out = asm(&e, &["login", "https://a.example.test/"], "");
    assert_eq!(text(&out.stderr).trim(), "invalid: asm login needs --reason TEXT");
    assert_eq!(out.status.code(), Some(2));
    for args in [
        vec!["login", "https://a.example.test/", "work/Site", "--reason", "r"],
        vec!["login", "https://a.example.test/", "work/Site"],
    ] {
        let out = asm(&e, &args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("no longer accepts a positional ITEM"));
        assert!(text(&out.stderr).contains("--account USERNAME_OR_EMAIL"));
    }
    assert!(f.log.lock().unwrap().is_empty());
}

// --- asm gh -------------------------------------------------------------------------

const GH_LEASE: &str = "44444444-2222-4333-8444-555555555555";
const GH_TOKEN_VALUE: &str = "ghs_fixture_token";

/// A manager for `asm gh`. Each POST /requests takes the next outcome (the last one
/// repeats): "approve"; "approve-write" (grants pull_requests=write besides the request);
/// "approve-short" (a token with five minutes left); "pending" (the next poll approves);
/// "deny".
fn gh_fixture(outcomes: &[&'static str]) -> (Fake, Env) {
    let queue = Mutex::new(outcomes.to_vec());
    let approved = Mutex::new(Value::Null);
    let f = start(Arc::new(move |method, path, body| match (method, path) {
        ("GET", "/v1/health") => (
            200,
            json!({"name":"asm-manager","version":"0.1.0","capabilities":["generated_credentials_v1","secret_fields_v1",
                "github_explicit_scope_v1","operator_selected_grant_v1","broader_lease_reuse_v1"]}),
        ),
        ("GET", "/v1/secrets") => (200, generator_catalog()),
        ("GET", "/v1/leases") => (200, json!({"leases":[]})),
        ("POST", "/v1/requests") => {
            let outcome = {
                let mut q = queue.lock().unwrap();
                if q.len() > 1 { q.remove(0) } else { q[0] }
            };
            let scope = &body["generation"]["scope"];
            let mut permissions = scope["permissions"].clone();
            if outcome == "approve-write" {
                permissions["pull_requests"] = json!("write");
            }
            let repositories: Vec<Value> = scope["repositories"].as_array().unwrap().iter().enumerate()
                .map(|(i, name)| json!({"id": i + 1, "full_name": name}))
                .collect();
            let left = if outcome == "approve-short" { 300 } else { 3600 };
            let result = json!({"lease_id":GH_LEASE,"mode":"raw","hosts":[],"expires_at":"2999-01-01T00:00:00Z",
                "files":[{"field":"value","relative_path":"GH_TOKEN","content":GH_TOKEN_VALUE,"substituted":false}],
                "generation":{"generator_id":"app-a","generator_revision":1,"grant":{"provider":"github_app","scope":{
                    "installation_id":7,"repositories":repositories,"permissions":permissions}}},
                "credential_expires_at":asm_proto::time::fmt_unix(unix_now() + left),"credential_version":1,
                "generator_name":"release-bot"});
            match outcome {
                "pending" => {
                    *approved.lock().unwrap() = result;
                    (202, json!({"request_id":REQ,"kind":"get","status":"pending","deny_reason":null,"result":null,
                        "expires_at":asm_proto::time::fmt_unix(unix_now() + 600),"pending_lifetime_secs":600}))
                }
                "deny" => (200, json!({"request_id":REQ,"kind":"get","status":"denied","deny_reason":"not now","result":null})),
                _ => (200, json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":result})),
            }
        }
        ("GET", p) if p.starts_with(&format!("/v1/requests/{REQ}?wait=")) => (
            200,
            json!({"request_id":REQ,"kind":"get","status":"approved","deny_reason":null,"result":approved.lock().unwrap().clone()}),
        ),
        _ => (404, json!({"error":{"code":"not_found","message":format!("{method} {path}")}})),
    }));
    let e = env();
    write_host_json(&e, &f);
    (f, e)
}

/// `gh.json` with `acme/web` and the default read permissions.
fn write_gh_config(e: &Env) {
    std::fs::create_dir_all(e.cfg.join("asm")).unwrap();
    let config = json!({"default_owner":"acme","owners":{"acme":{"source":"GH_TOKEN","repositories":["acme/web"],
        "permissions":{"metadata":"read","pull_requests":"read"}}}});
    std::fs::write(e.cfg.join("asm/gh.json"), config.to_string()).unwrap();
}

/// A stand-in for the real GitHub CLI that prints its arguments and token.
fn fake_gh(e: &Env) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = e.cfg.parent().unwrap().join("real-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(&gh, "#!/bin/sh\nprintf 'argv:%s\\n' \"$*\"\nprintf 'token:%s\\n' \"${GH_TOKEN:-none}\"\n[ \"$GH_TOKEN\" = \"$GITHUB_TOKEN\" ] && echo same\n").unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn gh_shim(e: &Env, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut all = vec!["gh", "shim", "--"];
    all.extend_from_slice(args);
    let mut env = vec![("ASM_NO_REAPER", "1")];
    env.extend_from_slice(vars);
    asm_env(e, &all, "", &env)
}

#[test]
fn gh_repo_add_requests_exactly_the_saved_scope_without_reuse_or_edits() {
    let (f, e) = gh_fixture(&["approve"]);
    let out = asm(&e, &["gh", "repo", "add", "Acme/Web"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("added acme/web"), "{}", text(&out.stdout));
    let read = json!({"actions":"read","checks":"read","contents":"read","issues":"read","metadata":"read",
        "pull_requests":"read","statuses":"read"});
    let sent = posted(&f);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["name"], "GH_TOKEN");
    assert_eq!(sent[0]["agent"], "asm-gh");
    assert_eq!(sent[0]["raw"], true);
    assert!(sent[0]["lease_id"].is_null());
    assert_eq!(sent[0]["new_lease"], false);
    // Neither broader-lease reuse nor operator edits: exactly this scope, or a prompt.
    assert_eq!(sent[0]["client_capabilities"], json!(["generated_credentials_v1", "github_explicit_scope_v1"]));
    assert_eq!(sent[0]["generation"], json!({"provider":"github_app","scope":{"repositories":["acme/web"],"permissions":read}}));
    let config: Value = serde_json::from_slice(&std::fs::read(e.cfg.join("asm/gh.json")).unwrap()).unwrap();
    assert_eq!(config["default_owner"], "acme");
    assert_eq!(config["owners"]["acme"]["repositories"], json!(["acme/web"]));

    let out = asm(&e, &["gh", "repo", "add", "acme/api", "--permissions", "pull_requests=write"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let mut widened = read.clone();
    widened["pull_requests"] = json!("write");
    assert_eq!(posted(&f)[1]["generation"], json!({"provider":"github_app","scope":{
        "repositories":["acme/api","acme/web"],"permissions":widened}}));
    // The same owner keeps one reason and agent, so its requests share one approval.
    assert_eq!(posted(&f)[1]["reason"], sent[0]["reason"]);
}

#[test]
fn gh_repo_add_saves_nothing_when_the_approval_differs_from_the_request() {
    let (f, e) = gh_fixture(&["approve-write"]);
    let out = asm(&e, &["gh", "repo", "add", "acme/web"], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("did not approve the exact requested grant"), "{}", text(&out.stderr));
    assert_eq!(posted(&f).len(), 1);
    assert!(!e.cfg.join("asm/gh.json").exists());
}

#[test]
fn gh_shim_auth_token_never_waits_and_prints_only_the_token() {
    let (f, e) = gh_fixture(&["pending", "approve"]);
    write_gh_config(&e);
    let started = Instant::now();
    let out = gh_shim(&e, &["auth", "token", "--hostname", "github.com"], &[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(out.stdout.is_empty());
    assert!(text(&out.stderr).contains("waiting for the operator's approval"), "{}", text(&out.stderr));
    // T3 Code polls: a pending request is reported at once, never polled.
    assert!(!f.log.lock().unwrap().iter().any(|(_, p, _)| p.starts_with("/v1/requests/")));
    let out = gh_shim(&e, &["auth", "token", "--hostname", "github.com", "--user", "ACME"], &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{GH_TOKEN_VALUE}\n"));
    let sent = posted(&f);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1]["generation"]["scope"]["repositories"], json!(["acme/web"]));
}

#[test]
fn gh_shim_adds_tokens_to_github_commands_and_passes_the_rest_through() {
    let (f, e) = gh_fixture(&["approve"]);
    let bin = fake_gh(&e);
    let path = bin.to_str().unwrap();
    // Without a configuration everything passes through untouched.
    let out = gh_shim(&e, &["pr", "list"], &[("PATH", path)]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "argv:pr list\ntoken:none\nsame\n");
    write_gh_config(&e);
    for local in [vec!["--version"], vec!["config", "get", "http_unix_socket"], vec!["auth", "login"], vec!["pr", "list", "--help"]] {
        let out = gh_shim(&e, &local, &[("PATH", path)]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), format!("argv:{}\ntoken:none\nsame\n", local.join(" ")));
    }
    assert!(posted(&f).is_empty(), "local commands must not ask the manager");
    let out = gh_shim(&e, &["pr", "view", "616", "-R", "acme/web"], &[("PATH", path)]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("argv:pr view 616 -R acme/web\ntoken:{GH_TOKEN_VALUE}\nsame\n"));
    assert_eq!(posted(&f).len(), 1);
    // An explicit token (asm exec … GH_TOKEN -- gh …) is never replaced.
    let out = gh_shim(&e, &["pr", "merge"], &[("PATH", path), ("GH_TOKEN", "explicit"), ("GITHUB_TOKEN", "explicit")]);
    assert_eq!(text(&out.stdout), "argv:pr merge\ntoken:explicit\nsame\n");
    assert_eq!(posted(&f).len(), 1);
    // Without a real gh besides the shim, the shim says so.
    let out = gh_shim(&e, &["--version"], &[("PATH", "/nonexistent")]);
    assert_eq!(out.status.code(), Some(127));
    assert!(text(&out.stderr).contains("no GitHub CLI (gh) on PATH"));
}

#[test]
fn gh_shim_refuses_other_grants_and_tokens_that_expire_too_soon() {
    for (outcome, message) in [
        ("approve-write", "did not approve the exact requested grant"),
        ("approve-short", "expires too soon"),
    ] {
        let (f, e) = gh_fixture(&[outcome]);
        write_gh_config(&e);
        let out = gh_shim(&e, &["auth", "token"], &[]);
        assert_eq!(out.status.code(), Some(1), "{outcome}: {}", text(&out.stderr));
        assert!(out.stdout.is_empty(), "{outcome}");
        assert!(text(&out.stderr).contains(message), "{outcome}: {}", text(&out.stderr));
        assert_eq!(posted(&f).len(), 1);
    }
}

#[test]
fn gh_shim_backs_off_after_a_denial_until_repo_add() {
    let (f, e) = gh_fixture(&["deny", "approve"]);
    write_gh_config(&e);
    let out = gh_shim(&e, &["auth", "token"], &[]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let out = gh_shim(&e, &["auth", "token"], &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("the operator denied GitHub access for acme"), "{}", text(&out.stderr));
    assert_eq!(posted(&f).len(), 1, "no new prompt while backing off");
    let out = asm(&e, &["gh", "repo", "add", "acme/web"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = gh_shim(&e, &["auth", "token"], &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{GH_TOKEN_VALUE}\n"));
}

/// A private directory on a tmpfs (the token cache refuses disk-backed directories).
#[cfg(target_os = "linux")]
fn tmpfs_dir() -> Option<tempfile::TempDir> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    mounts.lines().any(|l| l.split_whitespace().nth(1) == Some("/dev/shm") && l.contains(" tmpfs "))
        .then(|| tempfile::tempdir_in("/dev/shm").ok())
        .flatten()
}

#[cfg(target_os = "linux")]
#[test]
fn gh_shim_caches_tokens_on_tmpfs_and_uses_them_while_the_manager_is_away() {
    use std::os::unix::fs::PermissionsExt;
    let Some(runtime) = tmpfs_dir() else {
        eprintln!("skipped: no tmpfs at /dev/shm");
        return;
    };
    let rt = runtime.path().to_str().unwrap();
    let (f, e) = gh_fixture(&["approve"]);
    write_gh_config(&e);
    for _ in 0..2 {
        let out = gh_shim(&e, &["auth", "token"], &[("XDG_RUNTIME_DIR", rt)]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), format!("{GH_TOKEN_VALUE}\n"));
    }
    assert_eq!(posted(&f).len(), 1, "a token confirmed within a minute is reused");
    let cached = runtime.path().join("asm/gh/acme.json");
    assert_eq!(std::fs::metadata(&cached).unwrap().permissions().mode() & 0o777, 0o600);
    // Older than a minute and the manager is unreachable: the cached token still serves.
    let mut entry: Value = serde_json::from_slice(&std::fs::read(&cached).unwrap()).unwrap();
    entry["checked_at"] = json!(unix_now() - 120);
    std::fs::write(&cached, entry.to_string()).unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut host: Value = serde_json::from_slice(&std::fs::read(e.cfg.join("asm/host.json")).unwrap()).unwrap();
    host["manager_url"] = json!(format!("https://127.0.0.1:{closed}"));
    std::fs::write(e.cfg.join("asm/host.json"), host.to_string()).unwrap();
    let out = gh_shim(&e, &["auth", "token"], &[("XDG_RUNTIME_DIR", rt)]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{GH_TOKEN_VALUE}\n"));
    // A token too close to expiry is never served from the cache.
    entry["expires_at"] = json!(unix_now() + 60);
    std::fs::write(&cached, entry.to_string()).unwrap();
    let out = gh_shim(&e, &["auth", "token"], &[("XDG_RUNTIME_DIR", rt)]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
}

#[test]
fn gh_install_writes_an_updatable_shim_and_uninstall_removes_only_it() {
    use std::os::unix::fs::PermissionsExt;
    let (_f, e) = gh_fixture(&["approve"]);
    let real = fake_gh(&e);
    let bin = e.cfg.parent().unwrap().join("bin");
    let dir = bin.to_str().unwrap();
    // A login shell that answers `command -v gh` with $FOUND (T3 Code reads PATH this way).
    let shell = e.cfg.parent().unwrap().join("login-shell");
    std::fs::write(&shell, "#!/bin/sh\necho \"$FOUND\"\n").unwrap();
    std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim_path = format!("{dir}/gh");
    let install = |dir: &str, extra: &[&str], found: &str| {
        let mut args = vec!["gh", "install", "--dir", dir];
        args.extend_from_slice(extra);
        asm_env(&e, &args, "", &[("SHELL", shell.to_str().unwrap()), ("FOUND", found)])
    };
    let out = install(dir, &[], &shim_path);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with(&format!("installed: {shim_path}")), "{}", text(&out.stdout));
    assert!(text(&out.stdout).contains("login shell: finds the shim first"), "{}", text(&out.stdout));
    let shim = bin.join("gh");
    let script = std::fs::read_to_string(&shim).unwrap();
    assert!(script.starts_with("#!/bin/sh\n# asm gh shim "), "{script}");
    assert!(script.ends_with(" gh shim -- \"$@\"\n"), "{script}");
    assert_eq!(std::fs::metadata(&shim).unwrap().permissions().mode() & 0o777, 0o755);
    let out = install(dir, &[], "/usr/bin/gh");
    assert!(text(&out.stdout).starts_with("up to date:"), "{}", text(&out.stdout));
    assert!(text(&out.stderr).contains("your login shell finds gh at /usr/bin/gh before the shim"), "{}", text(&out.stderr));
    // The installed script runs the real gh found after it on PATH.
    write_gh_config(&e);
    let out = Command::new(&shim)
        .arg("--version")
        .env_clear()
        .env("HOME", e.cfg.parent().unwrap())
        .env("XDG_CONFIG_HOME", &e.cfg)
        .env("PATH", format!("{dir}:{}", real.display()))
        .output()
        .unwrap();
    assert_eq!(text(&out.stdout), "argv:--version\ntoken:none\nsame\n", "{}", text(&out.stderr));
    // Someone else's gh is replaced only with --force, and a program never.
    let mine = e.cfg.parent().unwrap().join("mine");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::write(mine.join("gh"), "#!/bin/sh\necho mine\n").unwrap();
    let out = install(mine.to_str().unwrap(), &[], "");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert_eq!(std::fs::read_to_string(mine.join("gh")).unwrap(), "#!/bin/sh\necho mine\n");
    let out = install(mine.to_str().unwrap(), &["--force"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    std::fs::write(mine.join("gh"), b"\x7fELF binary").unwrap();
    let out = install(mine.to_str().unwrap(), &["--force"], "");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert_eq!(std::fs::read(mine.join("gh")).unwrap(), b"\x7fELF binary");
    let out = asm(&e, &["gh", "uninstall", "--dir", dir], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!shim.exists());
    assert!(!e.cfg.join("asm/gh.json").exists());
    let out = asm(&e, &["gh", "uninstall", "--dir", mine.to_str().unwrap()], "");
    assert!(text(&out.stdout).contains("left alone (not installed by asm gh)"), "{}", text(&out.stdout));
    assert!(mine.join("gh").exists());
}

// ---- SSH leases ----

const SSH_TARGET_ID: &str = "0123abcd";
const SSH_LEASE2: &str = "22222222-2222-4333-8444-555555555555";
const SSH_HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const SSH_EXPIRES: &str = "2999-01-01T00:00:00Z";
const SSH_EXTENDED: &str = "2999-02-01T00:00:00Z";
const HOSTS_CONF_HEADER: &str = "# Managed by asm: rewritten whenever this machine's SSH leases change. Don't edit.\n# `asm ssh install` includes it from ~/.ssh/config; `asm ssh uninstall` stops that.\n";
const INSTALL_MARKER: &str = "# Added by asm ssh install; remove with asm ssh uninstall.";

/// A stand-in certificate blob; the CLI never parses beyond the base64.
fn ssh_cert_blob_with(fill: u8) -> Vec<u8> {
    let mut blob = Vec::new();
    asm_proto::ssh::put_string(&mut blob, b"ssh-ed25519-cert-v01@openssh.com");
    asm_proto::ssh::put_string(&mut blob, &[fill; 32]);
    blob
}

fn ssh_cert_blob() -> Vec<u8> {
    ssh_cert_blob_with(7)
}

fn ssh_cert_line_with(fill: u8) -> String {
    format!(
        "ssh-ed25519-cert-v01@openssh.com {} asm-lease-{LEASE}",
        asm_proto::ssh::b64_encode(&ssh_cert_blob_with(fill))
    )
}

fn ssh_cert_line() -> String {
    ssh_cert_line_with(7)
}

fn ssh_signature_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    asm_proto::ssh::put_string(&mut blob, b"ssh-ed25519");
    asm_proto::ssh::put_string(&mut blob, &[9; 64]);
    blob
}

/// Target `name` (id `tid`) with `access` (`privileged`, `restricted` or `user`), the
/// login it needs and a certificate of `fill`.
fn ssh_target(name: &str, tid: &str, access: &str, fill: u8) -> Value {
    let login = if access == "restricted" { "asm-ops" } else { "asm-priv" };
    json!({"name":name,"target_id":tid,"login":login,"hostname":format!("{name}.example.com"),
        "port":2222,"host_keys":[SSH_HOST_KEY],"access":access,"certificate":ssh_cert_line_with(fill)})
}

fn ssh_lease(lease_id: &str, expires_at: &str, targets: Vec<Value>) -> Value {
    json!({"lease_id":lease_id,"expires_at":expires_at,"targets":targets})
}

/// A privileged lease on t1.
fn ssh_result(expires_at: &str) -> Value {
    ssh_lease(LEASE, expires_at, vec![ssh_target("t1", SSH_TARGET_ID, "privileged", 7)])
}

/// A restricted lease on t1 that may read the logs of nginx.service.
fn ssh_restricted_result(expires_at: &str) -> Value {
    let mut t = ssh_target("t1", SSH_TARGET_ID, "restricted", 7);
    t["grants"] = json!(["logs:nginx.service"]);
    ssh_lease(LEASE, expires_at, vec![t])
}

/// A lease on t1 as `user`.
fn ssh_user_result(expires_at: &str, user: &str) -> Value {
    let mut t = ssh_target("t1", SSH_TARGET_ID, "user", 7);
    t["user"] = json!(user);
    ssh_lease(LEASE, expires_at, vec![t])
}

/// A lease on t1 (privileged, certificate 1), t2 (restricted, certificate 2) and t3 (as
/// deploy, certificate 3), each certificate's fill plus `bump`; the operator denied t4.
fn ssh_mixed_result(expires_at: &str, bump: u8) -> Value {
    let mut t2 = ssh_target("t2", "0000000b", "restricted", 2 + bump);
    t2["grants"] = json!(["logs:web.service", "read:/etc/nginx/nginx.conf", "reload:web.service"]);
    let mut t3 = ssh_target("t3", "0000000c", "user", 3 + bump);
    t3["user"] = json!("deploy");
    ssh_lease(LEASE, expires_at, vec![t3, ssh_target("t1", "0000000a", "privileged", 1 + bump), t2])
}

/// What the fake manager answers; a test may change it between commands.
struct SshScript {
    /// The result of an `ssh` request.
    result: Mutex<Value>,
    /// The result of an `ssh_extend` request.
    extend: Mutex<Value>,
    /// `POST /v1/ssh/sign` answers 404 once set.
    sign_ended: std::sync::atomic::AtomicBool,
}

fn approved_ssh(result: Value) -> Value {
    json!({"request_id":REQ,"kind":"ssh","status":"approved","deny_reason":null,"result":result})
}

fn ssh_handler(capable: bool, script: Arc<SshScript>) -> Arc<Handler> {
    Arc::new(move |method, path, body| match (method, path) {
        ("GET", "/v1/health") => {
            let capabilities: Vec<&str> = if capable { vec!["ssh_leases_v2"] } else { vec![] };
            (200, json!({"name":"asm-manager","version":"0.1.0","capabilities":capabilities}))
        }
        ("POST", "/v1/requests") if body["kind"] == "ssh" => {
            (200, approved_ssh(script.result.lock().unwrap().clone()))
        }
        ("POST", "/v1/requests") if body["kind"] == "ssh_extend" => {
            (200, approved_ssh(script.extend.lock().unwrap().clone()))
        }
        ("GET", "/v1/ssh/targets") => (
            200,
            json!({"targets":[
                {"name":"t1","privileged_login":"root","users":["deploy","postgres"],
                    "grants":["logs:nginx.service","restart:nginx.service","reload:nginx.service",
                        "read:/etc/nginx/nginx.conf"]},
                {"name":"t2","grants":["logs:web.service"]}]}),
        ),
        ("POST", "/v1/ssh/sign") if script.sign_ended.load(std::sync::atomic::Ordering::SeqCst) => (
            404,
            json!({"error":{"code":"not_found","message":"SSH lease has ended"}}),
        ),
        ("POST", "/v1/ssh/sign") => (
            200,
            json!({"signature":asm_proto::ssh::b64_encode(&ssh_signature_blob())}),
        ),
        _ => (
            404,
            json!({"error":{"code":"not_found","message":format!("{method} {path}")}}),
        ),
    })
}

fn ssh_paired_with(capable: bool, result: Value) -> (Fake, Env, Arc<SshScript>) {
    let script = Arc::new(SshScript {
        result: Mutex::new(result),
        extend: Mutex::new(Value::Null),
        sign_ended: std::sync::atomic::AtomicBool::new(false),
    });
    let f = start(ssh_handler(capable, script.clone()));
    let e = env();
    write_host_json(&e, &f);
    (f, e, script)
}

fn ssh_paired(capable: bool) -> (Fake, Env) {
    let (f, e, _) = ssh_paired_with(capable, ssh_result(SSH_EXPIRES));
    (f, e)
}

/// The test's temporary directory: `HOME` of the asm processes.
fn tmp_root(e: &Env) -> &Path {
    e.cfg.parent().unwrap()
}

fn ssh_state_dir(e: &Env) -> PathBuf {
    e.cfg.join("asm/ssh")
}

fn lease_config(e: &Env) -> PathBuf {
    ssh_state_dir(e).join(LEASE).join("config")
}

/// `asm` for SSH commands: no reaper, the agent log in `<tmp>/agent.log`, and
/// `<tmp>/bin` (where `fake_ssh` puts `ssh`) first on PATH.
fn asm_ssh_command(e: &Env, args: &[&str]) -> Command {
    let t = tmp_root(e);
    let mut c = Command::new(env!("CARGO_BIN_EXE_asm"));
    c.args(args)
        .env_clear()
        .env("HOME", t)
        .env("XDG_CONFIG_HOME", &e.cfg)
        .env("ASM_SECRETS_DIR", &e.secrets)
        .env("ASM_AGENT", "test-agent")
        .env("ASM_NO_REAPER", "1")
        .env("ASM_SSH_AGENT_LOG", t.join("agent.log"))
        .env("PATH", format!("{}:/usr/bin:/bin", t.join("bin").display()))
        .stdin(Stdio::null());
    c
}

fn asm_ssh(e: &Env, args: &[&str]) -> Output {
    asm_ssh_command(e, args).output().unwrap()
}

/// Put a fake `ssh` first on PATH. It appends its arguments as one line to
/// `<tmp>/ssh-args`, then runs `body`.
fn fake_ssh(e: &Env, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let bin = tmp_root(e).join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> '{}'\n{body}\n",
        tmp_root(e).join("ssh-args").display()
    );
    std::fs::write(bin.join("ssh"), script).unwrap();
    std::fs::set_permissions(bin.join("ssh"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// One line per call of the fake ssh.
fn ssh_calls(e: &Env) -> Vec<String> {
    std::fs::read_to_string(tmp_root(e).join("ssh-args"))
        .map(|s| s.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Pids of the agents that logged `started for` to `log`.
fn started_agents(log: &Path) -> Vec<i32> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("]: started for "))
        .filter_map(|l| l.split("asm ssh-agent[").nth(1)?.split(']').next()?.parse().ok())
        .collect()
}

/// Kills the agent processes a test started, also when it fails midway.
struct Agents {
    /// The log the detached agents write their pid to.
    log: PathBuf,
    /// An agent run as this test's child.
    child: Option<std::process::Child>,
}

impl Agents {
    fn new(e: &Env) -> Self {
        Agents {
            log: tmp_root(e).join("agent.log"),
            child: None,
        }
    }
}

impl Drop for Agents {
    fn drop(&mut self) {
        for pid in started_agents(&self.log) {
            // SAFETY: kill has no memory preconditions; the pid is an agent we started.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Whether some process holds the agent lock of `dir`.
fn agent_running(dir: &Path) -> bool {
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("agent.lock"))
    else {
        return false;
    };
    // SAFETY: flock on a descriptor owned by `f`; closing it releases the lock.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

/// Stop the agents asm started and run one in the foreground of this test; returns
/// its socket once it accepts connections.
fn foreground_agent(e: &Env, agents: &mut Agents) -> PathBuf {
    let dir = ssh_state_dir(e);
    for pid in started_agents(&agents.log) {
        // SAFETY: kill has no memory preconditions; the pid is an agent we started.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    assert!(wait_for(Duration::from_secs(5), || !agent_running(&dir)));
    let child = Command::new(env!("CARGO_BIN_EXE_asm"))
        .args(["ssh", "agent", "--dir", dir.to_str().unwrap()])
        .env_clear()
        .env("HOME", tmp_root(e))
        .env("XDG_CONFIG_HOME", &e.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    agents.child = Some(child);
    let sock = dir.join("agent.sock");
    assert!(wait_for(Duration::from_secs(5), || std::os::unix::net::UnixStream::connect(&sock).is_ok()));
    sock
}

/// One framed agent request and its framed reply.
fn agent_call(sock: &Path, msg: &[u8]) -> Vec<u8> {
    let mut s = std::os::unix::net::UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut framed = Vec::new();
    asm_proto::ssh::put_string(&mut framed, msg);
    s.write_all(&framed).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut reply).unwrap();
    reply
}

/// The IDENTITIES_ANSWER listing `blobs` of lease LEASE.
fn identities_answer(blobs: &[Vec<u8>]) -> Vec<u8> {
    let ids: Vec<(Vec<u8>, &str)> = blobs.iter().map(|b| (b.clone(), LEASE)).collect();
    leases_identities_answer(&ids)
}

/// The IDENTITIES_ANSWER listing each certificate blob with its lease.
fn leases_identities_answer(ids: &[(Vec<u8>, &str)]) -> Vec<u8> {
    let mut want = vec![12u8];
    want.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for (blob, lease) in ids {
        asm_proto::ssh::put_string(&mut want, blob);
        asm_proto::ssh::put_string(&mut want, format!("asm-lease-{lease}").as_bytes());
    }
    want
}

fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut sign = vec![13u8];
    asm_proto::ssh::put_string(&mut sign, blob);
    asm_proto::ssh::put_string(&mut sign, data);
    sign.extend_from_slice(&0u32.to_be_bytes());
    sign
}

#[test]
fn ssh_writes_lease_files_and_the_agent_signs_through_the_manager() {
    let (f, e) = ssh_paired(true);
    let dir = ssh_state_dir(&e);
    let ldir = dir.join(LEASE);
    let mut agents = Agents::new(&e);

    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let config = ldir.join("config");
    assert_eq!(
        text(&out.stdout),
        format!(
            "ssh lease {LEASE} until {SSH_EXPIRES}\nt1: ssh -F {} t1   (privileged)\n",
            config.display()
        )
    );
    let sent = f.log.lock().unwrap().iter().find(|(m, p, _)| m == "POST" && p == "/v1/requests").unwrap().2.clone();
    assert_eq!(
        sent,
        json!({"kind":"ssh","targets":["t1"],"access":"privileged","grants":[],"new_lease":false,"reason":"r","agent":"test-agent"})
    );
    let config_text = std::fs::read_to_string(&config).unwrap();
    assert!(config_text.starts_with(&format!("# Written by asm ssh for lease {LEASE}.\n")), "{config_text}");
    assert!(config_text.contains("\nHost t1 t1.example.com\n  HostName t1.example.com\n  Port 2222\n  User asm-priv\n  HostKeyAlias asm-target-0123abcd\n"), "{config_text}");
    assert!(config_text.contains(&format!("  UserKnownHostsFile \"{}\"\n", ldir.join("known_hosts").display())), "{config_text}");
    assert!(config_text.contains(&format!("  IdentityAgent \"{}\"\n", dir.join("agent.sock").display())), "{config_text}");
    assert!(config_text.contains(&format!("  IdentityFile \"{}\"\n", ldir.join("0123abcd-cert.pub").display())), "{config_text}");
    assert_eq!(
        std::fs::read_to_string(ldir.join("known_hosts")).unwrap(),
        format!("asm-target-{SSH_TARGET_ID} {SSH_HOST_KEY}\n")
    );
    assert_eq!(
        std::fs::read_to_string(ldir.join("0123abcd-cert.pub")).unwrap(),
        format!("{}\n", ssh_cert_line())
    );
    let leases = read_json(&dir.join("leases.json"));
    assert_eq!(leases[0]["lease_id"], LEASE);
    assert!(leases[0]["requested_at"].as_i64().unwrap() > 0);
    let hosts_conf = std::fs::read_to_string(dir.join("asm-ssh-hosts.conf")).unwrap();
    assert!(hosts_conf.starts_with(HOSTS_CONF_HEADER), "{hosts_conf}");
    assert!(hosts_conf.contains("\nHost t1 t1.example.com\n"), "{hosts_conf}");
    assert!(!dir.join("config").exists() && !dir.join("known_hosts").exists());

    // `asm ssh request` started the agent and waited for its socket.
    let started = started_agents(&agents.log);
    assert_eq!(started.len(), 1, "{}", std::fs::read_to_string(&agents.log).unwrap_or_default());
    assert!(agent_running(&dir));
    // A second instance leaves at once.
    let out = asm_ssh(&e, &["ssh", "agent", "--dir", dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(std::fs::read_to_string(&agents.log).unwrap().contains("another agent holds the lock"));

    let sock = foreground_agent(&e, &mut agents);
    let blob = ssh_cert_blob();
    assert_eq!(agent_call(&sock, &[11]), identities_answer(std::slice::from_ref(&blob)));

    let sign = sign_request(&blob, b"session data");
    let mut want = vec![14u8];
    asm_proto::ssh::put_string(&mut want, &ssh_signature_blob());
    assert_eq!(agent_call(&sock, &sign), want);
    let signed = f.log.lock().unwrap().iter().find(|(m, p, _)| m == "POST" && p == "/v1/ssh/sign").unwrap().2.clone();
    assert_eq!(signed, json!({"lease_id":LEASE,"data":asm_proto::ssh::b64_encode(b"session data")}));

    // An unknown key, an extension (session-bind) and a truncated request all fail.
    assert_eq!(agent_call(&sock, &sign_request(b"other key", b"data")), vec![5]);
    let mut extension = vec![27u8];
    asm_proto::ssh::put_string(&mut extension, b"session-bind@openssh.com");
    assert_eq!(agent_call(&sock, &extension), vec![5]);
    assert_eq!(agent_call(&sock, &sign[..sign.len() - 1]), vec![5]);
}

#[test]
fn ssh_hosts_lists_users_and_grants() {
    let (_f, e) = ssh_paired(true);
    let out = asm(&e, &["ssh", "hosts"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "t1\tprivileged:root\tusers:deploy,postgres\tgrants:logs:nginx.service,restart:nginx.service,reload:nginx.service,read:/etc/nginx/nginx.conf\nt2\tprivileged:-\tusers:-\tgrants:logs:web.service\n"
    );
    let out = asm(&e, &["ssh", "hosts", "--json"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["targets"][0]["privileged_login"], "root");
    assert_eq!(doc["targets"][0]["users"], json!(["deploy", "postgres"]));
    assert!(doc["targets"][1].get("privileged_login").is_none(), "{doc}");
}

#[test]
fn ssh_requires_manager_support() {
    let (f, e) = ssh_paired(false);
    for args in [&["ssh", "request", "t1", "r", "--privileged"][..], &["ssh", "hosts"]] {
        let out = asm(&e, args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(
            text(&out.stderr),
            "invalid: the manager does not support SSH leases; upgrade Agents Secrets Manager\n"
        );
    }
    assert!(!f.log.lock().unwrap().iter().any(|(m, _, _)| m == "POST"));
    assert!(!e.cfg.join("asm/ssh").exists());
}

#[test]
fn ssh_rejects_invalid_access_before_contacting_the_manager() {
    let (f, e) = ssh_paired(true);
    let cases: [(&[&str], &str); 9] = [
        (&["ssh", "request", "t1", "r", "--grant", "logs:nginx.service", "--privileged"], "cannot be used with"),
        (&["ssh", "request", "t1", "r", "--as", "deploy", "--privileged"], "cannot be used with"),
        (&["ssh", "request", "t1", "r", "--as", "deploy", "--grant", "logs:nginx.service"], "cannot be used with"),
        (&["ssh", "request", "t1", "r"], "choose --privileged, --as <user> or at least one --grant (logs:<unit>, restart:<unit>, reload:<unit> or read:<path>)"),
        (&["ssh", "request", "t1,t2", "r", "--privileged", "--", "uptime"], "a command needs exactly one host"),
        (&["ssh", "request", "t1", "r", "--grant", "restart:nginx"], "invalid"),
        (&["ssh", "request", "t1", "r", "--grant", "logs"], "invalid"),
        (&["ssh", "request", "t1", "r", "--grant", "reload:nginx"], "invalid"),
        (&["ssh", "request", "t1", "r", "--grant", "read:etc/nginx/nginx.conf"], "invalid file"),
    ];
    for (args, message) in cases {
        let out = asm(&e, args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains(message), "{args:?}: {}", text(&out.stderr));
    }
    assert!(f.log.lock().unwrap().is_empty());
}

#[test]
fn ssh_accepts_a_narrowed_approval() {
    let (_f, e, _s) = ssh_paired_with(true, ssh_restricted_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "request", "t1,t2", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "ssh lease {LEASE} until {SSH_EXPIRES}\nt1: ssh -F {} t1   (restricted: logs:nginx.service)\nt2: denied\n",
            lease_config(&e).display()
        )
    );
    assert_eq!(
        text(&out.stderr),
        "asm: t1: the operator approved restricted access, not the privileged access requested\nasm: t2: denied by the operator\n"
    );
}

#[test]
fn ssh_requests_access_as_a_user() {
    let (f, e, _s) = ssh_paired_with(true, ssh_user_result(SSH_EXPIRES, "deploy"));
    let _agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--as", "deploy"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "ssh lease {LEASE} until {SSH_EXPIRES}\nt1: ssh -F {} t1   (as deploy)\n",
            lease_config(&e).display()
        )
    );
    assert!(!text(&out.stderr).contains("operator approved"), "{}", text(&out.stderr));
    let sent = f.log.lock().unwrap().iter().find(|(m, p, _)| m == "POST" && p == "/v1/requests").unwrap().2.clone();
    assert_eq!(
        sent,
        json!({"kind":"ssh","targets":["t1"],"access":"user","grants":[],"user":"deploy","new_lease":false,"reason":"r","agent":"test-agent"})
    );
    let out = asm_ssh(&e, &["ssh", "leases", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc[0]["targets"][0]["user"], "deploy");
}

#[test]
fn ssh_reports_an_approval_of_other_access() {
    let (_f, e, _s) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--as", "deploy"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("asm: t1: the operator approved privileged access, not the access as deploy requested\n"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn ssh_reused_older_lease_prints_its_own_config_for_hosts_a_newer_lease_holds() {
    let (_f, e, script) = ssh_paired_with(true, ssh_restricted_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "install"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--grant", "logs:nginx.service"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("\nt1: ssh t1   (restricted: logs:nginx.service)\n"), "{}", text(&out.stdout));

    // A newer privileged lease on t1 takes `ssh t1` in the hosts conf.
    *script.result.lock().unwrap() =
        ssh_lease(SSH_LEASE2, SSH_EXPIRES, vec![ssh_target("t1", SSH_TARGET_ID, "privileged", 8)]);
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("\nt1: ssh t1   (privileged)\n"), "{}", text(&out.stdout));

    // The manager reuses the older restricted lease: its line names its own config.
    *script.result.lock().unwrap() = ssh_restricted_result(SSH_EXPIRES);
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--grant", "logs:nginx.service"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "ssh lease {LEASE} until {SSH_EXPIRES}\nt1: ssh -F {} t1   (restricted: logs:nginx.service)\n",
            lease_config(&e).display()
        )
    );
    let hosts_conf = std::fs::read_to_string(ssh_state_dir(&e).join("asm-ssh-hosts.conf")).unwrap();
    assert!(hosts_conf.contains(&format!("/{SSH_LEASE2}/{SSH_TARGET_ID}-cert.pub")), "{hosts_conf}");

    // The JSON connect command follows the same rule.
    let connect = |args: &[&str]| {
        let out = asm_ssh(&e, args);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(doc["installed"], true, "{doc}");
        doc["targets"][0]["connect"].as_str().unwrap().to_owned()
    };
    assert_eq!(
        connect(&["ssh", "request", "t1", "r", "--grant", "logs:nginx.service", "--json"]),
        format!("ssh -F {} t1", lease_config(&e).display())
    );
    *script.result.lock().unwrap() =
        ssh_lease(SSH_LEASE2, SSH_EXPIRES, vec![ssh_target("t1", SSH_TARGET_ID, "privileged", 8)]);
    assert_eq!(connect(&["ssh", "request", "t1", "r", "--privileged", "--json"]), "ssh t1");
}

#[test]
fn ssh_mixed_approval_writes_one_certificate_per_host() {
    let (_f, e, script) = ssh_paired_with(true, ssh_mixed_result(SSH_EXPIRES, 0));
    let ldir = ssh_state_dir(&e).join(LEASE);
    let _agents = Agents::new(&e);
    fake_ssh(&e, "exit 0");
    let out = asm_ssh(&e, &["ssh", "request", "t4,t3,t2,t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let config = lease_config(&e);
    let c = config.display();
    let t2_grants = "logs:web.service, read:/etc/nginx/nginx.conf, reload:web.service";
    assert_eq!(
        text(&out.stdout),
        format!(
            "ssh lease {LEASE} until {SSH_EXPIRES}\nt1: ssh -F {c} t1   (privileged)\nt2: ssh -F {c} t2   (restricted: {t2_grants})\nt3: ssh -F {c} t3   (as deploy)\nt4: denied\n"
        )
    );
    assert_eq!(
        text(&out.stderr),
        "asm: t2: the operator approved restricted access, not the privileged access requested\nasm: t3: the operator approved access as deploy, not the privileged access requested\nasm: t4: denied by the operator\n"
    );

    // One certificate file per host; each config block names its own.
    let hosts = [("t1", "0000000a", "asm-priv", 1u8), ("t2", "0000000b", "asm-ops", 2), ("t3", "0000000c", "asm-priv", 3)];
    let config_text = std::fs::read_to_string(&config).unwrap();
    let blocks: Vec<&str> = config_text.split("\nHost ").skip(1).collect();
    assert_eq!(blocks.len(), 3, "{config_text}");
    for (block, (name, tid, login, fill)) in blocks.iter().zip(hosts) {
        let cert = ldir.join(format!("{tid}-cert.pub"));
        assert_eq!(std::fs::read_to_string(&cert).unwrap(), format!("{}\n", ssh_cert_line_with(fill)));
        assert!(block.starts_with(&format!("{name} {name}.example.com\n")), "{config_text}");
        assert!(block.contains(&format!("\n  User {login}\n")), "{config_text}");
        assert!(block.contains(&format!("\n  IdentityFile \"{}\"\n", cert.display())), "{config_text}");
    }
    assert!(!ldir.join("cert.pub").exists());

    let out = asm_ssh(&e, &["ssh", "request", "t1,t2,t3,t4", "r", "--privileged", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let targets = json!([
        {"name":"t1","login":"asm-priv","access":"privileged","grants":[],"user":null},
        {"name":"t2","login":"asm-ops","access":"restricted",
            "grants":["logs:web.service","read:/etc/nginx/nginx.conf","reload:web.service"],"user":null},
        {"name":"t3","login":"asm-priv","access":"user","grants":[],"user":"deploy"}]);
    let mut with_connect = targets.clone();
    for (t, name) in with_connect.as_array_mut().unwrap().iter_mut().zip(["t1", "t2", "t3"]) {
        t["connect"] = json!(format!("ssh -F {c} {name}"));
    }
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc,
        json!({"lease_id":LEASE,"expires_at":SSH_EXPIRES,"config":config.to_str().unwrap(),"installed":false,
            "targets":with_connect,"denied":["t4"]})
    );
    let out = asm_ssh(&e, &["ssh", "leases"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("{LEASE}\tuntil {SSH_EXPIRES}\tt1 (privileged), t2 (restricted: {t2_grants}), t3 (as deploy)\t{c}\n")
    );
    let out = asm_ssh(&e, &["ssh", "leases", "--json"]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc,
        json!([{"lease_id":LEASE,"expires_at":SSH_EXPIRES,"config":config.to_str().unwrap(),"targets":targets}])
    );

    // An extension rewrites every certificate file and logs in to each host except the
    // restricted one.
    *script.extend.lock().unwrap() = ssh_mixed_result(SSH_EXTENDED, 10);
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("ssh lease {LEASE} extended until {SSH_EXTENDED}\nt1: confirmed\nt3: confirmed\n")
    );
    for (_, tid, _, fill) in hosts {
        assert_eq!(
            std::fs::read_to_string(ldir.join(format!("{tid}-cert.pub"))).unwrap(),
            format!("{}\n", ssh_cert_line_with(fill + 10))
        );
    }
    assert_eq!(std::fs::read_to_string(&config).unwrap(), config_text);
    let touch = |name: &str| format!("-F {c} -o BatchMode=yes -o ConnectTimeout=10 -- {name} true");
    assert_eq!(ssh_calls(&e), [touch("t1"), touch("t3")]);

    // An extension that changes a host's access is refused.
    let mut changed = ssh_mixed_result("2999-03-01T00:00:00Z", 20);
    changed["targets"][2]["grants"] = json!(["logs:web.service"]);
    *script.extend.lock().unwrap() = changed;
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "error: the manager sent an invalid SSH result\n");
}

#[test]
fn ssh_refuses_a_result_with_a_wrong_login_or_certificate() {
    let (_f, e, script) = ssh_paired_with(true, Value::Null);
    let mut bad_login = ssh_result(SSH_EXPIRES);
    bad_login["targets"][0]["login"] = json!("asm-ops");
    let mut bad_cert = ssh_result(SSH_EXPIRES);
    bad_cert["targets"][0]["certificate"] = json!(format!("ssh-ed25519 {}", asm_proto::ssh::b64_encode(&[1; 32])));
    for result in [bad_login, bad_cert] {
        *script.result.lock().unwrap() = result;
        let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        assert_eq!(text(&out.stderr), "error: the manager sent an invalid SSH result\n");
        assert!(!ssh_state_dir(&e).join(LEASE).exists());
    }
}

#[test]
fn ssh_agent_signs_with_the_lease_holding_each_certificate() {
    let (f, e, script) = ssh_paired_with(true, ssh_mixed_result(SSH_EXPIRES, 0));
    let mut agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "request", "t1,t2,t3", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let mut t4 = ssh_target("t4", "0000000d", "restricted", 4);
    t4["grants"] = json!(["logs:web.service"]);
    *script.result.lock().unwrap() =
        ssh_lease(SSH_LEASE2, SSH_EXPIRES, vec![t4, ssh_target("t5", "0000000e", "privileged", 5)]);
    let out = asm_ssh(&e, &["ssh", "request", "t4,t5", "r", "--privileged", "--new-lease"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let sock = foreground_agent(&e, &mut agents);
    let ids: Vec<(Vec<u8>, &str)> = [(1, LEASE), (2, LEASE), (3, LEASE), (4, SSH_LEASE2), (5, SSH_LEASE2)]
        .into_iter()
        .map(|(fill, lease)| (ssh_cert_blob_with(fill), lease))
        .collect();
    assert_eq!(agent_call(&sock, &[11]), leases_identities_answer(&ids));

    let mut want = vec![14u8];
    asm_proto::ssh::put_string(&mut want, &ssh_signature_blob());
    for (fill, lease) in [(4, SSH_LEASE2), (2, LEASE), (5, SSH_LEASE2), (3, LEASE)] {
        let data = format!("data {fill}");
        assert_eq!(agent_call(&sock, &sign_request(&ssh_cert_blob_with(fill), data.as_bytes())), want);
        let signed = f.log.lock().unwrap().iter().rfind(|(m, p, _)| m == "POST" && p == "/v1/ssh/sign").unwrap().2.clone();
        assert_eq!(signed, json!({"lease_id":lease,"data":asm_proto::ssh::b64_encode(data.as_bytes())}));
    }
}

#[test]
fn ssh_agent_forgets_an_ended_lease() {
    let (_f, e, script) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let dir = ssh_state_dir(&e);
    let mut agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sock = foreground_agent(&e, &mut agents);

    script.sign_ended.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(agent_call(&sock, &sign_request(&ssh_cert_blob(), b"data")), vec![5]);
    assert!(wait_for(Duration::from_secs(2), || {
        !dir.join(LEASE).exists() && !std::fs::read_to_string(dir.join("leases.json")).unwrap().contains(LEASE)
    }));
    assert_eq!(agent_call(&sock, &[11]), identities_answer(&[]));
}

#[test]
fn ssh_agent_serves_a_replaced_certificate_at_once() {
    let (_f, e, script) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let mut agents = Agents::new(&e);
    fake_ssh(&e, "exit 0");
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sock = foreground_agent(&e, &mut agents);
    assert_eq!(agent_call(&sock, &[11]), identities_answer(&[ssh_cert_blob()]));

    // `asm ssh extend` stores the new certificate for the same lease.
    let mut extended = ssh_result(SSH_EXTENDED);
    extended["targets"][0]["certificate"] = json!(ssh_cert_line_with(8));
    *script.extend.lock().unwrap() = extended;
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(agent_call(&sock, &[11]), identities_answer(&[ssh_cert_blob_with(8)]));
}

#[test]
fn ssh_install_edits_ssh_config_once_and_uninstall_restores_it() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let ssh = tmp_root(&e).join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let config = ssh.join("config");
    let original = b"Host other\n  User x\n";
    std::fs::write(&config, original).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    let hosts_conf = ssh_state_dir(&e).join("asm-ssh-hosts.conf");
    let include = format!("Include \"{}\"", hosts_conf.display());

    let out = asm_ssh(&e, &["ssh", "install"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("installed: {} now includes {}\n", config.display(), hosts_conf.display())
    );
    let installed = std::fs::read(&config).unwrap();
    let mut want = format!("{INSTALL_MARKER}\n{include}\n\n").into_bytes();
    want.extend_from_slice(original);
    assert_eq!(installed, want);
    assert_eq!(std::fs::metadata(&config).unwrap().permissions().mode() & 0o777, 0o644);
    assert_eq!(std::fs::read_to_string(&hosts_conf).unwrap(), HOSTS_CONF_HEADER);

    let out = asm_ssh(&e, &["ssh", "install"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("already installed: {}\n", config.display()));
    assert_eq!(std::fs::read(&config).unwrap(), installed);

    let out = asm_ssh(&e, &["ssh", "uninstall"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("uninstalled: {}\n", config.display()));
    assert_eq!(std::fs::read(&config).unwrap(), original);
    let out = asm_ssh(&e, &["ssh", "uninstall"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "not installed\n");
    assert_eq!(std::fs::read(&config).unwrap(), original);
    assert!(hosts_conf.exists());
}

#[test]
fn ssh_install_follows_a_symlinked_config() {
    let e = env();
    let ssh = tmp_root(&e).join(".ssh");
    let dotfiles = tmp_root(&e).join("dotfiles");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::create_dir_all(&dotfiles).unwrap();
    let real = dotfiles.join("ssh_config");
    std::fs::write(&real, "Host other\n").unwrap();
    std::os::unix::fs::symlink(&real, ssh.join("config")).unwrap();

    let out = asm_ssh(&e, &["ssh", "install"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(std::fs::symlink_metadata(ssh.join("config")).unwrap().file_type().is_symlink());
    let include = format!("Include \"{}\"", ssh_state_dir(&e).join("asm-ssh-hosts.conf").display());
    let content = std::fs::read_to_string(&real).unwrap();
    assert!(content.lines().any(|l| l == include), "{content}");
    assert!(content.ends_with("\nHost other\n"), "{content}");
}

#[test]
fn ssh_hosts_conf_tracks_leases() {
    if !Path::new("/usr/bin/ssh").exists() {
        eprintln!("skipping: /usr/bin/ssh not found");
        return;
    }
    let (_f, e, script) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let dir = ssh_state_dir(&e);
    let _agents = Agents::new(&e);
    let config = tmp_root(&e).join(".ssh/config");
    let ssh_g = |host: &str| {
        let out = Command::new("/usr/bin/ssh")
            .args(["-G", "-F", config.to_str().unwrap(), host])
            .env("HOME", tmp_root(&e))
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh -G {host}: {}", text(&out.stderr));
        text(&out.stdout)
    };

    let out = asm_ssh(&e, &["ssh", "install"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("\nt1: ssh t1   (privileged)\n"), "{}", text(&out.stdout));

    let resolved = ssh_g("t1");
    assert!(resolved.lines().any(|l| l == "user asm-priv"), "{resolved}");
    assert!(resolved.lines().any(|l| l == "hostkeyalias asm-target-0123abcd"), "{resolved}");
    let resolved = ssh_g("t1.example.com");
    assert!(resolved.lines().any(|l| l == "hostkeyalias asm-target-0123abcd"), "{resolved}");

    // The manager ends the lease: the agent forgets it at the next signature.
    script.sign_ended.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(agent_call(&dir.join("agent.sock"), &sign_request(&ssh_cert_blob(), b"data")), vec![5]);
    let hosts_conf = dir.join("asm-ssh-hosts.conf");
    assert!(wait_for(Duration::from_secs(2), || {
        std::fs::read_to_string(&hosts_conf).unwrap() == HOSTS_CONF_HEADER
    }));
    assert_eq!(std::fs::read_to_string(&hosts_conf).unwrap().lines().count(), 2);
    let resolved = ssh_g("t1");
    assert!(!resolved.contains("hostkeyalias asm-target"), "{resolved}");
}

#[test]
fn ssh_command_warns_before_the_lease_ends() {
    let expires = asm_proto::time::fmt_unix(unix_now() + 300);
    let (_f, e, _s) = ssh_paired_with(true, ssh_result(&expires));
    let _agents = Agents::new(&e);
    fake_ssh(&e, "sleep 1\nexit 7");
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged", "--", "uptime"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(stderr.contains(&format!("ends at {expires} (in 5 minutes)")), "{stderr}");
    assert!(stderr.contains(&format!("asm ssh extend {LEASE}")), "{stderr}");
    assert_eq!(ssh_calls(&e), [format!("-F {} -- t1 uptime", lease_config(&e).display())]);
}

#[test]
fn ssh_command_forwards_sigterm() {
    let (_f, e, _s) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    let got = tmp_root(&e).join("got");
    let ready = tmp_root(&e).join("ready");
    fake_ssh(
        &e,
        &format!(
            "trap 'kill $p; echo got-term >> {}; exit 9' TERM\nsleep 30 &\np=$!\necho ready > {}\nwait",
            got.display(),
            ready.display()
        ),
    );
    let mut child = asm_ssh_command(&e, &["ssh", "request", "t1", "r", "--privileged", "--", "uptime"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    if !wait_for(Duration::from_secs(10), || ready.exists()) {
        let _ = child.kill();
        panic!("the fake ssh did not start");
    }
    // SAFETY: kill has no memory preconditions; the pid is our child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let until = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            panic!("asm did not exit within 5 s of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(9));
    assert!(std::fs::read_to_string(&got).unwrap().contains("got-term"));
}

#[test]
fn ssh_extend_updates_the_lease_and_confirms_targets() {
    let (f, e, script) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let dir = ssh_state_dir(&e);
    let _agents = Agents::new(&e);
    fake_ssh(&e, "exit 0");
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let config = std::fs::read(lease_config(&e)).unwrap();
    let requested_at = read_json(&dir.join("leases.json"))[0]["requested_at"].clone();

    let mut extended = ssh_result(SSH_EXTENDED);
    extended["targets"][0]["certificate"] = json!(ssh_cert_line_with(8));
    *script.extend.lock().unwrap() = extended;
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("ssh lease {LEASE} extended until {SSH_EXTENDED}\nt1: confirmed\n")
    );
    let sent = f.log.lock().unwrap().iter().rfind(|(m, p, _)| m == "POST" && p == "/v1/requests").unwrap().2.clone();
    assert_eq!(sent, json!({"kind":"ssh_extend","lease_id":LEASE,"reason":"more time","agent":"test-agent"}));
    let leases = read_json(&dir.join("leases.json"));
    assert_eq!(leases[0]["expires_at"], asm_proto::time::parse_unix(SSH_EXTENDED).unwrap());
    assert_eq!(leases[0]["targets"][0]["certificate"], ssh_cert_line_with(8));
    assert_eq!(leases[0]["requested_at"], requested_at);
    assert_eq!(
        std::fs::read_to_string(dir.join(LEASE).join("0123abcd-cert.pub")).unwrap(),
        format!("{}\n", ssh_cert_line_with(8))
    );
    assert_eq!(std::fs::read(lease_config(&e)).unwrap(), config);
    assert_eq!(
        ssh_calls(&e),
        [format!("-F {} -o BatchMode=yes -o ConnectTimeout=10 -- t1 true", lease_config(&e).display())]
    );

    // A result that doesn't end later is refused; a later one is stored.
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "error: the manager sent an invalid SSH result\n");
    *script.extend.lock().unwrap() = ssh_result("2999-03-01T00:00:00Z");
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc,
        json!({"lease_id":LEASE,"expires_at":"2999-03-01T00:00:00Z","previous_expires_at":SSH_EXTENDED,
            "config":lease_config(&e).to_str().unwrap(),"targets":[{"name":"t1","confirmed":true}]})
    );
}

#[test]
fn ssh_extend_of_a_restricted_lease_logs_in_nowhere() {
    let (_f, e, script) = ssh_paired_with(true, ssh_restricted_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    fake_ssh(&e, "exit 0");
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--grant", "logs:nginx.service"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    *script.extend.lock().unwrap() = ssh_restricted_result(SSH_EXTENDED);
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("ssh lease {LEASE} extended until {SSH_EXTENDED}\n"));
    assert!(ssh_calls(&e).is_empty());
}

#[test]
fn ssh_extend_reports_an_unreachable_target() {
    let (_f, e, script) = ssh_paired_with(true, ssh_result(SSH_EXPIRES));
    let _agents = Agents::new(&e);
    fake_ssh(
        &e,
        "echo 'ssh: connect to host t1.example.com port 2222: Connection refused' >&2\nexit 255",
    );
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    *script.extend.lock().unwrap() = ssh_result(SSH_EXTENDED);
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("ssh lease {LEASE} extended until {SSH_EXTENDED}\n"));
    assert!(
        text(&out.stderr).contains(&format!(
            "asm: could not reach t1 (ssh: connect to host t1.example.com port 2222: Connection refused); its running sessions still end at {SSH_EXPIRES} unless"
        )),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn ssh_extend_refuses_an_unknown_lease() {
    let (f, e) = ssh_paired(true);
    let out = asm_ssh(&e, &["ssh", "extend", LEASE, "more time"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        format!("invalid: no active SSH lease {LEASE} on this machine; see asm ssh leases\n")
    );
    assert!(f.log.lock().unwrap().is_empty());
}

#[test]
fn ssh_leases_lists_local_leases() {
    let (_f, e) = ssh_paired(true);
    let _agents = Agents::new(&e);
    let out = asm_ssh(&e, &["ssh", "leases"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    let out = asm_ssh(&e, &["ssh", "request", "t1", "r", "--privileged"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let config = lease_config(&e);
    let out = asm_ssh(&e, &["ssh", "leases"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("{LEASE}\tuntil {SSH_EXPIRES}\tt1 (privileged)\t{}\n", config.display())
    );
    let out = asm_ssh(&e, &["ssh", "leases", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc,
        json!([{"lease_id":LEASE,"expires_at":SSH_EXPIRES,"config":config.to_str().unwrap(),
            "targets":[{"name":"t1","login":"asm-priv","access":"privileged","grants":[],"user":null}]}])
    );
}
