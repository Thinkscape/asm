//! `asm login`: request validation, the broker session lifecycle against a fake Chrome
//! (this test binary speaking CDP on fds 3 and 4), and a real Chrome run gated by
//! `ASM_TEST_CHROME=<path to the Chrome binary>`.
use super::tests::{Logins, open_manager, request_host};
use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const FAKE_ENV: &str = "ASM_TEST_FAKE_CHROME";
const PASSWORD: &str = "SuperSecretPassword!";
const URL: &str = "https://sso.exact.test/login";
const ORIGIN: &str = "https://sso.exact.test";

/// The fake Chrome's body when this binary runs as one (see [`fake_chrome`]);
/// otherwise nothing. Its page shows the requested URL with no sign-in form. A URL
/// containing `slow` delays the cookie export by a second; `storage-error` fails the
/// localStorage export; `no-storage` reports no localStorage for the origin.
#[test]
fn fake_chrome_process() {
    if std::env::var_os(FAKE_ENV).is_none() {
        return;
    }
    use std::os::fd::FromRawFd;
    // SAFETY: the broker passes the debugging pipe on fds 3 and 4.
    let (commands, mut replies) = unsafe { (std::fs::File::from_raw_fd(3), std::fs::File::from_raw_fd(4)) };
    let mut url = "about:blank".to_owned();
    let mut worlds = 0;
    let mut send = |message: Value| {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(0);
        replies.write_all(&bytes).is_ok()
    };
    for message in BufReader::new(commands).split(0) {
        let Ok(message) = message else { break };
        let m: Value = serde_json::from_slice(&message).unwrap();
        let method = m["method"].as_str().unwrap_or("");
        let origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
        let result = match method {
            "Target.getTargets" => json!({ "targetInfos": [{ "targetId": "T1", "type": "page", "url": url }] }),
            "Target.attachToTarget" => json!({ "sessionId": "S1" }),
            "Page.navigate" => {
                url = m["params"]["url"].as_str().unwrap_or_default().to_owned();
                json!({ "frameId": "F1", "loaderId": "L1" })
            }
            "Page.getFrameTree" => json!({ "frameTree": { "frame": { "id": "F1", "loaderId": "L1", "url": url } } }),
            "Page.createIsolatedWorld" => {
                worlds += 1;
                send(json!({ "method": "Runtime.executionContextCreated", "sessionId": "S1", "params": { "context": {
                    "id": 7, "uniqueId": format!("U{worlds}"), "name": "asm-fill", "origin": origin,
                    "auxData": { "frameId": "F1", "isDefault": false, "type": "isolated" },
                } } }));
                json!({ "executionContextId": 7 })
            }
            "Runtime.evaluate" if m["params"]["expression"].as_str().unwrap_or("").starts_with("(function (kinds") => {
                json!({ "result": { "type": "object", "value": { "origin": origin, "kind": null } } })
            }
            "Runtime.evaluate" => json!({ "result": { "type": "object", "subtype": "null", "value": null } }),
            "Storage.getCookies" => {
                if url.contains("slow") {
                    std::thread::sleep(Duration::from_secs(1));
                }
                json!({ "cookies": [
                    { "name": "sid", "value": "s", "domain": "sso.exact.test", "path": "/", "expires": -1,
                      "httpOnly": true, "secure": true, "session": true, "sameSite": "Lax", "size": 2 },
                    { "name": "dom", "value": "d", "domain": ".exact.test", "path": "/", "expires": 1_900_000_000,
                      "httpOnly": false, "secure": true, "session": false, "size": 2 },
                    { "name": "parent", "value": "p", "domain": "exact.test", "path": "/", "expires": -1,
                      "httpOnly": false, "secure": true, "session": true, "size": 2 },
                    { "name": "other", "value": "o", "domain": "other.test", "path": "/", "expires": -1,
                      "httpOnly": false, "secure": true, "session": true, "size": 2 },
                    { "name": "part", "value": "x", "domain": "sso.exact.test", "path": "/", "expires": -1,
                      "httpOnly": false, "secure": true, "session": true, "size": 2, "sameSite": "None",
                      "partitionKey": { "topLevelSite": "https://exact.test", "hasCrossSiteAncestor": false } },
                    { "name": "opaque", "value": "x", "domain": "sso.exact.test", "path": "/", "expires": -1,
                      "httpOnly": false, "secure": true, "session": true, "size": 2, "sameSite": "None",
                      "partitionKeyOpaque": true },
                ] })
            }
            "DOMStorage.getDOMStorageItems" if url.contains("storage-error") => {
                send(json!({ "id": m["id"], "error": { "code": -32000, "message": "Internal error" } }));
                continue;
            }
            "DOMStorage.getDOMStorageItems" if url.contains("no-storage") => {
                send(json!({ "id": m["id"], "error": { "code": -32000, "message": "Frame not found for the given storage id" } }));
                continue;
            }
            "DOMStorage.getDOMStorageItems" => json!({ "entries": [["token", "t"]] }),
            _ => json!({}),
        };
        if !send(json!({ "id": m["id"], "result": result })) || method == "Browser.close" {
            break;
        }
    }
    std::process::exit(0);
}

/// A "Chrome" that runs [`fake_chrome_process`] in this test binary.
fn fake_chrome(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let exe = std::env::current_exe().unwrap();
    let script = dir.join("fake-chrome");
    std::fs::write(&script, format!(
        "#!/bin/sh\n{FAKE_ENV}=1 exec '{}' --exact manager::requests::login_broker_tests::fake_chrome_process --test-threads=1 -q\n",
        exe.display()
    )).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn broker_manager(tmp: &tempfile::TempDir, chrome: Option<(PathBuf, Vec<String>)>) -> (Arc<Core>, HostRecord) {
    let core = broker_core(tmp, chrome);
    let host = request_host(&core);
    (core, host)
}

fn broker_core(tmp: &tempfile::TempDir, chrome: Option<(PathBuf, Vec<String>)>) -> Arc<Core> {
    let core = open_manager(tmp);
    core.registry.insert(VaultEntry {
        id: "logins".into(), name: "Logins".into(),
        config: VaultConfig::EnvFile { path: "/unused".into() },
        provider: Arc::new(Logins(AtomicU64::new(0))),
    });
    *lock(&core.broker.chrome_override) = Some(chrome);
    core
}

/// Wait until the session is gone (its request ended first), without polling the
/// request: a raw result is delivered to the first poll only.
fn wait_ended(core: &Core, id: &str) {
    wait_for("the session to end", || status(core, id).is_none());
}

fn login_body(name: &str, url: &str, extra: &[&str], reason: &str) -> RequestBody {
    serde_json::from_value(json!({
        "kind": "login", "name": name, "url": url, "reason": reason, "extra_fill_origins": extra,
        "client_capabilities": [asm_proto::wire::CAPABILITY_LOGIN_BROKER_V1],
    })).unwrap()
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn approve(core: &Core, id: &str, duration_secs: Option<u64>, fill_origins: &[&str]) -> Result<()> {
    core.resolve_request(id, ffi::Decision::ApproveLogin {
        duration_secs, fill_origins: fill_origins.iter().map(|o| o.to_string()).collect(),
    })
}

fn status(core: &Core, id: &str) -> Option<String> {
    core.snapshot().broker_sessions.into_iter().find(|s| s.request_id == id).map(|s| s.status)
}

#[test]
fn login_requests_validate_capability_url_fill_origins_and_item() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, None);
    let login = |name: &str, url: &str, extra: &[&str]| {
        core.create_request(&host, "127.0.0.1", login_body(name, url, extra, "sign in"))
    };
    fn error<T: std::fmt::Debug>(r: Result<T>) -> String {
        r.unwrap_err().message
    }

    let mut old_cli = login_body("", URL, &[], "sign in");
    let RequestBody::Login { client_capabilities, .. } = &mut old_cli else { unreachable!() };
    client_capabilities.clear();
    assert!(error(core.create_request(&host, "127.0.0.1", old_cli)).contains("login_broker_v1"));
    assert!(error(login("", "http://sso.exact.test/login", &[])).contains("https://"));
    assert_eq!(error(login("", "https://10.0.0.1/login", &[])), "login grants need a DNS host name");
    assert!(error(login("", "https://sso.exact.test/a b", &[])).contains("printable ASCII"));
    assert!(error(login("", URL, &["https://idp.test/login"])).contains("must be https://host[:port]"));
    assert!(error(login("", URL, &["http://idp.test"])).contains("fill origin"));
    let six = ["https://a.test", "https://b.test", "https://c.test", "https://d.test", "https://e.test", "https://f.test"];
    assert_eq!(error(login("", URL, &six)), "at most 5 extra fill origins");
    assert_eq!(error(login("", "https://nothing.test/", &[])), "no vault login item has a URI for nothing.test; pass ITEM");
    assert_eq!(error(login("", "https://shared.test/", &[])),
        "several vault logins match shared.test: SharedA, SharedB; pass ITEM");
    assert!(error(login("Note", URL, &[])).contains("not a vault login with a password"));

    let inferred = login("", URL, &["https://IDP.test/", ORIGIN, &six[0]]).unwrap();
    assert_eq!(inferred.kind, RequestKind::Login);
    assert_eq!(login("", URL, &["https://IDP.test/", ORIGIN, &six[0]]).unwrap(), inferred, "an equal request re-attaches");
    let named = login("Herokuapp", "https://the-internet.herokuapp.com/login", &[]).unwrap();
    let snapshot = core.snapshot();
    let detail = |id: &str| snapshot.pending.iter().find(|p| p.id == id).map(|p| (p.kind, p.detail.clone())).unwrap();
    assert_eq!(detail(&inferred.request_id), (ffi::RequestKind::Login, ffi::RequestDetail::Login {
        name: "Exact".into(), vault_name: "Logins".into(), url: URL.into(),
        fill_origins: vec![ORIGIN.into(), "https://idp.test".into(), "https://a.test".into()],
        reason: "sign in".into(), has_totp: false,
    }));
    let (_, ffi::RequestDetail::Login { has_totp, fill_origins, .. }) = detail(&named.request_id) else { panic!() };
    assert!(has_totp);
    assert_eq!(fill_origins, ["https://the-internet.herokuapp.com"]);

    // Approval checks before any browser starts.
    assert!(error(approve(&core, &inferred.request_id, None, &["https://evil.test"])).contains("not a fill origin"));
    assert_eq!(core.request_state(&host.id, &inferred.request_id).unwrap().status, RequestStatus::Pending);
    *lock(&core.broker.chrome_override) = Some(None);
    assert_eq!(error(approve(&core, &inferred.request_id, None, &[])), broker::NO_CHROME);
    let denied = core.request_state(&host.id, &inferred.request_id).unwrap();
    assert_eq!((denied.status, denied.deny_reason.as_deref()), (RequestStatus::Denied, Some(broker::NO_CHROME)));
    core.shutdown();
}

#[test]
fn approved_sign_in_stays_pending_then_hands_over_only_the_sites_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let id = core.create_request(&host, "127.0.0.1", login_body("", URL, &["https://idp.test"], "hand over"))
        .unwrap().request_id;
    approve(&core, &id, Some(1800), &[]).unwrap();
    let profile = core.broker.profile_dir(&id);
    assert!(profile.join(broker::PID_FILE).is_file());
    let snapshot = core.snapshot();
    assert!(snapshot.pending.is_empty(), "the operator sees a session, not the request");
    assert_eq!(snapshot.broker_sessions.len(), 1);
    assert_eq!((snapshot.broker_sessions[0].url.as_str(), snapshot.broker_sessions[0].host_label.as_str()),
        (URL, "request-host"));
    wait_for("the fill loop", || status(&core, &id).as_deref() == Some("waiting for a sign-in form on https://sso.exact.test"));
    // Neither the request's own lifetime nor a second decision ends a live session.
    core.expire_requests(core.generation_now() + 100_000).unwrap();
    assert_eq!(core.request_state(&host.id, &id).unwrap().status, RequestStatus::Pending);
    assert!(approve(&core, &id, None, &[]).unwrap_err().message.contains("already being resolved"));

    core.broker_handover(&id).unwrap();
    wait_ended(&core, &id);
    assert!(!profile.exists(), "the profile is deleted");
    assert!(core.snapshot().broker_sessions.is_empty());
    let state = core.request_state(&host.id, &id).unwrap();
    assert_eq!(state.status, RequestStatus::Approved);
    let Some(RequestResult::Get(result)) = state.result else { panic!("no storage state") };
    assert_eq!(result.mode, LeaseMode::Raw);
    assert_eq!(result.files.len(), 1);
    let file = &result.files[0];
    assert_eq!((file.field.as_str(), file.relative_path.as_str(), file.substituted),
        ("storage-state", "Exact.storage-state", Some(false)));
    let exported: Value = serde_json::from_str(&file.content).unwrap();
    assert_eq!(exported, json!({
        "cookies": [
            { "name": "sid", "value": "s", "domain": "sso.exact.test", "path": "/", "expires": -1.0,
              "httpOnly": true, "secure": true, "sameSite": "Lax" },
            { "name": "dom", "value": "d", "domain": ".exact.test", "path": "/", "expires": 1_900_000_000.0,
              "httpOnly": false, "secure": true, "sameSite": "Lax" },
        ],
        "origins": [{ "origin": ORIGIN, "localStorage": [{ "name": "token", "value": "t" }] }],
    }));
    let lease = core.store.get_lease(&result.lease_id).unwrap().unwrap();
    assert_eq!((lease.mode, lease.login.as_ref(), lease.hosts.len()), (LeaseMode::Raw, None, 0));
    assert_eq!(lease.expires_at.unwrap() - lease.created_at, 1800);
    assert!(core.request_state(&host.id, &id).unwrap().result.is_none(), "delivered once");

    // The password never reaches the activity log, the database or a snapshot.
    let activity = || core.list_activity(ffi::ActivityQuery {
        categories: Vec::new(), host_id: None, search: String::new(), before_id: None, limit: 1000,
    });
    wait_for("the activity log", || activity().iter().any(|e| e.kind == "browser_opened")
        && activity().iter().any(|e| e.kind == "approved"));
    let activity = activity();
    assert!(!format!("{activity:?}").contains(PASSWORD));
    assert!(!format!("{:?}", core.snapshot()).contains(PASSWORD));
    core.shutdown();
    for path in [core.dirs.db(), core.dirs.db().with_extension("db-wal")] {
        if let Ok(bytes) = std::fs::read(path) {
            assert!(!bytes.windows(PASSWORD.len()).any(|w| w == PASSWORD.as_bytes()));
        }
    }
}

#[test]
fn ended_sign_ins_deny_with_their_reason_and_delete_the_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let start = |reason: &str| {
        let id = core.create_request(&host, "127.0.0.1", login_body("", URL, &[], reason)).unwrap().request_id;
        approve(&core, &id, None, &[]).unwrap();
        wait_for("the session", || status(&core, &id).is_some_and(|s| s.starts_with("waiting")));
        (id.clone(), core.broker.profile_dir(&id))
    };
    let ended = |id: &str, profile: &Path| {
        wait_for("the session to end", || core.request_state(&host.id, id).unwrap().status != RequestStatus::Pending);
        wait_for("the session to be forgotten", || status(&core, id).is_none());
        assert!(!profile.exists(), "the profile is deleted");
        core.request_state(&host.id, id).unwrap()
    };

    let (id, profile) = start("cancel");
    core.broker_cancel(&id).unwrap();
    let state = ended(&id, &profile);
    assert_eq!((state.status, state.deny_reason.as_deref()), (RequestStatus::Denied, Some(broker::DENY_CANCELLED)));

    let (id, profile) = start("browser closed");
    let pid: i32 = std::fs::read_to_string(profile.join(broker::PID_FILE)).unwrap().trim().parse().unwrap();
    // SAFETY: the fake Chrome this session started.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let state = ended(&id, &profile);
    assert_eq!(state.deny_reason.as_deref(), Some(broker::DENY_CLOSED));

    *lock(&core.broker.session_timeout) = Some(Duration::from_secs(1));
    let (id, profile) = start("time out");
    let state = ended(&id, &profile);
    assert_eq!(state.deny_reason.as_deref(), Some(broker::DENY_TIMED_OUT));
    *lock(&core.broker.session_timeout) = None;

    // The requesting host cancels its own request.
    let (id, profile) = start("requester cancels");
    assert_eq!(core.cancel_request(&host.id, &id).unwrap().status, RequestStatus::Cancelled);
    wait_for("the session to end", || status(&core, &id).is_none());
    assert!(!profile.exists());

    // The session notices a revoked host by itself.
    let (id, profile) = start("revoked");
    assert!(core.store.revoke_host(&host.id, core.generation_now()).unwrap());
    wait_for("the session to end", || status(&core, &id).is_none());
    assert!(!profile.exists());
    let recent = core.snapshot().recent.into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(recent.deny_reason.as_deref(), Some(broker::DENY_REVOKED));
    core.shutdown();
}

#[test]
fn manager_shutdown_closes_sign_in_browsers_and_a_restart_reopens_the_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let id = core.create_request(&host, "127.0.0.1", login_body("", URL, &[], "restart")).unwrap().request_id;
    approve(&core, &id, None, &[]).unwrap();
    let profile = core.broker.profile_dir(&id);
    let pid: i32 = std::fs::read_to_string(profile.join(broker::PID_FILE)).unwrap().trim().parse().unwrap();
    core.shutdown();
    drop(core);
    assert!(!profile.exists());
    // SAFETY: probing the fake Chrome's pid.
    assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "the browser is gone");
    let core = broker_core(&tmp, None);
    let pending = core.snapshot().pending;
    assert_eq!(pending.len(), 1);
    assert_eq!((pending[0].id.as_str(), pending[0].error.as_deref()), (id.as_str(), Some(INTERRUPTED)));
    core.shutdown();
}

/// A local HTTPS site for the real-Chrome test: `sso.login.test` (the sign-in page,
/// setting host-only, domain and partitioned cookies), `login.test` and `other.test`.
struct TestSite {
    port: u16,
    posts: Arc<AtomicUsize>,
}

fn serve_site() -> TestSite {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(
        vec!["sso.login.test".into(), "login.test".into(), "other.test".into(), "evil.test".into()])
        .unwrap().self_signed(&key).unwrap();
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .unwrap());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts = Arc::new(AtomicUsize::new(0));
    let counter = posts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (config, posts) = (config.clone(), counter.clone());
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let _ = serve_one(&mut tls, port, &posts);
            });
        }
    });
    TestSite { port, posts }
}

fn serve_one(tls: &mut impl ReadWrite, port: u16, posts: &AtomicUsize) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut byte)? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or("").split(' ');
    let (method, path) = (request.next().unwrap_or(""), request.next().unwrap_or(""));
    let header = |name: &str| head.split("\r\n").find_map(|l| l.split_once(':')
        .filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()));
    let host = header("host").unwrap_or_default();
    let host = host.split(':').next().unwrap_or("").to_owned();
    let length: usize = header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; length];
    tls.read_exact(&mut body)?;
    let (status, cookies, content_type, body) = match (method, host.as_str(), path) {
        ("GET", "sso.login.test", "/login") => ("200 OK", vec![
            "sid=1; Path=/; Secure; HttpOnly",
            "dom=1; Domain=login.test; Path=/; Secure",
            "part=1; Path=/; Secure; SameSite=None; Partitioned",
        ], "text/html", format!(r#"<!doctype html><html><body>
<form action="/session" method="post">
<input name="username" autocomplete="username">
<input type="password" name="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<img src="https://login.test:{port}/c"><img src="https://other.test:{port}/c">
<script>localStorage.setItem('k', 'v')</script>
</body></html>"#)),
        ("GET", "sso.login.test", "/redirect-now") => ("200 OK", Vec::new(), "text/html", format!(r#"<!doctype html><html><body>
<form action="/session" method="post">
<input name="username" autocomplete="username"><input type="password" name="password">
</form>
<script>location.replace('https://evil.test:{port}/login')</script>
</body></html>"#)),
        ("GET", "sso.login.test", "/redirect-later") => ("200 OK", Vec::new(), "text/html", format!(r#"<!doctype html><html><body>
<form action="/session" method="post">
<input name="username" autocomplete="username"><input type="password" name="password">
</form>
<script>setTimeout(() => location.href = 'https://evil.test:{port}/login', 1500)</script>
</body></html>"#)),
        ("GET", "evil.test", "/login") => ("200 OK", Vec::new(), "text/html", r#"<!doctype html><html><body>
<form action="/session" method="post">
<input name="username" autocomplete="username"><input type="password" name="password">
</form>
</body></html>"#.to_owned()),
        ("GET", "login.test", "/c") => ("200 OK", vec!["parent=1; Path=/; Secure; SameSite=None"], "image/gif", String::new()),
        ("GET", "other.test", "/c") => ("200 OK", vec!["other=1; Path=/; Secure; SameSite=None"], "image/gif", String::new()),
        ("POST", _, "/session") => {
            posts.fetch_add(1, Ordering::SeqCst);
            ("200 OK", Vec::new(), "text/plain", "signed in".into())
        }
        _ => ("404 Not Found", Vec::new(), "text/plain", String::new()),
    };
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len());
    for c in cookies {
        response.push_str(&format!("Set-Cookie: {c}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&body);
    tls.write_all(response.as_bytes())?;
    tls.flush()
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// `ASM_TEST_CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
/// cargo test -p asm-core --lib real_chrome -- --nocapture` (headless, temporary profile).
#[test]
fn real_chrome_fills_the_form_without_submitting_and_hands_over_the_sites_cookies() {
    let Some(chrome) = std::env::var_os("ASM_TEST_CHROME") else {
        eprintln!("skipped: set ASM_TEST_CHROME to a Chrome binary");
        return;
    };
    let site = serve_site();
    let tmp = tempfile::tempdir().unwrap();
    let switches = vec![
        "--headless=new".to_owned(),
        "--ignore-certificate-errors".to_owned(),
        "--host-resolver-rules=MAP *.test 127.0.0.1".to_owned(),
    ];
    let (core, host) = broker_manager(&tmp, Some((PathBuf::from(chrome), switches)));
    let url = format!("https://sso.login.test:{}/login", site.port);
    let origin = format!("https://sso.login.test:{}", site.port);
    let id = core.create_request(&host, "127.0.0.1", login_body("Exact", &url, &[], "real chrome"))
        .unwrap().request_id;
    approve(&core, &id, None, &[]).unwrap();
    let fields = "document.querySelector('[name=username]').value + '|' + document.querySelector('[name=password]').value";
    let expected = format!("tomsmith|{PASSWORD}");
    wait_for("both fields to be filled", || {
        core.broker.eval_in_page(&id, fields).and_then(|v| v.as_str().map(|s| s == expected)).unwrap_or(false)
    });
    assert_eq!(status(&core, &id).unwrap(), format!("filled password, username on {origin}; sign in, then hand over"));
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(site.posts.load(Ordering::SeqCst), 0, "the broker never submits");

    let profile = core.broker.profile_dir(&id);
    core.broker_handover(&id).unwrap();
    wait_ended(&core, &id);
    let state = core.request_state(&host.id, &id).unwrap();
    assert_eq!(state.status, RequestStatus::Approved, "{:?}", state.deny_reason);
    let Some(RequestResult::Get(result)) = state.result else { panic!("no storage state") };
    let exported: Value = serde_json::from_str(&result.files[0].content).unwrap();
    let mut names: Vec<&str> = exported["cookies"].as_array().unwrap().iter()
        .map(|c| c["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(names, ["dom", "sid"], "only cookies valid for sso.login.test, never partitioned ones: {exported}");
    assert_eq!(exported["origins"], json!([{ "origin": origin, "localStorage": [{ "name": "k", "value": "v" }] }]));
    assert!(!profile.exists(), "the profile is deleted");
    core.shutdown();
}

/// The approved page navigates the tab to an unapproved origin (at once, and after
/// the broker filled it): nothing is ever filled there.
#[test]
fn real_chrome_never_fills_a_page_the_approved_one_navigates_to() {
    let Some(chrome) = std::env::var_os("ASM_TEST_CHROME") else {
        eprintln!("skipped: set ASM_TEST_CHROME to a Chrome binary");
        return;
    };
    let site = serve_site();
    let tmp = tempfile::tempdir().unwrap();
    let switches = vec![
        "--headless=new".to_owned(),
        "--ignore-certificate-errors".to_owned(),
        "--host-resolver-rules=MAP *.test 127.0.0.1".to_owned(),
    ];
    let (core, host) = broker_manager(&tmp, Some((PathBuf::from(chrome), switches)));
    let approved = format!("https://sso.login.test:{}", site.port);
    let evil = format!("evil.test:{}", site.port);
    let fields = "document.querySelector('[name=username]').value + '|' + document.querySelector('[name=password]').value";
    for path in ["/redirect-now", "/redirect-later"] {
        let id = core.create_request(&host, "127.0.0.1", login_body("Exact", &format!("{approved}{path}"), &[], path))
            .unwrap().request_id;
        approve(&core, &id, None, &[]).unwrap();
        wait_for("the unapproved page", || core.broker.eval_in_page(&id,
            "location.host + '|' + document.readyState").is_some_and(|v| v == json!(format!("{evil}|complete"))));
        // Several fill passes run on the unapproved page.
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(core.broker.eval_in_page(&id, fields), Some(json!("|")), "{path}: nothing filled on {evil}");
        assert_eq!(status(&core, &id).unwrap(), format!("paused: https://{evil} is not approved"), "{path}");

        // The in-page guards alone refuse, whatever world or element they are given.
        let find = format!("({})({}, {})", crate::broker::fill::FIND_JS, json!(["password", "username"]), json!([&approved]));
        assert_eq!(core.broker.eval_in_page(&id, &find), Some(json!({ "origin": format!("https://{evil}"), "kind": null })));
        let fill = format!("({}).call(document.querySelector('[name=password]'), 'x', {})",
            crate::broker::fill::FILL_FN, json!([&approved]));
        assert_eq!(core.broker.eval_in_page(&id, &fill), Some(json!(false)));
        assert_eq!(core.broker.eval_in_page(&id, "document.querySelectorAll('[data-asm-fill]').length"), Some(json!(0)));
        assert_eq!(core.broker.eval_in_page(&id, fields), Some(json!("|")));

        // Hand-over with no document of the export origin open still exports its cookies.
        core.broker_handover(&id).unwrap();
        wait_ended(&core, &id);
        let state = core.request_state(&host.id, &id).unwrap();
        assert_eq!(state.status, RequestStatus::Approved, "{path}: {:?}", state.deny_reason);
        let Some(RequestResult::Get(result)) = state.result else { panic!("no storage state") };
        let exported: Value = serde_json::from_str(&result.files[0].content).unwrap();
        assert_eq!(exported["origins"], json!([]), "{path}");
    }
    assert_eq!(site.posts.load(Ordering::SeqCst), 0);
    core.shutdown();
}

#[test]
fn a_cancel_during_the_export_wins_over_the_hand_over() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let id = core.create_request(&host, "127.0.0.1", login_body("", &format!("{URL}?slow"), &[], "cancel late"))
        .unwrap().request_id;
    approve(&core, &id, None, &[]).unwrap();
    wait_for("the session", || status(&core, &id).is_some_and(|s| s.starts_with("waiting")));
    core.broker_handover(&id).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    core.broker_cancel(&id).unwrap();
    wait_ended(&core, &id);
    let state = core.request_state(&host.id, &id).unwrap();
    assert_eq!((state.status, state.deny_reason.as_deref()), (RequestStatus::Denied, Some(broker::DENY_CANCELLED)));
    assert!(core.broker_cancel(&id).is_err(), "an ended session takes no more controls");
    core.shutdown();
}

#[test]
fn a_failed_hand_over_stays_visible_and_missing_storage_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let start = |query: &str| {
        let id = core.create_request(&host, "127.0.0.1", login_body("", &format!("{URL}?{query}"), &[], query))
            .unwrap().request_id;
        approve(&core, &id, None, &[]).unwrap();
        wait_for("the session", || status(&core, &id).is_some_and(|s| s.starts_with("waiting")));
        id
    };
    let failing = start("storage-error");
    core.broker_handover(&failing).unwrap();
    let failed = "hand-over failed: Internal error";
    wait_for("the failure", || status(&core, &failing).as_deref() == Some(failed));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(status(&core, &failing).as_deref(), Some(failed), "kept until the next control");
    assert_eq!(core.request_state(&host.id, &failing).unwrap().status, RequestStatus::Pending, "no partial export");
    core.broker_handover(&failing).unwrap();
    wait_for("the second failure", || status(&core, &failing).as_deref() == Some(failed));
    core.broker_cancel(&failing).unwrap();
    wait_ended(&core, &failing);

    let missing = start("no-storage");
    core.broker_handover(&missing).unwrap();
    wait_ended(&core, &missing);
    let state = core.request_state(&host.id, &missing).unwrap();
    assert_eq!(state.status, RequestStatus::Approved);
    let Some(RequestResult::Get(result)) = state.result else { panic!("no storage state") };
    let exported: Value = serde_json::from_str(&result.files[0].content).unwrap();
    assert_eq!(exported["origins"], json!([]));
    core.shutdown();
}

#[test]
fn revoking_the_host_denies_its_sign_in_with_the_brokers_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, host) = broker_manager(&tmp, Some((fake_chrome(tmp.path()), Vec::new())));
    let live = core.create_request(&host, "127.0.0.1", login_body("", URL, &[], "live")).unwrap().request_id;
    approve(&core, &live, None, &[]).unwrap();
    let waiting = core.create_request(&host, "127.0.0.1", login_body("", URL, &[], "not approved")).unwrap().request_id;
    let profile = core.broker.profile_dir(&live);
    core.revoke_host(&host.id).unwrap();
    wait_ended(&core, &live);
    assert!(!profile.exists());
    let recent = core.snapshot().recent;
    let outcome = |id: &str| recent.iter().find(|r| r.id == id).map(|r| (r.outcome, r.deny_reason.clone())).unwrap();
    assert_eq!(outcome(&live), (ffi::RequestOutcome::Denied, Some(broker::DENY_REVOKED.into())));
    assert_eq!(outcome(&waiting), (ffi::RequestOutcome::Cancelled, Some("host revoked".into())));
    core.shutdown();
}
