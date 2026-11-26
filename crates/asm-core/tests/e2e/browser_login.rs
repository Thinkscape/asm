//! Browser login grants end to end (plan Verification 2, e2e 1–4): the real manager,
//! the real `asm` CLI and `asm proxy-router`, and the real iron-proxy. The vault login
//! item comes from a structured fixture provider behind a registered vault.

use super::*;
use asm_proto::crypto::{proxy_password, sha256};
use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};

const LOGIN_URL: &str = "https://login.test/session";
const SITE_USER: &str = "agent@login.test";
const SITE_PASSWORD: &str = "site-password-0123456789";
const BROWSER_CA_CN: &str = "Agents Secrets Manager Browser CA";
const NO_ROUTE: &str = "asm: no active login grant routes this host through asm";

/// The selected account has an old saved domain; the current domain matches a different user.
struct SiteLogin;

impl asm_core::vault::VaultProvider for SiteLogin {
    fn status(&self) -> asm_core::vault::VaultStatus {
        asm_core::vault::VaultStatus::Ready
    }

    fn list(&self) -> asm_core::error::Result<Vec<asm_core::vault::SecretMeta>> {
        Ok([("personal", "login.test"), ("site", "legacy.test")].map(|(key, host)| asm_core::vault::SecretMeta {
            key: key.into(), name: key.into(), kind: asm_proto::wire::SecretKind::Login,
            fields: vec!["username".into(), "password".into(), "totp".into()], uri_hosts: vec![host.into()],
            collections: vec![],
        }).into())
    }

    fn list_logins(&self) -> asm_core::error::Result<Vec<asm_core::vault::LoginMeta>> {
        Ok(self.list()?.into_iter().map(|meta| asm_core::vault::LoginMeta {
            username: Some(if meta.key == "site" { SITE_USER } else { "personal@login.test" }.into()), meta,
        }).collect())
    }

    fn read(&self, key: &str) -> asm_core::error::Result<Vec<(String, String)>> {
        if key == "personal" {
            return Ok(vec![("username".into(), "personal@login.test".into()), ("password".into(), "personal-fixture".into()),
                ("totp".into(), "000013".into())]);
        }
        if key != "site" {
            return Err(asm_core::error::CoreError::not_found("unknown fixture item"));
        }
        Ok(vec![("username".into(), SITE_USER.into()), ("password".into(), SITE_PASSWORD.into()), ("totp".into(), "730012".into())])
    }

    fn update(&self, _: &str, _: &str, _: &str) -> asm_core::error::Result<()> {
        Err(asm_core::error::CoreError::invalid("fixture is read-only"))
    }

    fn add(&self, _: &str, _: &str, _: &asm_core::vault::AddTarget) -> asm_core::error::Result<()> {
        Err(asm_core::error::CoreError::invalid("fixture is read-only"))
    }
}

/// Fixture operator: choose the requested identity even though another account has the exact host.
struct LoginApprover {
    manager: OnceLock<Arc<Manager>>,
    busy: Mutex<()>,
    details: Mutex<Vec<RequestDetail>>,
    errors: Mutex<Vec<String>>,
}

impl LoginApprover {
    fn run(&self) {
        let Some(manager) = self.manager.get() else { return };
        let _busy = self.busy.lock().unwrap();
        for pending in manager.snapshot().pending {
            let RequestDetail::Login { account: Some(account), broker: false, .. } = &pending.detail else { continue };
            let choices = manager.login_choices().unwrap();
            let selection = choices.items.into_iter().find(|c| c.username.as_ref() == Some(account)).unwrap();
            match manager.resolve_request(pending.id, Decision::ApproveLogin {
                selection, duration_secs: Some(900), fill_origins: Vec::new(),
            }) {
                Ok(()) => self.details.lock().unwrap().push(pending.detail),
                Err(error) => self.errors.lock().unwrap().push(error.to_string()),
            }
        }
    }
}

struct LoginObserver(Arc<LoginApprover>);

impl ManagerObserver for LoginObserver {
    fn changed(&self, topic: String) {
        if topic == "requests" {
            let approver = self.0.clone();
            std::thread::spawn(move || approver.run());
        }
    }
}

/// `asm proxy-router run`, killed on drop.
struct RouterProcess(std::process::Child);

impl Drop for RouterProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The response head and body; stops after the head of a `200` CONNECT answer, so the
/// stream is positioned at the tunnel's first byte.
fn read_response(r: &mut impl Read, connect: bool) -> (u16, String) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if r.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if connect && status == 200 {
        return (status, String::new());
    }
    let length = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
    });
    let mut body = Vec::new();
    match length {
        Some(n) => {
            body.resize(n, 0);
            r.read_exact(&mut body).unwrap();
        }
        // Without a length the answer ends when the peer closes.
        None => {
            let _ = r.read_to_end(&mut body);
        }
    }
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// `CONNECT authority` to `127.0.0.1:port`, optionally with the browser route marker
/// and Basic proxy credentials (`user:password`).
fn connect(port: u16, authority: &str, marked: bool, credentials: Option<&str>) -> (TcpStream, u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if marked {
        head.push_str("Asm-Browser-Route: 1\r\n");
    }
    if let Some(c) = credentials {
        let encoded = base64::engine::general_purpose::STANDARD.encode(c);
        head.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let (status, body) = read_response(&mut stream, true);
    (stream, status, body)
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// A TLS client handshake inside a tunnel, trusting only `ca_pem`.
fn handshake(stream: TcpStream, ca_pem: &str, sni: &str) -> std::io::Result<Tls> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), ServerName::try_from(sni.to_owned()).unwrap())
        .map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

/// The issuer common name of a DER certificate.
fn issuer_cn(der: &[u8]) -> String {
    /// (tag, contents, rest) of the DER element at the start of `b`.
    fn tlv(b: &[u8]) -> (u8, &[u8], &[u8]) {
        let (len, header) = match b[1] {
            l if l < 0x80 => (l as usize, 2),
            l => {
                let n = (l & 0x7f) as usize;
                (b[2..2 + n].iter().fold(0, |a, &x| a << 8 | x as usize), 2 + n)
            }
        };
        (b[0], &b[header..header + len], &b[header + len..])
    }
    let (_, cert, _) = tlv(der);
    let (_, tbs, _) = tlv(cert);
    let (tag, _, after_version) = tlv(tbs);
    let serial_on = if tag == 0xa0 { after_version } else { tbs };
    let (_, _, signature_on) = tlv(serial_on);
    let (_, _, issuer_on) = tlv(signature_on);
    let (_, mut names, _) = tlv(issuer_on);
    while !names.is_empty() {
        let (_, set, rest) = tlv(names);
        names = rest;
        let (_, attribute, _) = tlv(set);
        let (_, oid, value) = tlv(attribute);
        if oid == [0x55, 0x04, 0x03] {
            return String::from_utf8(tlv(value).1.to_vec()).unwrap();
        }
    }
    panic!("certificate issuer has no common name")
}

/// POST a login form inside a browser tunnel to `login.test`.
fn post_form(tls: &mut Tls, target: &str, body: &str) -> (u16, String) {
    write!(
        tls,
        "POST {target} HTTP/1.1\r\nHost: login.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    tls.flush().unwrap();
    read_response(tls, false)
}

/// curl through the proxy's tunnel listener, optionally with `-U user:password`.
fn curl_via_proxy(proxy_port: u16, url: &str, credentials: Option<&str>) -> u16 {
    let mut c = Command::new("curl");
    c.args(["-sS", "--max-time", "15", "-o", "/dev/null", "-w", "%{http_code}", "-x"])
        .arg(format!("http://127.0.0.1:{proxy_port}"));
    if let Some(credentials) = credentials {
        c.arg("-U").arg(credentials);
    }
    let o = c.arg(url).env_remove("NO_PROXY").env_remove("no_proxy").output().expect("run curl");
    String::from_utf8_lossy(&o.stdout).trim().parse().unwrap_or(0)
}

fn router_status(env: &Env) -> serde_json::Value {
    let out = env.run(&["proxy-router", "status", "--json"], None);
    assert_eq!(out.code, 0, "router status failed: {}", out.stderr);
    serde_json::from_str(&out.stdout).unwrap()
}

fn routed_hosts(env: &Env) -> Vec<String> {
    router_status(env)["routes"].as_array().unwrap().iter()
        .map(|r| format!("{}:{}", r["host"].as_str().unwrap(), r["port"]))
        .collect()
}

fn claim_files(proxy_dir: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(proxy_dir.join("login-claims")) {
        Ok(entries) => entries.map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "claim")).collect(),
        Err(_) => Vec::new(),
    }
}

/// `asm get --login-url` with the reaper off; returns the JSON result.
fn login_get(env: &Env, reason: &str) -> serde_json::Value {
    let out = env.run_env(
        &["get", "--json", "--wait", "30", "--login-url", LOGIN_URL, "--account", SITE_USER,
            "--site", "https://app.test", "--reason", reason],
        None,
        &[("ASM_NO_REAPER", "1")],
    );
    assert_eq!(out.code, 0, "login get failed: {}{}", out.stdout, out.stderr);
    serde_json::from_str(&out.stdout).expect("get JSON")
}

#[test]
fn browser_login_grant_end_to_end() {
    let bin_dir = workspace().join("dist/bin");
    assert!(
        bin_dir.join("iron-proxy").is_file(),
        "missing prerequisite {}; run `just proxy` before integration tests",
        bin_dir.join("iron-proxy").display()
    );
    let cli = build_cli();
    // Short path: the router's admin socket must fit sun_path.
    let tmp = tempfile::Builder::new().prefix("asml").tempdir_in("/tmp").unwrap();
    let data = tmp.path().join("data");
    let ports = free_ports(6);
    let (proxy_port, router_port) = (ports[0], ports[5]);
    let approver = Arc::new(LoginApprover {
        manager: OnceLock::new(), busy: Mutex::new(()),
        details: Mutex::new(Vec::new()), errors: Mutex::new(Vec::new()),
    });
    let manager = Manager::start_with(
        data.clone(), bin_dir, Arc::new(LoginObserver(approver.clone())),
        StartOptions {
            resume_key: Some([19; 32]),
            values_root: Some(tmp.path().join("values")),
            settings: vec![
                (keys::API_BIND.into(), json!("127.0.0.1")), (keys::API_PORT.into(), json!(0)),
                (keys::PROXY_BIND.into(), json!("127.0.0.1")),
                (keys::PROXY_PORT.into(), json!(proxy_port)),
                (keys::PROXY_HTTP_PORT.into(), json!(ports[1])),
                (keys::PROXY_HTTPS_PORT.into(), json!(ports[2])),
                (keys::PROXY_MGMT_PORT.into(), json!(ports[3])),
                (keys::PROXY_METRICS_PORT.into(), json!(ports[4])),
                (keys::PROXY_UPSTREAM_DENY_CIDRS.into(), json!(["192.0.2.0/24"])),
                (keys::PROXY_ALLOW_PLAIN_HTTP.into(), json!(true)),
                (keys::PROXY_HINTS.into(), json!(["127.0.0.1"])),
            ],
        },
    ).expect("start manager");
    approver.manager.set(manager.clone()).ok().unwrap();
    let shutdown = ShutdownManager(manager);
    let m = &shutdown.0;
    wait_healthy(m);

    let empty = tmp.path().join("empty.env");
    std::fs::write(&empty, "").unwrap();
    let vault = m.save_vault(VaultDraft {
        id: None, name: "Sites".into(),
        config: VaultConfig::EnvFile { path: empty.to_string_lossy().into_owned() },
        client_secret: String::new(), master_password: String::new(),
    }).unwrap();
    let mut entry = m.core().registry.get(&vault.id).unwrap();
    entry.provider = Arc::new(SiteLogin);
    m.core().registry.insert(entry);

    // Host A: paired, with its proxy router running.
    let env = Env { cli, config: tmp.path().join("config"), secrets: tmp.path().join("secrets") };
    let code = m.create_pairing_code("host A".into(), Some(3600), Some(1), vec!["127.0.0.1/8".into()]).unwrap();
    let out = env.run(&["pair", &m.general_settings().listening_on, &code.code], None);
    assert_eq!(out.code, 0, "pair failed: {}", out.stderr);
    let host: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.config.join("asm/host.json")).unwrap()).unwrap();
    let host_id = host["host_id"].as_str().unwrap().to_owned();
    let password = proxy_password(&sha256(host["token"].as_str().unwrap().as_bytes()));

    let sites = env.run(&["list", "--sites", "--json"], None);
    assert_eq!(sites.code, 0, "{}", sites.stderr);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&sites.stdout).unwrap(),
        json!({"sites":["legacy.test","login.test"]}));

    let no_router = env.run(&["get", "--login-url", LOGIN_URL, "--reason", "sign in"], None);
    assert_ne!(no_router.code, 0);
    assert!(no_router.stderr.contains("no asm proxy-router on this machine"), "{}", no_router.stderr);
    assert!(approver.details.lock().unwrap().is_empty(), "no request without a router");

    let router_log = std::fs::File::create(tmp.path().join("router.log")).unwrap();
    let _router = RouterProcess(
        Command::new(&env.cli)
            .args(["proxy-router", "run", "--port", &router_port.to_string()])
            .env("XDG_CONFIG_HOME", &env.config)
            .stdin(Stdio::null())
            .stdout(router_log.try_clone().unwrap())
            .stderr(router_log)
            .spawn()
            .expect("spawn asm proxy-router"),
    );
    wait_until("proxy router admin socket", || {
        std::os::unix::net::UnixStream::connect(env.config.join("asm/router.sock")).is_ok()
    });

    // 1. The browser loads the login page through the router (login.test doesn't resolve,
    // so the router answers 502), which the CLI's routing check requires. Then a login
    // grant for host A: one approval, a Proxied 15-minute lease bound to the form action,
    // and the route is live on the proxy and pushed to the router.
    let (_, status, _) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 502);
    let grant = login_get(&env, "sign in to login.test");
    assert!(approver.errors.lock().unwrap().is_empty(), "{:?}", approver.errors.lock().unwrap());
    {
        let details = approver.details.lock().unwrap();
        assert_eq!(details.len(), 1);
        let RequestDetail::Login { account, site, url, broker, fill_origins, .. } = &details[0]
            else { panic!("operator selection expected") };
        assert_eq!(account.as_deref(), Some(SITE_USER));
        assert_eq!(site.as_deref(), Some("https://app.test"));
        assert_eq!(url, LOGIN_URL);
        assert!(!*broker);
        assert!(fill_origins.is_empty(), "site hints must not widen the password destination");
    }
    assert_eq!(grant["login"]["url"], LOGIN_URL);
    assert_eq!(grant["mode"], "sentinel");
    assert_eq!(grant["hosts"], json!(["login.test"]));
    let lease_id = grant["lease_id"].as_str().unwrap().to_owned();
    let mut sentinel = String::new();
    for file in grant["files"].as_array().unwrap() {
        let content = std::fs::read_to_string(file["path"].as_str().unwrap()).unwrap();
        match file["field"].as_str().unwrap() {
            "password" => {
                assert_eq!(file["delivery"], "sentinel");
                sentinel = content;
            }
            "username" => {
                assert_eq!(file["delivery"], "raw");
                assert_eq!(content, SITE_USER);
            }
            "totp" => assert_eq!(content, "730012", "must not use the exact-host personal account"),
            other => panic!("unexpected login file {other}"),
        }
    }
    assert!(is_sentinel(&sentinel), "password file holds a sentinel");
    let lease = m.list_leases().into_iter().find(|l| l.lease_id == lease_id).unwrap();
    assert_eq!(lease.mode, asm_core::ffi::LeaseMode::Sentinel);
    assert_eq!(lease.hosts, ["login.test"]);
    assert_eq!(lease.host_id, host_id);
    let lifetime = lease.expires_at.unwrap().duration_since(lease.created_at).unwrap();
    assert_eq!(lifetime, Duration::from_secs(900));
    assert_eq!(routed_hosts(&env), ["login.test:443"]);
    let fresh = env.run_env(&["totp", &lease_id, "--json"], None, &[("ASM_NO_REAPER", "1")]);
    assert_eq!(fresh.code, 0, "{}", fresh.stderr);
    let receipt: serde_json::Value = serde_json::from_str(&fresh.stdout).unwrap();
    let files = receipt["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["field"], "totp");
    assert_eq!(std::fs::read_to_string(files[0]["path"].as_str().unwrap()).unwrap(), "730012");
    assert_eq!(approver.details.lock().unwrap().len(), 1, "continuation must not queue an approval");

    // 2. A marked CONNECT gets a leaf from the browser CA, only for the granted site.
    let ca_pem = m.core().proxy.browser_ca_pem().unwrap();
    let (stream, status, body) = connect(proxy_port, "login.test:443", true, None);
    assert_eq!(status, 200, "{body}");
    let tls = handshake(stream, &ca_pem, "login.test").expect("browser CA handshake");
    let leaf = &tls.conn.peer_certificates().unwrap()[0];
    assert_eq!(issuer_cn(leaf), BROWSER_CA_CN);
    drop(tls);
    let (_, status, body) = connect(proxy_port, "other.test:443", true, None);
    assert_eq!(status, 403);
    assert!(body.contains(NO_ROUTE), "{body}");
    // Without the marker the asm root issues the leaf, which a browser trusting only
    // the browser CA rejects.
    let (stream, status, body) = connect(proxy_port, "login.test:443", false, None);
    assert_eq!(status, 200, "{body}");
    assert!(handshake(stream, &ca_pem, "login.test").is_err(), "unmarked tunnels never use the browser CA");

    // The browser's path: through the router. The sentinel is valid only as the
    // password of a form POST to the exact form action, and only once.
    let (stream, status, body) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 200, "{body}");
    let mut tls = handshake(stream, &ca_pem, "login.test").expect("routed handshake");
    let (status, body) = post_form(&mut tls, "/other", &format!("user=a&password={sentinel}"));
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("asm: login sentinel not valid for POST https://login.test:443/other"), "{body}");
    assert!(claim_files(&data.join("proxy")).is_empty(), "an out-of-scope use claims nothing");

    let (stream, status, body) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 200, "{body}");
    let mut tls = handshake(stream, &ca_pem, "login.test").expect("routed handshake");
    let (status, body) = post_form(&mut tls, "/session", &format!("user=a&password={sentinel}"));
    // login.test has no address, so the swapped request cannot reach an upstream;
    // the claim happens before forwarding and consumes the grant anyway.
    assert_eq!(status, 502, "{body}");
    assert!(!body.contains(SITE_PASSWORD), "{body}");
    assert_eq!(claim_files(&data.join("proxy")).len(), 1, "the first use claims the grant");
    wait_until("login substitution activity", || {
        m.list_activity(asm_core::ffi::ActivityQuery {
            categories: vec!["proxy".into()], host_id: None, search: String::new(), before_id: None, limit: 100,
        }).iter().any(|r| r.kind == "substitution" && r.secret.as_deref() == Some("site")
            && r.summary.contains("body"))
    });

    let (stream, status, body) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 200, "{body}");
    let mut tls = handshake(stream, &ca_pem, "login.test").expect("routed handshake");
    let (status, body) = post_form(&mut tls, "/session", &format!("user=a&password={sentinel}"));
    assert_eq!(status, 403, "{body}");
    assert_eq!(body.trim_end(), ENDED_BODY);
    let routed = router_status(&env);
    assert_eq!(routed["last_routed"]["host"], "login.test");

    // 3. Revoking the lease withdraws the route within 2 s; the router then drops it.
    let revoked_at = Instant::now();
    m.revoke_lease(lease_id.clone()).unwrap();
    assert_ne!(env.run(&["totp", &lease_id], None).code, 0, "ended grants must not issue codes");
    loop {
        let (_, status, body) = connect(proxy_port, "login.test:443", true, None);
        if status == 403 {
            assert!(body.contains(NO_ROUTE), "{body}");
            break;
        }
        assert_eq!(status, 200, "{body}");
        assert!(revoked_at.elapsed() < Duration::from_secs(2), "route still live 2 s after revocation");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (_, status, body) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 403, "{body}");
    assert!(body.contains(NO_ROUTE), "{body}");
    assert!(routed_hosts(&env).is_empty(), "the router drops a withdrawn route");

    // 4. Proxy authentication: per-host credentials on the tunnel listener.
    let mut settings = m.proxy_settings();
    settings.require_auth = true;
    m.set_proxy_settings(settings).unwrap();
    wait_healthy(m);
    let (echo_port, seen) = echo_server();
    let echo_url = format!("http://127.0.0.1:{echo_port}/echo");
    assert_eq!(curl_via_proxy(proxy_port, &echo_url, None), 407);
    assert_eq!(curl_via_proxy(proxy_port, &echo_url, Some(&format!("{host_id}:wrong"))), 407);
    assert!(seen.lock().unwrap().is_empty(), "unauthenticated requests never reach the upstream");
    let credentials = format!("{host_id}:{password}");
    assert_eq!(curl_via_proxy(proxy_port, &echo_url, Some(&credentials)), 200);
    assert_eq!(seen.lock().unwrap().len(), 1);
    let (_, status, _) = connect(proxy_port, "login.test:443", true, None);
    assert_eq!(status, 407, "a marked CONNECT needs credentials too");

    // A new grant with authentication on: the CLI's route probe and the router both
    // authenticate as host A.
    let grant = login_get(&env, "sign in to login.test again");
    assert_eq!(grant["login"]["url"], LOGIN_URL);
    assert_eq!(routed_hosts(&env), ["login.test:443"]);
    let (stream, status, body) = connect(proxy_port, "login.test:443", true, Some(&credentials));
    assert_eq!(status, 200, "{body}");
    assert!(handshake(stream, &ca_pem, "login.test").is_ok());
    let (stream, status, body) = connect(router_port, "login.test:443", false, None);
    assert_eq!(status, 200, "{body}");
    let tls = handshake(stream, &ca_pem, "login.test").expect("routed handshake with proxy auth");
    assert_eq!(issuer_cn(&tls.conn.peer_certificates().unwrap()[0]), BROWSER_CA_CN);
}
