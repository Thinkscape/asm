//! Headless end-to-end test (plan Verification 3): a `Manager` on a temp data dir with an
//! auto-approving observer, the real `asm` CLI, the patched iron-proxy from
//! `dist/bin/iron-proxy`, and a recording HTTP echo server.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use asm_core::ffi::{RequestDetail, VaultConfig, VaultDraft};
use asm_core::settings as keys;
use asm_core::{Decision, Manager, ManagerObserver, StartOptions};
use asm_core::generator::{GeneratorClient, GeneratorConfig, GithubAppConfig, GithubAppGenerator};
use asm_core::store::GeneratorRecord;
use asm_proto::generators::{
    GenerationGrant, GenerationSelection, GithubGrant, GithubPermission, GithubRepository,
};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use serde_json::json;

const REAL_1: &str = "real-value-123";
const REAL_2: &str = "real-value-456";
const ENDED_BODY: &str = "asm: sentinel expired or revoked; run asm get again";

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Build the CLI into its own target dir (no lock contention with this cargo run).
fn build_cli() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace().join("target"));
    let target = base.join("e2e-cli");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let st = Command::new(cargo)
        .args(["build", "-q", "-p", "asm-cli", "--target-dir"])
        .arg(&target)
        .current_dir(workspace())
        .status()
        .expect("run cargo build -p asm-cli");
    assert!(st.success(), "cargo build -p asm-cli failed");
    target.join("debug/asm")
}

/// Approves everything except `get` requests whose reason contains "deny-me"; a `get`
/// whose reason contains "short-lease" gets a 3-second lease.
struct AutoApprover {
    manager: OnceLock<Arc<Manager>>,
    approvals: AtomicUsize,
    busy: Mutex<()>,
}

impl AutoApprover {
    fn run(&self) {
        let Some(m) = self.manager.get() else { return };
        let _g = self.busy.lock().unwrap();
        for p in m.snapshot().pending {
            let decision = match &p.detail {
                RequestDetail::Pair { .. } => {
                    // A bad name is refused and leaves the request pending with the error.
                    match m.resolve_request(
                        p.id.clone(),
                        Decision::ApprovePair {
                            name: "bad\u{202E}name".into(),
                            replace: false,
                        },
                    ) {
                        Err(asm_core::ManagerError::Failed { code, .. }) => {
                            assert_eq!(code, "invalid")
                        }
                        other => panic!("bad name accepted: {other:?}"),
                    }
                    let still = m.snapshot().pending.into_iter().find(|q| q.id == p.id);
                    assert!(still.is_some_and(|q| q.error.is_some()));
                    Decision::ApprovePair {
                        name: "  e2e friendly  ".into(),
                        replace: false,
                    }
                }
                RequestDetail::Get { reason, .. } if reason.contains("deny-me") => Decision::Deny {
                    reason: "provide a better reason".into(),
                },
                RequestDetail::Get {
                    raw_requested,
                    requested_hosts,
                    initial_hosts,
                    reason,
                    ..
                } => {
                    let hosts = if requested_hosts.is_empty() {
                        initial_hosts.iter().map(|h| h.normalized.clone()).collect()
                    } else {
                        requested_hosts.clone()
                    };
                    Decision::ApproveGet {
                        mode: if *raw_requested {
                            asm_core::ffi::LeaseMode::Raw
                        } else {
                            asm_core::ffi::LeaseMode::Sentinel
                        },
                        duration_secs: Some(if reason.contains("short-lease") {
                            3
                        } else {
                            3600
                        }),
                        hosts,
                        generation: None,
                    }
                }
                RequestDetail::Update { vault_id, .. } => Decision::ApproveWrite {
                    vault_id: vault_id.clone(),
                    collection_id: None,
                },
                RequestDetail::Add { targets, .. } => {
                    let Some(target) = targets.first() else { continue };
                    Decision::ApproveWrite { vault_id: target.vault_id.clone(), collection_id: None }
                }
            };
            let deny = matches!(decision, Decision::Deny { .. });
            if m.resolve_request(p.id.clone(), decision).is_ok() && !deny {
                self.approvals.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

struct Observer(Arc<AutoApprover>);

impl ManagerObserver for Observer {
    fn changed(&self, topic: String) {
        if topic == "requests" {
            let a = self.0.clone();
            std::thread::spawn(move || a.run());
        }
    }
}

/// HTTP/1.1 echo server: records each request's `X-Key` header and answers `x-key=<value>`.
fn echo_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let rec = rec.clone();
            std::thread::spawn(move || {
                let _ = serve_one(s, &rec);
            });
        }
    });
    (port, seen)
}

fn serve_one(s: TcpStream, rec: &Mutex<Vec<String>>) -> std::io::Result<()> {
    let mut r = BufReader::new(s.try_clone()?);
    let mut key = String::new();
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "x-key" => key = v.trim().to_string(),
                "content-length" => len = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    rec.lock().unwrap().push(key.clone());
    let out = format!("x-key={key}\n");
    let mut w = s;
    write!(
        w,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
        out.len()
    )?;
    w.flush()
}

fn free_ports(n: usize) -> Vec<u16> {
    let ls: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    ls.iter().map(|l| l.local_addr().unwrap().port()).collect()
}

struct Env {
    cli: PathBuf,
    config: PathBuf,
    secrets: PathBuf,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Env {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Out {
        self.run_env(args, stdin, &[])
    }

    fn run_env(&self, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Out {
        let mut c = Command::new(&self.cli);
        c.args(args)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("ASM_SECRETS_DIR", &self.secrets)
            .env("ASM_AGENT", "e2e")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("ASM_PAIRING_CODE")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("https_proxy")
            .env_remove("http_proxy")
            .env_remove("all_proxy")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("ASM_NO_REAPER")
            .envs(env.iter().copied())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().expect("spawn asm");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

/// `asm get` output → (mode line, hosts line, file paths).
fn parse_get(out: &str) -> (String, String, Vec<PathBuf>) {
    let mut mode = String::new();
    let mut hosts = String::new();
    let mut paths = Vec::new();
    for l in out.lines() {
        if let Some(v) = l.strip_prefix("mode: ") {
            mode = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("hosts: ") {
            hosts = v.trim().to_string();
        } else if l.starts_with('/') {
            paths.push(PathBuf::from(l.trim()));
        }
    }
    (mode, hosts, paths)
}

fn is_sentinel(s: &str) -> bool {
    s.len() == 44 && s.starts_with("asm_") && s[4..].bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Request through the proxy with `X-Key: key`; returns (status, body).
fn via_proxy(proxy_port: u16, url: &str, key: &str) -> (u16, String) {
    let o = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "-x",
        ])
        .arg(format!("http://127.0.0.1:{proxy_port}"))
        .arg("-H")
        .arg(format!("X-Key: {key}"))
        .arg(url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("run curl");
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    let (body, code) = s.rsplit_once('\n').unwrap_or(("", "0"));
    (code.trim().parse().unwrap_or(0), body.to_string())
}

fn wait_healthy(m: &Manager) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = m.proxy_status();
        if st.running && st.healthy {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "proxy not healthy: {:?}",
            st.error
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn set_plain_http(m: &Manager, on: bool) {
    let mut ps = m.proxy_settings();
    ps.allow_plain_http = on;
    m.set_proxy_settings(ps).expect("set proxy settings");
    wait_healthy(m);
}

#[test]
fn headless_end_to_end() {
    let bin_dir = workspace().join("dist/bin");
    assert!(
        bin_dir.join("iron-proxy").is_file(),
        "missing prerequisite {}; run `just proxy` before integration tests",
        bin_dir.join("iron-proxy").display()
    );
    let cli = build_cli();

    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let values_root = tmp.path().join("values");
    let env_file = tmp.path().join("demo.env");
    std::fs::write(&env_file, format!("# demo\nDEMO_TOKEN={REAL_1}\n")).unwrap();

    let ports = free_ports(5);
    let approver = Arc::new(AutoApprover {
        manager: OnceLock::new(),
        approvals: AtomicUsize::new(0),
        busy: Mutex::new(()),
    });
    let options = StartOptions {
        resume_key: Some([17; 32]),
        values_root: Some(values_root),
        settings: vec![
            (keys::API_BIND.into(), json!("127.0.0.1")),
            (keys::API_PORT.into(), json!(0)),
            (keys::PROXY_BIND.into(), json!("127.0.0.1")),
            (keys::PROXY_PORT.into(), json!(ports[0])),
            (keys::PROXY_HTTP_PORT.into(), json!(ports[1])),
            (keys::PROXY_HTTPS_PORT.into(), json!(ports[2])),
            (keys::PROXY_MGMT_PORT.into(), json!(ports[3])),
            (keys::PROXY_METRICS_PORT.into(), json!(ports[4])),
            (
                keys::PROXY_UPSTREAM_DENY_CIDRS.into(),
                json!(["192.0.2.0/24"]),
            ),
            (keys::PROXY_ALLOW_PLAIN_HTTP.into(), json!(true)),
            (keys::PROXY_HINTS.into(), json!(["127.0.0.1"])),
        ],
    };
    let m = Manager::start_with(
        data.clone(),
        bin_dir,
        Arc::new(Observer(approver.clone())),
        options,
    )
    .expect("start");
    approver.manager.set(m.clone()).ok().unwrap();
    let proxy_port = ports[0];
    let api = m.general_settings().listening_on;
    assert!(api.starts_with("127.0.0.1:"), "{api}");
    wait_healthy(&m);

    m.save_vault(VaultDraft {
        id: None,
        name: "demo".into(),
        config: VaultConfig::EnvFile {
            path: env_file.to_string_lossy().into_owned(),
        },
        client_secret: String::new(),
        master_password: String::new(),
    })
    .expect("add .env vault");

    let (echo_port, seen) = echo_server();
    let echo_url = format!("http://127.0.0.1:{echo_port}/echo");
    let env = Env {
        cli,
        config: tmp.path().join("config"),
        secrets: tmp.path().join("secrets"),
    };

    // Pairing-code networks: invalid entries are refused at creation.
    match m.create_pairing_code("bad".into(), None, None, vec!["10.0.0.0/33".into()]) {
        Err(asm_core::ManagerError::Failed { code, message }) => {
            assert_eq!(code, "invalid");
            assert!(message.contains("10.0.0.0/33"), "{message}");
        }
        other => panic!("invalid network accepted: {other:?}"),
    }
    // A code limited to another network is refused from 127.0.0.1 and keeps its use.
    let elsewhere = m
        .create_pairing_code(
            "elsewhere".into(),
            Some(3600),
            Some(1),
            vec!["192.0.2.0/24".into()],
        )
        .unwrap();
    assert_eq!(elsewhere.info.allowed_networks, ["192.0.2.0/24"]);
    let o = env.run(&["pair", &api, &elsewhere.code], None);
    assert_eq!(o.code, 6, "pair from outside: {}{}", o.stdout, o.stderr);
    assert!(
        o.stderr
            .contains("pairing code not valid from this address"),
        "{}",
        o.stderr
    );
    assert!(m.list_hosts().is_empty());
    let listed = m
        .list_pairing_codes()
        .into_iter()
        .find(|c| c.id == elsewhere.info.id)
        .unwrap();
    assert_eq!(
        listed.uses, 0,
        "a network mismatch does not use up the code"
    );
    m.revoke_pairing_code(elsewhere.info.id.clone()).unwrap();

    // Unattended pairing with a code limited to loopback.
    let code = m
        .create_pairing_code(
            "e2e".into(),
            Some(3600),
            Some(1),
            vec!["127.0.0.1/8".into()],
        )
        .unwrap();
    assert_eq!(code.info.allowed_networks, ["127.0.0.0/8"]);
    let o = env.run(&["pair", &api, &code.code], None);
    assert_eq!(o.code, 0, "pair: {}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("paired: "), "{}", o.stdout);
    let hosts = m.list_hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].name, hosts[0].info.hostname,
        "unattended pairing names the host after its hostname"
    );
    let first_host = hosts[0].host_id.clone();
    let first_hostname = hosts[0].info.hostname.clone();
    assert_eq!(
        approver.approvals.load(Ordering::SeqCst),
        0,
        "unattended pairing needs no popup"
    );

    // get --hosts 127.0.0.1 → sentinel file.
    let o = env.run(
        &[
            "get",
            "--wait",
            "30",
            "--hosts",
            "127.0.0.1",
            "DEMO_TOKEN",
            "e2e: call the echo server",
        ],
        None,
    );
    assert_eq!(o.code, 0, "get: {}{}", o.stdout, o.stderr);
    let (mode, hosts, paths) = parse_get(&o.stdout);
    assert_eq!(mode, "sentinel");
    assert_eq!(hosts, "127.0.0.1");
    assert_eq!(paths.len(), 1);
    let sentinel = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(is_sentinel(&sentinel), "file holds a sentinel");
    let approvals = approver.approvals.load(Ordering::SeqCst);
    assert_eq!(approvals, 1);
    wait_healthy(&m);

    // Through the proxy: the server sees the real value, the client only the sentinel.
    let (status, body) = via_proxy(proxy_port, &echo_url, &sentinel);
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        seen.lock().unwrap().last().map(String::as_str),
        Some(REAL_1)
    );
    assert!(
        body.contains(&sentinel),
        "response is redacted back to the sentinel"
    );
    assert!(!body.contains(REAL_1));

    // Unapproved host → 403.
    let (status, body) = via_proxy(proxy_port, "http://unapproved.invalid/", &sentinel);
    assert_eq!(status, 403);
    assert!(
        body.contains("asm: sentinel not valid for this host or scheme"),
        "{body}"
    );

    // A second get without --hosts reuses the lease (no new approval).
    let o = env.run(
        &[
            "get",
            "--wait",
            "30",
            "DEMO_TOKEN",
            "e2e: call the echo server",
        ],
        None,
    );
    assert_eq!(o.code, 0, "get again: {}{}", o.stdout, o.stderr);
    let (_, hosts, paths) = parse_get(&o.stdout);
    assert_eq!(hosts, "127.0.0.1");
    assert_eq!(std::fs::read_to_string(&paths[0]).unwrap(), sentinel);
    assert_eq!(
        approver.approvals.load(Ordering::SeqCst),
        approvals,
        "no new approval"
    );

    // Plain-HTTP substitution off → 403; back on → works again.
    set_plain_http(&m, false);
    let before = seen.lock().unwrap().len();
    let (status, _) = via_proxy(proxy_port, &echo_url, &sentinel);
    assert_eq!(status, 403);
    assert_eq!(seen.lock().unwrap().len(), before, "upstream not called");
    set_plain_http(&m, true);
    let (status, _) = via_proxy(proxy_port, &echo_url, &sentinel);
    assert_eq!(status, 200);

    // Revoke → 403 and nothing new recorded.
    let lease = m
        .list_leases()
        .into_iter()
        .find(|l| l.status == asm_core::ffi::LeaseStatus::Active)
        .unwrap();
    m.revoke_lease(lease.lease_id.clone()).unwrap();
    let before = seen.lock().unwrap().len();
    let (status, body) = via_proxy(proxy_port, &echo_url, &sentinel);
    assert_eq!(status, 403);
    assert!(body.contains(ENDED_BODY), "{body}");
    assert_eq!(seen.lock().unwrap().len(), before);
    // An ended sentinel gets the same answer wherever it is sent.
    let (status, body) = via_proxy(proxy_port, "http://unapproved.invalid/", &sentinel);
    assert_eq!(status, 403);
    assert!(body.contains(ENDED_BODY), "{body}");

    // A short lease ends at the proxy within about a second of its expiry.
    let o = env.run(
        &[
            "get",
            "--wait",
            "30",
            "--hosts",
            "127.0.0.1",
            "DEMO_TOKEN",
            "e2e: short-lease expiry",
        ],
        None,
    );
    assert_eq!(o.code, 0, "short get: {}{}", o.stdout, o.stderr);
    let (_, _, paths) = parse_get(&o.stdout);
    let short = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(is_sentinel(&short) && short != sentinel);
    let short_lease = m
        .list_leases()
        .into_iter()
        .find(|l| l.status == asm_core::ffi::LeaseStatus::Active)
        .unwrap();
    let expires = short_lease.expires_at.expect("short lease expires");
    let (status, body) = via_proxy(proxy_port, &echo_url, &short);
    assert_eq!(status, 200, "short lease before expiry: {body}");
    let check_at = expires + Duration::from_millis(1200);
    if let Ok(d) = check_at.duration_since(std::time::SystemTime::now()) {
        std::thread::sleep(d);
    }
    let before = seen.lock().unwrap().len();
    let (status, body) = via_proxy(proxy_port, &echo_url, &short);
    let answered = std::time::SystemTime::now();
    assert_eq!(status, 403, "short lease after expiry: {body}");
    assert!(body.contains(ENDED_BODY), "{body}");
    assert!(
        answered <= expires + Duration::from_secs(2),
        "answered {:?} after expiry",
        answered.duration_since(expires)
    );
    assert_eq!(seen.lock().unwrap().len(), before, "upstream not called");
    let ended = m
        .list_leases()
        .into_iter()
        .find(|l| l.lease_id == short_lease.lease_id)
        .unwrap();
    assert_eq!(ended.status, asm_core::ffi::LeaseStatus::Expired);

    // A new sentinel lease, then a raw lease.
    let o = env.run(
        &[
            "get",
            "--wait",
            "30",
            "--hosts",
            "127.0.0.1",
            "DEMO_TOKEN",
            "e2e: call the echo server again",
        ],
        None,
    );
    assert_eq!(o.code, 0, "get: {}{}", o.stdout, o.stderr);
    let (_, _, paths) = parse_get(&o.stdout);
    let sentinel2 = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(is_sentinel(&sentinel2) && sentinel2 != sentinel);

    let o = env.run(
        &[
            "get",
            "--raw",
            "--wait",
            "30",
            "DEMO_TOKEN",
            "e2e: a tool that cannot use the proxy",
        ],
        None,
    );
    assert_eq!(o.code, 0, "get --raw: {}{}", o.stdout, o.stderr);
    let (mode, _, paths) = parse_get(&o.stdout);
    assert_eq!(mode, "raw");
    assert!(o.stdout.contains("hosts: none (raw value)"), "{}", o.stdout);
    assert_eq!(std::fs::read_to_string(&paths[0]).unwrap(), REAL_1);
    let raw_lease = m
        .list_leases()
        .into_iter()
        .find(|l| l.mode == asm_core::ffi::LeaseMode::Raw)
        .unwrap();

    // update → file rewritten, raw lease revoked, the active sentinel delivers the new value.
    let o = env.run(
        &["update", "--wait", "30", "DEMO_TOKEN"],
        Some(&format!("{REAL_2}\n")),
    );
    assert_eq!(o.code, 0, "update: {}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("updated DEMO_TOKEN in demo"),
        "{}",
        o.stdout
    );
    assert!(
        std::fs::read_to_string(&env_file)
            .unwrap()
            .contains(&format!("DEMO_TOKEN={REAL_2}"))
    );
    let raw_now = m
        .list_leases()
        .into_iter()
        .find(|l| l.lease_id == raw_lease.lease_id)
        .unwrap();
    assert_eq!(raw_now.status, asm_core::ffi::LeaseStatus::Revoked);
    wait_healthy(&m);
    let (status, body) = via_proxy(proxy_port, &echo_url, &sentinel2);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        seen.lock().unwrap().last().map(String::as_str),
        Some(REAL_2)
    );
    assert!(!body.contains(REAL_2));

    // add of an existing name → exists (exit 5), no popup.
    let o = env.run(
        &["add", "--wait", "5", "DEMO_TOKEN"],
        Some("whatever-value\n"),
    );
    assert_eq!(o.code, 5, "add: {}{}", o.stdout, o.stderr);

    // A denied get → exit 3 with the reason.
    let o = env.run(
        &[
            "get",
            "--raw",
            "--wait",
            "30",
            "DEMO_TOKEN",
            "deny-me: no context",
        ],
        None,
    );
    assert_eq!(o.code, 3, "denied get: {}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("provide a better reason"), "{}", o.stderr);

    // The proxy log never holds real values.
    let log = std::fs::read_to_string(data.join("logs/proxy.log")).unwrap_or_default();
    assert!(!log.is_empty(), "proxy log written");
    assert!(
        !log.contains(REAL_1) && !log.contains(REAL_2),
        "proxy log leaks a value"
    );

    // Interactive pairing: the popup's friendly name becomes the host's name.
    let env2 = Env {
        cli: env.cli.clone(),
        config: tmp.path().join("config2"),
        secrets: tmp.path().join("secrets2"),
    };
    let o = env2.run(&["pair", &api], None);
    assert_eq!(o.code, 0, "interactive pair: {}{}", o.stdout, o.stderr);
    let named = m
        .list_hosts()
        .into_iter()
        .find(|h| h.host_id != first_host)
        .expect("second host listed");
    assert_eq!(named.name, "e2e friendly");
    assert!(
        m.snapshot()
            .recent
            .iter()
            .any(|r| r.host_label == "e2e friendly"),
        "recent pairing request shows the chosen name"
    );

    // Renaming shows everywhere the host is named; empty = back to the hostname.
    m.rename_host(first_host.clone(), "Agent box".into())
        .unwrap();
    let leases = m.list_leases();
    assert!(leases.iter().any(|l| l.host_id == first_host));
    assert!(
        leases
            .iter()
            .filter(|l| l.host_id == first_host)
            .all(|l| l.host_label == "Agent box" && l.hostname == first_hostname)
    );
    assert!(
        m.snapshot()
            .recent
            .iter()
            .any(|r| r.host_label == "Agent box"),
        "recent requests follow the rename"
    );
    assert!(m.rename_host(first_host.clone(), "x\u{7}".into()).is_err());
    m.rename_host(first_host.clone(), " ".into()).unwrap();
    let h = m
        .list_hosts()
        .into_iter()
        .find(|h| h.host_id == first_host)
        .unwrap();
    assert_eq!(h.name, first_hostname);

    // Activity log: the flow is recorded, and no row holds a real value.
    let query = |categories: &[&str], host: Option<&str>| asm_core::ffi::ActivityQuery {
        categories: categories.iter().map(|c| c.to_string()).collect(),
        host_id: host.map(str::to_string),
        search: String::new(),
        before_id: None,
        limit: 1000,
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let rows = loop {
        let rows = m.list_activity(query(&[], None));
        let subs = rows
            .iter()
            .filter(|r| r.category == "proxy" && r.kind == "substitution")
            .count();
        // Two substituted requests through the first lease, one through the second.
        if subs >= 3 || Instant::now() > deadline {
            break rows;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    for r in &rows {
        let text = format!(
            "{} {} {:?} {:?}",
            r.summary, r.host_label, r.secret, r.detail
        );
        assert!(
            !text.contains(REAL_1) && !text.contains(REAL_2),
            "activity row leaks a value: {text}"
        );
        assert!(r.id > 0);
    }
    let has = |category: &str, kind: &str| {
        rows.iter()
            .any(|r| r.category == category && r.kind == kind)
    };
    for (category, kind) in [
        ("vaults", "added"),
        ("pairing", "paired_with_code"),
        ("pairing", "code_rejected_network"),
        ("pairing", "requested"),
        ("pairing", "approved"),
        ("pairing", "renamed"),
        ("requests", "requested"),
        ("requests", "approved"),
        ("requests", "reused"),
        ("requests", "denied"),
        ("leases", "created"),
        ("leases", "revoked"),
        ("proxy", "started"),
        ("proxy", "substitution"),
        ("proxy", "rejected"),
        ("leases", "expired"),
    ] {
        assert!(has(category, kind), "missing activity {category}/{kind}");
    }
    assert!(
        rows.iter().any(|r| r.category == "proxy"
            && r.kind == "rejected"
            && r.summary.contains("rejected: lease expired or revoked")),
        "ended sentinel rejection logged"
    );
    let sub = rows
        .iter()
        .find(|r| r.category == "proxy" && r.kind == "substitution")
        .unwrap();
    assert_eq!(sub.secret.as_deref(), Some("DEMO_TOKEN"));
    assert_eq!(sub.host_id.as_deref(), Some(first_host.as_str()));
    assert!(
        sub.summary.contains("substituted in header:X-Key"),
        "{}",
        sub.summary
    );
    assert!(
        sub.detail.as_deref().unwrap_or("").contains("lease_id"),
        "{:?}",
        sub.detail
    );
    let revoked: Vec<&str> = rows
        .iter()
        .filter(|r| r.category == "leases" && r.kind == "revoked")
        .map(|r| r.summary.as_str())
        .collect();
    assert!(
        revoked
            .iter()
            .any(|s| s.contains("revoked by the operator"))
            && revoked.iter().any(|s| s.contains("secret updated")),
        "{revoked:?}"
    );
    let denied = rows
        .iter()
        .find(|r| r.category == "requests" && r.kind == "denied")
        .unwrap();
    assert!(
        denied.summary.contains("provide a better reason"),
        "{}",
        denied.summary
    );
    // Filters: category, host, search and paging.
    let proxy_rows = m.list_activity(query(&["proxy"], None));
    assert!(!proxy_rows.is_empty() && proxy_rows.iter().all(|r| r.category == "proxy"));
    let host_rows = m.list_activity(query(&[], Some(&first_host)));
    assert!(
        !host_rows.is_empty()
            && host_rows
                .iter()
                .all(|r| r.host_id.as_deref() == Some(first_host.as_str()))
    );
    assert!(
        host_rows.iter().all(|r| r.host_label == first_hostname),
        "host label is the current friendly name"
    );
    let mut search = query(&[], None);
    search.search = "e2e friendly".into();
    let found = m.list_activity(search);
    assert!(
        !found.is_empty()
            && found
                .iter()
                .all(|r| r.host_label == "e2e friendly" || r.summary.contains("e2e friendly"))
    );
    let mut page = query(&[], None);
    page.limit = 2;
    let first_page = m.list_activity(page.clone());
    assert_eq!(first_page.len(), 2);
    page.before_id = Some(first_page[1].id);
    let second_page = m.list_activity(page);
    assert!(second_page.iter().all(|r| r.id < first_page[1].id));
    assert!(rows.windows(2).all(|w| w[0].id > w[1].id), "newest first");
    assert_eq!(rows[0].id, first_page[0].id);

    // Names switch from bare to vault-prefixed (a second vault with a colliding key):
    // existing leases keep working and keep their files.
    let o = env.run(
        &[
            "get",
            "--hosts",
            "127.0.0.1",
            "DEMO_TOKEN",
            "e2e: call the echo server again",
        ],
        None,
    );
    assert_eq!(o.code, 0, "get while bare: {}{}", o.stdout, o.stderr);
    let (_, _, old_paths) = parse_get(&o.stdout);
    assert_eq!(old_paths, vec![env.secrets.join("DEMO_TOKEN")]);
    let old_sentinel = std::fs::read_to_string(&old_paths[0]).unwrap();
    assert_eq!(old_sentinel, sentinel2, "the active lease from before");
    let lease_id = m
        .list_leases()
        .into_iter()
        .find(|l| {
            l.status == asm_core::ffi::LeaseStatus::Active
                && l.mode == asm_core::ffi::LeaseMode::Sentinel
        })
        .unwrap()
        .lease_id;
    let approvals = approver.approvals.load(Ordering::SeqCst);

    let other_file = tmp.path().join("other.env");
    std::fs::write(&other_file, "DEMO_TOKEN=other-vault-value\n").unwrap();
    m.save_vault(VaultDraft {
        id: None,
        name: "other".into(),
        config: VaultConfig::EnvFile {
            path: other_file.to_string_lossy().into_owned(),
        },
        client_secret: String::new(),
        master_password: String::new(),
    })
    .expect("add a second .env vault");
    wait_healthy(&m);

    let o = env.run(&["list"], None);
    assert_eq!(o.code, 0, "list: {}{}", o.stdout, o.stderr);
    let listed: Vec<&str> = o.stdout.lines().collect();
    assert!(
        listed.contains(&"demo/DEMO_TOKEN") && listed.contains(&"other/DEMO_TOKEN"),
        "{listed:?}"
    );
    assert!(!listed.contains(&"DEMO_TOKEN"), "{listed:?}");
    assert_eq!(
        std::fs::read_to_string(&old_paths[0]).unwrap(),
        old_sentinel,
        "old files untouched"
    );

    let (status, body) = via_proxy(proxy_port, &echo_url, &old_sentinel);
    assert_eq!(status, 200, "old sentinel after the switch: {body}");
    assert_eq!(
        seen.lock().unwrap().last().map(String::as_str),
        Some(REAL_2)
    );

    // The bare name the lease was taken under still finds it (no new approval).
    let o = env.run(
        &["get", "DEMO_TOKEN", "e2e: same lease after the switch"],
        None,
    );
    assert_eq!(
        o.code, 0,
        "bare get after the switch: {}{}",
        o.stdout, o.stderr
    );
    let (mode, hosts, paths) = parse_get(&o.stdout);
    assert_eq!((mode.as_str(), hosts.as_str()), ("sentinel", "127.0.0.1"));
    assert_eq!(paths, old_paths, "files keep the paths decided at approval");
    assert_eq!(std::fs::read_to_string(&paths[0]).unwrap(), old_sentinel);
    assert_eq!(
        approver.approvals.load(Ordering::SeqCst),
        approvals,
        "no new approval"
    );

    let o = env.run(&["list", "--json"], None);
    assert_eq!(o.code, 0, "list --json: {}{}", o.stdout, o.stderr);
    let listed: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    let entry = |name: &str| {
        listed["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("{name} listed"))
            .clone()
    };
    assert_eq!(
        entry("demo/DEMO_TOKEN")["lease"]["lease_id"],
        lease_id.as_str()
    );
    assert!(entry("other/DEMO_TOKEN")["lease"].is_null());

    // update under the bare name reaches the leased secret too.
    let o = env.run(&["update", "DEMO_TOKEN"], Some("real-value-789\n"));
    assert_eq!(
        o.code, 0,
        "bare update after the switch: {}{}",
        o.stdout, o.stderr
    );
    assert!(
        o.stdout.contains("updated demo/DEMO_TOKEN in demo"),
        "{}",
        o.stdout
    );
    assert!(
        std::fs::read_to_string(&env_file)
            .unwrap()
            .contains("DEMO_TOKEN=real-value-789")
    );
    assert_eq!(
        std::fs::read_to_string(&other_file).unwrap(),
        "DEMO_TOKEN=other-vault-value\n"
    );

    // Revoking still works: 403 at the proxy, files gone on the next command.
    m.revoke_lease(lease_id).unwrap();
    let (status, _) = via_proxy(proxy_port, &echo_url, &old_sentinel);
    assert_eq!(status, 403);
    let o = env.run(&["list"], None);
    assert_eq!(o.code, 0);
    assert!(!old_paths[0].exists(), "revoked lease files removed");
    // Without a lease the bare name is ambiguous again.
    let o = env.run(
        &["get", "--wait", "5", "DEMO_TOKEN", "e2e: no lease any more"],
        None,
    );
    assert_eq!(o.code, 5, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("ambiguous"), "{}", o.stderr);

    m.shutdown();
}

/// The issuer and resource server are real HTTP peers. Only their transport and
/// root-key lookup are injected; approvals, issuance validation and delivery are real.
struct LocalHttp {
    port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    errors: Arc<Mutex<Vec<String>>>,
}

struct LocalRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl LocalHttp {
    fn start(
        reply: impl Fn(LocalRequest) -> Result<(u16, serde_json::Value), String>
        + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let failures = errors.clone();
        let worker = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // On Darwin accepted sockets inherit O_NONBLOCK. Only accept() is polled;
                        // the HTTP parser must wait for headers and body bytes up to its timeout.
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        let response = read_local_request(&stream)
                            .map_err(|e| format!("local HTTP request could not be read: {e}"))
                            .and_then(&reply);
                        let (status, value) = response.unwrap_or_else(|error| {
                            failures.lock().unwrap().push(error);
                            (422, json!({"error":"isolated fixture rejected request"}))
                        });
                        let body = serde_json::to_vec(&value).unwrap();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        ).and_then(|_| stream.write_all(&body));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { port, stop, worker: Some(worker), errors }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn assert_clean(&self) {
        let errors = self.errors.lock().unwrap();
        assert!(errors.is_empty(), "local HTTP fixture rejected requests: {errors:?}");
    }
}

impl Drop for LocalHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn read_local_request(stream: &TcpStream) -> std::io::Result<LocalRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut words = first.split_whitespace();
    let method = words.next().unwrap_or("").to_owned();
    let target = words.next().unwrap_or("").to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers.get("content-length")
        .and_then(|length| length.parse::<usize>().ok()).unwrap_or(0);
    if length > 64 * 1024 {
        return Err(std::io::Error::other("oversized fixture request"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(LocalRequest { method, target, headers, body })
}

#[test]
fn local_http_waits_for_the_complete_request_body() {
    let server = LocalHttp::start(|request| {
        assert_eq!(request.body, b"test");
        Ok((200, json!("received")))
    });
    let mut client = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    client.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nte").unwrap();

    // No response is valid while two declared body bytes are still outstanding.
    client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut byte = [0; 1];
    assert!(matches!(client.peek(&mut byte), Err(e) if matches!(e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)), "fixture answered an incomplete request");
    client.write_all(b"st").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    server.assert_clean();
}

struct IssuedToken {
    token: String,
    expires_at: i64,
    org_repo: bool,
}

struct GithubFixtureState {
    issued: Vec<IssuedToken>,
    revoked: Vec<String>,
    post_bodies: Vec<serde_json::Value>,
    next_lifetime: i64,
    repository_checks: usize,
}

struct GithubFixture {
    http: LocalHttp,
    config: GithubAppConfig,
    pem: String,
    state: Arc<Mutex<GithubFixtureState>>,
}

fn repository(id: u64, full_name: &str) -> GithubRepository {
    GithubRepository { id, full_name: full_name.into() }
}

fn approved_grant(installation_id: u64) -> GithubGrant {
    GithubGrant {
        installation_id,
        repositories: vec![repository(202, "acme/web")],
        permissions: BTreeMap::from([
            ("contents".into(), GithubPermission::Read),
            ("metadata".into(), GithubPermission::Read),
        ]),
    }
}

impl GithubFixture {
    fn new(client_id: &str, installation_id: u64, other_repository: u64, org_installation: Option<u64>) -> Self {
        let private = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let pem = private.to_pkcs1_pem(Default::default()).unwrap().to_string();
        let public = rsa::PublicKey::from(&private)
            .to_pkcs1_pem(Default::default()).unwrap();
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public.as_bytes()).unwrap();
        let client_id = client_id.to_owned();
        let issuer = client_id.clone();
        let state = Arc::new(Mutex::new(GithubFixtureState {
            issued: Vec::new(),
            revoked: Vec::new(),
            post_bodies: Vec::new(),
            next_lifetime: 3600,
            repository_checks: 0,
        }));
        let serving = state.clone();
        let http = LocalHttp::start(move |request| {
            for (name, expected) in [
                ("accept", "application/vnd.github+json"),
                ("x-github-api-version", "2026-03-10"),
            ] {
                if request.headers.get(name).map(String::as_str) != Some(expected) {
                    return Err(format!("GitHub request missing required {name} header"));
                }
            }
            if !request.headers.get("user-agent").is_some_and(|agent| agent.starts_with("asm/")) {
                return Err("GitHub User-Agent is missing".into());
            }
            let bearer = request.headers.get("authorization")
                .and_then(|header| header.strip_prefix("Bearer "))
                .ok_or("GitHub bearer authentication missing")?;
            let mint_path = format!("/app/installations/{installation_id}/access_tokens");
            let org_repo = org_installation.is_some_and(|id| request.target == format!("/app/installations/{id}/access_tokens"));
            if request.method == "POST" && (request.target == mint_path || org_repo) {
                let jwt = jsonwebtoken::decode::<serde_json::Value>(
                    bearer, &decoding_key,
                    &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
                ).map_err(|_| "GitHub JWT signature validation failed")?;
                let now = asm_core::manager::now();
                let issued_at = jwt.claims["iat"].as_i64().ok_or("JWT iat missing")?;
                let expiry = jwt.claims["exp"].as_i64().ok_or("JWT exp missing")?;
                if jwt.claims["iss"].as_str() != Some(issuer.as_str())
                    || !(now - 65..=now - 55).contains(&issued_at)
                    || expiry - issued_at != 660
                {
                    return Err("JWT issuer or authorization window is incorrect".into());
                }
                let body: serde_json::Value = serde_json::from_slice(&request.body)
                    .map_err(|_| "GitHub mint request is not JSON")?;
                let permissions = if org_repo { json!({"metadata":"read"}) } else { json!({"contents":"read","metadata":"read"}) };
                if body != json!({"repository_ids":[if org_repo { 505 } else { 202 }], "permissions":permissions}) {
                    return Err("GitHub mint did not use the exact operator-approved scope".into());
                }
                let mut state = serving.lock().unwrap();
                state.post_bodies.push(body);
                let token = format!("fixture.{issuer}.{}.installation-token", state.issued.len() + 1);
                let expires_at = now + state.next_lifetime;
                state.next_lifetime = 3600;
                state.issued.push(IssuedToken { token: token.clone(), expires_at, org_repo });
                // Omit repositories deliberately: real adapter must enumerate this
                // token's actual scope before the manager can publish it.
                return Ok((201, json!({
                    "token":token,
                    "expires_at":asm_proto::time::fmt_rfc3339(asm_core::manager::to_system_time(expires_at)),
                    "permissions":permissions
                })));
            }
            let mut state = serving.lock().unwrap();
            let Some(issued) = state.issued.iter().find(|issued| issued.token == bearer) else {
                return Err("unknown installation token used at GitHub".into());
            };
            let org_repo = issued.org_repo;
            if request.method == "DELETE" && request.target == "/installation/token" {
                state.revoked.push(bearer.to_owned());
                return Ok((204, serde_json::Value::Null));
            }
            if request.method == "GET"
                && request.target == "/installation/repositories?per_page=100&page=1"
            {
                state.repository_checks += 1;
                return Ok((200, json!({
                    "total_count":1,"repositories":[if org_repo {
                        json!({"id":505,"full_name":"other-org/platform"})
                    } else { json!({"id":202,"full_name":"acme/web"}) }]
                })));
            }
            Err("unexpected GitHub method or endpoint".into())
        });
        let mut ceiling = approved_grant(installation_id);
        ceiling.repositories.push(repository(other_repository, "acme/other"));
        ceiling.permissions.insert("contents".into(), GithubPermission::Write);
        ceiling.canonicalize().unwrap();
        let mut installations = vec![ceiling];
        if let Some(id) = org_installation {
            installations.push(GithubGrant {
                installation_id: id, repositories: vec![repository(505, "other-org/platform")],
                permissions: BTreeMap::from([("metadata".into(), GithubPermission::Read)]),
            });
        }
        Self {
            http, config: GithubAppConfig { client_id, installations },
            pem, state,
        }
    }

    fn install(&self, manager: &Manager, id: &str, name: &str) {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build().unwrap();
        let generator = GithubAppGenerator::with_client_for_tests(
            &self.config, &self.pem, client,
            reqwest::Url::parse(&self.http.url("/")).unwrap(),
        ).unwrap();
        manager.core().install_generator_client(
            GeneratorRecord {
                id: id.into(), name: name.into(),
                config: GeneratorConfig::GithubApp(self.config.clone()),
                revision: 1, position: self.config.installations[0].installation_id as i64,
            },
            Arc::new(GeneratorClient::GithubApp(generator)),
        ).unwrap();
    }

    fn count(&self) -> usize {
        self.state.lock().unwrap().issued.len()
    }

    fn token(&self, index: usize) -> String {
        self.state.lock().unwrap().issued[index].token.clone()
    }

    fn was_revoked(&self, token: &str) -> bool {
        self.state.lock().unwrap().revoked.iter().any(|value| value == token)
    }
}

struct GeneratedApprover {
    manager: OnceLock<Arc<Manager>>,
    busy: Mutex<()>,
    details: Mutex<Vec<RequestDetail>>,
    errors: Mutex<Vec<String>>,
}

impl GeneratedApprover {
    fn run(&self) {
        let Some(manager) = self.manager.get() else { return };
        let _busy = self.busy.lock().unwrap();
        for pending in manager.snapshot().pending {
            let RequestDetail::Get {
                generator_choices, raw_requested, sentinel_required,
                has_substitutable_fields, requested_hosts, reason, ..
            } = &pending.detail else { continue };
            let generation = if generator_choices.is_empty() {
                None
            } else {
                assert!(!sentinel_required, "new generated requests cannot require a sentinel");
                assert!(requested_hosts.is_empty(), "generated requests cannot carry proxy hosts");
                let selected = generator_choices.iter()
                    .find(|candidate| candidate.choice.name == "review-bot")
                    .or_else(|| (generator_choices.len() == 1).then(|| &generator_choices[0]))
                    .expect("offered source is selectable");
                assert!(selected.choice.available);
                let grant = match &selected.choice.ceiling {
                    asm_core::ffi::GenerationGrant::GithubApp { scope } if scope.repositories.iter().any(|r| r.id == 505) =>
                        GenerationGrant::GithubApp(GithubGrant {
                            installation_id: scope.installation_id, repositories: vec![repository(505, "other-org/platform")],
                            permissions: BTreeMap::from([("metadata".into(), GithubPermission::Read)]),
                        }),
                    asm_core::ffi::GenerationGrant::GithubApp { scope } =>
                        GenerationGrant::GithubApp(approved_grant(scope.installation_id)),
                    asm_core::ffi::GenerationGrant::Gcloud { scope } =>
                        GenerationGrant::Gcloud(asm_proto::generators::GcloudGrant {
                            service_account_unique_id: scope.service_account_unique_id.clone(),
                            service_account_email: scope.service_account_email.clone(),
                            scopes: vec![gcloud::READ_SCOPE.into()],
                            project_id: Some(selected.default_project_id.clone().expect("Google candidate has a saved default project")),
                        }),
                    asm_core::ffi::GenerationGrant::GcloudAccess {
                        grant: asm_core::ffi::GcloudAccessGrant::Requested { access },
                    } => {
                        assert!(selected.gcloud_ready.is_some(), "provision profiles separately from lease approval");
                        GenerationGrant::GcloudAccess(asm_proto::generators::GcloudAccessGrant::Requested {
                            access: access.clone().into(),
                        })
                    }
                    asm_core::ffi::GenerationGrant::GcloudAccess { .. } =>
                        panic!("managed approval requires the exact request selector"),
                };
                Some(GenerationSelection {
                    generator_id: selected.choice.generator_id.clone(),
                    generator_revision: selected.choice.revision,
                    grant,
                }.into())
            };
            let mode = if generation.is_some() || *raw_requested {
                asm_core::ffi::LeaseMode::Raw
            } else {
                asm_core::ffi::LeaseMode::Sentinel
            };
            let hosts = if mode == asm_core::ffi::LeaseMode::Sentinel && *has_substitutable_fields {
                if requested_hosts.is_empty() {
                    vec!["127.0.0.1".into()]
                } else {
                    requested_hosts.clone()
                }
            } else {
                Vec::new()
            };
            let result = manager.resolve_request(pending.id, Decision::ApproveGet {
                mode,
                duration_secs: Some(if reason.contains("short-generated-lease") { 5 } else { 43_200 }),
                hosts, generation,
            });
            match result {
                Ok(()) => self.details.lock().unwrap().push(pending.detail),
                Err(error) => self.errors.lock().unwrap().push(error.to_string()),
            }
        }
    }

    fn count(&self) -> usize {
        self.details.lock().unwrap().len()
    }
}

struct GeneratedObserver(Arc<GeneratedApprover>);

impl ManagerObserver for GeneratedObserver {
    fn changed(&self, topic: String) {
        if topic == "requests" {
            let approver = self.0.clone();
            std::thread::spawn(move || approver.run());
        }
    }
}

struct ShutdownManager(Arc<Manager>);

impl Drop for ShutdownManager {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn json_get(env: &Env, arguments: &[&str]) -> serde_json::Value {
    let mut args = vec!["get", "--json", "--no-reaper", "--wait", "30"];
    args.extend_from_slice(arguments);
    let output = env.run(&args, None);
    assert_eq!(output.code, 0, "get failed: {}{}", output.stdout, output.stderr);
    assert!(!output.stdout.contains("installation-token"), "get JSON disclosed token bytes");
    serde_json::from_str(&output.stdout).expect("get JSON metadata")
}

fn delivered_path(result: &serde_json::Value) -> PathBuf {
    assert_eq!(result["files"].as_array().unwrap().len(), 1);
    PathBuf::from(result["files"][0]["path"].as_str().unwrap())
}

fn assert_generated_sentinel_rejected(output: Out) {
    assert_eq!(output.code, asm_proto::error::EXIT_INVALID, "{}", output.stderr);
    assert!(output.stderr.contains("generated credentials require raw delivery; remove --sentinel"),
        "{}", output.stderr);
    assert!(output.stdout.is_empty(), "rejected request must not deliver a credential");
}

fn assert_generated_leases_are_raw(manager: &Manager) {
    let leases = manager.list_leases();
    let proxy = manager.core().proxy_state.lock().unwrap();
    for lease in leases.iter().filter(|lease| lease.generation.is_some()) {
        assert_eq!(lease.mode, asm_core::ffi::LeaseMode::Raw);
        assert!(lease.hosts.is_empty());
        assert!(proxy.entries.get(&lease.lease_id).is_none_or(Vec::is_empty),
            "generated lease must not publish a proxy entry");
    }
}

fn wait_until(description: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {description}");
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// Snapshot all credential material and manifest bytes, rather than merely
/// checking that exec did not print a filename.
fn file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
        if !directory.exists() { return }
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, found);
            } else {
                found.insert(path.strip_prefix(root).unwrap().to_owned(), std::fs::read(path).unwrap());
            }
        }
    }
    let mut found = BTreeMap::new();
    collect(root, root, &mut found);
    found
}

/// A structured static fixture uses the normal VaultProvider read contract; it
/// cannot issue generated credentials or short-circuit manager authorization.
struct LoginFixture;

impl asm_core::vault::VaultProvider for LoginFixture {
    fn status(&self) -> asm_core::vault::VaultStatus {
        asm_core::vault::VaultStatus::Ready
    }

    fn list(&self) -> asm_core::error::Result<Vec<asm_core::vault::SecretMeta>> {
        Ok(vec![asm_core::vault::SecretMeta {
            key: "google".into(), name: "google".into(),
            kind: asm_proto::wire::SecretKind::Login,
            fields: vec!["username".into(), "password".into()],
            uri_hosts: vec!["http://127.0.0.1".into()],
        }])
    }

    fn read(&self, key: &str) -> asm_core::error::Result<Vec<(String, String)>> {
        if key != "google" {
            return Err(asm_core::error::CoreError::not_found("unknown fixture item"));
        }
        Ok(vec![
            ("username".into(), "fixture-user@example.test".into()),
            ("password".into(), "fixture-password\nwith-whitespace ".into()),
        ])
    }

    fn update(&self, _: &str, _: &str, _: &str) -> asm_core::error::Result<()> {
        Err(asm_core::error::CoreError::invalid("fixture is read-only"))
    }

    fn add(&self, _: &str, _: &str, _: &asm_core::vault::AddTarget) -> asm_core::error::Result<()> {
        Err(asm_core::error::CoreError::invalid("fixture is read-only"))
    }
}

fn generated_manager(tmp: &Path, ports: &[u16], bin_dir: PathBuf) -> (Arc<GeneratedApprover>, ShutdownManager) {
    let approver = Arc::new(GeneratedApprover {
        manager: OnceLock::new(), busy: Mutex::new(()),
        details: Mutex::new(Vec::new()), errors: Mutex::new(Vec::new()),
    });
    let manager = Manager::start_with(
        tmp.join("data"), bin_dir, Arc::new(GeneratedObserver(approver.clone())),
        StartOptions {
            resume_key: Some([18; 32]),
            values_root: Some(tmp.join("values")),
            settings: vec![
                (keys::API_BIND.into(), json!("127.0.0.1")), (keys::API_PORT.into(), json!(0)),
                (keys::PROXY_BIND.into(), json!("127.0.0.1")),
                (keys::PROXY_PORT.into(), json!(ports[0])),
                (keys::PROXY_HTTP_PORT.into(), json!(ports[1])),
                (keys::PROXY_HTTPS_PORT.into(), json!(ports[2])),
                (keys::PROXY_MGMT_PORT.into(), json!(ports[3])),
                (keys::PROXY_METRICS_PORT.into(), json!(ports[4])),
                (keys::PROXY_UPSTREAM_DENY_CIDRS.into(), json!(["192.0.2.0/24"])),
                (keys::PROXY_ALLOW_PLAIN_HTTP.into(), json!(true)),
                (keys::PROXY_HINTS.into(), json!(["127.0.0.1"])),
            ],
        },
    ).expect("start isolated manager");
    approver.manager.set(manager.clone()).ok().unwrap();
    (approver, ShutdownManager(manager))
}

#[test]
fn two_cold_github_cli_gets_share_one_approval_and_issuance() {
    let tmp = tempfile::tempdir().unwrap();
    let first = Env {
        cli: build_cli(),
        config: tmp.path().join("config"),
        secrets: tmp.path().join("first-secrets"),
    };
    // Share the paired host identity, but require each process to write its own material.
    let second = Env {
        cli: first.cli.clone(),
        config: first.config.clone(),
        secrets: tmp.path().join("second-secrets"),
    };
    let github = GithubFixture::new("cold-client", 41, 101, None);
    let (approver, shutdown) = generated_manager(tmp.path(), &free_ports(5), workspace().join("dist/bin"));
    let manager = &shutdown.0;
    github.install(manager, "00000000-0000-4000-8000-000000000041", "cold-bot");
    wait_healthy(manager);
    let code = manager.create_pairing_code(
        "cold CLI fixture".into(), Some(3600), Some(1), vec!["127.0.0.1/8".into()],
    ).unwrap();
    let paired = first.run(&["pair", &manager.general_settings().listening_on, &code.code], None);
    assert_eq!(paired.code, 0, "fixture pairing failed");

    let db = rusqlite::Connection::open_with_flags(
        tmp.path().join("data/asm.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ).unwrap();
    let args = [
        "get", "--json", "--no-reaper", "--wait", "30",
        "--repositories", "acme/web", "--permissions", "contents=read",
        "GH_TOKEN", "Read acme/web concurrently",
    ];
    let outputs = std::thread::scope(|scope| {
        let gate = approver.busy.lock().unwrap();
        let a = scope.spawn(|| first.run(&args, None));
        wait_until("first cold approval", || manager.snapshot().pending.len() == 1);
        let id = manager.snapshot().pending.pop().unwrap().id;
        let mut row = db.prepare(
            "SELECT sealed FROM resume_entries WHERE namespace = 'request-book-v1' AND id = ?1",
        ).unwrap();
        let mut sealed = || row.query_row([&id], |r| r.get::<_, Vec<u8>>(0)).unwrap();
        let before = sealed();
        let b = scope.spawn(|| second.run(&args, None));
        // While the operator is gated, only attaching a caller rewrites this pending row.
        // Seeing just one prompt would also be true before the second POST arrived.
        wait_until("second cold caller to join the first approval", || sealed() != before);
        assert_eq!(manager.snapshot().pending.len(), 1);
        drop(gate);
        [a.join().unwrap(), b.join().unwrap()]
    });

    // resolve_request publishes the result before the observer records its decision.
    let _finished = approver.busy.lock().unwrap();
    assert_eq!(approver.count(), 1);
    assert!(approver.errors.lock().unwrap().is_empty());
    assert_eq!(github.count(), 1);
    let leases = manager.list_leases();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].credential_version, Some(1));
    let token = github.token(0);
    assert!(!token.is_empty());
    for (output, env) in outputs.iter().zip([&first, &second]) {
        assert_eq!(output.code, 0, "cold CLI get failed");
        assert!(!output.stdout.contains(&token) && !output.stderr.contains(&token),
            "CLI printed credential material");
        let result: serde_json::Value = serde_json::from_str(&output.stdout).ok().expect("get JSON metadata");
        assert!(result["lease_id"].as_str() == Some(leases[0].lease_id.as_str()));
        assert!(result["credential_version"].as_u64() == Some(1));
        let path = delivered_path(&result);
        assert!(path == env.secrets.join("GH_TOKEN"), "wrong credential destination");
        assert!(std::fs::read(path).unwrap() == token.as_bytes(), "incorrect delivered credential");
    }
}

#[test]
fn generated_github_lease_end_to_end() {
    let bin_dir = workspace().join("dist/bin");
    assert!(
        bin_dir.join("iron-proxy").is_file(),
        "missing prerequisite {}; run `just proxy` before integration tests",
        bin_dir.join("iron-proxy").display()
    );
    let cli = build_cli();
    let tmp = tempfile::tempdir().unwrap();
    let release = GithubFixture::new("release-client", 41, 101, Some(93));
    let review = GithubFixture::new("review-client", 84, 303, None);
    let upstream_seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let seen = upstream_seen.clone();
    let issuers = [release.state.clone(), review.state.clone()];
    let upstream = LocalHttp::start(move |request| {
        let token = request.headers.get("x-key").ok_or("upstream request has no credential")?;
        seen.lock().unwrap().push((token.clone(), request.target.clone()));
        let active = issuers.iter().any(|issuer| {
            let issuer = issuer.lock().unwrap();
            issuer.issued.iter().any(|issued| issued.token == *token
                && issued.expires_at > asm_core::manager::now())
                && !issuer.revoked.contains(token)
        });
        let permitted = active && request.target == "/repos/acme/web";
        Ok((if permitted { 200 } else { 403 }, json!({"ok":permitted})))
    });
    let approved_url = upstream.url("/repos/acme/web");
    let outside_url = upstream.url("/repos/acme/private");
    let ports = free_ports(5);
    let (approver, shutdown) = generated_manager(tmp.path(), &ports, bin_dir);
    let manager = shutdown.0.clone();
    release.install(&manager, "00000000-0000-4000-8000-000000000041", "release-bot");
    review.install(&manager, "00000000-0000-4000-8000-000000000084", "review-bot");
    wait_healthy(&manager);
    let env = Env {
        cli: cli.clone(), config: tmp.path().join("config"),
        secrets: tmp.path().join("secrets"),
    };
    let code = manager.create_pairing_code(
        "generated e2e".into(), Some(3600), Some(1), vec!["127.0.0.1/8".into()],
    ).unwrap();
    let output = env.run(&["pair", &manager.general_settings().listening_on, &code.code], None);
    assert_eq!(output.code, 0, "pair failed: {}", output.stderr);
    let output = env.run(&["list", "--json"], None);
    assert_eq!(output.code, 0, "list failed: {}", output.stderr);
    let catalog: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    let rows = catalog["secrets"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "duplicate apps form one logical output");
    assert_eq!(rows[0]["name"], "GH_TOKEN");
    assert_eq!(rows[0]["aliases"], json!(["GITHUB_TOKEN"]));
    assert_eq!(rows[0]["generators"].as_array().unwrap().len(), 2);
    assert!(rows[0]["generators"].as_array().unwrap().iter()
        .all(|candidate| candidate.get("ceiling").is_none()));
    assert_eq!(release.count() + review.count(), 0, "listing never mints");

    let child_marker = tmp.path().join("sentinel-child-started");
    assert_generated_sentinel_rejected(env.run(&[
        "get", "--sentinel", "--hosts", "127.0.0.1", "--no-reaper", "--wait", "30",
        "--repositories", "acme/web", "--permissions", "contents=read",
        "GH_TOKEN", "Try an explicitly requested sentinel",
    ], None));
    assert_generated_sentinel_rejected(env.run(&[
        "exec", "--sentinel", "--wait", "30", "--repositories", "acme/web", "--permissions", "contents=read",
        "GITHUB_TOKEN", "--", "/bin/sh", "-c", r#": > "$1""#, "asm-fixture", child_marker.to_str().unwrap(),
    ], None));
    assert!(!child_marker.exists(), "rejected sentinel exec must not launch the child");
    assert_eq!(release.count() + review.count(), 0, "rejected sentinel requests never mint");
    assert_eq!(approver.count(), 0);
    assert!(manager.list_leases().is_empty(), "rejected sentinel requests create no lease");

    // One chooser offers both apps; the approval deliberately narrows review's
    // write/two-repository ceiling to one repository with read permission.
    let first = json_get(&env, &[
        "--repositories", "ACME/web", "--permissions", "contents=read",
        "GH_TOKEN", "Read acme/web directly",
    ]);
    assert_eq!(first["mode"], "raw");
    assert_eq!(first["files"][0]["delivery"], "raw");
    assert_eq!(first["generator_name"], "review-bot");
    assert_eq!(first["credential_version"], 1);
    assert_eq!(first["generation"]["grant"]["scope"]["repositories"], json!([
        {"id":202,"full_name":"acme/web"}
    ]));
    assert_eq!(first["generation"]["grant"]["scope"]["permissions"],
        json!({"contents":"read","metadata":"read"}));
    let lease_id = first["lease_id"].as_str().unwrap().to_owned();
    let deadline = first["expires_at"].clone();
    let first_lease = manager.list_leases().into_iter()
        .find(|lease| lease.lease_id == lease_id).unwrap();
    assert_eq!(first_lease.expires_at.unwrap().duration_since(first_lease.created_at).unwrap(),
        Duration::from_secs(43_200));
    assert_eq!(first_lease.fields, ["value"]);
    assert_eq!(release.count(), 0, "unselected app never signs or mints");
    assert_eq!(review.count(), 1);
    assert_eq!(approver.count(), 1);
    {
        let details = approver.details.lock().unwrap();
        let RequestDetail::Get { generator_choices, requested_generation, operator_selected_grant, .. } = &details[0]
            else { panic!("generated approval detail expected") };
        assert!(*operator_selected_grant);
        assert_eq!(generator_choices.len(), 2, "the approval must offer both identities");
        for candidate in generator_choices {
            let asm_core::ffi::GenerationGrant::GithubApp { scope } = &candidate.choice.ceiling
                else { panic!("GitHub ceiling expected") };
            assert_eq!(scope.repositories.len(), 2, "the approval must show the installation ceiling");
            assert!(scope.permissions.iter().any(|permission|
                permission.name == "contents" && permission.level == asm_core::ffi::GithubPermission::Write));
        }
        let Some(asm_core::ffi::GenerationRequest::GithubApp { scope }) = requested_generation
            else { panic!("requested GitHub scope expected") };
        assert_eq!(scope.repositories.as_deref(), Some(["acme/web".to_owned()].as_slice()));
    }
    let raw_path = delivered_path(&first);
    let token = std::fs::read_to_string(&raw_path).unwrap();
    assert_eq!(token, review.token(0));
    let direct = reqwest::blocking::Client::builder().no_proxy()
        .timeout(Duration::from_secs(5)).build().unwrap();
    let get_status = |url: &str, token: &str| {
        direct.get(url).header("X-Key", token).send().unwrap().status().as_u16()
    };
    assert_eq!(get_status(&approved_url, &token), 200);
    assert_eq!(get_status(&outside_url, &token), 403, "an unapproved repository is not accessible");
    assert_generated_leases_are_raw(&manager);

    // Alias reuse is one grant/version, not a second issuance or approval.
    let alias = json_get(&env, &[
        "--repositories", "acme/web", "--permissions", "contents=read", "GITHUB_TOKEN", "Continue reading acme/web",
    ]);
    let alias_path = delivered_path(&alias);
    assert_eq!(alias["lease_id"], first["lease_id"]);
    assert_eq!(alias["credential_version"], 1);
    assert_eq!(std::fs::read_to_string(&alias_path).unwrap(), token);
    assert_ne!(alias_path, raw_path);
    assert_eq!(review.count(), 1);

    // Refresh rewrites every local alias view without changing the grant or
    // authorization deadline. Give this replacement a short provider lifetime.
    review.state.lock().unwrap().next_lifetime = 8;
    let refreshed = json_get(&env, &[
        "--lease", &lease_id, "--refresh",
        "GITHUB_TOKEN", "Rotate the approved installation token",
    ]);
    assert_eq!(refreshed["lease_id"], first["lease_id"]);
    assert_eq!(refreshed["expires_at"], deadline);
    assert_eq!(refreshed["generation"], first["generation"]);
    assert_eq!(refreshed["credential_version"], 2);
    assert_eq!(std::fs::read_to_string(&raw_path).unwrap(), review.token(1));
    assert_eq!(std::fs::read_to_string(&alias_path).unwrap(), review.token(1));
    assert!(review.was_revoked(&review.token(0)), "explicit refresh revokes its predecessor");
    assert_eq!(get_status(&approved_url, &token), 403, "revoked predecessor cannot access the resource");
    wait_until("provider-expired credential suspension", || {
        manager.list_leases().iter().any(|lease| lease.lease_id == lease_id && lease.suspended)
    });
    assert_eq!(get_status(&approved_url, &review.token(1)), 403, "the provider enforces token expiry");
    assert_eq!(review.count(), 2, "sweeping/listing does not renew credentials");
    let resumed = json_get(&env, &[
        "--lease", &lease_id, "GH_TOKEN", "Resume the same approved grant",
    ]);
    assert_eq!(resumed["credential_version"], 3);
    assert_eq!(resumed["expires_at"], deadline);
    assert_eq!(resumed["generation"], first["generation"]);
    assert_eq!(std::fs::read_to_string(delivered_path(&resumed)).unwrap(), review.token(2));
    assert_eq!(approver.count(), 1, "renewal needs no new operator decision");
    assert_eq!(get_status(&approved_url, &review.token(2)), 200);

    let exec_env = Env {
        cli, config: env.config.clone(), secrets: tmp.path().join("exec-must-not-write"),
    };
    let saved_files = file_snapshot(&env.secrets);
    let approvals = approver.count();
    let minted = review.count();
    let raw_child = r#"set -eu
test "$GH_TOKEN" = "$GITHUB_TOKEN"
test "$GH_TOKEN" != stale-gh
test "$GITHUB_TOKEN" != stale-github
test "$HTTP_PROXY" = caller-network
test "$https_proxy" = caller-lowercase-proxy
test "$SSL_CERT_FILE" = caller-ca
test "$3" = 'literal;$(not-a-command)'
curl --noproxy '*' -fsS -o /dev/null -H "X-Key: $GH_TOKEN" "$1"
test "$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' -H "X-Key: $GITHUB_TOKEN" "$2")" = 403
printf 'raw-child-ok\n'"#;
    let output = exec_env.run_env(&[
        "exec", "--wait", "30", "--repositories", "acme/web", "--permissions", "contents=read", "GH_TOKEN,GITHUB_TOKEN", "--",
        "/bin/sh", "-c", raw_child, "asm-fixture",
        &approved_url, &outside_url, "literal;$(not-a-command)",
    ], None, &[
        ("GH_TOKEN", "stale-gh"), ("GITHUB_TOKEN", "stale-github"),
        ("HTTP_PROXY", "caller-network"),
        ("https_proxy", "caller-lowercase-proxy"), ("SSL_CERT_FILE", "caller-ca"),
    ]);
    assert_eq!(output.code, 0, "raw exec failed: {}", output.stderr);
    assert_eq!(output.stdout, "raw-child-ok\n");
    assert_eq!(upstream_seen.lock().unwrap().as_slice().last_chunk::<2>().unwrap(), &[
        (review.token(2), "/repos/acme/web".to_owned()),
        (review.token(2), "/repos/acme/private".to_owned()),
    ], "the child used the exact cached raw token");
    assert_eq!(review.count(), minted, "both aliases acquire one cached credential");
    assert_eq!(approver.count(), approvals);
    assert_eq!(file_snapshot(&env.secrets), saved_files);
    assert!(!exec_env.secrets.exists(), "exec must not open the credential directory");

    // Identity conflicts are rejected before either app is contacted; custom
    // destinations intentionally permit two distinct app identities.
    let conflict = exec_env.run(&[
        "exec", "--repositories", "acme/web", "--permissions", "contents=read", "GH_TOKEN=release-bot/GH_TOKEN,GITHUB_TOKEN=review-bot/GH_TOKEN",
        "--", "/bin/sh", "-c", "printf should-not-launch",
    ], None);
    assert_eq!(conflict.code, asm_proto::error::EXIT_INVALID);
    assert!(conflict.stdout.is_empty());
    assert_eq!(release.count(), 0);
    assert_eq!(review.count(), minted);
    let custom_child = r#"set -eu
test "$BOT_A_TOKEN" != "$BOT_B_TOKEN"
test "$GH_TOKEN" = inherited-gh
test "$GITHUB_TOKEN" = inherited-github
curl --noproxy '*' -fsS -o /dev/null -H "X-Key: $BOT_A_TOKEN" "$1"
curl --noproxy '*' -fsS -o /dev/null -H "X-Key: $BOT_B_TOKEN" "$1"
printf 'two-apps-ok\n'"#;
    let output = exec_env.run_env(&[
        "exec", "--wait", "30", "--repositories", "acme/web", "--permissions", "contents=read",
        "BOT_A_TOKEN=release-bot/GH_TOKEN,BOT_B_TOKEN=review-bot/GH_TOKEN",
        "--", "/bin/sh", "-c", custom_child, "asm-fixture", &approved_url,
    ], None, &[("GH_TOKEN", "inherited-gh"), ("GITHUB_TOKEN", "inherited-github")]);
    assert_eq!(output.code, 0, "two-app exec failed: {}", output.stderr);
    assert_eq!(output.stdout, "two-apps-ok\n");
    assert_eq!(release.count(), 1);
    assert_eq!(review.count(), minted + 1);
    assert!(!exec_env.secrets.exists());

    manager.revoke_lease(lease_id.clone()).unwrap();
    assert!(review.was_revoked(&review.token(2)));
    assert_eq!(get_status(&approved_url, &review.token(2)), 403);
    let ended = env.run(&[
        "get", "--no-reaper", "--lease", &lease_id, "GITHUB_TOKEN", "Do not rebind",
    ], None);
    assert_eq!(ended.code, 3, "ended --lease must be terminal: {}", ended.stderr);
    assert_eq!(review.count(), minted + 1, "revoked lease cannot mint");

    // Ending authorization, unlike provider expiry, permanently ends exact-lease
    // renewal and revokes its still-valid GitHub token.
    let short = json_get(&env, &[
        "--new-lease", "--repositories", "acme/web", "--permissions", "contents=read",
        "release-bot/GH_TOKEN", "short-generated-lease",
    ]);
    let short_id = short["lease_id"].as_str().unwrap();
    let short_token = std::fs::read_to_string(delivered_path(&short)).unwrap();
    assert_eq!(short_token, release.token(1));
    wait_until("generated authorization expiry", || manager.list_leases().iter()
        .any(|lease| lease.lease_id == short_id && lease.status == asm_core::ffi::LeaseStatus::Expired));
    wait_until("expired lease provider revocation", || release.was_revoked(&short_token));
    assert_eq!(get_status(&approved_url, &short_token), 403);
    let minted = release.count();
    let output = env.run(&[
        "get", "--no-reaper", "--lease", short_id,
        "release-bot/GITHUB_TOKEN", "An expired grant cannot renew",
    ], None);
    assert_eq!(output.code, 3, "expired --lease must be terminal: {}", output.stderr);
    assert_eq!(release.count(), minted);

    // The documented multi-secret shorthand acquires everything before invoking
    // the real child. Default static sentinel delivery also prepares the proxy.
    let examples_file = tmp.path().join("examples.env");
    std::fs::write(&examples_file, "OTHER_SECRET=fixture-other-value\n").unwrap();
    manager.save_vault(VaultDraft {
        id: None, name: "examples".into(),
        config: VaultConfig::EnvFile { path: examples_file.to_string_lossy().into_owned() },
        client_secret: String::new(), master_password: String::new(),
    }).unwrap();
    let output = exec_env.run(&[
        "exec", "--hosts", "127.0.0.2", "--wait", "30", "--repositories", "acme/web", "--permissions", "contents=read",
        "GH_TOKEN,OTHER_SECRET", "--", "/bin/sh", "-c",
        r#"set -eu; test "$GH_TOKEN" = "$GITHUB_TOKEN"; case "$GH_TOKEN" in fixture.*.installation-token) ;; *) exit 81 ;; esac; test -n "$HTTPS_PROXY"; case "$OTHER_SECRET" in asm_*) ;; *) exit 82 ;; esac; printf 'all-acquired-ok\n'"#,
    ], None);
    assert_eq!(output.code, 0, "multi-secret exec failed: {}", output.stderr);
    assert_eq!(output.stdout, "all-acquired-ok\n");
    let static_lease = manager.list_leases().into_iter().find(|lease| lease.name == "OTHER_SECRET").unwrap();
    assert_eq!(static_lease.mode, asm_core::ffi::LeaseMode::Sentinel);
    assert_eq!(static_lease.hosts, ["127.0.0.2"]);
    assert!(!exec_env.secrets.exists());

    // Shipped structured-field examples run through the real manager/CLI.
    let login_file = tmp.path().join("empty.env");
    std::fs::write(&login_file, "").unwrap();
    let vault = manager.save_vault(VaultDraft {
        id: None, name: "Vaultwarden".into(),
        config: VaultConfig::EnvFile { path: login_file.to_string_lossy().into_owned() },
        client_secret: String::new(), master_password: String::new(),
    }).unwrap();
    let mut entry = manager.core().registry.get(&vault.id).unwrap();
    entry.provider = Arc::new(LoginFixture);
    manager.core().registry.insert(entry);
    let username = json_get(&env, &[
        "GOOGLE_USER=Vaultwarden/google::username", "Sign in",
    ]);
    assert_eq!(username["files"][0]["field"], "username");
    let username_path = delivered_path(&username);
    assert_eq!(username_path.file_name().unwrap(), "GOOGLE_USER");
    assert_eq!(std::fs::read_to_string(&username_path).unwrap(), "fixture-user@example.test");
    let username_lease = manager.list_leases().into_iter()
        .find(|lease| lease.lease_id == username["lease_id"].as_str().unwrap()).unwrap();
    assert_eq!(username_lease.fields, ["username"]);
    assert!(username_lease.hosts.is_empty(), "plain username requires no host approval");
    let proxy_entries = manager.core().proxy_state.lock().unwrap();
    assert!(proxy_entries.entries.get(&username_lease.lease_id).is_none_or(Vec::is_empty),
        "plain-only selection never publishes a proxy entry");
    drop(proxy_entries);
    let approvals = approver.count();
    let whole = json_get(&env, &[
        "--hosts", "127.0.0.1", "Vaultwarden/google", "Sign in with the full item",
    ]);
    assert_eq!(whole["files"].as_array().unwrap().len(), 2);
    assert_eq!(approver.count(), approvals + 1, "a username-only lease cannot authorize password");
    let mut whole_fields: Vec<&str> = whole["files"].as_array().unwrap().iter()
        .map(|file| file["field"].as_str().unwrap()).collect();
    whole_fields.sort();
    assert_eq!(whole_fields, ["password", "username"]);

    let approvals = approver.count();
    let static_child = r#"set -eu
test "$GOOGLE_USER" = fixture-user@example.test
test "$GOOGLE_PASS" = 'fixture-password
with-whitespace '
printf 'structured-child-ok\n'"#;
    let static_args = [
        "exec", "--raw", "--wait", "30",
        "GOOGLE_USER=Vaultwarden/google::username,GOOGLE_PASS=Vaultwarden/google::password",
        "--", "/bin/sh", "-c", static_child,
    ];
    for _ in 0..2 {
        let output = exec_env.run(&static_args, None);
        assert_eq!(output.code, 0, "structured exec failed: {}", output.stderr);
        assert_eq!(output.stdout, "structured-child-ok\n");
    }
    assert_eq!(approver.count(), approvals + 2, "static raw requires approval each time");
    let details = approver.details.lock().unwrap();
    for detail in &details[details.len() - 2..] {
        let RequestDetail::Get { fields, .. } = detail else { panic!("get approval expected") };
        assert_eq!(fields, &["password", "username"], "one approval authorizes the field union");
    }
    drop(details);
    assert!(!exec_env.secrets.exists());
    assert!(approver.errors.lock().unwrap().is_empty(), "an approval failed");
    let approvals = approver.count();
    let split = json_get(&env, &[
        "--repositories", "acme/web,other-org/platform",
        "GH_TOKEN", "Choose one installation for the related repositories",
    ]);
    assert_eq!(approver.count(), approvals + 1, "mixed installations need an explicit decision");
    assert_eq!(split["generation"]["grant"]["scope"]["installation_id"], 84);
    assert_eq!(split["generation"]["grant"]["scope"]["repositories"],
        json!([{"id":202,"full_name":"acme/web"}]));
    assert_eq!(split["generation"]["grant"]["scope"]["permissions"],
        json!({"contents":"read","metadata":"read"}));
    let org = json_get(&env, &["--repositories", "other-org/platform", "GH_TOKEN", "Inspect platform metadata"]);
    assert_eq!(org["generator_name"], "release-bot");
    assert_eq!(org["generation"]["grant"]["scope"]["installation_id"], 93);
    assert_eq!(org["generation"]["grant"]["scope"]["permissions"], json!({"metadata":"read"}));

    let review_count = review.count();
    let release_count = release.count();
    assert_eq!(review.state.lock().unwrap().repository_checks, review_count);
    assert_eq!(release.state.lock().unwrap().repository_checks, release_count);
    upstream.assert_clean();

    assert_generated_leases_are_raw(&manager);
    // Configuration, SQLite and audit surfaces contain metadata only.
    for path in [
        tmp.path().join("data/asm.db"),
        tmp.path().join("data/asm.db-wal"),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("installation-token") && !text.contains("BEGIN RSA PRIVATE KEY"));
        }
    }
    let activities = manager.list_activity(asm_core::ffi::ActivityQuery {
        categories: vec![], host_id: None, search: String::new(),
        before_id: None, limit: 1000,
    });
    for activity in activities {
        let display = format!("{} {:?}", activity.summary, activity.detail);
        assert!(!display.contains("installation-token") && !display.contains("BEGIN RSA PRIVATE KEY"));
    }
    let prior_release_revokes = release.state.lock().unwrap().revoked.clone();
    let prior_review_revokes = review.state.lock().unwrap().revoked.clone();
    drop(shutdown);
    assert_eq!(release.state.lock().unwrap().revoked, prior_release_revokes, "shutdown must not revoke release credentials");
    assert_eq!(review.state.lock().unwrap().revoked, prior_review_revokes, "shutdown must not revoke review credentials");
    review.http.assert_clean();
    release.http.assert_clean();
}

#[path = "e2e/gcloud.rs"]
mod gcloud;
