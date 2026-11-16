//! Headless end-to-end test (plan Verification 3): a `Manager` on a temp data dir with an
//! auto-approving observer, the real `asm` CLI, the patched iron-proxy from
//! `dist/bin/iron-proxy`, and a recording HTTP echo server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use asm_core::ffi::{RequestDetail, VaultConfig, VaultDraft};
use asm_core::settings as keys;
use asm_core::{Decision, Manager, ManagerObserver, StartOptions};
use serde_json::json;

const REAL_1: &str = "real-value-123";
const REAL_2: &str = "real-value-456";

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

/// Approves everything except `get` requests whose reason contains "deny-me".
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
                RequestDetail::Pair { .. } => Decision::ApprovePair,
                RequestDetail::Get { reason, .. } if reason.contains("deny-me") => Decision::Deny {
                    reason: "provide a better reason".into(),
                },
                RequestDetail::Get {
                    raw_requested,
                    requested_hosts,
                    initial_hosts,
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
                        duration_secs: Some(3600),
                        hosts,
                    }
                }
                RequestDetail::Update { vault_id, .. } => Decision::ApproveWrite {
                    vault_id: vault_id.clone(),
                    collection_id: None,
                },
                RequestDetail::Add { targets, .. } => Decision::ApproveWrite {
                    vault_id: targets[0].vault_id.clone(),
                    collection_id: None,
                },
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
    if !bin_dir.join("iron-proxy").exists() {
        eprintln!(
            "SKIPPED: {} is missing; run `just proxy` first",
            bin_dir.join("iron-proxy").display()
        );
        return;
    }
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

    // Unattended pairing.
    let code = m
        .create_pairing_code("e2e".into(), Some(3600), Some(1))
        .unwrap();
    let o = env.run(&["pair", &api, &code.code], None);
    assert_eq!(o.code, 0, "pair: {}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("paired: "), "{}", o.stdout);
    assert_eq!(m.list_hosts().len(), 1);
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
    let (status, _) = via_proxy(proxy_port, &echo_url, &sentinel);
    assert_eq!(status, 403);
    assert_eq!(seen.lock().unwrap().len(), before);

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

    m.shutdown();
}
