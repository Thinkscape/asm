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
                RequestDetail::Pair { .. } => {
                    // A bad name is refused and leaves the request pending with the error.
                    match m.resolve_request(
                        p.id.clone(),
                        Decision::ApprovePair {
                            name: "bad\u{202E}name".into(),
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
                    }
                }
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
    ] {
        assert!(has(category, kind), "missing activity {category}/{kind}");
    }
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
