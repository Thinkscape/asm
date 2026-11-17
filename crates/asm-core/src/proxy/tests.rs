//! Supervisor tests. The end-to-end one needs the patched binary at `dist/bin/iron-proxy`
//! (or the directory in `ASM_IRON_PROXY_BIN_DIR`) and is skipped with a message otherwise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asm_proto::rules::new_sentinel;

use super::*;

const REAL: &str = "real-value-123";

fn bin_dir() -> PathBuf {
    std::env::var_os("ASM_IRON_PROXY_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist/bin"))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn counter() -> (Arc<AtomicUsize>, Arc<dyn Fn() + Send + Sync>) {
    let n = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&n);
    (
        n,
        Arc::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }),
    )
}

fn events() -> (Arc<Mutex<Vec<ProxyEvent>>>, EventSink) {
    let v = Arc::new(Mutex::new(Vec::new()));
    let c = Arc::clone(&v);
    (v, Arc::new(move |e| c.lock().unwrap().push(e)))
}

/// HTTP server that records each request's `X-Key` header and echoes it in the body.
fn echo_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut key = String::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((n, v)) = line.split_once(':')
                    && n.eq_ignore_ascii_case("x-key")
                {
                    key = v.trim().to_string();
                }
            }
            rec.lock().unwrap().push(key.clone());
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{key}",
                key.len()
            );
        }
    });
    (port, seen)
}

/// Plain-HTTP absolute-form proxy request on the tunnel port; (status, body).
fn via_proxy(proxy_port: u16, target_port: u16, key: &str) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut s = loop {
        match TcpStream::connect(("127.0.0.1", proxy_port)) {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("proxy not reachable: {e}"),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET http://127.0.0.1:{target_port}/echo HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nX-Key: {key}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn file_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

#[test]
fn start_without_binary_but_existing_ca_reports_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::create(&tmp.path().join("data"), Some(tmp.path())).unwrap();
    std::fs::write(dirs.proxy.join("ca.crt"), "x").unwrap();
    std::fs::write(dirs.proxy.join("ca.key"), "x").unwrap();
    let entry = ProxyEntry {
        lease_id: "l1".into(),
        index: 0,
        sentinel: new_sentinel(),
        value: REAL.into(),
        hosts: vec!["example.com".into()],
    };
    assert!(!format!("{entry:?}").contains(REAL));
    let (calls, cb) = counter();
    let (_, ev) = events();
    let sup = ProxySupervisor::start(
        tmp.path().join("nobin"),
        dirs.clone(),
        ProxyConfig::default(),
        vec![entry],
        cb,
        ev,
    )
    .unwrap();
    let st = sup.status();
    assert!(
        !st.running && st.error.as_deref().unwrap_or("").contains("cannot start"),
        "{st:?}"
    );
    assert!(calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(file_count(&dirs.values), 1);
    let yaml = std::fs::read_to_string(dirs.proxy.join("iron-proxy.yaml")).unwrap();
    assert!(!yaml.contains(REAL));
    sup.shutdown();
    assert_eq!(file_count(&dirs.values), 0);
}

#[test]
fn start_fails_when_ca_cannot_be_created() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::create(&tmp.path().join("data"), Some(tmp.path())).unwrap();
    let (_, cb) = counter();
    let (_, ev) = events();
    let err = ProxySupervisor::start(
        tmp.path().join("nobin"),
        dirs,
        ProxyConfig::default(),
        vec![],
        cb,
        ev,
    )
    .err()
    .expect("must fail");
    assert!(err.message.contains("generate-ca"), "{}", err.message);
}

#[test]
fn rejects_malformed_entries() {
    let ok = ProxyEntry {
        lease_id: "l".into(),
        index: 0,
        sentinel: new_sentinel(),
        value: "v".into(),
        hosts: vec!["h".into()],
    };
    assert!(validate_entries(std::slice::from_ref(&ok)).is_ok());
    assert!(validate_entries(&[ok.clone(), ok.clone()]).is_err());
    assert!(
        validate_entries(&[ProxyEntry {
            sentinel: "asm_short".into(),
            ..ok.clone()
        }])
        .is_err()
    );
    assert!(
        validate_entries(&[ProxyEntry {
            value: String::new(),
            ..ok.clone()
        }])
        .is_err()
    );
    assert!(
        validate_entries(&[ProxyEntry {
            hosts: vec![],
            ..ok
        }])
        .is_err()
    );
}

#[test]
fn end_to_end_with_patched_iron_proxy() {
    let bin = bin_dir();
    if !bin.join("iron-proxy").exists() {
        eprintln!(
            "SKIPPED end_to_end_with_patched_iron_proxy: {} not found",
            bin.join("iron-proxy").display()
        );
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::create(&tmp.path().join("data"), Some(tmp.path())).unwrap();
    let cfg = ProxyConfig {
        bind: "127.0.0.1".into(),
        port: free_port(),
        http_port: free_port(),
        https_port: free_port(),
        mgmt_port: free_port(),
        metrics_port: free_port(),
        allow_plain_http: true,
        upstream_deny_cidrs: Some(vec!["192.0.2.0/24".into()]),
        ..ProxyConfig::default()
    };
    let sentinel = new_sentinel();
    let entry = ProxyEntry {
        lease_id: "lease-1".into(),
        index: 0,
        sentinel: sentinel.clone(),
        value: REAL.into(),
        hosts: vec!["127.0.0.1".into()],
    };
    let (echo_port, seen) = echo_server();
    let (_, cb) = counter();
    let (events, ev) = events();
    let sup = ProxySupervisor::start(bin, dirs.clone(), cfg.clone(), vec![entry], cb, ev).unwrap();
    wait_for("healthy proxy", Duration::from_secs(15), || {
        sup.status().healthy
    });
    let st = sup.status();
    assert!(
        st.running && st.error.is_none() && st.last_reload.is_some(),
        "{st:?}"
    );
    assert!(
        st.ca_expiry.as_deref().is_some_and(|e| e.ends_with('Z')),
        "{st:?}"
    );
    assert_eq!(sup.ca_sha256_hex().unwrap().len(), 64);
    let pid = st.pid.unwrap();

    // Substitution: the upstream sees the real value, the client only the sentinel.
    let (status, body) = via_proxy(cfg.port, echo_port, &sentinel);
    assert_eq!(status, 200, "{body}");
    assert_eq!(seen.lock().unwrap().last().map(String::as_str), Some(REAL));
    assert!(!body.contains(REAL));
    assert_eq!(file_count(&dirs.values), 1);

    // Ending the lease: reload in place, sentinel now refused, value file deleted.
    sup.apply(vec![]).unwrap();
    let st = sup.status();
    assert_eq!(
        st.pid,
        Some(pid),
        "reload must not restart the child: {st:?}"
    );
    let before = seen.lock().unwrap().len();
    let (status, body) = via_proxy(cfg.port, echo_port, &sentinel);
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("asm: sentinel expired or revoked; run asm get again"),
        "{body}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "upstream must not be called"
    );
    assert_eq!(file_count(&dirs.values), 0);

    // A listen change that cannot bind is rolled back.
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = blocker.local_addr().unwrap().port();
    let err = sup
        .set_config(ProxyConfig {
            port: busy,
            ..cfg.clone()
        })
        .unwrap_err();
    assert!(err.message.contains("did not start"), "{}", err.message);
    assert_eq!(sup.config(), cfg);
    wait_for("restored proxy", Duration::from_secs(15), || {
        sup.status().healthy
    });
    let (status, _) = via_proxy(cfg.port, echo_port, "no-sentinel");
    assert_eq!(status, 200);
    drop(blocker);

    let logs = sup.log_tail(2000);
    assert!(
        logs.iter().any(|l| l.contains("swapped")),
        "expected a swap annotation in the log"
    );
    assert!(logs.iter().all(|l| !l.contains(REAL)));
    let log_file = std::fs::read_to_string(dirs.logs.join("proxy.log")).unwrap();
    assert!(!log_file.contains(REAL));

    // Activity events: lifecycle, the substitution (mapped to its value file) and the
    // rejected sentinel; never the real value.
    let events = events.lock().unwrap().clone();
    assert!(events.iter().any(|e| matches!(
        e,
        ProxyEvent::Lifecycle {
            kind: "started",
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        ProxyEvent::Lifecycle {
            kind: "crashed",
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(e, ProxyEvent::Request(a)
        if a.swaps.iter().any(|s| audit::lease_of_value_path(&s.value_path)
            == Some(("lease-1".to_string(), 0))))));
    assert!(events.iter().any(|e| matches!(e, ProxyEvent::Request(a)
        if a.status == Some(403) && a.rejected.as_ref().is_some_and(|r|
            r.reason.as_deref() == Some("sentinel_ended")))));
    assert!(!format!("{events:?}").contains(REAL));

    let pid = sup.status().pid.unwrap();
    sup.shutdown();
    assert!(!sup.status().running);
    assert!(!pid_alive(pid), "iron-proxy pid {pid} still running");
    assert_eq!(file_count(&dirs.values), 0);
    assert!(sup.apply(vec![]).is_err());
}

fn skip_without_binary(test: &str) -> Option<PathBuf> {
    let bin = bin_dir();
    if bin.join("iron-proxy").exists() {
        Some(bin)
    } else {
        eprintln!(
            "SKIPPED {test}: {} not found",
            bin.join("iron-proxy").display()
        );
        None
    }
}

fn loopback_config() -> ProxyConfig {
    ProxyConfig {
        bind: "127.0.0.1".into(),
        port: free_port(),
        http_port: free_port(),
        https_port: free_port(),
        mgmt_port: free_port(),
        metrics_port: free_port(),
        ..ProxyConfig::default()
    }
}

fn lifecycle(events: &Mutex<Vec<ProxyEvent>>, kind: &str) -> Vec<String> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            ProxyEvent::Lifecycle { kind: k, summary } if *k == kind => Some(summary.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn port_conflict_is_reported_as_down_and_recovers() {
    let Some(bin) = skip_without_binary("port_conflict_is_reported_as_down_and_recovers") else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::create(&tmp.path().join("data"), Some(tmp.path())).unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = ProxyConfig {
        metrics_port: blocker.local_addr().unwrap().port(),
        ..loopback_config()
    };
    let (_, cb) = counter();
    let (events, ev) = events();
    let sup = ProxySupervisor::start(bin, dirs, cfg.clone(), vec![], cb, ev).unwrap();
    wait_for("Down", Duration::from_secs(15), || {
        matches!(sup.status().phase, Phase::Down { .. })
    });
    let st = sup.status();
    let want = format!(
        "port {} is in use by {} (pid {})",
        cfg.metrics_port,
        procs::process_args(std::process::id() as libc::pid_t)
            .and_then(|a| a.into_iter().next())
            .map(|a0| Path::new(&a0)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned())
            .unwrap(),
        std::process::id()
    );
    assert!(
        matches!(&st.phase, Phase::Down { reason, .. } if *reason == want),
        "{st:?}"
    );
    assert_eq!(st.error.as_deref(), Some(want.as_str()));
    assert!(st.consecutive_failures >= 1);
    // The monitor records the transition on its next step.
    wait_for("down event", Duration::from_secs(2), || {
        !lifecycle(&events, "down").is_empty()
    });
    assert_eq!(
        lifecycle(&events, "crashed").len(),
        1,
        "repeated crashes are collapsed"
    );
    assert_eq!(
        lifecycle(&events, "down"),
        vec![format!("proxy is down: {want}")]
    );

    drop(blocker);
    wait_for("recovery", Duration::from_secs(40), || {
        matches!(sup.status().phase, Phase::Running)
    });
    let st = sup.status();
    assert!(
        st.healthy && st.error.is_none() && st.consecutive_failures == 0,
        "{st:?}"
    );
    let recovered = lifecycle(&events, "recovered");
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert!(
        recovered[0].starts_with("proxy recovered after "),
        "{recovered:?}"
    );
    sup.shutdown();
}

#[test]
fn orphan_with_our_config_is_killed_at_start() {
    let Some(bin) = skip_without_binary("orphan_with_our_config_is_killed_at_start") else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::create(&tmp.path().join("data"), Some(tmp.path())).unwrap();
    let cfg = loopback_config();
    // First supervisor: writes the CA and config, then goes away.
    let (_, cb) = counter();
    let (_, ev) = events();
    let first =
        ProxySupervisor::start(bin.clone(), dirs.clone(), cfg.clone(), vec![], cb, ev).unwrap();
    first.shutdown();
    drop(first);

    // The orphan: a copy of the binary elsewhere (not the pid file's), our config, no
    // parent watch.
    let other = tmp.path().join("old-app");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::copy(bin.join("iron-proxy"), other.join("iron-proxy")).unwrap();
    let mut orphan = Command::new(other.join("iron-proxy"))
        .arg("--config")
        .arg(config::config_path(&dirs))
        .env_clear()
        .env("IRON_MANAGEMENT_API_KEY", "k")
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let opid = orphan.id();
    wait_for("orphan listening", Duration::from_secs(10), || {
        TcpStream::connect(("127.0.0.1", cfg.metrics_port)).is_ok()
    });
    let (_, cb) = counter();
    let (events, ev) = events();
    let sup = ProxySupervisor::start(bin, dirs, cfg, vec![], cb, ev).unwrap();
    assert!(orphan.try_wait().unwrap().is_some() || orphan.wait().is_ok());
    let killed = lifecycle(&events, "orphan_killed");
    assert_eq!(
        killed,
        vec![format!(
            "killed orphaned iron-proxy pid {opid} (left running by an earlier manager)"
        )]
    );
    wait_for("healthy proxy", Duration::from_secs(15), || {
        sup.status().healthy
    });
    sup.shutdown();
}

/// A real, inert child records exactly the config/value material it was started with.
/// No monitor thread, network service, external proxy binary or credential store is used.
fn publication_supervisor(
    tmp: &Path,
    on_change: Arc<dyn Fn() + Send + Sync>,
) -> Arc<ProxySupervisor> {
    use std::os::unix::fs::PermissionsExt;

    let dirs = DataDirs::create(&tmp.join("data"), Some(tmp)).unwrap();
    let binary = tmp.join("iron-proxy");
    std::fs::write(
        &binary,
        "#!/bin/sh\n\
         cp iron-proxy.yaml started.yaml || exit 1\n\
         cat ../../net.thinkscape.asm/values/* > started.values 2>/dev/null\n\
         echo started >> starts\n\
         exec /bin/sleep 60\n",
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_, on_event) = events();
    Arc::new(ProxySupervisor {
        binary,
        ca: ca::CaPaths::new(&dirs.proxy),
        ca_expiry: None,
        logs: Arc::new(logs::LogSink::new(dirs.logs.join("proxy.log"))),
        on_change,
        on_event,
        ops: Mutex::new(()),
        state: Mutex::new(State {
            cfg: loopback_config(),
            entries: Vec::new(),
            apply_pending: false,
            sentinels: files::SentinelStore::default(),
            child: None,
            health: health::Health::default(),
            last_phase: Phase::Starting,
            killed_port_holder: false,
            last_reload: None,
            error: None,
            backoff: BACKOFF_MIN,
            restart_at: None,
            shutdown: false,
            spawns: 0,
        }),
        dirs,
    })
}

fn publication_entry(value: &str) -> ProxyEntry {
    ProxyEntry {
        lease_id: "generated-lease".into(),
        index: 0,
        sentinel: new_sentinel(),
        value: value.into(),
        hosts: vec!["api.github.com".into()],
    }
}

fn wait_for_publication(sup: &ProxySupervisor, starts: usize) {
    wait_for("child config snapshot", Duration::from_secs(3), || {
        std::fs::read_to_string(sup.dirs.proxy.join("starts"))
            .is_ok_and(|s| s.lines().count() == starts)
    });
}

fn retry_publication(sup: &ProxySupervisor) {
    lock(&sup.state).restart_at = Some(Instant::now());
    assert!(sup.tick(false));
}

/// Renaming over a directory fails even for privileged test runners.
fn block_publication_file(path: &Path) {
    std::fs::rename(path, path.with_extension("saved")).unwrap();
    std::fs::create_dir(path).unwrap();
}

#[test]
fn rotation_value_write_failure_stops_child_and_rewrites_before_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let sup = publication_supervisor(tmp.path(), cb);
    let initial = publication_entry(REAL);
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for_publication(&sup, 1);
    let pid = sup.status().pid.unwrap();
    let value_path = sup
        .dirs
        .values
        .join(files::value_file_name(&initial.lease_id, initial.index));
    block_publication_file(&value_path);
    let replacement = ProxyEntry {
        value: "replacement-token".into(),
        ..initial
    };

    assert!(sup.apply(vec![replacement]).is_err());
    assert!(!sup.status().running);
    assert!(!pid_alive(pid));
    assert!(lock(&sup.state).apply_pending);
    assert_eq!(lock(&sup.state).entries[0].value, "replacement-token");
    // The old readable config must not be used while its value rewrite still fails.
    retry_publication(&sup);
    assert!(!sup.status().running);
    assert_eq!(lock(&sup.state).spawns, 1);
    assert!(lock(&sup.state).apply_pending);

    std::fs::remove_dir(&value_path).unwrap();
    retry_publication(&sup);
    wait_for_publication(&sup, 2);
    assert!(!lock(&sup.state).apply_pending);
    assert_eq!(
        std::fs::read_to_string(sup.dirs.proxy.join("started.values")).unwrap(),
        "replacement-token"
    );
    assert_eq!(std::fs::read_to_string(value_path).unwrap(), "replacement-token");
    sup.shutdown();
}

#[test]
fn removal_rewrite_failures_never_restart_the_old_grant() {
    // Exercise both the sentinel-store write and the final YAML write.
    for blocked_name in ["sentinels.json", "iron-proxy.yaml"] {
        let tmp = tempfile::tempdir().unwrap();
        let (_, cb) = counter();
        let sup = publication_supervisor(tmp.path(), cb);
        let initial = publication_entry(REAL);
        let sentinel = initial.sentinel.clone();
        sup.apply(vec![initial]).unwrap();
        wait_for_publication(&sup, 1);
        let pid = sup.status().pid.unwrap();
        let blocked = sup.dirs.proxy.join(blocked_name);
        block_publication_file(&blocked);

        assert!(sup.apply(vec![]).is_err());
        assert!(!sup.status().running);
        assert!(!pid_alive(pid));
        assert!(lock(&sup.state).entries.is_empty());
        assert!(lock(&sup.state).apply_pending);
        retry_publication(&sup);
        assert!(!sup.status().running);
        assert_eq!(lock(&sup.state).spawns, 1);

        std::fs::remove_dir(&blocked).unwrap();
        retry_publication(&sup);
        wait_for_publication(&sup, 2);
        let yaml = std::fs::read_to_string(sup.dirs.proxy.join("started.yaml")).unwrap();
        assert!(yaml.contains(&sentinel));
        assert!(yaml.contains("ended: true"));
        assert!(!yaml.contains("source:"));
        assert_eq!(
            std::fs::read_to_string(sup.dirs.proxy.join("started.values")).unwrap(),
            ""
        );
        assert!(!lock(&sup.state).apply_pending);
        sup.shutdown();
    }
}

#[test]
fn failed_rotation_followed_by_removal_cannot_recover_the_rotated_grant() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let sup = publication_supervisor(tmp.path(), cb);
    let initial = publication_entry(REAL);
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for_publication(&sup, 1);
    let value_path = sup
        .dirs
        .values
        .join(files::value_file_name(&initial.lease_id, initial.index));
    block_publication_file(&value_path);
    assert!(
        sup.apply(vec![ProxyEntry {
            value: "never-published-token".into(),
            ..initial
        }])
        .is_err()
    );
    let blocked = sup.dirs.proxy.join("sentinels.json");
    block_publication_file(&blocked);
    assert!(sup.apply(vec![]).is_err());
    retry_publication(&sup);
    assert_eq!(lock(&sup.state).spawns, 1);
    assert!(lock(&sup.state).entries.is_empty());
    std::fs::remove_dir(&blocked).unwrap();
    std::fs::remove_dir(&value_path).unwrap();
    retry_publication(&sup);
    wait_for_publication(&sup, 2);
    assert_eq!(
        std::fs::read_to_string(sup.dirs.proxy.join("started.values")).unwrap(),
        ""
    );
    assert!(
        !std::fs::read_to_string(sup.dirs.proxy.join("started.yaml"))
            .unwrap()
            .contains("source:")
    );
    sup.shutdown();
}

#[test]
fn explicit_restart_cannot_bypass_a_pending_value_rewrite() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let sup = publication_supervisor(tmp.path(), cb);
    let initial = publication_entry(REAL);
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for_publication(&sup, 1);
    let value_path = sup
        .dirs
        .values
        .join(files::value_file_name(&initial.lease_id, initial.index));
    block_publication_file(&value_path);
    assert!(
        sup.apply(vec![ProxyEntry {
            value: "replacement-token".into(),
            ..initial
        }])
        .is_err()
    );
    assert!(sup.restart().is_err());
    assert!(!sup.status().running);
    assert_eq!(lock(&sup.state).spawns, 1);
    assert!(lock(&sup.state).apply_pending);
    sup.shutdown();
}

#[test]
fn deferred_apply_notifies_only_after_caller_releases_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let authorization = Arc::new(Mutex::new(()));
    let subject: Arc<Mutex<Option<Weak<ProxySupervisor>>>> = Arc::new(Mutex::new(None));
    let calls = Arc::new(AtomicUsize::new(0));
    let cb: Arc<dyn Fn() + Send + Sync> = {
        let authorization = authorization.clone();
        let subject = subject.clone();
        let calls = calls.clone();
        Arc::new(move || {
            let _authorization = authorization.try_lock().expect("authorization still held");
            let sup = lock(&subject).as_ref().unwrap().upgrade().unwrap();
            let _ops = sup.ops.try_lock().expect("supervisor ops still held");
            let _state = sup.state.try_lock().expect("supervisor state still held");
            calls.fetch_add(1, Ordering::SeqCst);
        })
    };
    let sup = publication_supervisor(tmp.path(), cb);
    *lock(&subject) = Some(Arc::downgrade(&sup));
    let initial = publication_entry(REAL);
    {
        let _authorization = lock(&authorization);
        sup.apply_deferred(vec![initial]).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    sup.notify_changed();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    wait_for_publication(&sup, 1);
    let blocked = sup.dirs.proxy.join("iron-proxy.yaml");
    block_publication_file(&blocked);
    {
        let _authorization = lock(&authorization);
        assert!(sup.apply_deferred(vec![]).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    sup.notify_changed();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    std::fs::remove_dir(blocked).unwrap();
    sup.apply(vec![]).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    sup.shutdown();
}

#[test]
fn invalid_desired_entries_stop_child_and_cannot_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let sup = publication_supervisor(tmp.path(), cb);
    let initial = publication_entry(REAL);
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for_publication(&sup, 1);
    let pid = sup.status().pid.unwrap();
    assert!(
        sup.apply(vec![ProxyEntry {
            value: String::new(),
            ..initial
        }])
        .is_err()
    );
    assert!(!sup.status().running);
    assert!(!pid_alive(pid));
    assert!(lock(&sup.state).apply_pending);
    retry_publication(&sup);
    assert!(!sup.status().running);
    assert_eq!(lock(&sup.state).spawns, 1);
    sup.apply(vec![]).unwrap();
    wait_for_publication(&sup, 2);
    assert!(!lock(&sup.state).apply_pending);
    sup.shutdown();
}

#[test]
fn failed_restart_retains_the_new_desired_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let sup = publication_supervisor(tmp.path(), cb);
    let initial = publication_entry(REAL);
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for_publication(&sup, 1);
    let binary_backup = sup.binary.with_extension("saved");
    std::fs::rename(&sup.binary, &binary_backup).unwrap();
    assert!(
        sup.apply(vec![ProxyEntry {
            value: "replacement-token".into(),
            ..initial
        }])
        .is_err()
    );
    assert!(!sup.status().running);
    assert!(lock(&sup.state).apply_pending);
    retry_publication(&sup);
    assert!(!sup.status().running);
    assert_eq!(lock(&sup.state).spawns, 1);
    std::fs::rename(binary_backup, &sup.binary).unwrap();
    retry_publication(&sup);
    wait_for_publication(&sup, 2);
    assert!(!lock(&sup.state).apply_pending);
    assert_eq!(
        std::fs::read_to_string(sup.dirs.proxy.join("started.values")).unwrap(),
        "replacement-token"
    );
    sup.shutdown();
}

#[test]
fn rewrite_failures_stop_forwarding_and_never_recover_an_old_grant() {
    let binary = bin_dir().join("iron-proxy");
    assert!(
        binary.exists(),
        "missing prerequisite {}; run just proxy before supervisor integration tests",
        binary.display()
    );
    let tmp = tempfile::tempdir().unwrap();
    let (_, cb) = counter();
    let mut sup = publication_supervisor(tmp.path(), cb);
    {
        let sup = Arc::get_mut(&mut sup).unwrap();
        sup.binary = binary;
        sup.ca = ca::ensure(&sup.binary, &sup.dirs.proxy).unwrap();
        let mut st = lock(&sup.state);
        st.cfg.allow_plain_http = true;
        st.cfg.upstream_deny_cidrs = Some(vec!["192.0.2.0/24".into()]);
    }
    let cfg = sup.config();
    let ready = || {
        http::request(
            cfg.metrics_port,
            "GET",
            "/healthz",
            None,
            Duration::from_millis(100),
        )
        .is_ok_and(|r| r.status == 200)
    };
    let initial = ProxyEntry {
        hosts: vec!["127.0.0.1".into()],
        ..publication_entry(REAL)
    };
    let sentinel = initial.sentinel.clone();
    let (echo_port, seen) = echo_server();
    sup.apply(vec![initial.clone()]).unwrap();
    wait_for("initial proxy", Duration::from_secs(10), ready);
    assert_eq!(via_proxy(cfg.port, echo_port, &sentinel).0, 200);
    assert_eq!(lock(&seen).last().map(String::as_str), Some(REAL));

    let value_path = sup
        .dirs
        .values
        .join(files::value_file_name(&initial.lease_id, initial.index));
    block_publication_file(&value_path);
    assert!(
        sup.apply(vec![ProxyEntry {
            value: "replacement-token".into(),
            ..initial
        }])
        .is_err()
    );
    assert!(!sup.status().running);
    assert!(TcpStream::connect(("127.0.0.1", cfg.port)).is_err());
    retry_publication(&sup);
    assert!(!sup.status().running);
    std::fs::remove_dir(&value_path).unwrap();
    retry_publication(&sup);
    wait_for("rotated proxy", Duration::from_secs(10), ready);
    assert_eq!(via_proxy(cfg.port, echo_port, &sentinel).0, 200);
    assert_eq!(
        lock(&seen).last().map(String::as_str),
        Some("replacement-token")
    );

    // Keep the old YAML readable while the sentinel-state write fails. Recovery
    // must rewrite a blocked sentinel instead of restarting with that old grant.
    let blocked = sup.dirs.proxy.join("sentinels.json");
    block_publication_file(&blocked);
    assert!(sup.apply(vec![]).is_err());
    assert!(!sup.status().running);
    assert!(TcpStream::connect(("127.0.0.1", cfg.port)).is_err());
    retry_publication(&sup);
    assert!(!sup.status().running);
    std::fs::remove_dir(blocked).unwrap();
    retry_publication(&sup);
    wait_for("reduced proxy", Duration::from_secs(10), ready);
    let calls = lock(&seen).len();
    assert_eq!(via_proxy(cfg.port, echo_port, &sentinel).0, 403);
    assert_eq!(lock(&seen).len(), calls);
    assert!(!lock(&sup.state).apply_pending);
    sup.shutdown();
}
