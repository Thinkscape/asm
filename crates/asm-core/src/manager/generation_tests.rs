//! Real manager/store and isolated HTTP-provider tests. No Keychain or GitHub access.
use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Condvar, mpsc};

use asm_proto::generators::GithubPermission;
use asm_proto::wire::{CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, CAPABILITY_SECRET_FIELDS_V1, HostInfo, RequestBody};
use serde_json::{Value, json};
use crate::generator::GithubAppConfig;
use crate::manager::{StartOptions, now};

struct Quiet;
impl ffi::ManagerObserver for Quiet { fn changed(&self, _: String) {} }

struct Gate { entered: mpsc::SyncSender<()>, released: Mutex<bool>, wake: Condvar }
impl Gate {
    fn release(&self) { *lock(&self.released) = true; self.wake.notify_all(); }
}

struct ProviderState {
    clock: Arc<AtomicI64>, issued: AtomicUsize, status: AtomicU16,
    ttl: AtomicI64, revoked: Mutex<Vec<String>>, bodies: Mutex<Vec<Value>>,
    gate: Mutex<Option<Arc<Gate>>>, stop: AtomicBool,
    revoke_delay_ms: AtomicI64, active_revocations: AtomicUsize, peak_revocations: AtomicUsize,
}
struct Provider { url: reqwest::Url, state: Arc<ProviderState>, thread: Option<std::thread::JoinHandle<()>> }
impl Provider {
    fn start(clock: Arc<AtomicI64>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
        let state = Arc::new(ProviderState { clock, issued: AtomicUsize::new(0), status: AtomicU16::new(201),
            ttl: AtomicI64::new(3600), revoked: Mutex::new(Vec::new()), bodies: Mutex::new(Vec::new()),
            gate: Mutex::new(None), stop: AtomicBool::new(false), revoke_delay_ms: AtomicI64::new(0),
            active_revocations: AtomicUsize::new(0), peak_revocations: AtomicUsize::new(0) });
        let server = state.clone();
        let thread = std::thread::spawn(move || {
            while !server.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => { let state = server.clone(); std::thread::spawn(move || respond(stream, state)); }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
                    Err(e) => panic!("local provider accept: {e}"),
                }
            }
        });
        Self { url, state, thread: Some(thread) }
    }
    fn block_next(&self) -> (Arc<Gate>, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::sync_channel(1);
        let gate = Arc::new(Gate { entered: tx, released: Mutex::new(false), wake: Condvar::new() });
        *lock(&self.state.gate) = Some(gate.clone());
        (gate, rx)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        if let Some(gate) = lock(&self.state.gate).take() { gate.release(); }
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}
fn github_repository_json(id: u64) -> Value {
    json!({ "id": id, "full_name": format!("acme/repo{id}") })
}

fn respond(mut stream: TcpStream, state: Arc<ProviderState>) {
    // Darwin can inherit O_NONBLOCK from this fixture's accept loop. Socket
    // timeouts do not clear that flag, and treating WouldBlock as EOF races POST.
    stream.set_nonblocking(false).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let remaining = || deadline.checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero()).expect("local provider request deadline elapsed");
    let mut received = Vec::new();
    let mut buffer = [0; 4096];
    let header_end = loop {
        stream.set_read_timeout(Some(remaining())).unwrap();
        let count = stream.read(&mut buffer).expect("read local provider request");
        if count == 0 && received.is_empty() { return; }
        assert_ne!(count, 0, "incomplete local provider request headers");
        received.extend_from_slice(&buffer[..count]);
        if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(received.len() <= 65_536, "local provider request headers are too large");
    };
    let headers = std::str::from_utf8(&received[..header_end]).unwrap();
    let first = headers.lines().next().unwrap().to_string();
    let mut length = 0;
    let mut authorization = String::new();
    for line in headers.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") { length = value.trim().parse::<usize>().unwrap(); }
            if key.eq_ignore_ascii_case("authorization") { authorization = value.trim().trim_start_matches("Bearer ").to_string(); }
        }
    }
    let mut body = received[header_end..].to_vec();
    while body.len() < length {
        stream.set_read_timeout(Some(remaining())).unwrap();
        let wanted = (length - body.len()).min(buffer.len());
        let count = stream.read(&mut buffer[..wanted]).expect("read local provider request body");
        assert_ne!(count, 0, "incomplete local provider request body");
        body.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(body.len(), length, "unexpected bytes after local provider request");
    let (status, body) = if first.starts_with("DELETE /installation/token ") {
        if authorization.starts_with("discovery-") {
            let _ = write!(stream, "HTTP/1.1 204 Test\r\nConnection: close\r\n\r\n");
            return;
        }
        lock(&state.revoked).push(authorization);
        let active = state.active_revocations.fetch_add(1, Ordering::SeqCst) + 1;
        state.peak_revocations.fetch_max(active, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_millis(state.revoke_delay_ms.load(Ordering::SeqCst).max(0) as u64);
        while Instant::now() < until && !state.stop.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_millis(5)); }
        state.active_revocations.fetch_sub(1, Ordering::SeqCst);
        (204, String::new())
    } else if let Some(id) = first.strip_prefix("GET /app/installations/")
        .and_then(|path| path.strip_suffix(" HTTP/1.1")).and_then(|id| id.parse::<u64>().ok())
    {
        assert!([7, 8].contains(&id));
        (200, json!({"id":id,"account":{"login":"acme"},"suspended_at":null,
            "permissions":{"metadata":"read","contents":"write"}}).to_string())
    } else if first == "GET /installation/repositories?per_page=100&page=1 HTTP/1.1" {
        let ids = match authorization.as_str() {
            "discovery-7" => [1, 2],
            "discovery-8" => [3, 4],
            _ => panic!("expected a discovery token"),
        };
        (200, json!({"total_count":ids.len(),"repositories":ids.map(github_repository_json)}).to_string())
    } else {
        let installation = first.strip_prefix("POST /app/installations/")
            .and_then(|path| path.strip_suffix("/access_tokens HTTP/1.1"))
            .and_then(|id| id.parse::<u64>().ok()).expect("expected a GitHub installation token request");
        let permitted_ids = match installation { 7 => [1, 2], 8 => [3, 4], _ => panic!("unexpected installation") };
        let request: Value = serde_json::from_slice(&body).unwrap();
        let expires_at = fmt_unix(state.clock.load(Ordering::SeqCst) + state.ttl.load(Ordering::SeqCst));
        if request.get("repository_ids").is_none() {
            assert_eq!(request, json!({"permissions":{"metadata":"read"}}));
            (201, json!({"token":format!("discovery-{installation}"),"expires_at":expires_at,
                "permissions":request["permissions"]}).to_string())
        } else {
            lock(&state.bodies).push(request.clone());
            let version = state.issued.fetch_add(1, Ordering::SeqCst) + 1;
            let gate = lock(&state.gate).take();
            if let Some(gate) = gate {
                gate.entered.send(()).unwrap();
                let mut released = lock(&gate.released);
                while !*released { released = gate.wake.wait(released).unwrap(); }
            }
            let status = state.status.load(Ordering::SeqCst);
            let repositories: Vec<_> = request["repository_ids"].as_array().unwrap().iter()
                .map(|id| {
                    let id = id.as_u64().unwrap();
                    assert!(permitted_ids.contains(&id));
                    github_repository_json(id)
                }).collect();
            (status, json!({"token":format!("isolated-credential-{version}"),"expires_at":expires_at,
                "permissions":request["permissions"],"repositories":repositories}).to_string())
        }
    };
    let _ = write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

struct Fixture { core: Arc<Core>, provider: Provider, clock: Arc<AtomicI64>, host: HostRecord, start: i64, _tmp: tempfile::TempDir }
impl Fixture {
    fn new() -> Self {
        Self::with_proxy(false)
    }

    fn with_proxy(real: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let dirs = crate::paths::DataDirs::create(&data, Some(tmp.path())).unwrap();
        let bin = if real {
            let bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist/bin");
            assert!(bin.join("iron-proxy").is_file(), "missing prerequisite: run just proxy");
            bin
        } else {
            std::fs::write(dirs.proxy.join("ca.crt"), "isolated existing ca").unwrap();
            std::fs::write(dirs.proxy.join("ca.key"), "isolated existing key").unwrap();
            tmp.path().join("no-proxy-binary")
        };
        let listeners: Vec<_> = (0..5).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let ports: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap().port()).collect();
        drop(listeners);
        let core = Core::start(data, bin, Arc::new(Quiet), StartOptions {
            values_root: Some(tmp.path().to_path_buf()),
            settings: vec![(crate::settings::API_BIND.into(), json!("127.0.0.1")),
                (crate::settings::API_PORT.into(), json!(0)),
                (crate::settings::PROXY_BIND.into(), json!("127.0.0.1")),
                (crate::settings::PROXY_PORT.into(), json!(ports[0])),
                (crate::settings::PROXY_HTTP_PORT.into(), json!(ports[1])),
                (crate::settings::PROXY_HTTPS_PORT.into(), json!(ports[2])),
                (crate::settings::PROXY_MGMT_PORT.into(), json!(ports[3])),
                (crate::settings::PROXY_METRICS_PORT.into(), json!(ports[4]))],
        }).unwrap();
        let start = now();
        let clock = Arc::new(AtomicI64::new(start));
        let time = clock.clone();
        lock(&core.generation).clock = Arc::new(move || time.load(Ordering::SeqCst));
        let provider = Provider::start(clock.clone());
        let host = HostRecord { id: new_uuid_v4(), info: HostInfo { hostname: "isolated-host".into(), ..Default::default() },
            name: String::new(), address: "127.0.0.1".into(), paired_at: start, last_seen: None, revoked_at: None, machine_hint: None };
        core.store.insert_host(&host, &asm_proto::crypto::sha256(host.id.as_bytes())).unwrap();
        let f = Self { core, provider, clock, host, start, _tmp: tmp };
        f.install("app-a", "release-bot", 1);
        f
    }
    fn grant() -> GithubGrant {
        GithubGrant { installation_id: 7, repositories: vec![GithubRepository { id: 1, full_name: "acme/repo1".into() }],
            permissions: [("metadata".into(), GithubPermission::Read), ("contents".into(), GithubPermission::Read)].into_iter().collect() }
    }
    fn install(&self, id: &str, name: &str, position: i64) {
        self.install_with_ceilings(id, name, position, vec![Self::grant()]);
    }
    fn install_with_ceilings(&self, id: &str, name: &str, position: i64, installations: Vec<GithubGrant>) {
        let config = GithubAppConfig { client_id: format!("client-{id}"), installations };
        let client = Arc::new(self.github_client(&config, crate::generator::github::test_pem()).unwrap());
        self.core.install_generator_client(GeneratorRecord { id: id.into(), name: name.into(), config: GeneratorConfig::GithubApp(config), revision: 1, position }, client).unwrap();
    }
    fn github_client(&self, config: &GithubAppConfig, pem: &str) -> Result<GithubAppGenerator> {
        GithubAppGenerator::with_client_for_tests(config, pem,
            reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            self.provider.url.clone())
    }
    fn at(&self, elapsed: i64) { self.clock.store(self.start + elapsed, Ordering::SeqCst); }
    fn body(&self, name: &str) -> RequestBody {
        serde_json::from_value(json!({ "kind":"get", "name":name, "reason":"Read the approved repository", "agent":"agent-a",
            "generation":{"provider":"github_app","scope":{"repositories":["acme/repo1"],"permissions":{"contents":"read"}}},
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, CAPABILITY_SECRET_FIELDS_V1] })).unwrap()
    }
    fn request(&self, body: RequestBody) -> Result<RequestState> { self.core.create_request(&self.host, "127.0.0.1", body) }
    fn approve(&self, id: &str, generator: &str, mode: LeaseMode, duration: u64) -> Result<()> {
        self.approve_github(id, generator, 1, Self::grant(), mode, duration)
    }
    fn approve_github(&self, id: &str, generator: &str, revision: u64, grant: GithubGrant, mode: LeaseMode, duration: u64) -> Result<()> {
        self.core.resolve_request(id, ffi::Decision::ApproveGet { mode: mode.into(), duration_secs: Some(duration),
            hosts: if mode == LeaseMode::Sentinel { vec!["api.github.com".into()] } else { Vec::new() },
            generation: Some(GenerationSelection { generator_id: generator.into(), generator_revision: revision,
                grant: GenerationGrant::GithubApp(grant) }.into()) })
    }
    fn first(&self) -> GetResult {
        let pending = self.request(self.body("GH_TOKEN")).unwrap();
        assert_eq!(pending.status, RequestStatus::Pending);
        self.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap();
        get(self.core.request_state(&self.host.id, &pending.request_id).unwrap())
    }
    fn issued(&self) -> usize { self.provider.state.issued.load(Ordering::SeqCst) }
}
impl Drop for Fixture { fn drop(&mut self) { self.core.shutdown(); } }
fn get(state: RequestState) -> GetResult {
    match state.result.unwrap() { RequestResult::Get(result) => result, _ => panic!("expected get result") }
}
fn conditional(f: &Fixture, lease: &str, version: u64) -> RequestBody {
    let mut body = f.body("GITHUB_TOKEN");
    if let RequestBody::Get { lease_id, refresh, refresh_from_version, .. } = &mut body {
        *lease_id = Some(lease.into()); *refresh = true; *refresh_from_version = Some(version);
    }
    body
}

#[test]
fn generation_twelve_hour_authority_renews_one_hour_credential_without_extension() {
    let f = Fixture::new();
    let first = f.first();
    assert_eq!(first.expires_at, Some(fmt_unix(f.start + 43_200)));
    assert_eq!(first.credential_expires_at, Some(fmt_unix(f.start + 3_600)));
    assert_eq!(first.credential_version, Some(1));
    for elapsed in [60, 2_999] {
        f.at(elapsed);
        let reused = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
        assert_eq!(reused.files, first.files);
        assert_eq!(reused.lease_id, first.lease_id);
    }
    assert_eq!(f.issued(), 1);
    f.at(3_000);
    let renewed = get(f.request(f.body("GH_TOKEN")).unwrap());
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.expires_at, first.expires_at);
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.credential_version, Some(2));
    assert_eq!(renewed.credential_expires_at, Some(fmt_unix(f.start + 6_600)));
    assert!(lock(&f.provider.state.revoked).is_empty());
    assert_eq!(lock(&f.core.generation).cached[&first.lease_id].retired.len(), 1);
    f.at(43_200);
    assert_eq!(f.request(f.body("GH_TOKEN")).unwrap().status, RequestStatus::Pending);
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_conditional_refresh_coalesces_and_revokes_all_known_predecessors() {
    let f = Fixture::new();
    let first = f.first();
    f.at(3_000);
    let second = get(f.request(f.body("GH_TOKEN")).unwrap());
    let refreshed = get(f.request(conditional(&f, &first.lease_id, 2)).unwrap());
    assert_eq!(refreshed.credential_version, Some(3));
    assert_eq!(f.issued(), 3);
    let revoked = lock(&f.provider.state.revoked).clone();
    assert!(revoked.contains(&first.files[0].content));
    assert!(revoked.contains(&second.files[0].content));
    let coalesced = get(f.request(conditional(&f, &first.lease_id, 2)).unwrap());
    assert_eq!(coalesced.credential_version, Some(3));
    assert_eq!(f.issued(), 3);
    assert!(f.request(conditional(&f, &first.lease_id, 4)).is_err());
    let mut ordinary = f.body("GH_TOKEN");
    if let RequestBody::Get { lease_id, .. } = &mut ordinary { *lease_id = Some(first.lease_id); }
    assert_eq!(get(f.request(ordinary).unwrap()).credential_version, Some(3));
    assert_eq!(f.issued(), 3);
}

#[test]
fn generation_retired_bound_rate_limits_without_revoking_live_raw_consumers() {
    let f = Fixture::new();
    f.provider.state.ttl.store(600, Ordering::SeqCst);
    let first = f.first();
    for version in [2, 3] {
        assert_eq!(get(f.request(f.body("GH_TOKEN")).unwrap()).credential_version, Some(version));
    }
    let error = f.request(f.body("GH_TOKEN")).unwrap_err();
    assert_eq!(error.code, asm_proto::ErrorCode::RateLimited);
    assert_eq!(f.issued(), 3);
    assert!(lock(&f.provider.state.revoked).is_empty());
    f.at(601);
    f.core.sweep_generated_at(f.start + 601);
    f.provider.state.ttl.store(3_600, Ordering::SeqCst);
    let renewed = get(f.request(f.body("GH_TOKEN")).unwrap());
    assert_eq!(renewed.credential_version, Some(4));
    assert_eq!(renewed.lease_id, first.lease_id);
}

#[test]
fn generation_raw_pending_marker_is_value_free_and_consumed_once() {
    let f = Fixture::new();
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    f.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap();
    {
        let book = lock(&f.core.book);
        let done = &book.done[&pending.request_id];
        assert!(matches!(&done.state.result, Some(RequestResult::Get(g)) if g.files.is_empty()));
        assert!(!done.generated.as_ref().unwrap().consumed);
    }
    let result = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert!(!result.files[0].content.is_empty());
    assert!(f.core.request_state(&f.host.id, &pending.request_id).is_err());
    let immediate = f.request(f.body("GH_TOKEN")).unwrap();
    assert!(f.core.request_state(&f.host.id, &immediate.request_id).is_err());
    let another = f.request(f.body("GH_TOKEN")).unwrap();
    f.core.cancel_request(&f.host.id, &another.request_id).unwrap();
    assert!(f.core.request_state(&f.host.id, &another.request_id).is_err());
}

#[test]
fn generation_mint_cancel_and_pending_deadline_discard_tokens() {
    for cancel in [true, false] {
        let f = Fixture::new();
        let pending = f.request(f.body("GH_TOKEN")).unwrap();
        let (gate, entered) = f.provider.block_next();
        let core = f.core.clone();
        let id = pending.request_id.clone();
        let worker = std::thread::spawn(move || core.resolve_request(&id, ffi::Decision::ApproveGet {
            mode: ffi::LeaseMode::Raw, duration_secs: Some(43_200), hosts: vec![],
            generation: Some(GenerationSelection { generator_id: "app-a".into(), generator_revision: 1,
                grant: GenerationGrant::GithubApp(Fixture::grant()) }.into()) }));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        if cancel { f.core.cancel_request(&f.host.id, &pending.request_id).unwrap(); }
        else { f.at(10_000); }
        gate.release();
        assert!(worker.join().unwrap().is_err());
        assert!(f.core.store.list_leases().unwrap().is_empty());
        assert!(lock(&f.core.generation).cached.is_empty());
        assert_eq!(lock(&f.provider.state.revoked).len(), 1);
    }
}

#[test]
fn generation_revoke_racing_renewal_never_reinstalls_token_or_proxy_entries() {
    let f = Fixture::new();
    let first = f.first();
    f.at(3_000);
    let (gate, entered) = f.provider.block_next();
    let core = f.core.clone();
    let host = f.host.clone();
    let body = f.body("GH_TOKEN");
    let worker = std::thread::spawn(move || core.create_request(&host, "127.0.0.1", body));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    f.core.revoke_lease(&first.lease_id).unwrap();
    gate.release();
    assert!(worker.join().unwrap().is_err());
    assert!(!lock(&f.core.generation).cached.contains_key(&first.lease_id));
    assert!(!lock(&f.core.proxy_state).entries.contains_key(&first.lease_id));
    assert_eq!(lock(&f.provider.state.revoked).len(), 2);
}

#[test]
fn generation_restart_missing_cache_keeps_durable_version_and_original_grant() {
    let f = Fixture::new();
    let first = f.first();
    // Restart's exact semantic seam: all nonpersistent material is gone, SQLite
    // remains authoritative. No read/list/sweep is allowed to mint it back.
    lock(&f.core.generation).cached.clear();
    f.core.sweep_generated_at(f.start);
    f.core.list_leases();
    assert_eq!(f.issued(), 1);
    assert_eq!(lock(&f.core.generation).next_expiry(f.start), None);
    let next = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
    assert_eq!(next.credential_version, Some(2));
    assert_eq!(next.lease_id, first.lease_id);
    assert_eq!(next.generation, first.generation);
    assert_eq!(next.expires_at, first.expires_at);
}

#[test]
fn generation_latest_ended_approval_does_not_rebind_to_older_active_identity() {
    let f = Fixture::new();
    f.install("app-b", "review-bot", 2);
    let a = f.first();
    let mut body = f.body("GH_TOKEN");
    if let RequestBody::Get { new_lease, .. } = &mut body { *new_lease = true; }
    let pending = f.request(body).unwrap();
    f.approve(&pending.request_id, "app-b", LeaseMode::Raw, 43_200).unwrap();
    let b = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    f.core.revoke_lease(&b.lease_id).unwrap();
    assert_eq!(f.request(f.body("GITHUB_TOKEN")).unwrap().status, RequestStatus::Pending);
    let mut pinned = f.body("GITHUB_TOKEN");
    if let RequestBody::Get { lease_id, .. } = &mut pinned { *lease_id = Some(a.lease_id.clone()); }
    assert_eq!(get(f.request(pinned).unwrap()).lease_id, a.lease_id);
}

#[test]
fn generation_github_scope_is_required_before_reusing_an_approved_lease() {
    let f = Fixture::new();
    let first = f.first();
    let mut no_scope = f.body("GH_TOKEN");
    if let RequestBody::Get { generation, .. } = &mut no_scope { *generation = None; }
    assert!(f.request(no_scope.clone()).unwrap_err().message.contains("--repositories"));
    let mut no_repositories = f.body("GH_TOKEN");
    if let RequestBody::Get { generation: Some(GenerationRequest::GithubApp(scope)), .. } = &mut no_repositories {
        scope.repositories = None;
    }
    assert!(f.request(no_repositories).unwrap_err().message.contains("--repositories"));
    assert!(f.core.snapshot().pending.is_empty());
    assert_eq!(f.issued(), 1);

    if let RequestBody::Get { lease_id, client_capabilities, .. } = &mut no_scope {
        *lease_id = Some(first.lease_id.clone());
        client_capabilities.retain(|c| c != CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1);
    }
    // A legacy client can explicitly pin and renew its existing authority.
    f.at(3_000);
    let renewed = get(f.request(no_scope).unwrap());
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.credential_version, Some(2));
}

#[test]
fn generation_github_requests_cannot_reuse_or_approve_broader_authority() {
    let f = Fixture::new();
    let broad = f.first();
    let mut ceiling = Fixture::grant();
    ceiling.repositories.push(GithubRepository { id: 2, full_name: "acme/repo2".into() });
    f.install_with_ceilings("app-b", "review-bot", 2, vec![ceiling.clone()]);

    let metadata_only = |lease: Option<String>| {
        let mut body = f.body("GITHUB_TOKEN");
        if let RequestBody::Get { generation, lease_id, .. } = &mut body {
            *generation = Some(GenerationRequest::GithubApp(GithubScopeRequest {
                repositories: Some(vec![" ACME/REPO1 ".into()]), permissions: None,
            }));
            *lease_id = lease;
        }
        body
    };
    assert!(f.request(metadata_only(Some(broad.lease_id))).is_err());
    let pending = f.request(metadata_only(None)).unwrap();
    assert_eq!(pending.status, RequestStatus::Pending);

    // Both grants would fit the configured ceiling, but not this request.
    assert!(f.approve(&pending.request_id, "app-b", LeaseMode::Raw, 43_200).is_err());
    ceiling.permissions.remove("contents");
    assert!(f.approve_github(&pending.request_id, "app-b", 1, ceiling.clone(), LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 1);

    ceiling.repositories.pop();
    let expected = ceiling.clone();
    ceiling.repositories[0].full_name = "forged/name".into();
    f.approve_github(&pending.request_id, "app-b", 1, ceiling, LeaseMode::Raw, 43_200).unwrap();
    let approved = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let GenerationGrant::GithubApp(actual) = approved.generation.unwrap().grant;
    assert_eq!(actual, expected);
    assert_eq!(actual.repositories[0].full_name, "acme/repo1");
    assert_eq!(lock(&f.provider.state.bodies).last(),
        Some(&json!({"repository_ids":[1],"permissions":{"metadata":"read"}})));
    assert_eq!(get(f.request(metadata_only(None)).unwrap()).lease_id, approved.lease_id);
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_github_routes_within_one_installation_and_respects_pins() {
    let f = Fixture::new();
    let mut other = Fixture::grant();
    other.installation_id = 8;
    other.repositories = vec![GithubRepository { id: 3, full_name: "acme/repo3".into() }];
    f.install_with_ceilings("app-b", "review-bot", 2, vec![Fixture::grant(), other.clone()]);
    let request = |name, names: &[&str]| {
        let mut body = f.body(name);
        if let RequestBody::Get { generation: Some(GenerationRequest::GithubApp(scope)), .. } = &mut body {
            scope.repositories = Some(names.iter().map(|name| (*name).to_owned()).collect());
        }
        body
    };
    assert!(f.request(request("GH_TOKEN", &["acme/repo1", "acme/repo3"])).unwrap_err().message.contains("split"));
    assert!(f.request(request("release-bot/GH_TOKEN", &["acme/repo3"])).is_err());
    assert!(f.request(request("GH_TOKEN", &["acme/missing"])).is_err());
    assert!(f.core.snapshot().pending.is_empty());
    let pending = f.request(request("GH_TOKEN", &["ACME/REPO3"])).unwrap();
    assert!(f.approve(&pending.request_id, "app-b", LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);
    f.approve_github(&pending.request_id, "app-b", 1, other.clone(), LeaseMode::Raw, 43_200).unwrap();
    let approved = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert_eq!(approved.generation.unwrap().grant, GenerationGrant::GithubApp(other));
    assert_eq!(f.issued(), 1);
    let first_installation = f.request(request("GH_TOKEN", &["acme/repo1"])).unwrap();
    assert_eq!(first_installation.status, RequestStatus::Pending);
    f.approve(&first_installation.request_id, "app-b", LeaseMode::Raw, 43_200).unwrap();
    let again = get(f.request(request("GITHUB_TOKEN", &["acme/repo3"])).unwrap());
    assert_eq!(again.lease_id, approved.lease_id);
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_github_reattaches_pending_work_when_another_generator_appears_during_mint() {
    let f = Fixture::new();
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    let (gate, entered) = f.provider.block_next();
    let f_ref = &f;
    std::thread::scope(|scope| {
        let approve = scope.spawn(|| f_ref.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        f.install("app-b", "review-bot", 2);
        let reattached = f.request(f.body("GITHUB_TOKEN"));
        gate.release();
        approve.join().unwrap().unwrap();
        assert_eq!(reattached.unwrap().request_id, pending.request_id);
    });
    assert!(f.core.snapshot().pending.is_empty());
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_failed_initial_sentinel_publication_creates_no_active_grant() {
    let f = Fixture::new();
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    assert!(f.approve(&pending.request_id, "app-a", LeaseMode::Sentinel, 43_200).is_err());
    assert!(f.core.store.active_leases(f.start).unwrap().is_empty());
    assert!(lock(&f.core.generation).cached.is_empty());
    assert!(lock(&f.core.proxy_state).entries.is_empty());
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);
    assert_eq!(lock(&f.provider.state.revoked).len(), 1);
}

#[test]
fn generation_agent_affinity_and_explicit_lease_remain_host_authorized() {
    let f = Fixture::new();
    let first = f.first();
    let mut other = f.body("GH_TOKEN");
    if let RequestBody::Get { agent, .. } = &mut other { *agent = "agent-b".into(); }
    assert_eq!(f.request(other.clone()).unwrap().status, RequestStatus::Pending);
    if let RequestBody::Get { lease_id, .. } = &mut other { *lease_id = Some(first.lease_id.clone()); }
    assert_eq!(get(f.request(other).unwrap()).lease_id, first.lease_id);
}

#[test]
fn generation_save_persistence_failure_rolls_back_new_key_without_live_changes() {
    let f = Fixture::new();
    let keys = Mutex::new(HashMap::<String, String>::new());
    let draft = ffi::GeneratorDraft { id: None, name: "release-bot".into(),
        config: GeneratorConfig::GithubApp(GithubAppConfig { client_id: "new-client".into(), installations: vec![Fixture::grant()] }).into(),
        private_key_pem: crate::generator::github::test_pem().into() };
    assert!(f.core.save_generator_with_github(draft,
        |id| Ok(lock(&keys).get(id).cloned()),
        |id, pem| { lock(&keys).insert(id.into(), pem.into()); Ok(()) },
        |id| { lock(&keys).remove(id); Ok(()) },
        |config, pem| f.github_client(config, pem)).is_err());
    assert!(lock(&keys).is_empty());
    assert_eq!(f.core.generators.entries().len(), 1);
    assert_eq!(f.core.store.list_generators().unwrap().len(), 1);
}

#[test]
fn generation_failed_provider_renewal_preserves_authority_without_claiming_success() {
    let f = Fixture::new();
    let first = f.first();
    f.at(3_000);
    f.provider.state.status.store(403, Ordering::SeqCst);
    let error = f.request(f.body("GH_TOKEN")).unwrap_err();
    assert_eq!(error.code, asm_proto::ErrorCode::VaultUnavailable);
    let lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
    assert!(lease.is_active(f.start + 3_000));
    assert_eq!(lease.credential_version, 1);
    assert_eq!(lease.expires_at, Some(f.start + 43_200));
    assert_eq!(lock(&f.core.book).pending.len(), 0);
}

#[test]
fn generation_parallel_ordinary_gets_share_one_issuance_and_never_force_refresh() {
    let f = Fixture::new();
    let first = f.first();
    f.at(3_000);
    let (gate, entered) = f.provider.block_next();
    let launch = || {
        let core = f.core.clone();
        let host = f.host.clone();
        let body = f.body("GITHUB_TOKEN");
        std::thread::spawn(move || get(core.create_request(&host, "127.0.0.1", body).unwrap()))
    };
    let a = launch();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let b = launch();
    gate.release();
    let a = a.join().unwrap();
    let b = b.join().unwrap();
    assert_eq!(a.lease_id, first.lease_id);
    assert_eq!(a.credential_version, Some(2));
    assert_eq!(a.files, b.files);
    assert_eq!(f.issued(), 2);
    assert!(lock(&f.provider.state.revoked).is_empty());
}

#[test]
fn generation_revision_change_or_shutdown_during_mint_discards_result() {
    for shutdown in [false, true] {
        let f = Fixture::new();
        let pending = f.request(f.body("GH_TOKEN")).unwrap();
        let (gate, entered) = f.provider.block_next();
        let core = f.core.clone();
        let id = pending.request_id.clone();
        let worker = std::thread::spawn(move || core.resolve_request(&id, ffi::Decision::ApproveGet {
            mode: ffi::LeaseMode::Raw, duration_secs: Some(43_200), hosts: vec![],
            generation: Some(GenerationSelection { generator_id: "app-a".into(), generator_revision: 1,
                grant: GenerationGrant::GithubApp(Fixture::grant()) }.into()) }));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        if shutdown {
            f.core.begin_generation_shutdown();
        } else {
            let draft = ffi::GeneratorDraft { id: Some("app-a".into()), name: "release-bot".into(),
                config: GeneratorConfig::GithubApp(GithubAppConfig { client_id: "changed-client".into(),
                    installations: vec![Fixture::grant()] }).into(), private_key_pem: String::new() };
            f.core.save_generator_with_github(draft, |_| Ok(Some(crate::generator::github::test_pem().into())),
                |_, _| Ok(()), |_| Ok(()), |config, pem| f.github_client(config, pem)).unwrap();
        }
        gate.release();
        assert!(worker.join().unwrap().is_err());
        assert!(f.core.store.list_leases().unwrap().is_empty());
        assert!(lock(&f.core.generation).cached.is_empty());
        assert_eq!(lock(&f.provider.state.revoked).len(), 1);
    }
}

#[test]
fn generation_host_revocation_recalls_current_and_every_live_retired_credential() {
    let f = Fixture::new();
    f.provider.state.ttl.store(600, Ordering::SeqCst);
    f.first();
    f.request(f.body("GH_TOKEN")).unwrap();
    f.request(f.body("GITHUB_TOKEN")).unwrap();
    f.core.revoke_host(&f.host.id).unwrap();
    assert_eq!(lock(&f.provider.state.revoked).len(), 3);
    assert!(lock(&f.core.generation).cached.is_empty());
    assert!(f.core.store.active_leases(f.start).unwrap().is_empty());
}

#[test]
fn generation_shorter_replacement_expiry_does_not_revoke_a_live_predecessor() {
    let f = Fixture::new();
    let first = f.first();
    f.at(3_000);
    f.provider.state.ttl.store(100, Ordering::SeqCst);
    f.request(f.body("GH_TOKEN")).unwrap();
    f.at(3_101);
    f.core.sweep_generated_at(f.start + 3_101);
    assert!(!lock(&f.core.generation).cached.contains_key(&first.lease_id));
    assert!(lock(&f.provider.state.revoked).is_empty());
    assert_eq!(lock(&f.core.generation).retired_only[&first.lease_id].tokens.len(), 1);
    f.core.revoke_lease(&first.lease_id).unwrap();
    assert!(lock(&f.provider.state.revoked).contains(&first.files[0].content));
}

#[test]
fn generation_dirty_rotation_then_revoke_recovers_only_the_reduced_desired_set() {
    let f = Fixture::with_proxy(true);
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    f.approve(&pending.request_id, "app-a", LeaseMode::Sentinel, 43_200).unwrap();
    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let config = f.core.dirs.proxy.join("iron-proxy.yaml");
    let saved_config = config.with_extension("saved");
    std::fs::rename(&config, &saved_config).unwrap();
    // Empty desired sets write no value files. Also obstruct config replacement,
    // so revocation publication cannot succeed before recovery is exercised.
    std::fs::create_dir(&config).unwrap();
    let saved = f.core.dirs.values.with_extension("saved");
    std::fs::rename(&f.core.dirs.values, &saved).unwrap();
    std::fs::write(&f.core.dirs.values, "force a value-directory write failure").unwrap();
    f.at(3_000);
    assert!(f.request(f.body("GITHUB_TOKEN")).is_err());
    assert!(lock(&f.core.proxy_state).dirty);
    let lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
    assert_eq!(lease.credential_version, 2);
    assert!(lease.is_active(f.start + 3_000));
    assert!(!f.core.proxy.status().running);
    f.core.revoke_lease(&first.lease_id).unwrap();
    assert!(!lock(&f.core.generation).cached.contains_key(&first.lease_id));
    assert!(lock(&f.core.proxy_state).dirty);
    assert!(!f.core.proxy.status().running);
    std::fs::remove_file(&f.core.dirs.values).unwrap();
    std::fs::rename(saved, &f.core.dirs.values).unwrap();
    std::fs::remove_dir(&config).unwrap();
    std::fs::rename(saved_config, &config).unwrap();
    f.core.reconcile_proxy_with(false, |_| {}).unwrap();
    assert!(!lock(&f.core.proxy_state).dirty);
    assert!(lock(&f.core.proxy_state).entries.is_empty());
    assert_eq!(std::fs::read_dir(&f.core.dirs.values).unwrap().count(), 0);
    let yaml = std::fs::read_to_string(config).unwrap();
    let revoked_value = f.core.dirs.values.join(format!("{}.0", first.lease_id));
    assert!(!yaml.contains(revoked_value.to_str().unwrap()));
    assert!(f.core.request_state(&f.host.id, &pending.request_id).is_err());
}

#[test]
fn generation_shutdown_has_four_workers_and_one_shared_five_second_deadline() {
    let f = Fixture::new();
    for _ in 0..8 {
        let mut body = f.body("GH_TOKEN");
        if let RequestBody::Get { new_lease, .. } = &mut body { *new_lease = true; }
        let pending = f.request(body).unwrap();
        f.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap();
    }
    f.provider.state.revoke_delay_ms.store(10_000, Ordering::SeqCst);
    let start = Instant::now();
    f.core.shutdown();
    assert!(start.elapsed() < Duration::from_secs(7), "shutdown must not serialize provider timeouts");
    assert!(f.provider.state.peak_revocations.load(Ordering::SeqCst) <= 4);
    assert!(lock(&f.provider.state.revoked).len() <= 4);
    assert!(lock(&f.core.generation).cached.is_empty());
    assert!(f.request(f.body("GH_TOKEN")).is_err());
}

#[test]
fn generation_capability_and_candidate_snapshot_checks_fail_before_issuance() {
    let f = Fixture::new();
    let mut legacy = f.body("GH_TOKEN");
    if let RequestBody::Get { client_capabilities, .. } = &mut legacy {
        client_capabilities.retain(|c| c != CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1);
    }
    assert_eq!(f.request(legacy).unwrap_err().code, asm_proto::ErrorCode::Invalid);
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    f.install("app-b", "review-bot", 2);
    assert!(f.approve(&pending.request_id, "app-b", LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);
    f.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap();
    assert_eq!(f.issued(), 1);
}

#[path = "generation_admin_tests.rs"]
mod admin;

#[test]
fn generation_pending_raw_delivery_rejects_a_superseded_version_without_minting() {
    let f = Fixture::new();
    let pending = f.request(f.body("GH_TOKEN")).unwrap();
    f.approve(&pending.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap();
    f.at(3_000);
    let replacement = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
    assert_eq!(replacement.credential_version, Some(2));
    let error = f.core.request_state(&f.host.id, &pending.request_id).unwrap_err();
    assert_eq!(error.code, asm_proto::ErrorCode::VaultUnavailable);
    assert_eq!(f.issued(), 2);
}
