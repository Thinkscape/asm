//! Real manager/store and isolated HTTP-provider tests. No Keychain or GitHub access.
use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Condvar, mpsc};

use asm_proto::generators::{GCLOUD_TOKEN_NAME, GcloudAccessGrant, GcloudAccessRequest, GcloudGrant,
    GcloudPermission, GcloudScopeRequest, GithubGrant, GithubPermission, GithubRepository, GithubScopeRequest};
use asm_proto::wire::{CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_GENERATED_CREDENTIALS_V1,
    CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, CAPABILITY_OPERATOR_SELECTED_GRANT_V1,
    CAPABILITY_OPERATOR_SELECTED_PROJECT_V1, CAPABILITY_SECRET_FIELDS_V1, HostInfo, RequestBody};
use serde_json::{Value, json};
use crate::generator::{GcloudConfig, GcloudConnectionConfig, GcloudGenerator, GcloudScopeOption, GcloudService, GithubAppConfig};
use crate::manager::{StartOptions, now};

const GCLOUD_ID: &str = "cloud-a";
const GCLOUD_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const GCLOUD_OTHER_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GCLOUD_PROJECT: &str = "fixture-project";
const GCLOUD_ALT_PROJECT: &str = "quota-project";
const GCLOUD_EMAIL: &str = "workload@fixture-project.iam.gserviceaccount.com";
const GCLOUD_ADC_FIXTURE: &str = r#"{"type":"authorized_user","client_id":"test.apps.googleusercontent.com","client_secret":"isolated-client-secret","refresh_token":"isolated-refresh-token"}"#;
const CONNECTION_ID: &str = "cloud-connection";
const CONNECTION_ACCOUNT_ID: &str = "987654321";
const OPERATOR_EMAIL: &str = "operator@example.test";
const COMPUTE_SCOPE: &str = "https://www.googleapis.com/auth/compute.readonly";

#[derive(Default)]
struct ManagedIam {
    storage_only: bool,
    selected_project: Option<&'static str>,
    project_searches: usize,
    account_email: Option<String>,
    project_policy: Option<Value>,
    account_policy: Option<Value>,
    deleted: bool,
    fail_delete: bool,
    writes: Vec<&'static str>,
}

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
    google_calls: AtomicUsize, managed_iam: Mutex<ManagedIam>,
}

impl ProviderState {
    fn wait_for_release(&self) {
        let gate = lock(&self.gate).take();
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            let mut released = lock(&gate.released);
            while !*released { released = gate.wake.wait(released).unwrap(); }
        }
    }
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
            active_revocations: AtomicUsize::new(0), peak_revocations: AtomicUsize::new(0),
            google_calls: AtomicUsize::new(0), managed_iam: Mutex::new(ManagedIam::default()) });
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
    let mut quota_project = "";
    for line in headers.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") { length = value.trim().parse::<usize>().unwrap(); }
            if key.eq_ignore_ascii_case("authorization") { authorization = value.trim().trim_start_matches("Bearer ").to_string(); }
            if key.eq_ignore_ascii_case("x-goog-user-project") { quota_project = value.trim(); }
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
    if authorization == "isolated-parent" || first.starts_with("POST /oauth2/") {
        state.google_calls.fetch_add(1, Ordering::SeqCst);
    }
    let (status, body) = if first.starts_with("DELETE /installation/token ") {
        if authorization.starts_with("discovery-") {
            (204, String::new())
        } else {
            lock(&state.revoked).push(authorization);
            let active = state.active_revocations.fetch_add(1, Ordering::SeqCst) + 1;
            state.peak_revocations.fetch_max(active, Ordering::SeqCst);
            let until = Instant::now() + Duration::from_millis(state.revoke_delay_ms.load(Ordering::SeqCst).max(0) as u64);
            while Instant::now() < until && !state.stop.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_millis(5)); }
            state.active_revocations.fetch_sub(1, Ordering::SeqCst);
            (204, String::new())
        }
    } else if first == "POST /oauth2/v1/tokeninfo HTTP/1.1" {
        assert!(authorization.is_empty(), "parent token used for child introspection");
        let form: Vec<_> = reqwest::Url::parse(&format!("http://127.0.0.1/?{}", std::str::from_utf8(&body).unwrap()))
            .unwrap().query_pairs().into_owned().collect();
        assert_eq!(form.len(), 1);
        assert_eq!(form[0].0, "access_token");
        assert!(form[0].1.starts_with("isolated-child-"), "tokeninfo did not receive the child token");
        state.issued.fetch_add(1, Ordering::SeqCst);
        state.wait_for_release();
        let scopes = if form[0].1.starts_with("isolated-child-managed-broad-") {
            format!("{COMPUTE_SCOPE} {GCLOUD_SCOPE}")
        } else { GCLOUD_SCOPE.into() };
        (200, json!({ "scope": scopes, "expires_in": state.ttl.load(Ordering::SeqCst) }).to_string())
    } else if first == "POST /v1/projects/fixture-project/serviceAccounts/112233:testIamPermissions HTTP/1.1" {
        assert_eq!(authorization, "isolated-parent");
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request, json!({"permissions":["iam.serviceAccounts.getAccessToken"]}));
        (200, request.to_string())
    } else if first == "GET /v1/userinfo HTTP/1.1" {
        assert_eq!(authorization, "isolated-parent");
        (200, json!({ "sub": "90001", "email": "operator@example.test", "email_verified": true }).to_string())
    } else if first.starts_with("GET /v3/projects:search?") {
        assert_eq!(authorization, "isolated-parent");
        assert!(quota_project.is_empty());
        lock(&state.managed_iam).project_searches += 1;
        (200, json!({ "projects": [{"projectId":GCLOUD_ALT_PROJECT,"state":"ACTIVE"}] }).to_string())
    } else if first == "GET /v3/projects/fixture-project HTTP/1.1" {
        assert_eq!(authorization, "isolated-parent");
        assert_eq!(quota_project, GCLOUD_PROJECT);
        (200, json!({ "name": "projects/123456", "projectId": GCLOUD_PROJECT }).to_string())
    } else if first.contains("IamPolicy") || first.ends_with("/serviceAccounts HTTP/1.1")
        || first.ends_with("/serviceAccounts/987654321 HTTP/1.1")
    {
        if first.starts_with("DELETE ") { state.wait_for_release(); }
        assert_eq!(authorization, "isolated-parent");
        managed_iam_response(&state.managed_iam, &first, &body, quota_project)
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
        assert!([7, 8].contains(&installation));
        let request: Value = serde_json::from_slice(&body).unwrap();
        let expires_at = fmt_unix(state.clock.load(Ordering::SeqCst) + state.ttl.load(Ordering::SeqCst));
        if request.get("repository_ids").is_none() {
            assert_eq!(request, json!({"permissions":{"metadata":"read"}}));
            (201, json!({"token":format!("discovery-{installation}"),"expires_at":expires_at,
                "permissions":request["permissions"]}).to_string())
        } else {
            lock(&state.bodies).push(request.clone());
            let version = state.issued.fetch_add(1, Ordering::SeqCst) + 1;
            state.wait_for_release();
            let status = state.status.load(Ordering::SeqCst);
            let repositories: Vec<_> = request["repository_ids"].as_array().unwrap().iter()
                .map(|id| {
                    let id = id.as_u64().unwrap();
                    assert!((if installation == 7 { [1, 2] } else { [3, 4] }).contains(&id));
                    github_repository_json(id)
                }).collect();
            (status, json!({"token":format!("isolated-credential-{version}"),"expires_at":expires_at,
                "permissions":request["permissions"],"repositories":repositories}).to_string())
        }
    };
    let _ = write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

fn managed_iam_response(iam: &Mutex<ManagedIam>, request: &str, body: &[u8], quota_project: &str) -> (u16, String) {
    let mut iam = lock(iam);
    let project = iam.selected_project.unwrap_or(GCLOUD_PROJECT);
    assert_eq!(quota_project, project);
    let (method, path) = request.split_once(' ').unwrap();
    let path = path.strip_suffix(" HTTP/1.1").unwrap();
    let (version, path) = path.strip_prefix('/').unwrap().split_once("/projects/").unwrap();
    let resource = path.strip_prefix(project).expect("IAM request must use the selected project");
    let account = |email: &str| json!({
        "name": format!("projects/{project}/serviceAccounts/{CONNECTION_ACCOUNT_ID}"),
        "projectId": project, "uniqueId": CONNECTION_ACCOUNT_ID, "email": email, "disabled": false,
    });
    let response = match (method, version, resource) {
        ("POST", "v1", "/serviceAccounts") => {
            let input: Value = serde_json::from_slice(body).unwrap();
            let account_id = input["accountId"].as_str().unwrap();
            assert!(iam.account_email.is_none(), "never create or adopt a second account");
            let email = format!("{account_id}@{project}.iam.gserviceaccount.com");
            iam.writes.push("create account");
            iam.account_email = Some(email.clone());
            account(&email)
        }
        ("GET", "v1", "/serviceAccounts/987654321") if iam.deleted =>
            return (404, json!({"error":{"code":404,"status":"NOT_FOUND","message":"Service account not found"}}).to_string()),
        ("GET", "v1", "/serviceAccounts/987654321") =>
            account(iam.account_email.as_deref().expect("account exists")),
        ("DELETE", "v1", "/serviceAccounts/987654321") => {
            assert!(!iam.deleted, "retry must confirm the same UID is already absent");
            iam.deleted = true;
            iam.writes.push("delete pinned account");
            if iam.fail_delete {
                return (503, "{}".into());
            }
            json!({})
        }
        ("POST", "v3", ":getIamPolicy") => {
            assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"options":{"requestedPolicyVersion":3}}));
            iam.project_policy.clone().unwrap_or_else(|| json!({"etag":"ACAB"}))
        }
        ("POST", "v1", "/serviceAccounts/987654321:getIamPolicy?options.requestedPolicyVersion=3") => {
            assert!(body.is_empty());
            iam.account_policy.clone().unwrap_or_else(|| json!({"etag":"ACAD"}))
        }
        ("POST", "v3", ":setIamPolicy") => {
            let policy = serde_json::from_slice::<Value>(body).unwrap()["policy"].clone();
            let member = format!("serviceAccount:{}", iam.account_email.as_deref().unwrap());
            let bindings = policy["bindings"].as_array().unwrap();
            assert_eq!(policy["etag"], "ACAB");
            let roles: &[&str] = if iam.storage_only {
                &["roles/storage.objectViewer"]
            } else {
                &["roles/compute.viewer", "roles/storage.objectViewer"]
            };
            assert_eq!(bindings.len(), roles.len());
            for role in roles {
                assert!(bindings.contains(&json!({ "role": role, "members": [&member] })));
            }
            iam.writes.push("bind project roles");
            iam.project_policy = Some(policy.clone());
            policy
        }
        ("POST", "v1", "/serviceAccounts/987654321:setIamPolicy") => {
            let policy = serde_json::from_slice::<Value>(body).unwrap()["policy"].clone();
            assert_eq!(policy["etag"], "ACAD");
            assert_eq!(policy["bindings"], json!([
                { "role":"roles/iam.serviceAccountTokenCreator", "members":[format!("user:{OPERATOR_EMAIL}")] }
            ]));
            iam.writes.push("bind account impersonation");
            iam.account_policy = Some(policy.clone());
            policy
        }
        _ => panic!("unexpected managed IAM request: {request}"),
    };
    (200, response.to_string())
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
        let generator = self.github_client(&config, crate::generator::github::test_pem()).unwrap();
        self.core.install_generator_client(GeneratorRecord { id: id.into(), name: name.into(), config: GeneratorConfig::GithubApp(config), revision: 1, position },
            Arc::new(GeneratorClient::GithubApp(generator))).unwrap();
    }
    fn github_client(&self, config: &GithubAppConfig, pem: &str) -> Result<GithubAppGenerator> {
        GithubAppGenerator::with_client_for_tests(config, pem,
            reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            self.provider.url.clone())
    }
    fn install_gcloud(&self) -> GcloudConfig {
        self.install_gcloud_for_uid("112233", GCLOUD_EMAIL)
    }
    fn install_gcloud_for_uid(&self, uid: &str, email: &str) -> GcloudConfig {
        use std::os::unix::fs::PermissionsExt;
        let path = self._tmp.path().canonicalize().unwrap().join("gcloud");
        std::fs::write(&path, format!(r#"#!/bin/sh
case "$1:$2:$3" in
  version:*) printf '%s\n' '{{"Google Cloud SDK":"582.0.0"}}' ;;
  auth:application-default:login) exit 7 ;;
  auth:application-default:print-access-token)
    [ "$4" = '--format=value(token)' ] && [ "$5" = '--quiet' ] &&
    [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ] || exit 7
    if [ "$#" -eq 5 ]; then
      printf 'isolated-parent\n'
    else
      [ "$#" -eq 9 ] && [ "$6" = '--impersonate-service-account={uid}' ] &&
      [ "$7" = '--scopes={GCLOUD_SCOPE}' ] && [ "$8" = '--lifetime=3600s' ] || exit 7
      case "$9" in --project={GCLOUD_PROJECT}|--project={GCLOUD_ALT_PROJECT}) ;; *) exit 7 ;; esac
      project=${{9#*=}}
      [ "$GOOGLE_CLOUD_QUOTA_PROJECT" = "$project" ] || exit 7
      if [ -f "$0.revoked" ]; then
        printf 'invalid_grant (do not expose this SDK diagnostic)\n' >&2
        exit 7
      fi
      printf 'isolated-child-%s-%s\n' "$project" "${{PWD##*/}}"
    fi ;;
  *) exit 7 ;;
esac
"#)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = GcloudConfig {
            sdk_path: path.to_str().unwrap().into(), account_subject: "90001".into(),
            account_email: "operator@example.test".into(), project_id: GCLOUD_PROJECT.into(),
            project_number: "123456".into(), ceiling: Self::gcloud_grant(),
            scope_catalog: vec![GcloudScopeOption { uri: GCLOUD_SCOPE.into(), description: "Storage reader".into(),
                services: vec![GcloudService { name: "storage.googleapis.com".into(), title: "Cloud Storage".into(), enabled: true }] }],
        };
        config.ceiling.service_account_unique_id = uid.into();
        config.ceiling.service_account_email = email.into();
        config.ceiling.scopes.push(GCLOUD_OTHER_SCOPE.into());
        config.scope_catalog.push(GcloudScopeOption { uri: GCLOUD_OTHER_SCOPE.into(), description: "Cross-service".into(),
            services: vec![config.scope_catalog[0].services[0].clone()] });
        config.canonicalize().unwrap();
        let generator = GcloudGenerator::with_endpoint_for_tests(&config, GCLOUD_ADC_FIXTURE,
            &self._tmp.path().join("google-work"), self.provider.url.clone()).unwrap();
        self.core.install_generator_client(GeneratorRecord { id: GCLOUD_ID.into(), name: "cloud-dev".into(),
            config: GeneratorConfig::Gcloud(config.clone()), revision: 1, position: 2 },
            Arc::new(GeneratorClient::Gcloud(generator))).unwrap();
        config
    }
    fn install_connection(&self) {
        use std::os::unix::fs::PermissionsExt;
        self.core.set_gcloud_setup_endpoint_for_test(self.provider.url.clone()).unwrap();
        let dir = self._tmp.path().canonicalize().unwrap().join("connection");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("gcloud");
        let project = lock(&self.provider.state.managed_iam).selected_project.unwrap_or(GCLOUD_PROJECT);
        std::fs::write(&path, format!(r#"#!/bin/sh
case "$1:$2:$3" in
  version:*) printf '%s\n' '{{"Google Cloud SDK":"582.0.0"}}' ;;
  auth:application-default:print-access-token)
    [ "$4" = '--format=value(token)' ] && [ "$5" = '--quiet' ] &&
    [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ] || exit 7
    if [ "$#" -eq 5 ]; then
      printf 'isolated-parent\n'
    else
      [ "$#" -eq 9 ] && [ "$6" = '--impersonate-service-account={CONNECTION_ACCOUNT_ID}' ] &&
      [ "$8" = '--lifetime=3600s' ] && [ "$9" = '--project={project}' ] &&
      [ "$GOOGLE_CLOUD_QUOTA_PROJECT" = '{project}' ] || exit 7
      case "$7" in
        --scopes={COMPUTE_SCOPE},{GCLOUD_SCOPE}) kind=broad ;;
        --scopes={GCLOUD_SCOPE}) kind=storage ;;
        *) exit 7 ;;
      esac
      printf 'isolated-child-managed-%s-%s-%s\n' "$kind" '{project}' "${{PWD##*/}}"
    fi ;;
  *) exit 7 ;;
esac
"#)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = GcloudConnectionConfig { sdk_path: path.to_str().unwrap().into(),
            account_subject: "90001".into(), account_email: OPERATOR_EMAIL.into() };
        let client = GcloudGenerator::connection_with_endpoint_for_tests(&config, GCLOUD_ADC_FIXTURE,
            &self._tmp.path().join("managed-work"), self.provider.url.clone()).unwrap();
        self.core.install_generator_client(GeneratorRecord { id: CONNECTION_ID.into(), name: "managed-cloud".into(),
            config: GeneratorConfig::GcloudConnection(config), revision: 1, position: 3 },
            Arc::new(GeneratorClient::Gcloud(client))).unwrap();
    }
    fn gcloud_grant() -> GcloudGrant {
        GcloudGrant { service_account_unique_id: "112233".into(), service_account_email: GCLOUD_EMAIL.into(),
            scopes: vec![GCLOUD_SCOPE.into()], project_id: None }
    }
    fn approve_gcloud(&self, id: &str) -> Result<()> {
        self.core.resolve_request(id, gcloud_approval(Self::gcloud_grant()))
    }
    fn github_client(&self, config: &GithubAppConfig, pem: &str) -> Result<GithubAppGenerator> {
        GithubAppGenerator::with_client_for_tests(config, pem,
            reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            self.provider.url.clone())
    }
    fn at(&self, elapsed: i64) { self.clock.store(self.start + elapsed, Ordering::SeqCst); }
    fn body(&self, name: &str) -> RequestBody {
        let generation = match name.rsplit('/').next().and_then(canonical_generated_output) {
            Some(GITHUB_TOKEN_NAME) => Some(GenerationRequest::GithubApp(GithubScopeRequest {
                repositories: Some(vec!["acme/repo1".into()]),
                permissions: Some([("contents".into(), GithubPermission::Read)].into_iter().collect()),
            })),
            Some(GCLOUD_TOKEN_NAME) => Some(GenerationRequest::Gcloud(GcloudScopeRequest { scopes: Some(vec![GCLOUD_SCOPE.into()]) })),
            _ => None,
        };
        serde_json::from_value(json!({ "kind":"get", "name":name, "reason":"Read the approved repository", "agent":"agent-a",
            "generation":generation,
            "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1,
                CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_SECRET_FIELDS_V1] })).unwrap()
    }
    fn request(&self, body: RequestBody) -> Result<RequestState> { self.core.create_request(&self.host, "127.0.0.1", body) }
    fn github_body(&self, editable: bool, repositories: &[&str], contents: GithubPermission) -> RequestBody {
        let mut body = self.body("GH_TOKEN");
        let RequestBody::Get { generation, client_capabilities, .. } = &mut body else { unreachable!() };
        *generation = Some(GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(repositories.iter().map(|name| (*name).into()).collect()),
            permissions: Some([("contents".into(), contents)].into()),
        }));
        if editable {
            client_capabilities.push(CAPABILITY_OPERATOR_SELECTED_GRANT_V1.into());
        }
        body
    }
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

fn gcloud_approval(grant: GcloudGrant) -> ffi::Decision {
    ffi::Decision::ApproveGet { mode: ffi::LeaseMode::Raw, duration_secs: Some(43_200), hosts: vec![],
        generation: Some(GenerationSelection { generator_id: GCLOUD_ID.into(), generator_revision: 1,
            grant: GenerationGrant::Gcloud(grant) }.into()) }
}

fn gcloud_conditional(f: &Fixture, lease_id_value: &str, version: u64) -> RequestBody {
    let mut body = f.body(GCLOUD_TOKEN_NAME);
    if let RequestBody::Get { lease_id, refresh, refresh_from_version, .. } = &mut body {
        *lease_id = Some(lease_id_value.into()); *refresh = true; *refresh_from_version = Some(version);
    }
    body
}

fn managed_access(permissions: &[GcloudPermission]) -> GcloudAccessRequest {
    GcloudAccessRequest { project_id: GCLOUD_PROJECT.into(), permissions: permissions.into() }
}

fn managed_body(f: &Fixture, access: GcloudAccessRequest) -> RequestBody {
    let mut body = f.body(GCLOUD_TOKEN_NAME);
    if let RequestBody::Get { generation, raw, .. } = &mut body {
        *generation = Some(GenerationRequest::GcloudAccess(access));
        *raw = true;
    }
    body
}

fn managed_approval(grant: GcloudAccessGrant) -> ffi::Decision {
    ffi::Decision::ApproveGet { mode: ffi::LeaseMode::Raw, duration_secs: Some(43_200), hosts: vec![],
        generation: Some(GenerationSelection { generator_id: CONNECTION_ID.into(), generator_revision: 1,
            grant: GenerationGrant::GcloudAccess(grant) }.into()) }
}

fn generator_activity(f: &Fixture) -> Vec<ffi::ActivityEntry> {
    f.core.list_activity(ffi::ActivityQuery { categories: vec!["generators".into()], host_id: None,
        search: String::new(), before_id: None, limit: 100 })
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
    assert!(!approved.operator_selected_grant);
    let GenerationGrant::GithubApp(actual) = approved.generation.unwrap().grant else { panic!("expected GitHub grant"); };
    assert_eq!(actual, expected);
    assert_eq!(actual.repositories[0].full_name, "acme/repo1");
    assert_eq!(lock(&f.provider.state.bodies).last(),
        Some(&json!({"repository_ids":[1],"permissions":{"metadata":"read"}})));
    assert_eq!(get(f.request(metadata_only(None)).unwrap()).lease_id, approved.lease_id);
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_github_operator_can_expand_but_only_exact_grants_are_reused() {
    let f = Fixture::new();
    let mut ceiling = Fixture::grant();
    ceiling.repositories.push(GithubRepository { id: 2, full_name: "acme/repo2".into() });
    ceiling.permissions.insert("contents".into(), GithubPermission::Write);
    f.install_with_ceilings("app-b", "review-bot", 2, vec![ceiling.clone()]);
    let editable = || f.github_body(true, &["acme/repo1"], GithubPermission::Read);
    let legacy = || f.github_body(false, &["acme/repo1"], GithubPermission::Read);

    let pending = f.request(editable()).unwrap();
    let legacy_pending = f.request(legacy()).unwrap();
    assert_ne!(pending.request_id, legacy_pending.request_id);
    assert_eq!(f.request(editable()).unwrap().request_id, pending.request_id);
    let snapshot = f.core.snapshot();
    for (id, editable, expected) in [
        (&pending.request_id, true, ceiling.clone()),
        (&legacy_pending.request_id, false, Fixture::grant()),
    ] {
        let item = snapshot.pending.iter().find(|p| &p.id == id).unwrap();
        let ffi::RequestDetail::Get { operator_selected_grant, generator_choices, .. } = &item.detail
            else { panic!("expected GitHub approval"); };
        assert_eq!(*operator_selected_grant, editable);
        let choice = generator_choices.iter().find(|c| c.choice.generator_id == "app-b").unwrap();
        assert_eq!(choice.choice.ceiling, ffi::GenerationGrant::from(GenerationGrant::GithubApp(expected)));
    }
    assert!(f.approve_github(&legacy_pending.request_id, "app-b", 1, ceiling.clone(), LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);
    f.approve_github(&pending.request_id, "app-b", 1, ceiling.clone(), LeaseMode::Raw, 43_200).unwrap();
    let approval = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert!(approval.operator_selected_grant);
    assert_eq!(approval.generation.as_ref().unwrap().grant, GenerationGrant::GithubApp(ceiling));
    let expected = json!({"repository_ids":[1, 2],"permissions":{"contents":"write","metadata":"read"}});
    assert_eq!(lock(&f.provider.state.bodies).as_slice(), std::slice::from_ref(&expected));

    assert_eq!(f.request(editable()).unwrap().status, RequestStatus::Pending);
    assert_eq!(f.request(legacy()).unwrap().request_id, legacy_pending.request_id);
    let exact = get(f.request(f.github_body(true, &["acme/repo2", "acme/repo1"], GithubPermission::Write)).unwrap());
    assert_eq!(exact.lease_id, approval.lease_id);
    assert!(!exact.operator_selected_grant);
    let mut pinned = editable();
    if let RequestBody::Get { lease_id, .. } = &mut pinned {
        *lease_id = Some(approval.lease_id.clone());
    }
    assert!(f.request(pinned.clone()).is_err(), "a pinned request cannot pretend to narrow its approved grant");
    assert_eq!(f.issued(), 1);
    if let RequestBody::Get { generation, refresh, .. } = &mut pinned {
        *generation = None;
        *refresh = true;
    }
    let renewal = get(f.request(pinned).unwrap());
    assert_eq!(renewal.generation, approval.generation);
    assert_eq!(renewal.credential_version, Some(2));
    assert!(!renewal.operator_selected_grant);
    assert_eq!(lock(&f.provider.state.bodies).last(), Some(&expected));
}

#[test]
fn generation_github_operator_can_narrow_but_not_cross_an_installation_ceiling() {
    let f = Fixture::new();
    let mut other = Fixture::grant();
    other.installation_id = 8;
    other.repositories = vec![GithubRepository { id: 3, full_name: "acme/repo3".into() }];
    f.install_with_ceilings("app-b", "review-bot", 2, vec![Fixture::grant(), other]);
    let editable = || f.github_body(true, &["acme/repo1", "acme/missing"], GithubPermission::Write);
    assert!(f.request(f.github_body(false, &["acme/repo1", "acme/missing"], GithubPermission::Write)).is_err());
    let pending = f.request(editable()).unwrap();
    let snapshot = f.core.snapshot();
    let ffi::RequestDetail::Get { generator_choices, .. } = &snapshot.pending[0].detail
        else { panic!("expected GitHub approval"); };
    assert_eq!(generator_choices.len(), 2, "the unrelated installation must not be offered");
    let offered = generator_choices.iter().find(|c| c.choice.generator_id == "app-b").unwrap();
    assert_eq!(offered.scope_issues.len(), 2, "missing repository and permission must stay visible");

    let mut outside = Fixture::grant();
    outside.repositories.push(GithubRepository { id: 3, full_name: "acme/repo3".into() });
    assert!(f.approve_github(&pending.request_id, "app-b", 1, outside, LeaseMode::Raw, 43_200).is_err());
    let mut excessive = Fixture::grant();
    excessive.permissions.insert("contents".into(), GithubPermission::Write);
    assert!(f.approve_github(&pending.request_id, "app-b", 1, excessive, LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);

    let mut narrowed = Fixture::grant();
    narrowed.permissions.remove("contents");
    f.approve_github(&pending.request_id, "app-b", 1, narrowed.clone(), LeaseMode::Raw, 43_200).unwrap();
    let approval = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert!(approval.operator_selected_grant);
    assert_eq!(approval.generation.unwrap().grant, GenerationGrant::GithubApp(narrowed));
    assert_eq!(lock(&f.provider.state.bodies).as_slice(), &[json!({"repository_ids":[1],"permissions":{"metadata":"read"}})]);
    assert_eq!(f.request(editable()).unwrap().status, RequestStatus::Pending,
        "the original request must not substitute for the narrower durable grant");
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_github_pending_name_cannot_be_rebound_to_a_new_repository_id() {
    let f = Fixture::new();
    let mut old = Fixture::grant();
    old.repositories[0].id = 2;
    f.install_with_ceilings("app-b", "review-bot", 2, vec![old.clone()]);
    let body = || {
        let mut body = f.github_body(true, &["acme/repo1"], GithubPermission::Read);
        if let RequestBody::Get { name, .. } = &mut body { *name = "review-bot/GH_TOKEN".into(); }
        body
    };
    let pending = f.request(body()).unwrap();
    let replacement = Fixture::grant();
    let draft = ffi::GeneratorDraft { id: Some("app-b".into()), name: "review-bot".into(),
        config: GeneratorConfig::GithubApp(GithubAppConfig { client_id: "client-app-b".into(),
            installations: vec![replacement.clone()] }).into(), credentials: ffi::GeneratorCredentials::Keep };
    let saved = f.core.save_generator_with_github(draft, |_, _| Ok(Some(crate::generator::github::test_pem().into())),
        |_, _, _| Ok(()), |_, _| Ok(()), |config, pem| f.github_client(config, pem)).unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Denied);
    assert!(f.approve_github(&pending.request_id, "app-b", 1, old, LeaseMode::Raw, 43_200).is_err());
    assert!(f.approve_github(&pending.request_id, "app-b", 2, replacement.clone(), LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);

    let reviewed = f.request(body()).unwrap();
    f.approve_github(&reviewed.request_id, "app-b", 2, replacement, LeaseMode::Raw, 43_200).unwrap();
    assert!(get(f.core.request_state(&f.host.id, &reviewed.request_id).unwrap()).operator_selected_grant);
    assert_eq!(lock(&f.provider.state.bodies).last(),
        Some(&json!({"repository_ids":[1],"permissions":{"contents":"read","metadata":"read"}})));
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
    let keys = Mutex::new(HashMap::<(String, String), String>::new());
    let draft = ffi::GeneratorDraft { id: None, name: "release-bot".into(),
        config: GeneratorConfig::GithubApp(GithubAppConfig { client_id: "new-client".into(), installations: vec![Fixture::grant()] }).into(),
        credentials: ffi::GeneratorCredentials::GithubPrivateKey { pem: crate::generator::github::test_pem().into() } };
    assert!(f.core.save_generator_with_github(draft,
        |id, kind| Ok(lock(&keys).get(&(id.into(), kind.into())).cloned()),
        |id, kind, pem| { lock(&keys).insert((id.into(), kind.into()), pem.into()); Ok(()) },
        |id, kind| { lock(&keys).remove(&(id.into(), kind.into())); Ok(()) },
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
        let pending = f.request(f.github_body(true, &["acme/repo1"], GithubPermission::Read)).unwrap();
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
                    installations: vec![Fixture::grant()] }).into(), credentials: ffi::GeneratorCredentials::Keep };
            f.core.save_generator_with_github(draft, |_, _| Ok(Some(crate::generator::github::test_pem().into())),
                |_, _, _| Ok(()), |_, _| Ok(()), |config, pem| f.github_client(config, pem)).unwrap();
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

#[test]
fn managed_google_denial_and_unprepared_approval_never_contact_google() {
    let f = Fixture::new();
    f.install_connection();
    let access = managed_access(&[GcloudPermission::StorageRead]);
    let requested = GcloudAccessGrant::Requested { access: access.clone() };
    let mut unsupported = managed_body(&f, access.clone());
    if let RequestBody::Get { client_capabilities, .. } = &mut unsupported {
        client_capabilities.retain(|capability| capability != CAPABILITY_GCLOUD_ACCESS_V1);
    }
    assert!(f.request(unsupported).is_err());
    assert!(f.request(f.body(GCLOUD_TOKEN_NAME)).is_err(), "connection rejects legacy selectors");
    let mut unscoped = f.body(GCLOUD_TOKEN_NAME);
    if let RequestBody::Get { generation, .. } = &mut unscoped { *generation = None; }
    assert!(f.request(unscoped).is_err());
    let mut wrong_provider = managed_body(&f, access.clone());
    if let RequestBody::Get { name, .. } = &mut wrong_provider { *name = GITHUB_TOKEN_NAME.into(); }
    assert!(f.request(wrong_provider).is_err());

    let pending = f.request(managed_body(&f, access)).unwrap();
    assert_eq!(pending.status, RequestStatus::Pending);
    let snapshot = f.core.snapshot();
    let ffi::RequestDetail::Get { generator_choices, .. } = &snapshot.pending[0].detail else {
        panic!("expected Google Cloud approval");
    };
    assert_eq!(generator_choices.len(), 1);
    assert!(generator_choices[0].gcloud_ready.is_none());
    assert_eq!(generator_choices[0].choice.ceiling,
        ffi::GenerationGrant::GcloudAccess { grant: requested.clone().into() });
    assert!(f.core.resolve_request(&pending.request_id, managed_approval(requested)).is_err());
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);
    f.core.resolve_request(&pending.request_id, ffi::Decision::Deny { reason: "Not needed".into() }).unwrap();
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Denied);
    assert_eq!(f.provider.state.google_calls.load(Ordering::SeqCst), 0);
    assert!(lock(&f.provider.state.managed_iam).writes.is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn managed_google_one_approval_provisions_and_releases_exact_access_then_renews() {
    let f = Fixture::new();
    f.install_gcloud(); // Same output must not offer the bound legacy account.
    f.install_connection();
    let broad = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    let narrow = managed_access(&[GcloudPermission::StorageRead]);
    let body = |access: &GcloudAccessRequest| managed_body(&f, access.clone());
    let selector = |access: &GcloudAccessRequest| GcloudAccessGrant::Requested { access: access.clone() };
    let noncanonical = managed_access(&[GcloudPermission::ComputeRead, GcloudPermission::StorageRead, GcloudPermission::StorageRead]);
    let pending = f.request(body(&noncanonical)).unwrap();
    let snapshot = f.core.snapshot();
    let ffi::RequestDetail::Get { generator_choices, .. } = &snapshot.pending[0].detail else {
        panic!("expected managed approval");
    };
    assert_eq!(generator_choices.len(), 1);
    assert_eq!(generator_choices[0].choice.generator_id, CONNECTION_ID);
    let mut legacy_qualified = body(&broad);
    if let RequestBody::Get { name, .. } = &mut legacy_qualified {
        *name = format!("cloud-dev/{GCLOUD_TOKEN_NAME}");
    }
    assert!(f.request(legacy_qualified).is_err());
    assert!(f.core.resolve_request(&pending.request_id, managed_approval(selector(&narrow))).is_err());
    assert_eq!(f.provider.state.google_calls.load(Ordering::SeqCst), 0);

    let decision = managed_approval(selector(&broad));
    let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    let plan_email = plan.service_account_email.clone();
    assert!(lock(&f.provider.state.managed_iam).writes.is_empty(), "preparation is a read-only review");
    assert_eq!(f.issued(), 0, "preparation must not mint a lease token");
    assert!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().result.is_none());
    assert!(f.core.resolve_request(&pending.request_id, decision.clone()).is_err(),
        "a Ready profile is required for ordinary approval; preview alone is not authority");
    assert_eq!(f.issued(), 0);
    let plan_id = plan.plan_id.expect("first use must review its IAM plan");
    f.core.gcloud_approve_profile(&pending.request_id, &plan_id, decision.clone()).unwrap();
    let cloud_writes = ["create account", "bind project roles", "bind account impersonation"];
    assert_eq!(lock(&f.provider.state.managed_iam).writes, cloud_writes);
    assert!(f.core.gcloud_approve_profile(&pending.request_id, &plan_id, decision).is_err());

    let expected = GcloudAccessGrant::Issued {
        access: broad.clone(), service_account_unique_id: CONNECTION_ACCOUNT_ID.into(),
        service_account_email: plan_email,
    };
    let lease = f.core.store.list_leases().unwrap().pop().unwrap();
    assert_eq!(lease.host_id, f.host.id);
    assert_eq!(lease.mode, LeaseMode::Raw);
    assert!(lease.hosts.is_empty());
    assert_eq!(lease.expires_at, Some(f.start + 43_200));
    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert_eq!(first.generation.as_ref().unwrap().grant, GenerationGrant::GcloudAccess(expected));
    assert!(first.files[0].content.starts_with("isolated-child-managed-"));
    assert_eq!(f.issued(), 1);

    let cached = get(f.request(body(&broad)).unwrap());
    assert_eq!(cached.lease_id, first.lease_id);
    assert_eq!(cached.files, first.files);
    assert_eq!(f.issued(), 1);
    let narrowed = f.request(body(&narrow)).unwrap();
    assert_eq!(narrowed.status, RequestStatus::Pending);
    assert!(narrowed.result.is_none(), "narrowing must never return the broader credential");
    assert!(f.core.resolve_request(&narrowed.request_id, managed_approval(selector(&narrow))).is_err());
    let mut pin = body(&broad);
    if let RequestBody::Get { lease_id, refresh, refresh_from_version, .. } = &mut pin {
        *lease_id = Some(first.lease_id.clone()); *refresh = true; *refresh_from_version = Some(1);
    }
    for wrong in [None, Some(GenerationRequest::GcloudAccess(narrow)), Some(GenerationRequest::Gcloud(GcloudScopeRequest {
        scopes: Some(vec![GCLOUD_SCOPE.into()]),
    }))] {
        let mut request = pin.clone();
        if let RequestBody::Get { generation, .. } = &mut request { *generation = wrong; }
        assert!(f.request(request).is_err());
    }
    assert_eq!(f.issued(), 1);

    let renewed = get(f.request(pin.clone()).unwrap());
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.credential_version, Some(2));
    assert_ne!(renewed.files, first.files);
    assert_eq!(f.issued(), 2);
    lock(&f.provider.state.managed_iam).account_policy = None;
    if let RequestBody::Get { refresh_from_version, .. } = &mut pin { *refresh_from_version = Some(2); }
    assert!(f.request(pin).is_err(), "renewal requires the verified direct account-level binding");
    assert!(f.core.check_generated_delivery(&first.lease_id, 2).is_err(),
        "an observed verification failure stops cached delivery");
    assert_eq!(f.issued(), 2);
    assert_eq!(lock(&f.provider.state.managed_iam).writes, cloud_writes, "approval and renewal must not repair IAM");
}

fn ledger_target(row: &ffi::GcloudOwnedAccount) -> ffi::GcloudOwnedAccountDelete {
    ffi::GcloudOwnedAccountDelete {
        profile_id: row.id,
        generator_id: row.generator_id.clone(),
        generator_revision: row.generator_revision.unwrap(),
        project_id: row.project_id.clone(),
        account_name: row.account_name.clone(),
        account_email: row.account_email.clone(),
        account_unique_id: row.account_unique_id.clone().unwrap(),
        expected_lease_ids: row.leases.iter().map(|lease| lease.id.clone()).collect(),
        confirmed: true,
    }
}

#[test]
fn retired_google_account_stops_raw_delivery_and_requires_exact_retry_after_unknown_outcome() {
    let f = Fixture::new();
    f.install_connection();
    let access = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    let decision = managed_approval(GcloudAccessGrant::Requested { access: access.clone() });
    let body = managed_body(&f, access.clone());
    let pending = f.request(body.clone()).unwrap();
    let review = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    let config = f.install_gcloud_for_uid(CONNECTION_ACCOUNT_ID, &review.service_account_email);
    let legacy_grant = GcloudGrant { scopes: vec![GCLOUD_SCOPE.into()], ..config.ceiling };
    f.core.gcloud_approve_profile(&pending.request_id, &review.plan_id.unwrap(), decision.clone()).unwrap();
    let mut legacy = f.body(GCLOUD_TOKEN_NAME);
    if let RequestBody::Get { raw, .. } = &mut legacy { *raw = true; }
    let legacy_pending = f.request(legacy.clone()).unwrap();
    f.core.resolve_request(&legacy_pending.request_id, gcloud_approval(legacy_grant.clone())).unwrap();
    let legacy_lease = get(f.core.request_state(&f.host.id, &legacy_pending.request_id).unwrap());
    f.core.revoke_lease(&legacy_lease.lease_id).unwrap();

    let mut pin = body.clone();
    let account = f.core.list_gcloud_owned_accounts().unwrap().pop().unwrap();
    assert_eq!(account.account_unique_id.as_deref(), Some(CONNECTION_ACCOUNT_ID));
    assert_eq!(account.leases.len(), 2, "ended legacy leases with the same immutable ID are dependencies");
    let managed_lease = account.leases.iter().find(|lease| lease.id != legacy_lease.lease_id).unwrap();
    if let RequestBody::Get { lease_id, refresh, .. } = &mut pin {
        *lease_id = Some(managed_lease.id.clone());
        *refresh = true;
    }
    let mut new = body;
    if let RequestBody::Get { new_lease, .. } = &mut new { *new_lease = true; }
    let next = f.request(new).unwrap();
    let review = f.core.gcloud_profile_plan(next.request_id.clone(), decision.clone()).unwrap();

    let mut stale = ledger_target(&account);
    stale.expected_lease_ids.clear();
    assert!(f.core.delete_gcloud_owned_account(stale).is_err());
    assert!(!lock(&f.provider.state.managed_iam).deleted);
    lock(&f.provider.state.managed_iam).fail_delete = true;
    let (release, running) = f.provider.block_next();
    let core = f.core.clone();
    let target = ledger_target(&account);
    let deletion = std::thread::spawn(move || core.delete_gcloud_owned_account(target));
    let entered = running.recv_timeout(Duration::from_secs(5));
    // These calls must complete while Google holds the DELETE response.
    let delivered = f.core.request_state(&f.host.id, &pending.request_id);
    let removed_generator = f.core.remove_generator(CONNECTION_ID);
    release.release();
    assert!(entered.is_ok());
    assert!(delivered.is_err());
    assert!(removed_generator.is_err());
    assert!(deletion.join().unwrap().is_err());
    assert!(lock(&f.provider.state.managed_iam).deleted);
    assert!(f.core.request_state(&f.host.id, &pending.request_id).is_err());
    assert!(f.request(pin).is_err());
    assert!(f.core.list_leases().is_empty());
    assert!(f.core.gcloud_approve_profile(&next.request_id, &review.plan_id.unwrap(), decision.clone()).is_err());
    assert!(f.core.gcloud_profile_plan(next.request_id.clone(), decision).is_err());
    assert_eq!(f.core.request_state(&f.host.id, &next.request_id).unwrap().status, RequestStatus::Pending);
    let pending_delete = f.core.list_gcloud_owned_accounts().unwrap().pop().unwrap();
    assert!(matches!(pending_delete.state, ffi::GcloudOwnedAccountState::DeletionPending));
    assert!(pending_delete.leases.is_empty());
    assert!(f.core.delete_gcloud_owned_account(ledger_target(&account)).is_err());
    f.core.delete_gcloud_owned_account(ledger_target(&pending_delete)).unwrap();
    let deleted = f.core.list_gcloud_owned_accounts().unwrap().pop().unwrap();
    assert!(matches!(deleted.state, ffi::GcloudOwnedAccountState::Deleted));
    assert!(!deleted.deletable);
    assert_eq!(lock(&f.provider.state.managed_iam).writes.iter().filter(|&&write| write == "delete pinned account").count(), 1);
    if let RequestBody::Get { new_lease, .. } = &mut legacy { *new_lease = true; }
    let old_uid = f.request(legacy).unwrap();
    assert!(f.core.resolve_request(&old_uid.request_id, gcloud_approval(legacy_grant)).is_err());
    assert_eq!(f.issued(), 2, "retirement must not mint or deliver another token");
}

#[test]
fn google_account_delete_waits_for_sentinel_cutover_even_on_retry() {
    let f = Fixture::with_proxy(true);
    f.install_connection();
    let access = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    let mut body = managed_body(&f, access.clone());
    if let RequestBody::Get { raw, .. } = &mut body { *raw = false; }
    let pending = f.request(body).unwrap();
    let mut decision = managed_approval(GcloudAccessGrant::Requested { access });
    if let ffi::Decision::ApproveGet { mode, hosts, .. } = &mut decision {
        *mode = ffi::LeaseMode::Sentinel;
        *hosts = vec!["storage.googleapis.com".into()];
    }
    let review = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    f.core.gcloud_approve_profile(&pending.request_id, &review.plan_id.unwrap(), decision).unwrap();
    let sentinel = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert!(f.core.proxy.status().running);
    let config = f.core.dirs.proxy.join("iron-proxy.yaml");
    let saved = config.with_extension("saved");
    std::fs::rename(&config, &saved).unwrap();
    std::fs::create_dir(&config).unwrap();

    let account = f.core.list_gcloud_owned_accounts().unwrap().pop().unwrap();
    assert!(f.core.delete_gcloud_owned_account(ledger_target(&account)).is_err());
    assert!(!f.core.proxy.status().running, "cannot leave the old forwarding process alive");
    assert!(f.core.request_state(&f.host.id, &pending.request_id).is_err());
    let pending_delete = f.core.list_gcloud_owned_accounts().unwrap().pop().unwrap();
    assert!(f.core.delete_gcloud_owned_account(ledger_target(&pending_delete)).is_err());
    assert!(!lock(&f.provider.state.managed_iam).deleted);

    std::fs::remove_dir(&config).unwrap();
    std::fs::rename(&saved, &config).unwrap();
    f.core.delete_gcloud_owned_account(ledger_target(&pending_delete)).unwrap();
    assert!(!f.core.dirs.values.join(format!("{}.0", sentinel.lease_id)).exists());
    assert!(lock(&f.provider.state.managed_iam).deleted);
}

#[test]
fn managed_google_edited_approval_provisions_and_reuses_only_the_final_exact_profile() {
    use asm_proto::wire::CAPABILITY_OPERATOR_SELECTED_GRANT_V1;

    let narrow = managed_access(&[GcloudPermission::StorageRead]);
    let broad = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    for (original, approved, roles, scopes) in [
        (&broad, &narrow, vec!["roles/storage.objectViewer"], vec![GCLOUD_SCOPE]),
        (&narrow, &broad, vec!["roles/storage.objectViewer", "roles/compute.viewer"], vec![COMPUTE_SCOPE, GCLOUD_SCOPE]),
    ] {
        let f = Fixture::new();
        f.install_connection();
        lock(&f.provider.state.managed_iam).storage_only = approved == &narrow;
        let decision = managed_approval(GcloudAccessGrant::Requested { access: approved.clone() });
        let mut opted_in = managed_body(&f, original.clone());
        let RequestBody::Get { client_capabilities, .. } = &mut opted_in else { unreachable!() };
        client_capabilities.retain(|capability| capability != CAPABILITY_OPERATOR_SELECTED_GRANT_V1);
        let legacy = f.request(opted_in.clone()).unwrap();
        assert!(f.core.gcloud_profile_plan(legacy.request_id.clone(), decision.clone()).is_err());
        assert!(f.core.resolve_request(&legacy.request_id, decision.clone()).is_err());
        assert_eq!(f.provider.state.google_calls.load(Ordering::SeqCst), 0);

        let RequestBody::Get { client_capabilities, .. } = &mut opted_in else { unreachable!() };
        client_capabilities.push(CAPABILITY_OPERATOR_SELECTED_GRANT_V1.into());
        let pending = f.request(opted_in.clone()).unwrap();
        assert_ne!(pending.request_id, legacy.request_id, "capability boundaries must not coalesce");
        let wrong_project = managed_approval(GcloudAccessGrant::Requested {
            access: GcloudAccessRequest { project_id: "different-project".into(), ..approved.clone() }
        });
        assert!(f.core.gcloud_profile_plan(pending.request_id.clone(), wrong_project).is_err());

        let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
        assert!(!plan.ready);
        assert_eq!(plan.project_roles, roles);
        assert_eq!(plan.scopes, scopes);
        assert!(lock(&f.provider.state.managed_iam).writes.is_empty());
        let plan_id = plan.plan_id.unwrap();
        f.core.gcloud_approve_profile(&pending.request_id, &plan_id, decision.clone()).unwrap();
        let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
        assert!(first.operator_selected_grant);
        let grant = GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
            access: approved.clone(), service_account_unique_id: CONNECTION_ACCOUNT_ID.into(),
            service_account_email: plan.service_account_email,
        });
        assert_eq!(first.generation.as_ref().unwrap().grant, grant);
        let lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
        assert_eq!(lease.requested_generation, Some(GenerationRequest::GcloudAccess(original.clone())));
        assert_eq!(lease.generation, Some(grant));
        assert_eq!(f.issued(), 1);

        let same_original = f.request(opted_in.clone()).unwrap();
        assert_eq!(same_original.status, RequestStatus::Pending);
        assert!(same_original.result.is_none());
        let mut exact = managed_body(&f, approved.clone());
        let cached = get(f.request(exact.clone()).unwrap());
        assert_eq!(cached.lease_id, first.lease_id);
        assert_eq!(cached.files, first.files);
        assert!(!cached.operator_selected_grant);

        for body in [&mut opted_in, &mut exact] {
            let RequestBody::Get { lease_id, refresh, refresh_from_version, .. } = body else { unreachable!() };
            *lease_id = Some(first.lease_id.clone());
            *refresh = true;
            *refresh_from_version = Some(1);
        }
        assert!(f.request(opted_in).is_err(), "the pre-edit request cannot renew this lease");
        assert_eq!(f.issued(), 1);
        let renewed = get(f.request(exact).unwrap());
        assert_eq!(renewed.generation, first.generation);
        assert_eq!(renewed.credential_version, Some(2));
        assert!(!renewed.operator_selected_grant);

        assert!(f.core.resolve_request(&same_original.request_id, decision.clone()).is_err(),
            "an edited selection must be reviewed even when its exact profile is ready");
        let stale = f.core.gcloud_profile_plan(same_original.request_id.clone(), decision.clone()).unwrap();
        let ready = f.core.gcloud_profile_plan(same_original.request_id.clone(), decision.clone()).unwrap();
        assert!(ready.ready && ready.expires_at.is_some());
        assert_eq!(ready.service_account_unique_id.as_deref(), Some(CONNECTION_ACCOUNT_ID));
        assert!(f.core.gcloud_approve_profile(&same_original.request_id, &stale.plan_id.unwrap(), decision.clone()).is_err());
        f.core.gcloud_approve_profile(&same_original.request_id, &ready.plan_id.unwrap(), decision).unwrap();
        let first_with_ready_profile = get(f.core.request_state(&f.host.id, &same_original.request_id).unwrap());
        assert_eq!(first_with_ready_profile.generation, first.generation);
        assert_ne!(first_with_ready_profile.lease_id, first.lease_id);
        assert!(first_with_ready_profile.operator_selected_grant);
        assert_eq!(f.issued(), 3);
        assert_eq!(lock(&f.provider.state.managed_iam).writes,
            ["create account", "bind project roles", "bind account impersonation"]);
    }
}

#[test]
fn managed_google_switch_mints_for_the_reviewed_project_and_only_reuses_exact_issued_claims() {
    let f = Fixture::new();
    {
        let mut iam = lock(&f.provider.state.managed_iam);
        iam.selected_project = Some(GCLOUD_ALT_PROJECT);
        iam.storage_only = true;
    }
    f.install_connection();
    let original = managed_access(&[GcloudPermission::StorageRead]);
    let selected = GcloudAccessRequest { project_id: GCLOUD_ALT_PROJECT.into(), ..original.clone() };
    let mut opted_in = managed_body(&f, original.clone());
    let RequestBody::Get { client_capabilities, .. } = &mut opted_in else { unreachable!() };
    client_capabilities.push(CAPABILITY_OPERATOR_SELECTED_PROJECT_V1.into());
    let pending = f.request(opted_in.clone()).unwrap();
    let snapshot = f.core.snapshot();
    let ffi::RequestDetail::Get { requested_generation, operator_selected_gcloud_project, operator_selected_grant, .. }
        = &snapshot.pending[0].detail else { panic!("expected managed Google approval"); };
    assert_eq!(*requested_generation, Some(GenerationRequest::GcloudAccess(original.clone()).into()));
    assert!(*operator_selected_gcloud_project && !*operator_selected_grant);
    let decision = managed_approval(GcloudAccessGrant::Requested { access: selected.clone() });
    assert_eq!(f.core.gcloud_approval_projects(&pending.request_id, CONNECTION_ID, 1).unwrap(), [GCLOUD_ALT_PROJECT]);
    let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    assert_eq!(plan.project_id, GCLOUD_ALT_PROJECT);
    assert_eq!(plan.project_roles, ["roles/storage.objectViewer"]);
    assert!(lock(&f.provider.state.managed_iam).writes.is_empty());
    f.core.gcloud_approve_profile(&pending.request_id, &plan.plan_id.unwrap(), decision.clone()).unwrap();

    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let issued = GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
        access: selected.clone(), service_account_unique_id: CONNECTION_ACCOUNT_ID.into(),
        service_account_email: plan.service_account_email,
    });
    assert_eq!(first.generation.as_ref().unwrap().grant, issued);
    assert!(first.operator_selected_grant, "a project-only switch must mark fresh operator-selected delivery");
    assert!(first.files[0].content.starts_with("isolated-child-managed-storage-quota-project-"));
    let lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
    assert_eq!(lease.requested_generation, Some(GenerationRequest::GcloudAccess(original)));
    assert_eq!(lease.generation, Some(issued));

    let fresh_original = f.request(opted_in.clone()).unwrap();
    assert_eq!(fresh_original.status, RequestStatus::Pending);
    assert!(f.core.resolve_request(&fresh_original.request_id, decision).is_err(),
        "a different project's Ready profile cannot bypass a new IAM review");
    let mut exact = managed_body(&f, selected);
    f.at(600); // Project evidence has expired; this lease still has exact issued authority.
    let cached = get(f.request(exact.clone()).unwrap());
    assert_eq!(cached.lease_id, first.lease_id);
    assert_eq!(cached.files, first.files);
    assert!(!cached.operator_selected_grant);
    for body in [&mut opted_in, &mut exact] {
        let RequestBody::Get { lease_id, refresh, refresh_from_version, .. } = body else { unreachable!() };
        *lease_id = Some(first.lease_id.clone());
        *refresh = true;
        *refresh_from_version = Some(1);
    }
    assert!(f.request(opted_in).is_err(), "the original project cannot renew the approved alternate");
    assert_eq!(f.issued(), 1);
    let renewed = get(f.request(exact).unwrap());
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.credential_version, Some(2));
    assert!(!renewed.operator_selected_grant);
    assert!(renewed.files[0].content.starts_with("isolated-child-managed-storage-quota-project-"));
    assert_eq!(f.issued(), 2);
    let iam = lock(&f.provider.state.managed_iam);
    assert_eq!(iam.project_searches, 1, "reuse and renewal must not discover new project authority");
    assert_eq!(iam.writes, ["create account", "bind project roles", "bind account impersonation"]);
}

#[test]
fn managed_google_failed_issuance_reports_ready_iam_and_only_retries_on_explicit_approval() {
    let f = Fixture::new();
    f.install_connection();
    let access = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    let pending = f.request(managed_body(&f, access.clone())).unwrap();
    let decision = managed_approval(GcloudAccessGrant::Requested { access: access.clone() });
    let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    let plan_id = plan.plan_id.unwrap();
    f.provider.state.ttl.store(1, Ordering::SeqCst);
    let error = f.core.gcloud_approve_profile(&pending.request_id, &plan_id, decision.clone()).unwrap_err();
    assert!(error.message.contains("no lease was approved"));
    assert!(error.message.contains("Google IAM changes remain"));
    assert_eq!(f.issued(), 1);
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);

    let cloud_writes = ["create account", "bind project roles", "bind account impersonation"];
    assert_eq!(lock(&f.provider.state.managed_iam).writes, cloud_writes);
    f.provider.state.ttl.store(3600, Ordering::SeqCst);
    assert!(f.core.gcloud_approve_profile(&pending.request_id, &plan_id, decision.clone()).is_err());
    let ready = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    assert!(ready.ready);
    assert!(ready.plan_id.is_some() && ready.expires_at.is_some());
    assert_eq!(ready.service_account_email, plan.service_account_email);
    assert_eq!(f.issued(), 1, "reviewing a Ready profile must not mint");
    let issued = GcloudAccessGrant::Issued {
        access, service_account_unique_id: CONNECTION_ACCOUNT_ID.into(),
        service_account_email: ready.service_account_email,
    };
    assert!(f.core.resolve_request(&pending.request_id, managed_approval(issued.clone())).is_err(),
        "even the correct issued grant is not an operator selector");
    f.core.resolve_request(&pending.request_id, decision).unwrap();
    let result = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    assert_eq!(result.generation.unwrap().grant, GenerationGrant::GcloudAccess(issued));
    assert_eq!(lock(&f.provider.state.managed_iam).writes, cloud_writes);
    assert_eq!(f.issued(), 2);
}

#[test]
fn managed_google_denial_during_mint_never_delivers_the_child() {
    let f = Fixture::new();
    f.install_connection();
    let access = managed_access(&[GcloudPermission::StorageRead, GcloudPermission::ComputeRead]);
    let pending = f.request(managed_body(&f, access.clone())).unwrap();
    let decision = managed_approval(GcloudAccessGrant::Requested { access });
    let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    let plan_id = plan.plan_id.unwrap();
    let (gate, entered) = f.provider.block_next();
    let core = f.core.clone();
    let id = pending.request_id.clone();
    let worker = std::thread::spawn(move || core.gcloud_approve_profile(&id, &plan_id, decision));
    let started = entered.recv_timeout(Duration::from_secs(10));
    if started.is_err() {
        gate.release();
        panic!("first-use approval did not reach the isolated child issuer: {:?}", worker.join().unwrap());
    }
    let denial = f.core.resolve_request(&pending.request_id, ffi::Decision::Deny { reason: "Stop".into() });
    gate.release();
    denial.unwrap();
    assert!(worker.join().unwrap().is_err());
    let state = f.core.request_state(&f.host.id, &pending.request_id).unwrap();
    assert_eq!(state.status, RequestStatus::Denied);
    assert!(state.result.is_none());
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert!(generator_activity(&f).iter().any(|event| event.kind == "revocation_unsupported"));
}

#[test]
fn managed_google_switch_evidence_expiring_during_mint_prevents_delivery() {
    let f = Fixture::new();
    {
        let mut iam = lock(&f.provider.state.managed_iam);
        iam.selected_project = Some(GCLOUD_ALT_PROJECT);
        iam.storage_only = true;
    }
    f.install_connection();
    let original = managed_access(&[GcloudPermission::StorageRead]);
    let mut body = managed_body(&f, original.clone());
    let RequestBody::Get { client_capabilities, .. } = &mut body else { unreachable!() };
    client_capabilities.push(CAPABILITY_OPERATOR_SELECTED_PROJECT_V1.into());
    let pending = f.request(body).unwrap();
    f.core.gcloud_approval_projects(&pending.request_id, CONNECTION_ID, 1).unwrap();
    let decision = managed_approval(GcloudAccessGrant::Requested {
        access: GcloudAccessRequest { project_id: GCLOUD_ALT_PROJECT.into(), ..original },
    });
    let plan = f.core.gcloud_profile_plan(pending.request_id.clone(), decision.clone()).unwrap();
    let plan_id = plan.plan_id.unwrap();
    let (gate, entered) = f.provider.block_next();
    let core = f.core.clone();
    let id = pending.request_id.clone();
    let worker = std::thread::spawn(move || core.gcloud_approve_profile(&id, &plan_id, decision));
    if entered.recv_timeout(Duration::from_secs(10)).is_err() {
        gate.release();
        panic!("switched approval did not reach the isolated child issuer: {:?}", worker.join().unwrap());
    }
    f.clock.store(plan.expires_at.unwrap(), Ordering::SeqCst);
    gate.release();
    assert!(worker.join().unwrap().unwrap_err().message.contains("no lease was approved"));
    let state = f.core.request_state(&f.host.id, &pending.request_id).unwrap();
    assert_eq!(state.status, RequestStatus::Pending);
    assert!(state.result.is_none());
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert!(generator_activity(&f).iter().any(|event| event.kind == "revocation_unsupported"));
}

#[test]
fn generation_google_renews_only_approved_scopes_and_evicts_at_provider_expiry() {
    let f = Fixture::new();
    f.install_gcloud();
    f.provider.state.ttl.store(120, Ordering::SeqCst);
    let mut body = f.body(GCLOUD_TOKEN_NAME);
    if let RequestBody::Get { generation, .. } = &mut body {
        *generation = Some(GenerationRequest::Gcloud(GcloudScopeRequest { scopes: Some(vec![GCLOUD_OTHER_SCOPE.into()]) }));
    }
    let pending = f.request(body.clone()).unwrap();
    // The operator can grant a different nonempty subset; scope requests are preferences.
    let mut grant = Fixture::gcloud_grant();
    grant.service_account_email = "submitted@fixture-project.iam.gserviceaccount.com".into();
    f.core.resolve_request(&pending.request_id, gcloud_approval(grant)).unwrap();
    let approved = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let GenerationGrant::Gcloud(approved_grant) = &approved.generation.as_ref().unwrap().grant else {
        panic!("expected a Google grant");
    };
    assert_eq!(approved_grant.service_account_email, GCLOUD_EMAIL);
    assert_eq!(approved_grant.scopes, [GCLOUD_SCOPE]);
    assert_eq!(approved_grant.project_id.as_deref(), Some(GCLOUD_PROJECT));
    assert!(approved.files[0].content.starts_with("isolated-child-"));
    assert!(approved.credential_expires_at.as_ref().unwrap() < approved.expires_at.as_ref().unwrap());

    assert_eq!(f.request(body.clone()).unwrap().status, RequestStatus::Pending,
        "repeating the unfulfilled request requires a fresh decision");
    if let RequestBody::Get { lease_id, .. } = &mut body { *lease_id = Some(approved.lease_id.clone()); }
    assert_eq!(f.request(body).unwrap_err().code, asm_proto::ErrorCode::Invalid,
        "pinning cannot reinterpret an explicit request as the approved scope");

    for version in [1, 2] {
        let refreshed = get(f.request(gcloud_conditional(&f, &approved.lease_id, version)).unwrap());
        assert_ne!(refreshed.files, approved.files);
        assert_eq!(refreshed.generation, approved.generation);
        assert_eq!(refreshed.expires_at, approved.expires_at);
        assert_eq!(refreshed.credential_version, Some(version + 1));
    }
    assert_eq!(f.request(gcloud_conditional(&f, &approved.lease_id, 3)).unwrap_err().code,
        asm_proto::ErrorCode::RateLimited);
    assert_eq!(f.issued(), 3);

    f.at(180);
    f.core.sweep_generated_at(f.start + 180);
    assert!(f.core.check_generated_delivery(&approved.lease_id, 3).is_err());
    let activity = generator_activity(&f);
    let unsupported: Vec<_> = activity.iter().filter(|row| row.kind == "revocation_unsupported").collect();
    assert!(unsupported.len() >= 3, "replacement and expiry record the non-revocable token outcome");
    assert!(unsupported.iter().all(|row| row.detail.as_ref().unwrap().contains("credential_expires_at")));
    assert!(!activity.iter().any(|row| row.kind == "revocation_failed" || row.detail.as_deref()
        .is_some_and(|detail| detail.contains("isolated-child-") || detail.contains("isolated-refresh-token"))));
    assert!(lock(&f.provider.state.revoked).is_empty());
}

#[test]
fn generation_google_legacy_approval_cannot_change_project() {
    let f = Fixture::new();
    f.install_gcloud();
    let pending = f.request(f.body(GCLOUD_TOKEN_NAME)).unwrap();
    let ffi::RequestDetail::Get { generator_choices, .. } = &f.core.snapshot().pending[0].detail else {
        panic!("expected a Google approval request");
    };
    assert_eq!(generator_choices[0].default_project_id.as_deref(), Some(GCLOUD_PROJECT));
    let mut grant = Fixture::gcloud_grant();
    grant.project_id = Some(GCLOUD_ALT_PROJECT.into());
    let error = f.core.resolve_request(&pending.request_id, gcloud_approval(grant.clone())).unwrap_err();
    assert_eq!(error.code, asm_proto::ErrorCode::Invalid);
    assert_eq!(f.issued(), 0);
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);
}

#[test]
fn generation_google_pins_historical_legacy_project_without_rewriting_its_grant() {
    let f = Fixture::new();
    f.install_gcloud();
    let legacy = LeaseRecord {
        id: new_uuid_v4(), host_id: f.host.id.clone(), vault_id: GCLOUD_ID.into(), vault_name: "cloud-dev".into(),
        secret_key: "token".into(), name: GCLOUD_TOKEN_NAME.into(), mode: LeaseMode::Raw,
        fields: vec![LeaseField { field: "value".into(), sentinel: None, path: GCLOUD_TOKEN_NAME.into() }],
        hosts: vec![], reason: "Read Storage objects".into(), agent: "agent-a".into(), created_at: f.start - 3_600,
        expires_at: Some(f.start + 1_800), revoked_at: None, source_kind: SourceKind::Generator,
        generation: Some(GenerationGrant::Gcloud(GcloudGrant {
            project_id: Some(GCLOUD_ALT_PROJECT.into()), ..Fixture::gcloud_grant()
        })),
        generator_revision: Some(1), credential_expires_at: Some(f.start - 1),
        approval_order: Some(f.core.store.reserve_generator_approval_order().unwrap()),
        credential_version: 1, requested_generation: None,
    };
    f.core.store.insert_lease(&legacy).unwrap();
    let mut pinned = gcloud_conditional(&f, &legacy.id, 1);
    if let RequestBody::Get { generation, .. } = &mut pinned { *generation = None; }
    let renewed = get(f.request(pinned).unwrap());
    assert_eq!(renewed.generation.unwrap().grant, legacy.generation.unwrap());
    assert_eq!(renewed.credential_version, Some(2));
    assert!(renewed.files[0].content.starts_with("isolated-child-quota-project-"));
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_google_approval_is_invalidated_by_concurrent_generator_revision() {
    let f = Fixture::new();
    let config = f.install_gcloud();
    let pending = f.request(f.body(GCLOUD_TOKEN_NAME)).unwrap();
    let (gate, entered) = f.provider.block_next();
    let grant = Fixture::gcloud_grant();
    let core = f.core.clone();
    let id = pending.request_id.clone();
    let worker = std::thread::spawn(move || core.resolve_request(&id, gcloud_approval(grant)));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    // A verified reconnect replaces the credential while the old client is minting.
    f.core.set_gcloud_setup_endpoint_for_test(f.provider.url.clone()).unwrap();
    let adc = GCLOUD_ADC_FIXTURE.replace("isolated-refresh-token", "reconnected-refresh-token");
    let session_id = f.core.install_gcloud_setup_for_test(config.sdk_path.clone().into(), &adc,
        crate::generator::gcloud::GcloudIdentity { subject: config.account_subject.clone(), email: config.account_email.clone() },
    ).unwrap();
    let save = f.core.save_generator_with(ffi::GeneratorDraft { id: Some(GCLOUD_ID.into()),
        name: "cloud-dev".into(), config: GeneratorConfig::Gcloud(config).into(),
        credentials: ffi::GeneratorCredentials::GcloudSession { session_id } },
        |_, _| Ok(Some(GCLOUD_ADC_FIXTURE.into())),
        |_, _, _| Ok(()),
        |_, _| panic!("a reconnect must not delete existing credentials"));
    gate.release();
    assert_eq!(save.unwrap().revision, 2);
    assert!(worker.join().unwrap().is_err());
    let state = f.core.request_state(&f.host.id, &pending.request_id).unwrap();
    assert_eq!(state.status, RequestStatus::Pending);
    assert!(state.result.is_none());
    let ffi::RequestDetail::Get { generator_choices, .. } = &f.core.snapshot().pending[0].detail else {
        panic!("expected the updated Google approval request");
    };
    assert_eq!(generator_choices[0].choice.revision, 2);
    assert_eq!(generator_choices[0].default_project_id.as_deref(), Some(GCLOUD_PROJECT));
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_google_late_approval_after_removal_is_never_delivered() {
    let f = Fixture::new();
    f.install_gcloud();
    let pending = f.request(f.body("cloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN")).unwrap();
    let (gate, entered) = f.provider.block_next();
    let core = f.core.clone();
    let id = pending.request_id.clone();
    let worker = std::thread::spawn(move || core.resolve_request(&id, gcloud_approval(Fixture::gcloud_grant())));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let removal = f.core.remove_generator_with(GCLOUD_ID, |id, kind| {
        assert_eq!((id, kind), (GCLOUD_ID, creds::GCLOUD_ADC));
        Ok(())
    });
    gate.release();
    removal.unwrap();
    assert!(worker.join().unwrap().is_err());
    let ended = f.core.request_state(&f.host.id, &pending.request_id).unwrap();
    assert_eq!(ended.status, RequestStatus::Denied);
    assert!(ended.result.is_none());
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert!(lock(&f.provider.state.revoked).is_empty());
    assert_eq!(generator_activity(&f).iter().filter(|r| r.kind == "revocation_unsupported").count(), 1);
}

#[test]
fn generation_google_expired_authorization_evicts_delivery_and_requires_sign_in() {
    let f = Fixture::new();
    let config = f.install_gcloud();
    let pending = f.request(f.body(GCLOUD_TOKEN_NAME)).unwrap();
    f.approve_gcloud(&pending.request_id).unwrap();
    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    std::fs::write(format!("{}.revoked", config.sdk_path), b"").unwrap();
    let error = f.request(gcloud_conditional(&f, &first.lease_id, 1)).unwrap_err();
    assert_eq!(error.message, GCLOUD_SIGN_IN_REQUIRED);
    assert!(f.core.check_generated_delivery(&first.lease_id, 1).is_err());
    let current = f.core.list_generators().into_iter().find(|item| item.id == GCLOUD_ID).unwrap();
    assert_eq!(current.status, ffi::VaultStatus::Error { message: GCLOUD_SIGN_IN_REQUIRED.into() });
    let activity = generator_activity(&f);
    assert!(activity.iter().any(|r| r.kind == "revocation_unsupported"));
    assert!(!activity.iter().any(|r| r.detail.as_ref().is_some_and(|d| d.contains("SDK diagnostic"))));
    assert!(lock(&f.provider.state.revoked).is_empty());
}
