use super::*;
use asm_proto::error::ErrorCode;
use asm_proto::generators::{GcloudAccessRequest, GcloudPermission};
use std::collections::BTreeMap;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::thread::{self, JoinHandle};
use crate::generator::{GcloudScopeOption, GcloudService};
use std::time::Instant;

const PARENT: &str = "test-operator-token";
const CHILD: &str = "test-impersonated-token+/=";
const ADC: &str = r#"{"type":"authorized_user","client_id":"test-client","client_secret":"test-secret","refresh_token":"test-refresh"}"#;
const PROJECT_ID: &str = "test-project";
const UNIQUE_ID: &str = "111111111111111111111";
const EMAIL: &str = "workload@test-project.iam.gserviceaccount.com";
const BROAD: &str = "https://www.googleapis.com/auth/cloud-platform";
const STORAGE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const RUN: &str = "https://www.googleapis.com/auth/run.readonly";
const TOKENINFO_PATH: &str = "/oauth2/v1/tokeninfo";

struct Step {
    method: &'static str,
    path: String,
    status: u16,
    location: Option<&'static str>,
    body: Value,
}

impl Step {
    fn get(path: impl Into<String>, body: Value) -> Self {
        Self { method: "GET", path: path.into(), status: 200, location: None, body }
    }

    fn tokeninfo(status: u16, body: Value) -> Self {
        Self { method: "POST", path: TOKENINFO_PATH.into(), status, location: None, body }
    }
}

struct Request {
    headers: BTreeMap<String, String>,
    body: String,
}

impl Request {
    fn assert_management(&self) {
        assert_eq!(self.headers["authorization"], format!("Bearer {PARENT}"));
        assert_eq!(self.headers["x-goog-user-project"], PROJECT_ID);
    }

    fn assert_public(&self) {
        assert!(!self.headers.contains_key("authorization"));
        assert!(!self.headers.contains_key("x-goog-user-project"));
    }
}

struct Server {
    endpoint: Url,
    requests: JoinHandle<Vec<Request>>,
}

impl Server {
    fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let requests = thread::spawn(move || steps.into_iter().map(|step| {
            let mut stream = accept(&listener);
            let request = receive(&mut stream, &step);
            let body = step.body.to_string();
            let location = step.location.map(|value| format!("Location: {value}\r\n")).unwrap_or_default();
            let response = format!("HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{location}\r\n{body}", step.status, body.len());
            stream.write_all(response.as_bytes()).unwrap();
            request
        }).collect());
        Self { endpoint, requests }
    }

    fn http(&self) -> GcloudHttp {
        GcloudHttp::with_test_endpoint(self.endpoint.clone()).unwrap()
    }

    fn finish(self) -> Vec<Request> {
        self.requests.join().unwrap()
    }
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return stream;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "expected provider request not sent");
                thread::sleep(Duration::from_millis(2));
            }
            Err(err) => panic!("provider socket failed: {err}"),
        }
    }
}

fn receive(stream: &mut TcpStream, expected: &Step) -> Request {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
    let mut words = line.split_ascii_whitespace();
    assert_eq!(words.next(), Some(expected.method));
    assert_eq!(words.next(), Some(expected.path.as_str()));
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers.get("content-length").map_or(0, |size| size.parse::<usize>().unwrap());
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    Request { headers, body: String::from_utf8(body).unwrap() }
}

#[test]
fn legacy_preflight_uses_the_immutable_target_and_refuses_missing_permission_or_redirects() {
    let path = format!("/v1/projects/{PROJECT_ID}/serviceAccounts/{UNIQUE_ID}:testIamPermissions");
    let server = Server::start(vec![
        Step { method: "POST", ..Step::get(&path, json!({"permissions":[IMPERSONATE_PERMISSION]})) },
        Step { method: "POST", ..Step::get(&path, json!({})) },
        Step { method: "POST", status: 302, location: Some("/other"), ..Step::get(&path, json!({})) },
    ]);
    let http = server.http();
    http.preflight(PARENT, PROJECT_ID, UNIQUE_ID).unwrap();
    assert!(http.preflight(PARENT, PROJECT_ID, UNIQUE_ID).unwrap_err().message.contains(IMPERSONATE_PERMISSION));
    assert!(http.preflight(PARENT, PROJECT_ID, UNIQUE_ID).unwrap_err().message.contains("HTTP 302"));
    for request in server.finish() {
        request.assert_management();
        assert_eq!(serde_json::from_str::<Value>(&request.body).unwrap(), json!({"permissions":[IMPERSONATE_PERMISSION]}));
    }
}

#[test]
fn identity_requires_verified_email_and_maps_only_unauthorized_as_reconnect() {
    let userinfo = "/v1/userinfo";
    let server = Server::start(vec![
        Step::get(userinfo, json!({"sub":"operator-id", "email":"operator@example.com", "email_verified":true})),
        Step::get(userinfo, json!({"sub":"operator-id", "email":"operator@example.com", "email_verified":false})),
        Step { status: 401, ..Step::get(userinfo, json!({"error":PARENT})) },
    ]);
    let http = server.http();
    assert_eq!(http.identity(PARENT).unwrap(), GcloudIdentity { subject: "operator-id".into(), email: "operator@example.com".into() });
    assert_eq!(http.identity(PARENT).unwrap_err().code, ErrorCode::VaultUnavailable);
    let error = http.identity(PARENT).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(!error.message.contains(PARENT));
    for request in server.finish() {
        assert_eq!(request.headers["authorization"], format!("Bearer {PARENT}"));
        assert!(!request.headers.contains_key("x-goog-user-project"));
    }
}

const SEARCH: &str = "/v3/projects:search?query=state%3AACTIVE&pageSize=100&fields=projects%28projectId%2Cstate%29%2CnextPageToken";

#[test]
fn project_search_lists_only_active_ids_across_every_page_without_a_quota_project() {
    let server = Server::start(vec![
        Step::get(SEARCH, json!({
            "projects":[
                {"projectId":"zebra-project","state":"ACTIVE","displayName":"not-an-id"},
                {"projectId":"deleted-project","state":"DELETE_REQUESTED"},
                {"projectId":"unknown-project","state":"STATE_UNSPECIFIED"}
            ],
            "nextPageToken":"two+/="
        })),
        Step::get(format!("{SEARCH}&pageToken=two%2B%2F%3D"), json!({
            "nextPageToken":"three"
        })),
        Step::get(format!("{SEARCH}&pageToken=three"), json!({
            "projects":[
                {"projectId":"alpha-project","state":"ACTIVE"},
                {"projectId":"zebra-project","state":"ACTIVE"}
            ]
        })),
    ]);
    assert_eq!(server.http().active_projects(PARENT).unwrap(), ["alpha-project", "zebra-project"]);
    for request in server.finish() {
        assert_eq!(request.headers["authorization"], format!("Bearer {PARENT}"));
        assert!(!request.headers.contains_key("x-goog-user-project"));
        assert!(request.body.is_empty());
    }
}

#[test]
fn project_search_refuses_partial_results_and_never_follows_a_redirect() {
    let server = Server::start(vec![
        Step::get(SEARCH, json!({
            "projects":[{"projectId":"active-project","state":"ACTIVE"}],
            "nextPageToken":"again"
        })),
        Step::get(format!("{SEARCH}&pageToken=again"), json!({"nextPageToken":"again"})),
        Step::get(SEARCH, json!({"projects":[{"projectId":"invalid project","state":"ACTIVE"}]})),
        Step::get(SEARCH, json!({"projects":[{"projectId":"missing-state"}]})),
        Step::get(SEARCH, json!({"projects":[{"projectId":"large-body","state":"ACTIVE", "unwanted":"x".repeat(64*1024)}]})),
        Step::get(SEARCH, json!({"nextPageToken":"x".repeat(4097)})),
        Step { status: 302, location: Some("/elsewhere"), ..Step::get(SEARCH, json!({})) },
        Step { status: 403, ..Step::get(SEARCH, json!({"error":PARENT})) },
        Step::get(SEARCH, json!({})),
    ]);
    let http = server.http();
    for message in ["repeated page token", "malformed", "malformed", "too large", "malformed", "HTTP 302", "resourcemanager.projects.get"] {
        let error = http.active_projects(PARENT).unwrap_err();
        assert!(error.message.contains(message), "expected {message}, got {error:?}");
        assert!(!error.message.contains(PARENT));
    }
    assert!(http.active_projects(PARENT).unwrap().is_empty());
    assert_eq!(server.finish().len(), 9);
}

#[test]
fn project_search_has_a_hard_page_limit_even_with_distinct_cursors() {
    let server = Server::start((0..PROJECTS_MAX_PAGES).map(|index| {
        let path = if index == 0 { SEARCH.to_owned() } else { format!("{SEARCH}&pageToken={index}") };
        Step::get(path, json!({"nextPageToken":(index + 1).to_string()}))
    }).collect());
    assert!(server.http().active_projects(PARENT).unwrap_err().message.contains("page limit"));
    assert_eq!(server.finish().len(), PROJECTS_MAX_PAGES);
}

fn grant(scopes: &[&str]) -> GcloudGrant {
    GcloudGrant {
        service_account_unique_id: UNIQUE_ID.into(), service_account_email: EMAIL.into(),
        scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
        project_id: None,
    }
}

struct SdkFixture {
    dir: tempfile::TempDir,
    config: GcloudConfig,
}

impl SdkFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sdk_path = dir.path().join("gcloud");
        let transcript = dir.path().join("commands");
        let transcript = transcript.to_str().unwrap().replace('\'', "'\\''");
        let script = format!(r#"#!/bin/sh
if [ "$1" = version ]; then
    printf '%s\n' '{{"Google Cloud SDK":"582.0.0"}}'
    exit 0
fi
printf '%s\n' "$@" >> '{transcript}'
printf '%s\n' "$GOOGLE_CLOUD_QUOTA_PROJECT" >> '{transcript}.quota'
printf '%s\n' '{CHILD}'
"#);
        std::fs::write(&sdk_path, script).unwrap();
        std::fs::set_permissions(&sdk_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ceiling = grant(&[BROAD, STORAGE, RUN]);
        let scope_catalog = ceiling.scopes.iter().map(|uri| GcloudScopeOption {
            uri: uri.clone(), description: "Fixture scope".into(), services: vec![GcloudService {
                name: "storage.googleapis.com".into(), title: "Storage".into(), enabled: true,
            }],
        }).collect();
        let config = GcloudConfig {
            sdk_path: sdk_path.to_str().unwrap().into(), account_subject: "operator-id".into(),
            account_email: "operator@example.com".into(), project_id: PROJECT_ID.into(),
            project_number: "1234".into(), ceiling, scope_catalog,
        };
        Self { dir, config }
    }

    fn generator(&self, endpoint: &Url, adc: &str) -> Result<GcloudGenerator> {
        GcloudGenerator::with_endpoint_for_tests(&self.config, adc, &self.dir.path().join("operations"), endpoint.clone())
    }

    fn connection(&self, endpoint: &Url) -> Result<GcloudGenerator> {
        let config = GcloudConnectionConfig {
            sdk_path: self.config.sdk_path.clone(),
            account_subject: self.config.account_subject.clone(),
            account_email: self.config.account_email.clone(),
        };
        GcloudGenerator::connection_with_endpoint_for_tests(
            &config, ADC, &self.dir.path().join("operations"), endpoint.clone(),
        )
    }

    fn transcript(&self) -> std::path::PathBuf {
        self.dir.path().join("commands")
    }

    fn quota_transcript(&self) -> std::path::PathBuf {
        self.dir.path().join("commands.quota")
    }
}

#[test]
fn delivers_only_the_exact_scoped_child_with_provider_expiry() {
    let sdk = SdkFixture::new();
    let server = Server::start(vec![Step::tokeninfo(200, json!({"scope":format!("{RUN} {STORAGE}"), "expires_in":107}))]);
    let client = sdk.generator(&server.endpoint, ADC).unwrap();
    let before = now().unwrap();
    let credential = client.issue(&grant(&[STORAGE, RUN])).unwrap();
    assert_eq!(credential.token, CHILD);
    assert!((before + 106..=now().unwrap() + 106).contains(&credential.expires_at));
    let request = server.finish().pop().unwrap();
    request.assert_public();
    assert_eq!(request.headers["content-type"], "application/x-www-form-urlencoded");
    assert_eq!(request.body, "access_token=test-impersonated-token%2B%2F%3D");
    let transcript = std::fs::read_to_string(sdk.transcript()).unwrap();
    let mut args = transcript.lines().collect::<Vec<_>>();
    args.sort_unstable();
    let expect_scopes = format!("--scopes={STORAGE},{RUN}");
    let expect_id = format!("--impersonate-service-account={UNIQUE_ID}");
    let mut expected = vec!["auth", "application-default", "print-access-token", "--format=value(token)",
        "--project=test-project", "--quiet", "--lifetime=3600s", &expect_scopes, &expect_id];
    expected.sort_unstable();
    assert_eq!(args, expected);
    assert_eq!(std::fs::read_to_string(sdk.quota_transcript()).unwrap().trim_end(), PROJECT_ID);
}

#[test]
fn uses_the_approved_project_and_quota_on_every_mint_without_changing_account_or_scopes() {
    let sdk = SdkFixture::new();
    let provider_result = json!({"scope":STORAGE, "expires_in":107});
    let server = Server::start(vec![Step::tokeninfo(200, provider_result.clone()), Step::tokeninfo(200, provider_result)]);
    let client = sdk.generator(&server.endpoint, ADC).unwrap();
    let selected = GcloudGrant { project_id: Some("alternate-project".into()), ..grant(&[STORAGE]) };
    assert_eq!(client.issue(&selected).unwrap().token, CHILD);
    assert_eq!(client.issue(&selected).unwrap().token, CHILD);
    for request in server.finish() { request.assert_public(); }
    let transcript = std::fs::read_to_string(sdk.transcript()).unwrap();
    assert_eq!(transcript.lines().filter(|arg| arg.starts_with("--project=")).collect::<Vec<_>>(),
        ["--project=alternate-project"; 2]);
    let expect_id = format!("--impersonate-service-account={UNIQUE_ID}");
    assert_eq!(transcript.lines().filter(|arg| arg.starts_with("--impersonate-service-account=")).collect::<Vec<_>>(),
        [expect_id.as_str(); 2]);
    let expect_scope = format!("--scopes={STORAGE}");
    assert_eq!(transcript.lines().filter(|arg| arg.starts_with("--scopes=")).collect::<Vec<_>>(),
        [expect_scope.as_str(); 2]);
    assert_eq!(std::fs::read_to_string(sdk.quota_transcript()).unwrap().lines().collect::<Vec<_>>(),
        ["alternate-project"; 2]);
}

#[test]
fn refuses_unverified_minted_tokens_without_parent_fallback() {
    let sdk = SdkFixture::new();
    let server = Server::start(vec![
        Step::tokeninfo(200, json!({"expires_in":300})),
        Step::tokeninfo(200, json!({"scope":format!("{STORAGE} {BROAD}"),"expires_in":300})),
        Step::tokeninfo(200, json!({"scope":RUN,"expires_in":300})),
        Step::tokeninfo(200, json!({"scope":STORAGE,"expires_in":1})),
        Step::tokeninfo(200, json!({"scope":STORAGE,"expires_in":3661})),
        Step::tokeninfo(503, json!({"error":CHILD})),
        Step::tokeninfo(401, json!({"error":CHILD})),
    ]);
    let client = sdk.generator(&server.endpoint, ADC).unwrap();
    for expected in ["malformed", "different", "different", "already expired", "invalid credential expiry", "HTTP 503", "HTTP 401"] {
        let error = client.issue(&grant(&[STORAGE])).unwrap_err();
        assert!(error.message.contains(expected), "{error}");
        assert_eq!(error.code, ErrorCode::VaultUnavailable);
        assert!(!error.message.contains(CHILD));
    }
    for request in server.finish() {
        request.assert_public();
        assert_eq!(request.body, "access_token=test-impersonated-token%2B%2F%3D");
    }
    let transcript = std::fs::read_to_string(sdk.transcript()).unwrap();
    assert_eq!(transcript.lines().filter(|arg| *arg == "print-access-token").count(), 7);
    assert_eq!(transcript.lines().filter(|arg| *arg == format!("--impersonate-service-account={UNIQUE_ID}")).count(), 7);
}

#[test]
fn refuses_empty_unsafe_outside_or_wrong_account_grants_before_spawning() {
    let sdk = SdkFixture::new();
    let server = Server::start(vec![]);
    let client = sdk.generator(&server.endpoint, ADC).unwrap();
    for rejected in [
        grant(&[]),
        grant(&["https://www.googleapis.com/auth/devstorage.full_control"]),
        grant(&["https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/cloud-platform"]),
        GcloudGrant { project_id: Some("--project=wrong".into()), ..grant(&[STORAGE]) },
        GcloudGrant { service_account_unique_id: "222".into(), ..grant(&[STORAGE]) },
    ] {
        assert_eq!(client.issue(&rejected).unwrap_err().code, ErrorCode::Invalid);
    }
    assert!(sdk.generator(&server.endpoint, r#"{"type":"authorized_user"}"#).is_err());
    assert!(!sdk.transcript().exists());
    server.finish();
}

#[test]
fn managed_connection_mints_only_the_profile_id_and_derived_scopes() {
    const COMPUTE: &str = "https://www.googleapis.com/auth/compute.readonly";
    let sdk = SdkFixture::new();
    let server = Server::start(vec![Step::tokeninfo(200, json!({
        "scope": format!("{STORAGE} {COMPUTE}"), "expires_in": 300,
    }))]);
    let client = sdk.connection(&server.endpoint).unwrap();
    let access = GcloudAccessRequest {
        project_id: "managed-project".into(),
        permissions: vec![GcloudPermission::StorageRead, GcloudPermission::ComputeRead],
    };

    // Neither catalog metadata, exact requested claims alone, nor a legacy
    // grant has a profile identity. None may launch the SDK.
    assert!(client.issue_access(&GcloudAccessGrant::Connection).is_err());
    assert!(client.issue_access(&GcloudAccessGrant::Requested { access: access.clone() }).is_err());
    assert!(client.issue(&grant(&[STORAGE])).is_err());
    let issued = |access| GcloudAccessGrant::Issued {
        access, service_account_unique_id: "777444".into(),
        service_account_email: "asm-workload@managed-project.iam.gserviceaccount.com".into(),
    };
    let mut unsorted = access.clone();
    unsorted.permissions.reverse();
    assert!(client.issue_access(&issued(unsorted)).is_err());
    assert!(!sdk.transcript().exists());

    assert_eq!(client.issue_access(&issued(access)).unwrap().token, CHILD);
    server.finish()[0].assert_public();
    let commands = std::fs::read_to_string(sdk.transcript()).unwrap();
    assert!(commands.lines().any(|arg| arg == "--impersonate-service-account=777444"));
    assert!(commands.lines().any(|arg| arg == "--project=managed-project"));
    assert!(commands.lines().any(|arg| arg == format!("--scopes={COMPUTE},{STORAGE}")));
    assert_eq!(commands.lines().filter(|arg| *arg == "print-access-token").count(), 1);
}
